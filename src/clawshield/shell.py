"""The single entry point for running external commands (DefenseClaw, OpenClaw).

Guarantees:
- argv list only, never `shell=True`; a plain string is rejected.
- a timeout on every call; stdin is closed so interactive prompts fail fast.
- the program is resolved to an absolute path from absolute PATH entries only
  (no current-directory or relative-PATH hijacking, which Windows allows by default).
- on Windows, refuses to pass cmd.exe metacharacters to .bat/.cmd programs, which
  re-parse their arguments even without a shell (BatBadBut class, CVE-2024-24576).
- logs never include arguments or environment (they may carry prompts or secrets).
"""

import logging
import os
import re

# This module is the single audited exec point; bandit B404/B603 reviewed here.
import subprocess  # nosec B404
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_WINDOWS = sys.platform == "win32"
_BATCH_SUFFIXES = frozenset({".bat", ".cmd"})
_CMD_UNSAFE = re.compile(r'[\x00-\x1f"%!^&|<>()]')
_DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD"


class CommandError(Exception):
    """A command could not be run safely or did not complete."""


class CommandNotFoundError(CommandError):
    """The program was not found on PATH (or the given absolute path)."""


class CommandTimeoutError(CommandError):
    """The command exceeded its timeout and was killed."""


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def _executable_suffixes(program: str) -> list[str]:
    if not _WINDOWS:
        return [""]
    pathext = [e for e in os.environ.get("PATHEXT", _DEFAULT_PATHEXT).split(os.pathsep) if e]
    if Path(program).suffix.upper() in {e.upper() for e in pathext}:
        return [""]
    return pathext


def resolve_program(program: str) -> str:
    """Resolve `program` to an absolute executable path without searching the CWD."""
    if os.sep in program or (os.altsep is not None and os.altsep in program):
        path = Path(program)
        if not path.is_absolute():
            raise CommandError(
                f"relative program path {program!r} not allowed; use a bare name or absolute path"
            )
        if not path.is_file():
            raise CommandNotFoundError(f"program not found: {program}")
        return str(path)

    suffixes = _executable_suffixes(program)
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue  # empty/relative PATH entries resolve against the CWD
        for suffix in suffixes:
            candidate = os.path.join(entry, program + suffix)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
    raise CommandNotFoundError(f"program not found on PATH: {program}")


def _validate_args(args: Sequence[str]) -> tuple[str, ...]:
    if isinstance(args, (str, bytes)):
        raise TypeError("args must be a sequence of strings, not a single string")
    argv = tuple(args)
    if not argv:
        raise ValueError("args must not be empty")
    for arg in argv:
        if not isinstance(arg, str):
            raise TypeError("every argument must be a str")
        if "\x00" in arg:
            raise CommandError("arguments must not contain NUL bytes")
    return argv


def run(
    args: Sequence[str],
    *,
    timeout_s: float,
    env_overrides: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run a command and capture its output. Non-zero exit is returned, not raised.

    Raises CommandNotFoundError, CommandTimeoutError or CommandError when the command
    cannot be run or does not finish.
    """
    argv = _validate_args(args)
    if timeout_s <= 0:
        raise ValueError("timeout_s must be > 0")

    executable = resolve_program(argv[0])
    name = Path(executable).name
    if (
        _WINDOWS
        and Path(executable).suffix.lower() in _BATCH_SUFFIXES
        and any(_CMD_UNSAFE.search(arg) for arg in argv[1:])
    ):
        raise CommandError(f"refusing to pass cmd.exe metacharacters to batch program {name}")

    env = None
    if env_overrides:
        env = {**os.environ, **env_overrides}

    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603  # nosec B603
            (executable, *argv[1:]),
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired:
        log.warning("exec %s timed out after %.1fs", name, timeout_s)
        raise CommandTimeoutError(f"{name} timed out after {timeout_s:g}s") from None
    except OSError as exc:
        raise CommandError(f"cannot run {name}: {exc.strerror or exc}") from None
    duration = time.monotonic() - started

    log.debug("exec %s args=%d rc=%d %.3fs", name, len(argv) - 1, completed.returncode, duration)
    return CommandResult(
        args=argv,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_s=duration,
    )
