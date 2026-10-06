import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from clawshield import shell
from clawshield.shell import (
    CommandError,
    CommandNotFoundError,
    CommandTimeoutError,
    resolve_program,
    run,
)

PY = sys.executable
WINDOWS = sys.platform == "win32"
INJECTION = "a && echo pwned; $(whoami) `id` | more > out.txt"


def _make_prog(directory: Path, name: str) -> Path:
    """Create a tiny program that echoes its arguments (batch file on Windows)."""
    if WINDOWS:
        path = directory / f"{name}.cmd"
        path.write_text("@echo off\r\necho %*\r\n", encoding="ascii")
    else:
        path = directory / name
        path.write_text('#!/bin/sh\necho "$@"\n', encoding="ascii")
        path.chmod(0o755)
    return path


# --- argument handling -------------------------------------------------------------


def test_metacharacters_passed_literally() -> None:
    result = run([PY, "-c", "import sys; print(sys.argv[1])", INJECTION], timeout_s=30)
    assert result.ok
    assert result.stdout.strip() == INJECTION


def test_never_uses_shell(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake_run(cmd: Any, **kwargs: Any) -> subprocess.CompletedProcess[str]:
        seen["cmd"], seen["kwargs"] = cmd, kwargs
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(shell.subprocess, "run", fake_run)
    run([PY, "-V"], timeout_s=5)
    assert seen["kwargs"]["shell"] is False
    assert seen["kwargs"]["stdin"] is subprocess.DEVNULL
    assert seen["kwargs"]["timeout"] == 5
    assert isinstance(seen["cmd"], tuple)


@pytest.mark.parametrize("bad", ["defenseclaw status", b"defenseclaw"])
def test_string_args_rejected(bad: Any) -> None:
    with pytest.raises(TypeError, match="not a single string"):
        run(bad, timeout_s=5)


def test_empty_args_rejected() -> None:
    with pytest.raises(ValueError, match="empty"):
        run([], timeout_s=5)


def test_non_str_arg_rejected() -> None:
    with pytest.raises(TypeError, match="must be a str"):
        run([PY, 1], timeout_s=5)  # type: ignore[list-item]


def test_nul_byte_rejected() -> None:
    with pytest.raises(CommandError, match="NUL"):
        run([PY, "-c", "pass\x00"], timeout_s=5)


@pytest.mark.parametrize("timeout", [0, -1])
def test_timeout_must_be_positive(timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout_s"):
        run([PY, "-V"], timeout_s=timeout)


# --- execution -----------------------------------------------------------------------


def test_timeout_kills_command() -> None:
    started = time.monotonic()
    with pytest.raises(CommandTimeoutError, match="timed out"):
        run([PY, "-c", "import time; time.sleep(30)"], timeout_s=0.5)
    assert time.monotonic() - started < 10


def test_stdin_is_closed() -> None:
    result = run([PY, "-c", "import sys; print(repr(sys.stdin.read()))"], timeout_s=30)
    assert result.stdout.strip() == "''"


def test_nonzero_exit_returned_with_stderr() -> None:
    result = run([PY, "-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"], timeout_s=30)
    assert not result.ok
    assert result.returncode == 3
    assert result.stderr == "boom"
    assert result.duration_s >= 0


def test_output_decoded_as_utf8_with_replacement() -> None:
    code = "import sys; sys.stdout.buffer.write('caf\\u00e9 \\u2713 '.encode() + b'\\xff')"
    result = run([PY, "-c", code], timeout_s=30)
    assert result.stdout == "café ✓ �"


def test_env_overrides_merged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAWSHIELD_INHERITED", "yes")
    code = "import os; print(os.environ['CLAWSHIELD_T'], os.environ['CLAWSHIELD_INHERITED'])"
    result = run([PY, "-c", code], timeout_s=30, env_overrides={"CLAWSHIELD_T": "v1"})
    assert result.stdout.split() == ["v1", "yes"]


def test_os_error_wrapped(tmp_path: Path) -> None:
    not_executable = tmp_path / "data.txt"
    not_executable.write_text("hello", encoding="ascii")
    with pytest.raises(CommandError, match=r"cannot run data\.txt"):
        run([str(not_executable)], timeout_s=5)


def test_logs_never_contain_arguments(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="clawshield.shell")
    run([PY, "-c", "pass", "SECRET-ARG-XYZ"], timeout_s=30)
    assert "rc=0" in caplog.text
    assert "SECRET-ARG-XYZ" not in caplog.text


# --- program resolution ---------------------------------------------------------------


def test_resolves_from_absolute_path_entry(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prog = _make_prog(tmp_path, "clawfake")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert Path(resolve_program("clawfake")) == prog


def test_cwd_is_never_searched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _make_prog(tmp_path, "clawfake")
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", str(empty))
    with pytest.raises(CommandNotFoundError):
        resolve_program("clawfake")


def test_relative_and_empty_path_entries_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_prog(tmp_path, "clawfake")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PATH", os.pathsep.join([".", "", "sub"]))
    with pytest.raises(CommandNotFoundError):
        resolve_program("clawfake")


def test_relative_program_path_rejected() -> None:
    with pytest.raises(CommandError, match="relative program path"):
        resolve_program(os.path.join(".", "clawfake"))


def test_missing_absolute_program(tmp_path: Path) -> None:
    with pytest.raises(CommandNotFoundError):
        run([str(tmp_path / "missing-prog")], timeout_s=5)


def test_missing_program_on_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(CommandNotFoundError, match="not found on PATH"):
        run(["definitely-not-installed-clawshield"], timeout_s=5)


def test_runs_resolved_program(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _make_prog(tmp_path, "clawfake")
    monkeypatch.setenv("PATH", str(tmp_path))
    result = run(["clawfake", "safe-arg_1.0"], timeout_s=30)
    assert result.ok
    assert result.stdout.strip() == "safe-arg_1.0"


# --- Windows batch-file guard -----------------------------------------------------------


@pytest.mark.skipif(not WINDOWS, reason="cmd.exe argument re-parsing is Windows-only")
@pytest.mark.parametrize("arg", ['a"&calc', "a&b", "%PATH%", "a|b", "x^y", "(a)", "a\nb"])
def test_batch_program_refuses_metacharacters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, arg: str
) -> None:
    _make_prog(tmp_path, "clawfake")
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(CommandError, match=r"refusing to pass cmd\.exe metacharacters"):
        run(["clawfake", arg], timeout_s=5)


@pytest.mark.skipif(not WINDOWS, reason="cmd.exe argument re-parsing is Windows-only")
def test_batch_guard_is_necessary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Proves the threat is real: with the guard disabled, the argument runs a second command.
    _make_prog(tmp_path, "clawfake")
    monkeypatch.setenv("PATH", str(tmp_path))
    payload = 'hello"&echo INJECTED-BY-ARG'
    monkeypatch.setattr(shell, "_CMD_UNSAFE", __import__("re").compile(r"(?!)"))
    result = run(["clawfake", payload], timeout_s=30)
    assert "\nINJECTED-BY-ARG" in result.stdout


@pytest.mark.skipif(not WINDOWS, reason="PATHEXT applies on Windows only")
def test_explicit_extension_resolved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    prog = _make_prog(tmp_path, "clawfake")
    monkeypatch.setenv("PATH", str(tmp_path))
    assert Path(resolve_program("clawfake.cmd")) == prog


@pytest.mark.skipif(WINDOWS, reason="POSIX scripts receive argv without re-parsing")
def test_posix_script_receives_metacharacters_literally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_prog(tmp_path, "clawfake")
    monkeypatch.setenv("PATH", str(tmp_path))
    result = run(["clawfake", INJECTION], timeout_s=30)
    assert result.stdout.strip() == INJECTION
