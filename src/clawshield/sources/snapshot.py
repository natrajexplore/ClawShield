"""Capture DefenseClaw's guardrail posture at run start, so every score is tied to an
exact configuration (ARCHITECTURE.md). Commands per docs/DEFENSECLAW_REFERENCE.md.

Never fabricates data: if DefenseClaw is unavailable, the snapshot says so and why.
"""

import json
from collections.abc import Callable
from typing import Any

from clawshield import shell
from clawshield.config import DefenseClawConfig
from clawshield.targets.base import Clock, utc_now

MAX_CAPTURE_CHARS = 64 * 1024

Runner = Callable[..., shell.CommandResult]


def capture_guardrail_snapshot(
    cfg: DefenseClawConfig, *, run: Runner = shell.run, clock: Clock = utc_now
) -> dict[str, Any]:
    errors: list[str] = []
    status_json: Any = None
    guardrail_text: str | None = None

    status = _try(run, [cfg.binary, "status", "--json"], cfg.command_timeout_s, errors)
    if status is not None:
        try:
            status_json = json.loads(status)
        except json.JSONDecodeError as exc:
            errors.append(f"status --json: invalid JSON at line {exc.lineno}: {exc.msg}")

    guardrail_text = _try(run, [cfg.binary, "guardrail", "status"], cfg.command_timeout_s, errors)

    return {
        "captured_at": clock().isoformat(),
        "available": not errors,
        "connector": cfg.connector,
        "defenseclaw_status": status_json,
        "guardrail_status": guardrail_text,
        "errors": errors,
    }


def _try(run: Runner, args: list[str], timeout_s: float, errors: list[str]) -> str | None:
    label = " ".join(args[1:])
    try:
        result = run(args, timeout_s=timeout_s)
    except shell.CommandError as exc:
        errors.append(f"{label}: {exc}")
        return None
    if not result.ok:
        stderr = result.stderr.strip().splitlines()
        detail = f": {stderr[-1][:200]}" if stderr else ""
        errors.append(f"{label}: exit code {result.returncode}{detail}")
        return None
    return result.stdout[:MAX_CAPTURE_CHARS]
