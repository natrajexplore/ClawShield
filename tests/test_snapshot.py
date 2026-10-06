from datetime import UTC, datetime
from typing import Any

from clawshield.config import DefenseClawConfig
from clawshield.shell import CommandNotFoundError, CommandResult, CommandTimeoutError
from clawshield.sources.snapshot import MAX_CAPTURE_CHARS, capture_guardrail_snapshot

T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
CFG = DefenseClawConfig(binary="defenseclaw", connector="openclaw", command_timeout_s=7)


def _ok(stdout: str) -> CommandResult:
    return CommandResult(args=(), returncode=0, stdout=stdout, stderr="", duration_s=0.1)


def _fake(responses: dict[str, Any]) -> Any:
    calls: list[tuple[list[str], float]] = []

    def run(args: list[str], *, timeout_s: float) -> CommandResult:
        calls.append((args, timeout_s))
        outcome = responses[" ".join(args[1:])]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    run.calls = calls  # type: ignore[attr-defined]
    return run


def _snap(run: Any) -> dict[str, Any]:
    return capture_guardrail_snapshot(CFG, run=run, clock=lambda: T0)


def test_available_snapshot() -> None:
    run = _fake(
        {
            "status --json": _ok('{"connectors": [{"name": "openclaw"}]}'),
            "guardrail status": _ok("openclaw: observe, rule-pack default"),
        }
    )
    snap = _snap(run)
    assert snap == {
        "captured_at": "2026-10-06T12:00:00+00:00",
        "available": True,
        "connector": "openclaw",
        "defenseclaw_status": {"connectors": [{"name": "openclaw"}]},
        "guardrail_status": "openclaw: observe, rule-pack default",
        "errors": [],
    }
    assert run.calls == [
        (["defenseclaw", "status", "--json"], 7),
        (["defenseclaw", "guardrail", "status"], 7),
    ]


def test_defenseclaw_missing_is_recorded_not_faked() -> None:
    missing = CommandNotFoundError("program not found on PATH: defenseclaw")
    snap = _snap(_fake({"status --json": missing, "guardrail status": missing}))
    assert snap["available"] is False
    assert snap["defenseclaw_status"] is None and snap["guardrail_status"] is None
    assert snap["errors"] == [
        "status --json: program not found on PATH: defenseclaw",
        "guardrail status: program not found on PATH: defenseclaw",
    ]


def test_invalid_json_status() -> None:
    snap = _snap(_fake({"status --json": _ok("not json"), "guardrail status": _ok("observe")}))
    assert snap["available"] is False
    assert snap["guardrail_status"] == "observe"
    assert snap["errors"][0].startswith("status --json: invalid JSON at line 1")


def test_nonzero_exit_and_timeout() -> None:
    failed = CommandResult(
        args=(), returncode=3, stdout="", stderr="warn\nconnector not configured", duration_s=0
    )
    snap = _snap(
        _fake(
            {
                "status --json": failed,
                "guardrail status": CommandTimeoutError("defenseclaw timed out after 7s"),
            }
        )
    )
    assert snap["errors"] == [
        "status --json: exit code 3: connector not configured",
        "guardrail status: defenseclaw timed out after 7s",
    ]


def test_output_capped() -> None:
    big = "x" * (MAX_CAPTURE_CHARS + 10)
    snap = _snap(_fake({"status --json": _ok("{}"), "guardrail status": _ok(big)}))
    assert len(snap["guardrail_status"]) == MAX_CAPTURE_CHARS
