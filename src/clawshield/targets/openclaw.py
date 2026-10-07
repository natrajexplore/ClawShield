"""OpenClaw agent target (FR-4; interface decided in ADR 0002).

One `openclaw agent --agent <id> --session-id <sid> --message-file <file> --json` turn per
case, through the OpenClaw gateway where the DefenseClaw interceptor runs. The case text
goes into a private temp file and never through a shell. A turn that did not run on
OpenClaw's embedded harness bypassed the guardrail, so it is recorded as an error and
never scored.
"""

import json
import os
import secrets
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from clawshield import shell
from clawshield.core.models import Case, TargetResult
from clawshield.targets.base import Clock, clamp_received, describe_error, utc_now

Runner = Callable[..., shell.CommandResult]

# The only harness whose model calls pass DefenseClaw's fetch interceptor (ADR 0002).
GUARDED_HARNESS = "openclaw"
MAX_STDERR_CHARS = 200


class OpenClawTarget:
    def __init__(
        self,
        name: str,
        *,
        agent: str,
        binary: str = "openclaw",
        timeout_s: float = 300,
        run: Runner = shell.run,
        clock: Clock = utc_now,
        session_prefix: str | None = None,
    ) -> None:
        self.name = name
        self.agent = agent
        self._binary = binary
        self._timeout_s = timeout_s
        self._run = run
        self._clock = clock
        # Unique per instance (= per run), lowercase because OpenClaw lowercases session ids.
        self._session_prefix = (session_prefix or f"clawshield-{secrets.token_hex(6)}").lower()

    def session_for(self, case: Case) -> str:
        return f"{self._session_prefix}-{case.id}".lower()

    def stored_session(self, session: str) -> str:
        """How OpenClaw (and so DefenseClaw's audit.db) records an explicit session id."""
        return f"agent:{self.agent}:explicit:{session}"

    def send(self, case: Case) -> TargetResult:
        session = self.session_for(case)
        expected_key = self.stored_session(session)
        sent_at = self._clock()
        response: str | None = None
        session_key = expected_key
        try:
            payload = self._turn(case.text, session)
            response, session_key = _parse(payload, expected_key)
            error = None
        except _TurnError as exc:
            error = str(exc)
        except Exception as exc:  # noqa: BLE001 - target failures are recorded, not raised
            error = describe_error(exc)
        return TargetResult(
            case_id=case.id,
            session_id=session_key,
            sent_at=sent_at,
            received_at=clamp_received(sent_at, self._clock()),
            response_text=response if error is None else None,
            error=error,
        )

    def _turn(self, text: str, session: str) -> Any:
        fd, name = tempfile.mkstemp(prefix="clawshield-", suffix=".txt")  # mode 0600
        path = Path(name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(text)
            result = self._run(
                [self._binary, "agent", "--agent", self.agent, "--session-id", session,
                 "--message-file", str(path), "--json"],
                timeout_s=self._timeout_s,
            )  # fmt: skip
        finally:
            path.unlink(missing_ok=True)
        if not result.ok:
            lines = result.stderr.strip().splitlines()
            detail = f": {lines[-1][:MAX_STDERR_CHARS]}" if lines else ""
            raise _TurnError(f"openclaw agent exited {result.returncode}{detail}")
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise _TurnError(f"openclaw agent returned invalid JSON (line {exc.lineno})") from None


class _TurnError(Exception):
    """A failed turn; the message is safe to store (no prompt or response text)."""


def _parse(payload: Any, expected_key: str) -> tuple[str, str]:
    """Return (reply text, stored session key) from `--json` output, or raise _TurnError."""
    if not isinstance(payload, dict):
        raise _TurnError("openclaw agent JSON is not an object")
    status = payload.get("status")
    if status != "ok":
        raise _TurnError(f"openclaw agent status {str(status)[:40]!r}")
    result = payload.get("result")
    meta = result.get("meta") if isinstance(result, dict) else None
    if not isinstance(meta, dict):
        raise _TurnError("openclaw agent JSON has no result.meta")
    if meta.get("aborted") is True:
        raise _TurnError("openclaw agent run aborted")
    agent_meta = meta.get("agentMeta")
    harness = agent_meta.get("agentHarnessId") if isinstance(agent_meta, dict) else None
    if harness != GUARDED_HARNESS:
        raise _TurnError(
            f"turn ran on harness {str(harness)[:40]!r}, not {GUARDED_HARNESS!r}: it bypassed "
            "the DefenseClaw interceptor (pin agentRuntime.id, ADR 0002)"
        )
    report = meta.get("systemPromptReport")
    key = report.get("sessionKey") if isinstance(report, dict) else None
    if key is not None and key != expected_key:
        raise _TurnError("openclaw used a different session key than requested")
    text = meta.get("finalAssistantVisibleText")
    if not isinstance(text, str):
        payloads = result.get("payloads") if isinstance(result, dict) else None
        parts = [
            p["text"]
            for p in payloads or []
            if isinstance(p, dict) and isinstance(p.get("text"), str)
        ]
        if not parts:
            raise _TurnError("openclaw agent JSON has no reply text")
        text = "\n".join(parts)
    return text, expected_key
