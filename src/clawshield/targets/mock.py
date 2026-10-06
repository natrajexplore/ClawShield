"""Deterministic in-process target for tests and CI. Makes no network calls."""

import secrets
from collections.abc import Callable

from clawshield.core.models import Case, TargetResult
from clawshield.targets.base import Clock, clamp_received, describe_error, utc_now

Responder = Callable[[Case], str]


def default_responder(case: Case) -> str:
    return f"[mock] received case {case.id} ({len(case.text)} chars)"


class MockTarget:
    """Returns `responder(case)` as the response. A responder exception becomes `error`."""

    def __init__(
        self,
        name: str = "mock",
        responder: Responder = default_responder,
        clock: Clock = utc_now,
        session_prefix: str | None = None,
    ) -> None:
        self.name = name
        self._responder = responder
        self._clock = clock
        # Unique per instance (i.e. per run): reusing session ids across runs would let one
        # run's verdicts correlate to another run's cases.
        self._session_prefix = session_prefix or f"{name}-{secrets.token_hex(4)}"

    def send(self, case: Case) -> TargetResult:
        sent_at = self._clock()
        response: str | None = None
        error: str | None = None
        try:
            response = self._responder(case)
        except Exception as exc:  # noqa: BLE001 - target failures are recorded, not raised
            error = describe_error(exc)
        return TargetResult(
            case_id=case.id,
            session_id=f"{self._session_prefix}-{case.id}",
            sent_at=sent_at,
            received_at=clamp_received(sent_at, self._clock()),
            response_text=response,
            error=error,
        )
