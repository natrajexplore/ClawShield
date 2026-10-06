"""TargetClient protocol and the allowlist-enforcing factory (NFR-2)."""

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

from clawshield.config import Settings
from clawshield.core.models import Case, TargetResult

Clock = Callable[[], datetime]

MAX_ERROR_CHARS = 500


def utc_now() -> datetime:
    return datetime.now(UTC)


def clamp_received(sent_at: datetime, received_at: datetime) -> datetime:
    """Wall clocks can step backwards (NTP); never record a negative latency."""
    return max(sent_at, received_at)


def describe_error(exc: BaseException) -> str:
    """Error text is stored even when responses are redacted, so target clients must
    never put response bodies or prompt text into exceptions they raise."""
    return f"{type(exc).__name__}: {exc}"[:MAX_ERROR_CHARS]


class TargetError(Exception):
    """The target cannot be built (not allowlisted, or not implemented)."""


@runtime_checkable
class TargetClient(Protocol):
    """Sends one corpus case to the guarded agent.

    Implementations must not raise for target-side failures (timeouts, HTTP errors,
    refusals); they return a TargetResult with `error` set instead.
    """

    name: str

    def send(self, case: Case) -> TargetResult: ...


def build_target(settings: Settings) -> TargetClient:
    """Create the configured target. Re-checks the allowlist before any request (NFR-2)."""
    target = settings.target
    if not settings.targets.allows(target):
        raise TargetError(f"target {target.identity()!r} is not in targets.allowlist")
    if target.kind == "mock":
        from clawshield.targets.mock import MockTarget

        return MockTarget(name=target.name)
    raise TargetError(f"target kind {target.kind!r} is not implemented yet (ADR 0002, M2)")
