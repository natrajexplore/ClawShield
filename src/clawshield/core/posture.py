"""Guardrail posture from a run's snapshot (FR-16 observe-period evidence). Pure: no I/O.

The snapshot embeds `defenseclaw status --json` (verified shape, DefenseClaw 0.8.10,
tests/fixtures/defenseclaw/status.json): `sidecar.running` and `connectors[]` with `name`,
`enabled`, `mode`. A run counts as observe-mode evidence only if its own snapshot says the
configured connector was enabled, in `observe` mode, with the sidecar running. Anything
missing or unexpected is "not verified", never assumed.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Posture:
    observe_verified: bool
    mode: str | None
    reason: str


def guardrail_posture(snapshot: Mapping[str, Any] | None, connector: str) -> Posture:
    if not isinstance(snapshot, Mapping) or snapshot.get("available") is not True:
        return Posture(False, None, "no guardrail snapshot")
    status = snapshot.get("defenseclaw_status")
    if not isinstance(status, Mapping):
        return Posture(False, None, "snapshot has no status --json")
    sidecar = status.get("sidecar")
    if not (isinstance(sidecar, Mapping) and sidecar.get("running") is True):
        return Posture(False, None, "DefenseClaw sidecar not running")
    connectors = status.get("connectors")
    if not isinstance(connectors, list):
        connectors = []
    entries = [c for c in connectors if isinstance(c, Mapping) and c.get("name") == connector]
    if len(entries) != 1:
        return Posture(False, None, f"connector {connector!r} not uniquely listed")
    entry = entries[0]
    mode = entry.get("mode") if isinstance(entry.get("mode"), str) else None
    if entry.get("enabled") is not True:
        return Posture(False, mode, f"connector {connector!r} disabled")
    if mode != "observe":
        return Posture(False, mode, f"connector {connector!r} in mode {str(mode)[:20]!r}")
    return Posture(True, mode, "observe")


def observe_streak_start(
    runs: Iterable[tuple[datetime, Mapping[str, Any] | None]], connector: str
) -> datetime | None:
    """Start of the current unbroken streak of verified-observe runs, oldest first input.

    Any run whose snapshot does not verify observe mode (action mode, disabled, missing or
    unparseable snapshot) restarts the clock, so a gap is never counted as observe time.
    """
    start: datetime | None = None
    for started_at, snapshot in runs:
        if guardrail_posture(snapshot, connector).observe_verified:
            start = start or started_at
        else:
            start = None
    return start
