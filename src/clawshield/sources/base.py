"""VerdictSource protocol: where DefenseClaw verdicts come from (FR-7)."""

from datetime import datetime
from typing import Protocol, runtime_checkable

from clawshield.core.models import Verdict


@runtime_checkable
class VerdictSource(Protocol):
    """Implementations: `AuditDbSource` (DefenseClaw audit.db, read-only; ADR 0001).

    `defenseclaw alerts --json` and a JSONL sink are not available in DefenseClaw 0.8.10.
    """

    name: str

    def fetch(self, since: datetime) -> list[Verdict]: ...
