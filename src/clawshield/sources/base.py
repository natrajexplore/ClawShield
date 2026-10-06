"""VerdictSource protocol: where DefenseClaw verdicts come from (FR-7)."""

from datetime import datetime
from typing import Protocol, runtime_checkable

from clawshield.core.models import Verdict


@runtime_checkable
class VerdictSource(Protocol):
    """Implementations: `defenseclaw alerts --json` (primary), JSONL sink (secondary).

    Both wait for real captured fixtures (M0) before their parsers are written.
    """

    name: str

    def fetch(self, since: datetime) -> list[Verdict]: ...
