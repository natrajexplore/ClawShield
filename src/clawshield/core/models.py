"""Core domain models. Pure: no I/O."""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class Severity(StrEnum):
    """DefenseClaw verdict severity, ordered LOW < MEDIUM < HIGH < CRITICAL."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Category(StrEnum):
    """Corpus categories, mapped to OWASP LLM Top 10 in docs/PRD.md section 9."""

    LLM01_DIRECT = "llm01_direct"
    LLM01_INDIRECT = "llm01_indirect"
    LLM02_SENSITIVE = "llm02_sensitive"
    LLM07_SYSPROMPT = "llm07_sysprompt"
    JAILBREAK = "jailbreak"
    OBFUSCATION = "obfuscation"
    BENIGN = "benign"
    BENIGN_LOOKALIKE = "benign_lookalike"

    @property
    def is_benign(self) -> bool:
        return self in (Category.BENIGN, Category.BENIGN_LOOKALIKE)


Label = Literal["benign", "malicious"]

MAX_CASE_TEXT_CHARS = 32_000


class Case(BaseModel):
    """One labeled corpus test prompt (FR-3). `text` is kept exactly as written."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)

    id: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")]
    text: Annotated[str, Field(min_length=1, max_length=MAX_CASE_TEXT_CHARS)]
    label: Label
    category: Category
    expected_severity: Severity
    canary: Annotated[str, Field(min_length=4)] | None = None

    @model_validator(mode="after")
    def _check_label_matches_category(self) -> Self:
        if self.category.is_benign != (self.label == "benign"):
            raise ValueError(
                f"label {self.label!r} does not match category {self.category.value!r}"
            )
        if self.label == "benign" and self.expected_severity is not Severity.LOW:
            raise ValueError("benign cases must have expected_severity 'low'")
        if not self.text.strip():
            raise ValueError("text must not be blank")
        return self


class TargetResult(BaseModel):
    """What the guarded target returned for one case (FR-4).

    A target failure is recorded in `error`, never raised, so one bad case cannot abort a
    run. `run_id` is attached when results are stored, not by the target client.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: Annotated[str, Field(min_length=1)]
    session_id: str | None = None
    sent_at: AwareDatetime
    received_at: AwareDatetime
    response_text: str | None = None
    error: str | None = None
    http_status: Annotated[int, Field(ge=100, le=599)] | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.received_at < self.sent_at:
            raise ValueError("received_at must not be before sent_at")
        if self.response_text is None and self.error is None:
            raise ValueError("a result needs response_text or error")
        return self

    @property
    def latency_s(self) -> float:
        return (self.received_at - self.sent_at).total_seconds()
