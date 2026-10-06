"""Paired A/B comparison of two scored runs on the same corpus (FR-12). Pure: no I/O.

Both runs replay the same cases, so each case is compared with itself (paired design).
Significance uses the exact McNemar test (a two-sided binomial test on the discordant
cases), which is correct for small counts where a chi-square approximation is not.

Per-slice p-values are NOT corrected for multiple comparisons: with ~10 slices one may
look significant by chance. Decide on the overall slice.
"""

from collections.abc import Callable
from dataclasses import dataclass
from math import comb
from typing import Literal

from clawshield.core.score import CaseOutcome, Scorecard

DEFAULT_ALPHA = 0.05

Verdict = Literal["B better", "B worse", "no significant difference", "n/a"]


def mcnemar_exact(a_only: int, b_only: int) -> float:
    """Two-sided exact McNemar p-value from the two discordant counts."""
    if a_only < 0 or b_only < 0:
        raise ValueError("counts must be >= 0")
    n = a_only + b_only
    if n == 0:
        return 1.0
    tail = sum(comb(n, k) for k in range(min(a_only, b_only) + 1))
    return min(1.0, tail / (1 << (n - 1)))  # exact integer arithmetic, then one division


@dataclass(frozen=True)
class PairedTest:
    a_only: int  # cases flagged in A but not in B
    b_only: int  # cases flagged in B but not in A
    p_value: float


@dataclass(frozen=True)
class SliceComparison:
    dimension: str
    value: str
    positives: int
    negatives: int
    recall_a: float | None
    recall_b: float | None
    fpr_a: float | None
    fpr_b: float | None
    recall_test: PairedTest | None
    fpr_test: PairedTest | None
    alpha: float

    @property
    def recall_verdict(self) -> Verdict:
        # Higher recall is better: B wins when it detects cases A missed.
        return _verdict(self.recall_test, self.alpha, b_wins_when_b_only_larger=True)

    @property
    def fpr_verdict(self) -> Verdict:
        # Lower FPR is better: B wins when A flags benign cases that B does not.
        return _verdict(self.fpr_test, self.alpha, b_wins_when_b_only_larger=False)


@dataclass(frozen=True)
class Comparison:
    paired_cases: int
    excluded_case_ids: tuple[str, ...]
    slices: tuple[SliceComparison, ...]
    latency_p50_delta_s: float | None
    latency_p95_delta_s: float | None
    alpha: float

    @property
    def overall(self) -> SliceComparison:
        return next(s for s in self.slices if s.dimension == "overall")


def _verdict(test: PairedTest | None, alpha: float, *, b_wins_when_b_only_larger: bool) -> Verdict:
    if test is None:
        return "n/a"
    if test.p_value >= alpha or test.a_only == test.b_only:
        return "no significant difference"
    b_larger = test.b_only > test.a_only
    return "B better" if b_larger == b_wins_when_b_only_larger else "B worse"


def _rate(flags: list[bool]) -> float | None:
    return sum(flags) / len(flags) if flags else None


def _paired(pairs: list[tuple[CaseOutcome, CaseOutcome]]) -> PairedTest | None:
    if not pairs:
        return None
    a_only = sum(1 for a, b in pairs if a.detected and not b.detected)
    b_only = sum(1 for a, b in pairs if b.detected and not a.detected)
    return PairedTest(a_only, b_only, mcnemar_exact(a_only, b_only))


def _compare_slice(
    dimension: str, value: str, pairs: list[tuple[CaseOutcome, CaseOutcome]], alpha: float
) -> SliceComparison:
    pos = [(a, b) for a, b in pairs if a.label == "malicious"]
    neg = [(a, b) for a, b in pairs if a.label == "benign"]
    return SliceComparison(
        dimension=dimension,
        value=value,
        positives=len(pos),
        negatives=len(neg),
        recall_a=_rate([a.detected for a, _ in pos]),
        recall_b=_rate([b.detected for _, b in pos]),
        fpr_a=_rate([a.detected for a, _ in neg]),
        fpr_b=_rate([b.detected for _, b in neg]),
        recall_test=_paired(pos),
        fpr_test=_paired(neg),
        alpha=alpha,
    )


def _delta(a: float | None, b: float | None) -> float | None:
    return None if a is None or b is None else b - a


def compare(a: Scorecard, b: Scorecard, *, alpha: float = DEFAULT_ALPHA) -> Comparison:
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between 0 and 1")
    a_by_id = {o.case_id: o for o in a.outcomes}
    b_by_id = {o.case_id: o for o in b.outcomes}
    for case_id in a_by_id.keys() & b_by_id.keys():
        if a_by_id[case_id].label != b_by_id[case_id].label:
            raise ValueError(f"case {case_id!r} has different labels in A and B")
    shared = [cid for cid in a_by_id if cid in b_by_id]  # A's order
    excluded = tuple(sorted(a_by_id.keys() ^ b_by_id.keys()))
    pairs = [(a_by_id[cid], b_by_id[cid]) for cid in shared]

    slices = [_compare_slice("overall", "all", pairs, alpha)]
    groupings: list[tuple[str, Callable[[CaseOutcome], str]]] = [
        ("category", lambda o: o.category),
        ("expected_severity", lambda o: o.expected_severity),
    ]
    for dimension, key in groupings:
        for value in sorted({key(pa) for pa, _ in pairs}):
            subset = [(pa, pb) for pa, pb in pairs if key(pa) == value]
            slices.append(_compare_slice(dimension, value, subset, alpha))

    return Comparison(
        paired_cases=len(pairs),
        excluded_case_ids=excluded,
        slices=tuple(slices),
        latency_p50_delta_s=_delta(a.latency_p50_s, b.latency_p50_s),
        latency_p95_delta_s=_delta(a.latency_p95_s, b.latency_p95_s),
        alpha=alpha,
    )
