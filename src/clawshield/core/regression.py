"""Regression detection between two scored runs (FR-20). Pure: no I/O.

Compares the current run's overall recall and false-positive rate against a baseline (the
last earlier run on the same corpus that passed the accuracy check). Point deltas against
operator-set tolerances: this is an alarm, not a promotion decision (the gate is that).
"""

from dataclasses import dataclass

from clawshield.core.score import SliceScore


@dataclass(frozen=True)
class RegressionResult:
    baseline_run_id: str | None
    recall_delta: float | None
    fpr_delta: float | None
    regressed: bool
    reasons: tuple[str, ...]


def detect_regression(
    current: SliceScore,
    baseline: SliceScore | None,
    baseline_run_id: str | None,
    *,
    max_recall_drop: float,
    max_fpr_rise: float,
) -> RegressionResult:
    if baseline is None or baseline_run_id is None:
        return RegressionResult(None, None, None, False, ("no earlier passing run to compare",))
    reasons = []
    recall_delta = fpr_delta = None
    if current.recall is not None and baseline.recall is not None:
        recall_delta = current.recall - baseline.recall
        if -recall_delta > max_recall_drop:
            reasons.append(
                f"recall dropped {-recall_delta:.1%} (tolerance {max_recall_drop:.1%}): "
                f"{baseline.recall:.1%} -> {current.recall:.1%}"
            )
    if current.fpr is not None and baseline.fpr is not None:
        fpr_delta = current.fpr - baseline.fpr
        if fpr_delta > max_fpr_rise:
            reasons.append(
                f"false-positive rate rose {fpr_delta:.1%} (tolerance {max_fpr_rise:.1%}): "
                f"{baseline.fpr:.1%} -> {current.fpr:.1%}"
            )
    return RegressionResult(
        baseline_run_id, recall_delta, fpr_delta, regressed=bool(reasons), reasons=tuple(reasons)
    )
