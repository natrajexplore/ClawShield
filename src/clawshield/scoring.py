"""Score a stored run: load results + verdicts, correlate, score (FR-10, FR-11).

Labels come from the corpus file the run used. The file must still hash to the run's
recorded corpus_hash; otherwise edited labels would silently change the scores.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from clawshield.config import Settings
from clawshield.core.compare import Comparison, PairedTest, compare
from clawshield.core.correlate import DEFAULT_PRE_S, CorrelationReport, correlate
from clawshield.core.gate import (
    STUB_REPLY_PREFIX,
    Criterion,
    GateEvidence,
    GateReport,
    GateThresholds,
    evaluate_gate,
)
from clawshield.core.models import Category, DeclaredConfig, Verdict
from clawshield.core.regression import RegressionResult, detect_regression
from clawshield.core.score import CaseInput, Interval, Scorecard, SliceScore, score
from clawshield.redteam.corpus import CorpusError, load_corpus
from clawshield.storage.db import RunRow, Store


class ScoringError(Exception):
    """The run cannot be scored reliably."""


@dataclass(frozen=True)
class RunScore:
    run: RunRow
    card: Scorecard
    correlation: CorrelationReport
    verdicts_in_window: int
    grace_s: float
    pre_s: float
    overlapping_runs: tuple[str, ...] = ()
    inputs: tuple[CaseInput, ...] = ()
    verdicts: Mapping[str, Verdict] = field(default_factory=dict)

    @property
    def snapshot_available(self) -> bool:
        return bool(self.run.guardrail_snapshot.get("available"))


def score_run(
    store: Store, settings: Settings, run_id: str, corpus_path: Path | None = None
) -> RunScore:
    run = store.get_run(run_id)
    if run.finished_at is None:
        raise ScoringError(f"run {run.id} is incomplete (interrupted); it cannot be scored")

    path = corpus_path or Path(run.corpus_path)
    corpus = load_corpus(path, known_canaries=settings.canaries)
    if corpus.sha256 != run.corpus_hash:
        raise ScoringError(
            f"corpus {path} has changed since run {run.id} "
            f"(hash {corpus.sha256[:12]} != {run.corpus_hash[:12]}); "
            "scoring with edited labels would be wrong"
        )
    cases = {c.id: c for c in corpus.cases}

    results = store.results(run.id)
    unknown = [r.case_id for r in results if r.case_id not in cases]
    if unknown:
        raise ScoringError(f"run {run.id} has results for cases not in the corpus: {unknown[:5]}")

    grace_s = settings.runner.correlation_grace_s
    window_start = run.started_at - timedelta(seconds=DEFAULT_PRE_S)
    window_end = run.finished_at + timedelta(seconds=grace_s)
    verdicts = store.verdicts_between(window_start, window_end)
    # Another run active inside this window can have its verdicts credited to our cases.
    overlapping = tuple(store.runs_overlapping(window_start, window_end, exclude=run.id))

    report = correlate(
        results, verdicts, grace_s=grace_s, pre_s=DEFAULT_PRE_S,
        connector=settings.defenseclaw.connector,
    )  # fmt: skip
    leaked = store.canary_hits(run.id)
    by_id = {v.id: v for v in verdicts}
    inputs = [
        CaseInput(case=cases[r.case_id], result=r, correlation=c, canary_leaked=r.case_id in leaked)
        for r, c in zip(results, report.cases, strict=True)
    ]
    card = score(
        inputs, by_id,
        detected_min=settings.scoring.detected_min_severity,
        block_at=settings.scoring.block_severity,
    )  # fmt: skip
    return RunScore(
        run=run, card=card, correlation=report, verdicts_in_window=len(verdicts),
        grace_s=grace_s, pre_s=DEFAULT_PRE_S, overlapping_runs=overlapping,
        inputs=tuple(inputs), verdicts=by_id,
    )  # fmt: skip


def _interval(ci: Interval | None) -> list[float] | None:
    return None if ci is None else [ci.low, ci.high]


def slice_to_dict(s: SliceScore) -> dict[str, Any]:
    return {
        "dimension": s.dimension, "value": s.value,
        "tp": s.tp, "fn": s.fn, "fp": s.fp, "tn": s.tn,
        "block_tp": s.block_tp, "block_fp": s.block_fp,
        "recall": s.recall, "recall_ci95": _interval(s.recall_ci),
        "fpr": s.fpr, "fpr_ci95": _interval(s.fpr_ci),
        "precision": s.precision, "block_recall": s.block_recall, "block_fpr": s.block_fpr,
    }  # fmt: skip


def to_dict(rs: RunScore, settings: Settings) -> dict[str, Any]:
    card, run = rs.card, rs.run
    return {
        "run": {
            "id": run.id,
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None,
            "target": run.target_name,
            "corpus_path": run.corpus_path,
            "corpus_hash": run.corpus_hash,
            "snapshot_available": rs.snapshot_available,
            "responses_redacted": run.responses_redacted,
        },
        "parameters": {
            "detected_min_severity": settings.scoring.detected_min_severity.value,
            "block_severity": settings.scoring.block_severity.value,
            "correlation_grace_s": rs.grace_s,
            "correlation_pre_s": rs.pre_s,
            "connector": settings.defenseclaw.connector,
        },
        "cases_total": card.cases_total,
        "cases_scored": card.scored,
        "excluded_ambiguous": list(card.excluded_ambiguous),
        "excluded_errors": list(card.excluded_errors),
        "canary_leaks": list(card.leaked_case_ids),
        "verdicts_in_window": rs.verdicts_in_window,
        "overlapping_runs": list(rs.overlapping_runs),
        "correlation": {
            "by_method": dict(rs.correlation.by_method),
            "coverage": rs.correlation.coverage,
            "attribution_rate": rs.correlation.attribution_rate,
            "unattributed_verdicts": len(rs.correlation.unattributed_verdict_ids),
        },
        "latency_p50_s": card.latency_p50_s,
        "latency_p95_s": card.latency_p95_s,
        "slices": [slice_to_dict(s) for s in card.slices],
    }


@dataclass(frozen=True)
class RunComparison:
    a: RunScore
    b: RunScore
    comparison: Comparison


def compare_runs(
    store: Store, settings: Settings, run_a: str, run_b: str, corpus_path: Path | None = None
) -> RunComparison:
    """A/B compare two runs (FR-12). Both must have used the identical corpus."""
    a = score_run(store, settings, run_a, corpus_path)
    b = score_run(store, settings, run_b, corpus_path)
    if a.run.id == b.run.id:
        raise ScoringError("A and B are the same run")
    if a.run.corpus_hash != b.run.corpus_hash:
        raise ScoringError(
            f"runs used different corpora ({a.run.corpus_hash[:12]} vs "
            f"{b.run.corpus_hash[:12]}); a paired comparison needs the same cases"
        )
    return RunComparison(a=a, b=b, comparison=compare(a.card, b.card))


def comparison_to_dict(rc: RunComparison) -> dict[str, Any]:
    c = rc.comparison

    def test(t: PairedTest | None) -> dict[str, Any] | None:
        return None if t is None else {"a_only": t.a_only, "b_only": t.b_only, "p": t.p_value}

    return {
        "a": {"id": rc.a.run.id, "notes": rc.a.run.notes,
              "snapshot_available": rc.a.snapshot_available},
        "b": {"id": rc.b.run.id, "notes": rc.b.run.notes,
              "snapshot_available": rc.b.snapshot_available},
        "corpus_hash": rc.a.run.corpus_hash,
        "method": "exact McNemar (paired), two-sided; per-slice p not corrected",
        "alpha": c.alpha,
        "paired_cases": c.paired_cases,
        "excluded_case_ids": list(c.excluded_case_ids),
        "latency_p50_delta_s": c.latency_p50_delta_s,
        "latency_p95_delta_s": c.latency_p95_delta_s,
        "slices": [
            {
                "dimension": s.dimension, "value": s.value,
                "positives": s.positives, "negatives": s.negatives,
                "recall_a": s.recall_a, "recall_b": s.recall_b,
                "recall_test": test(s.recall_test), "recall_verdict": s.recall_verdict,
                "fpr_a": s.fpr_a, "fpr_b": s.fpr_b,
                "fpr_test": test(s.fpr_test), "fpr_verdict": s.fpr_verdict,
            }
            for s in c.slices
        ],
    }  # fmt: skip


def gate_run(
    store: Store,
    settings: Settings,
    run_id: str,
    corpus_path: Path | None = None,
    *,
    now: datetime | None = None,
) -> tuple[RunScore, GateReport]:
    """Evaluate the promotion gate (FR-16, FR-17) on one scored run."""
    rs = score_run(store, settings, run_id, corpus_path)
    g = settings.gate
    thresholds = GateThresholds(
        min_observe_days=g.min_observe_days,
        min_critical_recall=g.min_critical_recall,
        max_benign_block_fpr=g.max_benign_block_fpr,
        max_canary_leaks=g.max_canary_leaks,
        min_cases_per_category=g.min_cases_per_category,
        proposed_rule_pack=g.proposed_rule_pack,
        propose_human_approval=g.propose_human_approval,
        propose_hilt_min_severity=g.propose_hilt_min_severity,
        evaluate_on=g.evaluate_on,
    )
    declared = (
        DeclaredConfig.model_validate(rs.run.declared_config) if rs.run.declared_config else None
    )
    evidence = GateEvidence(
        run_id=rs.run.id,
        card=rs.card,
        snapshot_available=rs.snapshot_available,
        verdicts_in_window=rs.verdicts_in_window,
        overlapping_runs=rs.overlapping_runs,
        observe_since=store.first_snapshot_run_start(),
        observe_mode_verified=False,  # needs snapshot parsing; DefenseClaw format pending M0
        declared=declared,
        now=now or datetime.now(UTC),
        responses_stubbed=any(
            (r.response_text or "").startswith(STUB_REPLY_PREFIX) for r in store.results(rs.run.id)
        ),
    )
    report = evaluate_gate(
        evidence,
        thresholds,
        connector=settings.defenseclaw.connector,
        categories=[c.value for c in Category],
    )
    return rs, report


ACCURACY_CRITERIA = ("evidence_quality", "critical_recall", "benign_block_fpr", "canary_leaks")


@dataclass(frozen=True)
class CheckResult:
    run_id: str
    accuracy: tuple[Criterion, ...]
    regression: RegressionResult

    @property
    def accuracy_passed(self) -> bool:
        return all(c.status == "PASS" for c in self.accuracy)

    @property
    def ok(self) -> bool:
        return self.accuracy_passed and not self.regression.regressed


def _accuracy(report: GateReport) -> tuple[Criterion, ...]:
    return tuple(c for c in report.criteria if c.name in ACCURACY_CRITERIA)


def check_run(store: Store, settings: Settings, run_id: str) -> CheckResult:
    """CI / nightly check (FR-20, FR-21): accuracy criteria + regression vs last passing run."""
    rs, report = gate_run(store, settings, run_id)
    baseline: RunScore | None = None
    for candidate in store.earlier_runs(rs.run.started_at, rs.run.corpus_hash):
        try:
            cand_rs, cand_report = gate_run(store, settings, candidate.id)
        except (ScoringError, CorpusError):
            continue
        if all(c.status == "PASS" for c in _accuracy(cand_report)):
            baseline = cand_rs
            break
    regression = detect_regression(
        rs.card.overall, baseline.card.overall if baseline else None,
        baseline.run.id if baseline else None,
        max_recall_drop=settings.regression.max_recall_drop,
        max_fpr_rise=settings.regression.max_fpr_rise,
    )  # fmt: skip
    return CheckResult(run_id=rs.run.id, accuracy=_accuracy(report), regression=regression)


def check_message(result: CheckResult) -> str:
    """Alert text: run id, criteria and deltas only (no prompt/response/canary text)."""
    lines = [f"ClawShield check {'OK' if result.ok else 'FAILED'} for run {result.run_id}"]
    lines += [f"- {c.status}: {c.name} ({c.observed})" for c in result.accuracy]
    reg = result.regression
    if reg.baseline_run_id:
        lines.append(f"- regression vs {reg.baseline_run_id}: {'YES' if reg.regressed else 'no'}")
        lines += [f"  - {r}" for r in reg.reasons]
    else:
        lines.append("- regression: no earlier passing run to compare")
    return chr(10).join(lines)  # newline-separated Slack text
