"""Score a stored run: load results + verdicts, correlate, score (FR-10, FR-11).

Labels come from the corpus file the run used. The file must still hash to the run's
recorded corpus_hash; otherwise edited labels would silently change the scores.
"""

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from clawshield.config import Settings
from clawshield.core.correlate import DEFAULT_PRE_S, CorrelationReport, correlate
from clawshield.core.score import CaseInput, Interval, Scorecard, SliceScore, score
from clawshield.redteam.corpus import load_corpus
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
        grace_s=grace_s, pre_s=DEFAULT_PRE_S,
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
