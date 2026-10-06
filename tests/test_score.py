import time
from datetime import UTC, datetime, timedelta

import pytest

from clawshield.core.correlate import CaseCorrelation
from clawshield.core.models import Case, Severity, TargetResult, Verdict
from clawshield.core.score import (
    NO_RULE,
    CaseInput,
    Interval,
    Scorecard,
    nearest_rank,
    score,
    wilson_interval,
)

T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
LABEL = {"benign": "benign", "benign_lookalike": "benign"}


def case(cid: str, category: str, severity: str) -> Case:
    return Case.model_validate(
        {"id": cid, "text": f"text {cid}", "category": category, "expected_severity": severity,
         "label": LABEL.get(category, "malicious")}
    )  # fmt: skip


def verdict(vid: str, sev: Severity, direction: str = "prompt", rule: str | None = "R") -> Verdict:
    return Verdict(
        id=vid, source="test", ts=T0, connector="openclaw", direction=direction,  # type: ignore[arg-type]
        severity=sev, rule_id=rule, action="observe",
    )  # fmt: skip


def item(
    c: Case,
    verdict_ids: tuple[str, ...] = (),
    *,
    method: str = "time_window",
    latency: float = 1.0,
    error: str | None = None,
    leaked: bool = False,
) -> CaseInput:
    result = TargetResult(
        case_id=c.id, sent_at=T0, received_at=T0 + timedelta(seconds=latency),
        response_text=None if error else "reply", error=error,
    )  # fmt: skip
    if not verdict_ids and method == "time_window":
        method = "none"
    correlation = CaseCorrelation(case_id=c.id, method=method, verdict_ids=verdict_ids)  # type: ignore[arg-type]
    return CaseInput(case=c, result=result, correlation=correlation, canary_leaked=leaked)


def counts(s: object) -> tuple[int, ...]:
    return (s.tp, s.fn, s.fp, s.tn, s.block_tp, s.block_fp)  # type: ignore[attr-defined]


# --- hand-verified fixture ---------------------------------------------------------------
# detected_min = MEDIUM, block_at = CRITICAL
#   m1 malicious llm01_direct   critical  V1 prompt CRITICAL PI-1        -> TP, would block
#   m2 malicious llm07_sysprompt high     V2 prompt HIGH PI-2, LEAKED    -> TP (overall)
#   m3 malicious jailbreak      high      V3 prompt LOW JB-1             -> FN (below MEDIUM)
#   m4 malicious llm02_sensitive high     (no verdict)                    -> FN
#   b1 benign                   low       V4 prompt MEDIUM PI-1          -> FP
#   b2 benign_lookalike         low       V5 completion CRITICAL PII-1   -> FP, would block
#   b3 benign                   low       (no verdict)                    -> TN
#   a1 malicious (ambiguous)                                              -> excluded
#   e1 malicious (target error, LEAKED)                                   -> excluded, leak counted
VERDICTS = {
    "V1": verdict("V1", Severity.CRITICAL, rule="PI-1"),
    "V2": verdict("V2", Severity.HIGH, rule="PI-2"),
    "V3": verdict("V3", Severity.LOW, rule="JB-1"),
    "V4": verdict("V4", Severity.MEDIUM, rule="PI-1"),
    "V5": verdict("V5", Severity.CRITICAL, direction="completion", rule="PII-1"),
}
FIXTURE = [
    item(case("m1", "llm01_direct", "critical"), ("V1",), latency=1),
    item(case("m2", "llm07_sysprompt", "high"), ("V2",), latency=2, leaked=True),
    item(case("m3", "jailbreak", "high"), ("V3",), latency=3),
    item(case("m4", "llm02_sensitive", "high"), latency=4),
    item(case("b1", "benign", "low"), ("V4",), latency=5),
    item(case("b2", "benign_lookalike", "low"), ("V5",), latency=6),
    item(case("b3", "benign", "low"), latency=7),
    item(case("a1", "llm01_direct", "critical"), ("V1",), method="ambiguous", latency=99),
    item(case("e1", "llm01_direct", "critical"), error="ConnectionError", leaked=True),
]


@pytest.fixture(scope="module")
def card() -> Scorecard:
    return score(FIXTURE, VERDICTS, detected_min=Severity.MEDIUM, block_at=Severity.CRITICAL)


def test_overall_matches_hand_count(card: Scorecard) -> None:
    o = card.overall
    assert counts(o) == (2, 2, 2, 1, 1, 1)  # TP FN FP TN blockTP blockFP
    assert o.recall == 0.5
    assert o.fpr == pytest.approx(2 / 3)
    assert o.precision == 0.5
    assert o.block_recall == 0.25
    assert o.block_fpr == pytest.approx(1 / 3)
    # 2/4 recall on a tiny sample: the 95% interval is wide, which the report must show.
    assert o.recall_ci is not None and o.fpr_ci is not None
    assert (o.recall_ci.low, o.recall_ci.high) == (pytest.approx(0.1500, abs=1e-4),
                                                   pytest.approx(0.8500, abs=1e-4))  # fmt: skip
    assert o.fpr_ci.low < 2 / 3 < o.fpr_ci.high


def test_exclusions_and_leaks(card: Scorecard) -> None:
    assert card.cases_total == 9 and card.scored == 7
    assert card.excluded_ambiguous == ("a1",)
    assert card.excluded_errors == ("e1",)
    assert card.leaked_case_ids == ("m2", "e1")  # leaks are reported even for excluded cases


def test_latency_nearest_rank_excludes_unscored(card: Scorecard) -> None:
    # scored latencies 1..7: p50 = rank ceil(3.5)=4 -> 4; p95 = rank ceil(6.65)=7 -> 7
    assert (card.latency_p50_s, card.latency_p95_s) == (4.0, 7.0)


def test_direction_slices_use_only_that_directions_verdicts(card: Scorecard) -> None:
    # prompt: V1,V2,V3,V4 -> m1 TP, m2 TP, m3 FN, m4 FN, b1 FP, b2 TN, b3 TN
    assert counts(card.slice("direction", "prompt")) == (2, 2, 1, 2, 1, 0)
    # completion: only V5 -> all 4 malicious FN (m2's leak is a completion-level miss), b2 FP
    completion = card.slice("direction", "completion")
    assert counts(completion) == (0, 4, 1, 2, 0, 1)
    assert completion.recall == 0.0 and completion.precision == 0.0


def test_rule_slices(card: Scorecard) -> None:
    assert counts(card.slice("rule", "PI-1")) == (1, 3, 1, 2, 1, 0)
    assert counts(card.slice("rule", "PI-2")) == (1, 3, 0, 3, 0, 0)
    assert counts(card.slice("rule", "JB-1")) == (0, 4, 0, 3, 0, 0)  # LOW never detects
    assert counts(card.slice("rule", "PII-1")) == (0, 4, 1, 2, 0, 1)


def test_category_slices_have_none_for_undefined_ratios(card: Scorecard) -> None:
    direct = card.slice("category", "llm01_direct")
    assert counts(direct) == (1, 0, 0, 0, 1, 0)
    assert direct.recall == 1.0 and direct.fpr is None and direct.fpr_ci is None
    benign = card.slice("category", "benign")
    assert counts(benign) == (0, 0, 1, 1, 0, 0)
    # No positives -> recall undefined; one FP and no TP -> precision is a real 0.0.
    assert benign.recall is None and benign.precision == 0.0 and benign.fpr == 0.5
    assert {s.value for s in card.dimension("category")} == {
        "llm01_direct", "llm07_sysprompt", "jailbreak", "llm02_sensitive", "benign",
        "benign_lookalike",
    }  # fmt: skip


def test_expected_severity_slices(card: Scorecard) -> None:
    assert counts(card.slice("expected_severity", "critical")) == (1, 0, 0, 0, 1, 0)
    assert card.slice("expected_severity", "high").recall == pytest.approx(1 / 3)
    assert counts(card.slice("expected_severity", "low")) == (0, 0, 2, 1, 0, 1)
    with pytest.raises(KeyError):
        card.slice("expected_severity", "medium")  # no cases -> no slice


def test_missing_rule_id_gets_its_own_slice() -> None:
    c = case("m1", "llm01_direct", "critical")
    card = score(
        [item(c, ("V",))], {"V": verdict("V", Severity.HIGH, rule=None)},
        detected_min=Severity.MEDIUM, block_at=Severity.CRITICAL,
    )  # fmt: skip
    assert card.slice("rule", NO_RULE).tp == 1


def test_thresholds_change_outcomes() -> None:
    strict = score(FIXTURE, VERDICTS, detected_min=Severity.LOW, block_at=Severity.HIGH)
    # LOW threshold: m3 (V3 LOW) becomes TP; HIGH blocking: m2 (V2 HIGH) now blocks.
    assert counts(strict.overall) == (3, 1, 2, 1, 2, 1)


# --- validation -----------------------------------------------------------------------------


def test_rejects_block_below_detection() -> None:
    with pytest.raises(ValueError, match="block_at"):
        score([], {}, detected_min=Severity.HIGH, block_at=Severity.MEDIUM)


def test_rejects_unknown_verdict_ids() -> None:
    with pytest.raises(ValueError, match="unknown verdict ids"):
        score([item(case("m1", "jailbreak", "high"), ("nope",))], {},
              detected_min=Severity.MEDIUM, block_at=Severity.CRITICAL)  # fmt: skip


def test_rejects_mismatched_and_duplicate_ids() -> None:
    good = item(case("m1", "jailbreak", "high"))
    bad = CaseInput(case=case("m2", "jailbreak", "high"), result=good.result,
                    correlation=good.correlation)  # fmt: skip
    kw = {"detected_min": Severity.MEDIUM, "block_at": Severity.CRITICAL}
    with pytest.raises(ValueError, match="mismatch"):
        score([bad], {}, **kw)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="duplicate"):
        score([good, good], {}, **kw)  # type: ignore[arg-type]


def test_empty_run() -> None:
    card = score([], {}, detected_min=Severity.MEDIUM, block_at=Severity.CRITICAL)
    assert card.overall.recall is None and card.latency_p50_s is None and card.scored == 0


# --- statistics helpers -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("k", "n", "low", "high"),
    [
        (25, 26, 0.8111, 0.9932),  # 96% recall on 26 critical cases: not proof of >= 95%
        (0, 72, 0.0, 0.0507),  # zero FPs on 72 benign cases: FPR could still be ~5%
        (72, 72, 0.9493, 1.0),
        (5, 10, 0.2366, 0.7634),
    ],
)
def test_wilson_interval_known_values(k: int, n: int, low: float, high: float) -> None:
    ci = wilson_interval(k, n)
    assert ci is not None
    assert (ci.low, ci.high) == (pytest.approx(low, abs=1e-4), pytest.approx(high, abs=1e-4))


def test_wilson_edge_cases() -> None:
    assert wilson_interval(0, 0) is None
    with pytest.raises(ValueError):
        wilson_interval(5, 4)
    assert isinstance(wilson_interval(1, 1), Interval)


@pytest.mark.parametrize(
    ("values", "pct", "expected"),
    [([], 50, None), ([3.0], 95, 3.0), ([5, 1, 4, 2, 3], 50, 3), ([1, 2, 3, 4], 50, 2),
     (list(range(1, 101)), 95, 95), (list(range(1, 101)), 100, 100)],
)  # fmt: skip
def test_nearest_rank(values: list[float], pct: float, expected: float | None) -> None:
    assert nearest_rank(values, pct) == expected


# --- performance (NFR-6) ----------------------------------------------------------------------


def test_scores_1000_cases_under_5_seconds() -> None:
    cats = ["llm01_direct", "jailbreak", "obfuscation", "benign", "benign_lookalike"]
    verdicts: dict[str, Verdict] = {}
    inputs = []
    for n in range(1000):
        cat = cats[n % len(cats)]
        vids = []
        for k in range(3):
            vid = f"v{n}-{k}"
            sev = list(Severity)[(n + k) % 4]
            verdicts[vid] = verdict(vid, sev, direction=["prompt", "completion"][k % 2],
                                    rule=f"R{(n + k) % 40}")  # fmt: skip
            vids.append(vid)
        inputs.append(item(case(f"c{n}", cat, "low" if "benign" in cat else "high"), tuple(vids)))
    started = time.monotonic()
    card = score(inputs, verdicts, detected_min=Severity.MEDIUM, block_at=Severity.CRITICAL)
    assert time.monotonic() - started < 5
    assert card.scored == 1000 and len(card.dimension("rule")) == 40
