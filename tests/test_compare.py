import json
from datetime import UTC, datetime
from math import comb
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from clawshield import cli
from clawshield.cli import EXIT_ERROR, app
from clawshield.core.compare import compare, mcnemar_exact
from clawshield.core.models import Severity, Verdict
from clawshield.core.score import CaseOutcome, Scorecard
from clawshield.storage.db import Store

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = REPO_ROOT / "redteam" / "corpus" / "seed.jsonl"


def card(
    outcomes: list[CaseOutcome], p50: float | None = 1.0, p95: float | None = 2.0
) -> Scorecard:
    return Scorecard(
        cases_total=len(outcomes), excluded_ambiguous=(), excluded_errors=(),
        leaked_case_ids=(), latency_p50_s=p50, latency_p95_s=p95, slices=(),
        outcomes=tuple(outcomes),
    )  # fmt: skip


def oc(cid: str, label: str, detected: bool, category: str = "jailbreak") -> CaseOutcome:
    sev = "low" if label == "benign" else "high"
    cat = "benign" if label == "benign" else category
    return CaseOutcome(cid, label, cat, sev, detected, False)


# --- exact McNemar ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a_only", "b_only", "expected"),
    [
        (0, 0, 1.0),
        (0, 6, 2 / 2**6),  # all 6 discordant favour B: 2 * (1/64)
        (1, 9, 2 * (comb(10, 0) + comb(10, 1)) / 2**10),
        (2, 8, 2 * (1 + 10 + 45) / 2**10),
        (5, 5, 1.0),  # capped at 1
        (9, 1, 2 * 11 / 2**10),  # symmetric
    ],
)
def test_mcnemar_exact_hand_values(a_only: int, b_only: int, expected: float) -> None:
    assert mcnemar_exact(a_only, b_only) == pytest.approx(expected)


def test_mcnemar_large_counts_do_not_overflow() -> None:
    assert 0 < mcnemar_exact(500, 520) < 1
    assert mcnemar_exact(0, 1100) == pytest.approx(0.0)


def test_mcnemar_rejects_negative() -> None:
    with pytest.raises(ValueError):
        mcnemar_exact(-1, 3)


# --- compare -------------------------------------------------------------------------------


def test_b_detects_more_attacks_significantly() -> None:
    a = card([oc(f"m{i}", "malicious", False) for i in range(8)] + [oc("b1", "benign", False)])
    b = card([oc(f"m{i}", "malicious", True) for i in range(8)] + [oc("b1", "benign", False)],
             p50=1.5, p95=3.5)  # fmt: skip
    c = compare(a, b)
    o = c.overall
    assert (o.recall_a, o.recall_b) == (0.0, 1.0)
    assert o.recall_test is not None and (o.recall_test.a_only, o.recall_test.b_only) == (0, 8)
    assert o.recall_test.p_value == pytest.approx(2 / 2**8)
    assert o.recall_verdict == "B better"
    assert o.fpr_verdict == "no significant difference"
    assert (c.latency_p50_delta_s, c.latency_p95_delta_s) == (0.5, 1.5)


def test_b_with_more_false_positives_is_worse() -> None:
    benign_a = [oc(f"b{i}", "benign", False) for i in range(10)]
    benign_b = [oc(f"b{i}", "benign", True) for i in range(10)]
    c = compare(card(benign_a), card(benign_b))
    assert c.overall.fpr_verdict == "B worse"
    assert c.overall.recall_verdict == "n/a"  # no malicious cases


def test_small_difference_is_not_significant() -> None:
    # 26 critical cases: 24 vs 25 detected is noise, not "B is better".
    a = card([oc(f"m{i}", "malicious", i >= 2) for i in range(26)])
    b = card([oc(f"m{i}", "malicious", i >= 1) for i in range(26)])
    o = compare(a, b).overall
    assert o.recall_b is not None and o.recall_a is not None and o.recall_b > o.recall_a
    assert o.recall_verdict == "no significant difference"


def test_discordance_in_both_directions_cancels() -> None:
    a = card([oc("m1", "malicious", True), oc("m2", "malicious", False)])
    b = card([oc("m1", "malicious", False), oc("m2", "malicious", True)])
    o = compare(a, b).overall
    assert o.recall_a == o.recall_b == 0.5
    assert o.recall_verdict == "no significant difference"


def test_pairs_only_cases_scored_in_both_runs() -> None:
    a = card([oc("m1", "malicious", True), oc("m2", "malicious", True)])
    b = card([oc("m2", "malicious", True), oc("m3", "malicious", False)])
    c = compare(a, b)
    assert c.paired_cases == 1
    assert c.excluded_case_ids == ("m1", "m3")


def test_category_and_severity_slices() -> None:
    a = card([oc("j1", "malicious", False), oc("d1", "malicious", False, "llm01_direct")])
    b = card([oc("j1", "malicious", True), oc("d1", "malicious", False, "llm01_direct")])
    c = compare(a, b)
    values = {(s.dimension, s.value) for s in c.slices}
    assert {("category", "jailbreak"), ("category", "llm01_direct"),
            ("expected_severity", "high")} <= values  # fmt: skip


def test_label_mismatch_rejected() -> None:
    with pytest.raises(ValueError, match="different labels"):
        compare(card([oc("x", "malicious", True)]), card([oc("x", "benign", True)]))


@pytest.mark.parametrize("alpha", [0, 1, -0.1])
def test_alpha_validated(alpha: float) -> None:
    with pytest.raises(ValueError, match="alpha"):
        compare(card([]), card([]), alpha=alpha)


def test_missing_latency_gives_none_delta() -> None:
    c = compare(card([], p50=None, p95=None), card([]))
    assert c.latency_p50_delta_s is None and c.latency_p95_delta_s is None


# --- CLI end to end ---------------------------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    config = {
        "target": {"kind": "mock", "name": "lab-mock"},
        "targets": {"allowlist": ["lab-mock"]},
        # grace 0: back-to-back test runs then do not share a correlation window.
        "runner": {"inter_case_delay_ms": 0, "correlation_grace_s": 0},
        "canaries": ["CANARY-7F3A"],
        "storage": {"db_path": str(tmp_path / "c.db")},
    }
    path = tmp_path / "clawshield.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})
    return {"config": str(path), "db": tmp_path / "c.db", "tmp": tmp_path}


def _new_run(lab: dict[str, Any], notes: str, corpus: Path = SEED) -> str:
    args = ["run", "--config", lab["config"], "--corpus", str(corpus), "--notes", notes]
    assert runner.invoke(app, args).exit_code == 0
    return Store(lab["db"]).get_run("latest").id


def _flag_all_attacks(lab: dict[str, Any], run_id: str) -> None:
    store = Store(lab["db"])
    verdicts = [
        Verdict(id=f"v-{r.case_id}", source="test", ts=r.sent_at, connector="openclaw",
                direction="prompt", severity=Severity.CRITICAL, action="observe",
                session_id=r.session_id)
        for r in store.results(run_id) if not r.case_id.startswith("b")
    ]  # fmt: skip
    store.add_verdicts(verdicts, ingested_at=datetime.now(UTC))


def test_cli_compare_end_to_end(lab: dict[str, Any]) -> None:
    run_a = _new_run(lab, "regex_only")
    run_b = _new_run(lab, "regex_judge")
    _flag_all_attacks(lab, run_b)
    result = runner.invoke(app, ["compare", run_a, run_b, "--config", lab["config"]])
    assert result.exit_code == 0, result.output
    assert "notes: regex_only" in result.output and "notes: regex_judge" in result.output
    assert "not corrected for multiple comparisons" in result.output
    overall = next(
        line for line in result.output.splitlines() if line.strip().startswith("overall")
    )
    assert "0.0% -> 100.0%" in overall and "B better" in overall

    as_json = runner.invoke(app, ["compare", run_a, run_b, "--json", "--config", lab["config"]])
    data = json.loads(as_json.stdout)
    assert data["paired_cases"] == 166
    first = data["slices"][0]
    assert first["recall_verdict"] == "B better" and first["recall_test"]["b_only"] == 94


def test_cli_compare_refuses_different_corpora(lab: dict[str, Any]) -> None:
    run_a = _new_run(lab, "a")
    other = lab["tmp"] / "other.jsonl"
    other.write_text(SEED.read_text(encoding="utf-8").split("\n", 1)[1], encoding="utf-8")
    run_b = _new_run(lab, "b", corpus=other)
    result = runner.invoke(app, ["compare", run_a, run_b, "--config", lab["config"]])
    assert result.exit_code == EXIT_ERROR and "different corpora" in result.output


def test_cli_compare_errors(lab: dict[str, Any]) -> None:
    no_db = runner.invoke(app, ["compare", "a", "b", "--config", lab["config"]])
    assert no_db.exit_code == EXIT_ERROR and "no runs yet" in no_db.output
    run_a = _new_run(lab, "a")
    same = runner.invoke(app, ["compare", run_a, run_a, "--config", lab["config"]])
    assert same.exit_code == EXIT_ERROR and "same run" in same.output
    missing = runner.invoke(app, ["compare", run_a, "nope", "--config", lab["config"]])
    assert missing.exit_code == EXIT_ERROR and "'nope' not found" in missing.output


def test_cli_warns_when_runs_overlap_in_time(lab: dict[str, Any]) -> None:
    config = yaml.safe_load(Path(lab["config"]).read_text(encoding="utf-8"))
    config["runner"]["correlation_grace_s"] = 30  # back-to-back runs now share a window
    Path(lab["config"]).write_text(yaml.safe_dump(config), encoding="utf-8")
    run_a, run_b = _new_run(lab, "a"), _new_run(lab, "b")
    _flag_all_attacks(lab, run_b)
    result = runner.invoke(app, ["compare", run_a, run_b, "--config", lab["config"]])
    assert result.exit_code == 0
    assert f"run {run_a} overlaps run(s) {run_b}" in result.output
    assert "cross-attributed" in result.output
    # B's verdicts are not silently credited to A's cases: they are ambiguous or B's own.
    data = json.loads(
        runner.invoke(app, ["score", "--run", run_a, "--json", "--config", lab["config"]]).stdout
    )
    assert data["overlapping_runs"] == [run_b]
    overall = next(s for s in data["slices"] if s["dimension"] == "overall")
    assert overall["tp"] == 0
