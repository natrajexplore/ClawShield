import ast
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

import clawshield.tuner.strategy as strategy_module
from clawshield import cli
from clawshield.cli import app
from clawshield.core.compare import Comparison, compare
from clawshield.core.models import DeclaredConfig, Severity, Verdict
from clawshield.core.score import CaseOutcome, Scorecard
from clawshield.storage.db import Store
from clawshield.tuner.strategy import recommend_config, setup_command

DEFAULT = DeclaredConfig(rule_pack="default", detection_strategy="regex_only")
JUDGE = DeclaredConfig(rule_pack="default", detection_strategy="regex_judge")
STRICT = DeclaredConfig(rule_pack="strict", detection_strategy="regex_only")


def oc(cid: str, label: str, detected: bool, sev: str = "high") -> CaseOutcome:
    cat = "benign" if label == "benign" else "jailbreak"
    return CaseOutcome(cid, label, cat, "low" if label == "benign" else sev, detected, False)


def card(outcomes: list[CaseOutcome], p50: float = 1.0) -> Scorecard:
    return Scorecard(cases_total=len(outcomes), excluded_ambiguous=(), excluded_errors=(),
                     leaked_case_ids=(), latency_p50_s=p50, latency_p95_s=p50, slices=(),
                     outcomes=tuple(outcomes))  # fmt: skip


def comparison(
    *,
    mal_a: int, mal_b: int, ben_a: int = 0, ben_b: int = 0, n_mal: int = 12, n_ben: int = 12,
    crit_a: int | None = None, crit_b: int | None = None, p50_b: float = 1.0,
) -> Comparison:  # fmt: skip
    """Build A/B where the first k cases of each group are detected."""

    def side(mal: int, ben: int, crit: int | None) -> list[CaseOutcome]:
        cases = [oc(f"m{i}", "malicious", i < mal) for i in range(n_mal)]
        cases += [oc(f"b{i}", "benign", i < ben) for i in range(n_ben)]
        if crit is not None:
            cases += [oc(f"c{i}", "malicious", i < crit, "critical") for i in range(12)]
        return cases

    return compare(card(side(mal_a, ben_a, crit_a)), card(side(mal_b, ben_b, crit_b), p50=p50_b))


def decide(
    c: Comparison, a: DeclaredConfig | None = DEFAULT, b: DeclaredConfig | None = JUDGE
) -> Any:
    return recommend_config(c, a, b, connector="openclaw")


# --- decision rules -------------------------------------------------------------------------


def test_adopt_b_when_recall_better_and_fpr_not_worse() -> None:
    rec = decide(comparison(mal_a=2, mal_b=12))
    assert rec.decision == "adopt_b" and rec.config == JUDGE
    assert rec.proposed_command is not None


def test_adopt_b_when_fpr_better_and_recall_not_worse() -> None:
    rec = decide(comparison(mal_a=10, mal_b=10, ben_a=10, ben_b=0), b=STRICT)
    assert rec.decision == "adopt_b"
    assert "lower false-positive rate" in rec.reasons[0]


def test_trade_off_when_recall_better_but_fpr_worse() -> None:
    rec = decide(comparison(mal_a=2, mal_b=12, ben_a=0, ben_b=10))
    assert rec.decision == "trade_off" and rec.proposed_command is None
    assert "clawshield tune" in rec.reasons[0]


def test_keep_a_when_no_significant_difference() -> None:
    rec = decide(comparison(mal_a=10, mal_b=11, ben_a=1, ben_b=1))
    assert rec.decision == "keep_a" and rec.proposed_command is None
    assert "cannot separate A and B" in rec.reasons[0]


def test_keep_a_when_b_worse() -> None:
    assert decide(comparison(mal_a=12, mal_b=2)).decision == "keep_a"


def test_critical_recall_regression_vetoes_overall_gain() -> None:
    # Overall recall rises significantly (30 non-critical gains vs 10 critical losses),
    # but critical recall drops 12 -> 2: the veto must win.
    c = comparison(mal_a=0, mal_b=30, crit_a=12, crit_b=2, n_mal=40)
    assert c.overall.recall_verdict == "B better"
    rec = decide(c)
    assert rec.decision == "keep_a"
    assert "critical-severity" in rec.reasons[0]


def test_latency_change_is_reported() -> None:
    rec = decide(comparison(mal_a=2, mal_b=12, p50_b=1.75))
    assert any("+0.750s" in r for r in rec.reasons)


def test_undeclared_or_identical_b_config_gives_no_command() -> None:
    undeclared = decide(comparison(mal_a=2, mal_b=12), b=None)
    assert undeclared.proposed_command is None
    assert any("--rule-pack and --detection-strategy" in r for r in undeclared.reasons)
    same = decide(comparison(mal_a=2, mal_b=12), a=JUDGE, b=JUDGE)
    assert same.proposed_command is None and any("same configuration" in r for r in same.reasons)


# --- proposed commands -----------------------------------------------------------------------


def test_setup_command_shapes() -> None:
    assert setup_command(STRICT, "openclaw") == (
        "defenseclaw setup guardrail --non-interactive --connector openclaw --mode observe "
        "--rule-pack strict --detection-strategy regex_only --restart"
    )
    judge = setup_command(JUDGE, "openclaw")
    assert "--judge-model <MODEL> --judge-api-key-env DEFENSECLAW_LLM_KEY" in judge
    custom = setup_command(
        DeclaredConfig(rule_pack="custom", detection_strategy="judge_first"), "x"
    )
    assert "--rule-pack-dir <YOUR_PACK_DIR>" in custom and "--rule-pack " not in custom
    for cmd in (judge, custom):
        assert "--mode observe" in cmd and "--mode action" not in cmd
    assert "--connector 'a b'" in setup_command(STRICT, "a b")


def test_declared_config_rejects_unknown_values() -> None:
    with pytest.raises(ValueError):
        DeclaredConfig(rule_pack="yolo", detection_strategy="regex_only")  # type: ignore[arg-type]


# --- FR-15 ------------------------------------------------------------------------------------


def test_strategy_module_cannot_execute_commands() -> None:
    tree = ast.parse(Path(strategy_module.__file__).read_text(encoding="utf-8"))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"subprocess", "os", "clawshield.shell", "shutil"}


# --- CLI --------------------------------------------------------------------------------------

runner = CliRunner()
SEED = Path(__file__).resolve().parents[1] / "redteam" / "corpus" / "seed.jsonl"


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    config = {
        "target": {"kind": "mock", "name": "lab-mock"},
        "targets": {"allowlist": ["lab-mock"]},
        "runner": {"inter_case_delay_ms": 0, "correlation_grace_s": 0},
        "canaries": ["CANARY-7F3A"],
        "storage": {"db_path": str(tmp_path / "c.db")},
    }
    path = tmp_path / "clawshield.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("FR-15 violated: a subprocess was started")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    return {"config": str(path), "db": tmp_path / "c.db"}


def _run(lab: dict[str, Any], *declare: str) -> str:
    args = ["run", "--config", lab["config"], "--corpus", str(SEED), *declare]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    return Store(lab["db"]).get_run("latest").id


def test_cli_recommends_judge_config_when_it_catches_more(lab: dict[str, Any]) -> None:
    run_a = _run(lab, "--rule-pack", "default", "--detection-strategy", "regex_only")
    run_b = _run(lab, "--rule-pack", "default", "--detection-strategy", "regex_judge")
    store = Store(lab["db"])
    assert store.get_run(run_b).declared_config == {
        "rule_pack": "default", "detection_strategy": "regex_judge"}  # fmt: skip
    store.add_verdicts(
        [Verdict(id=f"v{r.case_id}", source="t", ts=r.sent_at, connector="openclaw",
                 direction="prompt", severity=Severity.CRITICAL, action="observe",
                 session_id=r.session_id)
         for r in store.results(run_b) if not r.case_id.startswith("b")],
        ingested_at=datetime.now(UTC),
    )  # fmt: skip
    text = runner.invoke(app, ["recommend-config", run_a, run_b, "--config", lab["config"]])
    assert text.exit_code == 0, text.output
    assert "config: default / regex_judge" in text.output
    assert "decision: adopt_b" in text.output
    assert "--detection-strategy regex_judge --judge-model <MODEL>" in text.output

    data = json.loads(
        runner.invoke(
            app, ["recommend-config", run_a, run_b, "--json", "--config", lab["config"]]
        ).stdout
    )
    assert data["decision"] == "adopt_b" and data["config"]["detection_strategy"] == "regex_judge"


def test_cli_requires_both_declarations(lab: dict[str, Any]) -> None:
    result = runner.invoke(
        app, ["run", "--config", lab["config"], "--corpus", str(SEED), "--rule-pack", "strict"]
    )
    assert result.exit_code == 1 and "declare both" in result.output
    bad = runner.invoke(app, ["run", "--config", lab["config"], "--rule-pack", "yolo"])
    assert bad.exit_code != 0


def test_cli_undeclared_runs_keep_a(lab: dict[str, Any]) -> None:
    run_a, run_b = _run(lab), _run(lab)
    result = runner.invoke(app, ["recommend-config", run_a, run_b, "--config", lab["config"]])
    assert result.exit_code == 0
    assert "config: not declared" in result.output and "decision: keep_a" in result.output


def test_cli_recommend_config_errors(lab: dict[str, Any]) -> None:
    no_db = runner.invoke(app, ["recommend-config", "a", "b", "--config", lab["config"]])
    assert no_db.exit_code == 1 and "no runs yet" in no_db.output
    run_a = _run(lab)
    missing = runner.invoke(app, ["recommend-config", run_a, "zz", "--config", lab["config"]])
    assert missing.exit_code == 1 and "'zz' not found" in missing.output
    same = runner.invoke(app, ["recommend-config", run_a, run_a, "--config", lab["config"]])
    assert same.exit_code == 1 and "same run" in same.output
