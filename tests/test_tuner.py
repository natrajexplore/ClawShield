import ast
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

import clawshield.tuner.recommend as recommend_module
from clawshield import cli
from clawshield.cli import app
from clawshield.core.correlate import CaseCorrelation
from clawshield.core.models import Case, Severity, TargetResult, Verdict
from clawshield.core.score import CaseInput
from clawshield.storage.db import Store
from clawshield.tuner.recommend import PACK_DIR_PLACEHOLDER, recommend_suppressions

T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)


def case(cid: str, label: str) -> Case:
    cat, sev = ("benign", "low") if label == "benign" else ("llm01_direct", "high")
    return Case.model_validate(
        {"id": cid, "text": cid, "label": label, "category": cat, "expected_severity": sev}
    )


def v(
    vid: str, rule: str | None, sev: Severity = Severity.HIGH, direction: str = "prompt"
) -> Verdict:
    return Verdict(id=vid, source="t", ts=T0, connector="openclaw", direction=direction,  # type: ignore[arg-type]
                   severity=sev, rule_id=rule, action="observe")  # fmt: skip


def item(cid: str, label: str, vids: tuple[str, ...], *, method: str = "session",
         error: str | None = None) -> CaseInput:  # fmt: skip
    result = TargetResult(case_id=cid, sent_at=T0, received_at=T0 + timedelta(seconds=1),
                          response_text=None if error else "r", error=error)  # fmt: skip
    corr = CaseCorrelation(case_id=cid, method=method, verdict_ids=vids)  # type: ignore[arg-type]
    return CaseInput(case=case(cid, label), result=result, correlation=corr)


def recommend(inputs: list[CaseInput], verdicts: dict[str, Verdict], **kw: Any) -> list[Any]:
    args: dict[str, Any] = {"detected_min": Severity.MEDIUM, "connector": "openclaw"}
    args.update(kw)
    return recommend_suppressions(inputs, verdicts, **args)


# --- recommendations --------------------------------------------------------------------------

VERDICTS = {
    "f1": v("f1", "PI-GENERIC"), "f2": v("f2", "PI-GENERIC"), "f3": v("f3", "PI-OTHER"),
    "t1": v("t1", "PI-GENERIC"),                     # m1: caught only by PI-GENERIC
    "t2": v("t2", "PI-GENERIC"), "t3": v("t3", "JB-1"),  # m2: caught by two rules
    "low": v("low", "PI-LOW", Severity.LOW),          # below detection threshold
}  # fmt: skip
INPUTS = [
    item("b1", "benign", ("f1",)),
    item("b2", "benign", ("f2", "f3")),
    item("b3", "benign", ("low",)),
    item("m1", "malicious", ("t1",)),
    item("m2", "malicious", ("t2", "t3")),
]


def test_noisy_rule_gets_narrow_rule_with_evidence_and_risk() -> None:
    recs = recommend(INPUTS, VERDICTS)
    top = recs[0]
    assert (top.kind, top.target) == ("narrow_rule", "PI-GENERIC")
    assert top.evidence_case_ids == ("b1", "b2")
    assert top.lost_detection_case_ids == ("m1",)  # m2 is also caught by JB-1
    assert "suppressions do not apply to rule findings" in top.rationale
    assert "only detection of 1 malicious case" in top.rationale
    assert top.proposed_command == (
        "defenseclaw setup guardrail --non-interactive --connector openclaw --mode observe "
        f"--rule-pack-dir {PACK_DIR_PLACEHOLDER} --restart"
    )
    assert "--mode action" not in top.proposed_command


def test_rule_with_no_dependants_says_so_and_sorts_by_fp_count() -> None:
    recs = recommend(INPUTS, VERDICTS)
    assert [r.target for r in recs] == ["PI-GENERIC", "PI-OTHER"]
    assert "No malicious case in this run depends on it alone" in recs[1].rationale


def test_below_threshold_hits_are_not_false_positives() -> None:
    assert "PI-LOW" not in {r.target for r in recommend(INPUTS, VERDICTS)}


def test_min_false_positives() -> None:
    assert [r.target for r in recommend(INPUTS, VERDICTS, min_false_positives=2)] == ["PI-GENERIC"]
    with pytest.raises(ValueError):
        recommend(INPUTS, VERDICTS, min_false_positives=0)


def test_excluded_cases_and_rule_less_verdicts_are_ignored() -> None:
    verdicts = {"a": v("a", "AMB"), "e": v("e", "ERR"), "n": v("n", None), "x": v("x", "PI")}
    inputs = [
        item("b1", "benign", ("a",), method="ambiguous"),
        item("b2", "benign", ("e",), error="Timeout"),
        item("b3", "benign", ("n",)),
        # m1 is caught by PI and by a rule-less verdict: PI is not its sole detection.
        item("m1", "malicious", ("x", "n")),
        item("b4", "benign", ("x",)),
    ]
    recs = recommend(inputs, verdicts)
    assert [r.target for r in recs] == ["PI"]
    assert recs[0].lost_detection_case_ids == ()


def test_judge_finding_gets_valid_anchored_suppression_yaml() -> None:
    verdicts = {"j": v("j", "JUDGE-PII-PHONE"), "j2": v("j2", "JUDGE-PII-PHONE")}
    recs = recommend([item("b1", "benign", ("j",)), item("b2", "benign", ("j2",))], verdicts)
    (rec,) = recs
    assert rec.kind == "suppress"
    snippet = rec.proposed_change.split("\n", 1)[1]
    entry = yaml.safe_load(snippet)["finding_suppressions"][0]
    assert entry["finding_pattern"] == r"^JUDGE\-PII\-PHONE$"
    assert entry["finding_pattern"] not in (".*", ".+", "^.*$")
    assert "b1, b2" in entry["reason"]


def test_tool_call_findings_mention_alert_at_with_blast_radius() -> None:
    verdicts = {"t": v("t", "CMD-PIPE-CURL", direction="tool_call")}
    (rec,) = recommend([item("b1", "benign", ("t",))], verdicts)
    assert "defenseclaw guardrail alert-at HIGH --connector openclaw" in rec.proposed_change
    assert "affects every rule" in rec.proposed_change


HOSTILE = "JUDGE-X\"\n  - id: evil\n    finding_pattern: '.*'  $(rm -rf ~) `id`"


def test_hostile_rule_id_cannot_inject_into_yaml_or_command() -> None:
    (rec,) = recommend([item("b1", "benign", ("h",))], {"h": v("h", HOSTILE)})
    entries = yaml.safe_load(rec.proposed_change.split("\n", 1)[1])["finding_suppressions"]
    assert len(entries) == 1  # the injected "- id: evil" entry did not appear
    assert entries[0]["finding_pattern"] != ".*"
    assert "rm -rf" not in rec.proposed_command and "$(" not in rec.proposed_command


def test_connector_is_shell_quoted() -> None:
    (rec,) = recommend(INPUTS[:1], VERDICTS, connector="open claw; rm -rf ~")
    assert "--connector 'open claw; rm -rf ~'" in rec.proposed_command


# --- FR-15: proposed, never executed ------------------------------------------------------------


def test_tuner_module_cannot_execute_commands() -> None:
    tree = ast.parse(Path(recommend_module.__file__).read_text(encoding="utf-8"))
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    imported |= {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not imported & {"subprocess", "os", "clawshield.shell", "shutil"}


@pytest.fixture
def no_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("FR-15 violated: a subprocess was started")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)


@pytest.mark.usefixtures("no_subprocess")
def test_recommend_starts_no_subprocess() -> None:
    assert recommend(INPUTS, VERDICTS)


# --- CLI ------------------------------------------------------------------------------------------

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
    args = ["run", "--config", str(path), "--corpus", str(SEED)]
    assert runner.invoke(app, args).exit_code == 0
    store = Store(tmp_path / "c.db")
    results = store.results(store.get_run("latest").id)
    verdicts = [
        Verdict(id=f"v-{r.case_id}", source="t", ts=r.sent_at, connector="openclaw",
                direction="prompt", severity=Severity.HIGH, rule_id="PI-GENERIC",
                action="observe", session_id=r.session_id)
        for r in results if r.case_id.startswith(("bl-0", "d-0"))
    ]  # fmt: skip
    store.add_verdicts(verdicts, ingested_at=datetime.now(UTC))
    return {"config": str(path)}


@pytest.mark.usefixtures("no_subprocess")
def test_cli_tune_text_and_json(lab: dict[str, Any]) -> None:
    text = runner.invoke(app, ["tune", "--config", lab["config"]])
    assert text.exit_code == 0, text.output
    assert "1 recommendation(s). Review before running anything." in text.output
    assert "narrow_rule  PI-GENERIC" in text.output
    assert "then, in observe mode: defenseclaw setup guardrail" in text.output

    data = json.loads(runner.invoke(app, ["tune", "--json", "--config", lab["config"]]).stdout)
    (rec,) = data["recommendations"]
    assert rec["target"] == "PI-GENERIC"
    assert all(c.startswith("bl-") for c in rec["evidence_case_ids"])
    assert rec["lost_detection_case_ids"] and all(
        c.startswith("d-") for c in rec["lost_detection_case_ids"]
    )


def test_cli_tune_errors(tmp_path: Path) -> None:
    config = tmp_path / "c.yaml"
    config.write_text(yaml.safe_dump({
        "target": {"kind": "mock", "name": "m"}, "targets": {"allowlist": ["m"]},
        "storage": {"db_path": str(tmp_path / "none.db")},
    }), encoding="utf-8")  # fmt: skip
    result = runner.invoke(app, ["tune", "--config", str(config)])
    assert result.exit_code == 1 and "no runs yet" in result.output


def test_cli_tune_unknown_run_and_changed_corpus(lab: dict[str, Any], tmp_path: Path) -> None:
    missing = runner.invoke(app, ["tune", "--run", "nope", "--config", lab["config"]])
    assert missing.exit_code == 1 and "'nope' not found" in missing.output
    other = tmp_path / "other.jsonl"
    other.write_text(SEED.read_text(encoding="utf-8").split("\n", 1)[1], encoding="utf-8")
    changed = runner.invoke(app, ["tune", "--corpus", str(other), "--config", lab["config"]])
    assert changed.exit_code == 1 and "has changed since run" in changed.output


def test_cli_tune_warns_when_there_is_nothing_to_tune(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "fresh.yaml"
    config.write_text(yaml.safe_dump({
        "target": {"kind": "mock", "name": "m"}, "targets": {"allowlist": ["m"]},
        "runner": {"inter_case_delay_ms": 0}, "canaries": ["CANARY-7F3A"],
        "storage": {"db_path": str(tmp_path / "fresh.db")},
    }), encoding="utf-8")  # fmt: skip
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})
    run_args = ["run", "--config", str(config), "--corpus", str(SEED)]
    assert runner.invoke(app, run_args).exit_code == 0
    result = runner.invoke(app, ["tune", "--config", str(config)])
    assert result.exit_code == 0
    assert "0 recommendation(s)" in result.output
    assert "no verdicts in this run's window; nothing to tune" in result.output
