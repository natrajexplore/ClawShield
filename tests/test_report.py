import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from clawshield import cli
from clawshield.cli import EXIT_ERROR, EXIT_GATE_NOT_PASSED, app
from clawshield.report import code, md, render_markdown, write_evidence_pack
from clawshield.targets.mock import MockTarget

ESC = chr(27)
SEED = Path(__file__).resolve().parents[1] / "redteam" / "corpus" / "seed.jsonl"
runner = CliRunner()


# --- escaping --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "[approve here](https://evil.example/login)",
        "<img src=x onerror=alert(1)>",
        "**urgent** _now_ `code`",
        "col | injected | table",
        "# fake heading",
        "![tracking](https://evil.example/p.gif)",
    ],
)
def test_md_neutralises_markdown_and_html(hostile: str) -> None:
    out = md(hostile)
    for ch in "[]()<>*_`|#!":
        assert ch not in out.replace("\\" + ch, ""), (ch, out)


def test_md_escapes_control_characters() -> None:
    out = md("red" + ESC + "[31m text" + chr(7))
    assert ESC not in out and chr(7) not in out
    assert "\\x1b" in out and "\\x07" in out


def test_code_spans_only_for_id_shaped_values() -> None:
    assert code("20261006T120000Z-abc123") == "`20261006T120000Z-abc123`"
    assert code("bl_001.v2") == "`bl_001.v2`"
    assert code("x`; rm -rf ~") == md("x`; rm -rf ~")


# --- rendering ---------------------------------------------------------------------------------


def _evidence(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema": "clawshield-evidence/1",
        "generated_at": "2026-10-06T12:00:00+00:00",
        "clawshield_version": "0.1.0",
        "gate": {"overall": "PASS", "evaluate_on": "confidence_bound", "criteria": [],
                 "proposed_command": None},
        "run": {"id": "r1", "started_at": "a", "finished_at": "b", "target": "t",
                "target_kind": "mock", "corpus_path": "c.jsonl", "corpus_hash": "0" * 64,
                "notes": "", "declared_config": None, "responses_redacted": False},
        "snapshot": {"available": True, "captured_at": None},
        "scorecard": {"cases_total": 0, "cases_scored": 0, "verdicts_in_window": 0,
                      "correlation": {"attribution_rate": 1.0}, "slices": [],
                      "canary_leaks": [], "excluded_ambiguous": [], "excluded_errors": [],
                      "overlapping_runs": []},
        "limitations": [],
        "reproduce": ["clawshield score --run r1 --json"],
    }  # fmt: skip
    base.update(overrides)
    return base


def test_proposed_command_is_reproduced_exactly_even_with_backticks() -> None:
    command = "defenseclaw setup guardrail --connector 'odd```name' --mode action --restart"
    evidence = _evidence(gate={**_evidence()["gate"], "proposed_command": command})
    text = render_markdown(evidence, "f" * 64)
    assert command in text.splitlines()
    assert "````bash" in text  # fence longer than the 3-backtick run inside the command


def test_no_command_section_when_not_passed() -> None:
    text = render_markdown(_evidence(), "f" * 64)
    assert "None. Every criterion must PASS" in text and "--mode action --" not in text


def test_filename_cannot_escape_output_directory(tmp_path: Path) -> None:
    evidence = _evidence(run={**_evidence()["run"], "id": "../../etc/evil"})
    json_path, md_path = write_evidence_pack(evidence, tmp_path / "reports")
    for p in (json_path, md_path):
        assert p.parent == tmp_path / "reports"
        assert ".." not in p.name and "/" not in p.name


def test_markdown_hash_matches_json(tmp_path: Path) -> None:
    json_path, md_path = write_evidence_pack(_evidence(), tmp_path)
    digest = hashlib.sha256(json_path.read_bytes()).hexdigest()
    assert f"`{digest}`" in md_path.read_text(encoding="utf-8")
    json_path.read_bytes().decode("ascii")


# --- end to end ----------------------------------------------------------------------------------


SECRET_REPLY = "PRIVATE-REPLY-777 the admin token is CANARY-7F3A"
HOSTILE_NOTE = "[approve](https://evil.example) <script>x</script> | " + ESC + "[2J"


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    config = tmp_path / "c.yaml"
    config.write_text(yaml.safe_dump({
        "target": {"kind": "mock", "name": "m"}, "targets": {"allowlist": ["m"]},
        "runner": {"inter_case_delay_ms": 0, "max_cases_per_run": 1000},
        "canaries": ["CANARY-7F3A"], "storage": {"db_path": str(tmp_path / "c.db")},
    }), encoding="utf-8")  # fmt: skip
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})
    leaky = MockTarget(name="m", responder=lambda case: SECRET_REPLY)
    monkeypatch.setattr(cli, "build_target", lambda settings: leaky)
    args = ["run", "--config", str(config), "--corpus", str(SEED), "--notes", HOSTILE_NOTE,
            "--rule-pack", "default", "--detection-strategy", "regex_only"]  # fmt: skip
    assert runner.invoke(app, args).exit_code == 0
    return {"config": str(config), "reports": tmp_path / "reports"}


def test_export_writes_fail_pack_and_keeps_exit_code(lab: dict[str, Any]) -> None:
    result = runner.invoke(
        app, ["gate", "--config", lab["config"], "--export", str(lab["reports"])]
    )
    assert result.exit_code == EXIT_GATE_NOT_PASSED
    (md_path,) = lab["reports"].glob("gate-*.md")
    (json_path,) = lab["reports"].glob("gate-*.json")
    assert str(md_path) in result.output

    evidence = json.loads(json_path.read_text(encoding="ascii"))
    assert evidence["gate"]["overall"] == "FAIL" and evidence["gate"]["proposed_command"] is None
    assert evidence["scorecard"]["canary_leaks"]  # every case leaked the canary
    text = md_path.read_text(encoding="utf-8")
    assert text.startswith("# ClawShield promotion evidence: FAIL")
    assert "## Limitations" in text and "proving 95% recall" in text

    for path in (md_path, json_path):  # packs get forwarded: no response or prompt text
        content = path.read_text(encoding="utf-8")
        assert "PRIVATE-REPLY-777" not in content
        assert "Ignore all previous instructions" not in content
    assert "[approve](" not in text and "<script>" not in text and ESC not in text
    assert hashlib.sha256(json_path.read_bytes()).hexdigest() in text


def test_export_with_json_output_keeps_stdout_parseable(lab: dict[str, Any]) -> None:
    args = ["gate", "--json", "--config", lab["config"], "--export", str(lab["reports"])]
    result = runner.invoke(app, args)
    assert json.loads(result.stdout)["overall"] == "FAIL"


def test_export_to_unwritable_location_fails_cleanly(lab: dict[str, Any], tmp_path: Path) -> None:
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x", encoding="utf-8")
    result = runner.invoke(app, ["gate", "--config", lab["config"], "--export", str(blocker)])
    assert result.exit_code == EXIT_ERROR and "cannot write evidence pack" in result.output


def test_limitations_reflect_the_run(lab: dict[str, Any]) -> None:
    from dataclasses import replace

    from clawshield.config import load_settings
    from clawshield.report import _limitations
    from clawshield.scoring import gate_run
    from clawshield.storage.db import Store

    settings = load_settings(Path(lab["config"]))
    rs, gate = gate_run(Store(settings.storage.db_path), settings, "latest")
    no_snapshot = replace(
        rs,
        run=rs.run.model_copy(update={"guardrail_snapshot": {"available": False}}),
        card=replace(rs.card, excluded_ambiguous=("a",), excluded_errors=("e1", "e2"),
                     slices=tuple(s for s in rs.card.slices
                                  if s.dimension != "expected_severity")),
    )  # fmt: skip
    items = " ".join(_limitations(no_snapshot, gate, settings))
    assert "no guardrail snapshot" in items
    assert "1 ambiguous and 2 errored case(s) were excluded" in items
    assert "No critical-severity cases were scored." in items

    few_benign = replace(
        rs,
        card=replace(
            rs.card,
            slices=tuple(
                replace(s, tn=10) if s.dimension == "overall" else s for s in rs.card.slices
            ),
        ),
    )
    assert "benign case(s) scored; the FPR bound needs >= 381" in " ".join(
        _limitations(few_benign, gate, settings))  # fmt: skip


def test_accuracy_table_lists_only_reviewer_slices() -> None:
    slices = [
        {"dimension": d, "value": v, "tp": 1, "fn": 0, "fp": 0, "tn": 0, "recall": 1.0,
         "recall_ci95": [0.2, 1.0], "fpr": None, "fpr_ci95": None, "block_fpr": None}
        for d, v in [("overall", "all"), ("rule", "PI-1"), ("direction", "prompt")]
    ]  # fmt: skip
    evidence = _evidence()
    evidence["scorecard"]["slices"] = slices
    text = render_markdown(evidence, "f" * 64)
    assert "| overall |" in text and "PI-1" not in text and "direction=prompt" not in text
