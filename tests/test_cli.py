from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from clawshield import __version__, cli
from clawshield.cli import EXIT_ERROR, EXIT_NOT_IMPLEMENTED, app, printable
from clawshield.storage.db import Store
from tests.conftest import db_bytes

runner = CliRunner()

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = REPO_ROOT / "redteam" / "corpus" / "seed.jsonl"
SEED_CASES = sum(1 for line in SEED.read_text(encoding="ascii").splitlines() if line.strip())
STUB_COMMANDS = ["doctor", "ingest"]
ALL_COMMANDS = [*STUB_COMMANDS, "run", "runs", "score", "gate", "compare", "tune"]


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ALL_COMMANDS:
        assert command in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.parametrize("command", STUB_COMMANDS)
def test_stubs_fail_closed(command: str) -> None:
    result = runner.invoke(app, [command])
    assert result.exit_code == EXIT_NOT_IMPLEMENTED
    assert "not implemented" in result.output


def test_documented_options_parse() -> None:
    # Options shown in CLAUDE.md must be accepted (stubs still fail closed).
    missing = runner.invoke(app, ["ingest", "--promptfoo", "missing-results.json"])
    assert missing.exit_code == EXIT_ERROR and "cannot read" in missing.output


def test_printable_escapes_control_characters() -> None:
    assert printable("ok\x1b[31mred\x07\x9b") == "ok\\x1b[31mred\\x07\\x9b"
    assert printable("plain text") == "plain text"


# --- run / runs -------------------------------------------------------------------------


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Mock-target config in tmp_path; DefenseClaw snapshot stubbed (no live calls)."""
    config = {
        "target": {"kind": "mock", "name": "lab-mock"},
        "targets": {"allowlist": ["lab-mock"]},
        "runner": {"inter_case_delay_ms": 0},
        "canaries": ["CANARY-7F3A"],
        "storage": {"db_path": str(tmp_path / "data" / "clawshield.db")},
    }
    path = tmp_path / "clawshield.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    snapshot: dict[str, Any] = {"available": True, "errors": []}
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: snapshot)
    return {"config": path, "db": tmp_path / "data" / "clawshield.db", "snapshot": snapshot}


def _run(lab: dict[str, Any], *extra: str) -> Any:
    return runner.invoke(
        app, ["run", "--config", str(lab["config"]), "--corpus", str(SEED), *extra]
    )


def test_run_seed_corpus_against_mock(lab: dict[str, Any]) -> None:
    result = _run(lab, "--notes", "baseline")
    assert result.exit_code == 0, result.output
    assert f": {SEED_CASES} cases, 0 target errors" in result.output
    run = Store(lab["db"]).get_run("latest")
    assert run.finished_at is not None and run.notes == "baseline"


def test_runs_lists_completed_run(lab: dict[str, Any]) -> None:
    _run(lab)
    result = runner.invoke(app, ["runs", "--config", str(lab["config"])])
    assert result.exit_code == 0
    assert "lab-mock" in result.output
    assert f"{SEED_CASES}/{SEED_CASES}" in result.output and "complete" in result.output


def test_run_warns_when_snapshot_unavailable(lab: dict[str, Any]) -> None:
    lab["snapshot"].update(available=False, errors=["status --json: not found\x1b[2J"])
    result = _run(lab)
    assert result.exit_code == 0
    assert "cannot serve as gate evidence" in result.output
    assert "\\x1b[2J" in result.output and "\x1b" not in result.output
    listing = runner.invoke(app, ["runs", "--config", str(lab["config"])])
    assert "(no snapshot)" in listing.output


def test_runs_with_no_database(lab: dict[str, Any]) -> None:
    result = runner.invoke(app, ["runs", "--config", str(lab["config"])])
    assert result.exit_code == 0 and "no runs yet" in result.output
    assert not lab["db"].exists()


def test_runs_with_empty_database(lab: dict[str, Any]) -> None:
    Store(lab["db"])
    result = runner.invoke(app, ["runs", "--config", str(lab["config"])])
    assert "no runs yet" in result.output


def test_run_with_bad_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["run", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == EXIT_ERROR
    assert "cannot read config" in result.output


def test_runs_with_bad_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["runs", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == EXIT_ERROR


def test_run_with_bad_corpus(lab: dict[str, Any], tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id": "x"}\n', encoding="utf-8")
    result = runner.invoke(app, ["run", "--config", str(lab["config"]), "--corpus", str(bad)])
    assert result.exit_code == EXIT_ERROR
    assert "invalid corpus" in result.output and "line 1" in result.output
    assert not lab["db"].exists()  # nothing stored for a refused run


def test_run_refuses_unimplemented_target(lab: dict[str, Any]) -> None:
    config = yaml.safe_load(lab["config"].read_text(encoding="utf-8"))
    config["target"] = {"kind": "openclaw", "name": "helpdesk-demo"}
    config["targets"] = {"allowlist": ["helpdesk-demo"]}
    lab["config"].write_text(yaml.safe_dump(config), encoding="utf-8")
    result = _run(lab)
    assert result.exit_code == EXIT_ERROR
    assert "not implemented yet" in result.output


def test_run_refuses_too_many_cases(lab: dict[str, Any]) -> None:
    config = yaml.safe_load(lab["config"].read_text(encoding="utf-8"))
    config["runner"]["max_cases_per_run"] = 10
    lab["config"].write_text(yaml.safe_dump(config), encoding="utf-8")
    result = _run(lab)
    assert result.exit_code == EXIT_ERROR
    assert "max_cases_per_run=10" in result.output


def test_run_rejects_long_notes(lab: dict[str, Any]) -> None:
    result = _run(lab, "--notes", "x" * 1001)
    assert result.exit_code == EXIT_ERROR
    assert "--notes is longer" in result.output


def test_run_reports_canary_leaks(lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from clawshield.targets.mock import MockTarget

    leaky = MockTarget(name="lab-mock", responder=lambda c: f"leak CANARY-7F3A from {c.id}")
    monkeypatch.setattr(cli, "build_target", lambda settings: leaky)
    result = _run(lab)
    assert result.exit_code == 0
    assert f"{SEED_CASES} canary leaks" in result.output
    assert "leaked a planted canary" in result.output
    listing = runner.invoke(app, ["runs", "--config", str(lab["config"])])
    assert f"  {SEED_CASES}  complete" in listing.output


def test_run_and_runs_refuse_old_schema(lab: dict[str, Any]) -> None:
    import sqlite3

    lab["db"].parent.mkdir(parents=True)
    with sqlite3.connect(lab["db"]) as conn:
        conn.execute("CREATE TABLE runs (id TEXT PRIMARY KEY)")
    for args in (["runs"], ["run", "--corpus", str(SEED)]):
        result = runner.invoke(app, [*args, "--config", str(lab["config"])])
        assert result.exit_code == EXIT_ERROR
        assert "schema version 0" in result.output


def test_run_with_redaction_enabled(lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    from clawshield.targets.mock import MockTarget

    config = yaml.safe_load(lab["config"].read_text(encoding="utf-8"))
    config["storage"]["redact_responses"] = True
    lab["config"].write_text(yaml.safe_dump(config), encoding="utf-8")
    leaky = MockTarget(name="lab-mock", responder=lambda c: "PRIVATE-REPLY-777 CANARY-7F3A")
    monkeypatch.setattr(cli, "build_target", lambda settings: leaky)

    result = _run(lab)
    assert result.exit_code == 0, result.output
    assert f"{SEED_CASES} canary leaks" in result.output and "(responses redacted)" in result.output
    assert b"PRIVATE-REPLY-777" not in db_bytes(lab["db"])


# --- score ---------------------------------------------------------------------------------


def test_score_latest_after_run(lab: dict[str, Any]) -> None:
    _run(lab)
    result = runner.invoke(app, ["score", "--run", "latest", "--config", str(lab["config"])])
    assert result.exit_code == 0, result.output
    assert f"cases {SEED_CASES} | scored {SEED_CASES}" in result.output
    assert "no DefenseClaw verdicts in this run's window" in result.output
    for section in ("OVERALL", "CATEGORY", "EXPECTED SEVERITY"):
        assert section in result.output


def test_score_json(lab: dict[str, Any]) -> None:
    import json

    _run(lab)
    result = runner.invoke(app, ["score", "--json", "--config", str(lab["config"])])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["cases_total"] == SEED_CASES and data["verdicts_in_window"] == 0
    assert data["run"]["snapshot_available"] is True


def test_score_escapes_hostile_rule_ids(lab: dict[str, Any]) -> None:
    from datetime import UTC, datetime

    from clawshield.core.models import Severity, Verdict

    _run(lab)
    store = Store(lab["db"])
    first = store.results(store.get_run("latest").id)[0]
    store.add_verdicts(
        [Verdict(id="v", source="test", ts=first.sent_at, connector="openclaw",
                 direction="prompt", severity=Severity.HIGH, rule_id="evil" + chr(27) + "[2Jrule",
                 action="observe", session_id=first.session_id)],
        ingested_at=datetime.now(UTC),
    )  # fmt: skip
    result = runner.invoke(app, ["score", "--config", str(lab["config"])])
    escaped = "evil" + chr(92) + "x1b[2Jrule"
    assert escaped in result.output and chr(27) not in result.output


def test_score_errors(lab: dict[str, Any]) -> None:
    no_db = runner.invoke(app, ["score", "--config", str(lab["config"])])
    assert no_db.exit_code == EXIT_ERROR and "no runs yet" in no_db.output
    _run(lab)
    missing = runner.invoke(app, ["score", "--run", "nope", "--config", str(lab["config"])])
    assert missing.exit_code == EXIT_ERROR and "not found" in missing.output
    bad_cfg = runner.invoke(app, ["score", "--config", "missing.yaml"])
    assert bad_cfg.exit_code == EXIT_ERROR


def test_score_reports_ambiguous_cases(lab: dict[str, Any]) -> None:
    from datetime import UTC, datetime

    from clawshield.core.models import Severity, Verdict

    _run(lab)  # inter_case_delay_ms=0, so every case window overlaps its neighbours
    store = Store(lab["db"])
    first = store.results(store.get_run("latest").id)[0]
    store.add_verdicts(
        [Verdict(id="v", source="test", ts=first.received_at, connector="openclaw",
                 direction="prompt", severity=Severity.HIGH, action="observe")],
        ingested_at=datetime.now(UTC),
    )  # fmt: skip
    result = runner.invoke(app, ["score", "--config", str(lab["config"])])
    assert result.exit_code == 0
    assert "ambiguous case(s) excluded" in result.output
    assert "inter_case_delay_ms" in result.output


def test_score_warns_when_run_has_no_snapshot(lab: dict[str, Any]) -> None:
    lab["snapshot"].update(available=False, errors=["status --json: not found"])
    _run(lab)
    result = runner.invoke(app, ["score", "--config", str(lab["config"])])
    assert result.exit_code == 0
    assert "not valid as gate evidence" in result.output
