"""AuditDbSource against a SQLite file rebuilt from the captured lab audit_events (ADR 0001)."""

import json
import sqlite3
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from clawshield import cli
from clawshield.cli import EXIT_ERROR, app
from clawshield.core.models import Severity
from clawshield.sources.auditdb import (
    MAX_ROWS,
    AuditDbError,
    AuditDbSource,
    parse_timestamp,
)
from clawshield.sources.base import VerdictSource
from clawshield.storage.db import Store

FIXTURES = Path(__file__).parent / "fixtures" / "defenseclaw"
ROWS: list[dict[str, Any]] = json.loads((FIXTURES / "audit_events.json").read_text("utf-8"))
CASES: list[dict[str, Any]] = json.loads((FIXTURES / "m0_cases.json").read_text("utf-8"))
EPOCH = datetime(2026, 1, 1, tzinfo=UTC)
EVIDENCE = "defenseclaw.guardrail.evidence_summary"
D001 = next(c for c in CASES if c["case_id"] == "d-001")["session_id"]


def build_db(path: Path, rows: list[dict[str, Any]] = ROWS, drop: str | None = None) -> Path:
    columns = [c for c in ROWS[0] if c != drop]
    with sqlite3.connect(path) as conn:
        conn.execute(f"CREATE TABLE audit_events ({', '.join(columns)})")
        conn.executemany(
            f"INSERT INTO audit_events VALUES ({', '.join('?' for _ in columns)})",  # noqa: S608 - fixture column names
            [[r.get(c) for c in columns] for r in rows],
        )
    conn.close()
    return path


def _stored_session(sent: str) -> str:
    return f"agent:helpdesk:explicit:{sent.lower()}"


@pytest.fixture
def source(tmp_path: Path) -> AuditDbSource:
    return AuditDbSource(build_db(tmp_path / "audit.db"), connector="openclaw")


def test_is_a_verdict_source(source: AuditDbSource) -> None:
    assert isinstance(source, VerdictSource)
    assert source.name == "defenseclaw_auditdb"


def test_known_bad_case_maps_to_four_critical_prompt_verdicts(source: AuditDbSource) -> None:
    mine = [v for v in source.fetch(EPOCH) if v.session_id == _stored_session(D001)]
    assert len(mine) == 4
    assert {v.rule_id for v in mine} == {
        "TRUST-IGNORE-PREVIOUS", "LP-INJ-IGNORE", "UNKNOWN-IGNORE-ALL-PREVIOUS",
        "UNKNOWN-YOU-ARE-NOW",
    }  # fmt: skip
    for v in mine:
        assert v.severity is Severity.CRITICAL
        assert v.direction == "prompt"
        assert v.action == "observe"
        assert v.connector == "openclaw"  # null in audit.db; correlation filters on it
        assert v.id.startswith("defenseclaw_auditdb:")
        assert v.raw is not None and v.raw["finding"]["defenseclaw.scan.scanner"] == "local-pattern"


def test_per_case_findings_match_the_lab_result(source: AuditDbSource) -> None:
    by_session = Counter(v.session_id for v in source.fetch(EPOCH))
    latest = {c["case_id"]: by_session[_stored_session(c["session_id"])] for c in CASES}
    assert latest == {
        "b-001": 0, "b-002": 0, "b-003": 0, "bl-001": 3, "bl-002": 0,
        "d-001": 4, "d-002": 1, "s-001": 0, "i-001": 0, "o-001": 0,
    }  # fmt: skip


def test_plugin_scans_are_skipped_and_reported(source: AuditDbSource) -> None:
    batch = source.read(EPOCH)
    assert all(v.session_id for v in batch.verdicts)  # every guardrail finding has a session
    assert batch.skipped["scanner plugin-scanner"] == 40
    assert len(batch.verdicts) == 12


def test_since_filters_by_parsed_time_and_ignores_older_rows(source: AuditDbSource) -> None:
    newest = max(v.ts for v in source.fetch(EPOCH))
    batch = source.read(newest)
    assert [v.ts for v in batch.verdicts] == [newest] * len(batch.verdicts)
    assert not batch.skipped  # older plugin scans are outside the window, not "skipped"
    assert source.read(newest + timedelta(microseconds=1)).verdicts == []


def test_ingest_is_idempotent(source: AuditDbSource, tmp_path: Path) -> None:
    store = Store(tmp_path / "cs.db")
    first = store.add_verdicts(source.fetch(EPOCH), ingested_at=datetime.now(UTC))
    again = store.add_verdicts(source.fetch(EPOCH), ingested_at=datetime.now(UTC))
    assert (first.new, again.new, again.duplicates) == (12, 0, 12)


def _finding(**over: Any) -> dict[str, Any]:
    base = next(r for r in ROWS if r["session_id"] and r["action"] == "scan-finding")
    row = dict(base)
    sj = {**json.loads(base["structured_json"]), **over.pop("sj", {})}
    row["structured_json"] = json.dumps(sj)
    row.update(over)
    return row


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"event_name": "finding.cleared"}, "event finding.cleared"),
        ({"structured_json": "{not json"}, "invalid structured_json"),
        ({"structured_json": "[1]"}, "invalid structured_json"),
        ({"sj": {"defenseclaw.scan.scanner": "llm-judge"}}, "scanner llm-judge"),
        ({"enforced": 1}, "enforced set (action-mode rows unverified, ADR 0001)"),
        ({"sj": {"defenseclaw.security.severity": "INFO"}}, "severity INFO"),
        ({"timestamp": "yesterday"}, "missing id or bad timestamp"),
        ({"id": "x" * 300}, "invalid finding fields"),
    ],
)
def test_unusable_rows_are_skipped_with_a_reason(
    tmp_path: Path, override: dict[str, Any], reason: str
) -> None:
    db = build_db(tmp_path / "audit.db", [_finding(**override)])
    batch = AuditDbSource(db, connector="openclaw").read(EPOCH)
    assert batch.verdicts == [] and batch.skipped == Counter({reason: 1})


def test_direction_and_connector_mapping(tmp_path: Path) -> None:
    rows = [
        _finding(id="a", sj={EVIDENCE: "rule=X; target_type=completion"}),
        _finding(id="b", sj={EVIDENCE: "target_type=weird"}),
        _finding(id="c", sj={EVIDENCE: None}, connector="codex"),
    ]  # fmt: skip
    got = {
        v.id: v
        for v in AuditDbSource(build_db(tmp_path / "a.db", rows), connector="openclaw").fetch(EPOCH)
    }
    assert got["defenseclaw_auditdb:a"].direction == "completion"
    assert got["defenseclaw_auditdb:b"].direction == "unknown"
    assert got["defenseclaw_auditdb:c"].connector == "codex"  # kept; correlation filters it out


def test_missing_database_and_schema_drift_fail_loudly(tmp_path: Path) -> None:
    with pytest.raises(AuditDbError, match="not found"):
        AuditDbSource(tmp_path / "nope.db", connector="openclaw").read(EPOCH)
    drifted = build_db(tmp_path / "drift.db", drop="session_id")
    with pytest.raises(AuditDbError, match="session_id"):
        AuditDbSource(drifted, connector="openclaw").read(EPOCH)
    other = tmp_path / "other.db"
    with sqlite3.connect(other) as conn:
        conn.execute("CREATE TABLE t (x)")
    conn.close()
    with pytest.raises(AuditDbError, match="audit_events not found"):
        AuditDbSource(other, connector="openclaw").read(EPOCH)
    garbage = tmp_path / "garbage.db"
    garbage.write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(AuditDbError, match="cannot read"):
        AuditDbSource(garbage, connector="openclaw").read(EPOCH)


def test_opens_read_only(source: AuditDbSource) -> None:
    before = source.path.read_bytes()
    source.read(EPOCH)
    assert source.path.read_bytes() == before


def test_too_many_rows_is_an_error(source: AuditDbSource, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("clawshield.sources.auditdb.MAX_ROWS", 5)
    with pytest.raises(AuditDbError, match="more than 5"):
        source.read(EPOCH)
    assert MAX_ROWS == 200_000


def test_naive_since_rejected(source: AuditDbSource) -> None:
    with pytest.raises(ValueError, match="timezone"):
        source.read(datetime(2026, 1, 1))


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-10-07T09:30:18.724413519Z", datetime(2026, 10, 7, 9, 30, 18, 724413, tzinfo=UTC)),
        ("2026-10-07T09:30:18.7Z", datetime(2026, 10, 7, 9, 30, 18, 700000, tzinfo=UTC)),
        ("2026-10-07T09:30:18Z", datetime(2026, 10, 7, 9, 30, 18, tzinfo=UTC)),
        ("2026-10-07T09:30:18", None),  # naive: refused, never assumed UTC
        ("", None),
    ],
)
def test_parse_timestamp(text: str, expected: datetime | None) -> None:
    assert parse_timestamp(text) == expected


def test_every_fixture_timestamp_parses() -> None:
    assert all(parse_timestamp(r["timestamp"]) is not None for r in ROWS)


# --- clawshield ingest -------------------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def lab_config(tmp_path: Path) -> Path:
    config = {
        "defenseclaw": {"audit_db": str(build_db(tmp_path / "audit.db"))},
        "target": {"kind": "mock", "name": "lab-mock"},
        "targets": {"allowlist": ["lab-mock"]},
        "runner": {"inter_case_delay_ms": 0},
        "canaries": ["CANARY-7F3A"],
        "storage": {"db_path": str(tmp_path / "data" / "cs.db")},
    }
    path = tmp_path / "clawshield.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return path


def test_cli_ingest_with_since(lab_config: Path) -> None:
    args = ["ingest", "--config", str(lab_config), "--since", "2026-01-01T00:00:00+00:00"]
    first = runner.invoke(app, args)
    assert first.exit_code == 0, first.output
    assert "read 12 guardrail verdict(s)" in first.output and "12 new" in first.output
    assert "skipped 40: scanner plugin-scanner" in first.output
    again = runner.invoke(app, args)
    assert "0 new, 12 already stored" in again.output


def test_cli_ingest_warns_on_empty_window(lab_config: Path) -> None:
    result = runner.invoke(
        app, ["ingest", "--config", str(lab_config), "--since", "2027-01-01T00:00:00Z"]
    )
    assert result.exit_code == 0
    assert "read 0 guardrail verdict(s)" in result.output and "in-path probe" in result.output


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ([], "no runs yet"),
        (["--since", "2026-10-07T09:00:00"], "needs a UTC offset"),
        (["--since", "last tuesday"], "invalid --since"),
    ],
)
def test_cli_ingest_errors(lab_config: Path, extra: list[str], message: str) -> None:
    result = runner.invoke(app, ["ingest", "--config", str(lab_config), *extra])
    assert result.exit_code == EXIT_ERROR and message in result.output


def test_cli_ingest_missing_audit_db(tmp_path: Path, lab_config: Path) -> None:
    config = yaml.safe_load(lab_config.read_text("utf-8"))
    config["defenseclaw"]["audit_db"] = str(tmp_path / "missing.db")
    lab_config.write_text(yaml.safe_dump(config), encoding="utf-8")
    result = runner.invoke(
        app, ["ingest", "--config", str(lab_config), "--since", "2026-01-01T00:00:00Z"]
    )
    assert result.exit_code == EXIT_ERROR and "not found" in result.output


def test_cli_ingest_defaults_to_latest_run(
    lab_config: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})
    seed = Path(__file__).resolve().parents[1] / "redteam" / "corpus" / "seed.jsonl"
    run = runner.invoke(app, ["run", "--config", str(lab_config), "--corpus", str(seed)])
    assert run.exit_code == 0, run.output
    result = runner.invoke(app, ["ingest", "--config", str(lab_config)])
    assert result.exit_code == 0, result.output
    assert "read 0 guardrail verdict(s)" in result.output  # fixture findings predate the run
