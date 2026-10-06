import stat
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError, StatementError

from clawshield.core.models import TargetResult
from clawshield.storage.db import RunNotFoundError, RunRow, Store
from tests.conftest import db_bytes

T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)


def _run(run_id: str = "r1", started: datetime = T0) -> RunRow:
    return RunRow(
        id=run_id,
        started_at=started,
        target_kind="mock",
        target_name="lab-mock",
        target_identity="lab-mock",
        corpus_path="redteam/corpus/seed.jsonl",
        corpus_hash="0" * 64,
        case_count=2,
        guardrail_snapshot={"available": False, "errors": ["defenseclaw missing"]},
    )


def _result(case_id: str = "d-001", **kw: object) -> TargetResult:
    fields: dict[str, object] = {
        "case_id": case_id,
        "sent_at": T0,
        "received_at": T0 + timedelta(seconds=1),
        "response_text": "ok",
    }
    fields.update(kw)
    return TargetResult.model_validate(fields)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "data" / "clawshield.db")


def test_creates_parent_directory(tmp_path: Path) -> None:
    Store(tmp_path / "nested" / "dir" / "c.db")
    assert (tmp_path / "nested" / "dir" / "c.db").exists()


def test_run_round_trip(store: Store) -> None:
    store.create_run(_run())
    got = store.get_run("r1")
    assert got.target_name == "lab-mock"
    assert got.guardrail_snapshot == {"available": False, "errors": ["defenseclaw missing"]}
    assert got.finished_at is None


def test_datetimes_round_trip_as_aware_utc(store: Store) -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    store.create_run(_run(started=T0.astimezone(ist)))
    got = store.get_run("r1")
    assert got.started_at == T0
    assert got.started_at.tzinfo is UTC


def test_naive_datetime_rejected(store: Store) -> None:
    naive = datetime(2026, 10, 6, 12, 0, 0)
    with pytest.raises(StatementError, match="naive datetime"):
        store.create_run(_run(started=naive))


def test_results_round_trip_in_insert_order(store: Store) -> None:
    store.create_run(_run())
    second = _result("d-002", response_text=None, error="TimeoutError: slow", http_status=504)
    store.add_result("r1", _result("d-001", session_id="lab-d-001"))
    store.add_result("r1", second)
    got = store.results("r1")
    assert [r.case_id for r in got] == ["d-001", "d-002"]
    assert got[0].session_id == "lab-d-001"
    assert got[1] == second
    assert got[0].sent_at.tzinfo is UTC


def test_duplicate_case_in_run_rejected(store: Store) -> None:
    store.create_run(_run())
    store.add_result("r1", _result())
    with pytest.raises(IntegrityError):
        store.add_result("r1", _result())


def test_result_for_unknown_run_rejected(store: Store) -> None:
    with pytest.raises(IntegrityError):
        store.add_result("no-such-run", _result())


def test_finish_run(store: Store) -> None:
    store.create_run(_run())
    store.finish_run("r1", T0 + timedelta(minutes=5))
    assert store.get_run("r1").finished_at == T0 + timedelta(minutes=5)


def test_finish_unknown_run(store: Store) -> None:
    with pytest.raises(RunNotFoundError):
        store.finish_run("nope", T0)


def test_get_latest_and_unknown(store: Store) -> None:
    with pytest.raises(RunNotFoundError):
        store.get_run("latest")
    store.create_run(_run("old", T0))
    store.create_run(_run("new", T0 + timedelta(hours=1)))
    assert store.get_run("latest").id == "new"
    with pytest.raises(RunNotFoundError):
        store.get_run("missing")


def test_list_runs_counts_results_and_errors(store: Store) -> None:
    store.create_run(_run("a", T0))
    store.create_run(_run("b", T0 + timedelta(hours=1)))
    store.add_result("a", _result("d-001"))
    store.add_result("a", _result("d-002", response_text=None, error="boom"))
    store.finish_run("a", T0 + timedelta(minutes=1))
    listings = store.list_runs()
    assert [x.run.id for x in listings] == ["b", "a"]
    b, a = listings
    assert (a.results, a.errors, a.complete) == (2, 1, True)
    assert (b.results, b.errors, b.complete) == (0, 0, False)
    assert len(store.list_runs(limit=1)) == 1


def test_sql_metacharacters_stored_literally(store: Store) -> None:
    store.create_run(_run())
    payload = "'; DROP TABLE runs; --"
    store.add_result("r1", _result(response_text=payload))
    assert store.results("r1")[0].response_text == payload
    assert store.get_run("r1").id == "r1"


def test_reopening_existing_db_keeps_data(tmp_path: Path) -> None:
    path = tmp_path / "c.db"
    Store(path).create_run(_run())
    assert Store(path).get_run("r1").id == "r1"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_db_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "c.db"
    Store(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# --- canary hits + schema version ----------------------------------------------------------


def test_canary_hits_round_trip_and_counted(store: Store) -> None:
    from clawshield.core.canary import CanaryHit

    store.create_run(_run())
    store.add_result("r1", _result("d-001"), [CanaryHit("CANARY-7F3A", "base64")])
    store.add_result("r1", _result("d-002"))
    assert store.canary_hits("r1") == {"d-001": [CanaryHit("CANARY-7F3A", "base64")]}
    assert store.list_runs()[0].leaks == 1
    assert [r.case_id for r in store.results("r1")] == ["d-001", "d-002"]


def test_new_db_records_schema_version(tmp_path: Path) -> None:
    import sqlite3

    from clawshield.storage.db import SCHEMA_VERSION

    path = tmp_path / "c.db"
    Store(path)
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION


def test_mismatched_schema_refused(tmp_path: Path) -> None:
    import sqlite3

    from clawshield.storage.db import StoreSchemaError

    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:  # a pre-versioning database (user_version 0)
        conn.execute("CREATE TABLE runs (id TEXT PRIMARY KEY)")
    with pytest.raises(StoreSchemaError, match="schema version 0"):
        Store(path)


# --- redaction (NFR-1) -----------------------------------------------------------------------


SECRET_RESPONSE = "Here is the admin password hunter2-SECRET-RESPONSE-XYZ"


def test_redacting_store_never_writes_response_text(tmp_path: Path) -> None:
    import sqlite3

    from clawshield.storage.db import REDACTED_PLACEHOLDER

    path = tmp_path / "r.db"
    store = Store(path, redact_responses=True)
    store.create_run(_run())
    store.add_result("r1", _result("d-001", response_text=SECRET_RESPONSE))
    store.add_result("r1", _result("d-002", response_text=None, error="TimeoutError: slow"))

    got = store.results("r1")
    assert got[0].response_text == REDACTED_PLACEHOLDER
    assert (got[1].response_text, got[1].error) == (None, "TimeoutError: slow")
    assert store.get_run("r1").responses_redacted is True

    with sqlite3.connect(path) as conn:
        flags = conn.execute(
            "SELECT case_id, response_redacted FROM target_results ORDER BY id"
        ).fetchall()
        dump = "\n".join(conn.iterdump())
    assert flags == [("d-001", 1), ("d-002", 0)]  # nothing to redact on an error-only row
    assert "hunter2" not in dump and "SECRET-RESPONSE" not in dump
    assert b"hunter2" not in db_bytes(path)


def test_default_store_keeps_response_text(store: Store) -> None:
    store.create_run(_run())
    store.add_result("r1", _result(response_text=SECRET_RESPONSE))
    assert store.results("r1")[0].response_text == SECRET_RESPONSE
    assert store.get_run("r1").responses_redacted is False


def test_db_uses_wal_and_side_files_stay_secret_free(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "w.db"
    store = Store(path, redact_responses=True)
    store.create_run(_run())
    store.add_result("r1", _result(response_text=SECRET_RESPONSE))
    with sqlite3.connect(path) as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert path.with_name("w.db-wal").exists()  # recent writes live here until checkpoint
    assert b"hunter2" not in db_bytes(path)
