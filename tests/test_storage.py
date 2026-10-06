import stat
import sys
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy.exc import IntegrityError, StatementError

from clawshield.core.models import TargetResult
from clawshield.storage.db import RunNotFoundError, RunRow, Store

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
