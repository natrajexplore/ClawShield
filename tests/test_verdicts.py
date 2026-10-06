import sqlite3
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from clawshield.core.models import Severity, Verdict, stable_verdict_id
from clawshield.sources.base import VerdictSource
from clawshield.storage.db import Store

T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
RAW = {"id": "evt-1", "severity": "HIGH", "details": "rule=PI-001 snippet='CANARY-7F3A'"}


def _verdict(n: int = 1, *, ts: datetime = T0, raw: dict[str, Any] | None = None) -> Verdict:
    return Verdict(
        id=f"defenseclaw_cli:evt-{n}",
        source="defenseclaw_cli",
        ts=ts,
        connector="openclaw",
        direction="prompt",
        severity=Severity.HIGH,
        rule_id="PI-001",
        action="alert",
        session_id=f"sess-{n}",
        raw=raw if raw is not None else {**RAW, "id": f"evt-{n}"},
    )


# --- model + ids -------------------------------------------------------------------------


def test_native_id_is_namespaced_by_source() -> None:
    assert stable_verdict_id("defenseclaw_cli", RAW, "evt-1") == "defenseclaw_cli:evt-1"
    assert stable_verdict_id("jsonl", RAW, "evt-1") == "jsonl:evt-1"


def test_hash_id_ignores_key_order_and_changes_with_content() -> None:
    reordered = dict(reversed(list(RAW.items())))
    a = stable_verdict_id("jsonl", RAW)
    assert a == stable_verdict_id("jsonl", reordered)
    assert a.startswith("jsonl:sha256:") and len(a) == len("jsonl:sha256:") + 64
    assert a != stable_verdict_id("jsonl", {**RAW, "severity": "LOW"})
    assert a != stable_verdict_id("defenseclaw_cli", RAW)


def test_empty_native_id_falls_back_to_hash() -> None:
    assert stable_verdict_id("jsonl", RAW, "").startswith("jsonl:sha256:")


def test_verdict_requires_aware_ts_and_known_enums() -> None:
    naive = datetime(2026, 10, 6, 12, 0, 0)
    base = _verdict().model_dump()
    with pytest.raises(ValueError, match="timezone"):
        Verdict.model_validate({**base, "ts": naive})
    for field, bad in [("direction", "sideways"), ("action", "nuke"), ("severity", "INFO")]:
        with pytest.raises(ValueError, match=field):
            Verdict.model_validate({**base, field: bad})
    with pytest.raises(ValueError, match="source"):
        Verdict.model_validate({**base, "source": "Bad Source!"})


def test_unknown_direction_is_allowed() -> None:
    v = Verdict.model_validate({**_verdict().model_dump(), "direction": "unknown"})
    assert v.direction == "unknown"


def test_protocol_shape() -> None:
    class FakeSource:
        name = "fake"

        def fetch(self, since: datetime) -> list[Verdict]:
            return [_verdict()]

    assert isinstance(FakeSource(), VerdictSource)


# --- idempotent ingest (NFR-3) --------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "c.db")


def test_reingesting_creates_no_duplicates(store: Store) -> None:
    batch = [_verdict(1), _verdict(2), _verdict(3)]
    first = store.add_verdicts(batch, ingested_at=T0)
    second = store.add_verdicts(batch, ingested_at=T0 + timedelta(minutes=1))
    assert (first.received, first.new, first.duplicates) == (3, 3, 0)
    assert (second.received, second.new, second.duplicates) == (3, 0, 3)
    assert len(store.verdicts_between(T0 - timedelta(days=1), T0 + timedelta(days=1))) == 3


def test_overlapping_batches_and_in_batch_duplicates(store: Store) -> None:
    store.add_verdicts([_verdict(1), _verdict(2)], ingested_at=T0)
    report = store.add_verdicts([_verdict(2), _verdict(3), _verdict(3)], ingested_at=T0)
    assert (report.received, report.new, report.duplicates) == (3, 1, 2)


def test_first_ingested_copy_is_kept(store: Store) -> None:
    store.add_verdicts([_verdict(1, raw={"v": "first"})], ingested_at=T0)
    store.add_verdicts([_verdict(1, raw={"v": "second"})], ingested_at=T0)
    (got,) = store.verdicts_between(T0, T0)
    assert got.raw == {"v": "first"}


def test_empty_batch(store: Store) -> None:
    report = store.add_verdicts([], ingested_at=T0)
    assert (report.received, report.new) == (0, 0)


def test_round_trip_preserves_fields_and_utc(store: Store) -> None:
    ist = timezone(timedelta(hours=5, minutes=30))
    original = _verdict(1, ts=T0.astimezone(ist))
    store.add_verdicts([original], ingested_at=T0)
    (got,) = store.verdicts_between(T0, T0)
    assert got == original.model_copy(update={"ts": T0})
    assert got.ts.tzinfo is UTC and got.severity is Severity.HIGH


def test_window_is_inclusive_and_ordered(store: Store) -> None:
    times = [T0 + timedelta(seconds=s) for s in (5, 0, 10, 15)]
    store.add_verdicts([_verdict(n, ts=t) for n, t in enumerate(times)], ingested_at=T0)
    got = store.verdicts_between(T0, T0 + timedelta(seconds=10))
    assert [v.ts for v in got] == [T0, T0 + timedelta(seconds=5), T0 + timedelta(seconds=10)]


def test_redacting_store_drops_raw_payload(tmp_path: Path) -> None:
    path = tmp_path / "r.db"
    store = Store(path, redact_responses=True)
    store.add_verdicts([_verdict(1)], ingested_at=T0)
    (got,) = store.verdicts_between(T0, T0)
    assert got.raw is None and got.rule_id == "PI-001"
    with sqlite3.connect(path) as conn:
        dump = "\n".join(conn.iterdump())
    assert "CANARY-7F3A" not in dump and "snippet" not in dump


def test_hostile_strings_stored_literally(store: Store) -> None:
    payload = "'); DROP TABLE verdicts; --"
    v = _verdict(1).model_copy(update={"rule_id": payload, "raw": {"details": payload}})
    store.add_verdicts([v], ingested_at=T0)
    (got,) = store.verdicts_between(T0, T0)
    assert got.rule_id == payload and got.raw == {"details": payload}
