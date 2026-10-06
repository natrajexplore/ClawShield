from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from clawshield.config import Settings
from clawshield.core.models import Case
from clawshield.redteam.corpus import Corpus, content_hash
from clawshield.redteam.runner import RunError, execute_run, new_run_id
from clawshield.storage.db import Store
from clawshield.targets.mock import MockTarget

T0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
SNAPSHOT = {"available": False, "errors": ["defenseclaw missing"]}


def _cases(n: int) -> tuple[Case, ...]:
    return tuple(
        Case.model_validate(
            {
                "id": f"d-{i:03d}",
                "text": f"attack {i}",
                "label": "malicious",
                "category": "llm01_direct",
                "expected_severity": "critical",
            }
        )
        for i in range(n)
    )


def _corpus(n: int = 3) -> Corpus:
    cases = _cases(n)
    return Corpus(path=Path("c.jsonl"), sha256=content_hash(cases), cases=cases)


def _settings(**overrides: Any) -> Settings:
    data: dict[str, Any] = {
        "target": {"kind": "mock", "name": "lab-mock"},
        "targets": {"allowlist": ["lab-mock"]},
        "runner": {"inter_case_delay_ms": 250, "max_cases_per_run": 10},
    }
    data.update(overrides)
    return Settings.model_validate(data)


@pytest.fixture
def store(tmp_path: Path) -> Store:
    return Store(tmp_path / "c.db")


def _execute(store: Store, **kw: Any) -> Any:
    sleeps: list[float] = []
    args: dict[str, Any] = {
        "settings": _settings(),
        "corpus": _corpus(),
        "target": MockTarget(name="lab-mock"),
        "store": store,
        "snapshot": SNAPSHOT,
        "sleep": sleeps.append,
        "clock": lambda: T0,
    }
    args.update(kw)
    return execute_run(**args), sleeps


def test_full_run_stores_everything(store: Store) -> None:
    report, sleeps = _execute(store, notes="baseline")
    assert (report.cases, report.errors) == (3, 0)
    run = store.get_run(report.run_id)
    assert run.finished_at == T0
    assert run.case_count == 3 and run.notes == "baseline"
    assert run.corpus_hash == _corpus().sha256
    assert run.guardrail_snapshot == SNAPSHOT
    assert (run.target_kind, run.target_identity) == ("mock", "lab-mock")
    assert [r.case_id for r in store.results(report.run_id)] == ["d-000", "d-001", "d-002"]
    assert sleeps == [0.25, 0.25]  # between cases only, not before the first or after the last


def test_zero_delay_never_sleeps(store: Store) -> None:
    settings = _settings(runner={"inter_case_delay_ms": 0, "max_cases_per_run": 10})
    _, sleeps = _execute(store, settings=settings)
    assert sleeps == []


def test_target_errors_counted_and_stored(store: Store) -> None:
    def responder(case: Case) -> str:
        if case.id == "d-001":
            raise ConnectionError("refused")
        return "ok"

    report, _ = _execute(store, target=MockTarget(name="lab-mock", responder=responder))
    assert report.errors == 1
    errors = [r.error for r in store.results(report.run_id)]
    assert errors == [None, "ConnectionError: refused", None]


def test_interrupted_run_keeps_partial_results_and_stays_incomplete(store: Store) -> None:
    def responder(case: Case) -> str:
        if case.id == "d-002":
            raise KeyboardInterrupt
        return "ok"

    with pytest.raises(KeyboardInterrupt):
        _execute(store, target=MockTarget(name="lab-mock", responder=responder))
    listing = store.list_runs()[0]
    assert listing.results == 2
    assert listing.complete is False


def test_refuses_corpus_above_max_cases(store: Store) -> None:
    with pytest.raises(RunError, match=r"above runner\.max_cases_per_run=10"):
        _execute(store, corpus=_corpus(11))
    assert store.list_runs() == []


def test_refuses_when_redaction_requested(store: Store) -> None:
    settings = _settings(storage={"redact_responses": True, "db_path": "unused.db"})
    with pytest.raises(RunError, match="redact_responses"):
        _execute(store, settings=settings)
    assert store.list_runs() == []


def test_run_ids_are_unique_and_sortable() -> None:
    ids = {new_run_id(lambda: T0) for _ in range(200)}
    assert len(ids) == 200
    assert all(i.startswith("20261006T120000Z-") for i in ids)
    later = new_run_id(lambda: T0 + timedelta(seconds=1))
    assert later > max(ids)


def test_canary_leaks_detected_for_every_case_and_stored(store: Store) -> None:
    import base64

    def responder(case: Case) -> str:
        if case.id == "d-000":
            return "Sure: CANARY-7F3A"
        if case.id == "d-002":
            return base64.b64encode(b"rules... CANARY-7F3A ...").decode()
        return "I can't help with that."

    settings = _settings(canaries=["CANARY-7F3A"])
    target = MockTarget(name="lab-mock", responder=responder)
    report, _ = _execute(store, settings=settings, target=target)
    assert report.leaks == 2
    hits = store.canary_hits(report.run_id)
    assert {k: [h.method for h in v] for k, v in hits.items()} == {
        "d-000": ["exact"],
        "d-002": ["base64"],
    }


def test_no_canaries_configured_means_no_leaks(store: Store) -> None:
    target = MockTarget(name="lab-mock", responder=lambda c: "CANARY-7F3A")
    report, _ = _execute(store, target=target)
    assert report.leaks == 0
