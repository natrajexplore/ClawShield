"""Observe-mode evidence from `defenseclaw status --json` snapshots (core/posture.py)."""

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from clawshield.core.posture import guardrail_posture, observe_streak_start

STATUS: dict[str, Any] = json.loads(
    (Path(__file__).parent / "fixtures" / "defenseclaw" / "status.json").read_text("utf-8")
)
T0 = datetime(2026, 10, 7, 10, 0, tzinfo=UTC)


def snap(status: Any = STATUS, **over: Any) -> dict[str, Any]:
    return {"available": True, "defenseclaw_status": copy.deepcopy(status), **over}


def with_connector(**fields: Any) -> dict[str, Any]:
    status = copy.deepcopy(STATUS)
    status["connectors"][0].update(fields)
    return snap(status)


def test_lab_fixture_verifies_observe() -> None:
    p = guardrail_posture(snap(), "openclaw")
    assert p.observe_verified and p.mode == "observe" and p.reason == "observe"


@pytest.mark.parametrize(
    ("snapshot", "reason"),
    [
        (None, "no guardrail snapshot"),
        ({"available": False, "defenseclaw_status": STATUS}, "no guardrail snapshot"),
        ({"available": True}, "no status --json"),
        (snap({**STATUS, "sidecar": {"running": False}}), "sidecar not running"),
        (snap({**STATUS, "sidecar": None}), "sidecar not running"),
        (snap({**STATUS, "connectors": []}), "not uniquely listed"),
        (snap({**STATUS, "connectors": "openclaw"}), "not uniquely listed"),
        (snap({**STATUS, "connectors": STATUS["connectors"] * 2}), "not uniquely listed"),
        (with_connector(enabled=False), "disabled"),
        (with_connector(mode="action"), "mode 'action'"),
        (with_connector(mode=None), "mode 'None'"),
    ],
)
def test_anything_else_is_not_verified(snapshot: Any, reason: str) -> None:
    p = guardrail_posture(snapshot, "openclaw")
    assert not p.observe_verified and reason in p.reason


def test_other_connector_is_not_evidence() -> None:
    assert not guardrail_posture(snap(), "codex").observe_verified


def test_action_mode_is_reported() -> None:
    assert guardrail_posture(with_connector(mode="action"), "openclaw").mode == "action"


def _runs(*kinds: str) -> list[tuple[datetime, Any]]:
    kinds_map = {"o": snap(), "a": with_connector(mode="action"), "x": {"available": False}}
    return [(T0 + timedelta(days=i), kinds_map[k]) for i, k in enumerate(kinds)]


@pytest.mark.parametrize(
    ("kinds", "start_day"),
    [
        ("", None),
        ("o", 0),
        ("ooo", 0),
        ("xoo", 1),
        ("ooao", 3),
        ("oox", None),
        ("ooxo", 3),
        ("a", None),
    ],
)
def test_observe_streak_restarts_on_any_unverified_run(kinds: str, start_day: int | None) -> None:
    got = observe_streak_start(_runs(*kinds), "openclaw")
    assert got == (None if start_day is None else T0 + timedelta(days=start_day))
