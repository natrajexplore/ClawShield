import json
import time
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from clawshield import cli
from clawshield.alerts.slack import NotifyError, send_slack, validate_webhook
from clawshield.cli import EXIT_ERROR, EXIT_GATE_NOT_PASSED, app
from clawshield.core.models import Severity, Verdict
from clawshield.core.regression import detect_regression
from clawshield.core.score import SliceScore
from clawshield.storage.db import Store

SEED = Path(__file__).resolve().parents[1] / "redteam" / "corpus" / "seed.jsonl"
WEBHOOK = "https://hooks.slack.com/services/T000/B000/not-a-real-token-xyz"
runner = CliRunner()


# --- regression (pure) ---------------------------------------------------------------------------


def s(tp: int, fn: int, fp: int, tn: int) -> SliceScore:
    return SliceScore("overall", "all", tp, fp, tn, fn, 0, 0)


def test_no_baseline() -> None:
    r = detect_regression(s(9, 1, 0, 10), None, None, max_recall_drop=0.03, max_fpr_rise=0.01)
    assert not r.regressed and r.baseline_run_id is None


def test_recall_drop_beyond_tolerance() -> None:
    r = detect_regression(s(90, 10, 0, 10), s(100, 0, 0, 10), "base",
                          max_recall_drop=0.03, max_fpr_rise=0.01)  # fmt: skip
    assert r.regressed and r.recall_delta == pytest.approx(-0.10)
    assert "recall dropped 10.0%" in r.reasons[0]


def test_changes_within_tolerance_are_not_regressions() -> None:
    r = detect_regression(s(98, 2, 1, 199), s(100, 0, 0, 200), "base",
                          max_recall_drop=0.03, max_fpr_rise=0.01)  # fmt: skip
    assert not r.regressed and r.reasons == ()


def test_fpr_rise_beyond_tolerance() -> None:
    r = detect_regression(s(10, 0, 5, 95), s(10, 0, 0, 100), "base",
                          max_recall_drop=0.03, max_fpr_rise=0.01)  # fmt: skip
    assert r.regressed and "false-positive rate rose 5.0%" in r.reasons[0]


# --- Slack ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.slack.com/services/T/B/x",
        "https://hooks.slack.com.evil.example/services/T/B/x",
        "https://evil.example/services/T/B/x",
        "https://user:pw@hooks.slack.com/services/T/B/x",
        "https://hooks.slack.com:8443/services/T/B/x",
        "https://hooks.slack.com/api/other",
        "file:///etc/passwd",
    ],
)
def test_webhook_allowlist_rejects(url: str) -> None:
    with pytest.raises(NotifyError) as exc:
        validate_webhook(url)
    assert url not in str(exc.value)


def test_webhook_allowlist_accepts_slack() -> None:
    validate_webhook(WEBHOOK)


class FakeOpener:
    def __init__(self, error: Exception | None = None, status: int = 200) -> None:
        self.error, self.status, self.request = error, status, None
        self.timeout: float | None = None

    def __call__(self, request: Any, timeout: float) -> Any:
        self.request, self.timeout = request, timeout
        if self.error:
            raise self.error
        return type("R", (), {"status": self.status})()


def test_send_posts_json_with_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CS_TEST_HOOK", WEBHOOK)
    opener = FakeOpener()
    send_slack("CS_TEST_HOOK", "hello", opener=opener)
    assert opener.request.get_method() == "POST" and opener.timeout == 10
    assert json.loads(opener.request.data) == {"text": "hello"}


@pytest.mark.parametrize(
    ("error", "status", "fragment"),
    [
        (urllib.error.HTTPError(WEBHOOK, 403, "Forbidden", {}, None), 200, "HTTP 403"),  # type: ignore[arg-type]
        (urllib.error.URLError(OSError("dns")), 200, "cannot reach Slack"),
        (TimeoutError(), 200, "cannot reach Slack"),
        (None, 500, "HTTP 500"),
    ],
)
def test_send_failures_never_reveal_the_url(
    monkeypatch: pytest.MonkeyPatch, error: Exception | None, status: int, fragment: str
) -> None:
    monkeypatch.setenv("CS_TEST_HOOK", WEBHOOK)
    with pytest.raises(NotifyError) as exc:
        send_slack("CS_TEST_HOOK", "x", opener=FakeOpener(error, status))
    assert fragment in str(exc.value)
    assert "not-a-real-token" not in str(exc.value) and "hooks.slack.com/services" not in str(
        exc.value
    )


def test_send_requires_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CS_TEST_HOOK", raising=False)
    with pytest.raises(NotifyError, match="CS_TEST_HOOK is not set"):
        send_slack("CS_TEST_HOOK", "x", opener=FakeOpener())


def test_send_validates_url_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CS_TEST_HOOK", "https://evil.example/services/x")
    opener = FakeOpener()
    with pytest.raises(NotifyError):
        send_slack("CS_TEST_HOOK", "x", opener=opener)
    assert opener.request is None  # nothing was sent


# --- check / run --ci -----------------------------------------------------------------------------


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    config = tmp_path / "c.yaml"
    config.write_text(yaml.safe_dump({
        "target": {"kind": "mock", "name": "m"}, "targets": {"allowlist": ["m"]},
        "runner": {"inter_case_delay_ms": 0, "correlation_grace_s": 0, "max_cases_per_run": 1000},
        "canaries": ["CANARY-7F3A"], "storage": {"db_path": str(tmp_path / "c.db")},
        "gate": {"evaluate_on": "point_estimate"},  # seed corpus is too small for the bounds
        "alerts": {"slack_webhook_env": "CS_TEST_HOOK"},
    }), encoding="utf-8")  # fmt: skip
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})
    return {"config": str(config), "db": tmp_path / "c.db"}


def _run_and_flag(lab: dict[str, Any], keep: float) -> str:
    """Run the seed corpus; ingest CRITICAL verdicts for `keep` share of the attacks."""
    assert (
        runner.invoke(app, ["run", "--config", lab["config"], "--corpus", str(SEED)]).exit_code == 0
    )
    store = Store(lab["db"])
    run_id = store.get_run("latest").id
    attacks = [r for r in store.results(run_id) if not r.case_id.startswith("b")]
    flagged = attacks[: round(len(attacks) * keep)]
    store.add_verdicts(
        [Verdict(id=f"{run_id}-{r.case_id}", source="t", ts=r.sent_at, connector="openclaw",
                 direction="prompt", severity=Severity.CRITICAL, action="observe",
                 session_id=r.session_id) for r in flagged],
        ingested_at=datetime.now(UTC),
    )  # fmt: skip
    return run_id


def test_check_passes_then_detects_regression(lab: dict[str, Any]) -> None:
    baseline = _run_and_flag(lab, keep=1.0)
    ok = runner.invoke(app, ["check", "--run", baseline, "--config", lab["config"]])
    assert ok.exit_code == 0, ok.output
    assert "check OK" in ok.output and "no earlier passing run" in ok.output

    time.sleep(1.2)  # keep the runs' correlation windows apart (ADR 0003)
    current = _run_and_flag(lab, keep=0.8)
    bad = runner.invoke(app, ["check", "--config", lab["config"]])
    assert bad.exit_code == EXIT_GATE_NOT_PASSED
    assert f"regression vs {baseline}: YES" in bad.output and "recall dropped" in bad.output
    assert current in bad.output


def test_notify_sends_only_on_failure(lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[str] = []
    monkeypatch.setattr(cli, "send_slack", lambda env, text: sent.append(text))
    run_id = _run_and_flag(lab, keep=1.0)
    assert runner.invoke(app, ["check", "--notify", "--config", lab["config"]]).exit_code == 0
    assert sent == []  # passing check: no alert
    Store(lab["db"])  # a second run with no verdicts fails evidence quality
    time.sleep(1.2)
    assert (
        runner.invoke(app, ["run", "--config", lab["config"], "--corpus", str(SEED)]).exit_code == 0
    )
    result = runner.invoke(app, ["check", "--notify", "--config", lab["config"]])
    assert result.exit_code == EXIT_GATE_NOT_PASSED and "alert sent to Slack" in result.output
    assert len(sent) == 1 and "check FAILED" in sent[0]
    assert f"regression vs {run_id}: YES" in sent[0]  # baseline named; metrics only
    assert "Ignore all previous instructions" not in sent[0]  # no corpus text in alerts


def test_notify_failure_is_reported(lab: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CS_TEST_HOOK", raising=False)
    assert (
        runner.invoke(app, ["run", "--config", lab["config"], "--corpus", str(SEED)]).exit_code == 0
    )
    result = runner.invoke(app, ["check", "--notify", "--config", lab["config"]])
    assert result.exit_code == EXIT_GATE_NOT_PASSED
    assert "alert not sent: environment variable CS_TEST_HOOK is not set" in result.output


def test_run_ci_fails_closed_without_verdicts(lab: dict[str, Any]) -> None:
    args = ["run", "--ci", "--config", lab["config"], "--corpus", str(SEED)]
    result = runner.invoke(app, args)
    assert result.exit_code == EXIT_GATE_NOT_PASSED
    assert "no DefenseClaw verdicts ingested" in result.output


def test_notify_requires_ci(lab: dict[str, Any]) -> None:
    result = runner.invoke(app, ["run", "--notify", "--config", lab["config"]])
    assert result.exit_code == EXIT_ERROR and "--notify requires --ci" in result.output


def test_check_errors(lab: dict[str, Any], tmp_path: Path) -> None:
    no_db = runner.invoke(app, ["check", "--config", lab["config"]])
    assert no_db.exit_code == EXIT_ERROR and "no runs yet" in no_db.output
    assert (
        runner.invoke(app, ["run", "--config", lab["config"], "--corpus", str(SEED)]).exit_code == 0
    )
    missing = runner.invoke(app, ["check", "--run", "nope", "--config", lab["config"]])
    assert missing.exit_code == EXIT_ERROR and "'nope' not found" in missing.output
    bad_cfg = runner.invoke(app, ["check", "--config", str(tmp_path / "missing.yaml")])
    assert bad_cfg.exit_code == EXIT_ERROR
