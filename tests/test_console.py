import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from clawshield import cli
from clawshield.cli import EXIT_ERROR
from clawshield.cli import app as cli_app
from clawshield.config import Settings, load_settings
from clawshield.console.app import SECURITY_HEADERS, create_app
from clawshield.core.models import Severity, Verdict
from clawshield.storage.db import RunRow, Store

SEED = Path(__file__).resolve().parents[1] / "redteam" / "corpus" / "seed.jsonl"
HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)>'
cli_runner = CliRunner()


def _config(tmp_path: Path, **console: Any) -> Path:
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({
        "target": {"kind": "mock", "name": "m"}, "targets": {"allowlist": ["m"]},
        "runner": {"inter_case_delay_ms": 0, "correlation_grace_s": 0, "max_cases_per_run": 1000},
        "canaries": ["CANARY-7F3A"], "storage": {"db_path": str(tmp_path / "c.db")},
        **({"console": console} if console else {}),
    }), encoding="utf-8")  # fmt: skip
    return path


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    config = _config(tmp_path)
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})
    run_ids = []
    for notes in ("baseline " + HOSTILE, "second"):
        args = ["run", "--config", str(config), "--corpus", str(SEED), "--notes", notes]
        assert cli_runner.invoke(cli_app, args).exit_code == 0
        run_ids.append(Store(tmp_path / "c.db").get_run("latest").id)
    store = Store(tmp_path / "c.db")
    results = store.results(run_ids[0])
    verdicts = [
        Verdict(id=f"v-{r.case_id}", source="t", ts=r.sent_at, connector="openclaw",
                direction="prompt", severity=Severity.CRITICAL, action="observe",
                rule_id=HOSTILE if r.case_id.startswith("bl-") else "PI-1",
                session_id=r.session_id)
        for r in results if r.case_id.startswith(("d-", "bl-00"))
    ]  # fmt: skip
    store.add_verdicts(verdicts, ingested_at=datetime.now(UTC))
    settings = load_settings(config)
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    return {"client": client, "runs": run_ids, "settings": settings, "config": config}


def _get(lab: dict[str, Any], path: str) -> Any:
    return lab["client"].get(path)


# --- security --------------------------------------------------------------------------------


def test_foreign_host_header_is_rejected_dns_rebinding(lab: dict[str, Any]) -> None:
    for host in ("evil.example", "127.0.0.1.evil.example", "testserver"):
        response = lab["client"].get("/runs", headers={"Host": host})
        assert response.status_code == 400, host
    assert lab["client"].get("/runs", headers={"Host": "localhost:8088"}).status_code == 200


@pytest.mark.parametrize("path", ["/runs", "/trend", "/verdicts", "/healthz"])
def test_security_headers_on_every_response(lab: dict[str, Any], path: str) -> None:
    response = _get(lab, path)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert "script-src 'none'" in response.headers["Content-Security-Policy"]
    assert "server" not in {k.lower() for k in response.headers}


def test_error_pages_also_carry_headers(lab: dict[str, Any]) -> None:
    response = _get(lab, "/runs/does-not-exist")
    assert response.status_code == 404
    assert (
        response.headers["Content-Security-Policy"] == SECURITY_HEADERS["Content-Security-Policy"]
    )


def test_hostile_data_is_escaped_everywhere(lab: dict[str, Any]) -> None:
    run_a = lab["runs"][0]
    pages = ["/runs", f"/runs/{run_a}", f"/runs/{run_a}/recommendations", "/verdicts"]
    for path in pages:
        html = _get(lab, path).text
        assert "<script" not in html.lower(), path
        assert "<img src=x" not in html, path
    assert "&lt;script&gt;" in _get(lab, "/runs").text  # notes shown, escaped
    assert "&lt;script&gt;" in _get(lab, "/verdicts").text  # rule id shown, escaped


def test_console_is_read_only(lab: dict[str, Any]) -> None:
    for method in ("post", "put", "delete", "patch"):
        response = getattr(lab["client"], method)("/runs")
        assert response.status_code == 405, method


def test_no_api_docs_exposed(lab: dict[str, Any]) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert _get(lab, path).status_code == 404


# --- pages --------------------------------------------------------------------------------------


def test_root_redirects_to_runs(lab: dict[str, Any]) -> None:
    response = lab["client"].get("/", follow_redirects=False)
    assert response.status_code == 303 and response.headers["location"] == "/runs"


def test_runs_page_lists_both_runs(lab: dict[str, Any]) -> None:
    html = _get(lab, "/runs").text
    assert all(run_id in html for run_id in lab["runs"])


def test_run_detail_shows_metrics_charts_and_failing_cases(lab: dict[str, Any]) -> None:
    html = _get(lab, f"/runs/{lab['runs'][0]}").text
    assert "Detection rate by category" in html and "<svg" in html
    assert "Failing cases" in html and "false positive" in html and "miss" in html
    assert "No guardrail snapshot" not in html  # snapshot was available


def test_run_without_verdicts_warns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolated DB: in the shared lab, the fast back-to-back second run overlaps the first
    # run's window (correctly reported as an overlap instead).
    config = _config(tmp_path)
    monkeypatch.setattr(cli, "capture_guardrail_snapshot", lambda cfg: {"available": True})
    args = ["run", "--config", str(config), "--corpus", str(SEED)]
    assert cli_runner.invoke(cli_app, args).exit_code == 0
    client = TestClient(create_app(load_settings(config)), base_url="http://127.0.0.1")
    run_id = Store(tmp_path / "c.db").get_run("latest").id
    assert "No DefenseClaw verdicts in this run" in client.get(f"/runs/{run_id}").text


def test_back_to_back_runs_are_flagged_as_overlapping(lab: dict[str, Any]) -> None:
    html = _get(lab, f"/runs/{lab['runs'][1]}").text
    assert "verdicts may be cross-attributed" in html


def test_gate_page_shows_no_action_command_on_fail(lab: dict[str, Any]) -> None:
    html = _get(lab, f"/runs/{lab['runs'][0]}/gate").text
    assert "Promotion gate:" in html and "badge fail" in html
    assert "--mode action --" not in html and "None. Every criterion must PASS" in html


def test_recommendations_page(lab: dict[str, Any]) -> None:
    html = _get(lab, f"/runs/{lab['runs'][0]}/recommendations").text
    assert "narrow_rule" in html and "--mode observe" in html


def test_trend_needs_two_runs_and_draws_lines(lab: dict[str, Any]) -> None:
    html = _get(lab, "/trend").text
    assert "<polyline" in html and all(r in html for r in lab["runs"])


def test_api_score_json(lab: dict[str, Any]) -> None:
    data = _get(lab, f"/api/runs/{lab['runs'][0]}/score").json()
    assert data["run"]["id"] == lab["runs"][0] and data["verdicts_in_window"] > 0
    missing = _get(lab, "/api/runs/nope/score")
    assert missing.status_code == 404 and missing.json() == {"detail": "run 'nope' not found"}


def test_changed_corpus_gives_409(lab: dict[str, Any], tmp_path: Path) -> None:
    store = Store(lab["settings"].storage.db_path)
    run = store.get_run(lab["runs"][0])
    other = tmp_path / "other.jsonl"
    other.write_text(SEED.read_text(encoding="utf-8").split("\n", 1)[1], encoding="utf-8")
    store.create_run(RunRow(**{**run.model_dump(), "id": "moved", "corpus_path": str(other)}))
    response = _get(lab, "/runs/moved")
    assert response.status_code == 409 and "has changed since run" in response.text


def test_empty_state(tmp_path: Path) -> None:
    settings = Settings.model_validate({
        "target": {"kind": "mock", "name": "m"}, "targets": {"allowlist": ["m"]},
        "storage": {"db_path": str(tmp_path / "none.db")},
    })  # fmt: skip
    client = TestClient(create_app(settings), base_url="http://127.0.0.1")
    assert "No runs yet" in client.get("/runs").text
    assert "No DefenseClaw verdicts ingested yet" in client.get("/verdicts").text
    assert "Need at least two" in client.get("/trend").text
    assert client.get("/runs/x").status_code == 404
    assert client.get("/runs/x/gate").status_code == 404
    assert json.loads(client.get("/healthz").text)["status"] == "ok"


# --- CLI ---------------------------------------------------------------------------------------


def test_console_refuses_non_loopback_without_flag(tmp_path: Path) -> None:
    config = _config(tmp_path, host="0.0.0.0", port=8088)  # noqa: S104 - testing the refusal
    result = cli_runner.invoke(cli_app, ["console", "--config", str(config)])
    assert result.exit_code == EXIT_ERROR and "no authentication" in result.output


def test_console_serves_loopback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    seen: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    result = cli_runner.invoke(cli_app, ["console", "--config", str(_config(tmp_path))])
    assert result.exit_code == 0
    assert seen["host"] == "127.0.0.1" and seen["port"] == 8088
    assert seen["server_header"] is False and seen["proxy_headers"] is False


def test_console_allow_remote_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    seen: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    config = _config(tmp_path, host="10.0.0.5", port=9000)
    result = cli_runner.invoke(cli_app, ["console", "--config", str(config), "--allow-remote"])
    assert result.exit_code == 0 and seen["host"] == "10.0.0.5"


def test_console_bad_config(tmp_path: Path) -> None:
    result = cli_runner.invoke(cli_app, ["console", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == EXIT_ERROR
