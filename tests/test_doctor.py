"""`clawshield doctor` against recorded DefenseClaw/OpenClaw output (no live calls; FR-1)."""

import copy
import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from clawshield import doctor, shell
from clawshield.cli import app
from clawshield.config import Settings
from clawshield.core.models import Case, TargetResult
from clawshield.doctor import PROBE_TEXT, Check, exit_code, run_doctor, version_matches
from clawshield.sources.auditdb import AuditDbSource
from tests.test_auditdb import EPOCH, _finding, build_db

FX = Path(__file__).parent / "fixtures"
VERSION = json.loads((FX / "defenseclaw" / "version.json").read_text("utf-8"))
STATUS = json.loads((FX / "defenseclaw" / "status.json").read_text("utf-8"))
DC_DOCTOR = json.loads((FX / "defenseclaw" / "doctor.json").read_text("utf-8"))
GATEWAY = json.loads((FX / "openclaw" / "gateway_status.json").read_text("utf-8"))
SEED = FX.parents[1] / "redteam" / "corpus" / "seed.jsonl"
T0 = datetime(2026, 10, 7, 12, 0, 0, tzinfo=UTC)
PROBE_SESSION = "agent:helpdesk:explicit:clawshield-doctor-abcd1234-probe"


class FakeCli:
    """Answers `defenseclaw ...` / `openclaw ...` from recorded JSON, per subcommand."""

    def __init__(self, **over: Any) -> None:
        self.outputs: dict[str, Any] = {
            "version": VERSION, "status": STATUS, "doctor": DC_DOCTOR, "gateway": GATEWAY,
        }  # fmt: skip
        self.outputs.update(over)
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str], *, timeout_s: float) -> shell.CommandResult:
        args = list(args)
        self.calls.append(args)
        out = self.outputs[args[1]]
        if isinstance(out, Exception):
            raise out
        stdout = out if isinstance(out, str) else json.dumps(out)
        return shell.CommandResult(tuple(args), 1 if args[1] == "doctor" else 0, stdout, "", 0.1)


class FakeTarget:
    name = "helpdesk-demo"

    def __init__(self, error: str | None = None) -> None:
        self.error = error
        self.sent: list[Case] = []

    def send(self, case: Case) -> TargetResult:
        self.sent.append(case)
        return TargetResult(
            case_id=case.id, session_id=PROBE_SESSION, sent_at=T0,
            received_at=T0 + timedelta(seconds=8), error=self.error,
            response_text=None if self.error else "override accepted",
        )  # fmt: skip


def _probe_row(severity: str = "CRITICAL", session: str = PROBE_SESSION) -> dict[str, Any]:
    return _finding(
        id=f"probe-{severity}", session_id=session, timestamp="2026-10-07T12:00:02.5Z",
        sj={"defenseclaw.security.severity": severity},
    )  # fmt: skip


def _settings(tmp_path: Path, rows: list[dict[str, Any]] | None = None, **target: Any) -> Settings:
    db = build_db(tmp_path / "audit.db", rows if rows is not None else [_probe_row()])
    return Settings.model_validate(
        {
            "defenseclaw": {"audit_db": str(db), "expected_version": "0.8.10"},
            "target": {"kind": "openclaw", "name": "helpdesk-demo", "agent": "helpdesk"} | target,
            "targets": {"allowlist": ["helpdesk-demo"]},
        }
    )


@pytest.fixture
def target(monkeypatch: pytest.MonkeyPatch) -> FakeTarget:
    fake = FakeTarget()
    prefixes: list[str | None] = []

    def build(settings: Settings, *, session_prefix: str | None = None) -> FakeTarget:
        prefixes.append(session_prefix)
        return fake

    monkeypatch.setattr(doctor, "build_target", build)
    fake.prefixes = prefixes  # type: ignore[attr-defined]
    return fake


def _by_name(checks: list[Check]) -> dict[str, Check]:
    return {c.name: c for c in checks}


def _doctor(settings: Settings, cli: FakeCli | None = None, **kw: Any) -> dict[str, Check]:
    sleeps: list[float] = []
    checks = run_doctor(settings, run=cli or FakeCli(), clock=lambda: T0, sleep=sleeps.append, **kw)
    return _by_name(checks)


def test_lab_fixtures_verify(tmp_path: Path, target: FakeTarget) -> None:
    checks = _doctor(_settings(tmp_path))
    assert {n: c.status for n, c in checks.items()} == {
        "DefenseClaw version": "pass", "Guardrail posture": "pass", "DefenseClaw doctor": "warn",
        "Audit database": "pass", "Target gateway": "pass", "In-path probe": "pass",
    }  # fmt: skip
    assert "0.8.10" in checks["DefenseClaw version"].detail
    assert "LLM API key" in checks["DefenseClaw doctor"].detail
    assert "2026.7.35" in checks["Target gateway"].detail
    rule = json.loads(_probe_row()["structured_json"])["defenseclaw.finding.rule_id"]
    assert rule in checks["In-path probe"].detail
    assert exit_code(list(checks.values())) == 0
    assert target.sent[0].text == PROBE_TEXT
    assert target.prefixes[0].startswith("clawshield-doctor-")  # type: ignore[attr-defined]


def test_probe_text_is_corpus_case_d001() -> None:
    d001 = next(
        json.loads(line) for line in SEED.read_text("utf-8").splitlines() if '"d-001"' in line
    )
    assert d001["text"] == PROBE_TEXT


def test_probe_without_finding_fails_loudly(tmp_path: Path, target: FakeTarget) -> None:
    other = _probe_row(session="agent:helpdesk:explicit:someone-else")
    checks = _doctor(_settings(tmp_path, [other]))
    probe = checks["In-path probe"]
    assert probe.status == "fail" and "NOT inspecting" in probe.detail
    assert exit_code(list(checks.values())) == 1


def test_probe_with_only_lower_severity_fails(tmp_path: Path, target: FakeTarget) -> None:
    probe = _doctor(_settings(tmp_path, [_probe_row("HIGH")]))["In-path probe"]
    assert probe.status == "fail" and "only 1 lower-severity" in probe.detail


def test_probe_turn_error_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bypass = FakeTarget(error="turn ran on harness 'codex', not 'openclaw'")
    monkeypatch.setattr(doctor, "build_target", lambda s, session_prefix=None: bypass)
    probe = _doctor(_settings(tmp_path))["In-path probe"]
    assert probe.status == "fail" and "harness 'codex'" in probe.detail


def test_probe_waits_for_the_finding(tmp_path: Path, target: FakeTarget) -> None:
    settings = _settings(tmp_path, [])
    sleeps: list[float] = []

    def late_write(seconds: float) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 2:
            build_db(tmp_path / "late.db", [_probe_row()])
            (tmp_path / "audit.db").unlink()
            (tmp_path / "late.db").rename(tmp_path / "audit.db")

    checks = run_doctor(settings, run=FakeCli(), clock=lambda: T0, sleep=late_write)
    assert _by_name(checks)["In-path probe"].status == "pass"
    assert sleeps == [doctor.PROBE_POLL_S] * 2


def test_probe_refused_target(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    tampered = settings.model_copy(
        update={"targets": settings.targets.model_copy(update={"allowlist": ["other"]})}
    )
    probe = _doctor(tampered)["In-path probe"]
    assert probe.status == "fail" and "allowlist" in probe.detail


def test_no_probe_is_not_verified(tmp_path: Path, target: FakeTarget) -> None:
    checks = _doctor(_settings(tmp_path), probe=False)
    assert checks["In-path probe"].status == "skip" and target.sent == []
    assert exit_code(list(checks.values())) == 3


def test_mock_target_cannot_be_verified(tmp_path: Path, target: FakeTarget) -> None:
    settings = _settings(tmp_path)
    mock = settings.model_copy(
        update={
            "target": settings.target.model_copy(update={"kind": "mock", "agent": None}),
        }
    )
    checks = _doctor(mock)
    assert checks["In-path probe"].status == "skip" and checks["Target gateway"].status == "skip"
    assert exit_code(list(checks.values())) == 3 and target.sent == []


VER, POS, DOC, GW = (
    "DefenseClaw version",
    "Guardrail posture",
    "DefenseClaw doctor",
    "Target gateway",
)


def _with(data: dict[str, Any], path: Sequence[Any], value: Any) -> dict[str, Any]:
    out = copy.deepcopy(data)
    node: Any = out
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return out


@pytest.mark.parametrize(
    ("over", "check", "status", "text"),
    [
        ({"version": _with(VERSION, ["drift"], ["plugin 0.8.9"])}, VER, "fail", "out of sync"),
        ({"version": _with(VERSION, ["components", 0, "version"], "0.9.0")}, VER, "fail", "pins"),
        ({"version": "nope"}, VER, "fail", "no JSON"),
        ({"version": [1]}, VER, "fail", "not an object"),
        ({"version": shell.CommandNotFoundError("not found")}, VER, "fail", "not found"),
        ({"status": _with(STATUS, ["sidecar", "running"], False)}, POS, "fail", "sidecar"),
        ({"status": _with(STATUS, ["connectors"], [])}, POS, "fail", "not configured"),
        ({"status": _with(STATUS, ["connectors", 0, "enabled"], False)}, POS, "fail", "disabled"),
        ({"status": _with(STATUS, ["connectors", 0, "mode"], "action")}, POS, "warn", "ACTION"),
        ({"status": _with(STATUS, ["connectors", 0, "mode"], "weird")}, POS, "fail", "unknown"),
        ({"status": "x"}, POS, "fail", "no JSON"),
        ({"doctor": {**DC_DOCTOR, "checks": []}}, DOC, "pass", "35 passed"),
        ({"doctor": "crash"}, DOC, "warn", "no JSON"),
        ({"gateway": _with(GATEWAY, ["rpc", "ok"], False)}, GW, "fail", "not reachable"),
        ({"gateway": "down"}, GW, "fail", "no JSON"),
    ],
)  # fmt: skip
def test_individual_check_outcomes(
    tmp_path: Path, target: FakeTarget, over: dict[str, Any], check: str, status: str, text: str
) -> None:
    got = _doctor(_settings(tmp_path), FakeCli(**over))[check]
    assert got.status == status and text in got.detail


def test_many_doctor_failures_are_truncated(tmp_path: Path, target: FakeTarget) -> None:
    failing = [{"status": "fail", "label": f"check {n}"} for n in range(8)]
    got = _doctor(_settings(tmp_path), FakeCli(doctor={"passed": 1, "checks": failing}))
    assert got["DefenseClaw doctor"].detail.endswith("check 4 ...")


def test_missing_audit_db_fails(tmp_path: Path, target: FakeTarget) -> None:
    settings = _settings(tmp_path)
    (tmp_path / "audit.db").unlink()
    checks = _doctor(settings)
    assert checks["Audit database"].status == "fail"
    assert (
        checks["In-path probe"].status == "fail" and "not found" in checks["In-path probe"].detail
    )


@pytest.mark.parametrize(
    ("actual", "expected", "ok"),
    [("0.8.10", "", True), ("0.8.10", "0.8.10", True), ("0.8.11", "0.8.10", False),
     ("0.8.11", "0.8.x", True), ("0.9.0", "0.8.x", False), ("0.8.1", "0.8.10", False)],
)  # fmt: skip
def test_version_matches(actual: str, expected: str, ok: bool) -> None:
    assert version_matches(actual, expected) is ok


def test_probe_sessions_are_excluded_from_normal_ingest(tmp_path: Path) -> None:
    db = build_db(tmp_path / "audit.db", [_probe_row()])
    assert AuditDbSource(db, connector="openclaw").read(EPOCH).skipped == {
        "clawshield doctor probe": 1
    }
    assert len(AuditDbSource(db, connector="openclaw", include_probes=True).fetch(EPOCH)) == 1


# --- CLI ---------------------------------------------------------------------------------

runner = CliRunner()


def _cli_config(tmp_path: Path) -> Path:
    path = tmp_path / "clawshield.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "target": {"kind": "mock", "name": "lab-mock"},
                "targets": {"allowlist": ["lab-mock"]},
                "defenseclaw": {"audit_db": str(build_db(tmp_path / "audit.db", []))},
            }
        ),
        encoding="utf-8",
    )
    return path


def test_cli_doctor_prints_checks_and_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "clawshield.cli.run_doctor",
        lambda settings, probe: [Check("A", "pass", "fine\x1b[31m"), Check("B", "skip", "why")],
    )
    result = runner.invoke(app, ["doctor", "--config", str(_cli_config(tmp_path))])
    assert result.exit_code == 3
    assert "[PASS] A" in result.output and "fine\\x1b[31m" in result.output
    assert "NOT VERIFIED" in result.output


@pytest.mark.parametrize(
    ("status", "code", "word"), [("pass", 0, "VERIFIED"), ("fail", 1, "FAILED")]
)
def test_cli_doctor_verdicts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str, code: int, word: str
) -> None:
    seen: list[bool] = []

    def fake(settings: Settings, probe: bool) -> list[Check]:
        seen.append(probe)
        return [Check("A", status, "x")]  # type: ignore[arg-type]

    monkeypatch.setattr("clawshield.cli.run_doctor", fake)
    result = runner.invoke(app, ["doctor", "--config", str(_cli_config(tmp_path)), "--no-probe"])
    assert result.exit_code == code and f"doctor: {word}" in result.output
    assert seen == [False]


def test_cli_doctor_bad_config(tmp_path: Path) -> None:
    result = runner.invoke(app, ["doctor", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == 1
