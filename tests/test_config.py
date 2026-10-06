from pathlib import Path
from typing import Any

import pytest
import yaml

from clawshield.config import (
    DEFAULT_CONFIG_PATH,
    MAX_CONFIG_BYTES,
    ConfigError,
    Settings,
    load_settings,
    read_secret,
    url_origin,
)
from clawshield.core.models import Severity

REPO_ROOT = Path(__file__).resolve().parents[1]


def _base() -> dict[str, Any]:
    return {
        "target": {"kind": "mock", "name": "lab-mock"},
        "targets": {"allowlist": ["lab-mock"]},
    }


def _write(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "clawshield.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def _error(tmp_path: Path, data: object) -> str:
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, data))
    return str(exc.value)


# --- shipped config -------------------------------------------------------------


def test_shipped_config_is_valid() -> None:
    s = load_settings(REPO_ROOT / DEFAULT_CONFIG_PATH)
    assert s.target.kind == "openclaw"
    assert s.gate.min_critical_recall == 0.95
    assert s.scoring.block_severity is Severity.CRITICAL
    assert s.console.host == "127.0.0.1"
    assert s.alerts.slack_webhook_env == "CLAWSHIELD_SLACK_WEBHOOK"


def test_defaults_match_prd_fr16(tmp_path: Path) -> None:
    g = load_settings(_write(tmp_path, _base())).gate
    assert (g.min_observe_days, g.min_critical_recall, g.max_benign_block_fpr) == (7, 0.95, 0.01)
    assert (g.max_canary_leaks, g.min_cases_per_category) == (0, 10)


def test_settings_are_immutable(tmp_path: Path) -> None:
    s = load_settings(_write(tmp_path, _base()))
    with pytest.raises(ValueError, match="frozen"):
        s.gate.min_critical_recall = 0.0  # type: ignore[misc]


# --- allowlist (NFR-2) ----------------------------------------------------------


def test_named_target_not_allowlisted(tmp_path: Path) -> None:
    data = _base()
    data["targets"]["allowlist"] = ["other"]
    assert "not in targets.allowlist" in _error(tmp_path, data)


def test_empty_allowlist_rejected(tmp_path: Path) -> None:
    data = _base()
    data["targets"]["allowlist"] = []
    assert "targets.allowlist" in _error(tmp_path, data)


@pytest.mark.parametrize(
    ("base_url", "entry"),
    [
        ("http://127.0.0.1:4000/v1", "http://127.0.0.1:4000"),
        ("HTTP://LocalHost:4000/v1", "http://localhost:4000/"),
        ("https://lab.internal/v1", "https://lab.internal:443"),
        ("http://[::1]:4000/v1", "http://[::1]:4000"),
    ],
)
def test_url_target_allowed_by_origin(tmp_path: Path, base_url: str, entry: str) -> None:
    data = {
        "target": {"kind": "openai_compat", "name": "x", "base_url": base_url},
        "targets": {"allowlist": [entry]},
    }
    assert load_settings(_write(tmp_path, data)).target.base_url == base_url


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:4001/v1",  # different port
        "https://127.0.0.1:4000/v1",  # different scheme
        "http://localhost:4000/v1",  # different host spelling: fail closed
    ],
)
def test_url_target_other_origin_rejected(tmp_path: Path, base_url: str) -> None:
    data = {
        "target": {"kind": "openai_compat", "name": "x", "base_url": base_url},
        "targets": {"allowlist": ["http://127.0.0.1:4000"]},
    }
    assert "not in targets.allowlist" in _error(tmp_path, data)


def test_userinfo_bypass_rejected(tmp_path: Path) -> None:
    data = {
        "target": {
            "kind": "openai_compat",
            "name": "x",
            "base_url": "http://127.0.0.1:4000@evil.example/v1",
        },
        "targets": {"allowlist": ["http://127.0.0.1:4000"]},
    }
    assert "credentials" in _error(tmp_path, data)


def test_name_entry_does_not_allow_url_target(tmp_path: Path) -> None:
    data = {
        "target": {"kind": "openai_compat", "name": "lab", "base_url": "http://127.0.0.1:4000"},
        "targets": {"allowlist": ["lab"]},
    }
    assert "not in targets.allowlist" in _error(tmp_path, data)


def test_openai_compat_requires_base_url(tmp_path: Path) -> None:
    data = {"target": {"kind": "openai_compat", "name": "x"}, "targets": {"allowlist": ["x"]}}
    assert "base_url is required" in _error(tmp_path, data)


@pytest.mark.parametrize(
    "url", ["ftp://h/x", "file:///etc/passwd", "http:///nohost", "http://h:99999"]
)
def test_url_origin_rejects_bad_urls(url: str) -> None:
    with pytest.raises(ValueError):
        url_origin(url)


def test_bad_allowlist_url_entry_rejected(tmp_path: Path) -> None:
    data = _base()
    data["targets"]["allowlist"].append("ftp://lab")
    assert "scheme" in _error(tmp_path, data)


# --- secrets ----------------------------------------------------------------------


def test_pasted_secret_rejected_and_not_echoed(tmp_path: Path) -> None:
    fake_secret = "sk-test-NOT-A-REAL-KEY-abc123"
    data = _base()
    data["alerts"] = {"slack_webhook_env": fake_secret}
    message = _error(tmp_path, data)
    assert "environment variable NAME" in message
    assert fake_secret not in message


def test_error_has_no_chained_cause(tmp_path: Path) -> None:
    data = _base()
    data["alerts"] = {"slack_webhook_env": "https://hooks.example/secret"}
    with pytest.raises(ConfigError) as exc:
        load_settings(_write(tmp_path, data))
    assert exc.value.__cause__ is None
    assert exc.value.__suppress_context__ is True


def test_read_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAWSHIELD_TEST_SECRET", "s3cr3t")
    secret = read_secret("CLAWSHIELD_TEST_SECRET")
    assert secret is not None
    assert secret.get_secret_value() == "s3cr3t"
    assert "s3cr3t" not in repr(secret) and "s3cr3t" not in str(secret)


def test_read_secret_unset_or_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CLAWSHIELD_TEST_SECRET", raising=False)
    assert read_secret("CLAWSHIELD_TEST_SECRET") is None
    monkeypatch.setenv("CLAWSHIELD_TEST_SECRET", "")
    assert read_secret("CLAWSHIELD_TEST_SECRET") is None
    assert read_secret(None) is None


def test_read_secret_rejects_non_name() -> None:
    with pytest.raises(ValueError):
        read_secret("not a name")


# --- thresholds and structure ------------------------------------------------------


def test_unknown_key_rejected(tmp_path: Path) -> None:
    data = _base()
    data["gate"] = {"min_critical_recal": 0.5}  # typo must not silently use the default
    assert "gate.min_critical_recal" in _error(tmp_path, data)


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("gate", "min_critical_recall", 1.5),
        ("gate", "max_benign_block_fpr", -0.1),
        ("gate", "min_cases_per_category", 0),
        ("regression", "max_fpr_rise", 2),
        ("runner", "max_cases_per_run", 0),
        ("console", "port", 70000),
        ("defenseclaw", "command_timeout_s", 0),
        ("gate", "proposed_rule_pack", "yolo"),
        ("scoring", "block_severity", "severe"),
    ],
)
def test_out_of_range_rejected(tmp_path: Path, section: str, key: str, value: object) -> None:
    data = _base()
    data[section] = {key: value}
    assert f"{section}.{key}" in _error(tmp_path, data)


def test_block_below_detected_rejected(tmp_path: Path) -> None:
    data = _base()
    data["scoring"] = {"detected_min_severity": "high", "block_severity": "medium"}
    assert "block_severity must be >= detected_min_severity" in _error(tmp_path, data)


def test_short_canary_rejected(tmp_path: Path) -> None:
    data = _base()
    data["canaries"] = ["ab"]
    assert "canaries.0" in _error(tmp_path, data)


def test_severity_order() -> None:
    ranks = [s.rank for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert ranks == sorted(ranks) and len(set(ranks)) == 4


# --- file handling -----------------------------------------------------------------


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read config"):
        load_settings(tmp_path / "nope.yaml")


@pytest.mark.parametrize("text", ["- a\n- b\n", "just a string\n", ""])
def test_non_mapping_top_level(tmp_path: Path, text: str) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="top level must be a mapping"):
        load_settings(path)


def test_duplicate_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text(
        "target: {kind: mock, name: m}\ntargets: {allowlist: [m]}\n"
        "gate:\n  min_critical_recall: 0.95\n  min_critical_recall: 0.1\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate key 'min_critical_recall'"):
        load_settings(path)


def test_unhashable_key_rejected(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("? [a, b]\n: 1\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_settings(path)


def test_python_tags_not_executed(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("x: !!python/object/apply:os.system ['echo pwned']\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_settings(path)


def test_loader_is_safe_loader() -> None:
    from clawshield.config import _UniqueKeyLoader

    assert issubclass(_UniqueKeyLoader, yaml.SafeLoader)


def test_non_printable_character_rejected(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("target: \x07\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_settings(path)


def test_yaml_error_does_not_quote_line(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_text("alerts: {slack_webhook_env: SECRETVALUE123\n", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_settings(path)
    assert "line" in str(exc.value)
    assert "SECRETVALUE123" not in str(exc.value)


def test_oversized_file_rejected(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))
    with pytest.raises(ConfigError, match="exceeds"):
        load_settings(path)


def test_non_utf8_rejected(tmp_path: Path) -> None:
    path = tmp_path / "c.yaml"
    path.write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(ConfigError, match="UTF-8"):
        load_settings(path)


def test_settings_model_directly() -> None:
    s = Settings.model_validate(_base())
    assert s.target.identity() == "lab-mock"
