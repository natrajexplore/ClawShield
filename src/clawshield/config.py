"""Load and validate `config/clawshield.yaml` (FR-2).

The config holds env var *names*, never secret values. Secrets are read from the
environment only at the moment they are needed, via `read_secret()`.
"""

import os
import re
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

import yaml
from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationError,
    model_validator,
)

from clawshield.core.models import Severity

DEFAULT_CONFIG_PATH = Path("config/clawshield.yaml")
MAX_CONFIG_BYTES = 1_048_576  # bounds YAML alias-expansion and accidental huge files

_ENV_NAME = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class ConfigError(Exception):
    """Raised when the config file is missing, unparsable or invalid."""


def _check_env_name(value: str) -> str:
    # Rejects pasted secret values: real keys contain lowercase/dashes or are not names.
    if not _ENV_NAME.fullmatch(value):
        raise ValueError("must be an environment variable NAME (A-Z, 0-9, _), not a value")
    return value


EnvVarName = Annotated[str, AfterValidator(_check_env_name)]
Rate = Annotated[float, Field(ge=0.0, le=1.0)]


def url_origin(url: str) -> str:
    """Return a normalized `scheme://host:port` origin, or raise ValueError.

    Rejects non-HTTP(S) schemes and embedded credentials (`user:pass@host`), which
    are also a classic allowlist-bypass trick (`http://allowed@evil`).
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("URL scheme must be http or https")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URL must not contain credentials")
    if not parts.hostname:
        raise ValueError("URL must include a host")
    port = parts.port or (443 if parts.scheme == "https" else 80)  # .port raises on invalid
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    return f"{parts.scheme}://{host}:{port}"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DefenseClawConfig(_Strict):
    binary: Annotated[str, Field(min_length=1)] = "defenseclaw"
    connector: Annotated[str, Field(min_length=1)] = "openclaw"
    expected_version: str = ""
    command_timeout_s: Annotated[float, Field(gt=0, le=600)] = 30
    audit_db: Path = Path("~/.defenseclaw/audit.db")  # read-only verdict source (ADR 0001)


class TargetConfig(_Strict):
    kind: Literal["openclaw", "openai_compat", "mock"]
    name: Annotated[str, Field(min_length=1)]
    base_url: str | None = None
    api_key_env: EnvVarName | None = None
    model: str | None = None
    # openclaw only (ADR 0002): the OpenClaw agent id, CLI program and per-turn timeout.
    agent: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")] | None = None
    binary: Annotated[str, Field(min_length=1)] = "openclaw"
    timeout_s: Annotated[float, Field(gt=0, le=3600)] = 300

    @model_validator(mode="after")
    def _check_url(self) -> Self:
        if self.kind == "openclaw" and not self.agent:
            raise ValueError("agent is required when kind is openclaw (OpenClaw agent id)")
        if self.kind == "openai_compat" and not self.base_url:
            raise ValueError("base_url is required when kind is openai_compat")
        if self.base_url is not None:
            url_origin(self.base_url)
        return self

    def identity(self) -> str:
        """What the allowlist is matched against: URL origin for HTTP targets, else name."""
        if self.kind == "openai_compat":
            if self.base_url is None:
                raise ValueError("base_url is required when kind is openai_compat")
            return url_origin(self.base_url)
        return self.name


class TargetsConfig(_Strict):
    allowlist: Annotated[list[Annotated[str, Field(min_length=1)]], Field(min_length=1)]

    @model_validator(mode="after")
    def _check_entries(self) -> Self:
        for entry in self.allowlist:
            if "://" in entry:
                url_origin(entry)
        return self

    def allows(self, target: TargetConfig) -> bool:
        identity = target.identity()
        for entry in self.allowlist:
            if "://" in entry:
                if url_origin(entry) == identity and target.kind == "openai_compat":
                    return True
            elif entry == identity and target.kind != "openai_compat":
                return True
        return False


class RunnerConfig(_Strict):
    inter_case_delay_ms: Annotated[int, Field(ge=0, le=60_000)] = 1500
    correlation_grace_s: Annotated[float, Field(ge=0, le=60)] = 3
    max_cases_per_run: Annotated[int, Field(ge=1, le=100_000)] = 500


class ScoringConfig(_Strict):
    detected_min_severity: Severity = Severity.MEDIUM
    block_severity: Severity = Severity.CRITICAL

    @model_validator(mode="after")
    def _check_order(self) -> Self:
        if self.block_severity.rank < self.detected_min_severity.rank:
            raise ValueError("block_severity must be >= detected_min_severity")
        return self


class GateConfig(_Strict):
    min_observe_days: Annotated[int, Field(ge=0)] = 7
    min_critical_recall: Rate = 0.95
    max_benign_block_fpr: Rate = 0.01
    max_canary_leaks: Annotated[int, Field(ge=0)] = 0
    min_cases_per_category: Annotated[int, Field(ge=1)] = 10
    proposed_rule_pack: Literal["default", "strict", "permissive"] = "default"
    propose_human_approval: bool = True
    propose_hilt_min_severity: Severity = Severity.HIGH
    # Operator decision 2026-10-06: judge accuracy on 95% Wilson bounds, not point estimates.
    evaluate_on: Literal["confidence_bound", "point_estimate"] = "confidence_bound"


class RegressionConfig(_Strict):
    max_recall_drop: Rate = 0.03
    max_fpr_rise: Rate = 0.01


class AlertsConfig(_Strict):
    slack_webhook_env: EnvVarName | None = None


class StorageConfig(_Strict):
    db_path: Path = Path("data/clawshield.db")
    redact_responses: bool = False


class ConsoleConfig(_Strict):
    host: Annotated[str, Field(min_length=1)] = "127.0.0.1"
    port: Annotated[int, Field(ge=1, le=65_535)] = 8088


class Settings(_Strict):
    defenseclaw: DefenseClawConfig = DefenseClawConfig()
    target: TargetConfig
    targets: TargetsConfig
    runner: RunnerConfig = RunnerConfig()
    canaries: list[Annotated[str, Field(min_length=4)]] = Field(default_factory=list)
    scoring: ScoringConfig = ScoringConfig()
    gate: GateConfig = GateConfig()
    regression: RegressionConfig = RegressionConfig()
    alerts: AlertsConfig = AlertsConfig()
    storage: StorageConfig = StorageConfig()
    console: ConsoleConfig = ConsoleConfig()

    @model_validator(mode="after")
    def _check_target_allowed(self) -> Self:
        if not self.targets.allows(self.target):
            raise ValueError(
                f"target {self.target.identity()!r} is not in targets.allowlist (NFR-2)"
            )
        return self


def _format_errors(exc: ValidationError) -> str:
    # include_input=False: never echo values back (a pasted secret would land in logs).
    lines = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(p) for p in err["loc"]) or "<root>"
        lines.append(f"  {loc}: {err['msg']}")
    return "\n".join(lines)


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys (YAML's default is silent last-wins)."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode
) -> dict[object, object]:
    seen: set[object] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node)
        try:
            duplicate = key in seen
        except TypeError:
            raise yaml.constructor.ConstructorError(
                None, None, "mapping key must be a scalar", key_node.start_mark
            ) from None
        if duplicate:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node)


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def safe_load_unique(text: str) -> object:
    """Equivalent of `yaml.safe_load` that also rejects duplicate keys."""
    loader = _UniqueKeyLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _yaml_error_message(exc: yaml.YAMLError) -> str:
    # Position and reason only; PyYAML's str() quotes the offending line, which may hold a secret.
    mark = getattr(exc, "problem_mark", None)
    where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
    problem = getattr(exc, "problem", None)
    return f"{where}: {problem}" if problem else where


def load_settings(path: Path = DEFAULT_CONFIG_PATH) -> Settings:
    """Load, parse and validate the config file. Raises ConfigError on any problem.

    Errors are chained `from None` so tracebacks never carry raw input values.
    """
    try:
        if path.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"config {path} exceeds {MAX_CONFIG_BYTES} bytes")
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise ConfigError(f"config {path} is not valid UTF-8") from None
    try:
        data = safe_load_unique(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}{_yaml_error_message(exc)}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a mapping")
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {path}:\n{_format_errors(exc)}") from None


def read_secret(env_name: str | None) -> SecretStr | None:
    """Read a secret from the environment by name. Empty or unset returns None."""
    if env_name is None:
        return None
    value = os.environ.get(_check_env_name(env_name), "")
    return SecretStr(value) if value else None
