"""Import promptfoo red-team results as labeled corpus cases (FR-5).

File shape verified against promptfoo's source (src/types/index.ts EvaluateSummaryV3,
src/util/output.ts), 2026-10-06; confirm with a real captured results.json from the lab:

    {"evalId": ..., "results": {"version": 3, "results": [EvaluateResult, ...]}, ...}
    EvaluateResult.testCase.vars[<injectVar>]  -> the attack text
    EvaluateResult.testCase.metadata.pluginId / strategyId / severity (optional)

The file is untrusted data (THREAT_MODEL: malicious corpus import): size-capped, parsed
strictly, every case schema-validated, nothing executed. Only plugins on an explicit
allowlist are mapped to categories; anything else is rejected and counted, which also
keeps generators such as `harmful:*` out of the corpus (CLAUDE.md corpus safety rule).
"""

import hashlib
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from clawshield.core.models import Case, Category, Severity

MAX_RESULTS_BYTES = 200 * 1024 * 1024
DEFAULT_INJECT_VAR = "prompt"

PLUGIN_CATEGORIES: Mapping[str, Category] = {
    "prompt-extraction": Category.LLM07_SYSPROMPT,
    "pii": Category.LLM02_SENSITIVE,
    "pii:direct": Category.LLM02_SENSITIVE,
    "pii:session": Category.LLM02_SENSITIVE,
    "pii:social": Category.LLM02_SENSITIVE,
    "pii:api-db": Category.LLM02_SENSITIVE,
    "hijacking": Category.LLM01_DIRECT,
    "indirect-prompt-injection": Category.LLM01_INDIRECT,
}
OBFUSCATION_STRATEGIES = frozenset(
    {"base64", "rot13", "hex", "leetspeak", "homoglyph", "ascii-smuggling", "morse", "camelcase"}
)
DEFAULT_SEVERITY: Mapping[Category, Severity] = {
    Category.LLM01_DIRECT: Severity.CRITICAL,
    Category.LLM01_INDIRECT: Severity.HIGH,
    Category.LLM02_SENSITIVE: Severity.HIGH,
    Category.LLM07_SYSPROMPT: Severity.HIGH,
    Category.JAILBREAK: Severity.HIGH,
    Category.OBFUSCATION: Severity.HIGH,
}
PROMPTFOO_SEVERITY: Mapping[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.LOW,
}


class PromptfooImportError(Exception):
    """The file is not a readable promptfoo results file."""


@dataclass(frozen=True)
class ImportReport:
    cases: tuple[Case, ...]
    rejected: Mapping[str, int] = field(default_factory=dict)  # reason -> count
    duplicates: int = 0
    severity_defaulted: int = 0


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-standard JSON constant {name}")


def _load(path: Path) -> Any:
    try:
        if path.stat().st_size > MAX_RESULTS_BYTES:
            raise PromptfooImportError(f"{path} exceeds {MAX_RESULTS_BYTES} bytes")
        text = path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise PromptfooImportError(f"cannot read {path}: {exc.strerror}") from None
    except UnicodeDecodeError:
        raise PromptfooImportError(f"{path} is not valid UTF-8") from None
    try:
        return json.loads(
            text, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
        )
    except ValueError as exc:
        reason = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
        raise PromptfooImportError(f"{path}: invalid JSON: {reason}") from None


def _results_list(data: Any) -> list[Any]:
    summary = data.get("results") if isinstance(data, dict) else None
    rows = summary.get("results") if isinstance(summary, dict) else None
    if not isinstance(rows, list):
        raise PromptfooImportError(
            "not a promptfoo results file: expected results.results to be a list "
            "(promptfoo eval --output results.json, summary version 3)"
        )
    return rows


def _category(plugin: str, strategy: str | None) -> Category | None:
    if strategy:
        if strategy in OBFUSCATION_STRATEGIES:
            return Category.OBFUSCATION if plugin in PLUGIN_CATEGORIES else None
        if strategy == "jailbreak" or strategy.startswith("jailbreak:"):
            return Category.JAILBREAK if plugin in PLUGIN_CATEGORIES else None
    return PLUGIN_CATEGORIES.get(plugin)


def _case_id(plugin: str, strategy: str | None, text: str) -> str:
    digest = hashlib.sha256(f"{plugin}\x1f{strategy or ''}\x1f{text}".encode()).hexdigest()
    return f"pf-{digest[:16]}"


def import_promptfoo(
    path: Path, *, inject_var: str = DEFAULT_INJECT_VAR, existing_texts: Iterable[str] = ()
) -> ImportReport:
    rows = _results_list(_load(path))
    known = {" ".join(t.casefold().split()) for t in existing_texts}
    rejected: Counter[str] = Counter()
    cases: list[Case] = []
    seen_ids: set[str] = set()
    duplicates = defaulted = 0

    for row in rows:
        test = row.get("testCase") if isinstance(row, dict) else None
        if not isinstance(test, dict):
            rejected["missing testCase"] += 1
            continue
        raw_meta, raw_vars = test.get("metadata"), test.get("vars")
        meta: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        variables: dict[str, Any] = raw_vars if isinstance(raw_vars, dict) else {}
        plugin, strategy = meta.get("pluginId"), meta.get("strategyId")
        text = variables.get(inject_var)
        if not isinstance(plugin, str) or not plugin:
            rejected["missing pluginId"] += 1
            continue
        if strategy is not None and not isinstance(strategy, str):
            rejected["invalid strategyId"] += 1
            continue
        if not isinstance(text, str):
            rejected[f"missing vars.{inject_var}"] += 1
            continue
        category = _category(plugin, strategy)
        if category is None:
            rejected[f"plugin not on allowlist: {plugin[:40]}"] += 1
            continue
        severity = PROMPTFOO_SEVERITY.get(str(meta.get("severity", "")).lower())
        if severity is None:
            severity = DEFAULT_SEVERITY[category]
            defaulted += 1
        normalized = " ".join(text.casefold().split())
        case_id = _case_id(plugin, strategy, text)
        if case_id in seen_ids or normalized in known:
            duplicates += 1
            continue
        try:
            case = Case(
                id=case_id, text=text, label="malicious", category=category,
                expected_severity=severity,
            )  # fmt: skip
        except ValidationError as exc:
            field_name = ".".join(str(p) for p in exc.errors()[0]["loc"]) or "case"
            rejected[f"invalid {field_name}"] += 1
            continue
        seen_ids.add(case_id)
        known.add(normalized)
        cases.append(case)

    return ImportReport(
        cases=tuple(cases), rejected=dict(rejected), duplicates=duplicates,
        severity_defaulted=defaulted,
    )  # fmt: skip


def write_combined_corpus(base_lines: list[str], cases: Iterable[Case], out: Path) -> int:
    """Write base corpus lines (verbatim) plus imported cases as ASCII JSONL."""
    imported = [
        json.dumps(c.model_dump(mode="json", exclude_none=True), ensure_ascii=True) for c in cases
    ]
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join([*base_lines, *imported]) + "\n", encoding="ascii", newline="\n")
    return len(imported)
