"""promptfoo import tests. The fixture follows promptfoo's EvaluateSummaryV3 types (source,
2026-10-06); replace with a real captured results.json from the lab. Texts are neutral
placeholders: the importer's behaviour does not depend on what a case says."""

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from clawshield.cli import EXIT_ERROR, app
from clawshield.core.models import Category, Severity
from clawshield.redteam.corpus import load_corpus
from clawshield.redteam.promptfoo import (
    MAX_RESULTS_BYTES,
    PromptfooImportError,
    import_promptfoo,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SEED = REPO_ROOT / "redteam" / "corpus" / "seed.jsonl"
CONFIG = REPO_ROOT / "config" / "clawshield.yaml"


def row(text: Any, plugin: Any = "hijacking", strategy: Any = None, **meta: Any) -> dict[str, Any]:
    metadata: dict[str, Any] = {"pluginId": plugin, **meta}
    if strategy is not None:
        metadata["strategyId"] = strategy
    return {
        "promptIdx": 0, "testIdx": 0, "success": False, "score": 0,
        "vars": {"prompt": text},
        "testCase": {"vars": {"prompt": text}, "metadata": metadata},
        "response": {"output": "target output is ignored by the importer"},
    }  # fmt: skip


def results_file(tmp_path: Path, rows: list[dict[str, Any]], name: str = "results.json") -> Path:
    data = {
        "evalId": "eval-test",
        "results": {"version": 3, "timestamp": "2026-10-06T12:00:00Z", "results": rows,
                    "prompts": [], "stats": {"successes": 0, "failures": len(rows)}},
        "config": {}, "shareableUrl": None,
    }  # fmt: skip
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


# --- mapping ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("plugin", "strategy", "category", "severity"),
    [
        ("prompt-extraction", None, Category.LLM07_SYSPROMPT, Severity.HIGH),
        ("pii:direct", None, Category.LLM02_SENSITIVE, Severity.HIGH),
        ("hijacking", None, Category.LLM01_DIRECT, Severity.CRITICAL),
        ("indirect-prompt-injection", None, Category.LLM01_INDIRECT, Severity.HIGH),
        ("hijacking", "base64", Category.OBFUSCATION, Severity.HIGH),
        ("pii", "jailbreak:composite", Category.JAILBREAK, Severity.HIGH),
        ("prompt-extraction", "prompt-injection", Category.LLM07_SYSPROMPT, Severity.HIGH),
    ],
)
def test_plugin_and_strategy_mapping(
    tmp_path: Path, plugin: str, strategy: str | None, category: Category, severity: Severity
) -> None:
    report = import_promptfoo(results_file(tmp_path, [row("placeholder case", plugin, strategy)]))
    (case,) = report.cases
    assert (case.category, case.expected_severity, case.label) == (category, severity, "malicious")
    assert case.id.startswith("pf-") and report.severity_defaulted == 1


def test_promptfoo_severity_overrides_default(tmp_path: Path) -> None:
    rows = [row("p1", severity="critical"), row("p2", "pii", severity="informational")]
    report = import_promptfoo(results_file(tmp_path, rows))
    assert [c.expected_severity for c in report.cases] == [Severity.CRITICAL, Severity.LOW]
    assert report.severity_defaulted == 0


def test_unlisted_plugins_are_rejected_not_guessed(tmp_path: Path) -> None:
    rows = [row("p1", "harmful:example"), row("p2", "harmful:example", "base64"),
            row("p3", "some-new-plugin"), row("ok")]  # fmt: skip
    report = import_promptfoo(results_file(tmp_path, rows))
    assert len(report.cases) == 1
    assert report.rejected == {
        "plugin not on allowlist: harmful:example": 2,
        "plugin not on allowlist: some-new-plugin": 1,
    }


def test_malformed_rows_are_counted(tmp_path: Path) -> None:
    rows: list[Any] = [
        "not an object",
        {"no": "testCase"},
        row("x", plugin=None),
        row(None),
        row("y", strategy=7),
        row(""),
        row("z" * 40_000),
        row("fine"),
    ]
    report = import_promptfoo(results_file(tmp_path, rows))
    assert len(report.cases) == 1
    assert report.rejected == {
        "missing testCase": 2, "missing pluginId": 1, "missing vars.prompt": 1,
        "invalid strategyId": 1, "invalid text": 2,
    }  # fmt: skip


def test_custom_inject_var(tmp_path: Path) -> None:
    r = row("ignored")
    r["testCase"]["vars"] = {"query": "from query var"}
    report = import_promptfoo(results_file(tmp_path, [r]), inject_var="query")
    assert report.cases[0].text == "from query var"


def test_text_is_preserved_exactly(tmp_path: Path) -> None:
    text = "  spaced\ttext with " + chr(0x200B) + " zero-width and " + chr(0x0435) + "  "
    (case,) = import_promptfoo(results_file(tmp_path, [row(text)])).cases
    assert case.text == text


def test_duplicates_within_file_and_against_base_are_skipped(tmp_path: Path) -> None:
    rows = [row("same text"), row("Same   TEXT"), row("already in base"), row("new")]
    report = import_promptfoo(results_file(tmp_path, rows), existing_texts=["already in base"])
    assert [c.text for c in report.cases] == ["same text", "new"]
    assert report.duplicates == 2


def test_ids_are_stable_across_imports(tmp_path: Path) -> None:
    a = import_promptfoo(results_file(tmp_path, [row("stable")], "a.json")).cases[0].id
    b = import_promptfoo(results_file(tmp_path, [row("stable")], "b.json")).cases[0].id
    c = import_promptfoo(results_file(tmp_path, [row("stable", "pii")], "c.json")).cases[0].id
    assert a == b != c


# --- file handling (untrusted input) --------------------------------------------------------------


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ('{"results": {"results": [], "results": []}}', "duplicate key"),
        ('{"results": {"results": [NaN]}}', "non-standard JSON constant"),
        ("{not json", "invalid JSON"),
        ('{"results": {"outputs": []}}', "expected results.results to be a list"),
        ("[]", "expected results.results to be a list"),
    ],
)
def test_bad_files_rejected(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(PromptfooImportError, match=message):
        import_promptfoo(path)


def test_missing_oversized_and_non_utf8(tmp_path: Path) -> None:
    with pytest.raises(PromptfooImportError, match="cannot read"):
        import_promptfoo(tmp_path / "missing.json")
    big = tmp_path / "big.json"
    with big.open("wb") as f:
        f.truncate(MAX_RESULTS_BYTES + 1)
    with pytest.raises(PromptfooImportError, match="exceeds"):
        import_promptfoo(big)
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"x": "\xff"}')
    with pytest.raises(PromptfooImportError, match="UTF-8"):
        import_promptfoo(bad)


# --- CLI ------------------------------------------------------------------------------------------

runner = CliRunner()


def test_cli_ingest_writes_valid_combined_corpus(tmp_path: Path) -> None:
    rows = [row(f"placeholder hijack {i}") for i in range(3)]
    rows += [row("placeholder extraction", "prompt-extraction"), row("x", "harmful:example")]
    out = tmp_path / "combined.jsonl"
    result = runner.invoke(app, ["ingest", "--promptfoo", str(results_file(tmp_path, rows)),
                                 "--out", str(out), "--config", str(CONFIG)])  # fmt: skip
    assert result.exit_code == 0, result.output
    assert "imported 4 case(s)" in result.output
    assert "critical 3" in result.output
    assert "rejected 1: plugin not on allowlist: harmful:example" in result.output
    base = load_corpus(SEED, known_canaries=["CANARY-7F3A"])
    combined = load_corpus(out, known_canaries=["CANARY-7F3A"])
    assert len(combined.cases) == len(base.cases) + 4
    assert combined.cases[: len(base.cases)] == base.cases  # base kept verbatim, in order
    out.read_bytes().decode("ascii")  # ASCII for review


def test_cli_ingest_refuses_to_overwrite_base(tmp_path: Path) -> None:
    result = runner.invoke(app, ["ingest", "--promptfoo", str(results_file(tmp_path, [row("x")])),
                                 "--out", str(SEED), "--config", str(CONFIG)])  # fmt: skip
    assert result.exit_code == EXIT_ERROR and "never modified" in result.output


def test_cli_ingest_with_nothing_importable(tmp_path: Path) -> None:
    path = results_file(tmp_path, [row("x", "harmful:example")])
    result = runner.invoke(app, ["ingest", "--promptfoo", str(path),
                                 "--out", str(tmp_path / "o.jsonl"),
                                 "--config", str(CONFIG)])  # fmt: skip
    assert result.exit_code == EXIT_ERROR and "no importable cases" in result.output
    assert not (tmp_path / "o.jsonl").exists()


def test_cli_ingest_bad_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("[]", encoding="utf-8")
    result = runner.invoke(app, ["ingest", "--promptfoo", str(bad), "--config", str(CONFIG),
                                 "--out", str(tmp_path / "o.jsonl")])  # fmt: skip
    assert result.exit_code == EXIT_ERROR and "not a promptfoo results file" in result.output


def test_cli_ingest_without_promptfoo_reads_verdicts_and_fails_closed(tmp_path: Path) -> None:
    # Without --promptfoo, ingest reads DefenseClaw verdicts (tests/test_auditdb.py); a bad
    # config must still exit non-zero.
    result = runner.invoke(app, ["ingest", "--config", str(tmp_path / "missing.yaml")])
    assert result.exit_code == EXIT_ERROR


def test_cli_ingest_removes_combined_corpus_that_fails_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from clawshield import cli

    def corrupt(base_lines: list[str], cases: Any, out: Path) -> int:
        out.write_text('{"id": "broken"}\n', encoding="ascii")
        return 1

    monkeypatch.setattr(cli, "write_combined_corpus", corrupt)
    out = tmp_path / "combined.jsonl"
    result = runner.invoke(app, ["ingest", "--promptfoo", str(results_file(tmp_path, [row("x")])),
                                 "--out", str(out), "--config", str(CONFIG)])  # fmt: skip
    assert result.exit_code == EXIT_ERROR
    assert "failed validation and was removed" in result.output
    assert not out.exists()
