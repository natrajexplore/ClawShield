import pytest
from typer.testing import CliRunner

from clawshield import __version__
from clawshield.cli import EXIT_NOT_IMPLEMENTED, app

runner = CliRunner()

STUB_COMMANDS = ["doctor", "run", "score", "gate", "ingest"]


def test_help_lists_all_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in STUB_COMMANDS:
        assert command in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.mark.parametrize("command", STUB_COMMANDS)
def test_stubs_fail_closed(command: str) -> None:
    result = runner.invoke(app, [command])
    assert result.exit_code == EXIT_NOT_IMPLEMENTED
    assert "not implemented" in result.output


def test_documented_options_parse() -> None:
    # Options shown in CLAUDE.md must be accepted (stub still fails closed).
    assert runner.invoke(app, ["run", "--corpus", "x.jsonl"]).exit_code == EXIT_NOT_IMPLEMENTED
    assert runner.invoke(app, ["score", "--run", "latest"]).exit_code == EXIT_NOT_IMPLEMENTED
    assert runner.invoke(app, ["ingest", "--promptfoo", "r.json"]).exit_code == EXIT_NOT_IMPLEMENTED
