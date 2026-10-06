"""ClawShield command-line entrypoint.

Commands not yet implemented fail closed: they exit non-zero so that CI and
scripts never mistake a stub for a passing check (especially `gate`).
"""

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from clawshield import __version__

EXIT_NOT_IMPLEMENTED = 2

app = typer.Typer(
    name="clawshield",
    help="Measure, tune and gate Cisco DefenseClaw's guardrail (observe -> action).",
    no_args_is_help=True,
    add_completion=False,
)


def _not_implemented(command: str, milestone: str) -> NoReturn:
    typer.echo(f"clawshield {command}: not implemented yet ({milestone}).", err=True)
    raise typer.Exit(code=EXIT_NOT_IMPLEMENTED)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"clawshield {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """ClawShield operator CLI."""


@app.command()
def doctor() -> None:
    """Check DefenseClaw health, guardrail posture and target reachability (FR-1)."""
    _not_implemented("doctor", "M1")


@app.command()
def run(
    corpus: Annotated[
        Path,
        typer.Option(help="Labeled JSONL corpus to replay against the guarded target."),
    ] = Path("redteam/corpus/seed.jsonl"),
) -> None:
    """Replay the attack corpus against the allowlisted target (FR-4)."""
    _not_implemented("run", "M2")


@app.command()
def score(
    run_id: Annotated[str, typer.Option("--run", help="Run id, or 'latest'.")] = "latest",
) -> None:
    """Score a run: confusion matrix and metrics (FR-10, FR-11)."""
    _not_implemented("score", "M4")


@app.command()
def gate() -> None:
    """Evaluate observe -> action promotion readiness (FR-16, FR-17)."""
    _not_implemented("gate", "M5")


@app.command()
def ingest(
    promptfoo: Annotated[
        Path | None,
        typer.Option(help="promptfoo red-team results JSON to import as labeled cases."),
    ] = None,
) -> None:
    """Ingest DefenseClaw verdicts or external red-team results (FR-5, FR-7)."""
    _not_implemented("ingest", "M3")
