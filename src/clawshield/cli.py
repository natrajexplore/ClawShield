"""ClawShield command-line entrypoint.

Commands not yet implemented fail closed: they exit non-zero so that CI and
scripts never mistake a stub for a passing check (especially `gate`).
"""

import json
import re
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from clawshield import __version__
from clawshield.config import DEFAULT_CONFIG_PATH, ConfigError, load_settings
from clawshield.core.score import Interval, SliceScore
from clawshield.redteam.corpus import CorpusError, load_corpus
from clawshield.redteam.runner import RunError, execute_run
from clawshield.scoring import RunScore, ScoringError, score_run, to_dict
from clawshield.sources.snapshot import capture_guardrail_snapshot
from clawshield.storage.db import RunNotFoundError, Store, StoreSchemaError
from clawshield.targets.base import TargetError, build_target

EXIT_ERROR = 1
EXIT_NOT_IMPLEMENTED = 2
MAX_NOTES_CHARS = 1000

ConfigOption = Annotated[Path, typer.Option("--config", help="Path to clawshield.yaml.")]

_UNPRINTABLE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def printable(text: str) -> str:
    """Escape control characters so stored text cannot inject terminal escape codes."""
    return _UNPRINTABLE.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def _fail(message: str) -> NoReturn:
    safe = "\n".join(printable(line) for line in message.split("\n"))
    typer.echo(f"error: {safe}", err=True)
    raise typer.Exit(code=EXIT_ERROR)


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
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    notes: Annotated[str, typer.Option(help="Free-text note stored with the run.")] = "",
) -> None:
    """Replay the attack corpus against the allowlisted target (FR-4)."""
    if len(notes) > MAX_NOTES_CHARS:
        _fail(f"--notes is longer than {MAX_NOTES_CHARS} characters")
    try:
        settings = load_settings(config)
        loaded = load_corpus(corpus, known_canaries=settings.canaries)
        target = build_target(settings)
        store = Store(settings.storage.db_path, redact_responses=settings.storage.redact_responses)
        snapshot = capture_guardrail_snapshot(settings.defenseclaw)
        report = execute_run(
            settings=settings,
            corpus=loaded,
            target=target,
            store=store,
            snapshot=snapshot,
            notes=notes,
        )
    except (ConfigError, CorpusError, TargetError, RunError, StoreSchemaError) as exc:
        _fail(str(exc))

    if not snapshot["available"]:
        typer.echo(
            "warning: guardrail snapshot unavailable; this run cannot serve as gate evidence:",
            err=True,
        )
        for error in snapshot["errors"]:
            typer.echo(f"  {printable(error)}", err=True)
    typer.echo(
        f"run {report.run_id}: {report.cases} cases, {report.errors} target errors, "
        f"{report.leaks} canary leaks, {report.duration_s:.1f}s"
        + (" (responses redacted)" if report.redacted else "")
    )
    if report.leaks:
        typer.echo(f"warning: {report.leaks} response(s) leaked a planted canary", err=True)


@app.command()
def runs(
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    limit: Annotated[int, typer.Option(min=1, max=1000, help="Rows to show.")] = 20,
) -> None:
    """List recent runs, newest first."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        _fail(str(exc))
    if not settings.storage.db_path.exists():
        typer.echo("no runs yet")
        return
    try:
        listings = Store(settings.storage.db_path).list_runs(limit)
    except StoreSchemaError as exc:
        _fail(str(exc))
    if not listings:
        typer.echo("no runs yet")
        return
    typer.echo(
        f"{'RUN':<24} {'STARTED (UTC)':<20} {'TARGET':<20} "
        f"{'CASES':>7} {'ERR':>5} {'LEAK':>5}  STATUS"
    )
    for item in listings:
        r = item.run
        status = "complete" if item.complete else "INCOMPLETE"
        snap = "" if r.guardrail_snapshot.get("available") else " (no snapshot)"
        typer.echo(
            f"{r.id:<24} {r.started_at:%Y-%m-%d %H:%M:%S}  "
            f"{printable(r.target_name)[:20]:<20} {item.results:>3}/{r.case_count:<3} "
            f"{item.errors:>5} {item.leaks:>5}  {status}{snap}"
        )


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _ci(ci: Interval | None) -> str:
    return "" if ci is None else f"[{ci.low:.0%}-{ci.high:.0%}]"


_SLICE_HEADER = (
    f"  {'SLICE':<26} {'TP':>4} {'FN':>4} {'FP':>4} {'TN':>4}  "
    f"{'RECALL [95% CI]':<20} {'FPR [95% CI]':<19} {'PREC':>6} {'BLK-REC':>7} {'BLK-FPR':>7}"
)


def _secs(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}s"


def _slice_row(s: SliceScore) -> str:
    recall = f"{_pct(s.recall)} {_ci(s.recall_ci)}"
    fpr = f"{_pct(s.fpr)} {_ci(s.fpr_ci)}"
    return (
        f"  {printable(s.value)[:26]:<26} {s.tp:>4} {s.fn:>4} {s.fp:>4} {s.tn:>4}  "
        f"{recall:<20} {fpr:<19} "
        f"{_pct(s.precision):>6} {_pct(s.block_recall):>7} {_pct(s.block_fpr):>7}"
    )


def _print_scorecard(rs: RunScore) -> None:
    card, run, corr = rs.card, rs.run, rs.correlation
    typer.echo(
        f"run {run.id}  target {printable(run.target_name)}  "
        f"corpus {printable(Path(run.corpus_path).name)} (sha256 {run.corpus_hash[:12]})"
    )
    typer.echo(
        f"cases {card.cases_total} | scored {card.scored} | ambiguous "
        f"{len(card.excluded_ambiguous)} | target errors {len(card.excluded_errors)} | "
        f"canary leaks {len(card.leaked_case_ids)}"
    )
    methods = ", ".join(f"{k} {v}" for k, v in corr.by_method.items())
    typer.echo(
        f"verdicts in window {rs.verdicts_in_window} | correlation: {methods} | "
        f"attribution {_pct(corr.attribution_rate)} | "
        f"unattributed {len(corr.unattributed_verdict_ids)}"
    )
    if rs.verdicts_in_window == 0:
        typer.echo(
            "WARNING: no DefenseClaw verdicts in this run's window; every malicious case "
            "scores as a miss. Ingest verdicts first (clawshield ingest).",
            err=True,
        )
    if not rs.snapshot_available:
        typer.echo("WARNING: run has no guardrail snapshot; not valid as gate evidence.", err=True)
    if card.excluded_ambiguous:
        typer.echo(
            f"NOTE: {len(card.excluded_ambiguous)} ambiguous case(s) excluded; "
            "increase runner.inter_case_delay_ms (ADR 0003).",
            err=True,
        )
    for dimension in ("overall", "category", "expected_severity", "direction", "rule"):
        rows = card.dimension(dimension)
        if not rows:
            continue
        typer.echo()
        typer.echo(dimension.upper().replace("_", " "))
        typer.echo(_SLICE_HEADER)
        for row in rows:
            typer.echo(_slice_row(row))
    typer.echo()
    typer.echo(f"latency p50 {_secs(card.latency_p50_s)}  p95 {_secs(card.latency_p95_s)}")


@app.command()
def score(
    run_id: Annotated[str, typer.Option("--run", help="Run id, or 'latest'.")] = "latest",
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    corpus: Annotated[
        Path | None,
        typer.Option(help="Corpus file if it moved; must match the run's corpus hash."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Score a run: confusion matrix and metrics (FR-10, FR-11)."""
    try:
        settings = load_settings(config)
        if not settings.storage.db_path.exists():
            _fail("no runs yet; run `clawshield run` first")
        store = Store(settings.storage.db_path)
        result = score_run(store, settings, run_id, corpus)
    except RunNotFoundError:
        _fail(f"run {run_id!r} not found")
    except (ConfigError, CorpusError, StoreSchemaError, ScoringError) as exc:
        _fail(str(exc))
    if as_json:
        typer.echo(json.dumps(to_dict(result, settings), indent=2, sort_keys=True))
    else:
        _print_scorecard(result)


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
