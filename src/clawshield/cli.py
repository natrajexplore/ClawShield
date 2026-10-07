"""ClawShield command-line entrypoint.

Commands not yet implemented fail closed: they exit non-zero so that CI and
scripts never mistake a stub for a passing check (especially `gate`).
"""

import json
import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from clawshield import __version__
from clawshield.alerts.slack import NotifyError, send_slack
from clawshield.config import DEFAULT_CONFIG_PATH, ConfigError, Settings, load_settings
from clawshield.core.gate import GateReport
from clawshield.core.models import Case, DeclaredConfig
from clawshield.core.score import Interval, SliceScore
from clawshield.doctor import exit_code as doctor_exit_code
from clawshield.doctor import run_doctor
from clawshield.redteam.corpus import CorpusError, load_corpus
from clawshield.redteam.promptfoo import (
    ImportReport,
    PromptfooImportError,
    import_promptfoo,
    write_combined_corpus,
)
from clawshield.redteam.runner import RunError, execute_run
from clawshield.report import build_evidence, write_evidence_pack
from clawshield.scoring import (
    RunComparison,
    RunScore,
    ScoringError,
    check_message,
    check_run,
    compare_runs,
    comparison_to_dict,
    gate_run,
    score_run,
    to_dict,
)
from clawshield.sources.auditdb import AuditDbError, AuditDbSource
from clawshield.sources.snapshot import capture_guardrail_snapshot
from clawshield.storage.db import RunNotFoundError, Store, StoreSchemaError
from clawshield.targets.base import TargetError, build_target
from clawshield.tuner.recommend import Recommendation, recommend_suppressions
from clawshield.tuner.strategy import recommend_config

EXIT_ERROR = 1
EXIT_GATE_NOT_PASSED = 3
MAX_NOTES_CHARS = 1000


class RulePackChoice(StrEnum):
    default = "default"
    strict = "strict"
    permissive = "permissive"
    custom = "custom"


class StrategyChoice(StrEnum):
    regex_only = "regex_only"
    regex_judge = "regex_judge"
    judge_first = "judge_first"


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
def doctor(
    no_probe: Annotated[
        bool,
        typer.Option(
            "--no-probe",
            help="Skip the in-path probe (one known-bad model call). Exits 3: not verified.",
        ),
    ] = False,
    config: ConfigOption = DEFAULT_CONFIG_PATH,
) -> None:
    """Check DefenseClaw health and prove the guardrail inspects the target (FR-1).

    Exit 0 only when every check passes (warnings allowed); 1 on any failure; 3 when
    nothing failed but a check was skipped, so the setup is not verified.
    """
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        _fail(str(exc))
    checks = run_doctor(settings, probe=not no_probe)
    for c in checks:
        typer.echo(f"  [{c.status.upper():4}] {c.name:<20} {printable(c.detail)}")
    code = doctor_exit_code(checks)
    verdict = {0: "VERIFIED", 1: "FAILED", 3: "NOT VERIFIED"}[code]
    typer.echo(f"doctor: {verdict}", err=code != 0)
    raise typer.Exit(code=code)


@app.command()
def run(
    corpus: Annotated[
        Path,
        typer.Option(help="Labeled JSONL corpus to replay against the guarded target."),
    ] = Path("redteam/corpus/seed.jsonl"),
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    notes: Annotated[str, typer.Option(help="Free-text note stored with the run.")] = "",
    rule_pack: Annotated[
        RulePackChoice | None,
        typer.Option("--rule-pack", help="Declare the active DefenseClaw rule pack (FR-14)."),
    ] = None,
    strategy: Annotated[
        StrategyChoice | None,
        typer.Option("--detection-strategy", help="Declare the active detection strategy."),
    ] = None,
    ci: Annotated[
        bool,
        typer.Option("--ci", help="After the run, check accuracy + regression; exit 3 on failure."),
    ] = False,
    notify: Annotated[bool, typer.Option(help="With --ci: Slack alert on failure.")] = False,
) -> None:
    """Replay the attack corpus against the allowlisted target (FR-4, FR-21 with --ci)."""
    if notify and not ci:
        _fail("--notify requires --ci")
    if (rule_pack is None) != (strategy is None):
        _fail("declare both --rule-pack and --detection-strategy, or neither")
    declared = (
        DeclaredConfig(rule_pack=rule_pack.value, detection_strategy=strategy.value)
        if rule_pack is not None and strategy is not None
        else None
    )
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
            declared=declared,
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
    if ci:
        _check_and_exit(store, settings, report.run_id, notify=notify)


def _check_and_exit(store: Store, settings: Settings, run_id: str, *, notify: bool) -> NoReturn:
    """Shared by `run --ci` and `check`: print, alert on failure if asked, exit 0 or 3."""
    try:
        result = check_run(store, settings, run_id)
    except RunNotFoundError:
        _fail(f"run {run_id!r} not found")
    except (CorpusError, ScoringError, StoreSchemaError) as exc:
        _fail(str(exc))
    message = check_message(result)
    for line in message.splitlines():
        typer.echo(printable(line))
    if result.ok:
        raise typer.Exit(code=0)
    if notify:
        try:
            send_slack(settings.alerts.slack_webhook_env, message)
            typer.echo("alert sent to Slack", err=True)
        except NotifyError as exc:
            typer.echo(f"error: alert not sent: {exc}", err=True)
    raise typer.Exit(code=EXIT_GATE_NOT_PASSED)


@app.command()
def check(
    run_id: Annotated[str, typer.Option("--run", help="Run id, or 'latest'.")] = "latest",
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    notify: Annotated[bool, typer.Option(help="Slack alert on failure (FR-20).")] = False,
) -> None:
    """CI/nightly check: accuracy criteria + regression vs last passing run (FR-20, FR-21)."""
    try:
        settings = load_settings(config)
    except ConfigError as exc:
        _fail(str(exc))
    if not settings.storage.db_path.exists():
        _fail("no runs yet; run `clawshield run` first")
    _check_and_exit(Store(settings.storage.db_path), settings, run_id, notify=notify)


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
    _warn_overlap(rs)
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


def _warn_overlap(rs: RunScore) -> None:
    if rs.overlapping_runs:
        typer.echo(
            f"WARNING: run {rs.run.id} overlaps run(s) {', '.join(rs.overlapping_runs)} "
            f"within the {rs.grace_s:g}s correlation grace; verdicts may be cross-attributed. "
            "Leave at least the grace period between runs.",
            err=True,
        )


def _p(value: float) -> str:
    return "<0.001" if value < 0.001 else f"{value:.3f}"


def _print_comparison(rc: RunComparison) -> None:
    c = rc.comparison
    for tag, rs in (("A", rc.a), ("B", rc.b)):
        snap = "" if rs.snapshot_available else "  (no snapshot)"
        typer.echo(f"{tag}  {rs.run.id}  notes: {printable(rs.run.notes) or '-'}{snap}")
    typer.echo(
        f"paired cases {c.paired_cases} (excluded {len(c.excluded_case_ids)}) | "
        f"exact McNemar, alpha {c.alpha:g}"
    )
    _warn_overlap(rc.a)
    _warn_overlap(rc.b)
    typer.echo(
        "NOTE: per-slice p-values are not corrected for multiple comparisons; decide on OVERALL.",
        err=True,
    )
    typer.echo()
    typer.echo(
        f"  {'SLICE':<28} {'N+':>4} {'RECALL A -> B':<16} {'p':>6}  {'VERDICT':<26} "
        f"{'N-':>4} {'FPR A -> B':<16} {'p':>6}  VERDICT"
    )
    for s in c.slices:
        label = "overall" if s.dimension == "overall" else f"{s.dimension}={s.value}"
        rp = _p(s.recall_test.p_value) if s.recall_test else "-"
        fp = _p(s.fpr_test.p_value) if s.fpr_test else "-"
        recall = f"{_pct(s.recall_a)} -> {_pct(s.recall_b)}"
        fpr = f"{_pct(s.fpr_a)} -> {_pct(s.fpr_b)}"
        typer.echo(
            f"  {printable(label)[:28]:<28} {s.positives:>4} {recall:<16} {rp:>6}  "
            f"{s.recall_verdict:<26} {s.negatives:>4} {fpr:<16} {fp:>6}  {s.fpr_verdict}"
        )
    typer.echo()
    typer.echo(
        f"latency delta (B - A): p50 {_signed(c.latency_p50_delta_s)}  "
        f"p95 {_signed(c.latency_p95_delta_s)}"
    )


def _signed(value: float | None) -> str:
    return "n/a" if value is None else f"{value:+.3f}s"


@app.command()
def compare(
    run_a: Annotated[str, typer.Argument(help="Baseline run id (A).")],
    run_b: Annotated[str, typer.Argument(help="Candidate run id (B), or 'latest'.")],
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    corpus: Annotated[
        Path | None,
        typer.Option(help="Corpus file if it moved; must match both runs' corpus hash."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """A/B compare two runs on the same corpus with a paired significance test (FR-12)."""
    try:
        settings = load_settings(config)
        if not settings.storage.db_path.exists():
            _fail("no runs yet; run `clawshield run` first")
        result = compare_runs(Store(settings.storage.db_path), settings, run_a, run_b, corpus)
    except RunNotFoundError as exc:
        _fail(f"run {exc.args[0]!r} not found")
    except (ConfigError, CorpusError, StoreSchemaError, ScoringError) as exc:
        _fail(str(exc))
    if as_json:
        typer.echo(json.dumps(comparison_to_dict(result), indent=2, sort_keys=True))
    else:
        _print_comparison(result)


def recommendation_to_dict(r: Recommendation) -> dict[str, object]:
    return {
        "kind": r.kind, "target": r.target, "rationale": r.rationale,
        "evidence_case_ids": list(r.evidence_case_ids),
        "lost_detection_case_ids": list(r.lost_detection_case_ids),
        "directions": list(r.directions), "proposed_change": r.proposed_change,
        "proposed_command": r.proposed_command,
    }  # fmt: skip


@app.command()
def tune(
    run_id: Annotated[str, typer.Option("--run", help="Run id, or 'latest'.")] = "latest",
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    corpus: Annotated[
        Path | None,
        typer.Option(help="Corpus file if it moved; must match the run's corpus hash."),
    ] = None,
    min_fp: Annotated[
        int, typer.Option("--min-fp", min=1, help="Benign hits needed to recommend.")
    ] = 1,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Recommend fixes for noisy rules, with evidence (FR-13). Nothing is executed (FR-15)."""
    try:
        settings = load_settings(config)
        if not settings.storage.db_path.exists():
            _fail("no runs yet; run `clawshield run` first")
        rs = score_run(Store(settings.storage.db_path), settings, run_id, corpus)
    except RunNotFoundError:
        _fail(f"run {run_id!r} not found")
    except (ConfigError, CorpusError, StoreSchemaError, ScoringError) as exc:
        _fail(str(exc))
    recs = recommend_suppressions(
        rs.inputs, rs.verdicts,
        detected_min=settings.scoring.detected_min_severity,
        connector=settings.defenseclaw.connector, min_false_positives=min_fp,
    )  # fmt: skip
    if as_json:
        payload = {"run": rs.run.id, "recommendations": [recommendation_to_dict(r) for r in recs]}
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    typer.echo(f"run {rs.run.id}: {len(recs)} recommendation(s). Review before running anything.")
    if rs.verdicts_in_window == 0:
        typer.echo("WARNING: no verdicts in this run's window; nothing to tune.", err=True)
    _warn_overlap(rs)
    for n, r in enumerate(recs, start=1):
        typer.echo()
        typer.echo(f"[{n}] {r.kind}  {printable(r.target)}  ({', '.join(r.directions)})")
        typer.echo(f"    {printable(r.rationale)}")
        typer.echo(f"    benign evidence: {', '.join(r.evidence_case_ids)}")
        if r.lost_detection_case_ids:
            typer.echo(f"    only detection of: {', '.join(r.lost_detection_case_ids)}")
        for line in r.proposed_change.splitlines():
            typer.echo(f"    {printable(line)}")
        typer.echo(f"    then, in observe mode: {r.proposed_command}")
    if recs:
        typer.echo()
        typer.echo("Re-run the corpus after any change and compare: clawshield compare <old> <new>")


@app.command("recommend-config")
def recommend_config_cmd(
    run_a: Annotated[str, typer.Argument(help="Current configuration's run (A).")],
    run_b: Annotated[str, typer.Argument(help="Candidate configuration's run (B).")],
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    corpus: Annotated[
        Path | None,
        typer.Option(help="Corpus file if it moved; must match both runs' corpus hash."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Recommend a rule pack / detection strategy from an A/B pair (FR-14). Never executed."""
    try:
        settings = load_settings(config)
        if not settings.storage.db_path.exists():
            _fail("no runs yet; run `clawshield run` first")
        rc = compare_runs(Store(settings.storage.db_path), settings, run_a, run_b, corpus)
    except RunNotFoundError as exc:
        _fail(f"run {exc.args[0]!r} not found")
    except (ConfigError, CorpusError, StoreSchemaError, ScoringError) as exc:
        _fail(str(exc))
    declared = [
        DeclaredConfig.model_validate(rs.run.declared_config) if rs.run.declared_config else None
        for rs in (rc.a, rc.b)
    ]
    rec = recommend_config(
        rc.comparison, declared[0], declared[1], connector=settings.defenseclaw.connector
    )
    if as_json:
        payload = {
            "a": rc.a.run.id, "b": rc.b.run.id, "decision": rec.decision,
            "reasons": list(rec.reasons),
            "config": rec.config.model_dump() if rec.config else None,
            "proposed_command": rec.proposed_command,
        }  # fmt: skip
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    for tag, rs, cfg in (("A", rc.a, declared[0]), ("B", rc.b, declared[1])):
        shown = f"{cfg.rule_pack} / {cfg.detection_strategy}" if cfg else "not declared"
        typer.echo(f"{tag}  {rs.run.id}  config: {shown}  notes: {printable(rs.run.notes) or '-'}")
    _warn_overlap(rc.a)
    _warn_overlap(rc.b)
    typer.echo(f"decision: {rec.decision}")
    for reason in rec.reasons:
        typer.echo(f"  - {reason}")
    if rec.proposed_command:
        typer.echo("proposed (review, then run yourself; stays in observe mode):")
        typer.echo(f"  {rec.proposed_command}")


def gate_to_dict(report: GateReport) -> dict[str, object]:
    return {
        "run": report.run_id, "overall": report.overall, "evaluate_on": report.evaluate_on,
        "criteria": [
            {"name": c.name, "threshold": c.threshold, "observed": c.observed,
             "status": c.status, "detail": c.detail}
            for c in report.criteria
        ],
        "proposed_command": report.proposed_command,
    }  # fmt: skip


@app.command()
def gate(
    run_id: Annotated[str, typer.Option("--run", help="Run id, or 'latest'.")] = "latest",
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    corpus: Annotated[
        Path | None,
        typer.Option(help="Corpus file if it moved; must match the run's corpus hash."),
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
    export: Annotated[
        Path | None,
        typer.Option(help="Write the evidence pack (FR-18) as .json + .md into this directory."),
    ] = None,
) -> None:
    """Evaluate observe -> action promotion readiness (FR-16, FR-17).

    Exit 0 only on PASS; FAIL and UNVERIFIED exit 3. Nothing is executed.
    """
    try:
        settings = load_settings(config)
        if not settings.storage.db_path.exists():
            _fail("no runs yet; run `clawshield run` first")
        rs, report = gate_run(Store(settings.storage.db_path), settings, run_id, corpus)
    except RunNotFoundError:
        _fail(f"run {run_id!r} not found")
    except (ConfigError, CorpusError, StoreSchemaError, ScoringError) as exc:
        _fail(str(exc))
    if as_json:
        typer.echo(json.dumps(gate_to_dict(report), indent=2, sort_keys=True))
    else:
        typer.echo(f"gate for run {report.run_id} ({report.evaluate_on.replace('_', ' ')})")
        for c in report.criteria:
            typer.echo(f"  [{c.status:<10}] {c.name:<20} {c.threshold}")
            typer.echo(f"  {'':<12} observed: {printable(c.observed)}")
            if c.detail:
                typer.echo(f"  {'':<12} {printable(c.detail)}")
        typer.echo(f"OVERALL: {report.overall}")
        if report.proposed_command:
            typer.echo("proposed promotion (review, then run it yourself):")
            typer.echo(f"  {report.proposed_command}")
        else:
            typer.echo("no promotion command: every criterion must PASS first.")
    if export is not None:
        try:
            json_path, md_path = write_evidence_pack(build_evidence(rs, report, settings), export)
        except OSError as exc:
            _fail(f"cannot write evidence pack to {export}: {exc.strerror}")
        typer.echo(f"evidence pack: {md_path} (+ {json_path.name})", err=as_json)
    if report.overall != "PASS":
        raise typer.Exit(code=EXIT_GATE_NOT_PASSED)


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


@app.command()
def console(
    config: ConfigOption = DEFAULT_CONFIG_PATH,
    allow_remote: Annotated[
        bool, typer.Option(help="Allow a non-loopback console.host (not recommended).")
    ] = False,
) -> None:
    """Serve the read-only web console on console.host:console.port (default 127.0.0.1:8088)."""
    import uvicorn

    from clawshield.console.app import create_app

    try:
        settings = load_settings(config)
    except ConfigError as exc:
        _fail(str(exc))
    host, port = settings.console.host, settings.console.port
    if host not in LOOPBACK_HOSTS and not allow_remote:
        _fail(
            f"console.host {host!r} is not loopback; the console has no authentication. "
            "Use --allow-remote only behind your own authenticating proxy."
        )
    typer.echo(f"ClawShield console on http://{host}:{port} (read-only; Ctrl+C to stop)")
    uvicorn.run(
        create_app(settings), host=host, port=port, proxy_headers=False,
        server_header=False, date_header=False, log_level="warning",
    )  # fmt: skip


def _norm(text: str) -> str:
    return " ".join(text.casefold().split())


def _ingest_verdicts(config: Path, since_text: str | None) -> None:
    """Read guardrail findings from DefenseClaw's audit.db (ADR 0001) into the store."""
    try:
        settings = load_settings(config)
        store = Store(settings.storage.db_path, redact_responses=settings.storage.redact_responses)
        if since_text is None:
            started = store.get_run("latest").started_at
            since = started - timedelta(seconds=settings.runner.correlation_grace_s)
        else:
            since = datetime.fromisoformat(since_text)
            if since.tzinfo is None:
                _fail("--since needs a UTC offset, e.g. 2026-10-07T09:00:00+00:00")
        dc = settings.defenseclaw
        source = AuditDbSource(dc.audit_db, connector=dc.connector)
        batch = source.read(since)
        report = store.add_verdicts(batch.verdicts, ingested_at=datetime.now(UTC))
    except RunNotFoundError:
        _fail("no runs yet; pass --since to choose the start of the ingest window")
    except ValueError as exc:
        _fail(f"invalid --since: {exc}")
    except (ConfigError, StoreSchemaError, AuditDbError) as exc:
        _fail(str(exc))
    typer.echo(
        f"read {report.received} guardrail verdict(s) since {since.isoformat()} from "
        f"{printable(str(source.path))}: {report.new} new, {report.duplicates} already stored"
    )
    for reason, count in sorted(batch.skipped.items()):
        typer.echo(f"  skipped {count}: {printable(reason)}")
    if report.received == 0:
        typer.echo(
            "WARNING: no guardrail verdicts in this window. Check the in-path probe "
            "(LAB_RUNBOOK step 6) before trusting any score.",
            err=True,
        )


@app.command()
def ingest(
    promptfoo: Annotated[
        Path | None,
        typer.Option(help="promptfoo red-team results JSON to import as labeled cases."),
    ] = None,
    base: Annotated[
        Path, typer.Option(help="Corpus the imported cases are added to (kept verbatim).")
    ] = Path("redteam/corpus/seed.jsonl"),
    out: Annotated[Path, typer.Option(help="Combined corpus to write (base + imported).")] = Path(
        "redteam/corpus/combined.jsonl"
    ),
    inject_var: Annotated[
        str, typer.Option(help="promptfoo var holding the attack text (redteam injectVar).")
    ] = "prompt",
    extra: Annotated[
        list[Path] | None,
        typer.Option(
            help="Vendored corpus JSONL to merge (repeatable), e.g. "
            "redteam/corpus/public/gandalf_ignore_instructions.jsonl."
        ),
    ] = None,
    since: Annotated[
        str | None,
        typer.Option(
            help="Verdicts at or after this ISO-8601 time with offset (default: latest run "
            "start minus the correlation grace)."
        ),
    ] = None,
    config: ConfigOption = DEFAULT_CONFIG_PATH,
) -> None:
    """Ingest DefenseClaw verdicts (FR-7), or build a combined corpus (FR-5) from the base
    corpus plus --extra vendored corpora and/or --promptfoo red-team results."""
    if promptfoo is None and not extra:
        _ingest_verdicts(config, since)
        return
    extra = extra or []
    if any(p.resolve() == out.resolve() for p in [base, *extra]):
        _fail("--out must differ from --base and --extra; input corpora are never modified")
    try:
        settings = load_settings(config)
        base_corpus = load_corpus(base, known_canaries=settings.canaries)
        seen_text = {_norm(c.text) for c in base_corpus.cases}
        seen_ids = {c.id for c in base_corpus.cases}
        imported: list[Case] = []
        extra_dupes = 0
        for path in extra:
            for case in load_corpus(path, known_canaries=settings.canaries).cases:
                if case.id in seen_ids:
                    _fail(f"{path}: case id {case.id!r} already used by another corpus")
                if _norm(case.text) in seen_text:
                    extra_dupes += 1
                    continue
                seen_ids.add(case.id)
                seen_text.add(_norm(case.text))
                imported.append(case)
        report = (
            import_promptfoo(
                promptfoo,
                inject_var=inject_var,
                existing_texts=[*(c.text for c in base_corpus.cases), *(c.text for c in imported)],
            )
            if promptfoo is not None
            else ImportReport(cases=())
        )
    except (ConfigError, CorpusError, PromptfooImportError) as exc:
        _fail(str(exc))
    if extra:
        typer.echo(
            f"extra corpora: {len(imported)} case(s), {extra_dupes} duplicate text(s) skipped"
        )
    if promptfoo is not None and not report.cases:
        _fail(f"no importable cases in {promptfoo} (rejected: {dict(report.rejected) or 'none'})")
    imported.extend(report.cases)
    if not imported:
        _fail("nothing to add: every --extra case duplicates the base corpus")
    base_lines = [ln for ln in base.read_text(encoding="utf-8-sig").splitlines() if ln.strip()]
    added = write_combined_corpus(base_lines, imported, out)
    try:
        combined = load_corpus(out, known_canaries=settings.canaries)  # re-validate the result
    except CorpusError as exc:
        out.unlink(missing_ok=True)
        _fail(f"combined corpus failed validation and was removed: {exc}")
    counts = Counter(c.category.value for c in imported)
    typer.echo(f"imported {added} case(s) into {out} ({len(combined.cases)} total)")
    typer.echo("  by category: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    critical = sum(1 for c in imported if c.expected_severity.value == "critical")
    typer.echo(
        f"  critical {critical} | duplicates skipped {report.duplicates} | "
        f"severity defaulted {report.severity_defaulted}"
    )
    for reason, n in sorted(report.rejected.items()):
        typer.echo(f"  rejected {n}: {printable(reason)}", err=True)
    typer.echo(f"next: clawshield run --corpus {out}")
