"""Evidence pack for a change request / CAB (FR-18): gate result + the evidence behind it.

Written whatever the gate result: a FAIL pack that explains why is the expected output of
an untuned baseline. No prompt or response text is included (case ids only), so packs can
be forwarded. The Markdown carries the SHA-256 of the JSON so the two can be cross-checked.
Every value that came from data (notes, names, rule ids) is Markdown-escaped.
"""

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from clawshield import __version__
from clawshield.config import Settings
from clawshield.core.gate import (
    GateReport,
    cases_needed_for_fpr,
    cases_needed_for_recall,
)
from clawshield.scoring import RunScore, to_dict

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()<>#+!|~])")
NL = chr(10)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

STANDING_LIMITATIONS = (
    "Observe mode cannot yet be verified from the guardrail snapshot: the format of "
    "DefenseClaw status --json is pending capture from the lab (M0).",
    "The DefenseClaw verdict parser is pending real alerts --json fixtures; until then "
    "verdict fields follow DefenseClaw source code, not captured output.",
    "Detection is measured against ClawShield's own corpus; results do not generalise to "
    "attacks unlike those in the corpus.",
)


def md(text: object) -> str:
    """Escape a data value for Markdown: no links, HTML, emphasis or table breaks."""
    s = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(text))
    return _MD_SPECIAL.sub(r"\\\1", s)


_CODE_SAFE = re.compile(r"^[A-Za-z0-9_.:+-]+$")


def code(text: object) -> str:
    """Inline code span for ids/hashes; falls back to escaped text if it is not id-shaped."""
    s = str(text)
    return f"`{s}`" if _CODE_SAFE.fullmatch(s) else md(s)


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _ci(ci: list[float] | None) -> str:
    return "" if ci is None else f" [{ci[0]:.1%}-{ci[1]:.1%}]"


def _limitations(rs: RunScore, gate: GateReport, settings: Settings) -> list[str]:
    items = list(STANDING_LIMITATIONS)
    card = rs.card
    if not rs.snapshot_available:
        items.append("This run has no guardrail snapshot, so its configuration is unrecorded.")
    if rs.run.declared_config is not None:
        items.append("The run's rule pack and strategy are operator-declared, not yet "
                     "cross-checked against the snapshot.")  # fmt: skip
    if card.excluded_ambiguous or card.excluded_errors:
        items.append(
            f"{len(card.excluded_ambiguous)} ambiguous and {len(card.excluded_errors)} "
            "errored case(s) were excluded from every metric."
        )
    if settings.gate.evaluate_on == "confidence_bound":
        try:
            crit = card.slice("expected_severity", "critical")
            target = settings.gate.min_critical_recall
            need0 = cases_needed_for_recall(target, misses=0)
            need1 = cases_needed_for_recall(target, misses=1)
            if need0 is not None and crit.positives < (need1 or need0):
                items.append(
                    f"{crit.positives} critical case(s) scored; proving {target:.0%} recall at "
                    f"95% confidence needs >= {need0} with no misses (>= {need1} with one)."
                )
        except KeyError:
            items.append("No critical-severity cases were scored.")
        o = card.overall
        need_b = cases_needed_for_fpr(settings.gate.max_benign_block_fpr, o.block_fp)
        if need_b is not None and o.negatives < need_b:
            items.append(f"{o.negatives} benign case(s) scored; the FPR bound needs >= {need_b}.")
    if card.scored:
        share = card.overall.negatives / card.scored
        items.append(f"The scored corpus is {share:.0%} benign; precision reflects that base rate.")
    return items


def build_evidence(
    rs: RunScore, gate: GateReport, settings: Settings, *, generated_at: datetime | None = None
) -> dict[str, Any]:
    scorecard = to_dict(rs, settings)
    snapshot = rs.run.guardrail_snapshot
    return {
        "schema": "clawshield-evidence/1",
        "generated_at": (generated_at or datetime.now(UTC)).isoformat(),
        "clawshield_version": __version__,
        "gate": {
            "overall": gate.overall,
            "evaluate_on": gate.evaluate_on,
            "criteria": [
                {
                    "name": c.name,
                    "threshold": c.threshold,
                    "observed": c.observed,
                    "status": c.status,
                    "detail": c.detail,
                }
                for c in gate.criteria
            ],
            "proposed_command": gate.proposed_command,
        },
        "run": {
            **scorecard["run"],
            "notes": rs.run.notes,
            "declared_config": rs.run.declared_config,
            "target_kind": rs.run.target_kind,
            "case_count": rs.run.case_count,
        },
        "snapshot": {
            "available": bool(snapshot.get("available")),
            "captured_at": snapshot.get("captured_at"),
            "connector": snapshot.get("connector"),
            "errors": snapshot.get("errors", []),
            "defenseclaw_status": snapshot.get("defenseclaw_status"),
            "guardrail_status": snapshot.get("guardrail_status"),
        },
        "scorecard": {k: v for k, v in scorecard.items() if k != "run"},
        "limitations": _limitations(rs, gate, settings),
        "reproduce": [
            f"clawshield score --run {rs.run.id} --json",
            f"clawshield gate --run {rs.run.id} --json",
        ],
    }


def _fenced(text: str) -> list[str]:
    """Code block whose fence is longer than any backtick run in text (text stays exact)."""
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [f"{fence}bash", *text.split(NL), fence]


def _declared(config: dict[str, str] | None) -> str:
    if not config:
        return "not declared"
    return md(f"{config['rule_pack']} / {config['detection_strategy']}")


def render_markdown(evidence: dict[str, Any], json_sha256: str) -> str:
    g, run, sc = evidence["gate"], evidence["run"], evidence["scorecard"]
    lines = [
        f"# ClawShield promotion evidence: {md(g['overall'])}",
        "",
        f"- **Run:** {code(run['id'])} ({md(run['started_at'])} to {md(run['finished_at'])})",
        f"- **Target:** {md(run['target'])} ({md(run['target_kind'])})",
        f"- **Corpus:** {md(run['corpus_path'])}, sha256 {code(run['corpus_hash'])}",
        f"- **Declared config:** {_declared(run['declared_config'])}",
        f"- **Notes:** {md(run['notes']) or '-'}",
        f"- **Gate mode:** {md(g['evaluate_on'])}",
        f"- **Generated:** {md(evidence['generated_at'])} "
        f"by ClawShield {md(evidence['clawshield_version'])}",
        "",
        "## Gate criteria",
        "",
        "| Status | Criterion | Threshold | Observed | Detail |",
        "|---|---|---|---|---|",
    ]  # fmt: skip
    for c in g["criteria"]:
        lines.append(
            f"| **{md(c['status'])}** | {md(c['name'])} | {md(c['threshold'])} | "
            f"{md(c['observed'])} | {md(c['detail'])} |"
        )
    lines += ["", "## Proposed change", ""]
    if g["proposed_command"]:
        lines += [
            "Review, then run it yourself (ClawShield never executes it):",
            "",
            *_fenced(g["proposed_command"]),
        ]
    else:
        lines.append(
            "None. Every criterion must PASS before a `--mode action` command is proposed."
        )

    lines += [
        "",
        "## Accuracy",
        "",
        f"Cases {sc['cases_total']}, scored {sc['cases_scored']}; "
        f"verdicts in window {sc['verdicts_in_window']}; "
        f"correlation attribution {_pct(sc['correlation']['attribution_rate'])}.",
        "",
        "| Slice | TP | FN | FP | TN | Recall [95% CI] | FPR [95% CI] | Benign block FPR |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in sc["slices"]:
        if s["dimension"] not in ("overall", "expected_severity", "category"):
            continue
        name = "overall" if s["dimension"] == "overall" else f"{s['dimension']}={s['value']}"
        lines.append(
            f"| {md(name)} | {s['tp']} | {s['fn']} | {s['fp']} | {s['tn']} | "
            f"{_pct(s['recall'])}{_ci(s['recall_ci95'])} | {_pct(s['fpr'])}{_ci(s['fpr_ci95'])} | "
            f"{_pct(s['block_fpr'])} |"
        )
    leaks = sc["canary_leaks"]
    lines += [
        "",
        "## Canary leaks",
        "",
        f"{len(leaks)} case(s)" + (": " + ", ".join(code(x) for x in leaks) if leaks else "."),
        "",
        "## Evidence quality",
        "",
        f"- Snapshot available: {evidence['snapshot']['available']}"
        + (f" (captured {md(evidence['snapshot']['captured_at'])})"
           if evidence["snapshot"]["captured_at"] else ""),
        f"- Excluded: {len(sc['excluded_ambiguous'])} ambiguous, "
        f"{len(sc['excluded_errors'])} target error(s)",
        f"- Overlapping runs: {', '.join(md(r) for r in sc['overlapping_runs']) or 'none'}",
        f"- Responses redacted in storage: {run['responses_redacted']}",
        "",
        "## Limitations",
        "",
        *(f"- {md(item)}" for item in evidence["limitations"]),
        "",
        "## Reproduce",
        "",
        *_fenced(NL.join(evidence["reproduce"])),
        "",
        "## Integrity",
        "",
        f"SHA-256 of the accompanying JSON evidence file: `{json_sha256}`",
        "",
    ]  # fmt: skip
    return "\n".join(lines)


def write_evidence_pack(evidence: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.fromisoformat(evidence["generated_at"]).strftime("%Y%m%d")
    run_id = re.sub(r"[^A-Za-z0-9_-]", "_", evidence["run"]["id"])
    base = out_dir / f"gate-{stamp}-{run_id}"
    json_bytes = (json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "ascii"
    )
    json_path, md_path = base.with_suffix(".json"), base.with_suffix(".md")
    json_path.write_bytes(json_bytes)
    md_path.write_text(
        render_markdown(evidence, hashlib.sha256(json_bytes).hexdigest()),
        encoding="utf-8",
        newline="\n",
    )
    return json_path, md_path
