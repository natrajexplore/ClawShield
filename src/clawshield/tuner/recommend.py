"""Per-rule false-positive recommendations (FR-13, FR-15). Pure: no I/O, no execution.

DefenseClaw semantics (docs/DEFENSECLAW_REFERENCE.md): suppressions act on LLM-judge
findings only; regex/CEL rule findings are never suppressed and must instead be narrowed
or disabled in a custom rule pack. Each recommendation therefore names the remedy that
actually works for its finding, and every one states which malicious cases only that
rule caught, so a fix cannot silently remove the sole detection of a real attack.

Proposed commands are text for a human to review and run. Values from DefenseClaw data
(rule ids) never appear in commands; config values are shell-quoted.
"""

import json
import re
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from clawshield.core.models import Severity, Verdict
from clawshield.core.score import CaseInput, scorable

JUDGE_PREFIX = "JUDGE-"  # judge finding ids, per DefenseClaw docs examples (verify in lab)
PACK_DIR_PLACEHOLDER = "<YOUR_PACK_DIR>"

Kind = Literal["suppress", "narrow_rule"]


@dataclass(frozen=True)
class Recommendation:
    kind: Kind
    target: str  # rule / finding id
    rationale: str
    evidence_case_ids: tuple[str, ...]  # benign cases this rule fired on
    lost_detection_case_ids: tuple[str, ...]  # malicious cases caught by this rule alone
    directions: tuple[str, ...]
    proposed_change: str
    proposed_command: str


def _qualifying(
    item: CaseInput, verdicts: Mapping[str, Verdict], minimum: Severity
) -> list[Verdict]:
    found = (verdicts[v] for v in item.correlation.verdict_ids)
    return [v for v in found if v.severity.rank >= minimum.rank]


def _setup_command(connector: str) -> str:
    return " ".join(
        [
            "defenseclaw setup guardrail --non-interactive",
            f"--connector {shlex.quote(connector)} --mode observe",
            f"--rule-pack-dir {PACK_DIR_PLACEHOLDER} --restart",
        ]
    )


def _suppression_yaml(rule: str, evidence: Sequence[str]) -> str:
    # json.dumps yields a valid YAML double-quoted scalar, so hostile ids cannot break out.
    sample = ", ".join(evidence[:5])
    return "\n".join(
        [
            "finding_suppressions:",
            f"  - id: {json.dumps('SUPP-CLAWSHIELD-' + re.sub(r'[^A-Za-z0-9-]', '-', rule))}",
            f"    finding_pattern: {json.dumps('^' + re.escape(rule) + '$')}",
            '    entity_pattern: "<ANCHORED REGEX FOR THE SAFE ENTITY - never .* or .+>"',
            f"    reason: {json.dumps(f'ClawShield: {len(evidence)} benign FP(s), e.g. {sample}')}",
        ]
    )


def recommend_suppressions(
    inputs: Sequence[CaseInput],
    verdicts: Mapping[str, Verdict],
    *,
    detected_min: Severity,
    connector: str,
    min_false_positives: int = 1,
) -> list[Recommendation]:
    """Recommend a remedy for every rule with >= min_false_positives benign hits."""
    if min_false_positives < 1:
        raise ValueError("min_false_positives must be >= 1")
    fp_cases: dict[str, list[str]] = {}
    sole_catches: dict[str, list[str]] = {}
    directions: dict[str, set[str]] = {}

    for item in scorable(inputs):
        qualifying = _qualifying(item, verdicts, detected_min)
        hits = [(v.rule_id, v) for v in qualifying if v.rule_id]
        if item.case.label == "benign":
            for rule, v in hits:
                cases = fp_cases.setdefault(rule, [])
                if item.case.id not in cases:
                    cases.append(item.case.id)
                directions.setdefault(rule, set()).add(v.direction)
        else:
            rules = {rule for rule, _ in hits}
            # Only one rule detected this attack, and no rule-less verdict did.
            if len(rules) == 1 and len(hits) == len(qualifying):
                sole_catches.setdefault(next(iter(rules)), []).append(item.case.id)

    recs = []
    for rule, evidence in fp_cases.items():
        if len(evidence) < min_false_positives:
            continue
        lost = tuple(sole_catches.get(rule, []))
        dirs = tuple(sorted(directions[rule]))
        risk = (
            f" Caution: it is the only detection of {len(lost)} malicious case(s); "
            "narrow it rather than disable it, and re-run to confirm they are still caught."
            if lost
            else " No malicious case in this run depends on it alone."
        )
        if rule.startswith(JUDGE_PREFIX):
            kind: Kind = "suppress"
            rationale = f"LLM-judge finding {rule} fired on {len(evidence)} benign case(s).{risk}"
            change = (
                "Add to the suppressions.yaml of a custom copy of your rule pack:\n"
                + _suppression_yaml(rule, evidence)
            )
        else:
            kind = "narrow_rule"
            rationale = (
                f"Rule {rule} fired on {len(evidence)} benign case(s). DefenseClaw "
                f"suppressions do not apply to rule findings.{risk}"
            )
            change = (
                "Copy your rule pack to a directory you control and narrow (or, if it is not "
                "needed, disable) this rule in its rules/*.yaml so it no longer matches the "
                "evidence cases."
            )
            if "tool_call" in dirs:
                change += (
                    " For tool-call findings only, `defenseclaw guardrail alert-at HIGH "
                    f"--connector {shlex.quote(connector)}` raises the alert level instead; "
                    "that affects every rule, not just this one."
                )
        recs.append(
            Recommendation(
                kind=kind,
                target=rule,
                rationale=rationale,
                evidence_case_ids=tuple(evidence),
                lost_detection_case_ids=lost,
                directions=dirs,
                proposed_change=change,
                proposed_command=_setup_command(connector),
            )
        )
    recs.sort(key=lambda r: (-len(r.evidence_case_ids), len(r.lost_detection_case_ids), r.target))
    return recs
