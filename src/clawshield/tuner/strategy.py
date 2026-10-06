"""Rule-pack / detection-strategy recommendation from a paired A/B comparison (FR-14).

Pure: no I/O, no execution. The proposed command always keeps `--mode observe`;
promotion to action mode is the gate's decision (FR-16/17), never the tuner's.

Decision rules (overall slice unless stated; "better/worse" = significant, exact McNemar):
1. B worse on critical-severity recall           -> keep A (veto: critical attacks block)
2. B recall better, FPR not worse                -> adopt B
3. B FPR better, recall not worse                -> adopt B
4. B recall better but FPR worse                 -> trade-off: tune B, then re-compare
5. no significant difference in recall or FPR    -> keep A (evidence cannot separate them)
6. otherwise (B worse)                           -> keep A
"""

import shlex
from dataclasses import dataclass
from typing import Literal

from clawshield.core.compare import Comparison, SliceComparison
from clawshield.core.models import DeclaredConfig
from clawshield.tuner.recommend import PACK_DIR_PLACEHOLDER

Decision = Literal["adopt_b", "keep_a", "trade_off"]

JUDGE_KEY_ENV = "DEFENSECLAW_LLM_KEY"  # name only; ClawShield never reads its value
MODEL_PLACEHOLDER = "<MODEL>"


@dataclass(frozen=True)
class ConfigRecommendation:
    decision: Decision
    reasons: tuple[str, ...]
    config: DeclaredConfig | None
    proposed_command: str | None


def setup_command(config: DeclaredConfig, connector: str) -> str:
    """Observe-mode `setup guardrail` command for a declared config (flags per reference)."""
    parts = [
        "defenseclaw setup guardrail --non-interactive",
        f"--connector {shlex.quote(connector)} --mode observe",
    ]
    if config.rule_pack == "custom":
        parts.append(f"--rule-pack-dir {PACK_DIR_PLACEHOLDER}")
    else:
        parts.append(f"--rule-pack {shlex.quote(config.rule_pack)}")
    parts.append(f"--detection-strategy {shlex.quote(config.detection_strategy)}")
    if config.detection_strategy != "regex_only":
        parts.append(f"--judge-model {MODEL_PLACEHOLDER} --judge-api-key-env {JUDGE_KEY_ENV}")
    parts.append("--restart")
    return " ".join(parts)


def _critical(comparison: Comparison) -> SliceComparison | None:
    return next(
        (
            s
            for s in comparison.slices
            if (s.dimension, s.value) == ("expected_severity", "critical")
        ),
        None,
    )


def _decide(comparison: Comparison) -> tuple[Decision, list[str]]:
    o = comparison.overall
    recall, fpr = o.recall_verdict, o.fpr_verdict
    critical = _critical(comparison)
    if critical is not None and critical.recall_verdict == "B worse":
        return "keep_a", [
            "B detects significantly fewer critical-severity attacks; critical attacks are "
            "the ones that block, so this vetoes B regardless of other gains."
        ]
    if recall == "B better" and fpr != "B worse":
        return "adopt_b", ["B detects significantly more attacks without a significant FPR rise."]
    if fpr == "B better" and recall != "B worse":
        return "adopt_b", ["B has a significantly lower false-positive rate without losing recall."]
    if recall == "B better" and fpr == "B worse":
        return "trade_off", [
            "B detects significantly more attacks but also flags significantly more benign "
            "cases. Run `clawshield tune` on B's run, apply the fixes, re-run and re-compare."
        ]
    if recall in ("no significant difference", "n/a") and fpr in (
        "no significant difference",
        "n/a",
    ):
        return "keep_a", [
            "No significant difference in recall or FPR: the corpus cannot separate A and B, "
            "so keep the current configuration (or enlarge the corpus and re-run)."
        ]
    return "keep_a", ["B is significantly worse on recall or FPR."]


def recommend_config(
    comparison: Comparison,
    a: DeclaredConfig | None,
    b: DeclaredConfig | None,
    *,
    connector: str,
) -> ConfigRecommendation:
    decision, reasons = _decide(comparison)
    delta = comparison.latency_p50_delta_s
    if delta is not None and abs(delta) >= 0.001:
        reasons.append(f"Median latency changes by {delta:+.3f}s from A to B.")

    chosen = b if decision == "adopt_b" else None
    command = None
    if decision == "adopt_b":
        if chosen is None:
            reasons.append(
                "B's configuration was not declared, so no command can be proposed; "
                "re-run with --rule-pack and --detection-strategy."
            )
        elif chosen == a:
            reasons.append("A and B declare the same configuration; check the run labels.")
        else:
            command = setup_command(chosen, connector)
    return ConfigRecommendation(
        decision=decision, reasons=tuple(reasons), config=chosen, proposed_command=command
    )
