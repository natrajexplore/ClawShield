#!/usr/bin/env bash
# Nightly regression run on the LAB HOST (FR-20). Not a GitHub schedule: the lab is private.
#
# Install (as the lab user):
#   crontab -e   ->   30 2 * * *  /path/to/ClawShield/scripts/nightly.sh >> ~/clawshield-nightly.log 2>&1
# The Slack webhook comes from the env var named in config (alerts.slack_webhook_env),
# e.g. via a root-only EnvironmentFile for a systemd timer. Never put the URL in config or here.
set -euo pipefail

cd "$(dirname "$0")/.."
CORPUS="${CLAWSHIELD_CORPUS:-redteam/corpus/seed.jsonl}"
RULE_PACK="${CLAWSHIELD_RULE_PACK:-default}"
STRATEGY="${CLAWSHIELD_STRATEGY:-regex_only}"

echo "== $(date -u +%FT%TZ) nightly ClawShield run"

# 1. Replay the corpus against the guarded lab target (observe mode; nothing is blocked).
uv run clawshield run --corpus "$CORPUS" --notes "nightly" \
  --rule-pack "$RULE_PACK" --detection-strategy "$STRATEGY"

# 2. Pull DefenseClaw verdicts for the run window.
#    PENDING (M3): `clawshield ingest` for DefenseClaw needs captured alerts --json fixtures.
#    Until then the check below fails with "no DefenseClaw verdicts ingested" - by design.

# 3. Accuracy + regression check; Slack alert on failure. Exit code is the job status.
uv run clawshield check --run latest --notify
