#!/usr/bin/env bash
# M0 lab bootstrap: checks prerequisites and puts the guardrail in OBSERVE mode.
# Safe to re-run. Does not install anything without telling you.
set -euo pipefail

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1 — $2"; exit 1; }; }

say "1/5 Checking prerequisites"
need python3 "install Python 3.11+"
need uv      "https://docs.astral.sh/uv/"
need node    "Node.js (needed for OpenClaw and promptfoo)"
need openclaw "curl -fsSL https://openclaw.ai/install.sh | bash && openclaw onboard --install-daemon"
need defenseclaw "curl -LsSf https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh | bash && defenseclaw quickstart"

say "2/5 OpenClaw gateway"
openclaw gateway status

say "3/5 DefenseClaw health"
defenseclaw doctor

say "4/5 Guardrail -> observe mode for OpenClaw (records only, blocks nothing)"
defenseclaw setup guardrail \
  --non-interactive \
  --connector openclaw \
  --mode observe \
  --scanner-mode local \
  --restart

say "5/5 Current posture"
defenseclaw guardrail status
defenseclaw status

cat <<'EOF'

Next (manual, see docs/TASKS.md M0):
  - Configure the demo HelpDesk agent; put CANARY-7F3A in its system prompt.
  - Send 5 benign + 5 malicious messages by hand.
  - Capture fixtures:
      mkdir -p tests/fixtures/defenseclaw
      defenseclaw status --json            > tests/fixtures/defenseclaw/status.json
      defenseclaw guardrail status         > tests/fixtures/defenseclaw/guardrail_status.txt
      defenseclaw alerts --json --limit 50 > tests/fixtures/defenseclaw/alerts.json
EOF
