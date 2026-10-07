#!/usr/bin/env bash
# Lab bootstrap (M0): checks the verified tool versions, puts DefenseClaw's guardrail in
# OBSERVE mode for OpenClaw, and ends with `clawshield doctor`, which proves the guardrail
# actually inspects the agent's traffic. Safe to re-run. Installs nothing: every install
# step is in docs/LAB_RUNBOOK.md (download, read, then run). Run from the repo root.
set -euo pipefail

OPENCLAW_SERIES="2026.7."     # verified with DefenseClaw 0.8.10 (2026.9.8 never loads the plugin)
DEFENSECLAW_VERSION="0.8.10"  # keep in sync with config/clawshield.yaml defenseclaw.expected_version

say()  { printf '\n\033[1m%s\033[0m\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "missing $1: $2 (docs/LAB_RUNBOOK.md)"; }

[ -f config/clawshield.yaml ] || fail "run from the ClawShield repo root"
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"

say "1/6 Prerequisites and pinned versions"
need python3 "Python 3.11-3.13"
need uv "runbook step 2"
need node "Node.js 24, runbook step 2"
need openclaw "runbook step 3"
need defenseclaw "runbook step 4"
oc_version="$(openclaw --version | awk '{print $2}')"
case "$oc_version" in
  "$OPENCLAW_SERIES"*) echo "OpenClaw $oc_version" ;;
  *) fail "OpenClaw $oc_version; ${OPENCLAW_SERIES}x is the verified series (ADR 0002)" ;;
esac
dc_version="$(defenseclaw version --json --no-drift-exit | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print({c["name"]: c["version"] for c in d["components"]}.get("cli","?") if d.get("ok") else "drift")')"
[ "$dc_version" = "$DEFENSECLAW_VERSION" ] \
  || fail "DefenseClaw $dc_version (cli/gateway/plugin must be $DEFENSECLAW_VERSION and in sync)"
echo "DefenseClaw $dc_version, components in sync"

say "2/6 OpenClaw gateway"
openclaw gateway status --json | python3 -c \
  'import json,sys; r=json.load(sys.stdin).get("rpc") or {}; sys.exit(0 if r.get("ok") else 1)' \
  || fail "OpenClaw gateway RPC not reachable (openclaw gateway status)"
echo "gateway reachable"

say "3/6 Guardrail -> observe mode for OpenClaw (records only, blocks nothing)"
defenseclaw setup guardrail --non-interactive --connector openclaw \
  --mode observe --scanner-mode local --rule-pack default --restart

say "4/6 Interceptor loaded in the gateway process"
sleep 5
if journalctl --user -u openclaw-gateway --since "-10min" 2>/dev/null \
    | grep -q "LLM fetch interceptor active"; then
  echo "found: [defenseclaw] LLM fetch interceptor active"
else
  echo "WARNING: no 'LLM fetch interceptor active' line in the gateway journal yet;"
  echo "         step 6 (in-path probe) decides."
fi

say "5/6 DefenseClaw's own doctor (informational; it can pass while nothing is inspected)"
defenseclaw doctor || echo "(defenseclaw doctor reported failures; see above)"
defenseclaw guardrail status

say "6/6 clawshield doctor (decisive: sends one known-bad probe through the agent)"
uv sync --locked -q
uv run clawshield doctor

cat <<'EOF'

Lab verified. Next (docs/LAB_RUNBOOK.md):
  - step 5: HelpDesk agent with CANARY-7F3A, embedded runtime, per-agent key
  - step 6: python3 scripts/m0_send_seed_cases.py && bash scripts/capture_fixtures.sh
  - step 8: bash scripts/promptfoo_generate.sh, then clawshield ingest --extra ... --promptfoo ...
  - step 9: clawshield run --corpus redteam/corpus/combined.jsonl ...
EOF
