#!/usr/bin/env bash
# Generate promptfoo red-team cases LOCALLY on the lab host (FR-5). Run from the repo root.
#
# - promptfoo is the pinned install in ~/pf (override with PROMPTFOO_BIN); version is checked.
# - Remote generation, telemetry, sharing and update checks are disabled: nothing goes to
#   promptfoo's cloud. Generation uses your OpenAI key, typed at a hidden prompt, passed only
#   to the promptfoo process and never written to disk.
# - Output: redteam/generated/redteam.yaml (git-ignored). Review it, then import with
#   `clawshield ingest --promptfoo redteam/generated/redteam.yaml ...` (see the config header).
set -euo pipefail

PF="${PROMPTFOO_BIN:-$HOME/pf/node_modules/.bin/promptfoo}"
EXPECTED_VERSION="0.124.0"
CONFIG="redteam/promptfooconfig.yaml"
OUT="redteam/generated/redteam.yaml"

[ -f "$CONFIG" ] || { echo "run from the ClawShield repo root ($CONFIG not found)" >&2; exit 1; }
[ -x "$PF" ] || { echo "promptfoo not found at $PF (npm install --save-exact promptfoo@$EXPECTED_VERSION in ~/pf)" >&2; exit 1; }
version="$("$PF" --version)"
[ "$version" = "$EXPECTED_VERSION" ] || { echo "promptfoo $version found, $EXPECTED_VERSION pinned" >&2; exit 1; }

read -rsp "OpenAI API key for promptfoo generation (input hidden): " key; echo
[ -n "$key" ] || { echo "no key entered" >&2; exit 1; }

umask 077
mkdir -p "$(dirname "$OUT")"
OPENAI_API_KEY="$key" \
PROMPTFOO_DISABLE_REMOTE_GENERATION=true \
PROMPTFOO_DISABLE_TELEMETRY=1 \
PROMPTFOO_DISABLE_SHARING=1 \
PROMPTFOO_DISABLE_UPDATE=1 \
  "$PF" redteam generate -c "$CONFIG" -o "$OUT" --strict --no-progress-bar

if grep -qF -- "$key" "$OUT"; then
  rm -f "$OUT"; unset key
  echo "the API key appeared in the output; file deleted" >&2; exit 1
fi
unset key
echo "wrote $OUT ($(grep -c 'pluginId' "$OUT" || true) cases); review it, then:"
echo "  uv run clawshield ingest --extra redteam/corpus/public/gandalf_ignore_instructions.jsonl \\"
echo "    --promptfoo $OUT --out redteam/corpus/combined.jsonl"
