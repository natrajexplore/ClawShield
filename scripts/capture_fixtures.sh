#!/usr/bin/env bash
# M0: capture the real DefenseClaw outputs ClawShield's parsers are built from.
# Run on the LAB HOST after sending the hand-made messages (docs/LAB_RUNBOOK.md, step 6).
# Writes tests/fixtures/defenseclaw/ and scans the result for secrets BEFORE you share it.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=tests/fixtures/defenseclaw
mkdir -p "$OUT"
umask 077

echo "== DefenseClaw version"
defenseclaw --version | tee "$OUT/version.txt"

echo "== status --json"
defenseclaw status --json > "$OUT/status.json"
python3 -m json.tool "$OUT/status.json" > /dev/null && echo "   valid JSON"

echo "== guardrail status"
defenseclaw guardrail status > "$OUT/guardrail_status.txt"

echo "== alerts --json (last 50)"
defenseclaw alerts --json --limit 50 > "$OUT/alerts.json"
python3 -m json.tool "$OUT/alerts.json" > /dev/null && echo "   valid JSON"
python3 - "$OUT/alerts.json" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
print(f"   {len(rows)} alert rows; keys seen: {sorted({k for r in rows for k in r})}")
PY

echo "== secret scan (review any hit before sharing these files)"
if grep -rnIE '(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]{10,}|hooks\.slack\.com/services/|[Aa]pi[_-]?[Kk]ey"?[:=] *"?[A-Za-z0-9_-]{16,}|[Bb]earer [A-Za-z0-9._-]{20,})' "$OUT"; then
  echo "!! Possible secrets above. Redact them before committing or sharing." >&2
  exit 1
fi
echo "   no secret patterns found"
echo
echo "Done. Review $OUT, then commit it (or send it) so the M1/M3 parsers can be written."
