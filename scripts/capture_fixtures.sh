#!/usr/bin/env bash
# M0: capture the real DefenseClaw outputs ClawShield's parsers are built from.
# Run on the LAB HOST as the OpenClaw/DefenseClaw user, after sending the hand-made
# messages (docs/LAB_RUNBOOK.md step 6). Writes tests/fixtures/defenseclaw/ and checks
# the result for secrets BEFORE you share it.
#
# DefenseClaw 0.8.10 has no `alerts --json`: the alerts table is kept for reference only,
# and machine-readable verdict data comes from a READ-ONLY export of ~/.defenseclaw/audit.db
# (schema + audit_events rows), per ADR 0001.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT=tests/fixtures/defenseclaw
mkdir -p "$OUT"
umask 077
export PATH="$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"

echo "== versions"
{ defenseclaw version 2>&1; openclaw --version 2>&1; } | sed -e 's/\x1b\[[0-9;]*m//g' > "$OUT/version.txt"
cat "$OUT/version.txt"

echo "== status --json"
defenseclaw status --json > "$OUT/status.json"
python3 -m json.tool "$OUT/status.json" > /dev/null && echo "   valid JSON"

echo "== guardrail status"
defenseclaw guardrail status 2>&1 | sed -e 's/\x1b\[[0-9;]*m//g' > "$OUT/guardrail_status.txt"

echo "== alerts table (reference only; not a parser input)"
defenseclaw alerts --limit 50 2>&1 | sed -e 's/\x1b\[[0-9;]*m//g' > "$OUT/alerts_table.txt"

echo "== audit.db (read-only): schema + audit_events + correlation counts"
python3 - "$OUT" <<'PY'
import json, os, sqlite3, sys
out = sys.argv[1]
db = os.path.expanduser("~/.defenseclaw/audit.db")
con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
tables = [r[0] for r in con.execute("select name from sqlite_master where type='table' order by name")]
schema = {t: [dict(name=c[1], type=c[2]) for c in con.execute(f'pragma table_info("{t}")')] for t in tables}
counts = {t: con.execute(f'select count(*) from "{t}"').fetchone()[0] for t in tables}
json.dump({"tables": schema, "row_counts": counts}, open(f"{out}/audit_schema.json", "w"), indent=2)
rows = [dict(r) for r in con.execute("select * from audit_events order by timestamp desc limit 500")]
json.dump(rows, open(f"{out}/audit_events.json", "w"), indent=2, default=str)
print(f"   {len(tables)} tables; audit_events exported: {len(rows)} rows")
print("   correlation rows:", {t: n for t, n in counts.items() if t.startswith("correlation_") and n})
PY

echo "== secret checks (review any hit before sharing these files)"
python3 - "$OUT" <<'PY'
import json, os, pathlib, sys
out = pathlib.Path(sys.argv[1])
cfg = os.path.expanduser("~/.openclaw/openclaw.json")
token = ""
try:
    token = json.load(open(cfg))["gateway"]["auth"]["token"] or ""
except Exception:
    pass
hits = [p.name for p in out.iterdir() if p.is_file() and token and token in p.read_text(errors="ignore")]
if hits:
    print("!! The OpenClaw gateway token appears in:", hits, "- do not share these files.")
    sys.exit(1)
print("   OpenClaw gateway token: not present in any fixture" if token else "   (no gateway token to check)")
PY
if grep -rnIE '(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY|xox[baprs]-[A-Za-z0-9-]{10,}|hooks\.slack\.com/services/|[Bb]earer [A-Za-z0-9._-]{20,})' "$OUT"; then
  echo "!! Possible secrets above. Redact them before committing or sharing." >&2
  exit 1
fi
echo "   no secret patterns found"
echo
echo "Done. Review $OUT, then commit it (or send it) so the M1/M3 parsers can be written."
