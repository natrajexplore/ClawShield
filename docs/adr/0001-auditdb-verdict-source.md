# ADR 0001: Read DefenseClaw verdicts from its audit database

- **Status:** Accepted (schema verified in the M0 lab, 2026-10-07)
- **Lab:** OpenClaw 2026.7.35, DefenseClaw 0.8.10 (observe mode, default rule pack, regex only)
- **Implements:** FR-7 (collect verdicts), FR-8 (normalize); feeds FR-9 correlation (ADR 0003)

## Context
CLAUDE.md says to integrate through the CLI contract first (`defenseclaw alerts --json`) and to
read DefenseClaw's SQLite only behind `VerdictSource`, after documenting the schema here.
DefenseClaw 0.8.10 has **no `alerts --json`**; `alerts` prints a table for humans only. The
observability presets offer no JSONL sink. Every guardrail finding is, however, written to the
mandatory audit history `~/.defenseclaw/audit.db` (SQLite, 29 tables).

## Decision
`sources/auditdb.py` (`AuditDbSource`, source name `defenseclaw_auditdb`) reads `audit_events`.

1. **Read-only, always.** `file:<path>?mode=ro` URI plus `PRAGMA query_only=ON`, short busy
   timeout, connection closed after each read. ClawShield never writes, migrates or vacuums
   DefenseClaw's database. Path from config `defenseclaw.audit_db` (default `~/.defenseclaw/audit.db`).
2. **Schema contract (columns relied on):** `id`, `timestamp`, `action`, `event_name`,
   `severity`, `session_id`, `connector`, `enforced`, `structured_json`. Missing table or column
   is a hard error naming what is missing (schema drift after an upgrade must not score as
   "no findings").
3. **Which rows are verdicts:** `action = 'scan-finding'` and `event_name = 'finding.observed'`,
   **and** `structured_json."defenseclaw.scan.scanner"` in an allowlist of scanners verified to be
   the guardrail. Today: `local-pattern` only. Plugin/asset scans (`plugin-scanner`) are not
   guardrail verdicts and carry no session. Findings from other scanners (e.g. the LLM judge,
   once enabled) are **skipped and reported by scanner name** until verified with a lab fixture
   and added to the allowlist. Nothing is dropped silently: each read returns skip counts.
4. **Mapping to `Verdict`:**

   | Verdict field | From |
   |---|---|
   | `id` | `defenseclaw_auditdb:<audit_events.id>` (the finding id; idempotent re-ingest) |
   | `ts` | `timestamp` (RFC 3339, `Z`, up to nanoseconds; truncated to microseconds) |
   | `severity` | `defenseclaw.security.severity`, else column `severity`; `INFO` rows are skipped |
   | `rule_id` | `defenseclaw.finding.rule_id` |
   | `direction` | `target_type=` in `defenseclaw.guardrail.evidence_summary`: `prompt` (verified); `completion`, `tool_call` taken verbatim; anything else `unknown` |
   | `session_id` | `session_id` **verbatim** (`agent:<agent>:explicit:<id>`); the OpenClaw target reports the same stored form (ADR 0002) |
   | `connector` | `connector`; when null (all guardrail findings in 0.8.10) the configured `defenseclaw.connector`. Correlation filters on it, so `unknown` would silently score every case as a miss. Safe because the lab host runs one connector (runbook step 1); a non-null, different connector is kept and filtered out |
   | `action` | `observe` when `enforced` is null (observe mode); rows with `enforced` set are skipped and reported until action-mode output is verified |
   | `raw` | the finding's `structured_json` plus `id`, `timestamp`, `session_id`, `event_name`; no prompt text (dropped entirely when `storage.redact_responses`) |

5. **Window:** `fetch(since)` returns findings with `ts >= since`. The SQL pre-filter is a
   string comparison widened by one day (timestamps may carry offsets); the exact filter runs
   after parsing. More than 200,000 matching rows is an error, never a silent truncation.

## Evidence
`tests/fixtures/defenseclaw/audit_events.json` (292 rows, captured read-only from the lab):
12 guardrail findings with sessions (all `local-pattern`, `target_type=prompt`), 40 plugin-scan
findings without sessions, the rest lifecycle/correlation events. `d-001` maps to four CRITICAL
prompt verdicts in its session; `bl-001` to three (the benign false positive).

## Consequences
- Scores depend on an internal DefenseClaw table. Pin DefenseClaw (`defenseclaw.expected_version`),
  and re-capture fixtures after every upgrade; the column check catches drift.
- `scoring.would_block` stays severity-based (ARCHITECTURE.md), so observe-mode verdicts score
  exactly as they would be enforced under the balanced profile.
- **To verify before promotion:** `enforced` values and row shape in action mode; completion and
  tool-call `target_type` values; judge-scanner name. Each needs a fixture first.
- When a DefenseClaw release ships `alerts --json`, add `DefenseClawCliSource` and compare both
  sources on the same run before switching.

## Alternatives considered
- **Parse the `alerts` table:** column widths and truncation make it lossy; no session column.
- **Sidecar log lines** (`prompt-scan ... action=block severity=CRITICAL findings=4`): one line
  per message, no rule ids, log format not a contract.
- **Copy audit.db then read:** avoids lock contention but adds stale-copy risk; `mode=ro` with a
  busy timeout is enough for a database DefenseClaw writes concurrently.
