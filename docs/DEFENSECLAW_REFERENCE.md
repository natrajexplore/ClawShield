# DefenseClaw — verified reference for this project

Verified against the official docs on 2026-10-06. Canonical source:
https://cisco-ai-defense.github.io/defenseclaw/docs/ — re-check after any DefenseClaw upgrade
and pin the version you test with in `config/clawshield.yaml` (`defenseclaw.expected_version`).

## Lab install, verified 2026-10-07 (Ubuntu 26.04.1 VM, user `clawlab`)
- OpenClaw **2026.9.8** via `openclaw.ai/install.sh --no-onboard --no-prompt`: no sudo; with a
  root-owned npm prefix it switches to `~/.npm-global`. Gateway: systemd **user** service
  `openclaw-gateway.service`, loopback `127.0.0.1:18789`. Needs `loginctl enable-linger <user>`.
  Onboarding needs a real TTY (no pipes); `--non-interactive --accept-risk` exists for automation.
- DefenseClaw **0.8.10** via the release `install.sh --connector openclaw --yes`: user-local
  (`~/.defenseclaw`, `~/.local/bin`), no sudo when OpenClaw is already on PATH. Verifies release
  checksums with cosign pinned to `cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main`.
  Requires OpenClaw >= 2026.3.24 (else offers to update it; `--yes` would accept). Python must be
  `>=3.10,<3.14`; with only 3.14 present it installs a uv-managed Python 3.12. Needs `uv`.
- Post-install hint: `defenseclaw init --connector openclaw --profile observe` (`init` also has
  `--non-interactive`, `--yes`, `--enable-guardrail`, `--observe-all`, `--action-connectors`).
- `defenseclaw doctor` before `init`: FAIL config file, FAIL sidecar API (port **18970**),
  FAIL credential `OPENCLAW_GATEWAY_TOKEN` (`defenseclaw keys set OPENCLAW_GATEWAY_TOKEN`),
  WARN default rule pack not on disk ("enforcement would run with no rule packs"); default
  detection `regex_judge` with judge disabled. Doctor then **crashes** (FileNotFoundError on
  `~/.defenseclaw/config.yaml`) in its observability section - a DefenseClaw bug; run `init` first.

## Install & health
```bash
curl -LsSf https://github.com/cisco-ai-defense/defenseclaw/releases/latest/download/install.sh | bash
defenseclaw quickstart
defenseclaw doctor            # full health report
defenseclaw status            # environment, enforcement counts, connector roster (+ --json)
defenseclaw guardrail status  # resolved posture per connector
defenseclaw alerts --limit 25 # recent decisions; --connector <n>, --show <n>, --json
defenseclaw tui               # live audit panel
defenseclaw upgrade           # release upgrades
```
Toolchain (source builds): Python `>=3.10,<3.14`, Go 1.26.x, Node.js 24 in CI.

## Guardrail setup — `defenseclaw setup guardrail`
Key flags (full list: `defenseclaw setup guardrail --help`):

| Flag | Values / notes |
|---|---|
| `--connector` / `--agent` | includes `openclaw`, `claudecode`, `codex`, `cursor`, ... |
| `--mode` | `observe` (records only) · `action` (enforces) |
| `--scanner-mode` | `local` · `remote` (Cisco AI Defense) · `both` |
| `--cisco-endpoint`, `--cisco-api-key-env`, `--cisco-timeout-ms` | remote scanner |
| `--detection-strategy` | `regex_only` · `regex_judge` · `judge_first` |
| `--detection-strategy-prompt` / `-completion` / `-tool-call` | per-direction override |
| `--rule-pack` | `default` · `strict` · `permissive` |
| `--rule-pack-dir` | custom rule pack path |
| `--judge-model`, `--judge-provider`, `--judge-api-key-env` | turns the LLM judge on |
| `--human-approval` / `--no-human-approval` | HITL, action mode |
| `--hilt-min-severity` | `low` · `medium` · `high` · `critical` |
| `--port` | guardrail proxy port, default **4000** (proxy connectors only; hook connectors bind none) |
| `--block-message` | custom block text (action mode) |
| `--non-interactive` / `--yes` | CI-friendly |
| `--restart` / `--no-restart` | restart gateway after save |
| `--disable` | turn guardrail off and roll back hook entries |

Hook fail mode is **not** a `setup guardrail` flag: use
`defenseclaw guardrail fail-mode open|closed` or `defenseclaw setup <connector> --fail-mode`.

Judge fallback models: `guardrail.judge.fallbacks` in `~/.defenseclaw/config.yaml`.
Keys: `defenseclaw keys set DEFENSECLAW_LLM_KEY` (stored in `~/.defenseclaw/.env`).
Telemetry redaction: `defenseclaw setup redaction` (per destination).

## Mode semantics
- **observe:** findings logged to the audit DB and sinks; nothing blocked. Docs recommend
  at least a week before promoting. In observe mode the wizard skips judge and HITL questions.
- **action, balanced default profile:** CRITICAL blocks; HIGH alerts (or confirms with HITL);
  MEDIUM alerts; LOW allows. Every verdict is written to the audit log.

## Recipes used by ClawShield
```bash
# Baseline observe (M0)
defenseclaw setup guardrail --non-interactive --connector openclaw \
  --mode observe --scanner-mode local --restart

# A/B: regex + judge (still observe)
defenseclaw keys set DEFENSECLAW_LLM_KEY
defenseclaw setup guardrail --non-interactive --connector openclaw \
  --mode observe --detection-strategy regex_judge \
  --judge-model <provider/model> --judge-api-key-env DEFENSECLAW_LLM_KEY --restart

# Promotion (generated by `clawshield gate`, run by a human)
defenseclaw setup guardrail --non-interactive --connector openclaw \
  --mode action --rule-pack default --human-approval --hilt-min-severity high --restart
```

## Files
- `~/.defenseclaw/config.yaml` — saved guardrail config
- `~/.defenseclaw/.env` — keys (never read by ClawShield)
- `~/.defenseclaw/hooks/` — connector hook scripts (hook connectors)
- SQLite audit history is mandatory and fills with every collected prompt and tool call.
  For a scripted stream, configure an explicit `kind: jsonl` observability destination.

## Unknowns to resolve (update this file when answered)
- [ ] Exact JSON schema of `defenseclaw alerts --json` (fields for direction, severity, rule id, session).
      Leads from source (`cli/defenseclaw/commands/cmd_alerts.py`, unverified against real output):
      structured keys `defenseclaw.finding.rule_id`, `defenseclaw.finding.title`,
      `defenseclaw.scan.scanner`, `defenseclaw.guardrail.evidence_summary`; hook details carry
      `key=value` pairs incl. `action`, `raw_action`, `would_block`, `connector`. Confirm with lab fixtures.
      From `_alerts_json` (source read 2026-10-06, still unverified against real output):
      a JSON **list**, newest first, of rows with `id`, `timestamp` (ISO or `""`), `severity`
      (uppercase, e.g. `CRITICAL`), `action` (an **event type** such as `scan-finding`,
      `quarantine`, `telemetry-destination`, `circuit_breaker_open` - not block/alert),
      `target`, `actor`, `connector`, `details` (key=value string); optional `decision`,
      `route`, `rule` (`"<rule_id>: <title>"`), `scanner`, `location`, `sandbox`, `path`,
      `moved_to`. Implications: use `id` as the idempotency key; filter out non-guardrail
      event types; direction is not a field (look in `details`); `--limit` returns only the
      newest N, so ingest must request enough to cover the whole run window.
- [x] Whether `openclaw` connector is hook- or proxy-based in our pinned version.
      **Proxy** ("the reference proxy connector"), per `docs/connectors/openclaw` (checked 2026-10-06).
      Default proxy port 4000 (`--port`). Re-confirm against the pinned version in M0.
- [ ] JSONL destination config block and field names.
- [x] How suppressions are expressed (file format/location) for FR-13 command generation.
      Per `docs/policies/suppression-cookbook` (read 2026-10-06): a rule pack's
      `suppressions.yaml` with `pre_judge_strips`, `finding_suppressions`
      (`finding_pattern`, `entity_pattern`, optional `condition: is_epoch|is_platform_id`,
      `reason`) and `tool_suppressions` (`tool_pattern`, `suppress_findings`, `reason`).
      **Suppressions act on the LLM judge only; regex/CEL rule findings are never
      suppressed.** For a noisy rule: narrow/disable it in your own pack (`rules/*.yaml`
      entries have `id`, `pattern`, `title`, `severity`, `confidence`, `tags`, optional
      `expression`, `tool_call_only`) and point `--rule-pack-dir` at it. Blanket patterns
      (`.*`, `.+`, `^.*$`) are flagged `SUPP_OVER_BROAD` by DefenseClaw's creator.

## Severity levels (`cmd_guardrail.py`, read 2026-10-06)
- `defenseclaw guardrail block-at LEVEL [--connector X] [--no-restart] [--json]` and
  `alert-at` (same options). LEVEL: `CRITICAL|HIGH|MEDIUM|LOW|inherit` (any case).
- They apply to **tool calls in action mode**. Thresholds for LLM traffic through the
  guardrail proxy (prompt/completion) are separate: `policy edit guardrail` (not yet verified).
- Precedence: connector override > global > rule pack. Packs: strict blocks MEDIUM+;
  default and permissive block CRITICAL. Alerts: strict LOW+, default MEDIUM+, permissive HIGH+.
- Unverified until the lab: judge finding ids start with `JUDGE-` (docs examples), and the
  on-disk location of the bundled packs (source tree: `policies/guardrail/<pack>/`).

## Platform support
- OpenClaw (and ZeptoClaw) are **model-proxy connectors: unsupported on native Windows**. DefenseClaw
  is hook-only on Windows; WSL, Docker, VM or mixed native/POSIX workarounds are explicitly unsupported.
  Run the lab on macOS or Linux (`docs/connectors/openclaw`, Windows tab; checked 2026-10-06).
- Hook connectors (Claude Code, Codex, Cursor, ...) are the ones available on native Windows.
