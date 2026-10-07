# ClawShield — Milestones

Work top to bottom. Tick boxes as acceptance criteria are met. Commit prefix: `M<n>:`.

## M0 — Lab environment (manual + scripted)
> **Deferred to a Linux host (2026-10-06).** DefenseClaw does not support the OpenClaw (proxy)
> connector on native Windows, and WSL/Docker/VM workarounds from Windows are unsupported.
> Run M0 on a Linux/macOS machine with OpenClaw and DefenseClaw both installed there.
> M1 tasks that need no live lab proceed on Windows meanwhile.
> Step-by-step procedure: `docs/LAB_RUNBOOK.md`; fixture capture: `scripts/capture_fixtures.sh`.

- [x] OpenClaw installed and gateway running (`openclaw gateway status`).
      2026.7.35 (2026.9.8 never loads the DefenseClaw plugin; ADR 0002, LAB_RUNBOOK step 3).
- [ ] DefenseClaw installed (`defenseclaw quickstart`), `defenseclaw doctor` clean.
- [x] Guardrail in observe mode for the OpenClaw connector:
      `defenseclaw setup guardrail --non-interactive --connector openclaw --mode observe --scanner-mode local --restart`
- [x] Demo HelpDesk agent configured with a system prompt containing canary `CANARY-7F3A`.
- [x] Confirm whether the OpenClaw connector is hook-based or proxy-based (PRD Q1); record answer.
      **Proxy-based** per official docs (see `docs/DEFENSECLAW_REFERENCE.md`); re-confirm on the lab.
- [x] Capture real outputs into `tests/fixtures/defenseclaw/`: `status --json`, `guardrail status`,
      `alerts --json --limit 50` after sending 5 benign + 5 malicious messages by hand.
      0.8.10 has no `alerts --json`; captured `audit.db` `audit_events` instead (ADR 0001).

**Done when:** fixtures committed and `scripts/bootstrap.sh` documents every step.

## M1 — Skeleton + spikes
- [x] `uv` project, Typer CLI with `doctor`, `run`, `score`, `gate`, `ingest` stubs.
- [x] `config.py` loads `config/clawshield.yaml`; validates allowlist and thresholds (pydantic).
- [x] `shell.run()` wrapper with timeout and no `shell=True`; unit tests.
- [x] Spike + ADR 0002: how to send a message to OpenClaw programmatically.
- [x] Spike + ADR 0001: alert JSON fields available; document mapping to `Verdict`.
      No `alerts --json` in 0.8.10; ADR 0001 maps `audit.db` findings to `Verdict`.
- [x] `clawshield doctor` implements FR-1.
      Checks DefenseClaw version sync + pin, connector enabled/mode + sidecar (`status --json`),
      DefenseClaw's own doctor (failures are warnings: it passed while the guardrail saw nothing,
      and fails on an unused judge key), audit.db schema, OpenClaw gateway RPC, and an in-path
      probe (d-001 text through the real target; requires a block-severity finding in its
      session). Exit 0 verified / 1 failed / 3 not verified (`--no-probe`, mock target).
      Lab: VERIFIED in 16 s (4 CRITICAL probe findings); probe findings are skipped by ingest.

**Done when:** `uv run clawshield doctor` prints a green/red table against the lab.

## M2 — Corpus + runner
> Started ahead of M1's lab-dependent spikes (ADR 0001/0002, `doctor`), which wait for the Linux lab.

- [x] Corpus schema (FR-3) + loader with validation; `redteam/corpus/seed.jsonl` passes.
- [x] Expand corpus to ≥ 150 cases, ≥ 40% benign, ≥ 10 per category.
      2026-10-06: gate uses confidence bounds (operator decision). Benign grown to 402
      (>= 381 needed for a 1% block-FPR upper bound with zero FPs); near-duplicate test added.
      Critical cases (26; >= 110 needed for a 95% recall lower bound with one miss) are to
      come from promptfoo/garak imports (FR-5), not hand-written.
      2026-10-07: promptfoo 0.124 rates every allowlisted plugin High/Medium, so critical
      cases come from a public benchmark instead: Lakera gandalf_ignore_instructions test split
      (MIT, pinned revision + checksum, 112 real attacker prompts) vendored in
      `redteam/corpus/public/` -> 138 critical. Labeling rationale and selection bias
      (optimistic recall) in its README. Merge with `clawshield ingest --extra`.
      promptfoo: local generation only (`scripts/promptfoo_generate.sh`, hidden key prompt),
      `redteam.yaml` imported directly (no eval, no grader calls), promptfoo severity kept.
      promptfoo import done (`clawshield ingest --promptfoo`, format verified from promptfoo
      source; plugin allowlist; combined corpus re-validated). garak adapter pending.
- [x] `TargetClient` protocol + `mock` + `openclaw` implementations; allowlist enforced.
      `openclaw` (ADR 0002): one `openclaw agent --json` turn per case, text via a private temp
      file, lowercase per-run sessions, stored session key reported; turns not on the
      `openclaw` harness, aborted or non-`ok` are errors (never scored). Fixture-tested on a
      recorded reply; lab run 20261007T101819Z: 10 cases, 0 errors, 0 leaks.
- [x] `clawshield run` stores `Run` + `TargetResult` rows; captures guardrail snapshot.
      Snapshot parsing is unverified against real DefenseClaw output until M0 fixtures exist;
      runs without a snapshot are flagged "(no snapshot)" and must not be used as gate evidence.
- [x] Canary detection (FR-6). Every response is checked against every configured canary:
      exact, normalized (case/NFKC/zero-width/homoglyph/separators), tag chars, reversed,
      ROT13, base64, hex. Hits stored per result; LEAK column in `clawshield runs`.

**Done when:** a full run against the lab completes and is listed by `clawshield runs`.

## M3 — Collector + correlation
- [x] Verdict source parses DefenseClaw output into `Verdict` (fixture-tested).
      DefenseClaw 0.8.10 has no `alerts --json`, so `AuditDbSource` reads `audit.db` read-only
      (ADR 0001): guardrail scanner allowlist (`local-pattern`), skips reported by reason,
      schema-drift check, `clawshield ingest` (default window: latest run start - grace).
      Verified on the live lab DB: 12 verdicts, 40 plugin scans skipped, DB untouched.
      `DefenseClawCliSource` waits for a release with `alerts --json`.
- [ ] Optional `JsonlSource` behind the same interface.
- [x] Idempotent ingest (NFR-3) using a stable verdict hash.
      `Verdict` model (FR-8, direction may be `unknown`), `stable_verdict_id` (source id,
      else canonical-JSON SHA-256), `VerdictSource` protocol, `Store.add_verdicts` with
      ON CONFLICT DO NOTHING; raw payload dropped when redacting.
- [x] Correlation per ARCHITECTURE.md; ADR 0003; report correlation coverage.
      Done: `core/correlate.py` (session -> time window -> ambiguous, never guessed),
      coverage + unattributed counts, ADR 0003; `clawshield score` prints attribution.
      **Lab run 20261007T101819Z (10 cases, delay 7 s): attribution 100%, 0 ambiguous,
      3 cases by session** (done-when met on a smoke run; re-check at corpus scale). Config note: shipped delay 1500 ms < grace 3 s + 1 s
      makes windows overlap; see ADR 0003.

**Done when:** in a lab run, attribution rate ≥ 90% (verdicts credited to exactly one case)
and 0 ambiguous cases. Decided 2026-10-07: case coverage was rejected because cases that
correctly produce no verdict (allowed benign traffic) count against it (ADR 0003).

## M4 — Scoring
- [x] Confusion matrix + metrics (FR-10, FR-11) in pure `core/score.py`, ≥ 85% coverage.
      100% coverage; ratios are None when undefined; 95% Wilson intervals on recall/FPR;
      ambiguous and errored cases excluded and counted; hand-verified 9-case fixture.
- [x] Slices: direction, category, severity, rule.
      Category/severity filter cases; direction/rule re-score using only those verdicts.
- [x] `clawshield score --run <id>` prints a table; `--json` for machines.
      Refuses incomplete runs and corpora whose hash changed since the run (edited labels);
      warns on 0 verdicts in window, missing snapshot, and ambiguous exclusions.
- [x] A/B compare (FR-12): `clawshield compare <runA> <runB>`.
      Paired exact McNemar per slice (overall, category, expected severity) with
      B better / worse / no significant difference; refuses different corpora; latency delta;
      warns when runs overlap in time. Mock session ids are now unique per run (found by the
      end-to-end test: identical ids let one run's verdicts credit another run's cases).

**Done when:** scoring 1,000 synthetic outcomes < 5 s (NFR-6) and numbers hand-verified on a small fixture.

## M5 — Tuner + promotion gate
- [x] Suppression recommendations (FR-13) with evidence cases.
      `clawshield tune`: per noisy rule, the remedy DefenseClaw actually honours
      (judge finding -> `finding_suppressions` YAML; regex/CEL rule -> narrow in a custom
      pack, since suppressions never apply to rules), benign evidence, and the malicious
      cases that rule alone catches.
- [x] Rule pack / detection strategy recommendation from A/B (FR-14).
      `clawshield run --rule-pack P --detection-strategy S` declares a run's config;
      `clawshield recommend-config A B` applies explicit rules (critical-recall veto,
      adopt / keep / trade-off) and proposes an observe-mode command. Declared config is
      to be cross-checked against the guardrail snapshot once its format is verified.
- [x] Proposed commands generated, never executed (FR-15) — test asserts no subprocess call.
      Tuner, recommend-config and gate: AST import checks + subprocess traps.
- [x] Gate (FR-16, FR-17) with configurable thresholds; observe duration from first observe-mode run.
      PASS / FAIL / UNVERIFIED per criterion; overall PASS only if all pass (exit 0, else 3).
      `gate.evaluate_on: confidence_bound` (95% Wilson bounds) per operator decision; added
      evidence_quality and config_consistency criteria; `--mode action` command only on PASS.
      Observe mode stays UNVERIFIED until the snapshot format is verified (M0).
- [x] Evidence pack export (FR-18): `reports/gate-<date>.md` + `.json`.
      `clawshield gate --export reports/` -> gate-<date>-<run>.json/.md for any result;
      ids only (no prompt/response text), Markdown-escaped data, JSON SHA-256 in the .md,
      auto-generated limitations and reproduce commands.
      M5 done-when met against the mock baseline (FAIL with reasons); re-check on the lab.

**Done when:** gate FAILs on the untuned baseline and the report explains exactly why.

## M6 — Console
- [x] FastAPI app on `127.0.0.1:8088`; pages: Runs, Run detail, Verdicts, Recommendations, Gate.
      `clawshield console`; read-only GET routes, loopback bind (refuses non-loopback without
      --allow-remote), Host allowlist (DNS rebinding), strict CSP + security headers.
- [x] Charts: per-category detection bars, FPR trend across runs.
      Inline SVG with 95% CI whiskers; /trend plots recall and FPR across runs.
- [x] Use the frontend-design skill for visual direction; keep it HTMX + server templates.
      Deviation: no HTMX/JS at all. A read-only console needs none, and zero script allows
      CSP script-src 'none' and removes the CDN/supply-chain dependency.

**Done when:** the full story (baseline → tune → pass gate) is visible without the CLI.

## M7 — Continuous regression + CI
- [x] `clawshield run --ci` exit codes (FR-21).
      `run --ci` / `clawshield check`: accuracy criteria (gate logic) + regression vs the last
      passing run on the same corpus; exit 0 or 3. Fails closed until verdict ingest exists.
- [x] GitHub Actions workflow running against `mock` target + fixtures on every PR.
      .github/workflows/ci.yml: ubuntu + windows x py3.11/3.13; ruff, format, mypy, bandit,
      pip-audit, pytest (coverage >= 95%); SHA-pinned actions, read-only token.
- [x] Nightly scheduled lab run; Slack alert on regression (FR-20).
      scripts/nightly.sh for cron/systemd on the lab host; `--notify` posts to Slack only on
      failure; webhook must be https://hooks.slack.com/services/..., never logged.
- [ ] Optional `/metrics` endpoint + Grafana dashboard JSON in `deploy/grafana/`.

## M8 — Demo + write-up
- [ ] Tuning cycle documented: baseline vs tuned scorecards.
- [ ] Gate PASS → operator switches to action mode → live block of a CRITICAL injection, benign allowed.
- [ ] README with architecture diagram, screenshots, and a 3-minute demo script.
- [ ] LinkedIn post draft summarizing results.
