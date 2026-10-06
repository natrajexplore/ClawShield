# ClawShield — Milestones

Work top to bottom. Tick boxes as acceptance criteria are met. Commit prefix: `M<n>:`.

## M0 — Lab environment (manual + scripted)
> **Deferred to a Linux host (2026-10-06).** DefenseClaw does not support the OpenClaw (proxy)
> connector on native Windows, and WSL/Docker/VM workarounds from Windows are unsupported.
> Run M0 on a Linux/macOS machine with OpenClaw and DefenseClaw both installed there.
> M1 tasks that need no live lab proceed on Windows meanwhile.

- [ ] OpenClaw installed and gateway running (`openclaw gateway status`).
- [ ] DefenseClaw installed (`defenseclaw quickstart`), `defenseclaw doctor` clean.
- [ ] Guardrail in observe mode for the OpenClaw connector:
      `defenseclaw setup guardrail --non-interactive --connector openclaw --mode observe --scanner-mode local --restart`
- [ ] Demo HelpDesk agent configured with a system prompt containing canary `CANARY-7F3A`.
- [x] Confirm whether the OpenClaw connector is hook-based or proxy-based (PRD Q1); record answer.
      **Proxy-based** per official docs (see `docs/DEFENSECLAW_REFERENCE.md`); re-confirm on the lab.
- [ ] Capture real outputs into `tests/fixtures/defenseclaw/`: `status --json`, `guardrail status`,
      `alerts --json --limit 50` after sending 5 benign + 5 malicious messages by hand.

**Done when:** fixtures committed and `scripts/bootstrap.sh` documents every step.

## M1 — Skeleton + spikes
- [x] `uv` project, Typer CLI with `doctor`, `run`, `score`, `gate`, `ingest` stubs.
- [x] `config.py` loads `config/clawshield.yaml`; validates allowlist and thresholds (pydantic).
- [x] `shell.run()` wrapper with timeout and no `shell=True`; unit tests.
- [ ] Spike + ADR 0002: how to send a message to OpenClaw programmatically.
- [ ] Spike + ADR 0001: alert JSON fields available; document mapping to `Verdict`.
- [ ] `clawshield doctor` implements FR-1.

**Done when:** `uv run clawshield doctor` prints a green/red table against the lab.

## M2 — Corpus + runner
> Started ahead of M1's lab-dependent spikes (ADR 0001/0002, `doctor`), which wait for the Linux lab.

- [x] Corpus schema (FR-3) + loader with validation; `redteam/corpus/seed.jsonl` passes.
- [x] Expand corpus to ≥ 150 cases, ≥ 40% benign, ≥ 10 per category.
- [ ] `TargetClient` protocol + `mock` + `openclaw` implementations; allowlist enforced.
      Done: protocol, `mock`, allowlist re-check in `build_target`. Pending: `openclaw` (needs ADR 0002).
- [x] `clawshield run` stores `Run` + `TargetResult` rows; captures guardrail snapshot.
      Snapshot parsing is unverified against real DefenseClaw output until M0 fixtures exist;
      runs without a snapshot are flagged "(no snapshot)" and must not be used as gate evidence.
- [x] Canary detection (FR-6). Every response is checked against every configured canary:
      exact, normalized (case/NFKC/zero-width/homoglyph/separators), tag chars, reversed,
      ROT13, base64, hex. Hits stored per result; LEAK column in `clawshield runs`.

**Done when:** a full run against the lab completes and is listed by `clawshield runs`.

## M3 — Collector + correlation
- [ ] `DefenseClawCliSource` parses `alerts --json` into `Verdict` (fixture-tested).
- [ ] Optional `JsonlSource` behind the same interface.
- [x] Idempotent ingest (NFR-3) using a stable verdict hash.
      `Verdict` model (FR-8, direction may be `unknown`), `stable_verdict_id` (source id,
      else canonical-JSON SHA-256), `VerdictSource` protocol, `Store.add_verdicts` with
      ON CONFLICT DO NOTHING; raw payload dropped when redacting.
- [ ] Correlation per ARCHITECTURE.md; ADR 0003; report correlation coverage.
      Done: `core/correlate.py` (session -> time window -> ambiguous, never guessed),
      coverage + unattributed counts, ADR 0003. Pending: CLI coverage report, which needs
      a working VerdictSource (fixtures). Config note: shipped delay 1500 ms < grace 3 s + 1 s
      makes windows overlap; see ADR 0003.

**Done when:** ≥ 90% of cases in a lab run correlate by session or time window.

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
- [ ] Suppression recommendations (FR-13) with evidence cases.
- [ ] Rule pack / detection strategy recommendation from A/B (FR-14).
- [ ] Proposed commands generated, never executed (FR-15) — test asserts no subprocess call.
- [ ] Gate (FR-16, FR-17) with configurable thresholds; observe duration from first observe-mode run.
- [ ] Evidence pack export (FR-18): `reports/gate-<date>.md` + `.json`.

**Done when:** gate FAILs on the untuned baseline and the report explains exactly why.

## M6 — Console
- [ ] FastAPI app on `127.0.0.1:8088`; pages: Runs, Run detail, Verdicts, Recommendations, Gate.
- [ ] Charts: per-category detection bars, FPR trend across runs.
- [ ] Use the frontend-design skill for visual direction; keep it HTMX + server templates.

**Done when:** the full story (baseline → tune → pass gate) is visible without the CLI.

## M7 — Continuous regression + CI
- [ ] `clawshield run --ci` exit codes (FR-21).
- [ ] GitHub Actions workflow running against `mock` target + fixtures on every PR.
- [ ] Nightly scheduled lab run; Slack alert on regression (FR-20).
- [ ] Optional `/metrics` endpoint + Grafana dashboard JSON in `deploy/grafana/`.

## M8 — Demo + write-up
- [ ] Tuning cycle documented: baseline vs tuned scorecards.
- [ ] Gate PASS → operator switches to action mode → live block of a CRITICAL injection, benign allowed.
- [ ] README with architecture diagram, screenshots, and a 3-minute demo script.
- [ ] LinkedIn post draft summarizing results.
