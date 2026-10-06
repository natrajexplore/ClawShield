# ClawShield — Product Requirements

**Owner:** Nataraj Angappan · **Status:** Draft v0.1 · **Date:** 2026-10-06

## 1. Problem
Teams putting an AI chatbot or agent in front of users need protection against prompt
injection, jailbreaks, system-prompt leakage and data leakage in responses.
Cisco DefenseClaw provides a guardrail that inspects prompts, completions and tool calls,
with two modes: **observe** (log only) and **action** (enforce). DefenseClaw's own guidance
is to run observe mode for at least a week before promoting.

What's missing is the operator workflow around that guardrail:
- How many real attacks did observe mode catch, and how many benign prompts would it have blocked?
- Which rules are noisy and need suppressions, or which rule pack (`default` / `strict` / `permissive`) fits?
- Is the LLM judge worth its cost and latency versus regex only?
- What evidence proves it's safe to switch to action mode?

ClawShield answers those questions with measured data.

## 2. Goals
- G1. Quantify guardrail accuracy (detection rate, false-positive rate) per direction
  (prompt / completion / tool call), per severity and per rule.
- G2. Produce tuning recommendations with evidence, never auto-applied.
- G3. Provide an evidence-based **promotion gate** from observe to action.
- G4. Continuous regression: re-run the attack corpus on a schedule and alert on drift.
- G5. Portfolio-quality demo: a guarded OpenClaw chatbot plus a dashboard telling the story.

## 3. Non-goals
- Building our own detection engine or rule language (DefenseClaw owns detection).
- Attacking third-party systems. Red-team runs target **only** our own demo agent or systems
  the operator owns and is authorized to test.
- Multi-tenant SaaS, user auth beyond a single local operator (v1).

## 4. Users
- **Security engineer / operator:** runs observe mode, reviews findings, tunes, promotes.
- **App owner:** wants a single "is my bot safe to enforce?" answer and a report.
- **Reviewer / CAB:** needs the promotion evidence pack.

## 5. Functional requirements

### Setup & health
- **FR-1** `clawshield doctor` verifies: DefenseClaw installed and healthy (`defenseclaw doctor`),
  guardrail enabled for the target connector (`defenseclaw guardrail status`), current mode,
  and target agent reachable.
- **FR-2** Configuration in `config/clawshield.yaml`: target, connector name, thresholds,
  corpus paths, alert webhook env var name.

### Attack corpus & red-team runs
- **FR-3** Labeled corpus in JSONL. Each case has `id`, `text`, `label`
  (`benign` | `malicious`), `category` (OWASP LLM01 direct, LLM01 indirect, LLM07 system-prompt
  leak, LLM02 sensitive info, jailbreak, encoding/obfuscation, benign-lookalike), `expected_severity`,
  optional `canary`.
- **FR-4** `clawshield run` replays the corpus against the guarded target through a `TargetClient`,
  recording request, response, timestamps and session id per case.
- **FR-5** Optional engines: import promptfoo red-team results and garak reports as additional
  labeled cases (adapters, not re-implementations).
- **FR-6** Canary detection: if a response contains a planted canary (e.g. a secret placed in the
  system prompt), mark it as a confirmed leak regardless of guardrail verdict.

### Verdict collection
- **FR-7** Collect DefenseClaw verdicts via `defenseclaw alerts --json` (primary) and, optionally,
  a configured JSONL observability destination (secondary).
- **FR-8** Normalize to a `Verdict` model: timestamp, connector, direction, severity, rule id,
  action taken or would-have-taken, raw payload.
- **FR-9** Correlate each corpus case to zero or more verdicts (session id first, time window
  fallback). Record correlation confidence.

### Scoring
- **FR-10** Confusion matrix per run: TP, FP, TN, FN — overall, per direction, per category,
  per severity, per rule.
- **FR-11** Metrics: detection rate (recall), false-positive rate on benign traffic, precision,
  "would-block" rate under the balanced profile (CRITICAL blocks; HIGH/MEDIUM alert; LOW allow),
  median and p95 added latency where measurable.
- **FR-12** Compare runs (A/B): e.g. `regex_only` vs `regex_judge`, `default` vs `strict` rule pack.

### Tuning
- **FR-13** Recommend per-rule suppressions for rules with high FP on benign cases, with the
  offending examples attached.
- **FR-14** Recommend rule pack and detection strategy based on A/B results.
- **FR-15** Output recommendations as a reviewable list plus the exact proposed
  `defenseclaw setup guardrail ...` command. Never execute it.

### Promotion gate
- **FR-16** `clawshield gate` evaluates readiness against configurable thresholds. Defaults:
  - observe mode duration ≥ 7 days
  - CRITICAL-category detection rate ≥ 95%
  - benign false-positive rate at block level (CRITICAL) ≤ 1%
  - zero canary leaks in the latest run
  - at least N corpus cases per OWASP category (default 10)
- **FR-17** Gate output: PASS / FAIL per criterion, overall verdict, evidence links, and the proposed
  `--mode action` command (with `--rule-pack` and optional `--human-approval` / `--hilt-min-severity`).
- **FR-18** Export an evidence pack (Markdown + JSON) suitable for a change request / CAB.

### Console & alerting
- **FR-19** Web console: runs list, run detail (confusion matrix, per-category bars, failing cases),
  verdict feed, recommendations, gate status.
- **FR-20** Scheduled regression (cron / CI): nightly corpus run; Slack alert when detection rate
  drops or FPR rises beyond configured deltas versus the last passing run.
- **FR-21** CI mode: `clawshield run --ci` exits non-zero when the gate's accuracy criteria fail
  (for use as a GitHub Actions check after guardrail config changes).

## 6. Non-functional requirements
- **NFR-1 Security:** no secrets in repo/logs; prompts and responses stored locally only;
  configurable redaction of stored text; console binds to localhost by default.
- **NFR-2 Safety:** red-team target allowlist in config; `run` refuses targets not on it.
- **NFR-3 Reliability:** collector is idempotent (re-ingesting the same alerts creates no duplicates).
- **NFR-4 Portability:** Linux and macOS; Python 3.11; no GPU required.
- **NFR-5 Testability:** ≥ 85% coverage on `core/`; DefenseClaw integration tested against recorded fixtures.
- **NFR-6 Performance:** score a 1,000-case run in under 5 seconds.
- **NFR-7 Observability:** structured JSON logs; optional Prometheus `/metrics` for Grafana.

## 7. Success metrics (demo)
- Corpus of ≥ 150 cases across all categories, ≥ 40% benign (including benign look-alikes).
- One documented tuning cycle showing FPR reduced with detection rate held.
- Gate PASS with an exported evidence pack, followed by a live demo in action mode
  blocking a CRITICAL injection while allowing benign traffic.

## 8. Risks & open questions
- **R1** Correlating corpus cases to DefenseClaw alerts may be imprecise → spike in M1; prefer
  a session/conversation id if the OpenClaw connector exposes one.
- **R2** DefenseClaw alert JSON shape may change between releases → pin version, keep fixtures,
  isolate parsing in one module.
- **R3** OpenClaw programmatic access method for sending test messages → spike in M1;
  fallback is a thin chat API in front of the agent.
- **R4** LLM judge cost for large runs → cap run size, cache, make judge optional per run.
- **Q1** Is the OpenClaw connector hook-based or proxy-based in our DefenseClaw version?
  (Affects whether `--port`, default 4000, applies.) Confirm in M0.

## 9. Mapping to OWASP LLM Top 10
| Category | Corpus category | Direction |
|---|---|---|
| LLM01 Prompt Injection (direct) | `llm01_direct` | prompt |
| LLM01 Prompt Injection (indirect, via docs/tools) | `llm01_indirect` | tool call / prompt |
| LLM02 Sensitive Information Disclosure | `llm02_sensitive` | completion |
| LLM07 System Prompt Leakage | `llm07_sysprompt` | completion |
| Jailbreak / role-play | `jailbreak` | prompt |
| Obfuscation (base64, homoglyph, translation) | `obfuscation` | prompt |
| Benign controls | `benign`, `benign_lookalike` | prompt |
