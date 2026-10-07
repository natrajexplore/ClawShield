# ADR 0003: Correlating corpus cases with DefenseClaw verdicts

- **Status:** Accepted (logic implemented; parameters to be confirmed against the M0 lab)
- **Date:** 2026-10-06
- **Implements:** FR-9 · **Code:** `src/clawshield/core/correlate.py`

## Context
Scoring needs to know which DefenseClaw verdicts were caused by which corpus case.
DefenseClaw records verdicts in its own audit store; ClawShield only sees them afterwards
(`defenseclaw alerts --json`). There is no shared request id we control. Two joins are
possible: a session/conversation id (if the OpenClaw connector exposes one that ClawShield
can set or read), and timestamps.

A wrong attribution is worse than none: crediting a verdict to the neighbouring case turns
a false negative into a true positive (or a true negative into a false positive) and
corrupts every metric the promotion gate relies on.

## Decision
1. **Session first.** A verdict whose `session_id` equals the `session_id` of exactly one
   case belongs to that case. Session ids shared by several cases (a target reusing one
   conversation) are not used, because they would credit every sharer with every verdict.
   Session-matched cases keep their time window too: DefenseClaw may log some of a case's
   verdicts (e.g. completion or tool_call) without a session id, and such a verdict in the
   overlap with a neighbour must become ambiguous, not a clean match for the neighbour
   (found in code review, 2026-10-06).
2. **Time window fallback.** Each case has the window
   `[sent_at - pre_s, received_at + grace_s]` (`pre_s` = 1 s, `grace_s` =
   `runner.correlation_grace_s`). A remaining verdict inside exactly one window belongs to
   that case.
3. **Ambiguity is reported, never resolved by guessing.** A verdict inside two or more
   windows is credited to no case, and each case it touches is marked `ambiguous`.
   Scoring must exclude ambiguous cases from metrics and report how many there were.
4. **Every case records its method:** `session`, `time_window`, `ambiguous` or `none`.
   Two metrics are reported:
   - *coverage* = (session + time_window) / all cases;
   - *attribution rate* = verdicts credited to exactly one case / all considered verdicts.
   Coverage counts cases that correctly produced no verdict (e.g. allowed benign traffic,
   if `alerts --json` lists only alerts) as failures, so with a 43%-benign corpus it can
   never reach 90%. Attribution rate does not have that bias. **Decided 2026-10-07:** the
   M3 target is attribution rate >= 90% with 0 ambiguous cases; coverage stays reported
   for information only.
5. **Verdicts outside every window are counted as unattributed.** A high count signals
   foreign traffic in the lab or clock skew between ClawShield and DefenseClaw.
6. Only verdicts from the configured connector are considered.

## Consequences
- **Window overlap must be avoided by configuration.** Windows overlap whenever
  `inter_case_delay < grace + pre`. The shipped config (`inter_case_delay_ms: 1500`,
  `correlation_grace_s: 3`) overlaps by 2.5 s, so every time-window verdict landing in the
  overlap becomes ambiguous. Recommendation: `inter_case_delay_ms >= (grace + pre) x 1000`
  (>= 4000 ms at grace 3 s). This makes a 166-case run take ~11 minutes instead of ~4.
- Correctness depends on both clocks agreeing; DefenseClaw and ClawShield run on the same
  lab host, which keeps skew negligible. Re-check if they are ever split across hosts.
- The lab must be dedicated: unrelated traffic through the same connector during a run
  falls into case windows and would be attributed to them.
- Cost is O((cases + verdicts) log cases) using binary search over sorted windows
  (5,000 cases x 20,000 verdicts in ~0.15 s on the dev laptop).

## Alternatives considered
- **Nearest-case assignment for overlaps:** rejected; it silently guesses.
- **Shrinking each window to end where the next case starts:** rejected; it silently
  misattributes verdicts that DefenseClaw records late.
- **Run cases strictly one per session only:** preferred if the OpenClaw connector supports
  it (see ADR 0002, pending the M0 spike); the time window remains the fallback.
