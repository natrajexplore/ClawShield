# ClawShield — Prompt Injection Firewall (Claude Code context)

## What this project is
ClawShield is a tuning and promotion layer on top of **Cisco DefenseClaw's guardrail**.
DefenseClaw does the inspection and enforcement. ClawShield measures how well it works,
helps tune it, and decides when it is safe to move from `observe` to `action` mode.

Read these before writing code:
1. `docs/PRD.md` — what we are building and why (requirements are numbered, e.g. FR-3).
2. `docs/ARCHITECTURE.md` — components, data flow, interfaces.
3. `docs/TASKS.md` — milestones. Work one milestone at a time, in order.
4. `docs/DEFENSECLAW_REFERENCE.md` — verified DefenseClaw commands and behaviour.

## Golden rules
- **Never re-implement DefenseClaw.** Detection, blocking and rule packs belong to DefenseClaw.
  ClawShield only drives it, reads its verdicts and recommends changes.
- **Integrate through the CLI contract first** (`defenseclaw alerts --json`, `defenseclaw status --json`,
  `defenseclaw guardrail status`). Read DefenseClaw's SQLite/JSONL internals only behind the
  `VerdictSource` interface, and only after documenting the schema in `docs/adr/`.
- **Never auto-apply config changes.** The tuner and promotion gate output a proposed command
  plus evidence. A human runs it.
- **Verify, don't guess.** If a DefenseClaw flag or file path is not in `docs/DEFENSECLAW_REFERENCE.md`,
  check the official docs (https://cisco-ai-defense.github.io/defenseclaw/docs/) or run `--help`
  before using it, then add it to the reference file.
- **Secrets:** never read, print or commit `.env`, `~/.defenseclaw/.env`, or API keys.
  Use env var names in config, never values.
- **Attack corpus safety:** the corpus contains injection/jailbreak *test strings* only. Do not add
  real malware, real credentials, real PII, or instructions for real-world harm. Use canary tokens
  (e.g. `CANARY-7F3A`) to detect leakage.

## Stack
- Python 3.11 (DefenseClaw supports `>=3.10,<3.14`), `uv` for env management
- FastAPI + Jinja2 + HTMX for the console (no SPA framework)
- SQLite (own DB: `data/clawshield.db`) via SQLModel
- Typer for the CLI (`clawshield ...`)
- pytest, ruff, mypy (strict on `src/clawshield/core`)
- promptfoo (Node) and garak (Python) as optional red-team engines

## Layout
```
src/clawshield/
  cli.py            # Typer entrypoint
  config.py         # loads config/clawshield.yaml + env
  core/             # pure logic: models, scoring, gate rules (no I/O)
  targets/          # TargetClient implementations (openclaw, openai_compat)
  sources/          # VerdictSource implementations (defenseclaw_cli, jsonl)
  redteam/          # corpus loader, runner, promptfoo/garak adapters
  tuner/            # suppression + rule-pack recommendations
  gate/             # observe->action promotion readiness
  console/          # FastAPI app, templates
  alerts/           # Slack webhook notifier
redteam/corpus/     # labeled JSONL test prompts
tests/
```

## Commands
```bash
uv sync                          # install deps
uv run pytest -q                 # tests
uv run ruff check . && uv run ruff format --check .
uv run mypy src/clawshield/core
uv run bandit -q -c pyproject.toml -r src   # security lint
uv run pip-audit --skip-editable           # dependency CVEs
uv run clawshield doctor         # checks DefenseClaw + target reachability
uv run clawshield run --corpus redteam/corpus/seed.jsonl
uv run clawshield runs                    # list runs; INCOMPLETE / (no snapshot) flagged
uv run clawshield ingest --promptfoo results.json --out redteam/corpus/combined.jsonl
uv run clawshield score --run latest
uv run clawshield compare <runA> <runB>   # paired A/B with significance
uv run clawshield tune --run latest       # noisy-rule recommendations (never executed)
uv run clawshield recommend-config <A> <B> # rule pack / strategy from an A/B pair
uv run clawshield gate
uv run uvicorn clawshield.console.app:app --reload --port 8088
```

## Conventions
- Type hints everywhere; dataclasses/SQLModel for data, no raw dicts across module boundaries.
- `core/` is pure and fully unit-tested; I/O lives in `targets/`, `sources/`, `console/`.
- Every external command goes through `clawshield.shell.run()` (timeout, captured stderr, no `shell=True`).
- Tests for DefenseClaw integration use recorded fixtures in `tests/fixtures/defenseclaw/`
  (captured real `--json` output). No live calls in unit tests.
- Small commits, one milestone task per commit, message prefix `M<n>:`.

## Definition of done (every task)
- Acceptance criteria in `docs/TASKS.md` met and ticked.
- Tests added/updated and passing; ruff + mypy clean.
- bandit reports no issues and pip-audit reports no known vulnerabilities.
- Unimplemented commands fail closed (non-zero exit); nothing reports PASS without evidence.
- Any new DefenseClaw behaviour relied on is recorded in `docs/DEFENSECLAW_REFERENCE.md`.

