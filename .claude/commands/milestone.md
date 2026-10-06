---
description: Work the next unchecked milestone task from docs/TASKS.md
argument-hint: "[milestone, e.g. M2] (optional)"
---

1. Read CLAUDE.md, docs/TASKS.md and the PRD requirements referenced by the target milestone.
2. Target milestone: $ARGUMENTS (if empty, the first milestone with unchecked boxes).
3. Pick the first unchecked task. State the plan in 3–6 bullets, including which tests you will add.
4. Implement it following CLAUDE.md golden rules. If it depends on unverified DefenseClaw
   behaviour, check the official docs or `--help` first and update docs/DEFENSECLAW_REFERENCE.md.
5. Run: `uv run pytest -q`, `uv run ruff check .`, `uv run mypy src/clawshield/core`.
6. Tick the box in docs/TASKS.md, summarize what changed, and propose a commit message prefixed `M<n>:`.
   Stop after one task.
