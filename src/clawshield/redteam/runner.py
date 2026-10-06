"""Replay a corpus against the guarded target and store every result (FR-4).

Each result is committed as soon as it arrives. An interrupted run keeps its partial
results and has no `finished_at`, so it can never be scored as a complete run.
"""

import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from clawshield.config import Settings
from clawshield.core.canary import find_canary_leaks
from clawshield.redteam.corpus import Corpus
from clawshield.storage.db import RunRow, Store
from clawshield.targets.base import Clock, TargetClient, utc_now


class RunError(Exception):
    """The run was refused before any case was sent."""


@dataclass(frozen=True)
class RunReport:
    run_id: str
    cases: int
    errors: int
    leaks: int
    duration_s: float
    redacted: bool = False


def new_run_id(clock: Clock = utc_now) -> str:
    return f"{clock():%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


def execute_run(
    *,
    settings: Settings,
    corpus: Corpus,
    target: TargetClient,
    store: Store,
    snapshot: Mapping[str, Any],
    notes: str = "",
    sleep: Callable[[float], None] = time.sleep,
    clock: Clock = utc_now,
) -> RunReport:
    if store.redact_responses != settings.storage.redact_responses:
        # The store enforces redaction; refuse if it disagrees with the config.
        raise RunError("store redaction does not match storage.redact_responses")
    limit = settings.runner.max_cases_per_run
    if len(corpus.cases) > limit:
        raise RunError(
            f"corpus has {len(corpus.cases)} cases, above runner.max_cases_per_run={limit}"
        )

    started_at = clock()
    run_id = new_run_id(lambda: started_at)
    store.create_run(
        RunRow(
            id=run_id,
            started_at=started_at,
            target_kind=settings.target.kind,
            target_name=settings.target.name,
            target_identity=settings.target.identity(),
            corpus_path=str(corpus.path),
            corpus_hash=corpus.sha256,
            case_count=len(corpus.cases),
            guardrail_snapshot=dict(snapshot),
            notes=notes,
        )
    )

    delay_s = settings.runner.inter_case_delay_ms / 1000
    errors = 0
    leaks = 0
    began = time.monotonic()
    for index, case in enumerate(corpus.cases):
        if index and delay_s:
            sleep(delay_s)
        result = target.send(case)
        if result.error is not None:
            errors += 1
        # FR-6: check every configured canary, not only the case's own one; a benign
        # prompt that leaks the system prompt is still a leak. Detect before the store
        # redacts the text.
        hits = find_canary_leaks(result.response_text, settings.canaries)
        if hits:
            leaks += 1
        store.add_result(run_id, result, hits)

    store.finish_run(run_id, clock())
    return RunReport(
        run_id=run_id,
        cases=len(corpus.cases),
        errors=errors,
        leaks=leaks,
        duration_s=time.monotonic() - began,
        redacted=store.redact_responses,
    )
