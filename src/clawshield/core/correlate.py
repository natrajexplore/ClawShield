"""Correlate corpus cases with DefenseClaw verdicts (FR-9, ADR 0003). Pure: no I/O.

1. Session: a verdict whose session_id equals the session_id of exactly one case
   belongs to that case.
2. Time window: each remaining verdict is credited to the single case whose window
   [sent_at - pre_s, received_at + grace_s] contains its timestamp. Every case has a
   window, including session-matched ones: DefenseClaw may log some of a case's verdicts
   (e.g. completion or tool_call) without a session id.
3. A verdict inside two or more windows is "ambiguous": it is credited to no case, and
   every case it touches is marked ambiguous so scoring can exclude it, never guess.
"""

import bisect
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Literal

from clawshield.core.models import TargetResult, Verdict

Method = Literal["session", "time_window", "ambiguous", "none"]

DEFAULT_PRE_S = 1.0


@dataclass(frozen=True)
class CaseCorrelation:
    case_id: str
    method: Method
    verdict_ids: tuple[str, ...]
    ambiguous_verdict_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorrelationReport:
    cases: tuple[CaseCorrelation, ...]
    unattributed_verdict_ids: tuple[str, ...]
    by_method: dict[Method, int] = field(default_factory=dict)

    @property
    def coverage(self) -> float:
        """Share of all cases correlated by session or time window.

        Cases that legitimately produced no verdict (e.g. allowed benign traffic, if
        DefenseClaw does not list allows) count against this; see attribution_rate.
        """
        if not self.cases:
            return 0.0
        matched = self.by_method.get("session", 0) + self.by_method.get("time_window", 0)
        return matched / len(self.cases)

    @property
    def attribution_rate(self) -> float:
        """Share of considered verdicts credited to exactly one case (1.0 when none)."""
        attributed = {v for c in self.cases for v in c.verdict_ids}
        ambiguous = {v for c in self.cases for v in c.ambiguous_verdict_ids}
        total = len(attributed) + len(ambiguous) + len(self.unattributed_verdict_ids)
        return len(attributed) / total if total else 1.0


def correlate(
    results: Sequence[TargetResult],
    verdicts: Sequence[Verdict],
    *,
    grace_s: float,
    pre_s: float = DEFAULT_PRE_S,
    connector: str | None = None,
) -> CorrelationReport:
    if grace_s < 0 or pre_s < 0:
        raise ValueError("grace_s and pre_s must be >= 0")
    ids = [r.case_id for r in results]
    if len(set(ids)) != len(ids):
        raise ValueError("results contain duplicate case ids")

    pool = sorted(
        (v for v in verdicts if connector is None or v.connector == connector),
        key=lambda v: (v.ts, v.id),
    )

    # 1. Session matches. Only session ids used by exactly one case identify it; a shared
    #    id (target reusing one conversation) would credit every sharer with every verdict.
    seen = Counter(r.session_id for r in results if r.session_id)
    unique_sessions = {sid for sid, n in seen.items() if n == 1}
    session_hits: dict[str, list[str]] = {}
    remaining: list[Verdict] = []
    for verdict in pool:
        if verdict.session_id is not None and verdict.session_id in unique_sessions:
            session_hits.setdefault(verdict.session_id, []).append(verdict.id)
        else:
            remaining.append(verdict)

    # 2./3. Time windows for every case, located by binary search.
    pre, grace = timedelta(seconds=pre_s), timedelta(seconds=grace_s)
    windows = sorted(
        (r.sent_at - pre, r.received_at + grace, index) for index, r in enumerate(results)
    )
    starts = [w[0] for w in windows]
    longest = max((end - start for start, end, _ in windows), default=timedelta(0))

    assigned: dict[int, list[str]] = {}
    ambiguous: dict[int, list[str]] = {}
    unattributed: list[str] = []
    for verdict in remaining:
        lo = bisect.bisect_left(starts, verdict.ts - longest)
        hi = bisect.bisect_right(starts, verdict.ts)
        owners = [idx for start, end, idx in windows[lo:hi] if start <= verdict.ts <= end]
        if len(owners) == 1:
            assigned.setdefault(owners[0], []).append(verdict.id)
        elif owners:
            for idx in owners:
                ambiguous.setdefault(idx, []).append(verdict.id)
        else:
            unattributed.append(verdict.id)

    order = {v.id: n for n, v in enumerate(pool)}
    cases: list[CaseCorrelation] = []
    counts: dict[Method, int] = {"session": 0, "time_window": 0, "ambiguous": 0, "none": 0}
    for index, result in enumerate(results):
        by_session = session_hits.get(result.session_id or "", [])
        found = sorted([*by_session, *assigned.get(index, [])], key=order.__getitem__)
        method: Method
        if index in ambiguous:
            method = "ambiguous"
        elif by_session:
            method = "session"
        elif found:
            method = "time_window"
        else:
            method = "none"
        counts[method] += 1
        cases.append(
            CaseCorrelation(
                case_id=result.case_id,
                method=method,
                verdict_ids=tuple(found),
                ambiguous_verdict_ids=tuple(ambiguous.get(index, [])),
            )
        )
    return CorrelationReport(
        cases=tuple(cases), unattributed_verdict_ids=tuple(unattributed), by_method=counts
    )
