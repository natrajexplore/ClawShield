"""VerdictSource over DefenseClaw's audit database (FR-7, FR-8; schema in ADR 0001).

DefenseClaw 0.8.10 has no `alerts --json`, so guardrail findings are read from
`~/.defenseclaw/audit.db`, strictly read-only. Only scanners verified to be the guardrail
count as verdicts; every other row that looks like a finding is skipped and counted, so
nothing disappears silently.
"""

import json
import re
import sqlite3
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, get_args

from pydantic import ValidationError

from clawshield.core.models import Direction, Severity, Verdict, stable_verdict_id

SOURCE = "defenseclaw_auditdb"
# Verified in the M0 lab fixtures. Add a scanner only with a fixture proving it is the guardrail.
GUARDRAIL_SCANNERS = frozenset({"local-pattern"})
REQUIRED_COLUMNS = frozenset(
    {"id", "timestamp", "action", "event_name", "severity", "session_id", "connector",
     "enforced", "structured_json"}
)  # fmt: skip
MAX_ROWS = 200_000
BUSY_TIMEOUT_S = 5.0

_DIRECTIONS = frozenset(get_args(Direction)) - {"unknown"}
_FRACTION = re.compile(r"\.(\d+)")


class AuditDbError(Exception):
    """The audit database is missing, unreadable, or not the schema ADR 0001 documents."""


@dataclass(frozen=True)
class AuditDbBatch:
    verdicts: list[Verdict]
    skipped: Counter[str] = field(default_factory=Counter)


class AuditDbSource:
    name = SOURCE

    def __init__(self, path: Path, *, connector: str) -> None:
        self.path = path.expanduser()
        self.connector = connector

    def fetch(self, since: datetime) -> list[Verdict]:
        return self.read(since).verdicts

    def read(self, since: datetime) -> AuditDbBatch:
        if since.tzinfo is None:
            raise ValueError("since must be timezone-aware")
        if not self.path.is_file():
            raise AuditDbError(f"DefenseClaw audit database not found: {self.path}")
        # Widened by a day: the string pre-filter must not drop rows written with an offset.
        floor = (since.astimezone(UTC) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
        uri = self.path.resolve().as_uri() + "?mode=ro"
        try:
            with closing(sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_S)) as conn:
                conn.execute("PRAGMA query_only=ON")
                self._check_schema(conn)
                rows = conn.execute(
                    "SELECT id, timestamp, event_name, severity, session_id, connector, enforced,"
                    " structured_json FROM audit_events"
                    " WHERE action = 'scan-finding' AND timestamp >= ?"
                    " ORDER BY timestamp, id LIMIT ?",
                    (floor, MAX_ROWS + 1),
                ).fetchall()
        except sqlite3.Error as exc:
            raise AuditDbError(f"cannot read {self.path}: {exc}") from exc
        if len(rows) > MAX_ROWS:
            raise AuditDbError(
                f"more than {MAX_ROWS} findings since {since.isoformat()}; use a later --since"
            )
        verdicts: list[Verdict] = []
        skipped: Counter[str] = Counter()
        for row in rows:
            ts = parse_timestamp(str(row[1] or ""))
            if ts is not None and ts < since:
                continue  # inside the widened pre-filter only
            verdict, reason = self._to_verdict(row, ts)
            if verdict is None:
                skipped[reason] += 1
            else:
                verdicts.append(verdict)
        return AuditDbBatch(verdicts=verdicts, skipped=skipped)

    @staticmethod
    def _check_schema(conn: sqlite3.Connection) -> None:
        columns = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)")}
        if not columns:
            raise AuditDbError("table audit_events not found (not a DefenseClaw audit.db?)")
        missing = REQUIRED_COLUMNS - columns
        if missing:
            raise AuditDbError(
                f"audit_events lacks column(s) {', '.join(sorted(missing))}; DefenseClaw schema "
                "changed, re-verify ADR 0001"
            )

    def _to_verdict(self, row: tuple[Any, ...], ts: datetime | None) -> tuple[Verdict | None, str]:
        row_id, ts_text, event_name, col_severity, session_id, connector, enforced, sj = row
        if event_name != "finding.observed":
            return None, f"event {event_name}"
        try:
            finding = json.loads(sj) if sj else {}
        except json.JSONDecodeError:
            return None, "invalid structured_json"
        if not isinstance(finding, dict):
            return None, "invalid structured_json"
        scanner = str(finding.get("defenseclaw.scan.scanner") or "none")
        if scanner not in GUARDRAIL_SCANNERS:
            return None, f"scanner {scanner}"
        if enforced is not None:
            return None, "enforced set (action-mode rows unverified, ADR 0001)"
        severity_text = str(finding.get("defenseclaw.security.severity") or col_severity or "")
        try:
            severity = Severity(severity_text.lower())
        except ValueError:
            return None, f"severity {severity_text or 'none'}"
        if ts is None or not row_id:
            return None, "missing id or bad timestamp"
        raw = {
            "id": row_id, "timestamp": ts_text, "session_id": session_id,
            "event_name": event_name, "finding": finding,
        }  # fmt: skip
        rule_id = finding.get("defenseclaw.finding.rule_id")
        try:
            verdict = Verdict(
                id=stable_verdict_id(SOURCE, raw, str(row_id)),
                source=SOURCE,
                ts=ts,
                connector=str(connector) if connector else self.connector,
                direction=_direction(finding.get("defenseclaw.guardrail.evidence_summary")),
                severity=severity,
                rule_id=str(rule_id) if rule_id else None,
                action="observe",
                session_id=str(session_id) if session_id else None,
                raw=raw,
            )
        except ValidationError:
            return None, "invalid finding fields"
        return verdict, ""


def parse_timestamp(text: str) -> datetime | None:
    """RFC 3339 with up to nanoseconds and `Z` -> aware datetime (microseconds), else None."""
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        ts = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo is not None else None


def _direction(evidence: object) -> Direction:
    """`target_type=<x>` from the evidence summary; `prompt` verified, others verbatim."""
    if isinstance(evidence, str):
        for part in evidence.split(";"):
            key, _, value = part.strip().partition("=")
            if key == "target_type" and value in _DIRECTIONS:
                return value  # type: ignore[return-value]
    return "unknown"
