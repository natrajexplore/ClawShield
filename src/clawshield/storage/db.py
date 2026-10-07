"""SQLite persistence for runs and target results (via SQLModel).

- All queries go through the ORM with bound parameters; no SQL is built from strings.
- Timestamps are stored as UTC and returned timezone-aware (SQLite drops tzinfo).
- On POSIX the DB file is created owner-only (0600): it holds attack prompts and responses.
- With `redact_responses`, response text never reaches the DB: rows hold a fixed
  placeholder (no hash: short responses would be guessable) and `response_redacted`.
- The schema version is kept in `PRAGMA user_version`; a mismatched DB is refused with a
  clear message instead of failing mid-run on a missing column.
"""

import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from sqlalchemy import JSON, DateTime, Engine, UniqueConstraint, event, func, inspect, or_
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import URL
from sqlalchemy.types import TypeDecorator
from sqlmodel import Field, Session, SQLModel, col, create_engine, select

from clawshield.core.canary import CanaryHit, Method
from clawshield.core.models import TargetResult, Verdict

SCHEMA_VERSION = 5

REDACTED_PLACEHOLDER = "[redacted]"


class UTCDateTime(TypeDecorator[datetime]):
    """Rejects naive datetimes on write; stores UTC; returns aware UTC on read."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime cannot be stored; use timezone-aware UTC")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        return None if value is None else value.replace(tzinfo=UTC)


class RunRow(SQLModel, table=True):
    __tablename__ = "runs"

    id: str = Field(primary_key=True)
    started_at: datetime = Field(sa_type=UTCDateTime)
    finished_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    target_kind: str
    target_name: str
    target_identity: str
    corpus_path: str
    corpus_hash: str
    case_count: int
    guardrail_snapshot: dict[str, Any] = Field(sa_type=JSON)
    notes: str = ""
    responses_redacted: bool = False
    declared_config: dict[str, str] | None = Field(default=None, sa_type=JSON)


class ResultRow(SQLModel, table=True):
    __tablename__ = "target_results"
    __table_args__ = (UniqueConstraint("run_id", "case_id"),)

    id: int | None = Field(default=None, primary_key=True)
    run_id: str = Field(foreign_key="runs.id", index=True)
    case_id: str
    session_id: str | None = None
    sent_at: datetime = Field(sa_type=UTCDateTime)
    received_at: datetime = Field(sa_type=UTCDateTime)
    response_text: str | None = None
    error: str | None = None
    http_status: int | None = None
    canary_leaked: bool = False
    canary_hits: list[dict[str, str]] = Field(default_factory=list, sa_type=JSON)
    response_redacted: bool = False


class VerdictRow(SQLModel, table=True):
    __tablename__ = "verdicts"

    id: str = Field(primary_key=True)
    source: str
    ts: datetime = Field(sa_type=UTCDateTime, index=True)
    connector: str
    direction: str
    severity: str
    rule_id: str | None = None
    action: str
    session_id: str | None = Field(default=None, index=True)
    raw: dict[str, Any] | None = Field(default=None, sa_type=JSON)
    ingested_at: datetime = Field(sa_type=UTCDateTime)


@dataclass(frozen=True)
class IngestReport:
    received: int
    new: int

    @property
    def duplicates(self) -> int:
        return self.received - self.new


@dataclass(frozen=True)
class RunListing:
    run: RunRow
    results: int
    errors: int
    leaks: int

    @property
    def complete(self) -> bool:
        return self.run.finished_at is not None


class RunNotFoundError(LookupError):
    pass


class StoreSchemaError(Exception):
    """The database was created by a different ClawShield schema version."""


def _configure_connection(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    # WAL + NORMAL: every committed result survives an application crash or Ctrl+C (the
    # runner commits per case); only a power loss can drop the last commits. ~16x faster
    # than the default on Windows. SQLite gives -wal/-shm the database file's permissions.
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


def _restrict_permissions(path: Path) -> None:
    if sys.platform == "win32":
        return  # NTFS ACLs inherit from the user profile/project folder
    if not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    os.chmod(path, 0o600)


class Store:
    def __init__(self, db_path: Path, *, redact_responses: bool = False) -> None:
        self.redact_responses = redact_responses
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(db_path)
        self.engine: Engine = create_engine(URL.create("sqlite", database=str(db_path)))
        event.listen(self.engine, "connect", _configure_connection)
        self._init_schema(db_path)

    def _init_schema(self, db_path: Path) -> None:
        with self.engine.connect() as conn:
            version = conn.exec_driver_sql("PRAGMA user_version").scalar_one()
            tables = inspect(conn).get_table_names()
        if not tables:
            SQLModel.metadata.create_all(self.engine)
            with self.engine.begin() as conn:
                # PRAGMA cannot take bound parameters; the value is an int constant.
                conn.exec_driver_sql(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        elif version != SCHEMA_VERSION:
            raise StoreSchemaError(
                f"{db_path} has schema version {version}, this ClawShield needs "
                f"{SCHEMA_VERSION}; move the old database aside to start a new one"
            )

    def create_run(self, run: RunRow) -> None:
        run.responses_redacted = self.redact_responses
        with Session(self.engine) as session:
            session.add(run)
            session.commit()

    def add_result(
        self, run_id: str, result: TargetResult, canary_hits: Sequence[CanaryHit] = ()
    ) -> None:
        """Store one result. Canary hits must be computed on the full text beforehand."""
        fields = result.model_dump()
        redacted = self.redact_responses and result.response_text is not None
        if redacted:
            fields["response_text"] = REDACTED_PLACEHOLDER
        row = ResultRow(
            run_id=run_id,
            canary_leaked=bool(canary_hits),
            canary_hits=[{"canary": h.canary, "method": h.method} for h in canary_hits],
            response_redacted=redacted,
            **fields,
        )
        with Session(self.engine) as session:
            session.add(row)
            session.commit()

    def add_verdicts(self, verdicts: Sequence[Verdict], ingested_at: datetime) -> IngestReport:
        """Idempotent ingest (NFR-3): verdicts whose id is already stored are skipped.

        With redaction on, `raw` is dropped: DefenseClaw evidence fields can quote the
        prompt or response text.
        """
        if not verdicts:
            return IngestReport(received=0, new=0)
        rows = []
        for v in verdicts:
            row = v.model_dump(mode="python")  # column types convert ts/ingested_at to UTC
            row["severity"] = v.severity.value
            row["ingested_at"] = ingested_at
            if self.redact_responses:
                row["raw"] = None
            rows.append(row)
        table = SQLModel.metadata.tables["verdicts"]
        stmt = sqlite_insert(table).on_conflict_do_nothing(index_elements=["id"])
        with self.engine.begin() as conn:
            before = conn.execute(select(func.count()).select_from(VerdictRow)).scalar_one()
            conn.execute(stmt, rows)
            after = conn.execute(select(func.count()).select_from(VerdictRow)).scalar_one()
        return IngestReport(received=len(verdicts), new=after - before)

    def recent_verdicts(self, limit: int = 100) -> list[Verdict]:
        """Most recent verdicts first (console feed)."""
        with Session(self.engine) as session:
            stmt = select(VerdictRow).order_by(col(VerdictRow.ts).desc()).limit(limit)
            rows = session.exec(stmt).all()
        return [Verdict.model_validate(row.model_dump(exclude={"ingested_at"})) for row in rows]

    def verdicts_between(self, start: datetime, end: datetime) -> list[Verdict]:
        """Verdicts with start <= ts <= end, oldest first (correlation time window)."""
        with Session(self.engine) as session:
            stmt = (
                select(VerdictRow)
                .where(col(VerdictRow.ts) >= start, col(VerdictRow.ts) <= end)
                .order_by(col(VerdictRow.ts), col(VerdictRow.id))
            )
            rows = session.exec(stmt).all()
        return [Verdict.model_validate(row.model_dump(exclude={"ingested_at"})) for row in rows]

    def finish_run(self, run_id: str, finished_at: datetime) -> None:
        with Session(self.engine) as session:
            run = session.get(RunRow, run_id)
            if run is None:
                raise RunNotFoundError(run_id)
            run.finished_at = finished_at
            session.add(run)
            session.commit()

    def get_run(self, run_id: str) -> RunRow:
        """Fetch a run by id, or the most recently started run for 'latest'."""
        with Session(self.engine) as session:
            if run_id == "latest":
                stmt = select(RunRow).order_by(col(RunRow.started_at).desc()).limit(1)
                run = session.exec(stmt).first()
            else:
                run = session.get(RunRow, run_id)
        if run is None:
            raise RunNotFoundError(run_id)
        return run

    def earlier_runs(self, before: datetime, corpus_hash: str, limit: int = 50) -> list[RunRow]:
        """Complete runs on the same corpus that started before `before`, newest first."""
        with Session(self.engine) as session:
            stmt = (
                select(RunRow)
                .where(
                    col(RunRow.started_at) < before,
                    RunRow.corpus_hash == corpus_hash,
                    col(RunRow.finished_at).is_not(None),
                )
                .order_by(col(RunRow.started_at).desc())
                .limit(limit)
            )
            return list(session.exec(stmt).all())

    def snapshots_until(self, until: datetime) -> list[tuple[datetime, dict[str, Any]]]:
        """(start, guardrail snapshot) of every run started at or before `until`, oldest
        first: the observe-period history (core/posture.py)."""
        with Session(self.engine) as session:
            stmt = (
                select(RunRow)
                .where(col(RunRow.started_at) <= until)
                .order_by(col(RunRow.started_at), col(RunRow.id))
            )
            return [(run.started_at, run.guardrail_snapshot) for run in session.exec(stmt)]

    def runs_overlapping(self, start: datetime, end: datetime, exclude: str) -> list[str]:
        """Ids of other runs active at any point in [start, end] (unfinished = still active)."""
        with Session(self.engine) as session:
            stmt = select(RunRow.id).where(
                RunRow.id != exclude,
                col(RunRow.started_at) <= end,
                or_(col(RunRow.finished_at).is_(None), col(RunRow.finished_at) >= start),
            )
            return sorted(session.exec(stmt).all())

    def results(self, run_id: str) -> list[TargetResult]:
        with Session(self.engine) as session:
            stmt = select(ResultRow).where(ResultRow.run_id == run_id).order_by(col(ResultRow.id))
            rows = session.exec(stmt).all()
        return [
            TargetResult.model_validate(
                row.model_dump(
                    exclude={"id", "run_id", "canary_leaked", "canary_hits", "response_redacted"}
                )
            )
            for row in rows
        ]

    def canary_hits(self, run_id: str) -> dict[str, list[CanaryHit]]:
        """Leaked canaries per case id (cases without a leak are omitted)."""
        with Session(self.engine) as session:
            stmt = select(ResultRow).where(
                ResultRow.run_id == run_id, col(ResultRow.canary_leaked).is_(True)
            )
            rows = session.exec(stmt).all()
        return {
            row.case_id: [
                CanaryHit(h["canary"], cast(Method, h["method"])) for h in row.canary_hits
            ]
            for row in rows
        }

    def list_runs(self, limit: int = 20) -> list[RunListing]:
        with Session(self.engine) as session:
            runs = session.exec(
                select(RunRow).order_by(col(RunRow.started_at).desc()).limit(limit)
            ).all()
            listings = []
            for run in runs:
                total = session.exec(
                    select(func.count()).select_from(ResultRow).where(ResultRow.run_id == run.id)
                ).one()
                errors = session.exec(
                    select(func.count())
                    .select_from(ResultRow)
                    .where(ResultRow.run_id == run.id, col(ResultRow.error).is_not(None))
                ).one()
                leaks = session.exec(
                    select(func.count())
                    .select_from(ResultRow)
                    .where(ResultRow.run_id == run.id, col(ResultRow.canary_leaked).is_(True))
                ).one()
                listings.append(RunListing(run=run, results=total, errors=errors, leaks=leaks))
        return listings
