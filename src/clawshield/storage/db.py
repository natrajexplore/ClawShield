"""SQLite persistence for runs and target results (via SQLModel).

- All queries go through the ORM with bound parameters; no SQL is built from strings.
- Timestamps are stored as UTC and returned timezone-aware (SQLite drops tzinfo).
- On POSIX the DB file is created owner-only (0600): it holds attack prompts and responses.
"""

import os
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, Engine, UniqueConstraint, event, func
from sqlalchemy.engine import URL
from sqlalchemy.types import TypeDecorator
from sqlmodel import Field, Session, SQLModel, col, create_engine, select

from clawshield.core.models import TargetResult


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


@dataclass(frozen=True)
class RunListing:
    run: RunRow
    results: int
    errors: int

    @property
    def complete(self) -> bool:
        return self.run.finished_at is not None


class RunNotFoundError(LookupError):
    pass


def _enable_foreign_keys(dbapi_connection: Any, _record: Any) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _restrict_permissions(path: Path) -> None:
    if sys.platform == "win32":
        return  # NTFS ACLs inherit from the user profile/project folder
    if not path.exists():
        fd = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    os.chmod(path, 0o600)


class Store:
    def __init__(self, db_path: Path) -> None:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        _restrict_permissions(db_path)
        self.engine: Engine = create_engine(URL.create("sqlite", database=str(db_path)))
        event.listen(self.engine, "connect", _enable_foreign_keys)
        SQLModel.metadata.create_all(self.engine)

    def create_run(self, run: RunRow) -> None:
        with Session(self.engine) as session:
            session.add(run)
            session.commit()

    def add_result(self, run_id: str, result: TargetResult) -> None:
        row = ResultRow(run_id=run_id, **result.model_dump())
        with Session(self.engine) as session:
            session.add(row)
            session.commit()

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

    def results(self, run_id: str) -> list[TargetResult]:
        with Session(self.engine) as session:
            stmt = select(ResultRow).where(ResultRow.run_id == run_id).order_by(col(ResultRow.id))
            rows = session.exec(stmt).all()
        return [
            TargetResult.model_validate(row.model_dump(exclude={"id", "run_id"})) for row in rows
        ]

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
                listings.append(RunListing(run=run, results=total, errors=errors))
        return listings
