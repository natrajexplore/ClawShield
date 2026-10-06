"""Shared test helpers."""

from pathlib import Path


def db_bytes(path: Path) -> bytes:
    """Raw bytes of a SQLite DB *and* its WAL side files (recent writes live in -wal)."""
    parts = [path, path.with_name(path.name + "-wal"), path.with_name(path.name + "-shm")]
    return b"".join(p.read_bytes() for p in parts if p.exists())
