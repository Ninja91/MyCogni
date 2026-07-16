"""File-backed SQLite engine and connection policy."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from sqlalchemy import Engine, event
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import ConnectionPoolEntry

MIN_BUSY_TIMEOUT_MS = 1
MAX_BUSY_TIMEOUT_MS = 30_000


class Base(DeclarativeBase):
    """Declarative metadata root; intentionally empty in DB-001."""


@dataclass(frozen=True, slots=True)
class SQLiteSettings:
    """Bounded SQLite connection settings for the V1 local-lite profile."""

    url: str
    busy_timeout_ms: int = 5_000

    def __post_init__(self) -> None:
        parsed = make_url(self.url)
        if parsed.drivername != "sqlite":
            raise ValueError("DB-001 supports only the sqlite driver")
        if parsed.database in {None, "", ":memory:"}:
            raise ValueError("DB-001 requires a file-backed SQLite database")
        if not MIN_BUSY_TIMEOUT_MS <= self.busy_timeout_ms <= MAX_BUSY_TIMEOUT_MS:
            raise ValueError(
                f"busy_timeout_ms must be between {MIN_BUSY_TIMEOUT_MS} and {MAX_BUSY_TIMEOUT_MS}"
            )

    @property
    def sqlalchemy_url(self) -> URL:
        """Return the validated SQLAlchemy URL."""
        return make_url(self.url)


def _apply_sqlite_pragmas(
    dbapi_connection: sqlite3.Connection,
    _connection_record: ConnectionPoolEntry,
    *,
    busy_timeout_ms: int,
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute(f"PRAGMA busy_timeout={busy_timeout_ms:d}")
    finally:
        cursor.close()


def create_sqlite_engine(settings: SQLiteSettings) -> Engine:
    """Create a synchronous Engine with the required per-connection policy.

    SQLite WAL does not make network filesystems or Docker Desktop bind mounts
    durable. Later assurance work must qualify each supported filesystem and
    enforce the single-writer process model.
    """
    from sqlalchemy import create_engine

    engine = create_engine(
        settings.sqlalchemy_url,
        connect_args={"timeout": settings.busy_timeout_ms / 1_000},
    )
    event.listen(
        engine,
        "connect",
        lambda connection, record: _apply_sqlite_pragmas(
            connection,
            record,
            busy_timeout_ms=settings.busy_timeout_ms,
        ),
    )
    return engine
