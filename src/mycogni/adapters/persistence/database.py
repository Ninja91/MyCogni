"""File-backed SQLite engine and connection policy."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, event
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import ConnectionPoolEntry, Pool

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
        database = parsed.database
        if database is None or database in {"", ":memory:"}:
            raise ValueError("DB-001 requires a file-backed SQLite database")
        if parsed.query or database.lower().startswith("file:"):
            raise ValueError("DB-001 rejects SQLite URI and query-string modes")
        if not MIN_BUSY_TIMEOUT_MS <= self.busy_timeout_ms <= MAX_BUSY_TIMEOUT_MS:
            raise ValueError(
                f"busy_timeout_ms must be between {MIN_BUSY_TIMEOUT_MS} and {MAX_BUSY_TIMEOUT_MS}"
            )

    @property
    def sqlalchemy_url(self) -> URL:
        """Return the validated SQLAlchemy URL."""
        return make_url(self.url)

    @property
    def database_path(self) -> Path:
        """Return the normalized file target that SQLite must actually open."""
        database = self.sqlalchemy_url.database
        if database is None:  # pragma: no cover - guarded by validation
            raise RuntimeError("validated SQLite URL has no database path")
        return Path(database).resolve(strict=False)


def _read_scalar_pragma(cursor: sqlite3.Cursor, pragma: str) -> object:
    cursor.execute(f"PRAGMA {pragma}")
    row = cursor.fetchone()
    if row is None:
        raise RuntimeError(f"SQLite did not report PRAGMA {pragma}")
    return row[0]


def _assert_sqlite_connection_policy(
    cursor: sqlite3.Cursor,
    *,
    database_path: Path,
    busy_timeout_ms: int,
) -> None:
    expected_pragmas: tuple[tuple[str, object], ...] = (
        ("foreign_keys", 1),
        ("journal_mode", "wal"),
        ("synchronous", 2),
        ("busy_timeout", busy_timeout_ms),
    )
    for pragma, expected in expected_pragmas:
        actual = _read_scalar_pragma(cursor, pragma)
        if isinstance(expected, str):
            matches = str(actual).lower() == expected
        else:
            matches = actual == expected
        if not matches:
            raise RuntimeError(
                f"SQLite rejected required PRAGMA {pragma}: expected {expected!r}, got {actual!r}"
            )

    cursor.execute("PRAGMA database_list")
    databases = cursor.fetchall()
    main_files = [row[2] for row in databases if row[1] == "main"]
    if len(main_files) != 1 or not main_files[0]:
        raise RuntimeError("SQLite connection is not backed by a main database file")
    actual_path = Path(str(main_files[0])).resolve(strict=False)
    if actual_path != database_path:
        raise RuntimeError(
            f"SQLite opened unexpected database file: expected {database_path}, got {actual_path}"
        )


def _apply_sqlite_pragmas(
    dbapi_connection: sqlite3.Connection,
    _connection_record: ConnectionPoolEntry,
    *,
    database_path: Path,
    busy_timeout_ms: int,
) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=FULL")
        cursor.execute(f"PRAGMA busy_timeout={busy_timeout_ms:d}")
        _assert_sqlite_connection_policy(
            cursor,
            database_path=database_path,
            busy_timeout_ms=busy_timeout_ms,
        )
    finally:
        cursor.close()


def create_sqlite_engine(
    settings: SQLiteSettings,
    *,
    poolclass: type[Pool] | None = None,
) -> Engine:
    """Create a synchronous Engine with the required per-connection policy.

    SQLite WAL does not make network filesystems or Docker Desktop bind mounts
    durable. Later assurance work must qualify each supported filesystem and
    enforce the single-writer process model.
    """
    from sqlalchemy import create_engine

    engine_options: dict[str, Any] = {"connect_args": {"timeout": settings.busy_timeout_ms / 1_000}}
    if poolclass is not None:
        engine_options["poolclass"] = poolclass
    engine = create_engine(settings.sqlalchemy_url, **engine_options)
    event.listen(
        engine,
        "connect",
        lambda connection, record: _apply_sqlite_pragmas(
            connection,
            record,
            database_path=settings.database_path,
            busy_timeout_ms=settings.busy_timeout_ms,
        ),
    )
    return engine
