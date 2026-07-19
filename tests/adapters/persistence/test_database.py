"""DB-001 tests over disposable, synthetic SQLite databases."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from sqlalchemy import Column, Engine, Integer, MetaData, String, Table, insert, select, text

from mycogni.adapters.persistence import (
    FixedFilesystemProbe,
    SQLiteOperatorState,
    SQLiteProcessRole,
    SQLiteRuntime,
    SQLiteSettings,
    SQLiteWriterLease,
    create_sqlite_engine,
)
from mycogni.adapters.persistence.database import _assert_sqlite_connection_policy


def _settings(path: Path, *, busy_timeout_ms: int = 5_000) -> SQLiteSettings:
    return SQLiteSettings(url=f"sqlite:///{path}", busy_timeout_ms=busy_timeout_ms)


def _apply_expected_pragmas(cursor: sqlite3.Cursor) -> None:
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=FULL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.execute("PRAGMA trusted_schema=OFF")
    cursor.execute("PRAGMA secure_delete=ON")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.execute("PRAGMA wal_autocheckpoint=1000")


@contextmanager
def _owned_engine(settings: SQLiteSettings) -> Iterator[Engine]:
    lease = SQLiteWriterLease.acquire(
        settings,
        role=SQLiteProcessRole.ALL_IN_ONE,
        probe=FixedFilesystemProbe("ext4"),
    )
    engine = create_sqlite_engine(settings, writer_lease=lease)
    try:
        yield engine
    finally:
        engine.dispose()
        lease.release()


def test_every_connection_receives_required_pragmas(tmp_path: Path) -> None:
    with (
        _owned_engine(_settings(tmp_path / "pragmas.sqlite", busy_timeout_ms=2_750)) as engine,
        engine.connect() as connection,
    ):
        assert connection.scalar(text("PRAGMA foreign_keys")) == 1
        assert connection.scalar(text("PRAGMA journal_mode")) == "wal"
        assert connection.scalar(text("PRAGMA synchronous")) == 2
        assert connection.scalar(text("PRAGMA busy_timeout")) == 2_750
        assert connection.scalar(text("PRAGMA trusted_schema")) == 0
        assert connection.scalar(text("PRAGMA secure_delete")) == 1
        assert connection.scalar(text("PRAGMA temp_store")) == 2
        assert connection.scalar(text("PRAGMA wal_autocheckpoint")) == 1_000


@pytest.mark.parametrize("busy_timeout_ms", [0, 30_001])
def test_busy_timeout_is_bounded(tmp_path: Path, busy_timeout_ms: int) -> None:
    with pytest.raises(ValueError, match="busy_timeout_ms must be between"):
        _settings(tmp_path / "invalid.sqlite", busy_timeout_ms=busy_timeout_ms)


@pytest.mark.parametrize(
    "url",
    [
        "sqlite://",
        "sqlite:///:memory:",
        "sqlite:///file::memory:?cache=shared&uri=true",
        "sqlite:///file:memdb1?mode=memory&cache=shared&uri=true",
        "sqlite:///real.sqlite?mode=rwc&uri=true",
        "sqlite:///file:real.sqlite",
        "sqlite:///relative.sqlite",
        "postgresql:///mycogni",
    ],
)
def test_only_file_backed_sqlite_is_accepted(url: str) -> None:
    with pytest.raises(ValueError):
        SQLiteSettings(url=url)


def test_connection_policy_fails_closed_when_wal_is_unsupported(tmp_path: Path) -> None:
    connection = sqlite3.connect(":memory:")
    cursor = connection.cursor()
    try:
        _apply_expected_pragmas(cursor)
        with pytest.raises(RuntimeError, match="PRAGMA journal_mode.*'wal'.*'memory'"):
            _assert_sqlite_connection_policy(
                cursor,
                database_path=(tmp_path / "expected.sqlite").resolve(),
                busy_timeout_ms=5_000,
            )
    finally:
        cursor.close()
        connection.close()


def test_connection_policy_rejects_an_unexpected_physical_file(tmp_path: Path) -> None:
    actual_path = tmp_path / "actual.sqlite"
    connection = sqlite3.connect(actual_path)
    cursor = connection.cursor()
    try:
        _apply_expected_pragmas(cursor)
        with pytest.raises(RuntimeError, match="opened an unexpected database file"):
            _assert_sqlite_connection_policy(
                cursor,
                database_path=(tmp_path / "expected.sqlite").resolve(),
                busy_timeout_ms=5_000,
            )
    finally:
        cursor.close()
        connection.close()


def test_unit_of_work_requires_explicit_commit_and_closes_sessions(tmp_path: Path) -> None:
    runtime = SQLiteRuntime.open(
        _settings(tmp_path / "uow.sqlite"), probe=FixedFilesystemProbe("ext4")
    )
    metadata = MetaData()
    synthetic_records = Table(
        "synthetic_records",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("label", String, nullable=False),
    )
    metadata.create_all(runtime.engine)

    try:
        committed = runtime.unit_of_work()
        with committed:
            committed.session.execute(insert(synthetic_records).values(label="committed"))
            committed.commit()
        with pytest.raises(RuntimeError, match="not active"):
            _ = committed.session
        with pytest.raises(RuntimeError, match="not active"):
            committed.commit()
        with pytest.raises(RuntimeError, match="not active"):
            committed.rollback()
        with pytest.raises(RuntimeError, match="terminal"):
            committed.__enter__()

        rolled_back = runtime.unit_of_work()
        with rolled_back:
            rolled_back.session.execute(insert(synthetic_records).values(label="discarded"))
        with pytest.raises(RuntimeError, match="not active"):
            rolled_back.rollback()

        with runtime.engine.connect() as connection:
            labels = connection.scalars(select(synthetic_records.c.label)).all()
        assert labels == ["committed"]
    finally:
        runtime.close_cleanly()


def test_unit_of_work_rolls_back_when_body_raises(tmp_path: Path) -> None:
    runtime = SQLiteRuntime.open(
        _settings(tmp_path / "failure.sqlite"), probe=FixedFilesystemProbe("ext4")
    )
    metadata = MetaData()
    synthetic_records = Table(
        "synthetic_records",
        metadata,
        Column("id", Integer, primary_key=True),
    )
    metadata.create_all(runtime.engine)

    try:
        with (
            pytest.raises(RuntimeError, match="synthetic failure"),
            runtime.unit_of_work() as unit_of_work,
        ):
            unit_of_work.session.execute(insert(synthetic_records).values(id=1))
            raise RuntimeError("synthetic failure")

        with runtime.engine.connect() as connection:
            assert connection.scalar(select(synthetic_records.c.id)) is None
    finally:
        runtime.close_cleanly()


def test_unit_of_work_close_failure_after_commit_is_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = SQLiteRuntime.open(
        _settings(tmp_path / "close-failure.sqlite"),
        probe=FixedFilesystemProbe("ext4"),
    )
    metadata = MetaData()
    records = Table("synthetic_close_failure", metadata, Column("id", Integer, primary_key=True))
    metadata.create_all(runtime.engine)
    unit_of_work = runtime.unit_of_work()
    try:
        with unit_of_work:
            unit_of_work.session.execute(insert(records).values(id=1))
            session = unit_of_work.session
            real_close = session.close

            def fail_after_close() -> None:
                real_close()
                raise RuntimeError("synthetic close failure")

            monkeypatch.setattr(session, "close", fail_after_close)
            unit_of_work.commit()

        assert runtime.readiness.accepting_new_work is False
        assert runtime.readiness.external_actions_must_remain_paused is True
        assert runtime.readiness.operator_state is SQLiteOperatorState.STORAGE_IO_FAILURE
        with pytest.raises(RuntimeError, match="not active"):
            unit_of_work.commit()
        with pytest.raises(RuntimeError, match="terminal"):
            unit_of_work.__enter__()
        with runtime.engine.connect() as connection:
            assert connection.scalar(select(records.c.id)) == 1
    finally:
        runtime.close_cleanly()


def test_rollback_close_failure_pauses_without_masking_body_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = SQLiteRuntime.open(
        _settings(tmp_path / "rollback-close-failure.sqlite"),
        probe=FixedFilesystemProbe("ext4"),
    )
    metadata = MetaData()
    records = Table("synthetic_rollback_close", metadata, Column("id", Integer, primary_key=True))
    metadata.create_all(runtime.engine)
    unit_of_work = runtime.unit_of_work()
    try:
        with pytest.raises(ValueError, match="synthetic body failure"), unit_of_work:
            unit_of_work.session.execute(insert(records).values(id=1))
            session = unit_of_work.session
            real_close = session.close

            def fail_after_close() -> None:
                real_close()
                raise RuntimeError("synthetic rollback close failure")

            monkeypatch.setattr(session, "close", fail_after_close)
            raise ValueError("synthetic body failure")

        assert runtime.readiness.accepting_new_work is False
        assert runtime.readiness.external_actions_must_remain_paused is True
        assert runtime.readiness.operator_state is SQLiteOperatorState.STORAGE_IO_FAILURE
        with pytest.raises(RuntimeError, match="terminal"):
            unit_of_work.__enter__()
        with runtime.engine.connect() as connection:
            assert connection.scalar(select(records.c.id)) is None
    finally:
        runtime.close_cleanly()
