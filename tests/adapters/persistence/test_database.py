"""DB-001 tests over disposable, synthetic SQLite databases."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, insert, select, text

from mycogni.adapters.persistence import (
    SqlAlchemyUnitOfWork,
    SQLiteSettings,
    create_session_factory,
    create_sqlite_engine,
)


def _settings(path: Path, *, busy_timeout_ms: int = 5_000) -> SQLiteSettings:
    return SQLiteSettings(url=f"sqlite:///{path}", busy_timeout_ms=busy_timeout_ms)


def test_every_connection_receives_required_pragmas(tmp_path: Path) -> None:
    engine = create_sqlite_engine(_settings(tmp_path / "pragmas.sqlite", busy_timeout_ms=2_750))
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("PRAGMA foreign_keys")) == 1
            assert connection.scalar(text("PRAGMA journal_mode")) == "wal"
            assert connection.scalar(text("PRAGMA synchronous")) == 2
            assert connection.scalar(text("PRAGMA busy_timeout")) == 2_750
    finally:
        engine.dispose()


@pytest.mark.parametrize("busy_timeout_ms", [0, 30_001])
def test_busy_timeout_is_bounded(tmp_path: Path, busy_timeout_ms: int) -> None:
    with pytest.raises(ValueError, match="busy_timeout_ms must be between"):
        _settings(tmp_path / "invalid.sqlite", busy_timeout_ms=busy_timeout_ms)


@pytest.mark.parametrize("url", ["sqlite://", "sqlite:///:memory:", "postgresql:///mycogni"])
def test_only_file_backed_sqlite_is_accepted(url: str) -> None:
    with pytest.raises(ValueError):
        SQLiteSettings(url=url)


def test_unit_of_work_requires_explicit_commit_and_closes_sessions(tmp_path: Path) -> None:
    engine = create_sqlite_engine(_settings(tmp_path / "uow.sqlite"))
    metadata = MetaData()
    synthetic_records = Table(
        "synthetic_records",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("label", String, nullable=False),
    )
    metadata.create_all(engine)
    factory = create_session_factory(engine)

    try:
        committed = SqlAlchemyUnitOfWork(factory)
        with committed:
            committed.session.execute(insert(synthetic_records).values(label="committed"))
            committed.commit()
        with pytest.raises(RuntimeError, match="not active"):
            _ = committed.session

        rolled_back = SqlAlchemyUnitOfWork(factory)
        with rolled_back:
            rolled_back.session.execute(insert(synthetic_records).values(label="discarded"))

        with engine.connect() as connection:
            labels = connection.scalars(select(synthetic_records.c.label)).all()
        assert labels == ["committed"]
    finally:
        engine.dispose()


def test_unit_of_work_rolls_back_when_body_raises(tmp_path: Path) -> None:
    engine = create_sqlite_engine(_settings(tmp_path / "failure.sqlite"))
    metadata = MetaData()
    synthetic_records = Table(
        "synthetic_records",
        metadata,
        Column("id", Integer, primary_key=True),
    )
    metadata.create_all(engine)
    factory = create_session_factory(engine)

    try:
        with (
            pytest.raises(RuntimeError, match="synthetic failure"),
            SqlAlchemyUnitOfWork(factory) as unit_of_work,
        ):
            unit_of_work.session.execute(insert(synthetic_records).values(id=1))
            raise RuntimeError("synthetic failure")

        with engine.connect() as connection:
            assert connection.scalar(select(synthetic_records.c.id)) is None
    finally:
        engine.dispose()
