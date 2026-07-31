"""Alembic upgrade, downgrade, and idempotence smoke tests."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.pool import Pool

from mycogni.adapters.persistence import (
    FilesystemMount,
    FixedFilesystemProbe,
    SQLiteProcessRole,
    SQLiteRecoveryError,
    SQLiteRuntime,
    SQLiteSettings,
    SystemFilesystemProbe,
)

REPOSITORY_ROOT = Path(__file__).parents[3]
HEAD_REVISION = "0003_key_catalog"


@pytest.fixture(autouse=True)
def _qualify_synthetic_test_filesystem(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        SystemFilesystemProbe,
        "inspect",
        lambda self, path: FilesystemMount("ext4", path),
    )


def _config_for_url(url: str, *, busy_timeout_ms: int = 5_000) -> Config:
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", url)
    config.set_main_option("mycogni.busy_timeout_ms", str(busy_timeout_ms))
    return config


def _config(database_path: Path, *, busy_timeout_ms: int = 5_000) -> Config:
    return _config_for_url(
        f"sqlite:///{database_path}",
        busy_timeout_ms=busy_timeout_ms,
    )


def _current_revision(database_path: Path) -> str | None:
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        with engine.connect() as connection:
            if not inspect(connection).has_table("alembic_version"):
                return None
            return connection.scalar(text("SELECT version_num FROM alembic_version"))
    finally:
        engine.dispose()


def test_fresh_database_upgrades_to_auth_and_key_catalog_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "fresh.sqlite"
    command.upgrade(_config(database_path), "head")

    engine = create_engine(f"sqlite:///{database_path}")
    try:
        assert inspect(engine).get_table_names() == [
            "alembic_version",
            "auth_authority_handles",
            "auth_decision_state",
            "key_catalog",
            "key_nonce_reservations",
            "key_readiness_sentinel",
            "wrapped_profile_keys",
        ]
        columns = {column["name"] for column in inspect(engine).get_columns("auth_decision_state")}
        assert columns == {"singleton_id", "schema_version", "revision", "state_json"}
        key_catalog_columns = {
            column["name"] for column in inspect(engine).get_columns("key_catalog")
        }
        assert "source_commitment" in key_catalog_columns
        reservation_uniques = {
            constraint["name"]
            for constraint in inspect(engine).get_unique_constraints("key_nonce_reservations")
        }
        assert "uq_key_nonce_profile_binding" in reservation_uniques
    finally:
        engine.dispose()
    assert _current_revision(database_path) == HEAD_REVISION


def test_key_catalog_downgrade_never_touches_external_key_source(tmp_path: Path) -> None:
    database_path = tmp_path / "catalog.sqlite"
    key_path = tmp_path / "operator-owned.kek"
    key_material = b"MYCOGNI-OWNER-KEK\x00\x01" + b"k" * 32
    key_path.write_bytes(key_material)
    key_path.chmod(0o400)
    config = _config(database_path)

    command.upgrade(config, "head")
    command.downgrade(config, "0002_auth_decision_state")

    assert key_path.read_bytes() == key_material
    assert key_path.stat().st_mode & 0o777 == 0o400
    assert _current_revision(database_path) == "0002_auth_decision_state"


def test_online_migration_connection_uses_required_policy(tmp_path: Path) -> None:
    database_path = (tmp_path / "policy.sqlite").resolve()
    expected_timeout = 1_337
    observed: list[tuple[int, str, int, int, Path]] = []

    def observe_checkout(
        dbapi_connection: Any,
        _connection_record: Any,
        _connection_proxy: Any,
    ) -> None:
        connection = dbapi_connection
        if not isinstance(connection, sqlite3.Connection):
            return
        cursor = connection.cursor()
        try:
            cursor.execute("PRAGMA database_list")
            main_path = Path(next(row[2] for row in cursor.fetchall() if row[1] == "main"))
            cursor.execute("PRAGMA foreign_keys")
            foreign_keys = cursor.fetchone()[0]
            cursor.execute("PRAGMA journal_mode")
            journal_mode = cursor.fetchone()[0]
            cursor.execute("PRAGMA synchronous")
            synchronous = cursor.fetchone()[0]
            cursor.execute("PRAGMA busy_timeout")
            busy_timeout = cursor.fetchone()[0]
            observed.append(
                (foreign_keys, journal_mode, synchronous, busy_timeout, main_path.resolve())
            )
        finally:
            cursor.close()

    event.listen(Pool, "checkout", observe_checkout)
    try:
        command.upgrade(_config(database_path, busy_timeout_ms=expected_timeout), "head")
    finally:
        event.remove(Pool, "checkout", observe_checkout)

    # Startup, migration and the single sealed maintenance checkout each prove
    # the same policy; shutdown checkpoint + quick_check intentionally share
    # that one designated connection.
    assert len(observed) >= 3
    assert all(item == (1, "wal", 2, expected_timeout, database_path) for item in observed)


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///:memory:",
        "sqlite:///file:memdb1?mode=memory&cache=shared&uri=true",
        "postgresql:///mycogni",
    ],
)
def test_online_migrations_reject_non_file_sqlite_targets(url: str) -> None:
    with pytest.raises(ValueError):
        command.upgrade(_config_for_url(url), "head")


def test_upgrade_and_downgrade_are_repeatable(tmp_path: Path) -> None:
    database_path = tmp_path / "roundtrip.sqlite"
    config = _config(database_path)

    command.upgrade(config, "head")
    command.upgrade(config, "head")
    assert _current_revision(database_path) == HEAD_REVISION

    command.downgrade(config, "base")
    assert _current_revision(database_path) is None

    command.downgrade(config, "base")
    command.upgrade(config, "head")
    assert _current_revision(database_path) == HEAD_REVISION


def test_migration_refuses_unresolved_recovery_latch(tmp_path: Path) -> None:
    database_path = tmp_path / "recovery-required.sqlite"
    settings = SQLiteSettings(url=f"sqlite:///{database_path}")
    runtime = SQLiteRuntime.open(settings, probe=FixedFilesystemProbe("ext4"))
    runtime.abandon()

    with pytest.raises(SQLiteRecoveryError, match="migration refused"):
        command.upgrade(_config(database_path), "head")

    with pytest.raises(SQLiteRecoveryError, match="migration refused"):
        SQLiteRuntime.open(
            settings,
            role=SQLiteProcessRole.MIGRATION,
            probe=FixedFilesystemProbe("ext4"),
        )
    assert _current_revision(database_path) is None
