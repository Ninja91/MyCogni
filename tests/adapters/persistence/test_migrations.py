"""Alembic upgrade, downgrade, and idempotence smoke tests."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

REPOSITORY_ROOT = Path(__file__).parents[3]
HEAD_REVISION = "0001_database_baseline"


def _config(database_path: Path) -> Config:
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    return config


def _current_revision(database_path: Path) -> str | None:
    engine = create_engine(f"sqlite:///{database_path}")
    try:
        with engine.connect() as connection:
            if not inspect(connection).has_table("alembic_version"):
                return None
            return connection.scalar(text("SELECT version_num FROM alembic_version"))
    finally:
        engine.dispose()


def test_fresh_database_upgrades_to_head_without_business_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "fresh.sqlite"
    command.upgrade(_config(database_path), "head")

    engine = create_engine(f"sqlite:///{database_path}")
    try:
        assert inspect(engine).get_table_names() == ["alembic_version"]
    finally:
        engine.dispose()
    assert _current_revision(database_path) == HEAD_REVISION


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
