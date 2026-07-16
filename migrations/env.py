"""Alembic environment for the trusted-core SQLite schema."""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool

from mycogni.adapters.persistence import Base, SQLiteSettings, create_sqlite_engine

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_settings() -> SQLiteSettings:
    timeout_text = config.get_main_option("mycogni.busy_timeout_ms") or "5000"
    try:
        busy_timeout_ms = int(timeout_text)
    except ValueError as error:
        raise ValueError("mycogni.busy_timeout_ms must be an integer") from error
    return SQLiteSettings(
        url=config.get_main_option("sqlalchemy.url"),
        busy_timeout_ms=busy_timeout_ms,
    )


def run_migrations_offline() -> None:
    """Render migrations without creating an Engine."""
    settings = _database_settings()
    context.configure(
        url=settings.sqlalchemy_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the explicitly configured database."""
    connectable = create_sqlite_engine(_database_settings(), poolclass=pool.NullPool)

    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
                render_as_batch=True,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
