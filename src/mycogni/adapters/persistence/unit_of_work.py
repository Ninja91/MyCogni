"""Explicit transaction lifecycle for synchronous SQLAlchemy adapters."""

from __future__ import annotations

from types import TracebackType

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create sessions that do not hide transaction boundaries."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class SqlAlchemyUnitOfWork:
    """Context-managed transaction with explicit commit and safe rollback.

    Leaving the context without calling :meth:`commit` always rolls back. This
    concrete adapter is not an application port and exposes no repositories yet.
    """

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory
        self._session: Session | None = None

    @property
    def session(self) -> Session:
        """Return the active session, rejecting use outside the context."""
        if self._session is None:
            raise RuntimeError("unit of work is not active")
        return self._session

    def __enter__(self) -> SqlAlchemyUnitOfWork:
        if self._session is not None:
            raise RuntimeError("unit of work cannot be entered twice")
        self._session = self._session_factory()
        # Every application UoW is a potential writer. BEGIN IMMEDIATE obtains
        # SQLite's reserved lock before domain reads can lead to a write, while
        # the one-connection pool serializes worker/scheduler UoWs in-process.
        self._session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        if self._session is None:
            return
        try:
            self._session.rollback()
        finally:
            self._session.close()
            self._session = None

    def commit(self) -> None:
        """Commit the active transaction."""
        self.session.commit()

    def rollback(self) -> None:
        """Roll back the active transaction."""
        self.session.rollback()
