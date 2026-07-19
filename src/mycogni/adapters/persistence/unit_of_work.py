"""Explicit transaction lifecycle for synchronous SQLAlchemy adapters."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from types import TracebackType

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker


def _create_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Create sessions that do not hide transaction boundaries."""
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class SqlAlchemyUnitOfWork:
    """Context-managed transaction with explicit commit and safe rollback.

    Leaving the context without calling :meth:`commit` always rolls back. This
    concrete adapter is not an application port and exposes no repositories yet.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        readiness_guard: Callable[[], None],
        work_admission: Callable[[], None],
        work_release: Callable[[], None],
        cleanup_failure_handler: Callable[[], None],
    ) -> None:
        self._session_factory = session_factory
        self._readiness_guard = readiness_guard
        self._work_admission = work_admission
        self._work_release = work_release
        self._cleanup_failure_handler = cleanup_failure_handler
        self._session: Session | None = None
        self._terminal = False
        self._work_reserved = False

    @property
    def session(self) -> Session:
        """Return the active session, rejecting use outside the context."""
        if self._session is None:
            raise RuntimeError("unit of work is not active")
        return self._session

    def __enter__(self) -> SqlAlchemyUnitOfWork:
        if self._session is not None or self._terminal:
            raise RuntimeError("unit of work is terminal and cannot be entered")
        try:
            self._work_admission()
        except BaseException:
            self._terminal = True
            raise
        self._work_reserved = True
        # Every application UoW is a potential writer. BEGIN IMMEDIATE obtains
        # SQLite's reserved lock before domain reads can lead to a write, while
        # the one-connection pool serializes worker/scheduler UoWs in-process.
        try:
            self._session = self._session_factory()
            self._session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        except BaseException:
            session = self._session
            self._session = None
            self._terminal = True
            if session is not None:
                try:
                    session.rollback()
                except BaseException:
                    self._report_cleanup_failure()
                try:
                    session.close()
                except BaseException:
                    self._report_cleanup_failure()
            self._release_work_once()
            raise
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
        self._finish(commit=False)

    def _finish(self, *, commit: bool) -> None:
        session = self.session
        # Terminal state is published before any driver cleanup. A failing
        # commit, rollback, or close must never leave this UoW reusable.
        self._session = None
        self._terminal = True
        try:
            if commit:
                try:
                    self._readiness_guard()
                    session.commit()
                except BaseException:
                    try:
                        session.rollback()
                    except BaseException:
                        self._report_cleanup_failure()
                    try:
                        session.close()
                    except BaseException:
                        self._report_cleanup_failure()
                    raise
                try:
                    session.close()
                except BaseException:
                    # Commit is known successful. Returning success avoids an
                    # unsafe job-level retry; the runtime is paused separately.
                    self._report_cleanup_failure()
                return

            try:
                session.rollback()
            except BaseException:
                self._report_cleanup_failure()
                try:
                    session.rollback()
                except BaseException:
                    self._report_cleanup_failure()
                try:
                    session.close()
                except BaseException:
                    self._report_cleanup_failure()
                raise
            try:
                session.close()
            except BaseException:
                self._report_cleanup_failure()
            return
        finally:
            self._release_work_once()

    def _report_cleanup_failure(self) -> None:
        with suppress(BaseException):
            self._cleanup_failure_handler()

    def _release_work_once(self) -> None:
        if not self._work_reserved:
            return
        self._work_reserved = False
        try:
            self._work_release()
        except BaseException:
            self._report_cleanup_failure()

    def commit(self) -> None:
        """Commit and terminally close the active transaction."""
        self._finish(commit=True)

    def rollback(self) -> None:
        """Roll back and terminally close the active transaction."""
        self._finish(commit=False)
