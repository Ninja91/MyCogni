"""Application-owned structural ports frozen by CT-001."""

from __future__ import annotations

from datetime import datetime
from types import TracebackType
from typing import Protocol, Self, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """UTC time source supplied by composition or tests.

    Implementations must return an aware UTC ``datetime``. Consumers retain
    responsibility for rejecting naive or non-UTC values at trust boundaries.
    """

    def now(self) -> datetime:
        """Return the current aware UTC instant."""
        ...


@runtime_checkable
class UnitOfWork(Protocol):
    """Synchronous transaction boundary owned by the application layer.

    Entering provides a transaction scope. Leaving must roll back uncommitted
    work, including exceptional exits. ``commit`` is always explicit.
    """

    def __enter__(self) -> Self:
        """Enter one transaction scope."""
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the scope, rolling back anything not durably committed."""
        ...

    def commit(self) -> None:
        """Commit the active transaction."""
        ...

    def rollback(self) -> None:
        """Roll back the active transaction."""
        ...
