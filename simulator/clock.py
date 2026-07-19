"""A synchronized deterministic clock controlled only by the test caller."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from threading import RLock

DEFAULT_EPOCH = datetime(2030, 1, 1, tzinfo=UTC)
MAX_ADVANCE_SECONDS = 366 * 24 * 60 * 60


def canonical_instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class ControllableClock:
    def __init__(self, current: datetime = DEFAULT_EPOCH) -> None:
        if current.tzinfo is None or current.utcoffset() != timedelta(0):
            raise ValueError("controllable clock must start at an explicit UTC instant")
        self._current = current
        self._lock = RLock()

    def now(self) -> datetime:
        with self._lock:
            return self._current

    def advance(self, *, seconds: int) -> datetime:
        if not 0 <= seconds <= MAX_ADVANCE_SECONDS:
            raise ValueError("clock advance is outside the deterministic test horizon")
        with self._lock:
            self._current += timedelta(seconds=seconds)
            return self._current

    def canonical_now(self) -> str:
        with self._lock:
            return canonical_instant(self._current)
