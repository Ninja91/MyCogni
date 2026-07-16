"""A deterministic clock controlled only by the test caller."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

DEFAULT_EPOCH = datetime(2030, 1, 1, tzinfo=UTC)
MAX_ADVANCE_SECONDS = 366 * 24 * 60 * 60


@dataclass(slots=True)
class ControllableClock:
    _current: datetime = DEFAULT_EPOCH

    def __post_init__(self) -> None:
        if self._current.tzinfo is None or self._current.utcoffset() != timedelta(0):
            raise ValueError("controllable clock must start at an explicit UTC instant")

    def now(self) -> datetime:
        return self._current

    def advance(self, *, seconds: int) -> datetime:
        if not 0 <= seconds <= MAX_ADVANCE_SECONDS:
            raise ValueError("clock advance is outside the deterministic test horizon")
        self._current += timedelta(seconds=seconds)
        return self._current

    def canonical_now(self) -> str:
        return self._current.isoformat().replace("+00:00", "Z")
