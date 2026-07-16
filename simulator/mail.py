"""Synchronized in-memory mail fixture boundary with capacity reservations."""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from simulator.protocol import MAX_MAIL_MESSAGES, MailFixture, ReservationError, ResourceLimitError


@dataclass(frozen=True, slots=True)
class MailReservation:
    token: int
    message: MailFixture


class InMemoryMailCapture:
    def __init__(self) -> None:
        self._messages: list[MailFixture] = []
        self._reservations: dict[int, MailReservation] = {}
        self._next_token = 1
        self._lock = RLock()

    @property
    def messages(self) -> tuple[MailFixture, ...]:
        with self._lock:
            return tuple(self._messages)

    def reserve(self, message: MailFixture) -> MailReservation:
        with self._lock:
            if len(self._messages) + len(self._reservations) >= MAX_MAIL_MESSAGES:
                raise ResourceLimitError("mail fixture hard cap reached")
            reservation = MailReservation(self._next_token, message)
            self._next_token += 1
            self._reservations[reservation.token] = reservation
            return reservation

    def commit(self, reservation: MailReservation) -> None:
        with self._lock:
            current = self._reservations.pop(reservation.token, None)
            if current != reservation:
                raise ReservationError("mail reservation is stale")
            self._messages.append(reservation.message)

    def rollback(self, reservation: MailReservation) -> None:
        with self._lock:
            current = self._reservations.pop(reservation.token, None)
            if current != reservation:
                raise ReservationError("mail reservation is stale")

    def capture(self, message: MailFixture) -> None:
        reservation = self.reserve(message)
        self.commit(reservation)

    def clear(self) -> None:
        with self._lock:
            if self._reservations:
                raise ReservationError("cannot clear mail while reservations are active")
            self._messages.clear()
