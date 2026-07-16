"""Synchronized in-memory mail fixture boundary with capacity reservations."""

from __future__ import annotations

from _thread import RLock as RLockType
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

    def _reserve(self, message: MailFixture) -> MailReservation:
        with self._lock:
            if len(self._messages) + len(self._reservations) >= MAX_MAIL_MESSAGES:
                raise ResourceLimitError("mail fixture hard cap reached")
            reservation = MailReservation(self._next_token, message)
            self._next_token += 1
            self._reservations[reservation.token] = reservation
            return reservation

    def transaction_lock(self) -> RLockType:
        return self._lock

    def validate_reservation_locked(self, reservation: MailReservation) -> None:
        if self._reservations.get(reservation.token) != reservation:
            raise ReservationError("mail reservation is stale")

    def snapshot_locked(self, reservation: MailReservation) -> int:
        self.validate_reservation_locked(reservation)
        return len(self._messages)

    def commit_reservation_locked(self, reservation: MailReservation) -> None:
        self.validate_reservation_locked(reservation)
        self._messages.append(reservation.message)

    def restore_snapshot_locked(self, snapshot: int) -> None:
        del self._messages[snapshot:]

    def finalize_reservation_locked(self, reservation: MailReservation) -> None:
        self.validate_reservation_locked(reservation)
        self._reservations.pop(reservation.token)

    def cancel_reservation_locked(self, reservation: MailReservation) -> None:
        self._reservations.pop(reservation.token, None)

    def commit(self, reservation: MailReservation) -> None:
        with self._lock:
            snapshot = self.snapshot_locked(reservation)
            try:
                self.commit_reservation_locked(reservation)
                self.finalize_reservation_locked(reservation)
            except BaseException:
                self.restore_snapshot_locked(snapshot)
                self.cancel_reservation_locked(reservation)
                raise

    def rollback(self, reservation: MailReservation) -> None:
        with self._lock:
            self.validate_reservation_locked(reservation)
            self.cancel_reservation_locked(reservation)

    def capture(self, message: MailFixture) -> None:
        reservation = self._reserve(message)
        self.commit(reservation)

    def clear(self) -> None:
        with self._lock:
            if self._reservations:
                raise ReservationError("cannot clear mail while reservations are active")
            self._messages.clear()
