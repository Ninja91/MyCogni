"""In-memory mail fixture boundary; this module cannot deliver mail."""

from __future__ import annotations

from simulator.protocol import MAX_MAIL_MESSAGES, MailFixture, ResourceLimitError


class InMemoryMailCapture:
    def __init__(self) -> None:
        self._messages: list[MailFixture] = []

    @property
    def messages(self) -> tuple[MailFixture, ...]:
        return tuple(self._messages)

    def capture(self, message: MailFixture) -> None:
        if len(self._messages) >= MAX_MAIL_MESSAGES:
            raise ResourceLimitError("mail fixture hard cap reached")
        self._messages.append(message)

    def clear(self) -> None:
        self._messages.clear()
