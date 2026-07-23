"""Application-owned contract for a private operator terminal ceremony."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


class SecretDeliveryState(StrEnum):
    """What can safely be asserted about a secret write."""

    NOT_STARTED = "not_started"
    MAY_HAVE_DISCLOSED = "may_have_disclosed"
    COMPLETE = "complete"


class OperatorTerminalFailure(StrEnum):
    """Finite, redacted terminal failure vocabulary."""

    BUSY = "busy"
    NON_INTERACTIVE = "non_interactive"
    NOT_FOREGROUND = "not_foreground"
    FORKED = "forked"
    CANCELLED = "cancelled"
    EOF = "eof"
    INPUT_TOO_LONG = "input_too_long"
    IO_FAILED = "io_failed"
    RESTORE_FAILED = "restore_failed"
    OUTPUT_UNCERTAIN = "output_uncertain"


@dataclass(frozen=True, slots=True)
class SecretDelivery:
    """Typed result which never turns a partial write into a retry-safe claim."""

    state: SecretDeliveryState

    def __post_init__(self) -> None:
        if type(self.state) is not SecretDeliveryState:
            raise TypeError("secret delivery state must be exact")


@dataclass(frozen=True, slots=True, repr=False)
class SecretField:
    """One bounded label/value pair in an atomic ceremony disclosure attempt."""

    label: str
    value: str

    def __post_init__(self) -> None:
        if type(self.label) is not str or type(self.value) is not str:
            raise TypeError("secret field text must be exact")

    def __repr__(self) -> str:
        return "SecretField([REDACTED])"


class OperatorTerminalError(Exception):
    """Redacted terminal error with conservative secret-delivery state."""

    def __init__(
        self,
        failure: OperatorTerminalFailure,
        delivery: SecretDeliveryState = SecretDeliveryState.NOT_STARTED,
    ) -> None:
        if type(failure) is not OperatorTerminalFailure:
            raise TypeError("operator terminal failure must be exact")
        if type(delivery) is not SecretDeliveryState:
            raise TypeError("secret delivery state must be exact")
        self.failure = failure
        self.delivery = delivery
        super().__init__(failure.value)

    def __repr__(self) -> str:
        return (
            "OperatorTerminalError(failure="
            f"{self.failure.value!r}, delivery={self.delivery.value!r})"
        )

    def __str__(self) -> str:
        return f"operator_terminal:{self.failure.value}:{self.delivery.value}"


@runtime_checkable
class OperatorTerminal(Protocol):
    """Sole application boundary for operator-only input and secret output."""

    def isatty(self) -> bool: ...

    def write_public(self, value: str) -> None: ...

    def confirm(self, prompt: str) -> bool: ...

    def read_secret(self, prompt: str, max_bytes: int) -> str: ...

    def disclose(self, fields: tuple[SecretField, ...]) -> None: ...
