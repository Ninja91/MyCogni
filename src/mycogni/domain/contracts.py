"""Framework-independent value types shared by trusted-core use cases.

These types protect representation boundaries; they do not grant authority,
perform cryptography, or decide whether an external action may run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from uuid import UUID, uuid4

_SAFE_LABEL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def _validate_safe_label(value: str, field_name: str) -> None:
    if not _SAFE_LABEL.fullmatch(value):
        raise ValueError(f"{field_name} must be a 1-64 character lowercase ASCII slug")


@dataclass(frozen=True, slots=True)
class OpaqueId:
    """An opaque UUIDv4 identifier with canonical wire rendering."""

    value: UUID

    def __post_init__(self) -> None:
        if (
            self.value.version != 4
            or self.value.variant != UUID("00000000-0000-4000-8000-000000000000").variant
        ):
            raise ValueError("opaque IDs must be RFC 4122 UUIDv4 values")

    @classmethod
    def new(cls) -> OpaqueId:
        """Create a new opaque identifier using the operating-system RNG."""
        return cls(uuid4())

    @classmethod
    def parse(cls, value: str) -> OpaqueId:
        """Parse and validate a canonical UUIDv4 string."""
        parsed = UUID(value)
        if str(parsed) != value:
            raise ValueError("opaque IDs must use canonical lowercase UUID syntax")
        return cls(parsed)

    def __str__(self) -> str:
        return str(self.value)


class Sensitive[T]:
    """A value that is redacted from ordinary string and repr rendering.

    Callers must use :meth:`reveal` at a reviewed disclosure boundary. This is
    an ergonomics guard, not an access-control or encryption primitive.
    """

    __slots__ = ("__category", "__value")

    def __init__(self, value: T, *, category: str) -> None:
        _validate_safe_label(category, "sensitive category")
        self.__value = value
        self.__category = category

    @property
    def category(self) -> str:
        """Return the validated, immutable redaction category."""
        return self.__category

    def reveal(self) -> T:
        """Return the wrapped value for an explicitly reviewed boundary."""
        return self.__value

    def redacted(self) -> Redacted[T]:
        """Return a typed non-reversible display marker."""
        return Redacted(category=self.category)

    def __repr__(self) -> str:
        return f"Sensitive(category={self.category!r}, value=[REDACTED])"

    def __str__(self) -> str:
        return f"[REDACTED:{self.category}]"


@dataclass(frozen=True, slots=True)
class Redacted[T]:
    """A typed marker proving that a display value is not recoverable here."""

    category: str

    def __post_init__(self) -> None:
        _validate_safe_label(self.category, "redacted category")

    def __str__(self) -> str:
        return f"[REDACTED:{self.category}]"


@dataclass(frozen=True, slots=True, repr=False)
class Ciphertext:
    """Opaque ciphertext plus the metadata needed for later decryption.

    The type validates representation only. Constructing it does not prove the
    payload was encrypted correctly or authorize its decryption.
    """

    payload: bytes
    algorithm: str
    key_id: OpaqueId
    nonce: bytes
    aad_version: int

    def __post_init__(self) -> None:
        if not self.payload:
            raise ValueError("ciphertext payload must not be empty")
        _validate_safe_label(self.algorithm, "ciphertext algorithm")
        if not self.nonce:
            raise ValueError("ciphertext nonce must not be empty")
        if self.aad_version < 1:
            raise ValueError("ciphertext AAD version must be positive")

    def __repr__(self) -> str:
        return (
            "Ciphertext(payload=[REDACTED], "
            f"algorithm={self.algorithm!r}, key_id=[REDACTED], "
            f"nonce_bytes={len(self.nonce)}, aad_version={self.aad_version})"
        )

    def __str__(self) -> str:
        return "[REDACTED:ciphertext]"


@dataclass(frozen=True, slots=True, order=True)
class OptimisticVersion:
    """Non-negative aggregate version used for compare-and-swap writes."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or self.value < 0:
            raise ValueError("optimistic version must be a non-negative integer")

    def next(self) -> OptimisticVersion:
        """Return the version expected after one successful write."""
        return OptimisticVersion(self.value + 1)
