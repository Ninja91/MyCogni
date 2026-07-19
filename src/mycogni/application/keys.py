"""Provider-neutral contracts for wrapping independent profile keys.

These value types deliberately carry no installation key material.  They bind
wrapped profile keys to one installation, profile, catalog schema, and active
provider identity while keeping secret-provider failures safe to report.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import NoReturn, SupportsIndex

from mycogni.domain import OpaqueId

PROFILE_DEK_BYTES = 32
WRAP_NONCE_BYTES = 12
WRAPPED_PROFILE_KEY_BYTES = 48
WRAPPED_KEY_FORMAT_VERSION = 1
WRAPPED_KEY_AAD_VERSION = 1
WRAP_SUITE = "A256GCM"

_PROVIDER_KIND = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


def _positive_u32(value: object, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if not 1 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{label} must be between 1 and 4294967295")
    return value


def _positive_u16(value: object, label: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer")
    if not 1 <= value <= 0xFFFF:
        raise ValueError(f"{label} must be between 1 and 65535")
    return value


@dataclass(frozen=True, slots=True)
class ActiveKekRef:
    """Non-secret identity of the one explicitly configured wrapping key."""

    provider_kind: str
    provider_instance_id: OpaqueId
    kek_id: OpaqueId
    kek_version: int

    def __post_init__(self) -> None:
        if type(self.provider_kind) is not str:
            raise TypeError("provider kind must be a string")
        if not _PROVIDER_KIND.fullmatch(self.provider_kind):
            raise ValueError("provider kind must be a lowercase ASCII slug")
        if type(self.provider_instance_id) is not OpaqueId:
            raise TypeError("provider instance ID must be an OpaqueId")
        if type(self.kek_id) is not OpaqueId:
            raise TypeError("KEK ID must be an OpaqueId")
        _positive_u32(self.kek_version, "KEK version")

    def __repr__(self) -> str:
        return (
            "ActiveKekRef("
            f"provider_kind={self.provider_kind!r}, "
            "provider_instance_id=[REDACTED], kek_id=[REDACTED], "
            f"kek_version={self.kek_version})"
        )


@dataclass(frozen=True, slots=True)
class ProfileKeyBinding:
    """Persisted canonical binding that must authenticate every profile-key unwrap."""

    installation_id: OpaqueId
    profile_id: OpaqueId
    profile_key_version: int
    catalog_schema_version: int

    def __post_init__(self) -> None:
        if type(self.installation_id) is not OpaqueId:
            raise TypeError("installation ID must be an OpaqueId")
        if type(self.profile_id) is not OpaqueId:
            raise TypeError("profile ID must be an OpaqueId")
        _positive_u32(self.profile_key_version, "profile key version")
        _positive_u16(self.catalog_schema_version, "catalog schema version")

    def __repr__(self) -> str:
        return (
            "ProfileKeyBinding(installation_id=[REDACTED], profile_id=[REDACTED], "
            f"profile_key_version={self.profile_key_version}, "
            f"catalog_schema_version={self.catalog_schema_version})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class WrappedProfileKey:
    """Strict, redacted AES-256-GCM record for one random profile DEK."""

    kek_ref: ActiveKekRef
    binding: ProfileKeyBinding
    nonce: bytes
    ciphertext: bytes
    format_version: int = WRAPPED_KEY_FORMAT_VERSION
    aad_version: int = WRAPPED_KEY_AAD_VERSION
    suite: str = WRAP_SUITE

    def __post_init__(self) -> None:
        if type(self.kek_ref) is not ActiveKekRef:
            raise TypeError("wrapped key requires an active KEK reference")
        if type(self.binding) is not ProfileKeyBinding:
            raise TypeError("wrapped key requires a persisted profile-key binding")
        if type(self.format_version) is not int:
            raise TypeError("wrapped-key format version must be an integer")
        if self.format_version != WRAPPED_KEY_FORMAT_VERSION:
            raise ValueError("unsupported wrapped-key format version")
        if type(self.aad_version) is not int:
            raise TypeError("wrapped-key AAD version must be an integer")
        if self.aad_version != WRAPPED_KEY_AAD_VERSION:
            raise ValueError("unsupported wrapped-key AAD version")
        if type(self.suite) is not str:
            raise TypeError("wrapped-key suite must be a string")
        if self.suite != WRAP_SUITE:
            raise ValueError("unsupported wrapped-key suite")
        if type(self.nonce) is not bytes:
            raise TypeError("wrapped-key nonce must be bytes")
        if len(self.nonce) != WRAP_NONCE_BYTES:
            raise ValueError("wrapped-key nonce must be exactly 12 bytes")
        if type(self.ciphertext) is not bytes:
            raise TypeError("wrapped-key ciphertext must be bytes")
        if len(self.ciphertext) != WRAPPED_PROFILE_KEY_BYTES:
            raise ValueError("wrapped-key ciphertext must be exactly 48 bytes")

    def __repr__(self) -> str:
        return (
            "WrappedProfileKey(kek_ref=[REDACTED], profile_id=[REDACTED], "
            f"profile_key_version={self.binding.profile_key_version}, nonce=[REDACTED], "
            f"ciphertext=[REDACTED], format_version={self.format_version}, "
            f"aad_version={self.aad_version}, suite={self.suite!r})"
        )

    def __str__(self) -> str:
        return "[REDACTED:wrapped-profile-key]"


class SourceStatus(StrEnum):
    """Low-level source observations; readability never implies key readiness."""

    READABLE = "readable"
    UNAVAILABLE = "unavailable"
    UNSAFE = "unsafe"
    CORRUPT = "corrupt"


class KeyReadinessState(StrEnum):
    """Installation-level result after authenticating the dedicated sentinel."""

    READY = "ready"
    RECOVERY_REQUIRED = "recovery_required"


@dataclass(frozen=True, slots=True)
class KeyReadiness:
    """Non-secret readiness plus the narrower observed source condition."""

    state: KeyReadinessState
    source_status: SourceStatus

    def __post_init__(self) -> None:
        if type(self.state) is not KeyReadinessState:
            raise TypeError("key readiness state must be a KeyReadinessState")
        if type(self.source_status) is not SourceStatus:
            raise TypeError("key readiness source status must be a SourceStatus")


@dataclass(frozen=True, slots=True, repr=False)
class WrappedReadinessSentinel:
    """Dedicated persisted catalog sentinel; never interchangeable with a profile key."""

    kek_ref: ActiveKekRef
    installation_id: OpaqueId
    catalog_id: OpaqueId
    sentinel_id: OpaqueId
    nonce: bytes
    ciphertext: bytes
    format_version: int = WRAPPED_KEY_FORMAT_VERSION
    aad_version: int = WRAPPED_KEY_AAD_VERSION
    suite: str = WRAP_SUITE

    def __post_init__(self) -> None:
        if type(self.kek_ref) is not ActiveKekRef:
            raise TypeError("readiness sentinel requires an active KEK reference")
        for value, label in (
            (self.installation_id, "installation"),
            (self.catalog_id, "catalog"),
            (self.sentinel_id, "sentinel"),
        ):
            if type(value) is not OpaqueId:
                raise TypeError(f"readiness sentinel {label} ID must be an OpaqueId")
        if type(self.format_version) is not int:
            raise TypeError("readiness-sentinel format version must be an integer")
        if self.format_version != WRAPPED_KEY_FORMAT_VERSION:
            raise ValueError("unsupported readiness-sentinel format version")
        if type(self.aad_version) is not int:
            raise TypeError("readiness-sentinel AAD version must be an integer")
        if self.aad_version != WRAPPED_KEY_AAD_VERSION:
            raise ValueError("unsupported readiness-sentinel AAD version")
        if type(self.suite) is not str:
            raise TypeError("readiness-sentinel suite must be a string")
        if self.suite != WRAP_SUITE:
            raise ValueError("unsupported readiness-sentinel suite")
        if type(self.nonce) is not bytes:
            raise TypeError("readiness-sentinel nonce must be bytes")
        if len(self.nonce) != WRAP_NONCE_BYTES:
            raise ValueError("readiness-sentinel nonce must be exactly 12 bytes")
        if type(self.ciphertext) is not bytes:
            raise TypeError("readiness-sentinel ciphertext must be bytes")
        if len(self.ciphertext) != WRAPPED_PROFILE_KEY_BYTES:
            raise ValueError("readiness-sentinel ciphertext must be exactly 48 bytes")

    def __repr__(self) -> str:
        return (
            "WrappedReadinessSentinel(kek_ref=[REDACTED], installation_id=[REDACTED], "
            "catalog_id=[REDACTED], sentinel_id=[REDACTED], nonce=[REDACTED], "
            "ciphertext=[REDACTED], format_version=1, aad_version=1, suite='A256GCM')"
        )


class SecretFailureCode(StrEnum):
    """Stable redacted causes for fail-closed secret-provider decisions."""

    UNAVAILABLE = "unavailable"
    UNSAFE_STORAGE = "unsafe_storage"
    FORKED_PROCESS = "forked_process"
    MALFORMED_RECORD = "malformed_record"
    PROVIDER_MISMATCH = "provider_mismatch"
    CATALOG_KEY_MISMATCH = "catalog_key_mismatch"
    READINESS_REQUIRED = "readiness_required"
    RECOVERY_REQUIRED = "recovery_required"
    PROVIDER_ALREADY_ACTIVE = "provider_already_active"
    USAGE_LIMIT = "usage_limit"
    NONCE_REUSE = "nonce_reuse"


class SecretProviderError(RuntimeError):
    """Typed provider failure whose rendering cannot disclose backend details."""

    def __init__(self, code: SecretFailureCode) -> None:
        if type(code) is not SecretFailureCode:
            raise TypeError("secret failure code must be a SecretFailureCode")
        self.code = code
        super().__init__(f"secret provider failed closed ({code.value})")

    def __repr__(self) -> str:
        return f"SecretProviderError(code={self.code.value!r})"


class ProfileDekHandle:
    """One-use context-managed view of an unwrapped profile key.

    Closing overwrites this object's mutable buffer on a best-effort basis.
    Python and the cryptography backend may retain copies, so this is not an
    erasure or zeroization guarantee.
    """

    __slots__ = (
        "__active",
        "__closed",
        "__issuer_check",
        "__issuer_token",
        "__material",
        "__pid",
        "__used",
    )

    def __init__(
        self,
        material: bytes | bytearray,
        *,
        _issuer_token: object,
        _issuer_check: Callable[[object, int], bool],
        _pid: int | None = None,
    ) -> None:
        if not isinstance(material, (bytes, bytearray)):
            raise TypeError("profile key material must be bytes-like")
        if len(material) != PROFILE_DEK_BYTES:
            raise ValueError("profile key material must be exactly 32 bytes")
        if not callable(_issuer_check):
            raise TypeError("profile key issuer check must be callable")
        self.__material = bytearray(material)
        self.__issuer_token = _issuer_token
        self.__issuer_check = _issuer_check
        self.__pid = os.getpid() if _pid is None else _pid
        self.__active = False
        self.__closed = False
        self.__used = False

    def _assert_issuer(self) -> None:
        if self.__closed or os.getpid() != self.__pid:
            raise RuntimeError("profile key handle is not available")
        try:
            accepted = self.__issuer_check(self.__issuer_token, self.__pid)
        except Exception:
            accepted = False
        if type(accepted) is not bool or not accepted:
            raise RuntimeError("profile key handle is not available")

    def __enter__(self) -> ProfileDekHandle:
        self._assert_issuer()
        if self.__active:
            raise RuntimeError("profile key handle is not available")
        self.__active = True
        return self

    def use[T](self, operation: Callable[[memoryview], T]) -> T:
        """Run a synchronous operation against a temporary read-only view."""
        self._assert_issuer()
        if not self.__active or self.__used:
            raise RuntimeError("profile key handle is not active")
        if not callable(operation):
            raise TypeError("profile key operation must be callable")
        self.__used = True
        try:
            return operation(memoryview(self.__material).toreadonly())
        finally:
            self.close()

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Invalidate the handle and overwrite its owned mutable buffer."""
        if not self.__closed:
            self.__material[:] = b"\x00" * len(self.__material)
            self.__closed = True
            self.__active = False

    def __repr__(self) -> str:
        return "ProfileDekHandle([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED:profile-dek]"

    def __reduce_ex__(self, _protocol: SupportsIndex) -> NoReturn:
        raise TypeError("profile key handles cannot be serialized")

    def __copy__(self) -> NoReturn:
        raise TypeError("profile key handles cannot be copied")

    def __deepcopy__(self, _memo: object) -> NoReturn:
        raise TypeError("profile key handles cannot be copied")

    def __del__(self) -> None:
        if hasattr(self, "_ProfileDekHandle__closed"):
            self.close()
