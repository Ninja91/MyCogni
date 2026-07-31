"""Application orchestration for the durable wrapped-profile-key catalog.

The catalog owns persistence ordering; the secret provider owns KEK access and
AEAD.  A profile-key nonce is therefore prepared first, durably reserved by the
catalog, consumed by the provider, and published only after a second known-good
catalog commit.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Protocol, runtime_checkable

from mycogni.application.keys import (
    ActiveKekRef,
    KeyReadinessState,
    ProfileDekHandle,
    ProfileKeyBinding,
    ProfileKeyPreparation,
    SecretProviderError,
    WrappedProfileKey,
    WrappedReadinessSentinel,
)
from mycogni.application.ports import SecretPort
from mycogni.domain import OpaqueId

KEY_CATALOG_SCHEMA_VERSION = 1


class KeyCatalogState(StrEnum):
    """Finite durable catalog lifecycle."""

    PREPARING = "preparing"
    ACTIVE = "active"
    RECOVERY_REQUIRED = "recovery_required"


@dataclass(frozen=True, slots=True)
class KeyCatalogIdentity:
    """Immutable non-secret identity pinned by trusted composition."""

    installation_id: OpaqueId
    catalog_id: OpaqueId
    sentinel_id: OpaqueId
    active_kek: ActiveKekRef
    usage_limit: int
    schema_version: int = KEY_CATALOG_SCHEMA_VERSION

    def __post_init__(self) -> None:
        for value, label in (
            (self.installation_id, "installation"),
            (self.catalog_id, "catalog"),
            (self.sentinel_id, "sentinel"),
        ):
            if type(value) is not OpaqueId:
                raise TypeError(f"key catalog {label} ID must be an OpaqueId")
        if type(self.active_kek) is not ActiveKekRef:
            raise TypeError("key catalog requires an active KEK reference")
        if type(self.usage_limit) is not int or not 2 <= self.usage_limit <= 100_000:
            raise ValueError("key catalog usage limit must be between 2 and 100000")
        if type(self.schema_version) is not int:
            raise TypeError("key catalog schema version must be an integer")
        if self.schema_version != KEY_CATALOG_SCHEMA_VERSION:
            raise ValueError("unsupported key catalog schema version")

    def __repr__(self) -> str:
        return (
            "KeyCatalogIdentity(installation_id=[REDACTED], catalog_id=[REDACTED], "
            "sentinel_id=[REDACTED], active_kek=[REDACTED], "
            f"usage_limit={self.usage_limit}, schema_version={self.schema_version})"
        )


@dataclass(frozen=True, slots=True)
class KeyCatalogSnapshot:
    """Strict persisted catalog bootstrap state; it contains no plaintext key."""

    identity: KeyCatalogIdentity
    state: KeyCatalogState
    revision: int
    sentinel: WrappedReadinessSentinel | None

    def __post_init__(self) -> None:
        if type(self.identity) is not KeyCatalogIdentity:
            raise TypeError("key catalog snapshot requires an identity")
        if type(self.state) is not KeyCatalogState:
            raise TypeError("key catalog snapshot requires a state")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("key catalog revision must be positive")
        if self.state is KeyCatalogState.PREPARING:
            if self.sentinel is not None:
                raise ValueError("preparing catalog cannot publish a sentinel")
        elif type(self.sentinel) is not WrappedReadinessSentinel:
            raise TypeError("non-preparing catalog requires a readiness sentinel")
        if self.sentinel is not None and (
            self.sentinel.kek_ref != self.identity.active_kek
            or self.sentinel.installation_id != self.identity.installation_id
            or self.sentinel.catalog_id != self.identity.catalog_id
            or self.sentinel.sentinel_id != self.identity.sentinel_id
        ):
            raise ValueError("key catalog sentinel identity mismatch")

    def __repr__(self) -> str:
        return (
            "KeyCatalogSnapshot(identity=[REDACTED], "
            f"state={self.state.value!r}, revision={self.revision}, "
            "sentinel=[REDACTED])"
        )


class KeyCatalogFailureCode(StrEnum):
    """Stable path- and secret-free catalog failure vocabulary."""

    NOT_INITIALIZED = "not_initialized"
    IDENTITY_MISMATCH = "identity_mismatch"
    RECOVERY_REQUIRED = "recovery_required"
    DUPLICATE_PROFILE_KEY = "duplicate_profile_key"
    NONCE_REUSE = "nonce_reuse"
    USAGE_LIMIT = "usage_limit"
    COMMIT_OUTCOME_UNKNOWN = "commit_outcome_unknown"
    CORRUPT = "corrupt"
    UNAVAILABLE = "unavailable"


class KeyCatalogError(RuntimeError):
    """Redacted fail-closed error raised by catalog operations."""

    def __init__(self, code: KeyCatalogFailureCode) -> None:
        if type(code) is not KeyCatalogFailureCode:
            raise TypeError("key catalog failure code must be exact")
        self.code = code
        super().__init__(f"key catalog failed closed ({code.value})")

    def __repr__(self) -> str:
        return f"KeyCatalogError(code={self.code.value!r})"


@runtime_checkable
class KeyCatalogPort(Protocol):
    """Durable catalog operations; implementations own transaction semantics."""

    def load_catalog(self) -> KeyCatalogSnapshot:
        """Strictly load the single catalog or fail closed."""
        ...

    def reserve_profile_preparation(self, preparation: ProfileKeyPreparation) -> OpaqueId:
        """Durably burn the exact prepared nonce before any profile DEK exists."""
        ...

    def publish_profile_key(
        self,
        reservation_id: OpaqueId,
        preparation: ProfileKeyPreparation,
        wrapped: WrappedProfileKey,
    ) -> None:
        """Atomically publish the record and commit its nonce reservation."""
        ...

    def load_profile_key(self, binding: ProfileKeyBinding) -> WrappedProfileKey | None:
        """Load one immutable wrapped record by its complete binding."""
        ...

    def require_recovery(self) -> None:
        """Durably latch the catalog after a provider or integrity failure."""
        ...


class KeyCatalogService:
    """Serialize catalog decisions around the provider's one-use preparations."""

    def __init__(
        self,
        *,
        catalog: KeyCatalogPort,
        secrets: SecretPort,
        expected_identity: KeyCatalogIdentity,
    ) -> None:
        if not isinstance(catalog, KeyCatalogPort):
            raise TypeError("key catalog service requires a catalog port")
        if not isinstance(secrets, SecretPort):
            raise TypeError("key catalog service requires a secret port")
        if type(expected_identity) is not KeyCatalogIdentity:
            raise TypeError("key catalog service requires a pinned identity")
        self._catalog = catalog
        self._secrets = secrets
        self._expected_identity = expected_identity
        self._decision_lock = RLock()

    def readiness(self) -> KeyCatalogSnapshot:
        """Authenticate persisted identity and sentinel without mutating catalog state."""
        with self._decision_lock:
            snapshot = self._catalog.load_catalog()
            if snapshot.identity != self._expected_identity:
                raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
            if snapshot.state is not KeyCatalogState.ACTIVE:
                raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
            if self._secrets.active_kek() != self._expected_identity.active_kek:
                raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
            try:
                readiness = self._secrets.readiness()
            except SecretProviderError:
                self._catalog.require_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED) from None
            if readiness.state is not KeyReadinessState.READY:
                self._catalog.require_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
            return snapshot

    def create_profile_key(self, binding: ProfileKeyBinding) -> WrappedProfileKey:
        """Create one key, publishing nothing before both commits are known good."""
        if type(binding) is not ProfileKeyBinding:
            raise TypeError("key catalog service requires a profile-key binding")
        with self._decision_lock:
            self._assert_binding(binding)
            try:
                preparation = self._secrets.prepare_profile_key(binding)
            except SecretProviderError:
                self._catalog.require_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED) from None
            reservation_id = self._catalog.reserve_profile_preparation(preparation)
            try:
                wrapped = self._secrets.complete_profile_key(preparation)
            except SecretProviderError:
                self._catalog.require_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED) from None
            self._catalog.publish_profile_key(reservation_id, preparation, wrapped)
            return wrapped

    def open_profile_key(self, binding: ProfileKeyBinding) -> ProfileDekHandle:
        """Load and authenticate one existing wrapped profile key."""
        if type(binding) is not ProfileKeyBinding:
            raise TypeError("key catalog service requires a profile-key binding")
        with self._decision_lock:
            self._assert_binding(binding)
            wrapped = self._catalog.load_profile_key(binding)
            if wrapped is None:
                raise KeyCatalogError(KeyCatalogFailureCode.NOT_INITIALIZED)
            try:
                return self._secrets.unwrap_profile_key(wrapped, binding)
            except SecretProviderError:
                self._catalog.require_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED) from None

    def _assert_binding(self, binding: ProfileKeyBinding) -> None:
        snapshot = self.readiness()
        if (
            binding.installation_id != self._expected_identity.installation_id
            or binding.catalog_schema_version != self._expected_identity.schema_version
            or snapshot.identity != self._expected_identity
        ):
            raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
