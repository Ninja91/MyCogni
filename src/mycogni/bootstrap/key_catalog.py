"""Trusted native composition for the durable owner-file key catalog."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from mycogni.adapters.keys.owner_file import OwnerFileSecretProvider
from mycogni.adapters.keys.owner_file_admin import (
    create_readiness_sentinel,
    read_source_commitment,
)
from mycogni.adapters.persistence.key_catalog import SqliteKeyCatalog
from mycogni.application.key_catalog import (
    KeyCatalogError,
    KeyCatalogFailureCode,
    KeyCatalogIdentity,
    KeyCatalogService,
    KeyCatalogSnapshot,
    KeyCatalogState,
)
from mycogni.application.keys import (
    KeyReadinessState,
    ProfileKeyBinding,
    WrappedProfileKey,
)

_SENTINEL_NONCE_BYTES = 12


def _os_sentinel_nonce(length: int) -> bytes:
    """Private OS-entropy call site replaceable only by direct tests."""
    return os.urandom(length)


@dataclass(frozen=True, slots=True, repr=False)
class NativeKeyCatalogConfig:
    """Composition-pinned identity and filesystem boundaries outside SQLite."""

    identity: KeyCatalogIdentity
    key_path: Path
    managed_roots: tuple[Path, ...]

    def __post_init__(self) -> None:
        if type(self.identity) is not KeyCatalogIdentity:
            raise TypeError("native key composition requires a pinned catalog identity")
        if not isinstance(self.key_path, Path):
            raise TypeError("native key composition requires a pathlib key path")
        if type(self.managed_roots) is not tuple or not self.managed_roots:
            raise TypeError("native key composition requires managed roots")
        if any(not isinstance(root, Path) for root in self.managed_roots):
            raise TypeError("native key composition managed roots must be pathlib paths")

    def __repr__(self) -> str:
        return "NativeKeyCatalogConfig(identity=[REDACTED], paths=[REDACTED])"


def compose_native_key_catalog(
    *,
    catalog: SqliteKeyCatalog,
    config: NativeKeyCatalogConfig,
) -> KeyCatalogService:
    """Open an existing catalog without mutating either catalog or key source."""
    if type(catalog) is not SqliteKeyCatalog:
        raise TypeError("native key composition requires the owned SQLite key catalog")
    if type(config) is not NativeKeyCatalogConfig:
        raise TypeError("native key composition requires exact configuration")
    snapshot = catalog.load_catalog()
    if snapshot.identity != config.identity:
        raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
    if snapshot.state is not KeyCatalogState.ACTIVE or snapshot.sentinel is None:
        raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
    provider = OwnerFileSecretProvider(
        key_path=config.key_path,
        active_kek=config.identity.active_kek,
        installation_id=config.identity.installation_id,
        catalog_id=config.identity.catalog_id,
        sentinel_id=config.identity.sentinel_id,
        readiness_sentinel=snapshot.sentinel,
        managed_roots=config.managed_roots,
        process_wrap_limit=config.identity.usage_limit,
    )
    service = KeyCatalogService(
        catalog=catalog,
        secrets=provider,
        expected_identity=config.identity,
    )
    service.readiness()
    return service


def initialize_native_key_catalog(
    *,
    catalog: SqliteKeyCatalog,
    config: NativeKeyCatalogConfig,
) -> KeyCatalogService:
    """Run the explicit empty-install catalog and sentinel ceremony once."""
    if type(catalog) is not SqliteKeyCatalog:
        raise TypeError("native key initialization requires the owned SQLite key catalog")
    if type(config) is not NativeKeyCatalogConfig:
        raise TypeError("native key initialization requires exact configuration")
    try:
        nonce = _os_sentinel_nonce(_SENTINEL_NONCE_BYTES)
    except Exception:
        raise KeyCatalogError(KeyCatalogFailureCode.UNAVAILABLE) from None
    if type(nonce) is not bytes or len(nonce) != _SENTINEL_NONCE_BYTES:
        raise KeyCatalogError(KeyCatalogFailureCode.UNAVAILABLE)
    source_commitment = read_source_commitment(
        key_path=config.key_path,
        managed_roots=config.managed_roots,
    )
    reservation_id = catalog.begin_initialization(
        config.identity,
        nonce,
        source_commitment,
    )
    sentinel = create_readiness_sentinel(
        key_path=config.key_path,
        identity=config.identity,
        reserved_nonce=nonce,
        expected_source_commitment=source_commitment,
        managed_roots=config.managed_roots,
    )
    catalog.finish_initialization(reservation_id, sentinel)
    return compose_native_key_catalog(catalog=catalog, config=config)


def resume_native_key_catalog_initialization(
    *,
    catalog: SqliteKeyCatalog,
    config: NativeKeyCatalogConfig,
) -> KeyCatalogService:
    """Explicitly resume the sole durable PREPARING ceremony; never run at startup."""
    if type(catalog) is not SqliteKeyCatalog:
        raise TypeError("native key initialization requires the owned SQLite key catalog")
    if type(config) is not NativeKeyCatalogConfig:
        raise TypeError("native key initialization requires exact configuration")
    snapshot = catalog.load_catalog()
    if snapshot.identity != config.identity:
        raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
    if snapshot.state is not KeyCatalogState.PREPARING or snapshot.sentinel is not None:
        raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
    reservation_id, nonce, source_commitment = catalog.load_initialization()
    sentinel = create_readiness_sentinel(
        key_path=config.key_path,
        identity=config.identity,
        reserved_nonce=nonce,
        expected_source_commitment=source_commitment,
        managed_roots=config.managed_roots,
    )
    catalog.finish_initialization(reservation_id, sentinel)
    return compose_native_key_catalog(catalog=catalog, config=config)


def reconcile_native_profile_key(
    *,
    catalog: SqliteKeyCatalog,
    config: NativeKeyCatalogConfig,
    binding: ProfileKeyBinding,
) -> WrappedProfileKey | None:
    """Authenticate and report a zero-or-one result without retry or latch clearing."""
    if type(catalog) is not SqliteKeyCatalog:
        raise TypeError("native key reconciliation requires the owned SQLite key catalog")
    if type(config) is not NativeKeyCatalogConfig or type(binding) is not ProfileKeyBinding:
        raise TypeError("native key reconciliation requires exact configuration and binding")
    snapshot = catalog.load_catalog_for_reconciliation()
    if snapshot.identity != config.identity:
        raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
    if snapshot.state is not KeyCatalogState.ACTIVE or snapshot.sentinel is None:
        raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
    provider = OwnerFileSecretProvider(
        key_path=config.key_path,
        active_kek=config.identity.active_kek,
        installation_id=config.identity.installation_id,
        catalog_id=config.identity.catalog_id,
        sentinel_id=config.identity.sentinel_id,
        readiness_sentinel=snapshot.sentinel,
        managed_roots=config.managed_roots,
        process_wrap_limit=config.identity.usage_limit,
    )
    if provider.readiness().state is not KeyReadinessState.READY:
        raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
    wrapped = catalog.reconcile_profile_key(binding)
    if wrapped is not None:
        handle = provider.unwrap_profile_key(wrapped, binding)
        with handle as active:
            active.use(lambda _material: None)
    return wrapped


def reconcile_native_key_catalog_initialization(
    *,
    catalog: SqliteKeyCatalog,
    config: NativeKeyCatalogConfig,
) -> KeyCatalogSnapshot:
    """Explicitly finish PREPARING after dirty restart without clearing recovery."""
    if type(catalog) is not SqliteKeyCatalog:
        raise TypeError("native key reconciliation requires the owned SQLite key catalog")
    if type(config) is not NativeKeyCatalogConfig:
        raise TypeError("native key reconciliation requires exact configuration")
    snapshot = catalog.load_catalog_for_reconciliation()
    if snapshot.identity != config.identity:
        raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
    if snapshot.state is not KeyCatalogState.PREPARING or snapshot.sentinel is not None:
        raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
    reservation_id, nonce, source_commitment = catalog.load_initialization_for_reconciliation()
    sentinel = create_readiness_sentinel(
        key_path=config.key_path,
        identity=config.identity,
        reserved_nonce=nonce,
        expected_source_commitment=source_commitment,
        managed_roots=config.managed_roots,
    )
    catalog.finish_initialization_for_reconciliation(reservation_id, sentinel)
    reconciled = catalog.load_catalog_for_reconciliation()
    if reconciled.state is not KeyCatalogState.ACTIVE:
        raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
    return reconciled


__all__ = (
    "NativeKeyCatalogConfig",
    "compose_native_key_catalog",
    "initialize_native_key_catalog",
    "reconcile_native_key_catalog_initialization",
    "reconcile_native_profile_key",
    "resume_native_key_catalog_initialization",
)
