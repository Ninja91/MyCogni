"""Application ordering tests for the durable wrapped-key catalog."""

from __future__ import annotations

import os
from typing import NoReturn

import pytest

from mycogni.application.key_catalog import (
    KeyCatalogError,
    KeyCatalogFailureCode,
    KeyCatalogIdentity,
    KeyCatalogService,
    KeyCatalogSnapshot,
    KeyCatalogState,
)
from mycogni.application.keys import (
    ActiveKekRef,
    KeyReadiness,
    KeyReadinessState,
    ProfileKeyBinding,
    ProfileKeyPreparation,
    SourceStatus,
    WrappedProfileKey,
    WrappedReadinessSentinel,
)
from mycogni.domain import OpaqueId


def _id(value: str) -> OpaqueId:
    return OpaqueId.parse(value)


KEK = ActiveKekRef(
    provider_kind="owner-file",
    provider_instance_id=_id("30000000-0000-4000-8000-000000000001"),
    kek_id=_id("30000000-0000-4000-8000-000000000002"),
    kek_version=1,
)
IDENTITY = KeyCatalogIdentity(
    installation_id=_id("30000000-0000-4000-8000-000000000003"),
    catalog_id=_id("30000000-0000-4000-8000-000000000004"),
    sentinel_id=_id("30000000-0000-4000-8000-000000000005"),
    active_kek=KEK,
    usage_limit=100,
)
BINDING = ProfileKeyBinding(
    installation_id=IDENTITY.installation_id,
    profile_id=_id("30000000-0000-4000-8000-000000000006"),
    profile_key_version=1,
    catalog_schema_version=1,
)
SENTINEL = WrappedReadinessSentinel(
    kek_ref=KEK,
    installation_id=IDENTITY.installation_id,
    catalog_id=IDENTITY.catalog_id,
    sentinel_id=IDENTITY.sentinel_id,
    nonce=b"s" * 12,
    ciphertext=b"c" * 48,
)
SNAPSHOT = KeyCatalogSnapshot(IDENTITY, KeyCatalogState.ACTIVE, 1, SENTINEL)


class _Catalog:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.wrapped: WrappedProfileKey | None = None

    def load_catalog(self) -> KeyCatalogSnapshot:
        self.events.append("load")
        return SNAPSHOT

    def reserve_profile_preparation(self, preparation: ProfileKeyPreparation) -> OpaqueId:
        assert preparation.binding == BINDING
        assert preparation.nonce == b"n" * 12
        self.events.append("reserve_commit")
        return _id("30000000-0000-4000-8000-000000000007")

    def publish_profile_key(
        self,
        reservation_id: OpaqueId,
        preparation: ProfileKeyPreparation,
        wrapped: WrappedProfileKey,
    ) -> None:
        assert reservation_id == _id("30000000-0000-4000-8000-000000000007")
        assert preparation.nonce == wrapped.nonce
        self.events.append("publish_commit")
        self.wrapped = wrapped

    def load_profile_key(self, binding: ProfileKeyBinding) -> WrappedProfileKey | None:
        assert binding == BINDING
        self.events.append("load_profile")
        return self.wrapped

    def require_recovery(self) -> None:
        self.events.append("require_recovery")


class _Secrets:
    def __init__(self, catalog: _Catalog, *, fail_complete: bool = False) -> None:
        self._catalog = catalog
        self._fail_complete = fail_complete
        self._issuer = object()

    def active_kek(self) -> ActiveKekRef:
        return KEK

    def source_status(self) -> SourceStatus:
        return SourceStatus.READABLE

    def readiness(self) -> KeyReadiness:
        return KeyReadiness(KeyReadinessState.READY, SourceStatus.READABLE)

    def prepare_profile_key(self, binding: ProfileKeyBinding) -> ProfileKeyPreparation:
        self._catalog.events.append("prepare")
        return ProfileKeyPreparation(
            binding,
            b"n" * 12,
            _issuer_token=self._issuer,
            _issuer_check=lambda token, _pid: token is self._issuer,
        )

    def complete_profile_key(self, preparation: ProfileKeyPreparation) -> WrappedProfileKey:
        self._catalog.events.append("complete")
        if self._fail_complete:
            raise RuntimeError("synthetic provider failure")
        binding, nonce = preparation._consume(
            _issuer_token=self._issuer,
            _pid=os.getpid(),
        )
        return WrappedProfileKey(KEK, binding, nonce, b"w" * 48)

    def unwrap_profile_key(self, *_args: object) -> NoReturn:
        raise AssertionError("not used by these ordering tests")


def test_profile_key_is_reserved_before_aead_and_published_afterward() -> None:
    catalog = _Catalog()
    service = KeyCatalogService(
        catalog=catalog,
        secrets=_Secrets(catalog),
        expected_identity=IDENTITY,
    )

    wrapped = service.create_profile_key(BINDING)

    assert wrapped == catalog.wrapped
    assert catalog.events == [
        "load",
        "prepare",
        "reserve_commit",
        "complete",
        "publish_commit",
    ]


def test_provider_failure_burns_reservation_without_publishing() -> None:
    catalog = _Catalog()
    service = KeyCatalogService(
        catalog=catalog,
        secrets=_Secrets(catalog, fail_complete=True),
        expected_identity=IDENTITY,
    )

    with pytest.raises(RuntimeError, match="synthetic provider failure"):
        service.create_profile_key(BINDING)

    assert catalog.wrapped is None
    assert catalog.events == ["load", "prepare", "reserve_commit", "complete"]


def test_catalog_identity_is_pinned_outside_mutable_catalog_state() -> None:
    catalog = _Catalog()
    foreign = KeyCatalogIdentity(
        installation_id=OpaqueId.new(),
        catalog_id=IDENTITY.catalog_id,
        sentinel_id=IDENTITY.sentinel_id,
        active_kek=KEK,
        usage_limit=100,
    )
    service = KeyCatalogService(
        catalog=catalog,
        secrets=_Secrets(catalog),
        expected_identity=foreign,
    )

    with pytest.raises(KeyCatalogError) as caught:
        service.create_profile_key(BINDING)

    assert caught.value.code is KeyCatalogFailureCode.IDENTITY_MISMATCH
    assert catalog.events == ["load"]
