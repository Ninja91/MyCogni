"""Adversarial evidence for the pinned owner-only KEK provider."""

from __future__ import annotations

import gc
import os
import select
import stat
import struct
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mycogni.adapters.keys.owner_file import (
    OWNER_KEY_FILE_HEADER,
    OwnerFileSecretProvider,
)
from mycogni.application.keys import (
    ActiveKekRef,
    KeyReadinessState,
    ProfileKeyBinding,
    SecretFailureCode,
    SecretProviderError,
    SourceStatus,
    WrappedReadinessSentinel,
)
from mycogni.application.ports import SecretPort
from mycogni.domain import OpaqueId


def _id(value: str) -> OpaqueId:
    return OpaqueId.parse(value)


ACTIVE_KEK = ActiveKekRef(
    provider_kind="owner-file",
    provider_instance_id=_id("20000000-0000-4000-8000-000000000001"),
    kek_id=_id("20000000-0000-4000-8000-000000000002"),
    kek_version=1,
)
INSTALLATION_ID = _id("20000000-0000-4000-8000-000000000003")
PROFILE_ID = _id("20000000-0000-4000-8000-000000000004")
CATALOG_ID = _id("20000000-0000-4000-8000-000000000005")
SENTINEL_ID = _id("20000000-0000-4000-8000-000000000006")
BINDING = ProfileKeyBinding(
    installation_id=INSTALLATION_ID,
    profile_id=PROFILE_ID,
    profile_key_version=1,
    catalog_schema_version=1,
)
_SENTINEL_PLAINTEXT = b"MyCogni-readiness-sentinel-v1!!!"
_EXPECTED_KEY_MATERIAL: dict[Path, bytes] = {}


def _profile_aad(binding: ProfileKeyBinding = BINDING) -> bytes:
    return b"".join(
        (
            b"MyCogni\x00profile-dek-wrap\x00",
            struct.pack(">H", 1),
            struct.pack(">H", 1),
            binding.installation_id.value.bytes,
            binding.profile_id.value.bytes,
            struct.pack(">I", binding.profile_key_version),
            struct.pack(">H", binding.catalog_schema_version),
            b"\x01",
            ACTIVE_KEK.provider_instance_id.value.bytes,
            ACTIVE_KEK.kek_id.value.bytes,
            struct.pack(">I", ACTIVE_KEK.kek_version),
            b"\x01",
        )
    )


def _sentinel_aad(
    *,
    active_kek: ActiveKekRef = ACTIVE_KEK,
    installation_id: OpaqueId = INSTALLATION_ID,
    catalog_id: OpaqueId = CATALOG_ID,
    sentinel_id: OpaqueId = SENTINEL_ID,
) -> bytes:
    return b"".join(
        (
            b"MyCogni\x00readiness-sentinel\x00",
            struct.pack(">H", 1),
            struct.pack(">H", 1),
            installation_id.value.bytes,
            catalog_id.value.bytes,
            sentinel_id.value.bytes,
            b"\x01",
            active_kek.provider_instance_id.value.bytes,
            active_kek.kek_id.value.bytes,
            struct.pack(">I", active_kek.kek_version),
            b"\x01",
        )
    )


def _sentinel(
    material: bytes = b"k" * 32,
    *,
    active_kek: ActiveKekRef = ACTIVE_KEK,
    installation_id: OpaqueId = INSTALLATION_ID,
    catalog_id: OpaqueId = CATALOG_ID,
    sentinel_id: OpaqueId = SENTINEL_ID,
    nonce: bytes = b"s" * 12,
) -> WrappedReadinessSentinel:
    return WrappedReadinessSentinel(
        kek_ref=active_kek,
        installation_id=installation_id,
        catalog_id=catalog_id,
        sentinel_id=sentinel_id,
        nonce=nonce,
        ciphertext=AESGCM(material).encrypt(
            nonce,
            _SENTINEL_PLAINTEXT,
            _sentinel_aad(
                active_kek=active_kek,
                installation_id=installation_id,
                catalog_id=catalog_id,
                sentinel_id=sentinel_id,
            ),
        ),
    )


def _provision(path: Path, material: bytes | None = None, *, mode: int = 0o600) -> None:
    if material is None:
        material = _EXPECTED_KEY_MATERIAL.get(path, b"k" * 32)
    path.write_bytes(OWNER_KEY_FILE_HEADER + material)
    path.chmod(mode)


@pytest.fixture
def provider_paths(tmp_path: Path) -> tuple[Path, Path]:
    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    key_path = key_directory / "installation.kek"
    material = os.urandom(32)
    _EXPECTED_KEY_MATERIAL[key_path] = material
    _provision(key_path, material)
    managed_root = tmp_path / "managed-data"
    managed_root.mkdir(mode=0o700)
    return key_path, managed_root


def _provider(
    paths: tuple[Path, Path],
    *,
    sentinel_material: bytes | None = None,
    **changes: object,
) -> OwnerFileSecretProvider:
    key_path, managed_root = paths
    if sentinel_material is None:
        sentinel_material = _EXPECTED_KEY_MATERIAL.get(key_path, b"k" * 32)
    arguments: dict[str, object] = {
        "key_path": key_path,
        "active_kek": ACTIVE_KEK,
        "installation_id": INSTALLATION_ID,
        "catalog_id": CATALOG_ID,
        "sentinel_id": SENTINEL_ID,
        "readiness_sentinel": _sentinel(sentinel_material),
        "managed_roots": (managed_root,),
    }
    arguments.update(changes)
    return OwnerFileSecretProvider(**arguments)  # type: ignore[arg-type]


def _ready(provider: OwnerFileSecretProvider) -> None:
    result = provider.readiness()
    assert result.state is KeyReadinessState.READY
    assert result.source_status is SourceStatus.READABLE


def _extract(handle: object) -> bytes:
    with handle as active:  # type: ignore[attr-defined]
        return active.use(bytes)


def test_source_observation_never_authorizes_profile_key_work(
    provider_paths: tuple[Path, Path],
) -> None:
    provider = _provider(provider_paths)

    assert isinstance(provider, SecretPort)
    assert provider.active_kek() == ACTIVE_KEK
    assert provider.source_status() is SourceStatus.READABLE
    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(BINDING)
    assert caught.value.code is SecretFailureCode.READINESS_REQUIRED

    _ready(provider)
    wrapped = provider.create_profile_key(BINDING)
    assert len(wrapped.ciphertext) == 48
    assert _extract(provider.unwrap_profile_key(wrapped, BINDING)) != b"k" * 32


def test_exact_sentinel_record_recomposition_starts_not_ready_then_succeeds(
    provider_paths: tuple[Path, Path],
) -> None:
    provider = _provider(provider_paths)
    _ready(provider)
    del provider
    gc.collect()

    restarted = _provider(provider_paths)
    with pytest.raises(SecretProviderError) as caught:
        restarted.create_profile_key(BINDING)
    assert caught.value.code is SecretFailureCode.READINESS_REQUIRED
    _ready(restarted)


def test_aad_v1_exact_binary_vector(provider_paths: tuple[Path, Path]) -> None:
    provider = _provider(provider_paths)
    expected = bytes.fromhex(
        "4d79436f676e690070726f66696c652d64656b2d7772617000"
        "00010001200000000000400080000000000000032000000000004000"
        "80000000000000040000000100010120000000000040008000000000000001"
        "200000000000400080000000000000020000000101"
    )

    assert provider._profile_aad(BINDING) == expected
    assert expected == _profile_aad()


def test_deterministic_aes_gcm_wrap_vector_covers_every_aad_field(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    key = bytes(range(32))
    profile_dek = bytes(range(32, 64))
    nonce = bytes(range(12))
    expected_ciphertext_and_tag = bytes.fromhex(
        "6723f438e1c0e43ca568bda09dc45642b3e7b507c44e694b005edfbe21543e8d"
        "eb607f0496f6be947cb44dbc1b3a2eb0"
    )
    _provision(key_path, key)
    provider = _provider(provider_paths, sentinel_material=key)
    _ready(provider)
    monkeypatch.setattr(owner_file, "_os_nonce_bytes", lambda length: nonce[:length])
    monkeypatch.setattr(
        owner_file,
        "_os_profile_key_bytes",
        lambda length: profile_dek[:length],
    )

    wrapped = provider.create_profile_key(BINDING)

    assert wrapped.binding == BINDING
    assert wrapped.nonce == nonce
    assert wrapped.ciphertext == expected_ciphertext_and_tag
    assert _extract(provider.unwrap_profile_key(wrapped, BINDING)) == profile_dek


def test_randomized_round_trips_use_distinct_records(
    provider_paths: tuple[Path, Path],
) -> None:
    provider = _provider(provider_paths)
    _ready(provider)
    records = [provider.create_profile_key(BINDING) for _ in range(32)]

    assert len({record.nonce for record in records}) == len(records)
    assert len({record.ciphertext for record in records}) == len(records)
    assert all(
        len(_extract(provider.unwrap_profile_key(record, BINDING))) == 32 for record in records
    )


@pytest.mark.parametrize(
    "binding",
    [
        replace(BINDING, installation_id=_id("20000000-0000-4000-8000-000000000011")),
        replace(BINDING, profile_id=_id("20000000-0000-4000-8000-000000000012")),
        replace(BINDING, profile_key_version=2),
        replace(BINDING, catalog_schema_version=2),
    ],
)
def test_every_persisted_binding_substitution_fails_before_plaintext(
    provider_paths: tuple[Path, Path],
    binding: ProfileKeyBinding,
) -> None:
    provider = _provider(provider_paths)
    _ready(provider)
    wrapped = provider.create_profile_key(BINDING)

    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(wrapped, binding)
    assert caught.value.code is SecretFailureCode.PROVIDER_MISMATCH


@pytest.mark.parametrize(
    "kek_ref",
    [
        replace(ACTIVE_KEK, provider_kind="other-file"),
        replace(
            ACTIVE_KEK,
            provider_instance_id=_id("20000000-0000-4000-8000-000000000021"),
        ),
        replace(ACTIVE_KEK, kek_id=_id("20000000-0000-4000-8000-000000000022")),
        replace(ACTIVE_KEK, kek_version=2),
    ],
)
def test_every_provider_binding_substitution_fails_before_plaintext(
    provider_paths: tuple[Path, Path],
    kek_ref: ActiveKekRef,
) -> None:
    provider = _provider(provider_paths)
    _ready(provider)
    wrapped = provider.create_profile_key(BINDING)

    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(replace(wrapped, kek_ref=kek_ref), BINDING)
    assert caught.value.code is SecretFailureCode.PROVIDER_MISMATCH


def test_tampered_profile_record_latches_recovery(provider_paths: tuple[Path, Path]) -> None:
    provider = _provider(provider_paths)
    _ready(provider)
    wrapped = provider.create_profile_key(BINDING)
    mutated = replace(
        wrapped,
        ciphertext=bytes([wrapped.ciphertext[0] ^ 1]) + wrapped.ciphertext[1:],
    )

    with pytest.raises(SecretProviderError) as mismatch:
        provider.unwrap_profile_key(mutated, BINDING)
    with pytest.raises(SecretProviderError) as latched:
        provider.unwrap_profile_key(wrapped, BINDING)

    assert mismatch.value.code is SecretFailureCode.CATALOG_KEY_MISMATCH
    assert latched.value.code is SecretFailureCode.RECOVERY_REQUIRED
    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED


def test_readiness_backend_failure_is_redacted_unavailable(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)

    class FailingCipher:
        def __init__(self, _key: object) -> None:
            pass

        def decrypt(self, _nonce: bytes, _ciphertext: bytes, _aad: bytes) -> bytes:
            raise RuntimeError(f"backend-canary:{key_path}")

    monkeypatch.setattr(owner_file, "AESGCM", FailingCipher)
    readiness = provider.readiness()

    assert readiness.state is KeyReadinessState.RECOVERY_REQUIRED
    assert readiness.source_status is SourceStatus.UNAVAILABLE
    assert str(key_path) not in repr(readiness)


def test_unwrap_backend_failure_is_redacted_unavailable(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    _ready(provider)
    wrapped = provider.create_profile_key(BINDING)

    class FailingCipher:
        def __init__(self, _key: object) -> None:
            pass

        def decrypt(self, _nonce: bytes, _ciphertext: bytes, _aad: bytes) -> bytes:
            raise RuntimeError(f"backend-canary:{key_path}")

    monkeypatch.setattr(owner_file, "AESGCM", FailingCipher)
    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(wrapped, BINDING)

    assert caught.value.code is SecretFailureCode.UNAVAILABLE
    assert str(key_path) not in repr(caught.value)


def test_invalid_tag_does_not_overwrite_post_use_source_latch(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cryptography.exceptions import InvalidTag

    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    _ready(provider)
    wrapped = provider.create_profile_key(BINDING)

    class RemovingCipher:
        def __init__(self, _key: object) -> None:
            pass

        def decrypt(self, _nonce: bytes, _ciphertext: bytes, _aad: bytes) -> bytes:
            key_path.unlink()
            raise InvalidTag

    monkeypatch.setattr(owner_file, "AESGCM", RemovingCipher)
    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(wrapped, BINDING)

    assert caught.value.code is SecretFailureCode.CATALOG_KEY_MISMATCH
    readiness = provider.readiness()
    assert readiness.state is KeyReadinessState.RECOVERY_REQUIRED
    assert readiness.source_status is SourceStatus.UNAVAILABLE


def test_failed_initial_sentinel_authentication_is_permanently_latched(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    original_material = _EXPECTED_KEY_MATERIAL[key_path]
    provider = _provider(provider_paths)
    _provision(key_path, b"w" * 32)

    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED
    _provision(key_path, original_material)
    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED
    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(BINDING)
    assert caught.value.code is SecretFailureCode.RECOVERY_REQUIRED


def test_corrupted_sentinel_ciphertext_is_recovery_required_and_latched(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    sentinel = _sentinel(_EXPECTED_KEY_MATERIAL[key_path])
    corrupted = replace(
        sentinel,
        ciphertext=bytes([sentinel.ciphertext[0] ^ 1]) + sentinel.ciphertext[1:],
    )
    provider = _provider(provider_paths, readiness_sentinel=corrupted)

    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED
    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED


def test_profile_purpose_ciphertext_cannot_authorize_readiness(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    material = _EXPECTED_KEY_MATERIAL[key_path]
    nonce = b"p" * 12
    wrong_purpose = replace(
        _sentinel(material),
        nonce=nonce,
        ciphertext=AESGCM(material).encrypt(nonce, b"d" * 32, _profile_aad()),
    )
    provider = _provider(provider_paths, readiness_sentinel=wrong_purpose)

    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED


@pytest.mark.parametrize(
    ("field", "substituted_id"),
    [
        ("installation_id", _id("20000000-0000-4000-8000-000000000031")),
        ("catalog_id", _id("20000000-0000-4000-8000-000000000032")),
        ("sentinel_id", _id("20000000-0000-4000-8000-000000000033")),
    ],
)
def test_sentinel_identity_substitution_cannot_authorize_readiness(
    provider_paths: tuple[Path, Path],
    field: str,
    substituted_id: OpaqueId,
) -> None:
    key_path, _managed_root = provider_paths
    substituted = replace(
        _sentinel(_EXPECTED_KEY_MATERIAL[key_path]),
        **{field: substituted_id},
    )
    provider = _provider(
        provider_paths,
        readiness_sentinel=substituted,
        **{field: substituted_id},
    )

    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED


def test_existing_install_missing_source_is_never_unprovisioned(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    key_path.unlink()

    assert provider.source_status() is SourceStatus.UNAVAILABLE
    result = provider.readiness()
    assert result.state is KeyReadinessState.RECOVERY_REQUIRED
    assert result.source_status is SourceStatus.UNAVAILABLE
    assert not key_path.exists()


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"", SourceStatus.CORRUPT),
        (b"bad", SourceStatus.CORRUPT),
        (OWNER_KEY_FILE_HEADER + b"x" * 31, SourceStatus.CORRUPT),
        (b"X" * len(OWNER_KEY_FILE_HEADER) + b"k" * 32, SourceStatus.CORRUPT),
    ],
)
def test_corrupt_source_is_neutral_recovery_required(
    provider_paths: tuple[Path, Path],
    payload: bytes,
    expected: SourceStatus,
) -> None:
    key_path, _managed_root = provider_paths
    key_path.write_bytes(payload)
    key_path.chmod(0o600)
    provider = _provider(provider_paths)

    assert provider.source_status() is expected
    readiness = provider.readiness()
    assert readiness.state is KeyReadinessState.RECOVERY_REQUIRED
    assert readiness.source_status is expected


def test_valid_key_replacement_after_ready_latches_even_after_restore(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    _ready(provider)
    original = key_path.read_bytes()
    _provision(key_path, b"w" * 32)

    with pytest.raises(SecretProviderError) as changed:
        provider.create_profile_key(BINDING)
    key_path.write_bytes(original)
    key_path.chmod(0o600)
    with pytest.raises(SecretProviderError) as restored:
        provider.create_profile_key(BINDING)

    assert changed.value.code is SecretFailureCode.RECOVERY_REQUIRED
    assert restored.value.code is SecretFailureCode.RECOVERY_REQUIRED


def test_source_status_observation_of_change_latches_recovery(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    _ready(provider)
    original = key_path.read_bytes()
    _provision(key_path, b"w" * 32)

    assert provider.source_status() is SourceStatus.READABLE
    key_path.write_bytes(original)
    key_path.chmod(0o600)
    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED
    key_path.unlink()
    assert provider.source_status() is SourceStatus.UNAVAILABLE


def test_second_live_provider_for_same_source_is_rejected(
    provider_paths: tuple[Path, Path],
) -> None:
    provider = _provider(provider_paths)

    with pytest.raises(SecretProviderError) as caught:
        _provider(provider_paths)

    assert provider.active_kek() == ACTIVE_KEK
    assert caught.value.code is SecretFailureCode.PROVIDER_ALREADY_ACTIVE


def test_same_aes_key_domain_rejects_concurrent_cross_installation_provider(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, managed_root = provider_paths
    provider = _provider(provider_paths)
    _ready(provider)

    other_key_directory = key_path.parent.parent / "other-keys"
    other_key_directory.mkdir(mode=0o700)
    other_key_path = other_key_directory / "installation.kek"
    material = _EXPECTED_KEY_MATERIAL[key_path]
    _EXPECTED_KEY_MATERIAL[other_key_path] = material
    _provision(other_key_path, material)
    other_managed = managed_root.parent / "other-managed"
    other_managed.mkdir(mode=0o700)
    other_kek = replace(
        ACTIVE_KEK,
        provider_instance_id=_id("20000000-0000-4000-8000-000000000041"),
    )
    other_installation = _id("20000000-0000-4000-8000-000000000042")
    other_catalog = _id("20000000-0000-4000-8000-000000000043")
    other_sentinel_id = _id("20000000-0000-4000-8000-000000000044")
    other = OwnerFileSecretProvider(
        key_path=other_key_path,
        active_kek=other_kek,
        installation_id=other_installation,
        catalog_id=other_catalog,
        sentinel_id=other_sentinel_id,
        readiness_sentinel=_sentinel(
            material,
            active_kek=other_kek,
            installation_id=other_installation,
            catalog_id=other_catalog,
            sentinel_id=other_sentinel_id,
            nonce=b"t" * 12,
        ),
        managed_roots=(other_managed,),
    )

    other_readiness = other.readiness()
    assert other_readiness.state is KeyReadinessState.RECOVERY_REQUIRED
    assert other_readiness.source_status is SourceStatus.READABLE
    with pytest.raises(SecretProviderError) as caught:
        other.create_profile_key(replace(BINDING, installation_id=other_installation))
    assert caught.value.code is SecretFailureCode.RECOVERY_REQUIRED

    monkeypatch.setattr(owner_file, "_os_nonce_bytes", lambda _length: b"t" * 12)
    with pytest.raises(SecretProviderError) as collision:
        provider.create_profile_key(BINDING)
    assert collision.value.code is SecretFailureCode.NONCE_REUSE


def test_distinct_authenticated_sentinel_record_reusing_nonce_latches_domain(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    material = _EXPECTED_KEY_MATERIAL[key_path]
    provider = _provider(provider_paths)
    _ready(provider)
    del provider
    gc.collect()

    replacement_sentinel_id = _id("20000000-0000-4000-8000-000000000045")
    replacement = _provider(
        provider_paths,
        sentinel_id=replacement_sentinel_id,
        readiness_sentinel=_sentinel(
            material,
            sentinel_id=replacement_sentinel_id,
            nonce=b"s" * 12,
        ),
    )

    readiness = replacement.readiness()
    assert readiness.state is KeyReadinessState.RECOVERY_REQUIRED
    assert readiness.source_status is SourceStatus.READABLE
    with pytest.raises(SecretProviderError) as caught:
        replacement.create_profile_key(BINDING)
    assert caught.value.code is SecretFailureCode.RECOVERY_REQUIRED


def test_nonce_accounting_survives_cross_installation_recomposition(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, managed_root = provider_paths
    provider = _provider(provider_paths)
    _ready(provider)
    monkeypatch.setattr(owner_file, "_os_nonce_bytes", lambda _length: b"z" * 12)
    provider.create_profile_key(BINDING)
    del provider
    gc.collect()

    other_key_directory = key_path.parent.parent / "other-keys"
    other_key_directory.mkdir(mode=0o700)
    other_key_path = other_key_directory / "installation.kek"
    material = _EXPECTED_KEY_MATERIAL[key_path]
    _EXPECTED_KEY_MATERIAL[other_key_path] = material
    _provision(other_key_path, material)
    other_managed = managed_root.parent / "other-managed"
    other_managed.mkdir(mode=0o700)
    other_installation = _id("20000000-0000-4000-8000-000000000052")
    other_sentinel_id = _id("20000000-0000-4000-8000-000000000054")
    other = OwnerFileSecretProvider(
        key_path=other_key_path,
        active_kek=ACTIVE_KEK,
        installation_id=other_installation,
        catalog_id=CATALOG_ID,
        sentinel_id=other_sentinel_id,
        readiness_sentinel=_sentinel(
            material,
            installation_id=other_installation,
            sentinel_id=other_sentinel_id,
            nonce=b"u" * 12,
        ),
        managed_roots=(other_managed,),
    )
    _ready(other)

    with pytest.raises(SecretProviderError) as caught:
        other.create_profile_key(replace(BINDING, installation_id=other_installation))
    assert caught.value.code is SecretFailureCode.NONCE_REUSE


def test_process_usage_cap_survives_provider_recomposition(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    nonces: Iterator[bytes] = iter((b"a" * 12, b"b" * 12))
    provider = _provider(provider_paths, process_wrap_limit=2)
    _ready(provider)
    monkeypatch.setattr(owner_file, "_os_nonce_bytes", lambda _length: next(nonces))

    assert provider.create_profile_key(BINDING).nonce == b"a" * 12
    assert provider.create_profile_key(BINDING).nonce == b"b" * 12
    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(BINDING)
    assert caught.value.code is SecretFailureCode.USAGE_LIMIT

    del caught
    del provider
    gc.collect()
    provider = _provider(provider_paths, process_wrap_limit=2)
    _ready(provider)
    with pytest.raises(SecretProviderError) as exhausted:
        provider.create_profile_key(BINDING)
    assert exhausted.value.code is SecretFailureCode.USAGE_LIMIT


def test_duplicate_nonce_latch_survives_provider_recomposition(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    repeated: Iterator[bytes] = iter((b"z" * 12, b"z" * 12, b"y" * 12))
    provider = _provider(provider_paths)
    _ready(provider)
    monkeypatch.setattr(owner_file, "_os_nonce_bytes", lambda _length: next(repeated))
    provider.create_profile_key(BINDING)
    with pytest.raises(SecretProviderError) as collision:
        provider.create_profile_key(BINDING)
    assert collision.value.code is SecretFailureCode.NONCE_REUSE
    del collision
    del provider
    gc.collect()

    provider = _provider(provider_paths)
    readiness = provider.readiness()
    assert readiness.state is KeyReadinessState.RECOVERY_REQUIRED
    assert readiness.source_status is SourceStatus.READABLE
    with pytest.raises(SecretProviderError) as latched:
        provider.create_profile_key(BINDING)
    assert latched.value.code is SecretFailureCode.RECOVERY_REQUIRED


def test_sentinel_nonce_is_reserved_from_profile_wraps(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    provider = _provider(provider_paths)
    _ready(provider)
    monkeypatch.setattr(owner_file, "_os_nonce_bytes", lambda _length: b"s" * 12)

    with pytest.raises(SecretProviderError) as collision:
        provider.create_profile_key(BINDING)
    with pytest.raises(SecretProviderError) as latched:
        provider.create_profile_key(BINDING)
    assert collision.value.code is SecretFailureCode.NONCE_REUSE
    assert latched.value.code is SecretFailureCode.NONCE_REUSE


@pytest.mark.parametrize("generated", [b"short", b"x" * 31, b"x" * 33, bytearray(b"x" * 32)])
def test_private_profile_entropy_wrapper_rejects_bad_results(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
    generated: object,
) -> None:
    from mycogni.adapters.keys import owner_file

    provider = _provider(provider_paths)
    _ready(provider)
    monkeypatch.setattr(owner_file, "_os_profile_key_bytes", lambda _length: generated)

    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(BINDING)
    assert caught.value.code is SecretFailureCode.UNAVAILABLE
    assert "787878" not in repr(caught.value)


def test_forked_child_fails_before_inherited_held_lock(
    provider_paths: tuple[Path, Path],
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("requires POSIX fork")
    provider = _provider(provider_paths)
    _ready(provider)
    read_fd, write_fd = os.pipe()
    provider._state_lock.acquire()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            provider.create_profile_key(BINDING)
        except SecretProviderError as error:
            os.write(write_fd, error.code.value.encode("ascii"))
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        readable, _, _ = select.select([read_fd], [], [], 2.0)
        assert readable, "forked child blocked on an inherited provider lock"
        assert os.read(read_fd, 128) == b"forked_process"
    finally:
        provider._state_lock.release()
        os.close(read_fd)
        os.waitpid(child, 0)


def test_forked_child_recomposition_fails_before_inherited_registry_lock(
    provider_paths: tuple[Path, Path],
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("requires POSIX fork")
    from mycogni.adapters.keys import owner_file

    read_fd, write_fd = os.pipe()
    owner_file._REGISTRY_LOCK.acquire()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            _provider(provider_paths)
        except SecretProviderError as error:
            os.write(write_fd, error.code.value.encode("ascii"))
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        readable, _, _ = select.select([read_fd], [], [], 2.0)
        assert readable, "forked child blocked on the inherited registry lock"
        assert os.read(read_fd, 128) == b"forked_process"
    finally:
        owner_file._REGISTRY_LOCK.release()
        os.close(read_fd)
        os.waitpid(child, 0)


@pytest.mark.parametrize("mode", [0o000, 0o200, 0o440, 0o644, 0o700])
def test_key_file_rejects_every_non_owner_only_mode(
    provider_paths: tuple[Path, Path],
    mode: int,
) -> None:
    key_path, _managed_root = provider_paths
    key_path.chmod(mode)
    assert _provider(provider_paths).source_status() is SourceStatus.UNSAFE


def test_mode_0400_is_accepted(provider_paths: tuple[Path, Path]) -> None:
    key_path, _managed_root = provider_paths
    key_path.chmod(0o400)
    assert _provider(provider_paths).source_status() is SourceStatus.READABLE


def test_hardlink_symlink_fifo_and_wrong_owner_are_rejected(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    os.link(key_path, key_path.parent / "alias.kek")
    assert _provider(provider_paths).source_status() is SourceStatus.UNSAFE
    (key_path.parent / "alias.kek").unlink()

    target = key_path.parent / "target.kek"
    key_path.rename(target)
    key_path.symlink_to(target)
    assert _provider(provider_paths).source_status() is SourceStatus.UNSAFE
    key_path.unlink()
    target.unlink()
    os.mkfifo(key_path, mode=0o600)
    assert _provider(provider_paths).source_status() is SourceStatus.UNSAFE

    values = list(os.stat(__file__))
    values[0] = stat.S_IFREG | 0o600
    values[4] = os.geteuid() + 1
    values[3] = 1
    values[6] = len(OWNER_KEY_FILE_HEADER) + 32
    with pytest.raises(SecretProviderError) as caught:
        owner_file.OwnerFileSecretProvider._validate_file(os.stat_result(values))
    assert caught.value.code is SecretFailureCode.UNSAFE_STORAGE


def test_symlink_and_world_writable_ancestors_are_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    key_path = actual / "key.kek"
    _provision(key_path)
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    managed = tmp_path / "managed"
    managed.mkdir(mode=0o700)
    provider = _provider((linked / "key.kek", managed))
    assert provider.source_status() is SourceStatus.UNSAFE
    del provider
    gc.collect()

    linked.unlink()
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o700)
    directory = unsafe / "keys"
    directory.mkdir(mode=0o700)
    unsafe_key = directory / "key.kek"
    _provision(unsafe_key)
    unsafe.chmod(0o777)
    assert _provider((unsafe_key, managed)).source_status() is SourceStatus.UNSAFE


@pytest.mark.parametrize("managed_relative", ["keys", "keys/child", "."])
def test_key_and_managed_roots_must_be_lexically_disjoint(
    tmp_path: Path,
    managed_relative: str,
) -> None:
    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    key_path = key_directory / "key.kek"
    _provision(key_path)

    with pytest.raises(SecretProviderError) as caught:
        _provider((key_path, tmp_path / managed_relative))
    assert caught.value.code is SecretFailureCode.UNSAFE_STORAGE


def test_directory_rename_and_replacement_during_aead_returns_no_ciphertext(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    _ready(provider)

    class MutatingCipher:
        def __init__(self, _key: object) -> None:
            pass

        def encrypt(self, _nonce: bytes, _data: object, _aad: bytes) -> bytes:
            moved = key_path.parent.with_name("moved-keys")
            key_path.parent.rename(moved)
            key_path.parent.mkdir(mode=0o700)
            _provision(key_path)
            return b"c" * 48

    monkeypatch.setattr(owner_file, "AESGCM", MutatingCipher)
    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(BINDING)
    assert caught.value.code is SecretFailureCode.UNSAFE_STORAGE
    assert provider.readiness().state is KeyReadinessState.RECOVERY_REQUIRED


def test_routine_operations_do_not_mutate_key_source(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    before = key_path.read_bytes()
    before_stat = key_path.stat()
    _ready(provider)
    wrapped = provider.create_profile_key(BINDING)
    _extract(provider.unwrap_profile_key(wrapped, BINDING))
    after_stat = key_path.stat()

    assert key_path.read_bytes() == before
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert after_stat.st_ctime_ns == before_stat.st_ctime_ns
    assert stat.S_IMODE(after_stat.st_mode) == stat.S_IMODE(before_stat.st_mode)


def test_post_use_fstat_and_close_failures_are_typed_and_redacted(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    real_fstat = owner_file.os.fstat
    calls = 0

    def fail_late(descriptor: int) -> os.stat_result:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError(f"fstat-canary:{key_path}")
        return real_fstat(descriptor)

    monkeypatch.setattr(owner_file.os, "fstat", fail_late)
    assert provider.source_status() is SourceStatus.UNAVAILABLE
    monkeypatch.setattr(owner_file.os, "fstat", real_fstat)
    real_close = owner_file.os.close

    close_failed = False

    def fail_close_once(descriptor: int) -> None:
        nonlocal close_failed
        if not close_failed:
            close_failed = True
            raise OSError("close-canary")
        real_close(descriptor)

    monkeypatch.setattr(owner_file.os, "close", fail_close_once)
    assert provider.source_status() is SourceStatus.UNAVAILABLE


def test_private_paths_and_backend_errors_never_render(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    real_open = owner_file.os.open

    def fail_open(path: object, *args: object, **kwargs: object) -> int:
        if path == key_path.name:
            raise OSError(f"synthetic backend canary at {key_path}")
        return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(owner_file.os, "open", fail_open)
    assert provider.source_status() is SourceStatus.UNAVAILABLE
    rendered = repr(provider)
    assert key_path.name not in rendered
    assert str(key_path.parent) not in rendered
    assert "backend canary" not in rendered
