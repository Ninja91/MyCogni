"""Adversarial evidence for the pre-provisioned owner-only KEK provider."""

from __future__ import annotations

import os
import stat
import struct
import traceback
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from mycogni.adapters.keys.owner_file import (
    OWNER_KEY_FILE_HEADER,
    OwnerFileSecretProvider,
)
from mycogni.application.keys import (
    ActiveKekRef,
    ProfileKeyContext,
    SecretFailureCode,
    SecretProviderError,
    SecretProviderStatus,
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
CONTEXT = ProfileKeyContext(
    installation_id=_id("20000000-0000-4000-8000-000000000003"),
    profile_id=_id("20000000-0000-4000-8000-000000000004"),
    profile_key_version=1,
    catalog_schema_version=1,
)


def _provision(path: Path, material: bytes = b"k" * 32, *, mode: int = 0o600) -> None:
    path.write_bytes(OWNER_KEY_FILE_HEADER + material)
    path.chmod(mode)


@pytest.fixture
def provider_paths(tmp_path: Path) -> tuple[Path, Path]:
    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    key_path = key_directory / "installation.kek"
    _provision(key_path)
    managed_root = tmp_path / "managed-data"
    managed_root.mkdir(mode=0o700)
    return key_path, managed_root


def _provider(
    paths: tuple[Path, Path],
    **changes: object,
) -> OwnerFileSecretProvider:
    key_path, managed_root = paths
    arguments: dict[str, object] = {
        "key_path": key_path,
        "active_kek": ACTIVE_KEK,
        "managed_roots": (managed_root,),
    }
    arguments.update(changes)
    return OwnerFileSecretProvider(**arguments)  # type: ignore[arg-type]


def _extract(handle: object) -> bytes:
    with handle as active:  # type: ignore[attr-defined]
        return active.use(bytes)


def test_exact_round_trip_and_readiness_are_provider_neutral(
    provider_paths: tuple[Path, Path],
) -> None:
    provider = _provider(provider_paths, nonce_source=lambda length: b"n" * length)

    assert isinstance(provider, SecretPort)
    assert provider.active_kek() == ACTIVE_KEK
    assert provider.status() is SecretProviderStatus.READY
    wrapped = provider.create_profile_key(CONTEXT)
    plaintext = _extract(provider.unwrap_profile_key(wrapped, CONTEXT))

    assert len(plaintext) == 32
    assert wrapped.nonce == b"n" * 12
    assert len(wrapped.ciphertext) == 48
    assert provider.check_readiness(wrapped, CONTEXT) is SecretProviderStatus.READY


def test_aad_v1_exact_binary_vector(provider_paths: tuple[Path, Path]) -> None:
    provider = _provider(provider_paths)
    expected = b"".join(
        (
            b"MyCogni\x00profile-dek-wrap\x00",
            struct.pack(">H", 1),
            CONTEXT.installation_id.value.bytes,
            CONTEXT.profile_id.value.bytes,
            struct.pack(">I", CONTEXT.profile_key_version),
            struct.pack(">H", CONTEXT.catalog_schema_version),
            b"\x01",
            ACTIVE_KEK.provider_instance_id.value.bytes,
            ACTIVE_KEK.kek_id.value.bytes,
            struct.pack(">I", ACTIVE_KEK.kek_version),
            b"\x01",
        )
    )

    assert provider._aad(CONTEXT) == expected


def test_deterministic_aes_gcm_wrap_vector_covers_key_dek_nonce_aad_and_tag(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    key = bytes(range(32))
    profile_dek = bytes(range(32, 64))
    nonce = bytes(range(12))
    expected_aad = bytes.fromhex(
        "4d79436f676e690070726f66696c652d64656b2d77726170000001"
        "2000000000004000800000000000000320000000000040008000000000000004"
        "00000001000101"
        "20000000000040008000000000000001"
        "20000000000040008000000000000002"
        "0000000101"
    )
    expected_ciphertext_and_tag = bytes.fromhex(
        "6723f438e1c0e43ca568bda09dc45642b3e7b507c44e694b005edfbe21543e8d"
        "81ea5c5582547f06f4598b18911a24bb"
    )
    _provision(key_path, key)
    provider = _provider(
        provider_paths,
        nonce_source=lambda length: nonce if length == 12 else b"",
        _profile_key_source=lambda length: profile_dek if length == 32 else b"",
    )

    wrapped = provider.create_profile_key(CONTEXT)

    assert key_path.read_bytes() == OWNER_KEY_FILE_HEADER + key
    assert provider._aad(CONTEXT) == expected_aad
    assert wrapped.nonce == nonce
    assert wrapped.ciphertext == expected_ciphertext_and_tag
    assert _extract(provider.unwrap_profile_key(wrapped, CONTEXT)) == profile_dek


@pytest.mark.parametrize(
    "generated",
    [b"short", b"x" * 31, b"x" * 33, bytearray(b"x" * 32)],
)
def test_profile_key_entropy_seam_rejects_wrong_type_or_length_without_disclosure(
    provider_paths: tuple[Path, Path],
    generated: object,
) -> None:
    provider = _provider(
        provider_paths,
        _profile_key_source=lambda _length: generated,
    )

    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(CONTEXT)

    assert caught.value.code is SecretFailureCode.UNAVAILABLE
    assert "short" not in str(caught.value)
    assert "787878" not in repr(caught.value)


def test_profile_key_entropy_backend_error_is_redacted(
    provider_paths: tuple[Path, Path],
) -> None:
    def fail_entropy(_length: int) -> bytes:
        raise OSError("synthetic-profile-dek-entropy-canary")

    provider = _provider(provider_paths, _profile_key_source=fail_entropy)

    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(CONTEXT)

    assert caught.value.code is SecretFailureCode.UNAVAILABLE
    assert "canary" not in str(caught.value)


@pytest.mark.parametrize(
    "context",
    [
        replace(
            CONTEXT,
            installation_id=_id("20000000-0000-4000-8000-000000000011"),
        ),
        replace(CONTEXT, profile_id=_id("20000000-0000-4000-8000-000000000012")),
        replace(CONTEXT, profile_key_version=2),
        replace(CONTEXT, catalog_schema_version=2),
    ],
)
def test_every_context_binding_substitution_fails_closed(
    provider_paths: tuple[Path, Path],
    context: ProfileKeyContext,
) -> None:
    provider = _provider(provider_paths)
    wrapped = provider.create_profile_key(CONTEXT)

    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(wrapped, context)

    assert caught.value.code in {
        SecretFailureCode.PROVIDER_MISMATCH,
        SecretFailureCode.AUTHENTICATION_FAILED,
    }


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
def test_every_provider_binding_substitution_fails_closed(
    provider_paths: tuple[Path, Path],
    kek_ref: ActiveKekRef,
) -> None:
    provider = _provider(provider_paths)
    wrapped = provider.create_profile_key(CONTEXT)
    substituted = replace(wrapped, kek_ref=kek_ref)

    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(substituted, CONTEXT)

    assert caught.value.code is SecretFailureCode.PROVIDER_MISMATCH


def test_ciphertext_or_tag_mutation_is_wrong_key_not_success(
    provider_paths: tuple[Path, Path],
) -> None:
    provider = _provider(provider_paths)
    wrapped = provider.create_profile_key(CONTEXT)
    mutated = replace(
        wrapped,
        ciphertext=bytes([wrapped.ciphertext[0] ^ 1]) + wrapped.ciphertext[1:],
    )

    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(mutated, CONTEXT)

    assert caught.value.code is SecretFailureCode.AUTHENTICATION_FAILED


def test_wrong_preprovisioned_key_is_detected_by_catalog_sentinel(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    sentinel = provider.create_profile_key(CONTEXT)
    _provision(key_path, b"w" * 32)

    assert provider.status() is SecretProviderStatus.READY
    assert provider.check_readiness(sentinel, CONTEXT) is SecretProviderStatus.WRONG_KEY


def test_missing_provider_never_provisions_or_falls_back(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    key_path.unlink()
    provider = _provider(provider_paths)

    assert provider.status() is SecretProviderStatus.UNPROVISIONED
    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(CONTEXT)
    assert caught.value.code is SecretFailureCode.UNPROVISIONED
    assert not key_path.exists()


@pytest.mark.parametrize("payload", [b"", b"bad", OWNER_KEY_FILE_HEADER + b"x" * 31])
def test_corrupt_or_truncated_key_file_requires_recovery(
    provider_paths: tuple[Path, Path],
    payload: bytes,
) -> None:
    key_path, _managed_root = provider_paths
    key_path.write_bytes(payload)
    key_path.chmod(0o600)

    assert _provider(provider_paths).status() is SecretProviderStatus.RECOVERY_REQUIRED


def test_unknown_file_format_requires_recovery(provider_paths: tuple[Path, Path]) -> None:
    key_path, _managed_root = provider_paths
    key_path.write_bytes(b"X" * len(OWNER_KEY_FILE_HEADER) + b"k" * 32)
    key_path.chmod(0o600)

    assert _provider(provider_paths).status() is SecretProviderStatus.RECOVERY_REQUIRED


def test_deterministic_nonce_seam_and_process_usage_cap(
    provider_paths: tuple[Path, Path],
) -> None:
    nonces = iter((b"a" * 12, b"b" * 12))
    provider = _provider(
        provider_paths,
        process_wrap_limit=2,
        nonce_source=lambda _length: next(nonces),
    )

    assert provider.create_profile_key(CONTEXT).nonce == b"a" * 12
    assert provider.create_profile_key(CONTEXT).nonce == b"b" * 12
    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(CONTEXT)
    assert caught.value.code is SecretFailureCode.USAGE_LIMIT


def test_duplicate_nonce_latches_all_future_wraps(provider_paths: tuple[Path, Path]) -> None:
    nonces: Iterator[bytes] = iter((b"a" * 12, b"a" * 12, b"b" * 12))
    provider = _provider(provider_paths, nonce_source=lambda _length: next(nonces))
    provider.create_profile_key(CONTEXT)

    with pytest.raises(SecretProviderError) as collision:
        provider.create_profile_key(CONTEXT)
    with pytest.raises(SecretProviderError) as latched:
        provider.create_profile_key(CONTEXT)

    assert collision.value.code is SecretFailureCode.NONCE_REUSE
    assert latched.value.code is SecretFailureCode.NONCE_REUSE


def test_forked_child_must_recompose_provider(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    provider = _provider(provider_paths)
    current_pid = os.getpid()
    monkeypatch.setattr(owner_file.os, "getpid", lambda: current_pid + 1)

    with pytest.raises(SecretProviderError) as caught:
        provider.active_kek()
    assert caught.value.code is SecretFailureCode.FORKED_PROCESS


@pytest.mark.parametrize("mode", [0o000, 0o200, 0o400 | 0o040, 0o644, 0o700])
def test_key_file_rejects_every_non_owner_only_mode(
    provider_paths: tuple[Path, Path],
    mode: int,
) -> None:
    key_path, _managed_root = provider_paths
    key_path.chmod(mode)

    assert _provider(provider_paths).status() is SecretProviderStatus.UNSAFE


def test_mode_0400_is_accepted(provider_paths: tuple[Path, Path]) -> None:
    key_path, _managed_root = provider_paths
    key_path.chmod(0o400)

    assert _provider(provider_paths).status() is SecretProviderStatus.READY


def test_hardlinked_key_is_rejected(provider_paths: tuple[Path, Path]) -> None:
    key_path, _managed_root = provider_paths
    os.link(key_path, key_path.parent / "alias.kek")

    assert _provider(provider_paths).status() is SecretProviderStatus.UNSAFE


def test_symlink_key_is_rejected(provider_paths: tuple[Path, Path]) -> None:
    key_path, _managed_root = provider_paths
    target = key_path.parent / "target.kek"
    key_path.rename(target)
    key_path.symlink_to(target)

    assert _provider(provider_paths).status() is SecretProviderStatus.UNSAFE


def test_fifo_key_is_rejected_without_blocking(provider_paths: tuple[Path, Path]) -> None:
    key_path, _managed_root = provider_paths
    key_path.unlink()
    os.mkfifo(key_path, mode=0o600)

    assert _provider(provider_paths).status() is SecretProviderStatus.UNSAFE


def test_symlinked_key_directory_ancestor_is_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir(mode=0o700)
    key_path = actual / "key.kek"
    _provision(key_path)
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    managed = tmp_path / "managed"
    managed.mkdir(mode=0o700)
    provider = OwnerFileSecretProvider(
        key_path=linked / "key.kek",
        active_kek=ACTIVE_KEK,
        managed_roots=(managed,),
    )

    assert provider.status() is SecretProviderStatus.UNSAFE


def test_world_writable_key_ancestor_is_rejected(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o700)
    key_directory = unsafe / "keys"
    key_directory.mkdir(mode=0o700)
    key_path = key_directory / "key.kek"
    _provision(key_path)
    unsafe.chmod(0o777)
    managed = tmp_path / "managed"
    managed.mkdir(mode=0o700)
    provider = OwnerFileSecretProvider(
        key_path=key_path,
        active_kek=ACTIVE_KEK,
        managed_roots=(managed,),
    )

    assert provider.status() is SecretProviderStatus.UNSAFE


@pytest.mark.parametrize("managed_relative", ["keys", "keys/child", "."])
def test_key_and_managed_roots_must_be_disjoint_in_both_directions(
    tmp_path: Path,
    managed_relative: str,
) -> None:
    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    key_path = key_directory / "key.kek"
    _provision(key_path)
    managed = tmp_path / managed_relative

    with pytest.raises(SecretProviderError) as caught:
        OwnerFileSecretProvider(
            key_path=key_path,
            active_kek=ACTIVE_KEK,
            managed_roots=(managed,),
        )

    assert caught.value.code is SecretFailureCode.UNSAFE_STORAGE


def test_symlinked_managed_root_is_rejected(provider_paths: tuple[Path, Path]) -> None:
    key_path, managed_root = provider_paths
    target = managed_root.parent / "actual-managed"
    managed_root.rename(target)
    managed_root.symlink_to(target, target_is_directory=True)
    provider = OwnerFileSecretProvider(
        key_path=key_path,
        active_kek=ACTIVE_KEK,
        managed_roots=(managed_root,),
    )

    assert provider.status() is SecretProviderStatus.UNSAFE


def test_wrong_owner_metadata_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    from mycogni.adapters.keys import owner_file

    metadata_values = list(os.stat(__file__))
    metadata_values[0] = stat.S_IFREG | 0o600
    metadata_values[4] = os.geteuid() + 1
    metadata_values[3] = 1
    metadata_values[6] = len(OWNER_KEY_FILE_HEADER) + 32
    metadata = os.stat_result(metadata_values)

    with pytest.raises(SecretProviderError) as caught:
        owner_file.OwnerFileSecretProvider._validate_key_metadata(metadata)
    assert caught.value.code is SecretFailureCode.UNSAFE_STORAGE


def test_routine_operations_do_not_mutate_key_source(
    provider_paths: tuple[Path, Path],
) -> None:
    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    before = key_path.read_bytes()
    before_stat = key_path.stat()
    wrapped = provider.create_profile_key(CONTEXT)
    _extract(provider.unwrap_profile_key(wrapped, CONTEXT))
    after_stat = key_path.stat()

    assert key_path.read_bytes() == before
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns
    assert after_stat.st_ctime_ns == before_stat.st_ctime_ns
    assert stat.S_IMODE(after_stat.st_mode) == stat.S_IMODE(before_stat.st_mode)


def test_path_identity_is_revalidated_after_the_aead_operation(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths

    class MutatingCipher:
        def __init__(self, _key: object) -> None:
            pass

        def encrypt(self, _nonce: bytes, _data: object, _aad: bytes) -> bytes:
            _provision(key_path, b"z" * 32)
            return b"c" * 48

    monkeypatch.setattr(owner_file, "AESGCM", MutatingCipher)

    with pytest.raises(SecretProviderError) as caught:
        _provider(provider_paths).create_profile_key(CONTEXT)
    assert caught.value.code is SecretFailureCode.UNSAFE_STORAGE


def test_unwrap_preserves_typed_path_revalidation_failure(
    provider_paths: tuple[Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.keys import owner_file

    key_path, _managed_root = provider_paths
    provider = _provider(provider_paths)
    wrapped = provider.create_profile_key(CONTEXT)

    class MutatingCipher:
        def __init__(self, _key: object) -> None:
            pass

        def decrypt(self, _nonce: bytes, _data: bytes, _aad: bytes) -> bytes:
            _provision(key_path, b"z" * 32)
            return b"p" * 32

    monkeypatch.setattr(owner_file, "AESGCM", MutatingCipher)

    with pytest.raises(SecretProviderError) as caught:
        provider.unwrap_profile_key(wrapped, CONTEXT)
    assert caught.value.code is SecretFailureCode.UNSAFE_STORAGE
    assert caught.value.operator_status is SecretProviderStatus.UNSAFE


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
    with pytest.raises(SecretProviderError) as caught:
        provider.create_profile_key(CONTEXT)

    rendered = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
    )
    assert key_path.name not in rendered
    assert str(key_path.parent) not in rendered
    assert "backend canary" not in rendered
    assert "installation.kek" not in repr(provider)
