"""Explicit empty-install sentinel creation for an existing owner-only KEK.

This administration boundary is deliberately narrower than provisioning: it
never creates, replaces, repairs, chmods, deletes, discovers, or persists the
key source.  The caller must first durably reserve the exact sentinel nonce and
pin the catalog identity in its separate catalog transaction.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import stat
import struct
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mycogni.adapters.keys.owner_file import (
    OWNER_FILE_PROVIDER_KIND,
    OWNER_KEY_FILE_BYTES,
    OWNER_KEY_FILE_HEADER,
)
from mycogni.application.key_catalog import KeyCatalogIdentity
from mycogni.application.keys import (
    WRAP_NONCE_BYTES,
    SecretFailureCode,
    SecretProviderError,
    WrappedReadinessSentinel,
)

_READINESS_PLAINTEXT = b"MyCogni-readiness-sentinel-v1!!!"
_SENTINEL_AAD_PREFIX = b"MyCogni\x00readiness-sentinel\x00"
_PROVIDER_KIND_ID = 1
_SUITE_ID = 1
_PROCESS_PID = os.getpid()
_SOURCE_COMMITMENT_PREFIX = b"MyCogni\x00owner-file-source-commitment\x00"


def _fail(code: SecretFailureCode) -> NoReturn:
    raise SecretProviderError(code) from None


def _absolute(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("owner-file administration paths must be pathlib.Path values")
    return Path(os.path.abspath(os.fspath(path)))


def _within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class _SourceIdentity:
    parent_device: int
    parent_inode: int
    file_device: int
    file_inode: int
    file_mode: int
    file_uid: int
    file_gid: int
    file_links: int
    file_size: int
    modified_ns: int
    changed_ns: int
    material_digest: bytes


def _validate_directory(metadata: os.stat_result, *, final_parent: bool) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o022
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        _fail(SecretFailureCode.UNSAFE_STORAGE)
    if final_parent and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
        _fail(SecretFailureCode.UNSAFE_STORAGE)


def _validate_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
        or metadata.st_nlink != 1
    ):
        _fail(SecretFailureCode.UNSAFE_STORAGE)
    if metadata.st_size != OWNER_KEY_FILE_BYTES:
        _fail(SecretFailureCode.MALFORMED_RECORD)


def _open_private_parent(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(path.anchor, flags)
        parts = path.parent.parts[1:]
        metadata = os.fstat(descriptor)
        _validate_directory(metadata, final_parent=not parts)
        for index, part in enumerate(parts):
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            _validate_directory(metadata, final_parent=index == len(parts) - 1)
        return descriptor, os.fstat(descriptor)
    except SecretProviderError:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        raise
    except FileNotFoundError:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        _fail(SecretFailureCode.UNAVAILABLE)
    except OSError as error:
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            _fail(SecretFailureCode.UNSAFE_STORAGE)
        _fail(SecretFailureCode.UNAVAILABLE)


def _read_existing_source(path: Path) -> tuple[bytearray, _SourceIdentity]:
    parent, parent_metadata = _open_private_parent(path)
    descriptor = -1
    payload = bytearray(OWNER_KEY_FILE_BYTES)
    try:
        try:
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            _validate_file(named)
            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            descriptor = os.open(path.name, flags, dir_fd=parent)
            opened = os.fstat(descriptor)
            _validate_file(opened)
        except FileNotFoundError:
            _fail(SecretFailureCode.UNAVAILABLE)
        except OSError as error:
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                _fail(SecretFailureCode.UNSAFE_STORAGE)
            _fail(SecretFailureCode.UNAVAILABLE)

        def comparable(value: os.stat_result) -> tuple[int, ...]:
            return (
                value.st_dev,
                value.st_ino,
                value.st_mode,
                value.st_uid,
                value.st_gid,
                value.st_nlink,
                value.st_size,
                value.st_mtime_ns,
                value.st_ctime_ns,
            )

        if comparable(named) != comparable(opened):
            _fail(SecretFailureCode.UNSAFE_STORAGE)
        offset = 0
        while offset < len(payload):
            try:
                count = os.readv(descriptor, [memoryview(payload)[offset:]])
            except OSError:
                _fail(SecretFailureCode.UNAVAILABLE)
            if count <= 0:
                _fail(SecretFailureCode.MALFORMED_RECORD)
            offset += count
        after = os.fstat(descriptor)
        if comparable(opened) != comparable(after):
            _fail(SecretFailureCode.UNSAFE_STORAGE)
        if payload[: len(OWNER_KEY_FILE_HEADER)] != OWNER_KEY_FILE_HEADER:
            _fail(SecretFailureCode.MALFORMED_RECORD)
        material = bytearray(payload[len(OWNER_KEY_FILE_HEADER) :])
        return material, _SourceIdentity(
            parent_device=parent_metadata.st_dev,
            parent_inode=parent_metadata.st_ino,
            file_device=after.st_dev,
            file_inode=after.st_ino,
            file_mode=after.st_mode,
            file_uid=after.st_uid,
            file_gid=after.st_gid,
            file_links=after.st_nlink,
            file_size=after.st_size,
            modified_ns=after.st_mtime_ns,
            changed_ns=after.st_ctime_ns,
            material_digest=hashlib.sha256(_SOURCE_COMMITMENT_PREFIX + material).digest(),
        )
    finally:
        payload[:] = b"\x00" * len(payload)
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        with suppress(OSError):
            os.close(parent)


def _sentinel_aad(identity: KeyCatalogIdentity) -> bytes:
    active_kek = identity.active_kek
    return b"".join(
        (
            _SENTINEL_AAD_PREFIX,
            struct.pack(">H", 1),
            struct.pack(">H", 1),
            identity.installation_id.value.bytes,
            identity.catalog_id.value.bytes,
            identity.sentinel_id.value.bytes,
            struct.pack(">B", _PROVIDER_KIND_ID),
            active_kek.provider_instance_id.value.bytes,
            active_kek.kek_id.value.bytes,
            struct.pack(">I", active_kek.kek_version),
            struct.pack(">B", _SUITE_ID),
        )
    )


def create_readiness_sentinel(
    *,
    key_path: Path,
    identity: KeyCatalogIdentity,
    reserved_nonce: bytes,
    expected_source_commitment: bytes,
    managed_roots: tuple[Path, ...],
) -> WrappedReadinessSentinel:
    """Wrap the readiness sentinel using an existing, never-mutated owner file."""
    if os.getpid() != _PROCESS_PID:
        _fail(SecretFailureCode.FORKED_PROCESS)
    if type(identity) is not KeyCatalogIdentity:
        raise TypeError("sentinel administration requires a pinned catalog identity")
    if identity.active_kek.provider_kind != OWNER_FILE_PROVIDER_KIND:
        raise ValueError("sentinel administration requires the owner-file provider")
    if type(reserved_nonce) is not bytes:
        raise TypeError("reserved sentinel nonce must be bytes")
    if len(reserved_nonce) != WRAP_NONCE_BYTES:
        raise ValueError("reserved sentinel nonce must be exactly 12 bytes")
    if type(expected_source_commitment) is not bytes or len(expected_source_commitment) != 32:
        raise TypeError("expected source commitment must be exactly 32 bytes")
    if type(managed_roots) is not tuple or not managed_roots:
        raise TypeError("managed roots must be a non-empty tuple")
    path = _absolute(key_path)
    roots = tuple(_absolute(root) for root in managed_roots)
    key_directory = path.parent
    if any(_within(key_directory, root) or _within(root, key_directory) for root in roots):
        _fail(SecretFailureCode.UNSAFE_STORAGE)

    material, before = _read_existing_source(path)
    if not hmac.compare_digest(before.material_digest, expected_source_commitment):
        material[:] = b"\x00" * len(material)
        _fail(SecretFailureCode.CATALOG_KEY_MISMATCH)
    ciphertext = b""
    try:
        try:
            ciphertext = AESGCM(material).encrypt(
                reserved_nonce,
                _READINESS_PLAINTEXT,
                _sentinel_aad(identity),
            )
        except Exception:
            _fail(SecretFailureCode.UNAVAILABLE)
        if type(ciphertext) is not bytes or len(ciphertext) != 48:
            _fail(SecretFailureCode.UNAVAILABLE)
    finally:
        material[:] = b"\x00" * len(material)

    after_material, after = _read_existing_source(path)
    after_material[:] = b"\x00" * len(after_material)
    if before != after:
        _fail(SecretFailureCode.UNSAFE_STORAGE)
    return WrappedReadinessSentinel(
        kek_ref=identity.active_kek,
        installation_id=identity.installation_id,
        catalog_id=identity.catalog_id,
        sentinel_id=identity.sentinel_id,
        nonce=reserved_nonce,
        ciphertext=ciphertext,
    )


def read_source_commitment(
    *,
    key_path: Path,
    managed_roots: tuple[Path, ...],
) -> bytes:
    """Return a domain-separated commitment for explicit initialization only."""
    if os.getpid() != _PROCESS_PID:
        _fail(SecretFailureCode.FORKED_PROCESS)
    if type(managed_roots) is not tuple or not managed_roots:
        raise TypeError("managed roots must be a non-empty tuple")
    path = _absolute(key_path)
    roots = tuple(_absolute(root) for root in managed_roots)
    key_directory = path.parent
    if any(_within(key_directory, root) or _within(root, key_directory) for root in roots):
        _fail(SecretFailureCode.UNSAFE_STORAGE)
    material, identity = _read_existing_source(path)
    material[:] = b"\x00" * len(material)
    return identity.material_digest


__all__ = ("create_readiness_sentinel", "read_source_commitment")
