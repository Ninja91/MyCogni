"""Fail-closed owner-only file provider for a pre-provisioned local KEK.

This adapter never creates, replaces, repairs, discovers, migrates, or exports
the key file.  Provisioning is an external, explicit installation ceremony.
"""

from __future__ import annotations

import errno
import os
import stat
import struct
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NoReturn

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mycogni.application.keys import (
    PROFILE_DEK_BYTES,
    WRAP_NONCE_BYTES,
    ActiveKekRef,
    ProfileDekHandle,
    ProfileKeyContext,
    SecretFailureCode,
    SecretProviderError,
    SecretProviderStatus,
    WrappedProfileKey,
)

OWNER_FILE_PROVIDER_KIND = "owner-file"
OWNER_KEY_FILE_HEADER = b"MYCOGNI-OWNER-KEK\x00\x01"
OWNER_KEY_FILE_BYTES = len(OWNER_KEY_FILE_HEADER) + PROFILE_DEK_BYTES
DEFAULT_PROCESS_WRAP_LIMIT = 100_000
_AAD_PREFIX = b"MyCogni\x00profile-dek-wrap\x00"
_PROVIDER_KIND_ID = 1
_SUITE_ID = 1


def _fail(code: SecretFailureCode) -> NoReturn:
    raise SecretProviderError(code) from None


def _canonical_absolute(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("secret provider paths must be pathlib.Path values")
    return Path(os.path.abspath(os.fspath(path)))


def _is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _same_stable_file(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        _same_identity(left, right)
        and left.st_mode == right.st_mode
        and left.st_uid == right.st_uid
        and left.st_gid == right.st_gid
        and left.st_nlink == right.st_nlink
        and left.st_size == right.st_size
        and left.st_mtime_ns == right.st_mtime_ns
        and left.st_ctime_ns == right.st_ctime_ns
    )


class OwnerFileSecretProvider:
    """Use one explicitly configured, pre-provisioned owner-only KEK file."""

    def __init__(
        self,
        *,
        key_path: Path,
        active_kek: ActiveKekRef,
        managed_roots: Iterable[Path],
        process_wrap_limit: int = DEFAULT_PROCESS_WRAP_LIMIT,
        nonce_source: Callable[[int], bytes] | None = None,
        _profile_key_source: Callable[[int], bytes] | None = None,
    ) -> None:
        if type(active_kek) is not ActiveKekRef:
            raise TypeError("owner-file provider requires an active KEK reference")
        if active_kek.provider_kind != OWNER_FILE_PROVIDER_KIND:
            raise ValueError("active KEK reference has the wrong provider kind")
        if type(process_wrap_limit) is not int:
            raise TypeError("process wrap limit must be an integer")
        if not 1 <= process_wrap_limit <= DEFAULT_PROCESS_WRAP_LIMIT:
            raise ValueError("process wrap limit is outside the supported range")
        if nonce_source is not None and not callable(nonce_source):
            raise TypeError("nonce source must be callable")
        if _profile_key_source is not None and not callable(_profile_key_source):
            raise TypeError("profile key source must be callable")

        self._key_path = _canonical_absolute(key_path)
        self._active_kek = active_kek
        self._managed_roots = tuple(_canonical_absolute(root) for root in managed_roots)
        if not self._managed_roots:
            raise ValueError("at least one managed data/evidence/archive root is required")
        self._assert_structural_separation()

        self._pid = os.getpid()
        self._handle_issuer = object()
        self._process_wrap_limit = process_wrap_limit
        self._nonce_source = nonce_source if nonce_source is not None else os.urandom
        self._profile_key_source = (
            _profile_key_source if _profile_key_source is not None else os.urandom
        )
        self._wrap_count = 0
        self._used_nonces: set[bytes] = set()
        self._nonce_reuse_latched = False
        self._wrap_lock = threading.Lock()

    def __repr__(self) -> str:
        return "OwnerFileSecretProvider(key_path=[REDACTED], active_kek=[REDACTED])"

    def active_kek(self) -> ActiveKekRef:
        """Return stable non-secret key identity after the fork guard."""
        self._assert_process()
        return self._active_kek

    def status(self) -> SecretProviderStatus:
        """Inspect the configured source without creating or changing state."""
        try:
            with self._open_key_material():
                pass
        except SecretProviderError as error:
            return error.operator_status
        return SecretProviderStatus.READY

    def create_profile_key(self, context: ProfileKeyContext) -> WrappedProfileKey:
        """Create and wrap one independent random 32-byte profile DEK."""
        self._assert_context(context)
        try:
            generated_material = self._profile_key_source(PROFILE_DEK_BYTES)
        except Exception:
            _fail(SecretFailureCode.UNAVAILABLE)
        if type(generated_material) is not bytes or len(generated_material) != PROFILE_DEK_BYTES:
            _fail(SecretFailureCode.UNAVAILABLE)
        profile_material = bytearray(generated_material)
        nonce = b""
        try:
            nonce = self._reserve_nonce()
            with self._open_key_material() as key_material:
                cipher = AESGCM(key_material)
                ciphertext = cipher.encrypt(nonce, profile_material, self._aad(context))
        except SecretProviderError:
            raise
        except Exception:
            _fail(SecretFailureCode.UNAVAILABLE)
        finally:
            profile_material[:] = b"\x00" * len(profile_material)

        return WrappedProfileKey(
            kek_ref=self._active_kek,
            profile_id=context.profile_id,
            profile_key_version=context.profile_key_version,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def unwrap_profile_key(
        self,
        wrapped: WrappedProfileKey,
        context: ProfileKeyContext,
    ) -> ProfileDekHandle:
        """Authenticate all bindings and return a one-use profile-key handle."""
        self._assert_context(context)
        if type(wrapped) is not WrappedProfileKey:
            _fail(SecretFailureCode.MALFORMED_RECORD)
        if (
            wrapped.kek_ref != self._active_kek
            or wrapped.profile_id != context.profile_id
            or wrapped.profile_key_version != context.profile_key_version
        ):
            _fail(SecretFailureCode.PROVIDER_MISMATCH)

        try:
            with self._open_key_material() as key_material:
                cipher = AESGCM(key_material)
                plaintext = cipher.decrypt(wrapped.nonce, wrapped.ciphertext, self._aad(context))
        except SecretProviderError:
            raise
        except InvalidTag:
            _fail(SecretFailureCode.AUTHENTICATION_FAILED)
        except Exception:
            _fail(SecretFailureCode.MALFORMED_RECORD)
        if len(plaintext) != PROFILE_DEK_BYTES:
            _fail(SecretFailureCode.MALFORMED_RECORD)
        return ProfileDekHandle(
            plaintext,
            _issuer_token=self._handle_issuer,
            _issuer_check=self._handle_is_current,
            _pid=self._pid,
        )

    def check_readiness(
        self,
        sentinel: WrappedProfileKey,
        context: ProfileKeyContext,
    ) -> SecretProviderStatus:
        """Prove the configured key authenticates a known catalog sentinel."""
        try:
            handle = self.unwrap_profile_key(sentinel, context)
        except SecretProviderError as error:
            return error.operator_status
        handle.close()
        return SecretProviderStatus.READY

    def _assert_process(self) -> None:
        if os.getpid() != self._pid:
            _fail(SecretFailureCode.FORKED_PROCESS)

    def _handle_is_current(self, token: object, pid: int) -> bool:
        return token is self._handle_issuer and pid == self._pid and os.getpid() == self._pid

    @staticmethod
    def _assert_context(context: ProfileKeyContext) -> None:
        if type(context) is not ProfileKeyContext:
            _fail(SecretFailureCode.MALFORMED_RECORD)

    def _assert_structural_separation(self) -> None:
        key_directory = self._key_path.parent
        for root in self._managed_roots:
            if _is_within(key_directory, root) or _is_within(root, key_directory):
                _fail(SecretFailureCode.UNSAFE_STORAGE)

    def _validate_managed_root_ancestors(self) -> None:
        """Reject an existing symlink that could defeat lexical separation."""
        for root in self._managed_roots:
            current = Path(root.anchor)
            for part in root.parts[1:]:
                current /= part
                try:
                    metadata = current.lstat()
                except FileNotFoundError:
                    break
                except OSError:
                    _fail(SecretFailureCode.UNAVAILABLE)
                if stat.S_ISLNK(metadata.st_mode):
                    _fail(SecretFailureCode.UNSAFE_STORAGE)

    def _open_private_parent(self) -> int:
        """Traverse to the key directory with no-follow directory descriptors."""
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        nofollow_flags = flags | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(self._key_path.anchor, nofollow_flags)
            parts = self._key_path.parent.parts[1:]
            for index, part in enumerate(parts):
                child = os.open(part, nofollow_flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                metadata = os.fstat(descriptor)
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_mode & 0o022:
                    _fail(SecretFailureCode.UNSAFE_STORAGE)
                if index == len(parts) - 1 and (
                    metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
                ):
                    _fail(SecretFailureCode.UNSAFE_STORAGE)
            return descriptor
        except SecretProviderError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except FileNotFoundError:
            if descriptor >= 0:
                os.close(descriptor)
            _fail(SecretFailureCode.UNPROVISIONED)
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                _fail(SecretFailureCode.UNSAFE_STORAGE)
            _fail(SecretFailureCode.UNAVAILABLE)

    @staticmethod
    def _validate_key_metadata(metadata: os.stat_result) -> None:
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
            or metadata.st_nlink != 1
        ):
            _fail(SecretFailureCode.UNSAFE_STORAGE)
        if metadata.st_size != OWNER_KEY_FILE_BYTES:
            _fail(SecretFailureCode.MALFORMED_RECORD)

    @contextmanager
    def _open_key_material(self) -> Iterator[bytearray]:
        self._assert_process()
        self._assert_structural_separation()
        self._validate_managed_root_ancestors()
        directory_descriptor = self._open_private_parent()
        file_descriptor = -1
        payload = bytearray(OWNER_KEY_FILE_BYTES)
        material = bytearray()
        before: os.stat_result | None = None
        try:
            try:
                named_before_open = os.stat(
                    self._key_path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                _fail(SecretFailureCode.UNPROVISIONED)
            except OSError:
                _fail(SecretFailureCode.UNAVAILABLE)
            self._validate_key_metadata(named_before_open)

            flags = (
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            try:
                file_descriptor = os.open(
                    self._key_path.name,
                    flags,
                    dir_fd=directory_descriptor,
                )
            except FileNotFoundError:
                _fail(SecretFailureCode.UNPROVISIONED)
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    _fail(SecretFailureCode.UNSAFE_STORAGE)
                _fail(SecretFailureCode.UNAVAILABLE)

            before = os.fstat(file_descriptor)
            self._validate_key_metadata(before)
            if not _same_identity(named_before_open, before):
                _fail(SecretFailureCode.UNSAFE_STORAGE)
            offset = 0
            while offset < len(payload):
                try:
                    count = os.readv(file_descriptor, [memoryview(payload)[offset:]])
                except OSError:
                    _fail(SecretFailureCode.UNAVAILABLE)
                if count <= 0:
                    _fail(SecretFailureCode.MALFORMED_RECORD)
                offset += count

            after_read = os.fstat(file_descriptor)
            try:
                named = os.stat(
                    self._key_path.name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except OSError:
                _fail(SecretFailureCode.UNAVAILABLE)
            if not _same_stable_file(before, after_read) or not _same_identity(after_read, named):
                _fail(SecretFailureCode.UNSAFE_STORAGE)
            self._validate_key_metadata(named)

            if payload[: len(OWNER_KEY_FILE_HEADER)] != OWNER_KEY_FILE_HEADER:
                _fail(SecretFailureCode.MALFORMED_RECORD)
            material = bytearray(payload[len(OWNER_KEY_FILE_HEADER) :])
            payload[:] = b"\x00" * len(payload)
            try:
                yield material
            finally:
                after_use = os.fstat(file_descriptor)
                try:
                    named_after_use = os.stat(
                        self._key_path.name,
                        dir_fd=directory_descriptor,
                        follow_symlinks=False,
                    )
                except OSError:
                    _fail(SecretFailureCode.UNAVAILABLE)
                if not _same_stable_file(before, after_use) or not _same_identity(
                    after_use, named_after_use
                ):
                    _fail(SecretFailureCode.UNSAFE_STORAGE)
                self._validate_key_metadata(named_after_use)
        except SecretProviderError:
            payload[:] = b"\x00" * len(payload)
            raise
        finally:
            material[:] = b"\x00" * len(material)
            payload[:] = b"\x00" * len(payload)
            if file_descriptor >= 0:
                os.close(file_descriptor)
            os.close(directory_descriptor)

    def _reserve_nonce(self) -> bytes:
        with self._wrap_lock:
            if self._nonce_reuse_latched:
                _fail(SecretFailureCode.NONCE_REUSE)
            if self._wrap_count >= self._process_wrap_limit:
                _fail(SecretFailureCode.USAGE_LIMIT)
            try:
                nonce = self._nonce_source(WRAP_NONCE_BYTES)
            except Exception:
                _fail(SecretFailureCode.UNAVAILABLE)
            if type(nonce) is not bytes or len(nonce) != WRAP_NONCE_BYTES:
                _fail(SecretFailureCode.UNAVAILABLE)
            if nonce in self._used_nonces:
                self._nonce_reuse_latched = True
                _fail(SecretFailureCode.NONCE_REUSE)
            self._used_nonces.add(nonce)
            self._wrap_count += 1
            return nonce

    def _aad(self, context: ProfileKeyContext) -> bytes:
        return b"".join(
            (
                _AAD_PREFIX,
                struct.pack(">H", 1),
                context.installation_id.value.bytes,
                context.profile_id.value.bytes,
                struct.pack(">I", context.profile_key_version),
                struct.pack(">H", context.catalog_schema_version),
                struct.pack(">B", _PROVIDER_KIND_ID),
                self._active_kek.provider_instance_id.value.bytes,
                self._active_kek.kek_id.value.bytes,
                struct.pack(">I", self._active_kek.kek_version),
                struct.pack(">B", _SUITE_ID),
            )
        )
