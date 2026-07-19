"""Pinned, fail-closed owner-only source for an existing installation KEK.

Runtime never creates, replaces, repairs, discovers, migrates, or exports key
material or the dedicated readiness sentinel.  Empty-install provisioning is a
separate administration boundary.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import stat
import struct
import threading
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from mycogni.application.keys import (
    PROFILE_DEK_BYTES,
    WRAP_NONCE_BYTES,
    ActiveKekRef,
    KeyReadiness,
    KeyReadinessState,
    ProfileDekHandle,
    ProfileKeyBinding,
    SecretFailureCode,
    SecretProviderError,
    SourceStatus,
    WrappedProfileKey,
    WrappedReadinessSentinel,
)
from mycogni.domain import OpaqueId

OWNER_FILE_PROVIDER_KIND = "owner-file"
OWNER_KEY_FILE_HEADER = b"MYCOGNI-OWNER-KEK\x00\x01"
OWNER_KEY_FILE_BYTES = len(OWNER_KEY_FILE_HEADER) + PROFILE_DEK_BYTES
DEFAULT_PROCESS_WRAP_LIMIT = 100_000
_PROFILE_AAD_PREFIX = b"MyCogni\x00profile-dek-wrap\x00"
_SENTINEL_AAD_PREFIX = b"MyCogni\x00readiness-sentinel\x00"
_READINESS_PLAINTEXT = b"MyCogni-readiness-sentinel-v1!!!"
_PROVIDER_KIND_ID = 1
_SUITE_ID = 1


def _os_nonce_bytes(length: int) -> bytes:
    """Private OS-RNG call site monkeypatchable only by direct tests."""
    return os.urandom(length)


def _os_profile_key_bytes(length: int) -> bytes:
    """Private OS-RNG call site monkeypatchable only by direct tests."""
    return os.urandom(length)


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


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _SourcePin:
    parent: _DirectoryIdentity
    file: _FileIdentity
    material_digest: bytes


@dataclass(slots=True)
class _ProcessWrapState:
    limit: int
    count: int = 0
    used_nonces: set[bytes] = field(default_factory=set)
    sentinel_records: dict[bytes, bytes] = field(default_factory=dict)
    nonce_reuse_latched: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


_PROCESS_PID = os.getpid()
_REGISTRY_LOCK = threading.Lock()
_LIVE_PATH_PROVIDERS: weakref.WeakValueDictionary[Path, OwnerFileSecretProvider] = (
    weakref.WeakValueDictionary()
)
_LIVE_KEY_PROVIDERS: weakref.WeakValueDictionary[bytes, OwnerFileSecretProvider] = (
    weakref.WeakValueDictionary()
)
_PROCESS_WRAP_STATES: dict[bytes, _ProcessWrapState] = {}


class OwnerFileSecretProvider:
    """One existing installation bound to one authenticated, pinned KEK source."""

    def __init__(
        self,
        *,
        key_path: Path,
        active_kek: ActiveKekRef,
        installation_id: OpaqueId,
        catalog_id: OpaqueId,
        sentinel_id: OpaqueId,
        readiness_sentinel: WrappedReadinessSentinel,
        managed_roots: tuple[Path, ...],
        process_wrap_limit: int = DEFAULT_PROCESS_WRAP_LIMIT,
    ) -> None:
        if os.getpid() != _PROCESS_PID:
            _fail(SecretFailureCode.FORKED_PROCESS)
        if type(active_kek) is not ActiveKekRef:
            raise TypeError("owner-file provider requires an active KEK reference")
        if active_kek.provider_kind != OWNER_FILE_PROVIDER_KIND:
            raise ValueError("active KEK reference has the wrong provider kind")
        for value, label in (
            (installation_id, "installation"),
            (catalog_id, "catalog"),
            (sentinel_id, "sentinel"),
        ):
            if type(value) is not OpaqueId:
                raise TypeError(f"owner-file provider {label} ID must be an OpaqueId")
        if type(readiness_sentinel) is not WrappedReadinessSentinel:
            raise TypeError("existing installation requires a dedicated readiness sentinel")
        if (
            readiness_sentinel.kek_ref != active_kek
            or readiness_sentinel.installation_id != installation_id
            or readiness_sentinel.catalog_id != catalog_id
            or readiness_sentinel.sentinel_id != sentinel_id
        ):
            raise ValueError("readiness sentinel identity does not match trusted composition")
        if type(process_wrap_limit) is not int:
            raise TypeError("process wrap limit must be an integer")
        if not 1 <= process_wrap_limit <= DEFAULT_PROCESS_WRAP_LIMIT:
            raise ValueError("process wrap limit is outside the supported range")
        if type(managed_roots) is not tuple or not managed_roots:
            raise TypeError("managed roots must be a non-empty tuple")

        self._pid = os.getpid()
        self._key_path = _canonical_absolute(key_path)
        self._active_kek = active_kek
        self._installation_id = installation_id
        self._catalog_id = catalog_id
        self._sentinel_id = sentinel_id
        self._readiness_sentinel = readiness_sentinel
        self._managed_roots = tuple(_canonical_absolute(root) for root in managed_roots)
        self._assert_structural_separation()
        self._handle_issuer = object()
        self._source_pin: _SourcePin | None = None
        self._recovery_latched = False
        self._latched_source_status = SourceStatus.UNAVAILABLE
        self._state_lock = threading.Lock()
        self._wrap_state: _ProcessWrapState | None = None

        with _REGISTRY_LOCK:
            existing = _LIVE_PATH_PROVIDERS.get(self._key_path)
            if existing is not None:
                _fail(SecretFailureCode.PROVIDER_ALREADY_ACTIVE)
            _LIVE_PATH_PROVIDERS[self._key_path] = self
        self._process_wrap_limit = process_wrap_limit

    def __repr__(self) -> str:
        return "OwnerFileSecretProvider(key_path=[REDACTED], active_kek=[REDACTED])"

    def active_kek(self) -> ActiveKekRef:
        self._assert_process()
        return self._active_kek

    def source_status(self) -> SourceStatus:
        """Report source readability only; this is never installation readiness."""
        self._assert_process()
        with self._state_lock:
            self._assert_process()
            try:
                if self._source_pin is None:
                    with self._open_source():
                        pass
                else:
                    with self._material_session(required_pin=self._source_pin):
                        pass
            except SecretProviderError as error:
                if error.code is SecretFailureCode.RECOVERY_REQUIRED and self._recovery_latched:
                    return self._latched_source_status
                return self._source_status_for(error.code)
            return SourceStatus.READABLE

    def readiness(self) -> KeyReadiness:
        """Authenticate the dedicated sentinel, then pin this exact source."""
        self._assert_process()
        with self._state_lock:
            self._assert_process()
            if self._recovery_latched:
                return KeyReadiness(
                    KeyReadinessState.RECOVERY_REQUIRED,
                    self._latched_source_status,
                )
            required_pin = self._source_pin
            try:
                with self._material_session(required_pin=required_pin) as (material, snapshot):
                    try:
                        plaintext = AESGCM(material).decrypt(
                            self._readiness_sentinel.nonce,
                            self._readiness_sentinel.ciphertext,
                            self._sentinel_aad(),
                        )
                    except InvalidTag:
                        self._latch_recovery(SourceStatus.READABLE)
                        return KeyReadiness(
                            KeyReadinessState.RECOVERY_REQUIRED,
                            SourceStatus.READABLE,
                        )
                    except Exception:
                        self._latch_recovery(SourceStatus.UNAVAILABLE)
                        return KeyReadiness(
                            KeyReadinessState.RECOVERY_REQUIRED,
                            SourceStatus.UNAVAILABLE,
                        )
                    if type(plaintext) is not bytes or len(plaintext) != len(_READINESS_PLAINTEXT):
                        self._latch_recovery(SourceStatus.UNAVAILABLE)
                        return KeyReadiness(
                            KeyReadinessState.RECOVERY_REQUIRED,
                            SourceStatus.UNAVAILABLE,
                        )
                    self._record_authenticated_sentinel(snapshot)
                    if not hmac.compare_digest(plaintext, _READINESS_PLAINTEXT):
                        self._latch_recovery(SourceStatus.READABLE)
                        return KeyReadiness(
                            KeyReadinessState.RECOVERY_REQUIRED,
                            SourceStatus.READABLE,
                        )
                self._activate_key_domain(snapshot)
                self._source_pin = snapshot
            except SecretProviderError as error:
                source_status = self._latch_or_preserve_recovery(error.code)
                return KeyReadiness(
                    KeyReadinessState.RECOVERY_REQUIRED,
                    source_status,
                )
            return KeyReadiness(KeyReadinessState.READY, SourceStatus.READABLE)

    def create_profile_key(self, binding: ProfileKeyBinding) -> WrappedProfileKey:
        """Generate and wrap a profile DEK only after sentinel-authenticated readiness."""
        self._assert_process()
        if type(binding) is not ProfileKeyBinding:
            _fail(SecretFailureCode.MALFORMED_RECORD)
        if binding.installation_id != self._installation_id:
            _fail(SecretFailureCode.PROVIDER_MISMATCH)
        with self._state_lock:
            self._assert_process()
            pin = self._require_ready()
            with self._material_session(required_pin=pin) as (key_material, _snapshot):
                profile_material = self._new_profile_material()
                nonce = b""
                try:
                    nonce = self._reserve_nonce()
                    ciphertext = AESGCM(key_material).encrypt(
                        nonce,
                        profile_material,
                        self._profile_aad(binding),
                    )
                    if type(ciphertext) is not bytes or len(ciphertext) != PROFILE_DEK_BYTES + 16:
                        _fail(SecretFailureCode.UNAVAILABLE)
                except SecretProviderError:
                    raise
                except Exception:
                    _fail(SecretFailureCode.UNAVAILABLE)
                finally:
                    profile_material[:] = b"\x00" * len(profile_material)
            state = self._require_ready_state()
            with state.lock:
                self._assert_domain_unlatched_locked(state)
                return WrappedProfileKey(
                    kek_ref=self._active_kek,
                    binding=binding,
                    nonce=nonce,
                    ciphertext=ciphertext,
                )

    def unwrap_profile_key(
        self,
        wrapped: WrappedProfileKey,
        expected_binding: ProfileKeyBinding,
    ) -> ProfileDekHandle:
        """Authenticate the persisted record and canonical expected binding."""
        self._assert_process()
        if (
            type(wrapped) is not WrappedProfileKey
            or type(expected_binding) is not ProfileKeyBinding
        ):
            _fail(SecretFailureCode.MALFORMED_RECORD)
        if (
            wrapped.kek_ref != self._active_kek
            or wrapped.binding != expected_binding
            or expected_binding.installation_id != self._installation_id
        ):
            _fail(SecretFailureCode.PROVIDER_MISMATCH)
        with self._state_lock:
            self._assert_process()
            pin = self._require_ready()
            try:
                with self._material_session(required_pin=pin) as (key_material, _snapshot):
                    plaintext = AESGCM(key_material).decrypt(
                        wrapped.nonce,
                        wrapped.ciphertext,
                        self._profile_aad(expected_binding),
                    )
                    if type(plaintext) is not bytes or len(plaintext) != PROFILE_DEK_BYTES:
                        _fail(SecretFailureCode.UNAVAILABLE)
            except SecretProviderError:
                raise
            except InvalidTag:
                if not self._recovery_latched:
                    self._latch_recovery(SourceStatus.READABLE)
                _fail(SecretFailureCode.CATALOG_KEY_MISMATCH)
            except Exception:
                _fail(SecretFailureCode.UNAVAILABLE)
            state = self._require_ready_state()
            with state.lock:
                self._assert_domain_unlatched_locked(state)
                return ProfileDekHandle(
                    plaintext,
                    _issuer_token=self._handle_issuer,
                    _issuer_check=self._handle_is_current,
                    _pid=self._pid,
                )

    def _assert_process(self) -> None:
        if os.getpid() != self._pid:
            _fail(SecretFailureCode.FORKED_PROCESS)

    def _handle_is_current(self, token: object, pid: int) -> bool:
        if token is not self._handle_issuer or pid != self._pid or os.getpid() != self._pid:
            return False
        with self._state_lock:
            if self._recovery_latched:
                return False
            state = self._wrap_state
            if state is None:
                return False
            with state.lock:
                return not state.nonce_reuse_latched

    def _require_ready_state(self) -> _ProcessWrapState:
        state = self._wrap_state
        if state is None:
            _fail(SecretFailureCode.READINESS_REQUIRED)
        return state

    def _assert_domain_unlatched_locked(self, state: _ProcessWrapState) -> None:
        if state.nonce_reuse_latched:
            self._latch_recovery(SourceStatus.READABLE)
            _fail(SecretFailureCode.RECOVERY_REQUIRED)

    def _require_ready(self) -> _SourcePin:
        if self._recovery_latched:
            _fail(SecretFailureCode.RECOVERY_REQUIRED)
        state = self._require_ready_state()
        if self._source_pin is None:
            _fail(SecretFailureCode.READINESS_REQUIRED)
        with state.lock:
            self._assert_domain_unlatched_locked(state)
        return self._source_pin

    def _record_authenticated_sentinel(self, snapshot: _SourcePin) -> None:
        """Account for a sentinel immediately after its AEAD authentication."""
        domain = snapshot.material_digest
        with _REGISTRY_LOCK:
            state = _PROCESS_WRAP_STATES.get(domain)
            if state is None:
                state = _ProcessWrapState(self._process_wrap_limit)
                _PROCESS_WRAP_STATES[domain] = state
            sentinel_nonce = self._readiness_sentinel.nonce
            sentinel_commitment = self._sentinel_record_commitment()
            with state.lock:
                if state.nonce_reuse_latched:
                    _fail(SecretFailureCode.NONCE_REUSE)
                existing_commitment = state.sentinel_records.get(sentinel_nonce)
                if sentinel_nonce in state.used_nonces or (
                    existing_commitment is not None
                    and not hmac.compare_digest(existing_commitment, sentinel_commitment)
                ):
                    state.nonce_reuse_latched = True
                    _fail(SecretFailureCode.NONCE_REUSE)
                # Account for an authenticated record before any later composition
                # rejection: this nonce has already been used under the AES key.
                state.sentinel_records[sentinel_nonce] = sentinel_commitment

    def _activate_key_domain(self, snapshot: _SourcePin) -> None:
        """Activate a fully revalidated provider in its process-wide key domain."""
        domain = snapshot.material_digest
        with _REGISTRY_LOCK:
            state = _PROCESS_WRAP_STATES.get(domain)
            if state is None:
                _fail(SecretFailureCode.UNAVAILABLE)
            with state.lock:
                sentinel_nonce = self._readiness_sentinel.nonce
                expected_commitment = self._sentinel_record_commitment()
                actual_commitment = state.sentinel_records.get(sentinel_nonce)
                if (
                    state.nonce_reuse_latched
                    or actual_commitment is None
                    or not hmac.compare_digest(actual_commitment, expected_commitment)
                ):
                    _fail(SecretFailureCode.NONCE_REUSE)
                if state.limit != self._process_wrap_limit:
                    _fail(SecretFailureCode.PROVIDER_MISMATCH)
                existing = _LIVE_KEY_PROVIDERS.get(domain)
                if existing is not None and existing is not self:
                    _fail(SecretFailureCode.PROVIDER_ALREADY_ACTIVE)
                _LIVE_KEY_PROVIDERS[domain] = self
                self._wrap_state = state

    def _latch_recovery(self, source_status: SourceStatus) -> None:
        self._recovery_latched = True
        self._latched_source_status = source_status
        self._source_pin = None

    def _latch_or_preserve_recovery(self, code: SecretFailureCode) -> SourceStatus:
        if self._recovery_latched:
            return self._latched_source_status
        source_status = self._source_status_for(code)
        self._latch_recovery(source_status)
        return source_status

    @staticmethod
    def _source_status_for(code: SecretFailureCode) -> SourceStatus:
        if code is SecretFailureCode.UNSAFE_STORAGE:
            return SourceStatus.UNSAFE
        if code is SecretFailureCode.MALFORMED_RECORD:
            return SourceStatus.CORRUPT
        if code in {
            SecretFailureCode.CATALOG_KEY_MISMATCH,
            SecretFailureCode.NONCE_REUSE,
            SecretFailureCode.PROVIDER_ALREADY_ACTIVE,
            SecretFailureCode.PROVIDER_MISMATCH,
            SecretFailureCode.USAGE_LIMIT,
        }:
            return SourceStatus.READABLE
        return SourceStatus.UNAVAILABLE

    def _assert_structural_separation(self) -> None:
        key_directory = self._key_path.parent
        for root in self._managed_roots:
            if _is_within(key_directory, root) or _is_within(root, key_directory):
                _fail(SecretFailureCode.UNSAFE_STORAGE)

    def _validate_managed_root_ancestors(self) -> None:
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

    @staticmethod
    def _directory_identity(metadata: os.stat_result) -> _DirectoryIdentity:
        return _DirectoryIdentity(
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
        )

    @staticmethod
    def _file_identity(metadata: os.stat_result) -> _FileIdentity:
        return _FileIdentity(
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )

    @staticmethod
    def _safe_fstat(descriptor: int) -> os.stat_result:
        try:
            return os.fstat(descriptor)
        except OSError:
            _fail(SecretFailureCode.UNAVAILABLE)

    @staticmethod
    def _close(descriptor: int) -> bool:
        try:
            os.close(descriptor)
        except OSError:
            return False
        return True

    @staticmethod
    def _validate_ancestor(metadata: os.stat_result, *, final_parent: bool) -> None:
        trusted_owners = {0, os.geteuid()}
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o022
            or metadata.st_uid not in trusted_owners
        ):
            _fail(SecretFailureCode.UNSAFE_STORAGE)
        if final_parent and (metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077):
            _fail(SecretFailureCode.UNSAFE_STORAGE)

    def _open_private_parent(self) -> tuple[int, _DirectoryIdentity]:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        nofollow = flags | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(self._key_path.anchor, nofollow)
            parts = self._key_path.parent.parts[1:]
            anchor_metadata = self._safe_fstat(descriptor)
            self._validate_ancestor(anchor_metadata, final_parent=not parts)
            for index, part in enumerate(parts):
                child = os.open(part, nofollow, dir_fd=descriptor)
                if not self._close(descriptor):
                    self._close(child)
                    _fail(SecretFailureCode.UNAVAILABLE)
                descriptor = child
                metadata = self._safe_fstat(descriptor)
                self._validate_ancestor(
                    metadata,
                    final_parent=index == len(parts) - 1,
                )
            metadata = self._safe_fstat(descriptor)
            return descriptor, self._directory_identity(metadata)
        except SecretProviderError:
            if descriptor >= 0:
                self._close(descriptor)
            raise
        except FileNotFoundError:
            if descriptor >= 0:
                self._close(descriptor)
            _fail(SecretFailureCode.UNAVAILABLE)
        except OSError as error:
            if descriptor >= 0:
                self._close(descriptor)
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                _fail(SecretFailureCode.UNSAFE_STORAGE)
            _fail(SecretFailureCode.UNAVAILABLE)

    @staticmethod
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

    @contextmanager
    def _open_source(self) -> Iterator[tuple[bytearray, _SourcePin]]:
        self._assert_process()
        self._assert_structural_separation()
        self._validate_managed_root_ancestors()
        parent_descriptor, parent_identity = self._open_private_parent()
        file_descriptor = -1
        payload = bytearray(OWNER_KEY_FILE_BYTES)
        material = bytearray()
        primary = False
        try:
            try:
                named = os.stat(
                    self._key_path.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                _fail(SecretFailureCode.UNAVAILABLE)
            except OSError:
                _fail(SecretFailureCode.UNAVAILABLE)
            self._validate_file(named)
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
                    dir_fd=parent_descriptor,
                )
            except OSError as error:
                if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                    _fail(SecretFailureCode.UNSAFE_STORAGE)
                _fail(SecretFailureCode.UNAVAILABLE)
            opened = self._safe_fstat(file_descriptor)
            self._validate_file(opened)
            if self._file_identity(opened) != self._file_identity(named):
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
            after_read = self._safe_fstat(file_descriptor)
            if self._file_identity(opened) != self._file_identity(after_read):
                _fail(SecretFailureCode.UNSAFE_STORAGE)
            if payload[: len(OWNER_KEY_FILE_HEADER)] != OWNER_KEY_FILE_HEADER:
                _fail(SecretFailureCode.MALFORMED_RECORD)
            material = bytearray(payload[len(OWNER_KEY_FILE_HEADER) :])
            payload[:] = b"\x00" * len(payload)
            snapshot = _SourcePin(
                parent=parent_identity,
                file=self._file_identity(after_read),
                material_digest=hashlib.sha256(material).digest(),
            )
            yield material, snapshot
        except BaseException:
            primary = True
            raise
        finally:
            material[:] = b"\x00" * len(material)
            payload[:] = b"\x00" * len(payload)
            close_ok = True
            if file_descriptor >= 0:
                close_ok = self._close(file_descriptor) and close_ok
            close_ok = self._close(parent_descriptor) and close_ok
            if not close_ok and not primary:
                _fail(SecretFailureCode.UNAVAILABLE)

    @contextmanager
    def _material_session(
        self,
        *,
        required_pin: _SourcePin | None,
    ) -> Iterator[tuple[bytearray, _SourcePin]]:
        operation_error: BaseException | None = None
        try:
            with self._open_source() as (material, initial):
                if required_pin is not None and not self._same_pin(initial, required_pin):
                    self._latch_recovery(self._status_for_pin_difference(initial, required_pin))
                    _fail(SecretFailureCode.RECOVERY_REQUIRED)
                try:
                    yield material, initial
                except BaseException as error:
                    operation_error = error
                try:
                    with self._open_source() as (_after_material, after):
                        if not self._same_pin(after, initial):
                            if required_pin is not None:
                                self._latch_recovery(
                                    self._status_for_pin_difference(after, required_pin)
                                )
                            _fail(SecretFailureCode.UNSAFE_STORAGE)
                except SecretProviderError as post_error:
                    self._latch_recovery(self._source_status_for(post_error.code))
                    if operation_error is None:
                        raise
                if operation_error is not None:
                    raise operation_error
        except SecretProviderError as error:
            if (
                required_pin is not None
                and error is not operation_error
                and error.code
                not in {
                    SecretFailureCode.READINESS_REQUIRED,
                    SecretFailureCode.RECOVERY_REQUIRED,
                }
            ):
                self._latch_recovery(self._source_status_for(error.code))
            raise

    @staticmethod
    def _same_pin(current: _SourcePin, expected: _SourcePin) -> bool:
        return (
            current.parent == expected.parent
            and current.file == expected.file
            and hmac.compare_digest(current.material_digest, expected.material_digest)
        )

    @staticmethod
    def _status_for_pin_difference(current: _SourcePin, expected: _SourcePin) -> SourceStatus:
        if not hmac.compare_digest(current.material_digest, expected.material_digest):
            return SourceStatus.READABLE
        return SourceStatus.UNSAFE

    def _new_profile_material(self) -> bytearray:
        try:
            generated = _os_profile_key_bytes(PROFILE_DEK_BYTES)
        except Exception:
            _fail(SecretFailureCode.UNAVAILABLE)
        if type(generated) is not bytes or len(generated) != PROFILE_DEK_BYTES:
            _fail(SecretFailureCode.UNAVAILABLE)
        return bytearray(generated)

    def _reserve_nonce(self) -> bytes:
        self._assert_process()
        state = self._wrap_state
        if state is None:
            _fail(SecretFailureCode.READINESS_REQUIRED)
        with state.lock:
            self._assert_process()
            if state.nonce_reuse_latched:
                _fail(SecretFailureCode.NONCE_REUSE)
            if state.count >= state.limit:
                _fail(SecretFailureCode.USAGE_LIMIT)
            try:
                nonce = _os_nonce_bytes(WRAP_NONCE_BYTES)
            except Exception:
                _fail(SecretFailureCode.UNAVAILABLE)
            if type(nonce) is not bytes or len(nonce) != WRAP_NONCE_BYTES:
                _fail(SecretFailureCode.UNAVAILABLE)
            if nonce in state.used_nonces or nonce in state.sentinel_records:
                state.nonce_reuse_latched = True
                _fail(SecretFailureCode.NONCE_REUSE)
            state.used_nonces.add(nonce)
            state.count += 1
            return nonce

    def _profile_aad(self, binding: ProfileKeyBinding) -> bytes:
        return b"".join(
            (
                _PROFILE_AAD_PREFIX,
                struct.pack(">H", 1),
                struct.pack(">H", 1),
                binding.installation_id.value.bytes,
                binding.profile_id.value.bytes,
                struct.pack(">I", binding.profile_key_version),
                struct.pack(">H", binding.catalog_schema_version),
                struct.pack(">B", _PROVIDER_KIND_ID),
                self._active_kek.provider_instance_id.value.bytes,
                self._active_kek.kek_id.value.bytes,
                struct.pack(">I", self._active_kek.kek_version),
                struct.pack(">B", _SUITE_ID),
            )
        )

    def _sentinel_aad(self) -> bytes:
        sentinel = self._readiness_sentinel
        return b"".join(
            (
                _SENTINEL_AAD_PREFIX,
                struct.pack(">H", sentinel.format_version),
                struct.pack(">H", sentinel.aad_version),
                self._installation_id.value.bytes,
                self._catalog_id.value.bytes,
                self._sentinel_id.value.bytes,
                struct.pack(">B", _PROVIDER_KIND_ID),
                self._active_kek.provider_instance_id.value.bytes,
                self._active_kek.kek_id.value.bytes,
                struct.pack(">I", self._active_kek.kek_version),
                struct.pack(">B", _SUITE_ID),
            )
        )

    def _sentinel_record_commitment(self) -> bytes:
        """Commit to the complete authenticated sentinel record for idempotence."""
        aad = self._sentinel_aad()
        ciphertext = self._readiness_sentinel.ciphertext
        return hashlib.sha256(
            b"MyCogni\x00sentinel-record-commitment\x00"
            + struct.pack(">I", len(aad))
            + aad
            + struct.pack(">I", len(ciphertext))
            + ciphertext
        ).digest()
