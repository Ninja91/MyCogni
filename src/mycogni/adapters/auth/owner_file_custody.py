"""Strict owner-file custody for authentication authorities.

The runtime reader never creates, repairs, replaces, or changes permissions on
the source.  ``OwnerFileAuthCustodyProvisioner`` is the separate create-new
administration boundary for an empty installation.
"""

from __future__ import annotations

import errno
import hashlib
import os
import stat
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn
from uuid import UUID

from mycogni.application.auth import ReprovisionOperatorAuthority
from mycogni.application.auth_custody import (
    AuthCustodyBinding,
    AuthCustodyBundle,
    AuthCustodyError,
    AuthCustodyFailureCode,
    AuthCustodyStatus,
)
from mycogni.domain import OpaqueId
from mycogni.domain.auth import OpaqueCredential, RootCapability, RootPurpose

_MAGIC = b"MYCOGNI-AUTH-C\x00\x00"
_VERSION = 1
_COUNT = 5
_HEADER = struct.Struct(">16sBBQ16s16s16s")
_RECORD = struct.Struct(">B16s32s")
_FILE_BYTES = _HEADER.size + _COUNT * _RECORD.size
_TAGS = (1, 2, 10, 11, 12)
_ROOT_TAGS = {
    10: RootPurpose.INITIAL_BOOTSTRAP,
    11: RootPurpose.EMERGENCY_REVOKE,
    12: RootPurpose.REPROVISION,
}


def _fail(code: AuthCustodyFailureCode) -> NoReturn:
    raise AuthCustodyError(code) from None


def _digest_secret(credential: OpaqueCredential) -> bytes:
    return hashlib.sha256(credential.secret.reveal()).digest()


def _opaque(raw: bytes) -> OpaqueId:
    try:
        return OpaqueId(UUID(bytes=raw))
    except (TypeError, ValueError):
        _fail(AuthCustodyFailureCode.MALFORMED_RECORD)


def _credential(handle: bytes, secret: bytes) -> OpaqueCredential:
    try:
        return OpaqueCredential.from_secret(_opaque(handle), secret)
    except (TypeError, ValueError):
        _fail(AuthCustodyFailureCode.MALFORMED_RECORD)


def _serialize(bundle: AuthCustodyBundle) -> bytes:
    binding = bundle.binding
    credentials = (
        bundle.operator_authority.credential,
        bundle.service_identity,
        *(root.credential for root in bundle.roots),
    )
    payload = bytearray(
        _HEADER.pack(
            _MAGIC,
            _VERSION,
            _COUNT,
            bundle.generation,
            binding.installation_id.value.bytes,
            binding.actor_id.value.bytes,
            binding.represented_profile_id.value.bytes,
        )
    )
    for tag, credential in zip(_TAGS, credentials, strict=True):
        payload.extend(_RECORD.pack(tag, credential.handle.value.bytes, credential.secret.reveal()))
    return bytes(payload)


def _parse(payload: bytes, expected: AuthCustodyBinding) -> AuthCustodyBundle:
    if type(payload) is not bytes or len(payload) != _FILE_BYTES:
        _fail(AuthCustodyFailureCode.MALFORMED_RECORD)
    try:
        magic, version, count, generation, installation, actor, profile = _HEADER.unpack_from(
            payload
        )
    except struct.error:
        _fail(AuthCustodyFailureCode.MALFORMED_RECORD)
    if magic != _MAGIC or version != _VERSION or count != _COUNT or generation < 1:
        _fail(AuthCustodyFailureCode.MALFORMED_RECORD)
    binding = AuthCustodyBinding(_opaque(installation), _opaque(actor), _opaque(profile))
    if binding != expected:
        _fail(AuthCustodyFailureCode.BINDING_MISMATCH)
    records: dict[int, OpaqueCredential] = {}
    offset = _HEADER.size
    for wanted in _TAGS:
        try:
            tag, handle, secret = _RECORD.unpack_from(payload, offset)
        except struct.error:
            _fail(AuthCustodyFailureCode.MALFORMED_RECORD)
        offset += _RECORD.size
        if tag != wanted or tag in records:
            _fail(AuthCustodyFailureCode.MALFORMED_RECORD)
        records[tag] = _credential(handle, secret)
    if len({value.handle for value in records.values()}) != _COUNT:
        _fail(AuthCustodyFailureCode.MALFORMED_RECORD)

    def root(tag: int) -> RootCapability:
        return RootCapability(
            credential=records[tag],
            installation_id=binding.installation_id,
            actor_id=binding.actor_id,
            represented_profile_id=binding.represented_profile_id,
            purpose=_ROOT_TAGS[tag],
        )

    try:
        return AuthCustodyBundle(
            binding=binding,
            generation=generation,
            operator_authority=ReprovisionOperatorAuthority(records[1]),
            service_identity=records[2],
            initial_bootstrap=root(10),
            emergency_revoke=root(11),
            reprovision=root(12),
        )
    except (TypeError, ValueError):
        _fail(AuthCustodyFailureCode.MALFORMED_RECORD)


@dataclass(frozen=True, slots=True)
class _Identity:
    device: int
    inode: int
    mode: int
    uid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int


@dataclass(frozen=True, slots=True)
class _Pin:
    ancestry: tuple[tuple[int, int, int, int], ...]
    file: _Identity
    digest: bytes


def _identity(meta: os.stat_result) -> _Identity:
    return _Identity(
        meta.st_dev,
        meta.st_ino,
        meta.st_mode,
        meta.st_uid,
        meta.st_nlink,
        meta.st_size,
        meta.st_mtime_ns,
        meta.st_ctime_ns,
    )


def _within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


class _OwnerPathBoundary:
    def __init__(self, *, path: Path, managed_roots: tuple[Path, ...]) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or Path(os.path.abspath(path)) != path
        ):
            raise TypeError("auth custody path must be canonical and absolute")
        if type(managed_roots) is not tuple or not managed_roots:
            raise TypeError("managed roots must be a non-empty tuple")
        self._path = path
        if any(
            not isinstance(root, Path)
            or not root.is_absolute()
            or Path(os.path.abspath(root)) != root
            for root in managed_roots
        ):
            raise TypeError("managed roots must be canonical absolute paths")
        self._roots = managed_roots
        self._assert_structural_separation()

    @staticmethod
    def _existing_ancestry(path: Path) -> tuple[tuple[Path, tuple[int, int]], ...]:
        entries: list[tuple[Path, tuple[int, int]]] = []
        current = Path(path.anchor)
        parts = path.parts[1:]
        candidates = (
            current,
            *(current.joinpath(*parts[:index]) for index in range(1, len(parts) + 1)),
        )
        for candidate in candidates:
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                break
            except OSError:
                _fail(AuthCustodyFailureCode.UNAVAILABLE)
            if stat.S_ISLNK(metadata.st_mode):
                _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)
            entries.append((candidate, (metadata.st_dev, metadata.st_ino)))
        return tuple(entries)

    def _assert_structural_separation(self) -> None:
        directory = self._path.parent
        custody_ancestry = self._existing_ancestry(directory)
        custody_identities = {identity: path for path, identity in custody_ancestry}
        resolved_directory = directory.resolve(strict=False)
        for root in self._roots:
            root_ancestry = self._existing_ancestry(root)
            resolved_root = root.resolve(strict=False)
            if _within(resolved_directory, resolved_root) or _within(
                resolved_root, resolved_directory
            ):
                _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)
            for root_path, identity in root_ancestry:
                custody_path = custody_identities.get(identity)
                if custody_path is not None and custody_path != root_path:
                    _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)

    def _validate_managed_root_ancestors(self) -> None:
        self._assert_structural_separation()

    @staticmethod
    def _validate_directory(meta: os.stat_result, *, final: bool) -> None:
        if (
            not stat.S_ISDIR(meta.st_mode)
            or meta.st_uid not in {0, os.geteuid()}
            or meta.st_mode & 0o022
            or (final and (meta.st_uid != os.geteuid() or meta.st_mode & 0o077))
        ):
            _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)

    def _open_parent(
        self,
    ) -> tuple[int, os.stat_result, tuple[tuple[int, int, int, int], ...]]:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        ancestry: list[tuple[int, int, int, int]] = []
        try:
            descriptor = os.open(self._path.anchor, flags)
            parts = self._path.parent.parts[1:]
            metadata = os.fstat(descriptor)
            self._validate_directory(metadata, final=not parts)
            ancestry.append((metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid))
            for index, part in enumerate(parts):
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                metadata = os.fstat(descriptor)
                self._validate_directory(metadata, final=index == len(parts) - 1)
                ancestry.append(
                    (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid)
                )
            return descriptor, os.fstat(descriptor), tuple(ancestry)
        except AuthCustodyError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            if error.errno in {errno.ELOOP, errno.ENOTDIR}:
                _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)
            _fail(AuthCustodyFailureCode.UNAVAILABLE)

    @staticmethod
    def _validate_file(meta: os.stat_result, *, exact_size: bool = True) -> None:
        if (
            not stat.S_ISREG(meta.st_mode)
            or meta.st_uid != os.geteuid()
            or stat.S_IMODE(meta.st_mode) not in {0o400, 0o600}
            or meta.st_nlink != 1
        ):
            _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)
        if exact_size and meta.st_size != _FILE_BYTES:
            _fail(AuthCustodyFailureCode.MALFORMED_RECORD)

    def _read(self) -> tuple[bytes, _Pin]:
        self._validate_managed_root_ancestors()
        parent, parent_meta, ancestry = self._open_parent()
        descriptor = -1
        try:
            named = os.stat(self._path.name, dir_fd=parent, follow_symlinks=False)
            self._validate_file(named)
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(self._path.name, flags, dir_fd=parent)
            opened = os.fstat(descriptor)
            self._validate_file(opened)
            if _identity(named) != _identity(opened):
                _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)
            chunks = bytearray()
            while len(chunks) < _FILE_BYTES:
                part = os.read(descriptor, _FILE_BYTES - len(chunks))
                if not part:
                    break
                chunks.extend(part)
            after = os.fstat(descriptor)
            after_parent = os.fstat(parent)
            if _identity(opened) != _identity(after) or (
                parent_meta.st_dev,
                parent_meta.st_ino,
            ) != (after_parent.st_dev, after_parent.st_ino):
                _fail(AuthCustodyFailureCode.UNSAFE_STORAGE)
            payload = bytes(chunks)
            if len(payload) != _FILE_BYTES:
                _fail(AuthCustodyFailureCode.MALFORMED_RECORD)
            return payload, _Pin(
                ancestry,
                _identity(after),
                hashlib.sha256(payload).digest(),
            )
        except AuthCustodyError:
            raise
        except FileNotFoundError:
            _fail(AuthCustodyFailureCode.UNAVAILABLE)
        except OSError:
            _fail(AuthCustodyFailureCode.UNAVAILABLE)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent)

    def _conclusively_missing(self) -> bool:
        """Return true only for an absent final name below a validated parent."""
        self._validate_managed_root_ancestors()
        parent, _parent_meta, _ancestry = self._open_parent()
        try:
            try:
                os.stat(self._path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                return True
            except OSError:
                _fail(AuthCustodyFailureCode.UNAVAILABLE)
            return False
        finally:
            os.close(parent)


class OwnerFileAuthCustody(_OwnerPathBoundary):
    """Pinned runtime reader; changes permanently latch this instance."""

    def __init__(self, *, path: Path, managed_roots: tuple[Path, ...]) -> None:
        super().__init__(path=path, managed_roots=managed_roots)
        self._pid = os.getpid()
        self._pin: _Pin | None = None
        self._latched = False
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "OwnerFileAuthCustody(path=[REDACTED])"

    def _assert_process(self) -> None:
        if os.getpid() != self._pid:
            _fail(AuthCustodyFailureCode.FORKED_PROCESS)

    def status(self, expected: AuthCustodyBinding) -> AuthCustodyStatus:
        self._assert_process()
        if type(expected) is not AuthCustodyBinding:
            _fail(AuthCustodyFailureCode.BINDING_MISMATCH)
        with self._lock:
            self._assert_process()
            if self._latched:
                return AuthCustodyStatus.RECOVERY_REQUIRED
            try:
                if self._conclusively_missing():
                    return AuthCustodyStatus.UNPROVISIONED
                payload, pin = self._read()
                _parse(payload, expected)
                if self._pin is not None and pin != self._pin:
                    _fail(AuthCustodyFailureCode.CAS_MISMATCH)
                self._pin = pin
                return AuthCustodyStatus.READY
            except AuthCustodyError:
                self._latched = True
                return AuthCustodyStatus.RECOVERY_REQUIRED

    def load(self, expected: AuthCustodyBinding) -> AuthCustodyBundle:
        self._assert_process()
        if type(expected) is not AuthCustodyBinding:
            _fail(AuthCustodyFailureCode.BINDING_MISMATCH)
        with self._lock:
            self._assert_process()
            if self._latched:
                _fail(AuthCustodyFailureCode.RECOVERY_REQUIRED)
            try:
                payload, pin = self._read()
                bundle = _parse(payload, expected)
                if self._pin is not None and pin != self._pin:
                    _fail(AuthCustodyFailureCode.CAS_MISMATCH)
                self._pin = pin
                return bundle
            except AuthCustodyError:
                self._latched = True
                raise


class OwnerFileAuthCustodyProvisioner(_OwnerPathBoundary):
    """Explicit create-new-only administration boundary."""

    def __init__(self, *, path: Path, managed_roots: tuple[Path, ...]) -> None:
        super().__init__(path=path, managed_roots=managed_roots)
        self._pid = os.getpid()

    def provision_empty(self, bundle: AuthCustodyBundle) -> None:
        if os.getpid() != self._pid:
            _fail(AuthCustodyFailureCode.FORKED_PROCESS)
        if type(bundle) is not AuthCustodyBundle:
            _fail(AuthCustodyFailureCode.MALFORMED_RECORD)
        payload = _serialize(bundle)
        self._validate_managed_root_ancestors()
        parent, _metadata, _ancestry = self._open_parent()
        descriptor = -1
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._path.name, flags, 0o600, dir_fd=parent)
            metadata = os.fstat(descriptor)
            self._validate_file(metadata, exact_size=False)
            offset = 0
            while offset < len(payload):
                count = os.write(descriptor, payload[offset:])
                if count <= 0:
                    _fail(AuthCustodyFailureCode.UNAVAILABLE)
                offset += count
            os.fsync(descriptor)
            self._validate_file(os.fstat(descriptor))
            os.fsync(parent)
        except FileExistsError:
            _fail(AuthCustodyFailureCode.ALREADY_PROVISIONED)
        except AuthCustodyError:
            raise
        except OSError:
            _fail(AuthCustodyFailureCode.UNAVAILABLE)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            os.close(parent)


__all__ = ("OwnerFileAuthCustody", "OwnerFileAuthCustodyProvisioner")
