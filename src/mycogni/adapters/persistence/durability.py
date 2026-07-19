"""Fail-closed SQLite ownership, storage, and dirty-shutdown lifecycle.

The local-lite durability contract deliberately supports one database-owning
process.  Its API, worker, and scheduler share one SQLAlchemy connection pool;
other processes must use the authenticated API rather than opening SQLite.
"""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
import subprocess
import sys
import threading
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, Self

from sqlalchemy import Engine, event, text
from sqlalchemy.engine import ExceptionContext

if TYPE_CHECKING:
    from mycogni.adapters.persistence.database import SQLiteSettings
    from mycogni.adapters.persistence.unit_of_work import SqlAlchemyUnitOfWork

_ALLOWED_FILESYSTEMS = frozenset({"apfs", "btrfs", "ext4", "xfs"})
_DIRTY_MARKER = b'{"schema":1,"state":"open"}\n'
_RECOVERY_LATCH = b'{"schema":1,"state":"recovery-required"}\n'
_MAX_MARKER_BYTES = 128
_ACTIVE_PATHS: set[Path] = set()
_ACTIVE_PATHS_LOCK = threading.Lock()


class SQLiteProcessRole(StrEnum):
    """The only processes allowed to own a local-lite database."""

    ALL_IN_ONE = "all-in-one"
    MIGRATION = "migration"


class ShutdownState(StrEnum):
    """State observed before the current owner created its dirty marker."""

    CLEAN = "clean"
    DIRTY = "dirty"


class SQLiteOperatorState(StrEnum):
    """Redacted state safe for readiness and operator surfaces."""

    READY = "ready"
    RECOVERY_REQUIRED = "recovery_required"
    STORAGE_EXHAUSTED = "storage_exhausted"
    STORAGE_IO_FAILURE = "storage_io_failure"
    INTEGRITY_FAILURE = "integrity_failure"
    WRITER_CONTENTION = "writer_contention"
    SHUTDOWN_BLOCKED = "shutdown_blocked"


class SQLiteOwnershipError(RuntimeError):
    """Raised when another process/engine owns the SQLite writer boundary."""


class SQLiteStorageUnsupported(RuntimeError):
    """Raised when the configured storage cannot receive the support claim."""


class SQLiteRecoveryError(RuntimeError):
    """Raised when recovery or a clean checkpoint cannot be proven."""

    def __init__(
        self,
        message: str,
        *,
        operator_state: SQLiteOperatorState = SQLiteOperatorState.RECOVERY_REQUIRED,
    ) -> None:
        super().__init__(message)
        self.operator_state = operator_state


class SQLiteReadinessError(RuntimeError):
    """Raised when new application work is not currently permitted."""


@dataclass(frozen=True, slots=True)
class FilesystemMount:
    """Minimum mount identity used by the fail-closed support decision."""

    filesystem_type: str
    mount_point: Path


class FilesystemProbe(Protocol):
    """Resolve the filesystem backing an existing directory."""

    def inspect(self, path: Path) -> FilesystemMount:
        """Return the filesystem type and mount point for *path*."""
        ...


@dataclass(frozen=True, slots=True)
class FixedFilesystemProbe:
    """Deterministic probe for conformance tests, never production composition."""

    filesystem_type: str
    mount_point: Path = Path("/")

    def inspect(self, path: Path) -> FilesystemMount:
        del path
        return FilesystemMount(self.filesystem_type, self.mount_point)


class SystemFilesystemProbe:
    """Inspect Linux mountinfo or the macOS filesystem type."""

    def inspect(self, path: Path) -> FilesystemMount:
        try:
            resolved = path.resolve(strict=True)
        except OSError:
            raise SQLiteStorageUnsupported("cannot resolve the database directory") from None
        if sys.platform.startswith("linux"):
            return self._inspect_linux(resolved)
        if sys.platform == "darwin":
            return self._inspect_macos(resolved)
        raise SQLiteStorageUnsupported(
            f"SQLITE-DUR-001 has no filesystem probe for platform {sys.platform!r}"
        )

    @staticmethod
    def _decode_mount_path(value: str) -> str:
        for encoded, decoded in (
            ("\\040", " "),
            ("\\011", "\t"),
            ("\\012", "\n"),
            ("\\134", "\\"),
        ):
            value = value.replace(encoded, decoded)
        return value

    @classmethod
    def _inspect_linux(cls, path: Path) -> FilesystemMount:
        candidates: list[FilesystemMount] = []
        try:
            mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
        except OSError:
            raise SQLiteStorageUnsupported("cannot read /proc/self/mountinfo") from None

        for line in mountinfo.splitlines():
            fields = line.split()
            try:
                separator = fields.index("-")
                mount_point = Path(cls._decode_mount_path(fields[4])).resolve(strict=False)
                filesystem_type = fields[separator + 1].lower()
                path.relative_to(mount_point)
            except (ValueError, IndexError):
                continue
            candidates.append(FilesystemMount(filesystem_type, mount_point))

        if not candidates:
            raise SQLiteStorageUnsupported("cannot identify the database filesystem mount")
        return max(candidates, key=lambda candidate: len(candidate.mount_point.parts))

    @staticmethod
    def _inspect_macos(path: Path) -> FilesystemMount:
        try:
            completed = subprocess.run(
                ["/sbin/mount"],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            raise SQLiteStorageUnsupported("cannot identify the database filesystem type") from None
        candidates: list[FilesystemMount] = []
        for line in completed.stdout.splitlines():
            left, separator, options_text = line.rpartition(" (")
            if not separator or not options_text.endswith(")"):
                continue
            _source, on_separator, mount_text = left.rpartition(" on ")
            if not on_separator or not mount_text.startswith("/"):
                continue
            options = [value.strip().lower() for value in options_text[:-1].split(",")]
            if not options or not options[0]:
                continue
            try:
                mount_point = Path(mount_text).resolve(strict=True)
                path.relative_to(mount_point)
            except (OSError, ValueError):
                continue
            candidates.append(FilesystemMount(options[0], mount_point))
        if not candidates:
            raise SQLiteStorageUnsupported("cannot identify the database filesystem mount")
        return max(candidates, key=lambda candidate: len(candidate.mount_point.parts))


@dataclass(frozen=True, slots=True)
class SQLiteStorageAssessment:
    """Recorded input to the local-lite filesystem support decision."""

    database_path: Path
    filesystem_type: str
    mount_point: Path


def _assert_owned_regular_file(metadata: os.stat_result, *, label: str) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise SQLiteStorageUnsupported(f"{label} must be a regular non-symlink file")
    if metadata.st_uid != os.geteuid():
        raise SQLiteStorageUnsupported(f"{label} must be owned by the current service user")
    if metadata.st_nlink != 1:
        raise SQLiteStorageUnsupported(f"{label} must have exactly one hard link")
    if metadata.st_mode & 0o022:
        raise SQLiteStorageUnsupported(f"{label} must not be group/world writable")


def _assert_no_symlinked_ancestors(parent: Path) -> None:
    current = Path(parent.anchor)
    try:
        for part in parent.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise SQLiteStorageUnsupported(
                    "database directory ancestors must be real directories"
                )
    except FileNotFoundError:
        raise SQLiteStorageUnsupported("database directory does not exist") from None
    except OSError:
        raise SQLiteStorageUnsupported("cannot validate database directory ancestors") from None


def _open_private_directory(parent: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        descriptor = os.open(parent, flags)
        metadata = os.fstat(descriptor)
    except OSError:
        if descriptor >= 0:
            os.close(descriptor)
        raise SQLiteStorageUnsupported("cannot open the private database directory") from None
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise SQLiteStorageUnsupported("database directory must be a directory")
    if metadata.st_uid != os.geteuid():
        os.close(descriptor)
        raise SQLiteStorageUnsupported("database directory must be owned by the service user")
    if metadata.st_mode & 0o077:
        os.close(descriptor)
        raise SQLiteStorageUnsupported("database directory must be private (mode 0700 or stricter)")
    return descriptor


def _assert_named_file(
    directory_descriptor: int,
    name: str,
    *,
    label: str,
    required: bool = False,
) -> None:
    try:
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        if required:
            raise SQLiteStorageUnsupported(f"{label} does not exist") from None
        return
    except OSError:
        raise SQLiteStorageUnsupported(f"cannot validate {label}") from None
    _assert_owned_regular_file(metadata, label=label)


def _managed_names(database_name: str) -> tuple[tuple[str, str], ...]:
    return (
        (database_name, "database"),
        (f"{database_name}-wal", "SQLite WAL sidecar"),
        (f"{database_name}-shm", "SQLite shared-memory sidecar"),
        (f".{database_name}.writer.lock", "writer lock"),
        (f".{database_name}.dirty", "dirty marker"),
        (f".{database_name}.recovery-required", "recovery latch"),
    )


def assess_sqlite_storage(
    settings: SQLiteSettings,
    *,
    probe: FilesystemProbe | None = None,
) -> SQLiteStorageAssessment:
    """Fail closed unless the target is a private supported local filesystem.

    Filesystem-type detection qualifies only the software configuration.  It
    cannot prove disk-controller flushes, physical power-loss durability, or
    that an operator has not layered an unsafe mount below the observed one.
    """
    configured_path = settings.configured_database_path
    parent = configured_path.parent
    try:
        _assert_no_symlinked_ancestors(parent)
        directory_descriptor = _open_private_directory(parent)
        try:
            for name, label in _managed_names(configured_path.name):
                _assert_named_file(directory_descriptor, name, label=label)
        finally:
            os.close(directory_descriptor)

        mount = (probe or SystemFilesystemProbe()).inspect(parent)
        filesystem_type = mount.filesystem_type.strip().lower()
        if filesystem_type not in _ALLOWED_FILESYSTEMS:
            allowed = ", ".join(sorted(_ALLOWED_FILESYSTEMS))
            raise SQLiteStorageUnsupported(
                f"filesystem {filesystem_type!r} is unsupported; allowed local types: {allowed}"
            )
        mount_point = mount.mount_point.resolve(strict=True)
    except SQLiteStorageUnsupported:
        raise
    except OSError:
        raise SQLiteStorageUnsupported("cannot assess database storage") from None
    return SQLiteStorageAssessment(
        database_path=parent / configured_path.name,
        filesystem_type=filesystem_type,
        mount_point=mount_point,
    )


def _fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError:
        raise SQLiteRecoveryError("cannot synchronize the database directory") from None


class SQLiteWriterLease:
    """Exclusive process ownership of one SQLite database and one Engine."""

    def __init__(
        self,
        *,
        database_path: Path,
        role: SQLiteProcessRole,
        lock_path: Path,
        descriptor: int,
        directory_descriptor: int,
        assessment: SQLiteStorageAssessment,
    ) -> None:
        self.database_path = database_path
        self.role = role
        self.lock_path = lock_path
        self.assessment = assessment
        self._descriptor = descriptor
        self._directory_descriptor = directory_descriptor
        self._database_name = database_path.name
        self._owner_pid = os.getpid()
        self._active = True
        self._engine_bound = False
        self._checked_out = 0
        self._shutdown_sealed = False
        self._checkout_lock = threading.Lock()

    @classmethod
    def acquire(
        cls,
        settings: SQLiteSettings,
        *,
        role: SQLiteProcessRole,
        probe: FilesystemProbe | None = None,
    ) -> Self:
        assessment = assess_sqlite_storage(settings, probe=probe)
        database_path = assessment.database_path
        lock_path = database_path.parent / f".{database_path.name}.writer.lock"

        with _ACTIVE_PATHS_LOCK:
            if database_path in _ACTIVE_PATHS:
                raise SQLiteOwnershipError("SQLite database already has an owner in this process")
            _ACTIVE_PATHS.add(database_path)

        descriptor = -1
        directory_descriptor = -1
        try:
            directory_descriptor = _open_private_directory(database_path.parent)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(
                lock_path.name,
                flags,
                0o600,
                dir_fd=directory_descriptor,
            )
            metadata = os.fstat(descriptor)
            try:
                _assert_owned_regular_file(metadata, label="writer lock")
            except SQLiteStorageUnsupported as error:
                raise SQLiteOwnershipError(str(error)) from None
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SQLiteOwnershipError("another process owns the SQLite writer lease") from None
            payload = json.dumps(
                {"role": role.value, "schema": 1}, sort_keys=True, separators=(",", ":")
            ).encode("ascii")
            os.ftruncate(descriptor, 0)
            os.write(descriptor, payload + b"\n")
            os.fsync(descriptor)
            _fsync_directory(directory_descriptor)
            for name, label in _managed_names(database_path.name):
                if name != lock_path.name:
                    _assert_named_file(directory_descriptor, name, label=label)
            return cls(
                database_path=database_path,
                role=role,
                lock_path=lock_path,
                descriptor=descriptor,
                directory_descriptor=directory_descriptor,
                assessment=assessment,
            )
        except BaseException as error:
            if descriptor >= 0:
                os.close(descriptor)
            if directory_descriptor >= 0:
                os.close(directory_descriptor)
            with _ACTIVE_PATHS_LOCK:
                _ACTIVE_PATHS.discard(database_path)
            if isinstance(error, (SQLiteOwnershipError, SQLiteStorageUnsupported)):
                raise
            raise SQLiteOwnershipError("SQLite writer-lease acquisition failed") from None

    def _assert_owned_unlocked(self, database_path: Path) -> None:
        if not self._active or self._owner_pid != os.getpid():
            raise SQLiteOwnershipError(
                "SQLite writer lease is inactive or belongs to another process"
            )
        if database_path != self.database_path:
            raise SQLiteOwnershipError("SQLite writer lease is bound to a different database")

    def assert_owned(self, database_path: Path) -> None:
        """Verify ownership while allowing internal shutdown state operations."""
        with self._checkout_lock:
            self._assert_owned_unlocked(database_path)

    def assert_active(self, database_path: Path) -> None:
        """Verify that normal connection work remains admitted."""
        with self._checkout_lock:
            self._assert_owned_unlocked(database_path)
            if self._shutdown_sealed:
                raise SQLiteOwnershipError("SQLite writer lease is sealed for shutdown")

    @property
    def database_name(self) -> str:
        return self._database_name

    @property
    def directory_descriptor(self) -> int:
        self.assert_owned(self.database_path)
        return self._directory_descriptor

    def bind_engine(self, database_path: Path) -> None:
        self.assert_active(database_path)
        if self._engine_bound:
            raise SQLiteOwnershipError("one writer lease may bind exactly one SQLAlchemy Engine")
        self._engine_bound = True

    def register_checkout(self) -> None:
        with self._checkout_lock:
            self._assert_owned_unlocked(self.database_path)
            if self._shutdown_sealed:
                raise SQLiteOwnershipError("SQLite writer lease is sealed for shutdown")
            self._checked_out += 1

    def register_checkin(self) -> None:
        with self._checkout_lock:
            if self._checked_out <= 0:
                raise SQLiteOwnershipError("SQLite connection checkout accounting underflow")
            self._checked_out -= 1

    def has_checked_out_connections(self) -> bool:
        with self._checkout_lock:
            return self._checked_out != 0

    def seal_for_shutdown(self) -> None:
        """Atomically deny future work only when no connection is checked out."""
        with self._checkout_lock:
            self._assert_owned_unlocked(self.database_path)
            if self._checked_out != 0:
                raise SQLiteOwnershipError(
                    "SQLite shutdown cannot seal with checked-out connections"
                )
            self._shutdown_sealed = True

    def unseal_after_failed_shutdown(self) -> bool:
        """Re-admit maintenance work only while this process still owns the lease."""
        with self._checkout_lock:
            if not self._active or self._owner_pid != os.getpid():
                return False
            self._shutdown_sealed = False
            return True

    def owned_by_current_process(self) -> bool:
        with self._checkout_lock:
            return self._active and self._owner_pid == os.getpid()

    def release(self) -> None:
        with self._checkout_lock:
            if not self._active:
                return
            if self._owner_pid != os.getpid():
                raise SQLiteOwnershipError(
                    "forked child cannot release its parent's SQLite writer lease"
                )
            if self._checked_out != 0:
                raise SQLiteOwnershipError(
                    "SQLite writer lease cannot release with checked-out connections"
                )
            previously_sealed = self._shutdown_sealed
            self._shutdown_sealed = True
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        except BaseException:
            with self._checkout_lock:
                if self._active:
                    self._shutdown_sealed = previously_sealed
            raise
        with self._checkout_lock:
            self._active = False
        with _ACTIVE_PATHS_LOCK:
            _ACTIVE_PATHS.discard(self.database_path)
        # LOCK_UN is the ownership boundary. close(2) may report an error even
        # when the descriptor is already closed, so cleanup after a successful
        # unlock is best effort and cannot truthfully turn release into a
        # retained-ownership failure.
        with suppress(OSError):
            os.close(self._descriptor)
        with suppress(OSError):
            os.close(self._directory_descriptor)

    def __enter__(self) -> Self:
        self.assert_active(self.database_path)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.release()


@dataclass(frozen=True, slots=True)
class SQLiteCheckpoint:
    """The three integers returned by SQLite's WAL checkpoint pragma."""

    busy: int
    log_frames: int
    checkpointed_frames: int


@dataclass(frozen=True, slots=True)
class SQLiteStartupReport:
    """Conservative startup disposition for policy and operator surfaces."""

    previous_shutdown: ShutdownState
    quick_check: str
    recovery_checkpoint: SQLiteCheckpoint | None
    requires_reconciliation: bool
    external_actions_must_remain_paused: bool
    filesystem_type: str


@dataclass(slots=True)
class SQLiteReadiness:
    """Mutable, PII-free decision updated by SQLite driver failures."""

    accepting_new_work: bool
    external_actions_must_remain_paused: bool
    operator_state: SQLiteOperatorState


def _primary_sqlite_error_code(error: BaseException) -> int | None:
    current: BaseException | None = error
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, sqlite3.Error):
            code = getattr(current, "sqlite_errorcode", None)
            if isinstance(code, int):
                return code & 0xFF
        next_error = current.__cause__ or current.__context__
        current = next_error if isinstance(next_error, BaseException) else None
    return None


def _operator_state_for_error(error: BaseException) -> SQLiteOperatorState | None:
    code = _primary_sqlite_error_code(error)
    if code == sqlite3.SQLITE_FULL:
        return SQLiteOperatorState.STORAGE_EXHAUSTED
    if code == sqlite3.SQLITE_IOERR:
        return SQLiteOperatorState.STORAGE_IO_FAILURE
    if code in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
        return SQLiteOperatorState.INTEGRITY_FAILURE
    if code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return SQLiteOperatorState.WRITER_CONTENTION
    return None


def _read_state_file(
    lease: SQLiteWriterLease,
    name: str,
    *,
    expected: bytes,
    label: str,
) -> bool:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=lease.directory_descriptor,
        )
    except FileNotFoundError:
        return False
    except OSError:
        raise SQLiteRecoveryError(f"cannot open {label}") from None
    try:
        metadata = os.fstat(descriptor)
        try:
            _assert_owned_regular_file(metadata, label=label)
        except SQLiteStorageUnsupported as error:
            raise SQLiteRecoveryError(str(error)) from None
        if metadata.st_size > _MAX_MARKER_BYTES:
            raise SQLiteRecoveryError(f"{label} is oversized")
        payload = os.read(descriptor, _MAX_MARKER_BYTES + 1)
    except OSError:
        raise SQLiteRecoveryError(f"cannot read {label}") from None
    finally:
        os.close(descriptor)
    if payload != expected:
        raise SQLiteRecoveryError(f"{label} has an invalid schema")
    return True


def _create_state_file(
    lease: SQLiteWriterLease,
    name: str,
    *,
    payload: bytes,
    label: str,
) -> None:
    if _read_state_file(lease, name, expected=payload, label=label):
        # A previous create may have failed only at the directory-fsync step.
        # Re-sync the directory so retry can establish durable presence.
        _fsync_directory(lease.directory_descriptor)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            name,
            flags,
            0o600,
            dir_fd=lease.directory_descriptor,
        )
    except OSError:
        raise SQLiteRecoveryError(f"cannot create {label}") from None
    try:
        metadata = os.fstat(descriptor)
        try:
            _assert_owned_regular_file(metadata, label=label)
        except SQLiteStorageUnsupported as error:
            raise SQLiteRecoveryError(str(error)) from None
        written = os.write(descriptor, payload)
        if written != len(payload):
            raise SQLiteRecoveryError(f"{label} write was incomplete")
        os.fsync(descriptor)
    except OSError:
        raise SQLiteRecoveryError(f"cannot synchronize {label}") from None
    finally:
        os.close(descriptor)
    _fsync_directory(lease.directory_descriptor)


def _remove_state_file(lease: SQLiteWriterLease, name: str, *, label: str) -> None:
    try:
        _assert_named_file(lease.directory_descriptor, name, label=label, required=True)
        os.unlink(name, dir_fd=lease.directory_descriptor)
        _fsync_directory(lease.directory_descriptor)
    except SQLiteStorageUnsupported as error:
        raise SQLiteRecoveryError(str(error)) from None
    except OSError:
        raise SQLiteRecoveryError(f"cannot remove {label}") from None


def _quick_check(engine: Engine, lease: SQLiteWriterLease) -> str:
    lease.assert_active(lease.database_path)
    with engine.connect() as connection:
        rows = tuple(str(row[0]) for row in connection.execute(text("PRAGMA quick_check")))
    if rows != ("ok",):
        raise SQLiteRecoveryError(
            "SQLite quick_check failed",
            operator_state=SQLiteOperatorState.INTEGRITY_FAILURE,
        )
    return rows[0]


def _checkpoint(
    engine: Engine,
    lease: SQLiteWriterLease,
    *,
    mode: str,
) -> SQLiteCheckpoint:
    lease.assert_active(lease.database_path)
    if mode not in {"PASSIVE", "TRUNCATE"}:  # pragma: no cover - internal invariant
        raise ValueError("unsupported checkpoint mode")
    with engine.connect() as connection:
        row = connection.execute(text(f"PRAGMA wal_checkpoint({mode})")).one()
    return SQLiteCheckpoint(
        busy=int(row[0]), log_frames=int(row[1]), checkpointed_frames=int(row[2])
    )


class SQLiteRuntime:
    """Owned Engine plus explicit dirty-start and clean-shutdown protocol."""

    def __init__(
        self,
        *,
        engine: Engine,
        lease: SQLiteWriterLease,
        marker_path: Path,
        recovery_latch_path: Path,
        startup: SQLiteStartupReport,
        readiness: SQLiteReadiness,
    ) -> None:
        self.engine = engine
        self.lease = lease
        self.marker_path = marker_path
        self.recovery_latch_path = recovery_latch_path
        self.startup = startup
        self.readiness = readiness
        self._closed = False
        event.listen(self.engine, "handle_error", self._handle_driver_error)

    @property
    def _marker_name(self) -> str:
        return self.marker_path.name

    @property
    def _recovery_latch_name(self) -> str:
        return self.recovery_latch_path.name

    def _pause(self, state: SQLiteOperatorState) -> None:
        self.readiness.accepting_new_work = False
        self.readiness.external_actions_must_remain_paused = True
        self.readiness.operator_state = state

    def _preserve_recovery_state(self) -> None:
        _create_state_file(
            self.lease,
            self._marker_name,
            payload=_DIRTY_MARKER,
            label="dirty marker",
        )
        _create_state_file(
            self.lease,
            self._recovery_latch_name,
            payload=_RECOVERY_LATCH,
            label="recovery latch",
        )

    def assert_accepting_new_work(self) -> None:
        """Fail closed before every supported application UoW boundary."""
        self.lease.assert_active(self.lease.database_path)
        if self._closed or not self.readiness.accepting_new_work:
            raise SQLiteReadinessError("SQLite runtime is not accepting new work")

    def unit_of_work(self) -> SqlAlchemyUnitOfWork:
        """Return the only supported readiness-guarded application UoW."""
        from mycogni.adapters.persistence.unit_of_work import (
            SqlAlchemyUnitOfWork,
            _create_session_factory,
        )

        self.assert_accepting_new_work()
        return SqlAlchemyUnitOfWork(
            _create_session_factory(self.engine),
            readiness_guard=self.assert_accepting_new_work,
        )

    def _handle_driver_error(self, context: ExceptionContext) -> None:
        self.record_driver_failure(context.original_exception)

    def record_driver_failure(self, error: BaseException) -> bool:
        """Apply the fail-closed readiness decision for a SQLite failure.

        Returns whether the error was a storage/integrity class that changed
        readiness. The raw error and database path are never retained.
        """
        state = _operator_state_for_error(error)
        if state is None:
            return False
        self.readiness.operator_state = state
        self.readiness.accepting_new_work = False
        self.readiness.external_actions_must_remain_paused = True
        return True

    @classmethod
    def open(
        cls,
        settings: SQLiteSettings,
        *,
        role: SQLiteProcessRole = SQLiteProcessRole.ALL_IN_ONE,
        probe: FilesystemProbe | None = None,
    ) -> Self:
        from mycogni.adapters.persistence.database import create_sqlite_engine

        lease = SQLiteWriterLease.acquire(settings, role=role, probe=probe)
        marker_path = lease.database_path.parent / f".{lease.database_path.name}.dirty"
        recovery_latch_path = (
            lease.database_path.parent / f".{lease.database_path.name}.recovery-required"
        )
        engine: Engine | None = None
        try:
            inherited_dirty = _read_state_file(
                lease,
                marker_path.name,
                expected=_DIRTY_MARKER,
                label="dirty marker",
            )
            recovery_latched = _read_state_file(
                lease,
                recovery_latch_path.name,
                expected=_RECOVERY_LATCH,
                label="recovery latch",
            )
            if inherited_dirty:
                _create_state_file(
                    lease,
                    recovery_latch_path.name,
                    payload=_RECOVERY_LATCH,
                    label="recovery latch",
                )
                recovery_latched = True
            if role is SQLiteProcessRole.MIGRATION and recovery_latched:
                raise SQLiteRecoveryError("migration refused while recovery is required")
            _create_state_file(
                lease,
                marker_path.name,
                payload=_DIRTY_MARKER,
                label="dirty marker",
            )
            engine = create_sqlite_engine(settings, writer_lease=lease)
            quick_check = _quick_check(engine, lease)
            for name, label in _managed_names(lease.database_name):
                _assert_named_file(lease.directory_descriptor, name, label=label)
            recovery_checkpoint = None
            if inherited_dirty:
                recovery_checkpoint = _checkpoint(engine, lease, mode="PASSIVE")
                if recovery_checkpoint.busy != 0:
                    raise SQLiteRecoveryError("dirty-start WAL recovery checkpoint was busy")
            requires_reconciliation = recovery_latched
            return cls(
                engine=engine,
                lease=lease,
                marker_path=marker_path,
                recovery_latch_path=recovery_latch_path,
                startup=SQLiteStartupReport(
                    previous_shutdown=(
                        ShutdownState.DIRTY if inherited_dirty else ShutdownState.CLEAN
                    ),
                    quick_check=quick_check,
                    recovery_checkpoint=recovery_checkpoint,
                    requires_reconciliation=requires_reconciliation,
                    external_actions_must_remain_paused=requires_reconciliation,
                    filesystem_type=lease.assessment.filesystem_type,
                ),
                readiness=SQLiteReadiness(
                    accepting_new_work=not requires_reconciliation,
                    external_actions_must_remain_paused=requires_reconciliation,
                    operator_state=(
                        SQLiteOperatorState.RECOVERY_REQUIRED
                        if requires_reconciliation
                        else SQLiteOperatorState.READY
                    ),
                ),
            )
        except BaseException as error:
            if engine is not None:
                engine.dispose()
            lease.release()
            if isinstance(error, SQLiteRecoveryError):
                raise
            raise SQLiteRecoveryError(
                "SQLite startup validation failed",
                operator_state=(
                    _operator_state_for_error(error) or SQLiteOperatorState.RECOVERY_REQUIRED
                ),
            ) from None

    def close_cleanly(self) -> None:
        """Prove a clean close while retaining ownership on every failure."""
        if self._closed:
            return
        self.readiness.accepting_new_work = False
        try:
            checkpoint = _checkpoint(self.engine, self.lease, mode="TRUNCATE")
            if checkpoint != SQLiteCheckpoint(0, 0, 0):
                raise SQLiteRecoveryError(f"clean-shutdown checkpoint incomplete: {checkpoint!r}")
            _quick_check(self.engine, self.lease)
            self.lease.seal_for_shutdown()
        except BaseException:
            try:
                self._preserve_recovery_state()
            finally:
                self._pause(SQLiteOperatorState.SHUTDOWN_BLOCKED)
                self.lease.unseal_after_failed_shutdown()
            raise SQLiteRecoveryError(
                "clean-shutdown validation failed; ownership retained"
            ) from None

        try:
            if self.readiness.operator_state is not SQLiteOperatorState.READY:
                _create_state_file(
                    self.lease,
                    self._recovery_latch_name,
                    payload=_RECOVERY_LATCH,
                    label="recovery latch",
                )
            self.engine.dispose()
            _remove_state_file(self.lease, self._marker_name, label="dirty marker")
            self.lease.release()
        except BaseException:
            self._pause(SQLiteOperatorState.STORAGE_IO_FAILURE)
            if self.lease.owned_by_current_process():
                try:
                    self._preserve_recovery_state()
                finally:
                    self.lease.unseal_after_failed_shutdown()
            raise SQLiteRecoveryError(
                "clean shutdown could not durably remove its marker; ownership retained"
            ) from None
        self._closed = True

    def abandon(self) -> None:
        """Release resources but leave the marker to force recovery next start."""
        if self._closed:
            return
        self._pause(SQLiteOperatorState.SHUTDOWN_BLOCKED)
        self._preserve_recovery_state()
        try:
            self.lease.seal_for_shutdown()
        except BaseException:
            raise SQLiteRecoveryError(
                "cannot abandon runtime with checked-out connections; ownership retained"
            ) from None
        try:
            self.engine.dispose()
            self.lease.release()
        except BaseException:
            if self.lease.owned_by_current_process():
                self.lease.unseal_after_failed_shutdown()
            raise SQLiteRecoveryError("runtime abandon failed; ownership retained") from None
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_value, traceback
        if exc_type is None:
            self.close_cleanly()
        else:
            self.abandon()
