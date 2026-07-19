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
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Protocol, Self

from sqlalchemy import Engine, event, text
from sqlalchemy.engine import ExceptionContext

if TYPE_CHECKING:
    from mycogni.adapters.persistence.database import SQLiteSettings

_ALLOWED_FILESYSTEMS = frozenset({"apfs", "btrfs", "ext4", "xfs"})
_DIRTY_MARKER = b'{"schema":1,"state":"open"}\n'
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


class SQLiteOwnershipError(RuntimeError):
    """Raised when another process/engine owns the SQLite writer boundary."""


class SQLiteStorageUnsupported(RuntimeError):
    """Raised when the configured storage cannot receive the support claim."""


class SQLiteRecoveryError(RuntimeError):
    """Raised when recovery or a clean checkpoint cannot be proven."""


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
        resolved = path.resolve(strict=True)
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
                ["/usr/bin/stat", "-f", "%T", str(path)],
                check=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            raise SQLiteStorageUnsupported("cannot identify the database filesystem type") from None
        filesystem_type = completed.stdout.strip().lower()
        if not filesystem_type:
            raise SQLiteStorageUnsupported("database filesystem type was empty")
        return FilesystemMount(filesystem_type, path)


@dataclass(frozen=True, slots=True)
class SQLiteStorageAssessment:
    """Recorded input to the local-lite filesystem support decision."""

    database_path: Path
    filesystem_type: str
    mount_point: Path


def _assert_regular_file(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SQLiteStorageUnsupported(f"{label} must be a regular non-symlink file")
    if metadata.st_mode & 0o022:
        raise SQLiteStorageUnsupported(f"{label} must not be group/world writable")


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
        parent_metadata = parent.lstat()
    except FileNotFoundError:
        raise SQLiteStorageUnsupported("database directory does not exist") from None
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(parent_metadata.st_mode):
        raise SQLiteStorageUnsupported("database directory must be a non-symlink directory")
    if parent_metadata.st_mode & 0o077:
        raise SQLiteStorageUnsupported("database directory must be private (mode 0700 or stricter)")

    database_path = configured_path.resolve(strict=False)
    _assert_regular_file(configured_path, label="database")
    for suffix in ("-wal", "-shm"):
        _assert_regular_file(Path(f"{configured_path}{suffix}"), label=f"SQLite {suffix} sidecar")

    mount = (probe or SystemFilesystemProbe()).inspect(parent)
    filesystem_type = mount.filesystem_type.strip().lower()
    if filesystem_type not in _ALLOWED_FILESYSTEMS:
        allowed = ", ".join(sorted(_ALLOWED_FILESYSTEMS))
        raise SQLiteStorageUnsupported(
            f"filesystem {filesystem_type!r} is unsupported; allowed local types: {allowed}"
        )
    return SQLiteStorageAssessment(
        database_path=database_path,
        filesystem_type=filesystem_type,
        mount_point=mount.mount_point.resolve(strict=False),
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class SQLiteWriterLease:
    """Exclusive process ownership of one SQLite database and one Engine."""

    def __init__(
        self,
        *,
        database_path: Path,
        role: SQLiteProcessRole,
        lock_path: Path,
        descriptor: int,
        assessment: SQLiteStorageAssessment,
    ) -> None:
        self.database_path = database_path
        self.role = role
        self.lock_path = lock_path
        self.assessment = assessment
        self._descriptor = descriptor
        self._owner_pid = os.getpid()
        self._active = True
        self._engine_bound = False

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
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
            flags |= getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(lock_path, flags, 0o600)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise SQLiteOwnershipError("writer lock is not a regular file")
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
            _fsync_directory(lock_path.parent)
            return cls(
                database_path=database_path,
                role=role,
                lock_path=lock_path,
                descriptor=descriptor,
                assessment=assessment,
            )
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            with _ACTIVE_PATHS_LOCK:
                _ACTIVE_PATHS.discard(database_path)
            raise

    def assert_active(self, database_path: Path) -> None:
        if not self._active or self._owner_pid != os.getpid():
            raise SQLiteOwnershipError(
                "SQLite writer lease is inactive or belongs to another process"
            )
        if database_path.resolve(strict=False) != self.database_path:
            raise SQLiteOwnershipError("SQLite writer lease is bound to a different database")

    def bind_engine(self, database_path: Path) -> None:
        self.assert_active(database_path)
        if self._engine_bound:
            raise SQLiteOwnershipError("one writer lease may bind exactly one SQLAlchemy Engine")
        self._engine_bound = True

    def release(self) -> None:
        if not self._active:
            return
        if self._owner_pid != os.getpid():
            raise SQLiteOwnershipError(
                "forked child cannot release its parent's SQLite writer lease"
            )
        try:
            fcntl.flock(self._descriptor, fcntl.LOCK_UN)
        finally:
            os.close(self._descriptor)
            self._active = False
            with _ACTIVE_PATHS_LOCK:
                _ACTIVE_PATHS.discard(self.database_path)

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


def _read_marker(marker_path: Path) -> ShutdownState:
    try:
        metadata = marker_path.lstat()
    except FileNotFoundError:
        return ShutdownState.CLEAN
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SQLiteRecoveryError("dirty marker is not a regular file")
    if metadata.st_size > _MAX_MARKER_BYTES:
        raise SQLiteRecoveryError("dirty marker is oversized")
    try:
        payload = marker_path.read_bytes()
    except OSError:
        raise SQLiteRecoveryError("dirty marker cannot be read") from None
    if payload != _DIRTY_MARKER:
        raise SQLiteRecoveryError("dirty marker has an invalid schema")
    return ShutdownState.DIRTY


def _create_marker(marker_path: Path, previous_shutdown: ShutdownState) -> None:
    if previous_shutdown is ShutdownState.DIRTY:
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(marker_path, flags, 0o600)
    try:
        written = os.write(descriptor, _DIRTY_MARKER)
        if written != len(_DIRTY_MARKER):
            raise SQLiteRecoveryError("dirty marker write was incomplete")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(marker_path.parent)


def _quick_check(engine: Engine, lease: SQLiteWriterLease) -> str:
    lease.assert_active(lease.database_path)
    with engine.connect() as connection:
        rows = tuple(str(row[0]) for row in connection.execute(text("PRAGMA quick_check")))
    if rows != ("ok",):
        raise SQLiteRecoveryError(f"SQLite quick_check failed: {rows!r}")
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
        startup: SQLiteStartupReport,
        readiness: SQLiteReadiness,
    ) -> None:
        self.engine = engine
        self.lease = lease
        self.marker_path = marker_path
        self.startup = startup
        self.readiness = readiness
        self._closed = False
        event.listen(self.engine, "handle_error", self._handle_driver_error)

    def _handle_driver_error(self, context: ExceptionContext) -> None:
        self.record_driver_failure(context.original_exception)

    def record_driver_failure(self, error: BaseException) -> bool:
        """Apply the fail-closed readiness decision for a SQLite failure.

        Returns whether the error was a storage/integrity class that changed
        readiness. The raw error and database path are never retained.
        """
        code = _primary_sqlite_error_code(error)
        if code == sqlite3.SQLITE_FULL:
            self.readiness.operator_state = SQLiteOperatorState.STORAGE_EXHAUSTED
        elif code == sqlite3.SQLITE_IOERR:
            self.readiness.operator_state = SQLiteOperatorState.STORAGE_IO_FAILURE
        elif code in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}:
            self.readiness.operator_state = SQLiteOperatorState.INTEGRITY_FAILURE
        elif code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
            # With one process and one pooled connection, a write-side BUSY or
            # LOCKED error means an unsupported writer bypassed ownership.
            self.readiness.operator_state = SQLiteOperatorState.WRITER_CONTENTION
        else:
            return False
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
        engine: Engine | None = None
        try:
            previous_shutdown = _read_marker(marker_path)
            _create_marker(marker_path, previous_shutdown)
            engine = create_sqlite_engine(settings, writer_lease=lease)
            quick_check = _quick_check(engine, lease)
            recovery_checkpoint = None
            if previous_shutdown is ShutdownState.DIRTY:
                recovery_checkpoint = _checkpoint(engine, lease, mode="PASSIVE")
                if recovery_checkpoint.busy != 0:
                    raise SQLiteRecoveryError("dirty-start WAL recovery checkpoint was busy")
            requires_reconciliation = previous_shutdown is ShutdownState.DIRTY
            return cls(
                engine=engine,
                lease=lease,
                marker_path=marker_path,
                startup=SQLiteStartupReport(
                    previous_shutdown=previous_shutdown,
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
        except BaseException:
            if engine is not None:
                engine.dispose()
            lease.release()
            raise

    def close_cleanly(self) -> None:
        """Checkpoint, validate, dispose, then durably remove the dirty marker."""
        if self._closed:
            return
        failure: BaseException | None = None
        try:
            checkpoint = _checkpoint(self.engine, self.lease, mode="TRUNCATE")
            if checkpoint != SQLiteCheckpoint(0, 0, 0):
                raise SQLiteRecoveryError(f"clean-shutdown checkpoint incomplete: {checkpoint!r}")
            _quick_check(self.engine, self.lease)
        except BaseException as error:
            failure = error
        finally:
            self.engine.dispose()

        if failure is not None:
            # The marker still records an unclean lifecycle, so another owner
            # may safely acquire only after this lease is released.
            self.lease.release()
            self._closed = True
            raise failure
        try:
            self.marker_path.unlink()
            _fsync_directory(self.marker_path.parent)
        except OSError:
            # Never release the kernel lease after losing the marker. Recreate
            # and fsync it first; if that also fails, retain ownership so a
            # second process cannot be admitted without a recovery signal.
            try:
                marker_state = _read_marker(self.marker_path)
                _create_marker(self.marker_path, marker_state)
            except BaseException:
                self.readiness.accepting_new_work = False
                self.readiness.external_actions_must_remain_paused = True
                self.readiness.operator_state = SQLiteOperatorState.STORAGE_IO_FAILURE
                raise SQLiteRecoveryError(
                    "clean shutdown lost its recovery marker; writer lease retained"
                ) from None
            self.lease.release()
            self._closed = True
            raise SQLiteRecoveryError(
                "clean shutdown could not durably remove its marker"
            ) from None
        self.lease.release()
        self._closed = True

    def abandon(self) -> None:
        """Release resources but leave the marker to force recovery next start."""
        if self._closed:
            return
        self.engine.dispose()
        marker_state = _read_marker(self.marker_path)
        try:
            _create_marker(self.marker_path, marker_state)
        except BaseException:
            self.readiness.accepting_new_work = False
            self.readiness.external_actions_must_remain_paused = True
            self.readiness.operator_state = SQLiteOperatorState.STORAGE_IO_FAILURE
            raise SQLiteRecoveryError(
                "cannot preserve dirty marker; writer lease retained"
            ) from None
        self.lease.release()
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
