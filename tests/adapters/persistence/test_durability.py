"""Deterministic SQLITE-DUR-001 fault and lifecycle evidence."""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

import pytest
from sqlalchemy import Column, Integer, MetaData, Table, func, insert, select, text
from sqlalchemy.exc import OperationalError, TimeoutError

from mycogni.adapters.persistence import (
    FixedFilesystemProbe,
    ShutdownState,
    SqlAlchemyUnitOfWork,
    SQLiteOperatorState,
    SQLiteOwnershipError,
    SQLiteProcessRole,
    SQLiteRecoveryError,
    SQLiteRuntime,
    SQLiteSettings,
    SQLiteStorageUnsupported,
    SQLiteWriterLease,
    assess_sqlite_storage,
    create_session_factory,
    create_sqlite_engine,
)

REPOSITORY_ROOT = Path(__file__).parents[3]


def _settings(path: Path, *, busy_timeout_ms: int = 250) -> SQLiteSettings:
    path.parent.chmod(0o700)
    return SQLiteSettings(url=f"sqlite:///{path}", busy_timeout_ms=busy_timeout_ms)


def _open_runtime(path: Path, *, busy_timeout_ms: int = 250) -> SQLiteRuntime:
    return SQLiteRuntime.open(
        _settings(path, busy_timeout_ms=busy_timeout_ms),
        probe=FixedFilesystemProbe("ext4"),
    )


@pytest.mark.parametrize("filesystem_type", ["apfs", "btrfs", "ext4", "xfs"])
def test_local_persistent_filesystem_types_are_eligible(
    tmp_path: Path,
    filesystem_type: str,
) -> None:
    assessment = assess_sqlite_storage(
        _settings(tmp_path / "eligible.sqlite"),
        probe=FixedFilesystemProbe(filesystem_type),
    )

    assert assessment.filesystem_type == filesystem_type


@pytest.mark.parametrize(
    "filesystem_type",
    ["9p", "cifs", "fuse", "nfs", "overlay", "smbfs", "tmpfs", "virtiofs", "unknown"],
)
def test_network_ephemeral_bind_and_unknown_filesystems_fail_closed(
    tmp_path: Path,
    filesystem_type: str,
) -> None:
    with pytest.raises(SQLiteStorageUnsupported, match="filesystem .* is unsupported"):
        assess_sqlite_storage(
            _settings(tmp_path / "rejected.sqlite"),
            probe=FixedFilesystemProbe(filesystem_type),
        )


def test_database_directory_must_be_private(tmp_path: Path) -> None:
    tmp_path.chmod(0o755)
    settings = SQLiteSettings(url=f"sqlite:///{tmp_path / 'private.sqlite'}")

    with pytest.raises(SQLiteStorageUnsupported, match="mode 0700"):
        assess_sqlite_storage(settings, probe=FixedFilesystemProbe("ext4"))


def test_symlink_target_is_rejected_without_leaking_its_path(tmp_path: Path) -> None:
    actual = tmp_path / "actual.sqlite"
    actual.touch(mode=0o600)
    canary_name = "synthetic-private-canary.sqlite"
    configured = tmp_path / canary_name
    configured.symlink_to(actual)

    with pytest.raises(SQLiteStorageUnsupported) as caught:
        assess_sqlite_storage(
            _settings(configured),
            probe=FixedFilesystemProbe("ext4"),
        )

    assert canary_name not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


def test_os_error_traceback_suppresses_private_path_context(tmp_path: Path) -> None:
    canary_name = "synthetic-private-directory-canary"
    database_path = tmp_path / canary_name / "database.sqlite"
    settings = SQLiteSettings(url=f"sqlite:///{database_path}")

    with pytest.raises(SQLiteStorageUnsupported) as caught:
        assess_sqlite_storage(settings, probe=FixedFilesystemProbe("ext4"))

    rendered = "".join(
        traceback.format_exception(type(caught.value), caught.value, caught.value.__traceback__)
    )
    assert canary_name not in rendered
    assert str(tmp_path) not in rendered
    assert caught.value.__suppress_context__ is True


def test_one_process_and_one_engine_own_the_writer_boundary(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "owned.sqlite")
    lease = SQLiteWriterLease.acquire(
        settings,
        role=SQLiteProcessRole.ALL_IN_ONE,
        probe=FixedFilesystemProbe("ext4"),
    )
    engine = create_sqlite_engine(settings, writer_lease=lease)
    try:
        with pytest.raises(SQLiteOwnershipError, match="already has an owner"):
            SQLiteWriterLease.acquire(
                settings,
                role=SQLiteProcessRole.MIGRATION,
                probe=FixedFilesystemProbe("ext4"),
            )
        with pytest.raises(SQLiteOwnershipError, match="exactly one"):
            create_sqlite_engine(settings, writer_lease=lease)
    finally:
        engine.dispose()
        lease.release()


def test_kernel_lock_rejects_a_competing_process(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "process-owned.sqlite")
    lease = SQLiteWriterLease.acquire(
        settings,
        role=SQLiteProcessRole.ALL_IN_ONE,
        probe=FixedFilesystemProbe("ext4"),
    )
    lock_payload = json.loads(lease.lock_path.read_text(encoding="ascii"))
    assert lock_payload == {"role": "all-in-one", "schema": 1}
    os.utime(lease.lock_path, (1, 1))
    script = """
import sys
from mycogni.adapters.persistence import (
    FixedFilesystemProbe, SQLiteOwnershipError, SQLiteProcessRole,
    SQLiteSettings, SQLiteWriterLease,
)
settings = SQLiteSettings(url=sys.argv[1])
try:
    SQLiteWriterLease.acquire(
        settings,
        role=SQLiteProcessRole.MIGRATION,
        probe=FixedFilesystemProbe("ext4"),
    )
except SQLiteOwnershipError:
    raise SystemExit(23)
raise SystemExit(24)
"""
    try:
        completed = subprocess.run(
            [sys.executable, "-c", script, settings.url],
            cwd=REPOSITORY_ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    finally:
        lease.release()

    assert completed.returncode == 23, completed.stderr


def test_single_connection_pool_serializes_in_process_access(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "serialized.sqlite", busy_timeout_ms=50)
    lease = SQLiteWriterLease.acquire(
        settings,
        role=SQLiteProcessRole.ALL_IN_ONE,
        probe=FixedFilesystemProbe("ext4"),
    )
    engine = create_sqlite_engine(settings, writer_lease=lease)
    failures: list[type[BaseException]] = []
    try:
        with engine.connect():

            def contend() -> None:
                try:
                    with engine.connect():
                        pass
                except BaseException as error:
                    failures.append(type(error))

            thread = threading.Thread(target=contend)
            thread.start()
            thread.join(timeout=2)
        assert not thread.is_alive()
        assert failures == [TimeoutError]
    finally:
        engine.dispose()
        lease.release()


def test_wal_reader_snapshot_does_not_block_owned_writer(tmp_path: Path) -> None:
    database_path = tmp_path / "wal.sqlite"
    with _open_runtime(database_path) as runtime:
        with runtime.engine.begin() as writer:
            writer.execute(text("CREATE TABLE synthetic_items (id INTEGER PRIMARY KEY)"))
            writer.execute(text("INSERT INTO synthetic_items (id) VALUES (1)"))

        reader = sqlite3.connect(database_path)
        try:
            reader.execute("BEGIN")
            assert reader.execute("SELECT count(*) FROM synthetic_items").fetchone() == (1,)
            with runtime.engine.begin() as writer:
                writer.execute(text("INSERT INTO synthetic_items (id) VALUES (2)"))
            assert reader.execute("SELECT count(*) FROM synthetic_items").fetchone() == (1,)
            reader.commit()
            assert reader.execute("SELECT count(*) FROM synthetic_items").fetchone() == (2,)
        finally:
            reader.close()


def test_unexpected_external_writer_contention_fails_without_corruption(tmp_path: Path) -> None:
    database_path = tmp_path / "contention.sqlite"
    runtime = _open_runtime(database_path, busy_timeout_ms=50)
    metadata = MetaData()
    records = Table("synthetic_records", metadata, Column("id", Integer, primary_key=True))
    metadata.create_all(runtime.engine)
    factory = create_session_factory(runtime.engine)
    rogue = sqlite3.connect(database_path, timeout=0.05)
    try:
        rogue.execute("BEGIN IMMEDIATE")
        rogue.execute("INSERT INTO synthetic_records (id) VALUES (1)")
        with (
            pytest.raises(OperationalError, match="database is locked"),
            SqlAlchemyUnitOfWork(factory),
        ):
            pass
        rogue.rollback()

        with SqlAlchemyUnitOfWork(factory) as unit_of_work:
            unit_of_work.session.execute(insert(records).values(id=2))
            unit_of_work.commit()
        with runtime.engine.connect() as connection:
            assert connection.scalar(select(func.count()).select_from(records)) == 1
        assert runtime.readiness.accepting_new_work is False
        assert runtime.readiness.external_actions_must_remain_paused is True
        assert runtime.readiness.operator_state is SQLiteOperatorState.WRITER_CONTENTION
    finally:
        rogue.close()
        runtime.close_cleanly()


def test_sqlite_full_rolls_back_and_pauses_new_work(tmp_path: Path) -> None:
    runtime = _open_runtime(tmp_path / "full.sqlite")
    try:
        with runtime.engine.begin() as connection:
            connection.execute(
                text("CREATE TABLE synthetic_payloads (id INTEGER PRIMARY KEY, payload BLOB)")
            )
            connection.execute(
                text("INSERT INTO synthetic_payloads (id, payload) VALUES (1, zeroblob(16))")
            )
        with runtime.engine.connect() as connection:
            page_count = int(connection.scalar(text("PRAGMA page_count")) or 0)
            connection.execute(text(f"PRAGMA max_page_count={page_count}"))

        with (
            pytest.raises(OperationalError, match="database or disk is full"),
            runtime.engine.begin() as connection,
        ):
            connection.execute(
                text("INSERT INTO synthetic_payloads (id, payload) VALUES (2, zeroblob(1048576))")
            )

        with runtime.engine.connect() as connection:
            connection.execute(text("PRAGMA max_page_count=1073741823"))
            assert connection.scalar(text("SELECT count(*) FROM synthetic_payloads")) == 1
        assert runtime.readiness.accepting_new_work is False
        assert runtime.readiness.external_actions_must_remain_paused is True
        assert runtime.readiness.operator_state is SQLiteOperatorState.STORAGE_EXHAUSTED
    finally:
        runtime.close_cleanly()


def test_synthetic_ioerr_has_redacted_fail_closed_readiness(tmp_path: Path) -> None:
    class SyntheticIOError(sqlite3.OperationalError):
        sqlite_errorcode = sqlite3.SQLITE_IOERR

    with _open_runtime(tmp_path / "ioerr.sqlite") as runtime:
        error = SyntheticIOError("synthetic path must not be retained")
        assert runtime.record_driver_failure(error) is True
        assert runtime.readiness.accepting_new_work is False
        assert runtime.readiness.external_actions_must_remain_paused is True
        assert runtime.readiness.operator_state is SQLiteOperatorState.STORAGE_IO_FAILURE
        assert not hasattr(runtime.readiness, "error")


def test_sigkill_recovery_keeps_committed_and_discards_uncommitted(tmp_path: Path) -> None:
    database_path = tmp_path / "sigkill.sqlite"
    ready_path = tmp_path / "child-ready"
    settings = _settings(database_path)
    script = """
import os
import sys
import time
from pathlib import Path
from sqlalchemy import text
from mycogni.adapters.persistence import FixedFilesystemProbe, SQLiteRuntime, SQLiteSettings

runtime = SQLiteRuntime.open(
    SQLiteSettings(url=sys.argv[1]),
    probe=FixedFilesystemProbe("ext4"),
)
with runtime.engine.begin() as connection:
    connection.execute(text("CREATE TABLE synthetic_crash (label TEXT PRIMARY KEY)"))
    connection.execute(text("INSERT INTO synthetic_crash VALUES ('committed')"))
connection = runtime.engine.connect()
connection.exec_driver_sql("BEGIN IMMEDIATE")
connection.execute(text("INSERT INTO synthetic_crash VALUES ('uncommitted')"))
ready = Path(sys.argv[2])
descriptor = os.open(ready, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(descriptor, b"ready")
os.fsync(descriptor)
os.close(descriptor)
time.sleep(30)
"""
    process = subprocess.Popen(
        [sys.executable, "-c", script, settings.url, str(ready_path)],
        cwd=REPOSITORY_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not ready_path.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if not ready_path.exists():
        stdout, stderr = process.communicate(timeout=2)
        pytest.fail(f"crash child did not become ready: {stdout!r} {stderr!r}")
    process.send_signal(signal.SIGKILL)
    process.wait(timeout=5)
    assert process.returncode == -signal.SIGKILL

    runtime = _open_runtime(database_path)
    try:
        assert runtime.startup.previous_shutdown is ShutdownState.DIRTY
        assert runtime.startup.quick_check == "ok"
        assert runtime.startup.requires_reconciliation is True
        assert runtime.readiness.operator_state is SQLiteOperatorState.RECOVERY_REQUIRED
        with runtime.engine.connect() as connection:
            labels = connection.scalars(text("SELECT label FROM synthetic_crash")).all()
        assert labels == ["committed"]
    finally:
        runtime.close_cleanly()


def test_busy_truncate_checkpoint_refuses_clean_shutdown(tmp_path: Path) -> None:
    database_path = tmp_path / "checkpoint-busy.sqlite"
    runtime = _open_runtime(database_path, busy_timeout_ms=50)
    with runtime.engine.begin() as connection:
        connection.execute(text("CREATE TABLE synthetic_checkpoint (id INTEGER PRIMARY KEY)"))
        connection.execute(text("INSERT INTO synthetic_checkpoint VALUES (1)"))
    reader = sqlite3.connect(database_path)
    reader.execute("BEGIN")
    assert reader.execute("SELECT count(*) FROM synthetic_checkpoint").fetchone() == (1,)
    with runtime.engine.begin() as connection:
        connection.execute(text("INSERT INTO synthetic_checkpoint VALUES (2)"))

    try:
        with pytest.raises(SQLiteRecoveryError, match="checkpoint incomplete"):
            runtime.close_cleanly()
    finally:
        reader.close()

    recovered = _open_runtime(database_path)
    assert recovered.startup.previous_shutdown is ShutdownState.DIRTY
    recovered.close_cleanly()


def test_marker_fsync_failure_restores_marker_before_releasing_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.adapters.persistence import durability

    database_path = tmp_path / "marker-fsync.sqlite"
    runtime = _open_runtime(database_path)
    real_fsync_directory = durability._fsync_directory
    calls = 0

    def fail_once(path: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic directory fsync failure")
        real_fsync_directory(path)

    monkeypatch.setattr(durability, "_fsync_directory", fail_once)
    with pytest.raises(SQLiteRecoveryError, match="could not durably remove"):
        runtime.close_cleanly()

    recovered = _open_runtime(database_path)
    assert recovered.startup.previous_shutdown is ShutdownState.DIRTY
    recovered.close_cleanly()


def test_invalid_dirty_marker_fails_closed_and_is_redacted(tmp_path: Path) -> None:
    database_path = tmp_path / "synthetic-marker-canary.sqlite"
    settings = _settings(database_path)
    marker_path = tmp_path / f".{database_path.name}.dirty"
    marker_path.write_bytes(b"not-a-valid-marker\n")
    marker_path.chmod(0o600)

    with pytest.raises(SQLiteRecoveryError, match="invalid schema") as caught:
        SQLiteRuntime.open(settings, probe=FixedFilesystemProbe("ext4"))

    assert database_path.name not in str(caught.value)
    assert str(tmp_path) not in str(caught.value)
