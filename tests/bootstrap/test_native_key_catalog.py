"""Restart integration evidence for native durable key-catalog composition."""

from __future__ import annotations

import gc
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from mycogni.adapters.keys.owner_file import OWNER_KEY_FILE_HEADER
from mycogni.adapters.persistence.database import SQLiteSettings
from mycogni.adapters.persistence.durability import (
    FixedFilesystemProbe,
    SQLiteReadinessError,
    SQLiteRuntime,
)
from mycogni.adapters.persistence.key_catalog import KeyCatalogCrashPoint, SqliteKeyCatalog
from mycogni.application.key_catalog import (
    KeyCatalogError,
    KeyCatalogFailureCode,
    KeyCatalogIdentity,
    KeyCatalogState,
)
from mycogni.application.keys import ActiveKekRef, ProfileKeyBinding, SecretProviderError
from mycogni.bootstrap.key_catalog import (
    NativeKeyCatalogConfig,
    compose_native_key_catalog,
    initialize_native_key_catalog,
    reconcile_native_key_catalog_initialization,
    reconcile_native_profile_key,
    resume_native_key_catalog_initialization,
)
from mycogni.domain import OpaqueId

REPOSITORY_ROOT = Path(__file__).parents[2]

_SUBPROCESS_SCRIPT = r"""import gc, hashlib, json, os, signal, sys
from pathlib import Path
from mycogni.adapters.keys.owner_file_admin import read_source_commitment
from mycogni.adapters.persistence import FixedFilesystemProbe, SQLiteRuntime, SQLiteSettings
from mycogni.adapters.persistence.key_catalog import SqliteKeyCatalog
from mycogni.application.key_catalog import KeyCatalogIdentity
from mycogni.application.keys import ActiveKekRef, ProfileKeyBinding
from mycogni.bootstrap.key_catalog import NativeKeyCatalogConfig, compose_native_key_catalog, initialize_native_key_catalog
from mycogni.domain import OpaqueId
def oid(value): return OpaqueId.parse(value)
identity = KeyCatalogIdentity(
    oid("72000000-0000-4000-8000-000000000001"),
    oid("72000000-0000-4000-8000-000000000002"),
    oid("72000000-0000-4000-8000-000000000003"),
    ActiveKekRef("owner-file", oid("72000000-0000-4000-8000-000000000004"), oid("72000000-0000-4000-8000-000000000005"), 1),
    usage_limit=100,
)
bindings = tuple(ProfileKeyBinding(identity.installation_id, oid(f"72000000-0000-4000-8000-{index:012d}"), 1, 1) for index in (11, 12))
action, database, key_path, managed = sys.argv[1:]
runtime = SQLiteRuntime.open(SQLiteSettings(url=f"sqlite:///{database}"), probe=FixedFilesystemProbe("ext4"))
catalog = SqliteKeyCatalog(runtime)
config = NativeKeyCatalogConfig(identity, Path(key_path), (Path(managed),))
if action == "kill-after-begin":
    commitment = read_source_commitment(key_path=Path(key_path), managed_roots=(Path(managed),))
    catalog.begin_initialization(identity, b"z" * 12, commitment)
    os.kill(os.getpid(), signal.SIGKILL)
service = initialize_native_key_catalog(catalog=catalog, config=config) if action == "init" else compose_native_key_catalog(catalog=catalog, config=config)
if action == "init":
    for binding in bindings: service.create_profile_key(binding)
digests = []
for binding in bindings:
    handle = service.open_profile_key(binding)
    with handle as active: digests.append(active.use(lambda value: hashlib.sha256(value).hexdigest()))
print("RESULT:" + json.dumps(digests, separators=(",", ":")))
del service, catalog
gc.collect()
runtime.close_cleanly()
"""


def _id(value: str) -> OpaqueId:
    return OpaqueId.parse(value)


IDENTITY = KeyCatalogIdentity(
    installation_id=_id("72000000-0000-4000-8000-000000000001"),
    catalog_id=_id("72000000-0000-4000-8000-000000000002"),
    sentinel_id=_id("72000000-0000-4000-8000-000000000003"),
    active_kek=ActiveKekRef(
        provider_kind="owner-file",
        provider_instance_id=_id("72000000-0000-4000-8000-000000000004"),
        kek_id=_id("72000000-0000-4000-8000-000000000005"),
        kek_version=1,
    ),
    usage_limit=100,
)
BINDINGS = tuple(
    ProfileKeyBinding(
        installation_id=IDENTITY.installation_id,
        profile_id=_id(f"72000000-0000-4000-8000-{index:012d}"),
        profile_key_version=1,
        catalog_schema_version=1,
    )
    for index in (11, 12)
)


def _migrate(database_path: Path) -> None:
    config = Config(REPOSITORY_ROOT / "alembic.ini")
    config.set_main_option("script_location", str(REPOSITORY_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    command.upgrade(config, "head")


def _runtime(database_path: Path) -> SQLiteRuntime:
    return SQLiteRuntime.open(
        SQLiteSettings(url=f"sqlite:///{database_path}"),
        probe=FixedFilesystemProbe("ext4"),
    )


def _fresh_process(
    action: str,
    database_path: Path,
    config: NativeKeyCatalogConfig,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            _SUBPROCESS_SCRIPT,
            action,
            str(database_path),
            str(config.key_path),
            str(config.managed_roots[0]),
        ],
        cwd=REPOSITORY_ROOT,
        check=check,
        capture_output=True,
        text=True,
    )


def _subprocess_result(completed: subprocess.CompletedProcess[str]) -> list[str]:
    line = next(line for line in completed.stdout.splitlines() if line.startswith("RESULT:"))
    result = json.loads(line.removeprefix("RESULT:"))
    assert type(result) is list and all(type(item) is str for item in result)
    return result


@pytest.fixture
def native_install(tmp_path: Path) -> tuple[Path, NativeKeyCatalogConfig]:
    database_path = (tmp_path / "state.sqlite").resolve()
    _migrate(database_path)
    key_directory = tmp_path / "keys"
    key_directory.mkdir(mode=0o700)
    key_path = key_directory / "installation.kek"
    key_path.write_bytes(OWNER_KEY_FILE_HEADER + os.urandom(32))
    key_path.chmod(0o600)
    managed = tmp_path / "managed"
    managed.mkdir(mode=0o700)
    return database_path, NativeKeyCatalogConfig(
        identity=IDENTITY,
        key_path=key_path,
        managed_roots=(managed,),
    )


def _extract(service: object, binding: ProfileKeyBinding) -> bytes:
    handle = service.open_profile_key(binding)  # type: ignore[attr-defined]
    with handle as active:
        return active.use(bytes)


def _assert_secret_canaries_absent(
    database_path: Path,
    secrets: tuple[bytes, ...],
    captured: pytest.CaptureFixture[str],
) -> None:
    streams = captured.readouterr()
    rendered = (streams.out + streams.err).encode()
    for suffix in ("", "-wal", "-shm"):
        path = Path(f"{database_path}{suffix}")
        if not path.exists():
            continue
        content = path.read_bytes()
        assert all(secret not in content for secret in secrets)
    assert all(secret not in rendered for secret in secrets)


def test_initialize_two_keys_and_unwrap_after_fresh_runtime(
    native_install: tuple[Path, NativeKeyCatalogConfig],
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_path, config = native_install
    owner_kek = config.key_path.read_bytes()[-32:]
    runtime = _runtime(database_path)
    catalog = SqliteKeyCatalog(runtime)
    service = initialize_native_key_catalog(catalog=catalog, config=config)
    wrapped = tuple(service.create_profile_key(binding) for binding in BINDINGS)
    plaintext = tuple(_extract(service, binding) for binding in BINDINGS)
    assert plaintext[0] != plaintext[1]
    assert wrapped[0].nonce != wrapped[1].nonce
    _assert_secret_canaries_absent(database_path, (owner_kek, *plaintext), capsys)
    del service, catalog
    gc.collect()
    runtime.close_cleanly()
    _assert_secret_canaries_absent(database_path, (owner_kek, *plaintext), capsys)

    restarted = _runtime(database_path)
    restarted_catalog = SqliteKeyCatalog(restarted)
    restarted_service = compose_native_key_catalog(
        catalog=restarted_catalog,
        config=config,
    )
    assert tuple(_extract(restarted_service, binding) for binding in BINDINGS) == plaintext
    _assert_secret_canaries_absent(database_path, (owner_kek, *plaintext), capsys)
    del restarted_service, restarted_catalog
    gc.collect()
    restarted.close_cleanly()
    _assert_secret_canaries_absent(database_path, (owner_kek, *plaintext), capsys)


def test_fresh_exec_processes_restart_and_open_same_synthetic_keys(
    native_install: tuple[Path, NativeKeyCatalogConfig],
) -> None:
    database_path, config = native_install
    initialized = _fresh_process("init", database_path, config)
    restarted = _fresh_process("open", database_path, config)

    initial_digests = _subprocess_result(initialized)
    assert _subprocess_result(restarted) == initial_digests
    assert len(set(initial_digests)) == 2
    owner_kek = config.key_path.read_bytes()[-32:]
    rendered = (
        initialized.stdout + initialized.stderr + restarted.stdout + restarted.stderr
    ).encode()
    assert owner_kek not in rendered


def test_sigkill_after_initialization_reservation_can_be_explicitly_reconciled(
    native_install: tuple[Path, NativeKeyCatalogConfig],
) -> None:
    database_path, config = native_install
    killed = _fresh_process("kill-after-begin", database_path, config, check=False)
    assert killed.returncode == -9

    recovered = _runtime(database_path)
    catalog = SqliteKeyCatalog(recovered)
    before = catalog.load_catalog_for_reconciliation()
    assert before.state is KeyCatalogState.PREPARING
    reconciled = reconcile_native_key_catalog_initialization(
        catalog=catalog,
        config=config,
    )
    assert reconciled.state is KeyCatalogState.ACTIVE
    assert recovered.readiness.accepting_new_work is False
    assert recovered.recovery_latch_path.exists()
    with pytest.raises((KeyCatalogError, SQLiteReadinessError)):
        compose_native_key_catalog(catalog=catalog, config=config)
    recovered.close_cleanly()


def test_routine_composition_rejects_pinned_identity_substitution_before_provider(
    native_install: tuple[Path, NativeKeyCatalogConfig],
) -> None:
    database_path, config = native_install
    runtime = _runtime(database_path)
    catalog = SqliteKeyCatalog(runtime)
    service = initialize_native_key_catalog(catalog=catalog, config=config)
    del service
    gc.collect()
    foreign = replace(
        config,
        identity=replace(
            config.identity,
            catalog_id=_id("72000000-0000-4000-8000-000000000099"),
        ),
    )
    with pytest.raises(KeyCatalogError) as caught:
        compose_native_key_catalog(catalog=catalog, config=foreign)
    assert caught.value.code is KeyCatalogFailureCode.IDENTITY_MISMATCH
    runtime.close_cleanly()


def test_source_failure_latches_recovery_and_restore_cannot_self_clear(
    native_install: tuple[Path, NativeKeyCatalogConfig],
) -> None:
    database_path, config = native_install
    runtime = _runtime(database_path)
    catalog = SqliteKeyCatalog(runtime)
    service = initialize_native_key_catalog(catalog=catalog, config=config)
    del service
    gc.collect()
    config.key_path.unlink()
    with pytest.raises((KeyCatalogError, SecretProviderError)):
        compose_native_key_catalog(catalog=catalog, config=config)
    after = catalog.load_catalog()
    assert after.state is KeyCatalogState.RECOVERY_REQUIRED
    assert not config.key_path.exists()
    config.key_path.write_bytes(
        OWNER_KEY_FILE_HEADER + b"replacement-does-not-clear".ljust(32, b"!")
    )
    config.key_path.chmod(0o600)
    with pytest.raises(KeyCatalogError) as still_latched:
        compose_native_key_catalog(catalog=catalog, config=config)
    assert still_latched.value.code is KeyCatalogFailureCode.RECOVERY_REQUIRED
    runtime.close_cleanly()


def test_interrupted_initialization_leaves_preparing_and_source_untouched(
    native_install: tuple[Path, NativeKeyCatalogConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.bootstrap import key_catalog as bootstrap

    database_path, config = native_install
    runtime = _runtime(database_path)
    catalog = SqliteKeyCatalog(runtime)
    before = (config.key_path.stat(), config.key_path.read_bytes())
    real_create_sentinel = bootstrap.create_readiness_sentinel
    monkeypatch.setattr(
        bootstrap,
        "create_readiness_sentinel",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic interruption")),
    )
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        initialize_native_key_catalog(catalog=catalog, config=config)
    snapshot = catalog.load_catalog()
    assert snapshot.state is KeyCatalogState.PREPARING
    assert snapshot.sentinel is None
    assert (config.key_path.stat(), config.key_path.read_bytes()) == before
    with pytest.raises(KeyCatalogError) as caught:
        compose_native_key_catalog(catalog=catalog, config=config)
    assert caught.value.code is KeyCatalogFailureCode.RECOVERY_REQUIRED
    monkeypatch.setattr(bootstrap, "create_readiness_sentinel", real_create_sentinel)
    resumed = resume_native_key_catalog_initialization(catalog=catalog, config=config)
    assert resumed.readiness().state is KeyCatalogState.ACTIVE
    assert (config.key_path.stat(), config.key_path.read_bytes()) == before
    del resumed
    gc.collect()
    runtime.close_cleanly()


def test_native_reconciliation_authenticates_real_after_commit_unknown_record(
    native_install: tuple[Path, NativeKeyCatalogConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path, config = native_install
    runtime = _runtime(database_path)
    catalog = SqliteKeyCatalog(runtime)
    service = initialize_native_key_catalog(catalog=catalog, config=config)
    real_reserve = catalog.reserve_profile_preparation
    arm_crash = catalog.arm_crash_once

    def reserve_then_arm(preparation: object) -> OpaqueId:
        reservation = real_reserve(preparation)  # type: ignore[arg-type]
        arm_crash(KeyCatalogCrashPoint.AFTER_COMMIT)
        return reservation

    monkeypatch.setattr(catalog, "reserve_profile_preparation", reserve_then_arm)
    with pytest.raises(KeyCatalogError) as ambiguous:
        service.create_profile_key(BINDINGS[0])
    assert ambiguous.value.code is KeyCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN
    del ambiguous, service, catalog
    gc.collect()

    recovered = _runtime(database_path)
    recovered_catalog = SqliteKeyCatalog(recovered)
    reconciled = reconcile_native_profile_key(
        catalog=recovered_catalog,
        config=config,
        binding=BINDINGS[0],
    )
    assert reconciled is not None
    assert reconciled.binding == BINDINGS[0]
    assert recovered.readiness.accepting_new_work is False
    assert recovered.recovery_latch_path.exists()
    recovered.close_cleanly()


def test_initialization_resume_rejects_replaced_safe_owner_source(
    native_install: tuple[Path, NativeKeyCatalogConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.bootstrap import key_catalog as bootstrap

    database_path, config = native_install
    runtime = _runtime(database_path)
    catalog = SqliteKeyCatalog(runtime)
    real_create_sentinel = bootstrap.create_readiness_sentinel
    monkeypatch.setattr(
        bootstrap,
        "create_readiness_sentinel",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("synthetic interruption")),
    )
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        initialize_native_key_catalog(catalog=catalog, config=config)
    config.key_path.write_bytes(OWNER_KEY_FILE_HEADER + os.urandom(32))
    config.key_path.chmod(0o600)
    monkeypatch.setattr(bootstrap, "create_readiness_sentinel", real_create_sentinel)

    with pytest.raises(SecretProviderError) as mismatch:
        resume_native_key_catalog_initialization(catalog=catalog, config=config)

    assert mismatch.value.code.value == "catalog_key_mismatch"
    snapshot = catalog.load_catalog()
    assert snapshot.state is KeyCatalogState.PREPARING
    assert snapshot.sentinel is None
    runtime.close_cleanly()
