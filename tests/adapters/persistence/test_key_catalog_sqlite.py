"""Focused restart and invariant tests for the normalized SQLite key catalog."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

import mycogni.adapters.persistence.key_catalog as key_catalog_adapter
from mycogni.adapters.persistence import (
    FixedFilesystemProbe,
    SQLiteReadinessError,
    SQLiteRuntime,
    SQLiteSettings,
)
from mycogni.adapters.persistence.key_catalog import KeyCatalogCrashPoint, SqliteKeyCatalog
from mycogni.application.key_catalog import (
    KeyCatalogError,
    KeyCatalogFailureCode,
    KeyCatalogIdentity,
    KeyCatalogState,
)
from mycogni.application.keys import (
    ActiveKekRef,
    ProfileKeyBinding,
    ProfileKeyPreparation,
    WrappedProfileKey,
    WrappedReadinessSentinel,
)
from mycogni.domain import OpaqueId

ROOT = Path(__file__).parents[3]


def _id(tail: int) -> OpaqueId:
    return OpaqueId.parse(f"10000000-0000-4000-8000-{tail:012d}")


KEK = ActiveKekRef("owner-file", _id(1), _id(2), 1)
IDENTITY = KeyCatalogIdentity(_id(3), _id(4), _id(5), KEK, usage_limit=4)
BINDING = ProfileKeyBinding(_id(3), _id(6), 1, 1)
SENTINEL_NONCE = b"s" * 12
SOURCE_COMMITMENT = b"k" * 32
SENTINEL = WrappedReadinessSentinel(KEK, _id(3), _id(4), _id(5), SENTINEL_NONCE, b"S" * 48)


def _migrate(path: Path) -> None:
    config = Config(ROOT / "alembic.ini")
    config.set_main_option("script_location", str(ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", f"sqlite:///{path}")
    command.upgrade(config, "head")


def _open(path: Path) -> SQLiteRuntime:
    return SQLiteRuntime.open(
        SQLiteSettings(url=f"sqlite:///{path}"), probe=FixedFilesystemProbe("ext4")
    )


def _preparation(
    binding: ProfileKeyBinding = BINDING, nonce: bytes = b"p" * 12
) -> ProfileKeyPreparation:
    token = object()
    return ProfileKeyPreparation(
        binding,
        nonce,
        _issuer_token=token,
        _issuer_check=lambda candidate, _pid: candidate is token,
    )


def _initialize(store: SqliteKeyCatalog) -> None:
    reservation = store.begin_initialization(IDENTITY, SENTINEL_NONCE, SOURCE_COMMITMENT)
    preparing = store.load_catalog()
    assert preparing.state is KeyCatalogState.PREPARING
    assert preparing.sentinel is None
    store.finish_initialization(reservation, SENTINEL)


def test_initialization_is_two_durable_transactions_and_restarts(tmp_path: Path) -> None:
    path = tmp_path / "catalog.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    reservation = store.begin_initialization(IDENTITY, SENTINEL_NONCE, SOURCE_COMMITMENT)
    runtime.close_cleanly()

    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    assert store.load_catalog().state is KeyCatalogState.PREPARING
    snapshot = store.finish_initialization(reservation, SENTINEL)
    assert snapshot.state is KeyCatalogState.ACTIVE
    assert snapshot.sentinel == SENTINEL
    runtime.close_cleanly()


def test_profile_reservation_publish_and_load_survive_restart(tmp_path: Path) -> None:
    path = tmp_path / "profile.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    preparation = _preparation()
    reservation = store.reserve_profile_preparation(preparation)
    assert store.load_profile_key(BINDING) is None
    wrapped = WrappedProfileKey(KEK, BINDING, preparation.nonce, b"W" * 48)
    store.publish_profile_key(reservation, preparation, wrapped)
    runtime.close_cleanly()

    runtime = _open(path)
    assert SqliteKeyCatalog(runtime).load_profile_key(BINDING) == wrapped
    runtime.close_cleanly()


def test_duplicate_profile_and_nonce_reuse_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "duplicates.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    preparation = _preparation()
    reservation = store.reserve_profile_preparation(preparation)
    store.publish_profile_key(
        reservation, preparation, WrappedProfileKey(KEK, BINDING, preparation.nonce, b"W" * 48)
    )
    with pytest.raises(KeyCatalogError) as duplicate:
        store.reserve_profile_preparation(_preparation(nonce=b"q" * 12))
    assert duplicate.value.code is KeyCatalogFailureCode.DUPLICATE_PROFILE_KEY

    other_binding = ProfileKeyBinding(_id(3), _id(7), 1, 1)
    with pytest.raises(KeyCatalogError) as collision:
        store.reserve_profile_preparation(_preparation(other_binding, preparation.nonce))
    assert collision.value.code is KeyCatalogFailureCode.NONCE_REUSE
    assert runtime.recovery_latch_path.exists()
    runtime.close_cleanly()


@pytest.mark.parametrize("lifecycle", ["reserved", "burned"])
def test_interrupted_profile_binding_cannot_be_reserved_again_after_restart(
    tmp_path: Path, lifecycle: str
) -> None:
    path = tmp_path / f"binding-{lifecycle}.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    store.reserve_profile_preparation(_preparation())
    if lifecycle == "burned":
        with runtime.unit_of_work() as uow:
            uow.session.execute(
                text(
                    "UPDATE key_nonce_reservations SET lifecycle='burned' "
                    "WHERE purpose='profile' AND profile_id=:profile_id "
                    "AND profile_key_version=:profile_key_version"
                ),
                {
                    "profile_id": str(BINDING.profile_id),
                    "profile_key_version": BINDING.profile_key_version,
                },
            )
            uow.commit()
    runtime.close_cleanly()

    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    with pytest.raises(KeyCatalogError) as duplicate:
        store.reserve_profile_preparation(_preparation(nonce=b"q" * 12))
    assert duplicate.value.code is KeyCatalogFailureCode.DUPLICATE_PROFILE_KEY
    with runtime.unit_of_work() as uow:
        assert (
            uow.session.execute(
                text(
                    "SELECT COUNT(*) FROM key_nonce_reservations "
                    "WHERE purpose='profile' AND profile_id=:profile_id "
                    "AND profile_key_version=:profile_key_version"
                ),
                {
                    "profile_id": str(BINDING.profile_id),
                    "profile_key_version": BINDING.profile_key_version,
                },
            ).scalar_one()
            == 1
        )
        assert (
            uow.session.execute(
                text("SELECT usage_reserved FROM key_catalog WHERE singleton_id=1")
            ).scalar_one()
            == 2
        )
    runtime.close_cleanly()


def test_concurrent_clients_accept_only_one_reservation_for_profile_binding(
    tmp_path: Path,
) -> None:
    path = tmp_path / "binding-concurrency.sqlite"
    _migrate(path)
    runtime = _open(path)
    _initialize(SqliteKeyCatalog(runtime))
    stores = (SqliteKeyCatalog(runtime), SqliteKeyCatalog(runtime))

    def attempt(index: int) -> tuple[int, str]:
        try:
            stores[index].reserve_profile_preparation(
                _preparation(nonce=(b"a" if index == 0 else b"b") * 12)
            )
        except KeyCatalogError as error:
            return index, error.code.value
        except SQLiteReadinessError:
            return index, "writer_busy"
        return index, "accepted"

    with ThreadPoolExecutor(max_workers=2) as executor:
        attempts = list(executor.map(attempt, range(2)))

    outcomes = [outcome for _, outcome in attempts]
    assert outcomes.count("accepted") == 1
    rejected_index, rejected_outcome = next(
        (index, outcome) for index, outcome in attempts if outcome != "accepted"
    )
    assert rejected_outcome in {
        "writer_busy",
        KeyCatalogFailureCode.DUPLICATE_PROFILE_KEY.value,
    }
    if rejected_outcome == "writer_busy":
        with pytest.raises(KeyCatalogError) as duplicate:
            stores[rejected_index].reserve_profile_preparation(
                _preparation(nonce=(b"c" if rejected_index == 0 else b"d") * 12)
            )
        assert duplicate.value.code is KeyCatalogFailureCode.DUPLICATE_PROFILE_KEY
    with runtime.unit_of_work() as uow:
        assert (
            uow.session.execute(
                text(
                    "SELECT COUNT(*) FROM key_nonce_reservations "
                    "WHERE purpose='profile' AND profile_id=:profile_id "
                    "AND profile_key_version=:profile_key_version"
                ),
                {
                    "profile_id": str(BINDING.profile_id),
                    "profile_key_version": BINDING.profile_key_version,
                },
            ).scalar_one()
            == 1
        )
        assert (
            uow.session.execute(
                text("SELECT usage_reserved FROM key_catalog WHERE singleton_id=1")
            ).scalar_one()
            == 2
        )
    runtime.close_cleanly()


def test_burned_reservations_count_against_restart_durable_usage_limit(tmp_path: Path) -> None:
    path = tmp_path / "usage.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    store.reserve_profile_preparation(_preparation(nonce=b"a" * 12))
    runtime.close_cleanly()

    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    store.reserve_profile_preparation(
        _preparation(ProfileKeyBinding(_id(3), _id(8), 1, 1), b"b" * 12)
    )
    store.reserve_profile_preparation(
        _preparation(ProfileKeyBinding(_id(3), _id(9), 1, 1), b"c" * 12)
    )
    with pytest.raises(KeyCatalogError) as exhausted:
        store.reserve_profile_preparation(
            _preparation(ProfileKeyBinding(_id(3), _id(10), 1, 1), b"d" * 12)
        )
    assert exhausted.value.code is KeyCatalogFailureCode.USAGE_LIMIT
    runtime.close_cleanly()


def test_commit_uncertainty_unwinds_then_persists_recovery_latch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "ambiguous.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)

    def ambiguous(_uow: object) -> None:
        raise key_catalog_adapter._CommitAmbiguous

    monkeypatch.setattr(store, "_commit_or_latch", ambiguous)
    with pytest.raises(KeyCatalogError) as failure:
        store.begin_initialization(IDENTITY, SENTINEL_NONCE, SOURCE_COMMITMENT)
    assert failure.value.code is KeyCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN
    assert runtime.recovery_latch_path.exists()


def test_counter_drift_is_corruption_and_latches_recovery(tmp_path: Path) -> None:
    path = tmp_path / "counter-drift.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    with runtime.unit_of_work() as uow:
        uow.session.execute(text("UPDATE key_catalog SET usage_reserved=2 WHERE singleton_id=1"))
        uow.commit()

    with pytest.raises(KeyCatalogError) as failure:
        store.load_catalog()

    assert failure.value.code is KeyCatalogFailureCode.CORRUPT
    assert runtime.recovery_latch_path.exists()


def test_driver_failure_is_redacted_and_latches_after_uow_unwinds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "driver-redaction.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    canary = "raw-key-and-private-path-canary"

    def fail_driver(_session: object) -> None:
        raise SQLAlchemyError(canary)

    monkeypatch.setattr(store, "_catalog_row", fail_driver)
    with pytest.raises(KeyCatalogError) as failure:
        store.begin_initialization(IDENTITY, SENTINEL_NONCE, SOURCE_COMMITMENT)

    assert failure.value.code is KeyCatalogFailureCode.UNAVAILABLE
    assert canary not in f"{failure.value!s} {failure.value!r}"
    assert runtime.recovery_latch_path.exists()


@pytest.mark.parametrize(
    ("crash_point", "record_committed"),
    [
        (KeyCatalogCrashPoint.BEFORE_COMMIT, False),
        (KeyCatalogCrashPoint.AFTER_COMMIT, True),
    ],
)
def test_restart_reconciliation_reports_zero_or_one_without_retry_or_clear(
    tmp_path: Path,
    crash_point: KeyCatalogCrashPoint,
    record_committed: bool,
) -> None:
    path = tmp_path / f"reconcile-{crash_point.value}.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    preparation = _preparation()
    reservation = store.reserve_profile_preparation(preparation)
    wrapped = WrappedProfileKey(KEK, BINDING, preparation.nonce, b"W" * 48)
    store.arm_crash_once(crash_point)

    with pytest.raises(KeyCatalogError) as ambiguous:
        store.publish_profile_key(reservation, preparation, wrapped)

    assert ambiguous.value.code is KeyCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN
    assert runtime.recovery_latch_path.exists()
    recovered = _open(path)
    recovered_store = SqliteKeyCatalog(recovered)
    with pytest.raises(SQLiteReadinessError):
        recovered_store.load_profile_key(BINDING)
    reconciled = recovered_store.reconcile_profile_key(BINDING)
    assert (reconciled == wrapped) is record_committed
    assert recovered.readiness.accepting_new_work is False
    assert recovered.recovery_latch_path.exists()
    recovered.close_cleanly()


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE key_catalog SET revision=999 WHERE singleton_id=1",
        "DELETE FROM key_catalog",
        "INSERT INTO key_catalog(singleton_id) VALUES(2)",
        "CREATE TABLE forbidden_recovery_write(value INTEGER)",
        "PRAGMA query_only=OFF",
    ],
)
def test_reconciliation_reader_rejects_all_mutation_and_has_no_commit(
    tmp_path: Path,
    statement: str,
) -> None:
    path = tmp_path / "read-only-reconciliation.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    runtime.abandon()
    recovered = _open(path)
    with recovered.reconciliation_reader() as reader:
        before = reader.execute(
            text("SELECT revision FROM key_catalog WHERE singleton_id=1")
        ).scalar_one()
        assert not hasattr(reader, "commit")
        with pytest.raises(RuntimeError, match="SELECT statements only"):
            reader.execute(text(statement))

    with recovered.reconciliation_reader() as reader:
        after = reader.execute(
            text("SELECT revision FROM key_catalog WHERE singleton_id=1")
        ).scalar_one()
    assert after == before
    assert recovered.readiness.accepting_new_work is False
    assert recovered.recovery_latch_path.exists()
    recovered.close_cleanly()


@pytest.mark.parametrize("corruption", ["extra_sentinel", "orphan_committed_profile"])
def test_reverse_ledger_orphans_are_corruption(
    tmp_path: Path,
    corruption: str,
) -> None:
    path = tmp_path / f"reverse-ledger-{corruption}.sqlite"
    _migrate(path)
    runtime = _open(path)
    store = SqliteKeyCatalog(runtime)
    _initialize(store)
    with runtime.unit_of_work() as uow:
        if corruption == "extra_sentinel":
            uow.session.execute(
                text(
                    "INSERT INTO key_nonce_reservations(reservation_id,catalog_id,"
                    "provider_instance_id,kek_id,kek_version,nonce,purpose,lifecycle,"
                    "usage_sequence,profile_id,profile_key_version) VALUES"
                    "(:reservation_id,:catalog_id,:provider,:kek_id,1,:nonce,'sentinel',"
                    "'reserved',2,NULL,NULL)"
                ),
                {
                    "reservation_id": str(OpaqueId.new()),
                    "catalog_id": str(IDENTITY.catalog_id),
                    "provider": str(KEK.provider_instance_id),
                    "kek_id": str(KEK.kek_id),
                    "nonce": b"x" * 12,
                },
            )
        else:
            uow.session.execute(
                text(
                    "INSERT INTO key_nonce_reservations(reservation_id,catalog_id,"
                    "provider_instance_id,kek_id,kek_version,nonce,purpose,lifecycle,"
                    "usage_sequence,profile_id,profile_key_version) VALUES"
                    "(:reservation_id,:catalog_id,:provider,:kek_id,1,:nonce,'profile',"
                    "'committed',2,:profile_id,1)"
                ),
                {
                    "reservation_id": str(OpaqueId.new()),
                    "catalog_id": str(IDENTITY.catalog_id),
                    "provider": str(KEK.provider_instance_id),
                    "kek_id": str(KEK.kek_id),
                    "nonce": b"x" * 12,
                    "profile_id": str(BINDING.profile_id),
                },
            )
        uow.session.execute(text("UPDATE key_catalog SET usage_reserved=2 WHERE singleton_id=1"))
        uow.commit()

    with pytest.raises(KeyCatalogError) as failure:
        store.load_catalog()
    assert failure.value.code is KeyCatalogFailureCode.CORRUPT
    assert runtime.recovery_latch_path.exists()
