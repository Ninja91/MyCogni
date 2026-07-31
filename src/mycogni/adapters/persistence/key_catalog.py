"""Strict normalized SQLite storage for the wrapped-profile-key catalog."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from enum import StrEnum
from functools import wraps
from threading import RLock
from typing import Any, cast

from sqlalchemy import text
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import SQLAlchemyError

from mycogni.adapters.persistence.durability import SQLiteRuntime
from mycogni.application.key_catalog import (
    KeyCatalogError,
    KeyCatalogFailureCode,
    KeyCatalogIdentity,
    KeyCatalogSnapshot,
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


class _CommitAmbiguous(RuntimeError):
    """Internal signal handled only after the UoW has fully unwound."""


class KeyCatalogCrashPoint(StrEnum):
    """Deterministic ambiguity injection points used by executable evidence."""

    BEFORE_COMMIT = "before_commit"
    AFTER_COMMIT = "after_commit"


def _latch_commit_ambiguity[**P, R](operation: Callable[P, R]) -> Callable[P, R]:
    @wraps(operation)
    def guarded(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return operation(*args, **kwargs)
        except _CommitAmbiguous:
            instance = cast("SqliteKeyCatalog", args[0])
            instance._latch_recovery()
            raise KeyCatalogError(KeyCatalogFailureCode.COMMIT_OUTCOME_UNKNOWN) from None
        except KeyCatalogError as error:
            if error.code in {
                KeyCatalogFailureCode.CORRUPT,
                KeyCatalogFailureCode.NONCE_REUSE,
            }:
                instance = cast("SqliteKeyCatalog", args[0])
                instance._latch_recovery()
            raise
        except SQLAlchemyError:
            instance = cast("SqliteKeyCatalog", args[0])
            instance._latch_recovery()
            raise KeyCatalogError(KeyCatalogFailureCode.UNAVAILABLE) from None

    return guarded


class SqliteKeyCatalog:
    """Serialize catalog changes through the one owned SQLite runtime."""

    def __init__(self, runtime: SQLiteRuntime) -> None:
        if type(runtime) is not SQLiteRuntime:
            raise TypeError("SQLite key catalog requires an owned SQLiteRuntime")
        self._runtime = runtime
        self._client_lock = RLock()
        self._crash_once: KeyCatalogCrashPoint | None = None

    def arm_crash_once(self, point: KeyCatalogCrashPoint) -> None:
        if type(point) is not KeyCatalogCrashPoint:
            raise TypeError("key catalog crash point must be exact")
        self._crash_once = point

    @_latch_commit_ambiguity
    def begin_initialization(
        self,
        identity: KeyCatalogIdentity,
        sentinel_nonce: bytes,
        source_commitment: bytes,
    ) -> OpaqueId:
        """Persist PREPARING and burn the sentinel nonce before sentinel AEAD."""
        if type(identity) is not KeyCatalogIdentity:
            raise TypeError("key catalog initialization requires an identity")
        if type(sentinel_nonce) is not bytes or len(sentinel_nonce) != 12:
            raise TypeError("key catalog initialization requires a 12-byte nonce")
        if type(source_commitment) is not bytes or len(source_commitment) != 32:
            raise TypeError("key catalog initialization requires a 32-byte source commitment")
        reservation_id = OpaqueId.new()
        with self._client_lock, self._runtime.unit_of_work() as uow:
            if self._catalog_row(uow.session) is not None:
                raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
            params = self._identity_params(identity)
            uow.session.execute(
                text(
                    "INSERT INTO key_catalog(singleton_id,schema_version,revision,state,"
                    "installation_id,catalog_id,sentinel_id,provider_kind,provider_instance_id,"
                    "kek_id,kek_version,usage_limit,usage_reserved,source_commitment) VALUES"
                    "(1,:schema_version,1,'preparing',:installation_id,:catalog_id,:sentinel_id,"
                    ":provider_kind,:provider_instance_id,:kek_id,:kek_version,:usage_limit,1,"
                    ":source_commitment)"
                ),
                {**params, "source_commitment": source_commitment},
            )
            uow.session.execute(
                text(
                    "INSERT INTO key_nonce_reservations(reservation_id,catalog_id,"
                    "provider_instance_id,kek_id,kek_version,nonce,purpose,lifecycle,usage_sequence,"
                    "profile_id,profile_key_version) VALUES(:reservation_id,:catalog_id,"
                    ":provider_instance_id,:kek_id,:kek_version,:nonce,'sentinel','reserved',1,NULL,NULL)"
                ),
                {**params, "reservation_id": str(reservation_id), "nonce": sentinel_nonce},
            )
            self._commit_or_latch(uow)
            return reservation_id

    @_latch_commit_ambiguity
    def finish_initialization(
        self, reservation_id: OpaqueId, sentinel: WrappedReadinessSentinel
    ) -> KeyCatalogSnapshot:
        """Publish the exact reserved sentinel and activate after a known commit."""
        if type(reservation_id) is not OpaqueId or type(sentinel) is not WrappedReadinessSentinel:
            raise TypeError("key catalog initialization requires exact records")
        with self._client_lock, self._runtime.unit_of_work() as uow:
            self._stage_initialization_finish(uow.session, reservation_id, sentinel)
            self._commit_or_latch(uow)
        return self.load_catalog()

    def load_initialization(self) -> tuple[OpaqueId, bytes, bytes]:
        """Load the sole PREPARING sentinel reservation for explicit admin resume."""
        with self._client_lock:
            try:
                with self._runtime.unit_of_work() as uow:
                    return self._load_initialization_record(uow.session)
            except KeyCatalogError as error:
                if error.code is KeyCatalogFailureCode.CORRUPT:
                    self._latch_recovery()
                raise
            except (TypeError, ValueError, SQLAlchemyError):
                self._latch_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT) from None

    def load_initialization_for_reconciliation(self) -> tuple[OpaqueId, bytes, bytes]:
        """Inspect the PREPARING reservation after a dirty process restart."""
        try:
            with self._client_lock, self._runtime.reconciliation_reader() as reader:
                return self._load_initialization_record(reader)
        except KeyCatalogError:
            raise
        except (TypeError, ValueError, SQLAlchemyError):
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT) from None

    def finish_initialization_for_reconciliation(
        self,
        reservation_id: OpaqueId,
        sentinel: WrappedReadinessSentinel,
    ) -> None:
        """CAS-finish only PREPARING initialization while the outer latch stays closed."""
        if type(reservation_id) is not OpaqueId or type(sentinel) is not WrappedReadinessSentinel:
            raise TypeError("key initialization reconciliation requires exact records")
        with self._client_lock:
            self._runtime._admit_reconciliation_work()
            try:
                with self._runtime.engine.begin() as connection:
                    self._runtime._assert_reconciliation_work()
                    self._stage_initialization_finish(connection, reservation_id, sentinel)
            except KeyCatalogError:
                raise
            except SQLAlchemyError:
                raise KeyCatalogError(KeyCatalogFailureCode.UNAVAILABLE) from None
            finally:
                self._runtime._release_application_work()

    def _load_initialization_record(self, source: Any) -> tuple[OpaqueId, bytes, bytes]:
        snapshot = self._load_snapshot(source)
        if snapshot.state is not KeyCatalogState.PREPARING:
            raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
        rows = (
            source.execute(
                text(
                    "SELECT reservation_id,nonce FROM key_nonce_reservations "
                    "WHERE purpose='sentinel' AND lifecycle='reserved'"
                )
            )
            .mappings()
            .all()
        )
        if len(rows) != 1:
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
        catalog_row = self._catalog_row(source)
        if catalog_row is None:
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
        return (
            self._opaque(rows[0]["reservation_id"]),
            self._exact_bytes(rows[0]["nonce"], 12),
            self._exact_bytes(catalog_row["source_commitment"], 32),
        )

    def _stage_initialization_finish(
        self,
        destination: Any,
        reservation_id: OpaqueId,
        sentinel: WrappedReadinessSentinel,
    ) -> None:
        snapshot = self._load_snapshot(destination)
        if snapshot.state is not KeyCatalogState.PREPARING or (
            sentinel.installation_id != snapshot.identity.installation_id
            or sentinel.catalog_id != snapshot.identity.catalog_id
            or sentinel.sentinel_id != snapshot.identity.sentinel_id
            or sentinel.kek_ref != snapshot.identity.active_kek
        ):
            raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
        reservation = (
            destination.execute(
                text("SELECT * FROM key_nonce_reservations WHERE reservation_id=:value"),
                {"value": str(reservation_id)},
            )
            .mappings()
            .one_or_none()
        )
        if (
            reservation is None
            or reservation["purpose"] != "sentinel"
            or reservation["lifecycle"] != "reserved"
            or bytes(reservation["nonce"]) != sentinel.nonce
        ):
            raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
        destination.execute(
            text(
                "INSERT INTO key_readiness_sentinel(singleton_id,catalog_id,sentinel_id,"
                "reservation_id,format_version,aad_version,suite,ciphertext) VALUES"
                "(1,:catalog_id,:sentinel_id,:reservation_id,:format_version,:aad_version,:suite,"
                ":ciphertext)"
            ),
            {
                "catalog_id": str(snapshot.identity.catalog_id),
                "sentinel_id": str(snapshot.identity.sentinel_id),
                "reservation_id": str(reservation_id),
                "format_version": sentinel.format_version,
                "aad_version": sentinel.aad_version,
                "suite": sentinel.suite,
                "ciphertext": sentinel.ciphertext,
            },
        )
        reservation_changed = cast(
            CursorResult[Any],
            destination.execute(
                text(
                    "UPDATE key_nonce_reservations SET lifecycle='committed' "
                    "WHERE reservation_id=:value AND lifecycle='reserved'"
                ),
                {"value": str(reservation_id)},
            ),
        )
        if reservation_changed.rowcount != 1:
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
        changed = cast(
            CursorResult[Any],
            destination.execute(
                text(
                    "UPDATE key_catalog SET state='active',revision=revision+1 "
                    "WHERE singleton_id=1 AND state='preparing' AND revision=:revision"
                ),
                {"revision": snapshot.revision},
            ),
        )
        if changed.rowcount != 1:
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)

    def load_catalog(self) -> KeyCatalogSnapshot:
        with self._client_lock:
            try:
                with self._runtime.unit_of_work() as uow:
                    return self._load_snapshot(uow.session)
            except KeyCatalogError as error:
                if error.code is KeyCatalogFailureCode.CORRUPT:
                    self._latch_recovery()
                raise
            except (TypeError, ValueError):
                self._latch_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT) from None
            except SQLAlchemyError:
                self._latch_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.UNAVAILABLE) from None

    def load_catalog_for_reconciliation(self) -> KeyCatalogSnapshot:
        """Inspect the strict catalog under an already-latched recovery runtime."""
        try:
            with self._client_lock, self._runtime.reconciliation_reader() as reader:
                return self._load_snapshot(reader)
        except KeyCatalogError:
            raise
        except (TypeError, ValueError, SQLAlchemyError):
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT) from None

    def reconcile_profile_key(self, binding: ProfileKeyBinding) -> WrappedProfileKey | None:
        """Report zero-or-one committed record without retrying or clearing recovery."""
        if type(binding) is not ProfileKeyBinding:
            raise TypeError("key catalog reconciliation requires a binding")
        try:
            with self._client_lock, self._runtime.reconciliation_reader() as reader:
                snapshot = self._load_snapshot(reader)
                if (
                    binding.installation_id != snapshot.identity.installation_id
                    or binding.catalog_schema_version != snapshot.identity.schema_version
                ):
                    raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
                row = self._profile_row(reader, binding)
                if row is None:
                    return None
                reservation = (
                    reader.execute(
                        text("SELECT * FROM key_nonce_reservations WHERE reservation_id=:value"),
                        {"value": row["reservation_id"]},
                    )
                    .mappings()
                    .one_or_none()
                )
                if reservation is None or reservation["lifecycle"] != "committed":
                    raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
                return WrappedProfileKey(
                    kek_ref=snapshot.identity.active_kek,
                    binding=binding,
                    nonce=self._exact_bytes(reservation["nonce"], 12),
                    ciphertext=self._exact_bytes(row["ciphertext"], 48),
                    format_version=self._exact_int(row["format_version"]),
                    aad_version=self._exact_int(row["aad_version"]),
                    suite=self._exact_str(row["suite"]),
                )
        except KeyCatalogError:
            raise
        except (TypeError, ValueError, SQLAlchemyError):
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT) from None

    @_latch_commit_ambiguity
    def reserve_profile_preparation(self, preparation: ProfileKeyPreparation) -> OpaqueId:
        if type(preparation) is not ProfileKeyPreparation:
            raise TypeError("key catalog reservation requires a preparation")
        binding = preparation.binding
        reservation_id = OpaqueId.new()
        with self._client_lock, self._runtime.unit_of_work() as uow:
            snapshot = self._load_snapshot(uow.session)
            self._assert_active_binding(snapshot, binding)
            if (
                self._profile_row(uow.session, binding) is not None
                or self._profile_reservation_row(uow.session, binding) is not None
            ):
                raise KeyCatalogError(KeyCatalogFailureCode.DUPLICATE_PROFILE_KEY)
            if (
                uow.session.execute(
                    text(
                        "SELECT 1 FROM key_nonce_reservations WHERE provider_instance_id=:provider "
                        "AND kek_id=:kek AND kek_version=:version AND nonce=:nonce"
                    ),
                    {
                        "provider": str(snapshot.identity.active_kek.provider_instance_id),
                        "kek": str(snapshot.identity.active_kek.kek_id),
                        "version": snapshot.identity.active_kek.kek_version,
                        "nonce": preparation.nonce,
                    },
                ).one_or_none()
                is not None
            ):
                raise KeyCatalogError(KeyCatalogFailureCode.NONCE_REUSE)
            catalog_row = self._catalog_row(uow.session)
            assert catalog_row is not None
            used = self._exact_int(catalog_row["usage_reserved"])
            if used >= snapshot.identity.usage_limit:
                raise KeyCatalogError(KeyCatalogFailureCode.USAGE_LIMIT)
            next_usage = used + 1
            uow.session.execute(
                text(
                    "INSERT INTO key_nonce_reservations"
                    "(reservation_id,catalog_id,provider_instance_id,kek_id,kek_version,nonce,"
                    "purpose,lifecycle,usage_sequence,profile_id,profile_key_version) "
                    "VALUES(:reservation_id,:catalog_id,:provider,:kek,:kek_version,:nonce,"
                    "'profile','reserved',:sequence,:profile_id,:profile_key_version)"
                ),
                {
                    "reservation_id": str(reservation_id),
                    "catalog_id": str(snapshot.identity.catalog_id),
                    "provider": str(snapshot.identity.active_kek.provider_instance_id),
                    "kek": str(snapshot.identity.active_kek.kek_id),
                    "kek_version": snapshot.identity.active_kek.kek_version,
                    "nonce": preparation.nonce,
                    "sequence": next_usage,
                    "profile_id": str(binding.profile_id),
                    "profile_key_version": binding.profile_key_version,
                },
            )
            changed = cast(
                CursorResult[Any],
                uow.session.execute(
                    text(
                        "UPDATE key_catalog SET usage_reserved=:used,revision=revision+1 "
                        "WHERE singleton_id=1 AND revision=:revision AND state='active'"
                    ),
                    {"used": next_usage, "revision": snapshot.revision},
                ),
            )
            if changed.rowcount != 1:
                raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
            self._commit_or_latch(uow)
            return reservation_id

    @_latch_commit_ambiguity
    def publish_profile_key(
        self,
        reservation_id: OpaqueId,
        preparation: ProfileKeyPreparation,
        wrapped: WrappedProfileKey,
    ) -> None:
        if type(reservation_id) is not OpaqueId:
            raise TypeError("key catalog publication requires a reservation ID")
        if type(preparation) is not ProfileKeyPreparation or type(wrapped) is not WrappedProfileKey:
            raise TypeError("key catalog publication requires exact key records")
        if wrapped.binding != preparation.binding or wrapped.nonce != preparation.nonce:
            raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
        with self._client_lock, self._runtime.unit_of_work() as uow:
            snapshot = self._load_snapshot(uow.session)
            self._assert_active_binding(snapshot, wrapped.binding)
            if wrapped.kek_ref != snapshot.identity.active_kek:
                raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
            reservation = (
                uow.session.execute(
                    text(
                        "SELECT * FROM key_nonce_reservations WHERE reservation_id=:reservation_id"
                    ),
                    {"reservation_id": str(reservation_id)},
                )
                .mappings()
                .one_or_none()
            )
            if reservation is None or not self._reservation_matches(
                reservation, snapshot, preparation, lifecycle="reserved"
            ):
                raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)
            if self._profile_row(uow.session, wrapped.binding) is not None:
                raise KeyCatalogError(KeyCatalogFailureCode.DUPLICATE_PROFILE_KEY)
            uow.session.execute(
                text(
                    "INSERT INTO wrapped_profile_keys"
                    "(profile_id,profile_key_version,catalog_schema_version,installation_id,"
                    "reservation_id,format_version,aad_version,suite,ciphertext) VALUES"
                    "(:profile_id,:profile_key_version,:catalog_schema_version,:installation_id,"
                    ":reservation_id,:format_version,:aad_version,:suite,:ciphertext)"
                ),
                {
                    "profile_id": str(wrapped.binding.profile_id),
                    "profile_key_version": wrapped.binding.profile_key_version,
                    "catalog_schema_version": wrapped.binding.catalog_schema_version,
                    "installation_id": str(wrapped.binding.installation_id),
                    "reservation_id": str(reservation_id),
                    "format_version": wrapped.format_version,
                    "aad_version": wrapped.aad_version,
                    "suite": wrapped.suite,
                    "ciphertext": wrapped.ciphertext,
                },
            )
            changed = cast(
                CursorResult[Any],
                uow.session.execute(
                    text(
                        "UPDATE key_nonce_reservations SET lifecycle='committed' "
                        "WHERE reservation_id=:reservation_id AND lifecycle='reserved'"
                    ),
                    {"reservation_id": str(reservation_id)},
                ),
            )
            if changed.rowcount != 1:
                raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
            uow.session.execute(
                text("UPDATE key_catalog SET revision=revision+1 WHERE singleton_id=1"),
            )
            self._commit_or_latch(uow)

    def load_profile_key(self, binding: ProfileKeyBinding) -> WrappedProfileKey | None:
        if type(binding) is not ProfileKeyBinding:
            raise TypeError("key catalog lookup requires a binding")
        with self._client_lock:
            try:
                with self._runtime.unit_of_work() as uow:
                    snapshot = self._load_snapshot(uow.session)
                    self._assert_active_binding(snapshot, binding)
                    row = self._profile_row(uow.session, binding)
                    if row is None:
                        return None
                    reservation = (
                        uow.session.execute(
                            text(
                                "SELECT * FROM key_nonce_reservations WHERE reservation_id=:value"
                            ),
                            {"value": row["reservation_id"]},
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if reservation is None or reservation["lifecycle"] != "committed":
                        raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
                    wrapped = WrappedProfileKey(
                        kek_ref=snapshot.identity.active_kek,
                        binding=binding,
                        nonce=self._exact_bytes(reservation["nonce"], 12),
                        ciphertext=self._exact_bytes(row["ciphertext"], 48),
                        format_version=self._exact_int(row["format_version"]),
                        aad_version=self._exact_int(row["aad_version"]),
                        suite=self._exact_str(row["suite"]),
                    )
                    return wrapped
            except KeyCatalogError as error:
                if error.code is KeyCatalogFailureCode.CORRUPT:
                    self._latch_recovery()
                raise
            except (TypeError, ValueError):
                self._latch_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT) from None
            except SQLAlchemyError:
                self._latch_recovery()
                raise KeyCatalogError(KeyCatalogFailureCode.UNAVAILABLE) from None

    @_latch_commit_ambiguity
    def require_recovery(self) -> None:
        """Persist the finite recovery state after an existing-install failure."""
        with self._client_lock, self._runtime.unit_of_work() as uow:
            snapshot = self._load_snapshot(uow.session)
            if snapshot.state is KeyCatalogState.RECOVERY_REQUIRED:
                return
            changed = cast(
                CursorResult[Any],
                uow.session.execute(
                    text(
                        "UPDATE key_catalog SET state='recovery_required',revision=revision+1 "
                        "WHERE singleton_id=1 AND revision=:revision"
                    ),
                    {"revision": snapshot.revision},
                ),
            )
            if changed.rowcount != 1:
                raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
            self._commit_or_latch(uow)

    def _load_snapshot(self, session: Any) -> KeyCatalogSnapshot:
        row = self._catalog_row(session)
        if row is None:
            raise KeyCatalogError(KeyCatalogFailureCode.NOT_INITIALIZED)
        active_kek = ActiveKekRef(
            provider_kind=self._exact_str(row["provider_kind"]),
            provider_instance_id=self._opaque(row["provider_instance_id"]),
            kek_id=self._opaque(row["kek_id"]),
            kek_version=self._exact_int(row["kek_version"]),
        )
        sentinel_row = (
            session.execute(
                text(
                    "SELECT s.*,n.nonce,n.lifecycle,n.purpose FROM key_readiness_sentinel s "
                    "JOIN key_nonce_reservations n ON n.reservation_id=s.reservation_id "
                    "WHERE s.singleton_id=1"
                )
            )
            .mappings()
            .one_or_none()
        )
        state = KeyCatalogState(self._exact_str(row["state"]))
        sentinel = None
        if sentinel_row is not None:
            if sentinel_row["lifecycle"] != "committed" or sentinel_row["purpose"] != "sentinel":
                raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
            sentinel = WrappedReadinessSentinel(
                kek_ref=active_kek,
                installation_id=self._opaque(row["installation_id"]),
                catalog_id=self._opaque(row["catalog_id"]),
                sentinel_id=self._opaque(sentinel_row["sentinel_id"]),
                nonce=self._exact_bytes(sentinel_row["nonce"], 12),
                ciphertext=self._exact_bytes(sentinel_row["ciphertext"], 48),
                format_version=self._exact_int(sentinel_row["format_version"]),
                aad_version=self._exact_int(sentinel_row["aad_version"]),
                suite=self._exact_str(sentinel_row["suite"]),
            )
        identity = KeyCatalogIdentity(
            installation_id=self._opaque(row["installation_id"]),
            catalog_id=self._opaque(row["catalog_id"]),
            sentinel_id=self._opaque(row["sentinel_id"]),
            active_kek=active_kek,
            usage_limit=self._exact_int(row["usage_limit"]),
            schema_version=self._exact_int(row["schema_version"]),
        )
        self._exact_bytes(row["source_commitment"], 32)
        self._validate_ledger(
            session,
            identity,
            usage_reserved=self._exact_int(row["usage_reserved"]),
        )
        return KeyCatalogSnapshot(
            identity=identity,
            state=state,
            revision=self._exact_int(row["revision"]),
            sentinel=sentinel,
        )

    @classmethod
    def _validate_ledger(
        cls,
        session: Any,
        identity: KeyCatalogIdentity,
        *,
        usage_reserved: int,
    ) -> None:
        """Reject counter drift, gaps, foreign domains, and broken record bindings."""
        aggregate = (
            session.execute(
                text(
                    "SELECT COUNT(*) AS total,MIN(usage_sequence) AS first_usage,"
                    "MAX(usage_sequence) AS last_usage,"
                    "SUM(CASE WHEN purpose='sentinel' THEN 1 ELSE 0 END) AS sentinel_rows,"
                    "SUM(CASE WHEN purpose='sentinel' AND usage_sequence=1 THEN 1 ELSE 0 END) "
                    "AS first_sentinel_rows,"
                    "SUM(CASE WHEN usage_sequence>1 AND purpose!='profile' THEN 1 ELSE 0 END) "
                    "AS later_non_profile_rows,"
                    "SUM(CASE WHEN catalog_id!=:catalog_id OR provider_instance_id!=:provider "
                    "OR kek_id!=:kek_id OR kek_version!=:kek_version THEN 1 ELSE 0 END) AS foreign_rows "
                    "FROM key_nonce_reservations"
                ),
                {
                    "catalog_id": str(identity.catalog_id),
                    "provider": str(identity.active_kek.provider_instance_id),
                    "kek_id": str(identity.active_kek.kek_id),
                    "kek_version": identity.active_kek.kek_version,
                },
            )
            .mappings()
            .one()
        )
        if (
            cls._exact_int(aggregate["total"]) != usage_reserved
            or cls._exact_int(aggregate["first_usage"]) != 1
            or cls._exact_int(aggregate["last_usage"]) != usage_reserved
            or cls._exact_int(aggregate["sentinel_rows"]) != 1
            or cls._exact_int(aggregate["first_sentinel_rows"]) != 1
            or cls._exact_int(aggregate["later_non_profile_rows"]) != 0
            or cls._exact_int(aggregate["foreign_rows"]) != 0
        ):
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
        invalid_wrapped = session.execute(
            text(
                "SELECT COUNT(*) FROM wrapped_profile_keys w "
                "LEFT JOIN key_nonce_reservations n ON n.reservation_id=w.reservation_id "
                "WHERE n.reservation_id IS NULL OR n.purpose!='profile' OR n.lifecycle!='committed' "
                "OR n.profile_id!=w.profile_id OR n.profile_key_version!=w.profile_key_version "
                "OR n.catalog_id!=:catalog_id OR n.provider_instance_id!=:provider "
                "OR n.kek_id!=:kek_id OR n.kek_version!=:kek_version "
                "OR w.installation_id!=:installation_id OR w.catalog_schema_version!=:schema_version"
            ),
            {
                "catalog_id": str(identity.catalog_id),
                "provider": str(identity.active_kek.provider_instance_id),
                "kek_id": str(identity.active_kek.kek_id),
                "kek_version": identity.active_kek.kek_version,
                "installation_id": str(identity.installation_id),
                "schema_version": identity.schema_version,
            },
        ).scalar_one()
        if cls._exact_int(invalid_wrapped) != 0:
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)
        orphan_committed = session.execute(
            text(
                "SELECT COUNT(*) FROM key_nonce_reservations n "
                "LEFT JOIN wrapped_profile_keys w ON w.reservation_id=n.reservation_id "
                "WHERE n.purpose='profile' AND n.lifecycle='committed' "
                "AND (w.reservation_id IS NULL OR w.profile_id!=n.profile_id "
                "OR w.profile_key_version!=n.profile_key_version)"
            )
        ).scalar_one()
        if cls._exact_int(orphan_committed) != 0:
            raise KeyCatalogError(KeyCatalogFailureCode.CORRUPT)

    @staticmethod
    def _catalog_row(session: Any) -> Any:
        return (
            session.execute(text("SELECT * FROM key_catalog WHERE singleton_id=1"))
            .mappings()
            .one_or_none()
        )

    @staticmethod
    def _profile_row(session: Any, binding: ProfileKeyBinding) -> Any:
        return (
            session.execute(
                text(
                    "SELECT * FROM wrapped_profile_keys WHERE profile_id=:profile_id "
                    "AND profile_key_version=:profile_key_version"
                ),
                {
                    "profile_id": str(binding.profile_id),
                    "profile_key_version": binding.profile_key_version,
                },
            )
            .mappings()
            .one_or_none()
        )

    @staticmethod
    def _profile_reservation_row(session: Any, binding: ProfileKeyBinding) -> Any:
        return (
            session.execute(
                text(
                    "SELECT reservation_id,lifecycle FROM key_nonce_reservations "
                    "WHERE purpose='profile' AND profile_id=:profile_id "
                    "AND profile_key_version=:profile_key_version"
                ),
                {
                    "profile_id": str(binding.profile_id),
                    "profile_key_version": binding.profile_key_version,
                },
            )
            .mappings()
            .one_or_none()
        )

    @staticmethod
    def _identity_params(identity: KeyCatalogIdentity) -> dict[str, object]:
        return {
            "schema_version": identity.schema_version,
            "installation_id": str(identity.installation_id),
            "catalog_id": str(identity.catalog_id),
            "sentinel_id": str(identity.sentinel_id),
            "provider_kind": identity.active_kek.provider_kind,
            "provider_instance_id": str(identity.active_kek.provider_instance_id),
            "kek_id": str(identity.active_kek.kek_id),
            "kek_version": identity.active_kek.kek_version,
            "usage_limit": identity.usage_limit,
        }

    @staticmethod
    def _assert_active_binding(snapshot: KeyCatalogSnapshot, binding: ProfileKeyBinding) -> None:
        if snapshot.state is not KeyCatalogState.ACTIVE:
            raise KeyCatalogError(KeyCatalogFailureCode.RECOVERY_REQUIRED)
        if (
            binding.installation_id != snapshot.identity.installation_id
            or binding.catalog_schema_version != snapshot.identity.schema_version
        ):
            raise KeyCatalogError(KeyCatalogFailureCode.IDENTITY_MISMATCH)

    @staticmethod
    def _reservation_matches(
        row: Any,
        snapshot: KeyCatalogSnapshot,
        preparation: ProfileKeyPreparation,
        *,
        lifecycle: str,
    ) -> bool:
        binding = preparation.binding
        return (
            row["catalog_id"] == str(snapshot.identity.catalog_id)
            and row["provider_instance_id"]
            == str(snapshot.identity.active_kek.provider_instance_id)
            and row["kek_id"] == str(snapshot.identity.active_kek.kek_id)
            and row["kek_version"] == snapshot.identity.active_kek.kek_version
            and bytes(row["nonce"]) == preparation.nonce
            and row["purpose"] == "profile"
            and row["lifecycle"] == lifecycle
            and row["profile_id"] == str(binding.profile_id)
            and row["profile_key_version"] == binding.profile_key_version
        )

    @staticmethod
    def _opaque(value: object) -> OpaqueId:
        if type(value) is not str:
            raise ValueError("invalid catalog identifier")
        return OpaqueId.parse(value)

    @staticmethod
    def _exact_int(value: object) -> int:
        if type(value) is not int:
            raise ValueError("invalid catalog integer")
        return value

    @staticmethod
    def _exact_str(value: object) -> str:
        if type(value) is not str:
            raise ValueError("invalid catalog string")
        return value

    @staticmethod
    def _exact_bytes(value: object, length: int) -> bytes:
        if type(value) is not bytes or len(value) != length:
            raise ValueError("invalid catalog bytes")
        return value

    def _commit_or_latch(self, uow: Any) -> None:
        if self._crash_once is KeyCatalogCrashPoint.BEFORE_COMMIT:
            self._crash_once = None
            raise _CommitAmbiguous
        try:
            uow.commit()
        except BaseException:
            raise _CommitAmbiguous from None
        if self._crash_once is KeyCatalogCrashPoint.AFTER_COMMIT:
            self._crash_once = None
            raise _CommitAmbiguous

    def _latch_recovery(self) -> None:
        with suppress(BaseException):
            self._runtime.abandon()
