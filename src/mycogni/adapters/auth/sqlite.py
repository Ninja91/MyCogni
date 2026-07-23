"""Restart-durable SQLite adapter for the accepted auth decision protocol.

The persisted document is a strict, versioned encoding of finite decision state.
It contains opaque identifiers, fixed-size secret digests and policy metadata, but
never an ``OpaqueCredential`` or raw credential material. Every mutating decision
reloads and commits the complete state under the single-owner runtime's
``BEGIN IMMEDIATE`` boundary so concurrent clients cannot both consume one-use
authority. A second database-owning process remains unsupported and is rejected
by ``SQLiteRuntime``.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime
from enum import Enum, StrEnum
from threading import RLock
from typing import Any, TypeVar, cast

from sqlalchemy import text
from sqlalchemy.engine import CursorResult

from mycogni.adapters.auth.volatile import VolatileAuthDecisionStore
from mycogni.adapters.persistence.durability import SQLiteRuntime
from mycogni.application.auth import AuthDecisionStore, AuthStateSnapshotV1
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    ActorRecord,
    AuthDenial,
    AuthorityGrant,
    AuthOutcome,
    AuthPurpose,
    AuthScope,
    BootstrapDecision,
    BootstrapIssue,
    BootstrapRecord,
    CompositionBindingRecord,
    GrantProvenanceRecord,
    OpaqueCredential,
    RecoveryIssue,
    RecoveryRecord,
    ReprovisionCeremonyIssue,
    ReprovisionCeremonyRecord,
    RootCapability,
    RootCapabilityIssue,
    RootCapabilityRecord,
    RootPurpose,
    SecretDigest,
    SessionIssue,
    SessionRecord,
    StepUpRecord,
)

_STATE_SCHEMA_VERSION = 1
_T = TypeVar("_T")


class DurableAuthCrashPoint(StrEnum):
    """Test-only transaction boundaries; never a runtime retry policy."""

    BEFORE_COMMIT = "before_commit"
    AFTER_COMMIT = "after_commit"


class AuthCommitOutcomeUnknown(RuntimeError):
    """Commit status or credential delivery is unknown; reconciliation is required."""


class AuthStateCorrupt(RuntimeError):
    """Persisted auth state is malformed; rendering never includes stored content."""


class _CommitAmbiguous(RuntimeError):
    """Internal marker stripped before crossing the adapter boundary."""


_RECORD_TYPES: dict[str, type[Any]] = {
    cls.__name__: cls
    for cls in (
        ActorRecord,
        AuthorityGrant,
        BootstrapRecord,
        GrantProvenanceRecord,
        RecoveryRecord,
        RootCapabilityRecord,
        SessionRecord,
        StepUpRecord,
        CompositionBindingRecord,
        ReprovisionCeremonyRecord,
    )
}

# This is the persistence-owned V1 wire contract.  Do not derive it from the
# current operational dataclasses: changing those classes must not silently
# redefine already-written schema-version 1 documents.
_V1_RECORD_FIELDS: dict[str, tuple[str, ...]] = {
    "ActorRecord": (
        "actor_id",
        "represented_profile_id",
        "epoch",
        "last_observed_utc",
        "initialized",
    ),
    "AuthorityGrant": (
        "actor_id",
        "represented_profile_id",
        "session_id",
        "authority_evidence_id",
        "purpose",
        "scopes",
        "not_before_utc",
        "expires_at_utc",
        "epoch",
    ),
    "BootstrapRecord": (
        "handle",
        "actor_id",
        "represented_profile_id",
        "digest",
        "not_before_utc",
        "expires_at_utc",
        "attempts_remaining",
        "root_capability_id",
        "root_purpose",
        "consumed",
        "retired_at_utc",
    ),
    "CompositionBindingRecord": (
        "installation_id",
        "operator_handle",
        "operator_digest",
        "service_handle",
        "service_digest",
    ),
    "GrantProvenanceRecord": ("grant", "used_at_utc"),
    "RecoveryRecord": (
        "handle",
        "actor_id",
        "represented_profile_id",
        "digest",
        "epoch",
        "not_before_utc",
        "expires_at_utc",
        "attempts_remaining",
        "consumed",
        "retired_at_utc",
    ),
    "ReprovisionCeremonyRecord": (
        "handle",
        "digest",
        "bootstrap_handle",
        "installation_id",
        "service_handle",
        "expires_at_utc",
        "replay_seconds",
        "terminal_at_utc",
        "terminal_denial",
    ),
    "RootCapabilityRecord": (
        "handle",
        "installation_id",
        "actor_id",
        "represented_profile_id",
        "purpose",
        "digest",
        "consumed",
        "retired_at_utc",
    ),
    "SessionRecord": (
        "handle",
        "actor_id",
        "represented_profile_id",
        "digest",
        "epoch",
        "not_before_utc",
        "expires_at_utc",
        "revoked",
        "retired_at_utc",
    ),
    "StepUpRecord": (
        "handle",
        "actor_id",
        "represented_profile_id",
        "session_id",
        "digest",
        "epoch",
        "purpose",
        "scopes",
        "not_before_utc",
        "expires_at_utc",
        "attempts_remaining",
        "consumed",
        "retired_at_utc",
    ),
}
_V1_RECORD_NAMES_BY_TYPE = {record_type: name for name, record_type in _RECORD_TYPES.items()}

_ENUM_TYPES: dict[str, type[Enum]] = {
    enum_type.__name__: enum_type for enum_type in (AuthDenial, AuthPurpose, AuthScope, RootPurpose)
}
_V1_ENUM_VALUES: dict[str, frozenset[str]] = {
    "AuthDenial": frozenset(
        {
            "non_interactive",
            "invalid_proof",
            "attempts_exhausted",
            "replayed",
            "expired",
            "not_yet_valid",
            "clock_rollback",
            "session_not_found",
            "revoked",
            "wrong_actor",
            "wrong_profile",
            "wrong_installation",
            "wrong_session",
            "wrong_purpose",
            "scope_widening",
            "stale_epoch",
            "malformed_credential",
            "operator_declined",
            "output_interrupted",
            "capacity_exhausted",
        }
    ),
    "AuthPurpose": frozenset(
        {
            "setup_authority_change",
            "external_action_resume",
            "exception_submission",
            "key_recovery_change",
            "profile_deletion",
            "destructive_restore",
            "all_session_revoke",
        }
    ),
    "AuthScope": frozenset(
        {
            "change_setup_authority",
            "resume_external_actions",
            "submit_exception",
            "change_key_recovery",
            "delete_profile",
            "restore_destructively",
            "revoke_all_sessions",
        }
    ),
    "RootPurpose": frozenset({"initial_bootstrap", "emergency_revoke", "reprovision"}),
}


def _encode(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is OpaqueId:
        return {"type": "opaque_id", "value": str(value)}
    if type(value) is SecretDigest:
        return {
            "type": "secret_digest",
            "value": base64.b64encode(value.value).decode("ascii"),
        }
    if type(value) is datetime:
        return {"type": "utc_datetime", "value": value.isoformat()}
    if isinstance(value, Enum) and type(value).__name__ in _ENUM_TYPES:
        enum_name = type(value).__name__
        if value.value not in _V1_ENUM_VALUES[enum_name]:
            raise TypeError("auth state contains an enum value outside the V1 schema")
        return {"type": "enum", "name": enum_name, "value": value.value}
    if type(value) is frozenset:
        return {"type": "frozenset", "items": sorted((_encode(item) for item in value), key=str)}
    record_name = _V1_RECORD_NAMES_BY_TYPE.get(type(value))
    if record_name is not None:
        return {
            "type": "record",
            "name": record_name,
            "fields": {
                name: _encode(getattr(value, name)) for name in _V1_RECORD_FIELDS[record_name]
            },
        }
    raise TypeError("auth state contains a non-canonical or secret-bearing value")


def _decode(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is not dict or type(value.get("type")) is not str:
        raise ValueError("auth state contains malformed canonical data")
    kind = value["type"]
    if kind == "opaque_id":
        if set(value) != {"type", "value"} or type(value["value"]) is not str:
            raise ValueError("auth state opaque ID encoding is not canonical")
        return OpaqueId.parse(value["value"])
    if kind == "secret_digest":
        if set(value) != {"type", "value"} or type(value["value"]) is not str:
            raise ValueError("auth state digest encoding is not canonical")
        raw = base64.b64decode(value["value"], validate=True)
        return SecretDigest(raw)
    if kind == "utc_datetime":
        if set(value) != {"type", "value"} or type(value["value"]) is not str:
            raise ValueError("auth state datetime encoding is not canonical")
        parsed = datetime.fromisoformat(value["value"])
        return parsed
    if kind == "enum":
        if set(value) != {"type", "name", "value"} or type(value.get("value")) is not str:
            raise ValueError("auth state enum encoding is not canonical")
        enum_name = value.get("name")
        if type(enum_name) is not str:
            raise ValueError("auth state contains an invalid enum name")
        enum_type = _ENUM_TYPES.get(enum_name)
        if enum_type is None or value["value"] not in _V1_ENUM_VALUES.get(enum_name, frozenset()):
            raise ValueError("auth state contains an unknown enum")
        return enum_type(value["value"])
    if kind == "frozenset":
        if set(value) != {"type", "items"} or type(value["items"]) is not list:
            raise ValueError("auth state set encoding is not canonical")
        return frozenset(_decode(item) for item in value["items"])
    if kind == "record":
        if set(value) != {"type", "name", "fields"}:
            raise ValueError("auth state record encoding is not canonical")
        record_name = value.get("name")
        if type(record_name) is not str:
            raise ValueError("auth state contains an invalid record name")
        record_type = _RECORD_TYPES.get(record_name)
        field_values = value.get("fields")
        if record_type is None or type(field_values) is not dict:
            raise ValueError("auth state contains an unknown record")
        expected = set(_V1_RECORD_FIELDS[record_name])
        if set(field_values) != expected:
            raise ValueError("auth state record fields are not canonical")
        return record_type(**{name: _decode(item) for name, item in field_values.items()})
    raise ValueError("auth state contains an unknown canonical type")


def _snapshot(store: VolatileAuthDecisionStore) -> str:
    snapshot = store.export_durable_state_v1()
    state: dict[str, dict[OpaqueId, object]] = {
        "actors": {item.actor_id: item for item in snapshot.actors},
        "installation_actors": dict(snapshot.installation_actors),
        "roots": {item.handle: item for item in snapshot.roots},
        "bootstraps": {item.handle: item for item in snapshot.bootstraps},
        "sessions": {item.handle: item for item in snapshot.sessions},
        "recoveries": {item.handle: item for item in snapshot.recoveries},
        "step_ups": {item.handle: item for item in snapshot.step_ups},
        "grant_provenance": {
            item.grant.authority_evidence_id: item for item in snapshot.grant_provenance
        },
        "composition_bindings": {
            item.installation_id: item for item in snapshot.composition_bindings
        },
        "reprovision_ceremonies": {item.handle: item for item in snapshot.reprovision_ceremonies},
    }
    canonical = {
        name: [
            [_encode(key), _encode(item)]
            for key, item in sorted(values.items(), key=lambda pair: str(pair[0]))
        ]
        for name, values in state.items()
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    if "auth_secret" in payload or "OpaqueCredential" in payload or "Sensitive" in payload:
        raise RuntimeError("auth persistence rejected secret-bearing state")
    return payload


def _reject_duplicate_object_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    decoded: dict[str, object] = {}
    for key, value in pairs:
        if key in decoded:
            raise ValueError("auth state contains a duplicate object key")
        decoded[key] = value
    return decoded


def _restore_canonical(payload: str) -> VolatileAuthDecisionStore:
    parsed = json.loads(payload, object_pairs_hook=_reject_duplicate_object_keys)
    if type(parsed) is not dict:
        raise ValueError("auth state document must be an object")
    expected = {
        "actors",
        "installation_actors",
        "roots",
        "bootstraps",
        "sessions",
        "recoveries",
        "step_ups",
        "grant_provenance",
        "composition_bindings",
        "reprovision_ceremonies",
    }
    if set(parsed) != expected:
        raise ValueError("auth state document fields are not canonical")
    collection_types: dict[str, tuple[type[object], str | None]] = {
        "actors": (ActorRecord, "actor_id"),
        "installation_actors": (OpaqueId, None),
        "roots": (RootCapabilityRecord, "handle"),
        "bootstraps": (BootstrapRecord, "handle"),
        "sessions": (SessionRecord, "handle"),
        "recoveries": (RecoveryRecord, "handle"),
        "step_ups": (StepUpRecord, "handle"),
        "grant_provenance": (GrantProvenanceRecord, "grant.authority_evidence_id"),
        "composition_bindings": (CompositionBindingRecord, "installation_id"),
        "reprovision_ceremonies": (ReprovisionCeremonyRecord, "handle"),
    }
    decoded: dict[str, list[tuple[OpaqueId, object]]] = {}
    for name, pairs in parsed.items():
        if type(pairs) is not list:
            raise ValueError("auth state collection must be a list")
        restored: dict[OpaqueId, object] = {}
        item_type, key_attribute = collection_types[name]
        for pair in pairs:
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("auth state entry must be a key/value pair")
            key, item = _decode(pair[0]), _decode(pair[1])
            if type(key) is not OpaqueId or key in restored:
                raise ValueError("auth state key is invalid or duplicated")
            if type(item) is not item_type:
                raise ValueError("auth state collection contains the wrong record type")
            if key_attribute is not None:
                actual: object = item
                for attribute in key_attribute.split("."):
                    actual = getattr(actual, attribute)
                if actual != key:
                    raise ValueError("auth state key does not match its record handle")
            restored[key] = item
        decoded[name] = list(restored.items())
    snapshot = AuthStateSnapshotV1(
        actors=tuple(cast(ActorRecord, item) for _key, item in decoded["actors"]),
        installation_actors=tuple(
            (key, cast(OpaqueId, item)) for key, item in decoded["installation_actors"]
        ),
        roots=tuple(cast(RootCapabilityRecord, item) for _key, item in decoded["roots"]),
        bootstraps=tuple(cast(BootstrapRecord, item) for _key, item in decoded["bootstraps"]),
        sessions=tuple(cast(SessionRecord, item) for _key, item in decoded["sessions"]),
        recoveries=tuple(cast(RecoveryRecord, item) for _key, item in decoded["recoveries"]),
        step_ups=tuple(cast(StepUpRecord, item) for _key, item in decoded["step_ups"]),
        grant_provenance=tuple(
            cast(GrantProvenanceRecord, item) for _key, item in decoded["grant_provenance"]
        ),
        composition_bindings=tuple(
            cast(CompositionBindingRecord, item) for _key, item in decoded["composition_bindings"]
        ),
        reprovision_ceremonies=tuple(
            cast(ReprovisionCeremonyRecord, item)
            for _key, item in decoded["reprovision_ceremonies"]
        ),
    )
    return VolatileAuthDecisionStore.from_durable_state_v1(snapshot)


def _restore(payload: str) -> VolatileAuthDecisionStore:
    try:
        return _restore_canonical(payload)
    except (KeyError, TypeError, ValueError):
        raise AuthStateCorrupt("persisted auth decision state is corrupt") from None


def _authority_registry(store: VolatileAuthDecisionStore) -> list[dict[str, str]]:
    registry: dict[OpaqueId, tuple[str, OpaqueId]] = {}

    def register(handle: OpaqueId, kind: str, installation_id: OpaqueId) -> None:
        if handle in registry:
            raise RuntimeError("auth authority handle is not globally unique")
        registry[handle] = (kind, installation_id)

    snapshot = store.export_durable_state_v1()
    for root in snapshot.roots:
        register(root.handle, "root", root.installation_id)
    for binding in snapshot.composition_bindings:
        register(binding.operator_handle, "operator", binding.installation_id)
        register(binding.service_handle, "service", binding.installation_id)
    return [
        {"handle": str(handle), "authority_kind": kind, "installation_id": str(installation_id)}
        for handle, (kind, installation_id) in sorted(
            registry.items(), key=lambda pair: str(pair[0])
        )
    ]


class SqliteAuthDecisionStore:
    """Serialize every auth decision through one SQLite writer transaction."""

    def __init__(self, runtime: SQLiteRuntime) -> None:
        if type(runtime) is not SQLiteRuntime:
            raise TypeError("SQLite auth store requires an owned SQLiteRuntime")
        self._runtime = runtime
        self._client_lock = RLock()
        self._crash_once: DurableAuthCrashPoint | None = None

    def arm_crash_once(self, point: DurableAuthCrashPoint) -> None:
        """Inject a bounded test failure without persisting the injection control."""
        if type(point) is not DurableAuthCrashPoint:
            raise TypeError("durable auth crash point must be exact")
        self._crash_once = point

    def _crash_if_armed(self, point: DurableAuthCrashPoint) -> None:
        if self._crash_once is point:
            self._crash_once = None
            if point is DurableAuthCrashPoint.AFTER_COMMIT:
                raise AuthCommitOutcomeUnknown(
                    "auth decision outcome is unknown; do not retry one-use authority"
                )
            raise RuntimeError("synthetic auth failure before commit")

    def _decision(self, operation: Callable[[VolatileAuthDecisionStore], _T]) -> _T:
        with self._client_lock:
            try:
                return self._decision_locked(operation)
            except AuthStateCorrupt:
                self._latch_recovery()
                raise
            except (_CommitAmbiguous, AuthCommitOutcomeUnknown):
                self._latch_recovery()
                raise AuthCommitOutcomeUnknown(
                    "auth decision outcome is unknown; do not retry; reconciliation is required"
                ) from None

    def _read(self, operation: Callable[[VolatileAuthDecisionStore], _T]) -> _T:
        with self._client_lock:
            try:
                with self._runtime.unit_of_work() as unit_of_work:
                    store, _revision, _exists = self._load_state(unit_of_work.session)
                    return operation(store)
            except AuthStateCorrupt:
                self._latch_recovery()
                raise

    def _latch_recovery(self) -> None:
        with suppress(BaseException):
            self._runtime.abandon()

    @staticmethod
    def _load_row(session: Any) -> Any:
        return (
            session.execute(
                text(
                    "SELECT schema_version, revision, state_json "
                    "FROM auth_decision_state WHERE singleton_id=1"
                )
            )
            .mappings()
            .one_or_none()
        )

    @classmethod
    def _load_state(cls, session: Any) -> tuple[VolatileAuthDecisionStore, int, bool]:
        """Load and validate the exact supported row for both reads and decisions."""
        row = cls._load_row(session)
        if row is None:
            return VolatileAuthDecisionStore(), 0, False
        if (
            type(row["schema_version"]) is not int
            or row["schema_version"] != _STATE_SCHEMA_VERSION
            or type(row["revision"]) is not int
            or row["revision"] < 1
            or type(row["state_json"]) is not str
        ):
            raise AuthStateCorrupt("persisted auth decision state is corrupt")
        store = _restore(row["state_json"])
        cls._validate_authority_registry(session, store)
        return store, row["revision"], True

    @staticmethod
    def _validate_authority_registry(session: Any, store: VolatileAuthDecisionStore) -> None:
        expected = {
            (item["handle"], item["authority_kind"], item["installation_id"])
            for item in _authority_registry(store)
        }
        rows = session.execute(
            text("SELECT handle, authority_kind, installation_id FROM auth_authority_handles")
        ).all()
        actual = {(row.handle, row.authority_kind, row.installation_id) for row in rows}
        if actual != expected:
            raise AuthStateCorrupt("persisted auth decision state is corrupt")

    def _decision_locked(self, operation: Callable[[VolatileAuthDecisionStore], _T]) -> _T:
        # SQLiteRuntime admits one owned application UoW and starts it with
        # BEGIN IMMEDIATE. A commit exception returns no newly issued material;
        # callers must treat it as outcome-unknown and must not auto-retry.
        with self._runtime.unit_of_work() as unit_of_work:
            store, revision, exists = self._load_state(unit_of_work.session)
            result = operation(store)
            payload = _snapshot(store)
            authorities = _authority_registry(store)
            if not exists:
                changed = cast(
                    CursorResult[Any],
                    unit_of_work.session.execute(
                        text(
                            "INSERT INTO auth_decision_state"
                            "(singleton_id,schema_version,revision,state_json) "
                            "VALUES(1,:schema_version,1,:state_json)"
                        ),
                        {"schema_version": _STATE_SCHEMA_VERSION, "state_json": payload},
                    ),
                )
                if changed.rowcount != 1:
                    raise RuntimeError("auth decision state revision changed unexpectedly")
            else:
                changed = cast(
                    CursorResult[Any],
                    unit_of_work.session.execute(
                        text(
                            "UPDATE auth_decision_state SET revision=:next_revision, "
                            "state_json=:state_json WHERE singleton_id=1 AND revision=:revision"
                        ),
                        {
                            "next_revision": revision + 1,
                            "state_json": payload,
                            "revision": revision,
                        },
                    ),
                )
                if changed.rowcount != 1:
                    raise RuntimeError("auth decision state revision changed unexpectedly")
            unit_of_work.session.execute(text("DELETE FROM auth_authority_handles"))
            if authorities:
                unit_of_work.session.execute(
                    text(
                        "INSERT INTO auth_authority_handles"
                        "(handle,authority_kind,installation_id) "
                        "VALUES(:handle,:authority_kind,:installation_id)"
                    ),
                    authorities,
                )
            self._crash_if_armed(DurableAuthCrashPoint.BEFORE_COMMIT)
            try:
                unit_of_work.commit()
            except BaseException:
                raise _CommitAmbiguous from None
            self._crash_if_armed(DurableAuthCrashPoint.AFTER_COMMIT)
            return result

    def initialize_installation(
        self,
        *,
        installation_id: OpaqueId,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        records: tuple[RootCapabilityRecord, ...],
        operator_authority: RootCapabilityIssue,
        service_identity: RootCapabilityIssue,
        now: datetime,
    ) -> None:
        self._decision(
            lambda store: store.initialize_installation(
                installation_id=installation_id,
                actor_id=actor_id,
                represented_profile_id=represented_profile_id,
                records=records,
                operator_authority=operator_authority,
                service_identity=service_identity,
                now=now,
            )
        )

    def create_root_bootstrap(
        self,
        root: RootCapability,
        root_digest: SecretDigest,
        record: BootstrapRecord,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]:
        return self._decision(
            lambda store: store.create_root_bootstrap(root, root_digest, record, now)
        )

    def create_authenticated_bootstrap(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        record: BootstrapRecord,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]:
        return self._decision(
            lambda store: store.create_authenticated_bootstrap(
                session, session_digest, grant, record, now
            )
        )

    def create_reprovision_bootstrap(
        self,
        reprovision: OpaqueCredential,
        reprovision_digest: SecretDigest,
        issue: BootstrapIssue,
        now: datetime,
    ) -> AuthOutcome[BootstrapRecord]:
        return self._decision(
            lambda store: store.create_reprovision_bootstrap(
                reprovision, reprovision_digest, issue, now
            )
        )

    def cancel_bootstrap(self, handle: OpaqueId, now: datetime) -> None:
        self._decision(lambda store: store.cancel_bootstrap(handle, now))

    def exchange_bootstrap(
        self,
        handle: OpaqueId,
        presented_digest: SecretDigest,
        now: datetime,
        session: SessionRecord,
        recovery: RecoveryRecord,
        replacement_reprovision: RootCapabilityIssue,
    ) -> AuthOutcome[BootstrapDecision]:
        return self._decision(
            lambda store: store.exchange_bootstrap(
                handle, presented_digest, now, session, recovery, replacement_reprovision
            )
        )

    def create_reprovision_ceremony(
        self,
        service_identity: OpaqueCredential,
        service_digest: SecretDigest,
        operator_identity: OpaqueCredential,
        operator_digest: SecretDigest,
        bootstrap_handle: OpaqueId,
        issue: ReprovisionCeremonyIssue,
        now: datetime,
        *,
        active_capacity: int,
        tombstone_capacity: int,
        replay_seconds: int,
    ) -> AuthOutcome[OpaqueId]:
        return self._decision(
            lambda store: store.create_reprovision_ceremony(
                service_identity,
                service_digest,
                operator_identity,
                operator_digest,
                bootstrap_handle,
                issue,
                now,
                active_capacity=active_capacity,
                tombstone_capacity=tombstone_capacity,
                replay_seconds=replay_seconds,
            )
        )

    def exchange_reprovision_bootstrap(
        self,
        handle: OpaqueId,
        presented_digest: SecretDigest,
        service_identity: OpaqueCredential,
        service_digest: SecretDigest,
        ceremony: OpaqueCredential,
        ceremony_digest: SecretDigest,
        now: datetime,
        session: SessionRecord,
        recovery: RecoveryRecord,
        replacement_reprovision: RootCapabilityIssue,
        *,
        tombstone_capacity: int,
        replay_seconds: int,
    ) -> AuthOutcome[BootstrapDecision]:
        return self._decision(
            lambda store: store.exchange_reprovision_bootstrap(
                handle,
                presented_digest,
                service_identity,
                service_digest,
                ceremony,
                ceremony_digest,
                now,
                session,
                recovery,
                replacement_reprovision,
                tombstone_capacity=tombstone_capacity,
                replay_seconds=replay_seconds,
            )
        )

    def reprovision_ceremony_counts(self, service_handle: OpaqueId) -> dict[str, int]:
        return self._read(lambda store: store.reprovision_ceremony_counts(service_handle))

    def authenticate_session(
        self,
        credential: OpaqueCredential,
        presented_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[SessionRecord]:
        return self._decision(
            lambda store: store.authenticate_session(credential, presented_digest, now)
        )

    def create_step_up(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        now: datetime,
        challenge: StepUpRecord,
    ) -> AuthOutcome[StepUpRecord]:
        return self._decision(
            lambda store: store.create_step_up(session, session_digest, now, challenge)
        )

    def consume_step_up(
        self,
        challenge: OpaqueCredential,
        challenge_digest: SecretDigest,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        actor_id: OpaqueId,
        represented_profile_id: OpaqueId,
        purpose: AuthPurpose,
        scopes: frozenset[AuthScope],
        now: datetime,
    ) -> AuthOutcome[StepUpRecord]:
        return self._decision(
            lambda store: store.consume_step_up(
                challenge,
                challenge_digest,
                session,
                session_digest,
                actor_id,
                represented_profile_id,
                purpose,
                scopes,
                now,
            )
        )

    def rotate_session(
        self,
        current: OpaqueCredential,
        current_digest: SecretDigest,
        now: datetime,
        replacement: SessionRecord,
    ) -> AuthOutcome[SessionRecord]:
        return self._decision(
            lambda store: store.rotate_session(current, current_digest, now, replacement)
        )

    def revoke_session(
        self,
        current: OpaqueCredential,
        current_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[OpaqueId]:
        return self._decision(lambda store: store.revoke_session(current, current_digest, now))

    def renew_recovery(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        replacement: RecoveryRecord,
        now: datetime,
    ) -> AuthOutcome[RecoveryRecord]:
        return self._decision(
            lambda store: store.renew_recovery(session, session_digest, grant, replacement, now)
        )

    def revoke_all_authenticated(
        self,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        grant: AuthorityGrant,
        replacement: RecoveryRecord,
        now: datetime,
    ) -> AuthOutcome[RecoveryRecord]:
        return self._decision(
            lambda store: store.revoke_all_authenticated(
                session, session_digest, grant, replacement, now
            )
        )

    def emergency_revoke(
        self,
        root: RootCapability,
        root_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[int]:
        return self._decision(lambda store: store.emergency_revoke(root, root_digest, now))

    def recover(
        self,
        recovery: OpaqueCredential,
        recovery_digest: SecretDigest,
        now: datetime,
        session: SessionIssue,
        replacement_recovery: RecoveryIssue,
    ) -> AuthOutcome[SessionRecord]:
        return self._decision(
            lambda store: store.recover(
                recovery, recovery_digest, now, session, replacement_recovery
            )
        )

    def validate_grant(
        self,
        grant: object,
        session: OpaqueCredential,
        session_digest: SecretDigest,
        now: datetime,
    ) -> AuthOutcome[AuthorityGrant]:
        return self._decision(
            lambda store: store.validate_grant(grant, session, session_digest, now)
        )

    def garbage_collect(self, now: datetime, retention_seconds: int) -> int:
        return self._decision(lambda store: store.garbage_collect(now, retention_seconds))


def _auth_store_conformance(store: SqliteAuthDecisionStore) -> AuthDecisionStore:
    return store
