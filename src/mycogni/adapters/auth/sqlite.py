"""Restart-durable SQLite adapter for the accepted auth decision protocol.

The persisted document is a strict, versioned encoding of finite decision state.
It contains opaque identifiers, fixed-size secret digests and policy metadata, but
never an ``OpaqueCredential`` or raw credential material.  Every public decision
reloads and commits the complete state under ``BEGIN IMMEDIATE`` so two processes
cannot both consume one-use authority.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from dataclasses import fields, is_dataclass
from datetime import datetime
from enum import Enum, StrEnum
from threading import RLock
from typing import Any, TypeVar, cast

from sqlalchemy import text

from mycogni.adapters.auth import volatile as volatile_module
from mycogni.adapters.auth.volatile import VolatileAuthDecisionStore
from mycogni.adapters.persistence.durability import SQLiteRuntime
from mycogni.domain import OpaqueId
from mycogni.domain.auth import (
    ActorRecord,
    AuthorityGrant,
    BootstrapRecord,
    GrantProvenanceRecord,
    RecoveryRecord,
    RootCapabilityRecord,
    SecretDigest,
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
    """A decision committed but its credential-bearing response was not delivered."""


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
        volatile_module._CompositionBinding,
        volatile_module._ReprovisionCeremonyRecord,
    )
}

_ENUM_TYPES: dict[str, type[Enum]] = {}
for record_type in _RECORD_TYPES.values():
    for field in fields(record_type):
        annotation = field.type
        if isinstance(annotation, type) and issubclass(annotation, Enum):
            _ENUM_TYPES[annotation.__name__] = annotation

# Postponed annotations mean explicit registration is clearer and fail-closed.
from mycogni.domain.auth import AuthDenial, AuthPurpose, AuthScope, RootPurpose  # noqa: E402

for enum_type in (AuthDenial, AuthPurpose, AuthScope, RootPurpose):
    _ENUM_TYPES[enum_type.__name__] = enum_type


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
        return {"type": "enum", "name": type(value).__name__, "value": value.value}
    if type(value) is frozenset:
        return {"type": "frozenset", "items": sorted((_encode(item) for item in value), key=str)}
    if is_dataclass(value) and type(value).__name__ in _RECORD_TYPES:
        return {
            "type": "record",
            "name": type(value).__name__,
            "fields": {field.name: _encode(getattr(value, field.name)) for field in fields(value)},
        }
    raise TypeError("auth state contains a non-canonical or secret-bearing value")


def _decode(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is not dict or type(value.get("type")) is not str:
        raise ValueError("auth state contains malformed canonical data")
    kind = value["type"]
    if kind == "opaque_id":
        return OpaqueId.parse(value["value"])
    if kind == "secret_digest":
        raw = base64.b64decode(value["value"], validate=True)
        return SecretDigest(raw)
    if kind == "utc_datetime":
        parsed = datetime.fromisoformat(value["value"])
        return parsed
    if kind == "enum":
        enum_name = value.get("name")
        if type(enum_name) is not str:
            raise ValueError("auth state contains an invalid enum name")
        enum_type = _ENUM_TYPES.get(enum_name)
        if enum_type is None:
            raise ValueError("auth state contains an unknown enum")
        return enum_type(value["value"])
    if kind == "frozenset":
        return frozenset(_decode(item) for item in value["items"])
    if kind == "record":
        record_name = value.get("name")
        if type(record_name) is not str:
            raise ValueError("auth state contains an invalid record name")
        record_type = _RECORD_TYPES.get(record_name)
        field_values = value.get("fields")
        if record_type is None or type(field_values) is not dict:
            raise ValueError("auth state contains an unknown record")
        expected = {field.name for field in fields(record_type)}
        if set(field_values) != expected:
            raise ValueError("auth state record fields are not canonical")
        return record_type(**{name: _decode(item) for name, item in field_values.items()})
    raise ValueError("auth state contains an unknown canonical type")


def _snapshot(store: VolatileAuthDecisionStore) -> str:
    state: dict[str, dict[OpaqueId, object]] = {
        "actors": cast(dict[OpaqueId, object], store._actors),
        "installation_actors": cast(dict[OpaqueId, object], store._installation_actors),
        "roots": cast(dict[OpaqueId, object], store._roots),
        "bootstraps": cast(dict[OpaqueId, object], store._bootstraps),
        "sessions": cast(dict[OpaqueId, object], store._sessions),
        "recoveries": cast(dict[OpaqueId, object], store._recoveries),
        "step_ups": cast(dict[OpaqueId, object], store._step_ups),
        "grant_provenance": cast(dict[OpaqueId, object], store._grant_provenance),
        "composition_bindings": cast(dict[OpaqueId, object], store._composition_bindings),
        "reprovision_ceremonies": cast(dict[OpaqueId, object], store._reprovision_ceremonies),
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


def _restore(payload: str) -> VolatileAuthDecisionStore:
    parsed = json.loads(payload)
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
    store = VolatileAuthDecisionStore()
    for name, pairs in parsed.items():
        if type(pairs) is not list:
            raise ValueError("auth state collection must be a list")
        restored: dict[object, object] = {}
        for pair in pairs:
            if type(pair) is not list or len(pair) != 2:
                raise ValueError("auth state entry must be a key/value pair")
            key, item = _decode(pair[0]), _decode(pair[1])
            if type(key) is not OpaqueId or key in restored:
                raise ValueError("auth state key is invalid or duplicated")
            restored[key] = item
        setattr(store, f"_{name}", restored)
    return store


def _authority_registry(store: VolatileAuthDecisionStore) -> list[dict[str, str]]:
    registry: dict[OpaqueId, tuple[str, OpaqueId]] = {}

    def register(handle: OpaqueId, kind: str, installation_id: OpaqueId) -> None:
        if handle in registry:
            raise RuntimeError("auth authority handle is not globally unique")
        registry[handle] = (kind, installation_id)

    for root in store._roots.values():
        register(root.handle, "root", root.installation_id)
    for installation_id, binding in store._composition_bindings.items():
        register(binding.operator_handle, "operator", installation_id)
        register(binding.service_handle, "service", installation_id)
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
            return self._decision_locked(operation)

    def _decision_locked(self, operation: Callable[[VolatileAuthDecisionStore], _T]) -> _T:
        # SQLiteRuntime admits one owned application UoW and starts it with
        # BEGIN IMMEDIATE. A commit exception returns no newly issued material;
        # callers must treat it as outcome-unknown and must not auto-retry.
        with self._runtime.unit_of_work() as unit_of_work:
            row = (
                unit_of_work.session.execute(
                    text(
                        "SELECT schema_version, revision, state_json "
                        "FROM auth_decision_state WHERE singleton_id=1"
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                store = VolatileAuthDecisionStore()
                revision = 0
            else:
                if row["schema_version"] != _STATE_SCHEMA_VERSION:
                    raise RuntimeError("unsupported auth decision state schema")
                store = _restore(row["state_json"])
                revision = row["revision"]
            result = operation(store)
            payload = _snapshot(store)
            authorities = _authority_registry(store)
            if row is None:
                unit_of_work.session.execute(
                    text(
                        "INSERT INTO auth_decision_state"
                        "(singleton_id,schema_version,revision,state_json) "
                        "VALUES(1,:schema_version,1,:state_json)"
                    ),
                    {"schema_version": _STATE_SCHEMA_VERSION, "state_json": payload},
                )
            else:
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
                )
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
            unit_of_work.commit()
            self._crash_if_armed(DurableAuthCrashPoint.AFTER_COMMIT)
            return result

    def initialize_installation(self, **kwargs: Any) -> None:
        self._decision(lambda store: store.initialize_installation(**kwargs))

    def create_root_bootstrap(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.create_root_bootstrap(*args, **kwargs))

    def create_authenticated_bootstrap(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.create_authenticated_bootstrap(*args, **kwargs))

    def create_reprovision_bootstrap(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.create_reprovision_bootstrap(*args, **kwargs))

    def cancel_bootstrap(self, *args: Any, **kwargs: Any) -> None:
        self._decision(lambda store: store.cancel_bootstrap(*args, **kwargs))

    def exchange_bootstrap(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.exchange_bootstrap(*args, **kwargs))

    def create_reprovision_ceremony(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.create_reprovision_ceremony(*args, **kwargs))

    def exchange_reprovision_bootstrap(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.exchange_reprovision_bootstrap(*args, **kwargs))

    def reprovision_ceremony_counts(self, *args: Any, **kwargs: Any) -> dict[str, int]:
        return self._decision(lambda store: store.reprovision_ceremony_counts(*args, **kwargs))

    def authenticate_session(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.authenticate_session(*args, **kwargs))

    def create_step_up(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.create_step_up(*args, **kwargs))

    def consume_step_up(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.consume_step_up(*args, **kwargs))

    def rotate_session(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.rotate_session(*args, **kwargs))

    def revoke_session(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.revoke_session(*args, **kwargs))

    def renew_recovery(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.renew_recovery(*args, **kwargs))

    def revoke_all_authenticated(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.revoke_all_authenticated(*args, **kwargs))

    def emergency_revoke(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.emergency_revoke(*args, **kwargs))

    def recover(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.recover(*args, **kwargs))

    def validate_grant(self, *args: Any, **kwargs: Any) -> Any:
        return self._decision(lambda store: store.validate_grant(*args, **kwargs))

    def garbage_collect(self, *args: Any, **kwargs: Any) -> int:
        return self._decision(lambda store: store.garbage_collect(*args, **kwargs))
