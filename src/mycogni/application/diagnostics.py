"""Typed, allowlisted local diagnostic contracts.

The contract intentionally cannot represent URLs, queries, headers, bodies,
mail content, HTML, browser content, proxy metadata, exception messages, or
tracebacks. Validation is a representation guard, not a PII classifier.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, Self
from uuid import UUID, uuid4

MAX_DURATION_MS = 86_400_000
MAX_RETRY_NUMBER = 10_000
MAX_COUNT = 1_000_000
_CORRELATION_FACTORY_TOKEN = object()


class _DiagnosticCorrelationId:
    """Factory-only base for purpose-specific local diagnostic correlation."""

    __slots__ = ("__value",)
    __value: UUID

    def __init__(self, token: object, value: UUID) -> None:
        if token is not _CORRELATION_FACTORY_TOKEN or type(value) is not UUID:
            raise TypeError("diagnostic correlation IDs must be created with new()")
        object.__setattr__(self, "_DiagnosticCorrelationId__value", value)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("diagnostic correlation IDs are immutable")

    @classmethod
    def new(cls) -> Self:
        """Create a fresh local-only correlation with the operating-system RNG."""
        return cls(_CORRELATION_FACTORY_TOKEN, uuid4())

    def __str__(self) -> str:
        return str(self.__value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}([OPAQUE])"

    def __eq__(self, other: object) -> bool:
        return type(other) is type(self) and str(other) == str(self)

    def __hash__(self) -> int:
        return hash((type(self), self.__value))


class DiagnosticJobId(_DiagnosticCorrelationId):
    """Correlation for one local diagnostic job view only."""


class DiagnosticActionId(_DiagnosticCorrelationId):
    """Correlation for one local diagnostic external-action view only."""


class DiagnosticTraceId(_DiagnosticCorrelationId):
    """Correlation for one local diagnostic trace view only."""


class DiagnosticLevel(StrEnum):
    """Finite local diagnostic severity vocabulary."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class DiagnosticComponent(StrEnum):
    """Finite component vocabulary without host or process metadata."""

    API = "api"
    WORKER = "worker"
    SCHEDULER = "scheduler"
    CONNECTOR_BOUNDARY = "connector_boundary"
    EGRESS_GATEWAY = "egress_gateway"
    PERSISTENCE = "persistence"
    BACKUP = "backup"
    AUTH = "auth"


class EventId(StrEnum):
    """Stable event identities; additions require catalog review."""

    SERVICE_LIFECYCLE = "service_lifecycle"
    JOB_TRANSITION = "job_transition"
    CONNECTOR_ATTEMPT = "connector_attempt"
    EGRESS_DECISION = "egress_decision"
    EVIDENCE_OPERATION = "evidence_operation"
    BACKUP_OPERATION = "backup_operation"
    AUTH_DECISION = "auth_decision"
    EXCEPTION_CLASSIFIED = "exception_classified"


class FieldName(StrEnum):
    """Complete set of fields accepted by protocol version 1 diagnostics."""

    ACTION = "action"
    RESULT_CODE = "result_code"
    CONNECTOR_ID = "connector_id"
    CONNECTOR_VERSION = "connector_version"
    DURATION_MS = "duration_ms"
    RETRY_NUMBER = "retry_number"
    COUNT = "count"
    JOB_ID = "job_id"
    ACTION_ID = "action_id"
    TRACE_ID = "trace_id"
    ERROR_CATEGORY = "error_category"


class ErrorCategory(StrEnum):
    """Finite exception categories that reveal no message or class name."""

    TIMEOUT = "timeout"
    PERMISSION = "permission"
    VALIDATION = "validation"
    CONFLICT = "conflict"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    IO = "io"
    CANCELLED = "cancelled"
    UNEXPECTED = "unexpected"


class ActionCode(StrEnum):
    """Finite coarse operations that cannot carry caller-provided text."""

    START = "start"
    STOP = "stop"
    LEASE = "lease"
    EXECUTE = "execute"
    OBSERVE = "observe"
    PREPARE = "prepare"
    SUBMIT = "submit"
    POLL = "poll"
    VERIFY = "verify"
    DIAL = "dial"
    WRITE = "write"
    READ = "read"
    DELETE = "delete"
    CREATE = "create"
    RESTORE = "restore"
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"
    ROTATE = "rotate"
    CHECK = "check"


class DiagnosticResultCode(StrEnum):
    """Finite operational results without external-content detail."""

    SUCCEEDED = "succeeded"
    ACCEPTED = "accepted"
    DENIED = "denied"
    FAILED = "failed"
    RETRY = "retry"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    INCONCLUSIVE = "inconclusive"
    UNAVAILABLE = "unavailable"
    CONFLICT = "conflict"
    INVALID = "invalid"
    REVOKED = "revoked"
    STALE = "stale"
    UNKNOWN = "unknown"


class ConnectorCode(StrEnum):
    """Finite reviewed public connector IDs available to diagnostics."""

    SYNTHETIC_PEOPLE_SEARCH = "synthetic-people-search"


class ConnectorVersionCode(StrEnum):
    """Finite reviewed public connector versions available to diagnostics."""

    SYNTHETIC_0_1_0 = "0.1.0"


type DiagnosticValue = (
    int
    | DiagnosticJobId
    | DiagnosticActionId
    | DiagnosticTraceId
    | ErrorCategory
    | ActionCode
    | DiagnosticResultCode
    | ConnectorCode
    | ConnectorVersionCode
)


@dataclass(frozen=True, slots=True)
class EventCombination:
    """One allowed component/action/result/level combination."""

    component: DiagnosticComponent
    action: ActionCode
    result: DiagnosticResultCode
    level: DiagnosticLevel


@dataclass(frozen=True, slots=True)
class EventSpec:
    """Exact field and enum-combination contract for one event identity."""

    required_fields: frozenset[FieldName]
    optional_fields: frozenset[FieldName]
    combinations: frozenset[EventCombination]
    connector_releases: frozenset[tuple[ConnectorCode, ConnectorVersionCode]] = frozenset()
    exception_results: Mapping[ErrorCategory, DiagnosticResultCode] | None = None

    @property
    def allowed_fields(self) -> frozenset[FieldName]:
        return self.required_fields | self.optional_fields


def _combinations(
    components: frozenset[DiagnosticComponent],
    rules: Mapping[ActionCode, Mapping[DiagnosticResultCode, frozenset[DiagnosticLevel]]],
) -> frozenset[EventCombination]:
    return frozenset(
        EventCombination(component, action, result, level)
        for component in components
        for action, results in rules.items()
        for result, levels in results.items()
        for level in levels
    )


_INFO = frozenset({DiagnosticLevel.INFO})
_WARN = frozenset({DiagnosticLevel.WARNING})
_ERROR = frozenset({DiagnosticLevel.ERROR})
_ERROR_CRITICAL = frozenset({DiagnosticLevel.ERROR, DiagnosticLevel.CRITICAL})
_DEBUG_INFO = frozenset({DiagnosticLevel.DEBUG, DiagnosticLevel.INFO})
_ACTION_RESULT_FIELDS = frozenset({FieldName.ACTION, FieldName.RESULT_CODE})
_CORRELATION_FIELDS = frozenset({FieldName.TRACE_ID})
_SYNTHETIC_RELEASES = frozenset(
    {(ConnectorCode.SYNTHETIC_PEOPLE_SEARCH, ConnectorVersionCode.SYNTHETIC_0_1_0)}
)

EVENT_CATALOG: Mapping[EventId, EventSpec] = MappingProxyType(
    {
        EventId.SERVICE_LIFECYCLE: EventSpec(
            _ACTION_RESULT_FIELDS,
            frozenset(),
            _combinations(
                frozenset(
                    {
                        DiagnosticComponent.API,
                        DiagnosticComponent.WORKER,
                        DiagnosticComponent.SCHEDULER,
                    }
                ),
                {
                    ActionCode.START: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.FAILED: _ERROR_CRITICAL,
                    },
                    ActionCode.STOP: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.FAILED: _ERROR_CRITICAL,
                    },
                },
            ),
        ),
        EventId.JOB_TRANSITION: EventSpec(
            _ACTION_RESULT_FIELDS | {FieldName.JOB_ID},
            frozenset({FieldName.DURATION_MS, FieldName.RETRY_NUMBER, FieldName.TRACE_ID}),
            _combinations(
                frozenset({DiagnosticComponent.WORKER, DiagnosticComponent.SCHEDULER}),
                {
                    ActionCode.LEASE: {
                        DiagnosticResultCode.ACCEPTED: _DEBUG_INFO,
                        DiagnosticResultCode.DENIED: _WARN,
                        DiagnosticResultCode.CONFLICT: _WARN,
                        DiagnosticResultCode.STALE: _WARN,
                    },
                    ActionCode.EXECUTE: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.FAILED: _ERROR,
                        DiagnosticResultCode.RETRY: _WARN,
                        DiagnosticResultCode.TIMEOUT: _WARN,
                        DiagnosticResultCode.CANCELLED: _INFO,
                    },
                },
            ),
        ),
        EventId.CONNECTOR_ATTEMPT: EventSpec(
            _ACTION_RESULT_FIELDS
            | {
                FieldName.ACTION_ID,
                FieldName.CONNECTOR_ID,
                FieldName.CONNECTOR_VERSION,
            },
            frozenset({FieldName.DURATION_MS, FieldName.RETRY_NUMBER, FieldName.TRACE_ID}),
            _combinations(
                frozenset({DiagnosticComponent.CONNECTOR_BOUNDARY}),
                {
                    ActionCode.OBSERVE: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.INCONCLUSIVE: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                        DiagnosticResultCode.TIMEOUT: _WARN,
                        DiagnosticResultCode.CANCELLED: _INFO,
                    },
                    ActionCode.PREPARE: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.INVALID: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                        DiagnosticResultCode.CANCELLED: _INFO,
                    },
                    ActionCode.SUBMIT: {
                        DiagnosticResultCode.ACCEPTED: _INFO,
                        DiagnosticResultCode.DENIED: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                        DiagnosticResultCode.TIMEOUT: _WARN,
                        DiagnosticResultCode.INCONCLUSIVE: _WARN,
                        DiagnosticResultCode.CANCELLED: _INFO,
                        DiagnosticResultCode.REVOKED: _WARN,
                        DiagnosticResultCode.STALE: _WARN,
                    },
                    ActionCode.POLL: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.INCONCLUSIVE: _WARN,
                        DiagnosticResultCode.RETRY: _INFO,
                        DiagnosticResultCode.TIMEOUT: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                        DiagnosticResultCode.CANCELLED: _INFO,
                    },
                    ActionCode.VERIFY: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.INCONCLUSIVE: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                        DiagnosticResultCode.TIMEOUT: _WARN,
                        DiagnosticResultCode.CANCELLED: _INFO,
                    },
                },
            ),
            connector_releases=_SYNTHETIC_RELEASES,
        ),
        EventId.EGRESS_DECISION: EventSpec(
            _ACTION_RESULT_FIELDS
            | {FieldName.ACTION_ID, FieldName.CONNECTOR_ID, FieldName.CONNECTOR_VERSION},
            frozenset({FieldName.DURATION_MS, FieldName.TRACE_ID}),
            _combinations(
                frozenset({DiagnosticComponent.EGRESS_GATEWAY}),
                {
                    ActionCode.DIAL: {
                        DiagnosticResultCode.ACCEPTED: _INFO,
                        DiagnosticResultCode.DENIED: _WARN,
                        DiagnosticResultCode.STALE: _WARN,
                        DiagnosticResultCode.REVOKED: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                        DiagnosticResultCode.TIMEOUT: _ERROR,
                    }
                },
            ),
            connector_releases=_SYNTHETIC_RELEASES,
        ),
        EventId.EVIDENCE_OPERATION: EventSpec(
            _ACTION_RESULT_FIELDS | {FieldName.ACTION_ID},
            frozenset({FieldName.COUNT, FieldName.DURATION_MS, FieldName.TRACE_ID}),
            _combinations(
                frozenset({DiagnosticComponent.PERSISTENCE}),
                {
                    action: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.INVALID: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                    }
                    for action in (ActionCode.WRITE, ActionCode.READ, ActionCode.DELETE)
                },
            ),
        ),
        EventId.BACKUP_OPERATION: EventSpec(
            _ACTION_RESULT_FIELDS,
            frozenset({FieldName.COUNT, FieldName.DURATION_MS, FieldName.TRACE_ID}),
            _combinations(
                frozenset({DiagnosticComponent.BACKUP}),
                {
                    action: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.INVALID: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                    }
                    for action in (ActionCode.CREATE, ActionCode.RESTORE, ActionCode.CHECK)
                },
            ),
        ),
        EventId.AUTH_DECISION: EventSpec(
            _ACTION_RESULT_FIELDS,
            _CORRELATION_FIELDS,
            _combinations(
                frozenset({DiagnosticComponent.AUTH}),
                {
                    ActionCode.AUTHENTICATE: {
                        DiagnosticResultCode.ACCEPTED: _INFO,
                        DiagnosticResultCode.DENIED: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                    },
                    ActionCode.AUTHORIZE: {
                        DiagnosticResultCode.ACCEPTED: _INFO,
                        DiagnosticResultCode.DENIED: _WARN,
                        DiagnosticResultCode.REVOKED: _WARN,
                        DiagnosticResultCode.FAILED: _ERROR,
                    },
                    ActionCode.ROTATE: {
                        DiagnosticResultCode.SUCCEEDED: _INFO,
                        DiagnosticResultCode.FAILED: _ERROR,
                    },
                },
            ),
        ),
        EventId.EXCEPTION_CLASSIFIED: EventSpec(
            _ACTION_RESULT_FIELDS | {FieldName.ERROR_CATEGORY},
            frozenset({FieldName.JOB_ID, FieldName.ACTION_ID, FieldName.TRACE_ID}),
            _combinations(
                frozenset(
                    {
                        DiagnosticComponent.API,
                        DiagnosticComponent.WORKER,
                        DiagnosticComponent.SCHEDULER,
                        DiagnosticComponent.CONNECTOR_BOUNDARY,
                        DiagnosticComponent.EGRESS_GATEWAY,
                        DiagnosticComponent.PERSISTENCE,
                        DiagnosticComponent.BACKUP,
                        DiagnosticComponent.AUTH,
                    }
                ),
                {
                    ActionCode.EXECUTE: {
                        DiagnosticResultCode.FAILED: _ERROR_CRITICAL,
                        DiagnosticResultCode.TIMEOUT: _ERROR,
                        DiagnosticResultCode.CANCELLED: _WARN,
                    }
                },
            ),
            exception_results=MappingProxyType(
                {
                    ErrorCategory.TIMEOUT: DiagnosticResultCode.TIMEOUT,
                    ErrorCategory.CANCELLED: DiagnosticResultCode.CANCELLED,
                    ErrorCategory.PERMISSION: DiagnosticResultCode.FAILED,
                    ErrorCategory.VALIDATION: DiagnosticResultCode.FAILED,
                    ErrorCategory.CONFLICT: DiagnosticResultCode.FAILED,
                    ErrorCategory.RESOURCE_EXHAUSTED: DiagnosticResultCode.FAILED,
                    ErrorCategory.IO: DiagnosticResultCode.FAILED,
                    ErrorCategory.UNEXPECTED: DiagnosticResultCode.FAILED,
                }
            ),
        ),
    }
)


def _validate_bounded_int(value: DiagnosticValue, field_name: FieldName) -> None:
    if type(value) is not int:
        raise TypeError(f"diagnostic field {field_name.value} must be an integer")
    maximum = {
        FieldName.DURATION_MS: MAX_DURATION_MS,
        FieldName.RETRY_NUMBER: MAX_RETRY_NUMBER,
        FieldName.COUNT: MAX_COUNT,
    }[field_name]
    if not 0 <= value <= maximum:
        raise ValueError(f"diagnostic field {field_name.value} is outside its safe bound")


def _require_exact_type(value: object, expected: type[object], field_name: FieldName) -> None:
    if type(value) is not expected:
        raise TypeError(f"diagnostic field {field_name.value} must be a {expected.__name__}")


def _validate_field_value(field_name: FieldName, value: DiagnosticValue) -> None:
    expected_id_types: dict[FieldName, type[object]] = {
        FieldName.JOB_ID: DiagnosticJobId,
        FieldName.ACTION_ID: DiagnosticActionId,
        FieldName.TRACE_ID: DiagnosticTraceId,
    }
    if field_name in expected_id_types:
        _require_exact_type(value, expected_id_types[field_name], field_name)
        return
    expected_enum_types: dict[FieldName, type[object]] = {
        FieldName.ACTION: ActionCode,
        FieldName.RESULT_CODE: DiagnosticResultCode,
        FieldName.CONNECTOR_ID: ConnectorCode,
        FieldName.CONNECTOR_VERSION: ConnectorVersionCode,
        FieldName.ERROR_CATEGORY: ErrorCategory,
    }
    if field_name in expected_enum_types:
        _require_exact_type(value, expected_enum_types[field_name], field_name)
        return
    if field_name in {FieldName.DURATION_MS, FieldName.RETRY_NUMBER, FieldName.COUNT}:
        _validate_bounded_int(value, field_name)
        return
    raise ValueError("diagnostic field is not implemented by protocol version 1")


@dataclass(frozen=True, slots=True)
class DiagnosticEvent:
    """One validated event accepted by a local diagnostic sink."""

    occurred_at_utc: datetime
    level: DiagnosticLevel
    component: DiagnosticComponent
    event_id: EventId
    fields: Mapping[FieldName, DiagnosticValue]

    def __post_init__(self) -> None:
        if type(self.occurred_at_utc) is not datetime:
            raise TypeError("diagnostic timestamp must be a datetime")
        if self.occurred_at_utc.utcoffset() != UTC.utcoffset(self.occurred_at_utc):
            raise ValueError("diagnostic timestamp must be an aware UTC instant")
        if type(self.level) is not DiagnosticLevel:
            raise TypeError("diagnostic level must be a DiagnosticLevel")
        if type(self.component) is not DiagnosticComponent:
            raise TypeError("diagnostic component must be a DiagnosticComponent")
        if type(self.event_id) is not EventId:
            raise TypeError("diagnostic event_id must be an EventId")
        if not isinstance(self.fields, Mapping):
            raise TypeError("diagnostic fields must be a mapping")

        normalized: dict[FieldName, DiagnosticValue] = {}
        for field_name, value in self.fields.items():
            if type(field_name) is not FieldName:
                raise TypeError("diagnostic field names must be FieldName values")
            _validate_field_value(field_name, value)
            normalized[field_name] = value

        spec = EVENT_CATALOG[self.event_id]
        present = frozenset(normalized)
        if spec.required_fields - present:
            raise ValueError("diagnostic event is missing required fields")
        if present - spec.allowed_fields:
            raise ValueError("diagnostic event contains fields outside its catalog entry")

        action = normalized[FieldName.ACTION]
        result = normalized[FieldName.RESULT_CODE]
        assert type(action) is ActionCode
        assert type(result) is DiagnosticResultCode
        combination = EventCombination(self.component, action, result, self.level)
        if combination not in spec.combinations:
            raise ValueError("diagnostic event has an impossible enum combination")

        if spec.connector_releases:
            connector = normalized[FieldName.CONNECTOR_ID]
            version = normalized[FieldName.CONNECTOR_VERSION]
            assert type(connector) is ConnectorCode
            assert type(version) is ConnectorVersionCode
            if (connector, version) not in spec.connector_releases:
                raise ValueError("diagnostic event has an unreviewed connector release pair")

        if spec.exception_results is not None:
            category = normalized[FieldName.ERROR_CATEGORY]
            assert type(category) is ErrorCategory
            if spec.exception_results[category] is not result:
                raise ValueError("diagnostic exception category and result are inconsistent")
        object.__setattr__(self, "fields", MappingProxyType(normalized))


def classify_exception(exception: BaseException) -> ErrorCategory:
    """Return only a finite category; never inspect or retain exception text."""
    if isinstance(exception, asyncio.CancelledError):
        return ErrorCategory.CANCELLED
    if isinstance(exception, TimeoutError):
        return ErrorCategory.TIMEOUT
    if isinstance(exception, PermissionError):
        return ErrorCategory.PERMISSION
    if isinstance(exception, (ValueError, TypeError, KeyError)):
        return ErrorCategory.VALIDATION
    if isinstance(exception, FileExistsError):
        return ErrorCategory.CONFLICT
    if isinstance(exception, MemoryError):
        return ErrorCategory.RESOURCE_EXHAUSTED
    if isinstance(exception, InterruptedError):
        return ErrorCategory.CANCELLED
    if isinstance(exception, OSError):
        return ErrorCategory.IO
    return ErrorCategory.UNEXPECTED


class DiagnosticSink(Protocol):
    """Application-owned synchronous local diagnostic sink port."""

    def emit(self, event: DiagnosticEvent) -> None:
        """Persist one already validated event locally."""
        ...
