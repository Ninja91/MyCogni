"""Typed, allowlisted local diagnostic contracts.

The contract intentionally cannot represent URLs, queries, headers, bodies,
mail content, HTML, browser content, proxy metadata, exception messages, or
tracebacks. Validation is a representation guard, not a PII classifier.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from mycogni.domain import OpaqueId

MAX_DURATION_MS = 86_400_000
MAX_RETRY_NUMBER = 10_000
MAX_COUNT = 1_000_000


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
    | OpaqueId
    | ErrorCategory
    | ActionCode
    | DiagnosticResultCode
    | ConnectorCode
    | ConnectorVersionCode
)


@dataclass(frozen=True, slots=True)
class EventSpec:
    """Required and optional fields for one immutable event identity."""

    required_fields: frozenset[FieldName]
    optional_fields: frozenset[FieldName] = frozenset()

    @property
    def allowed_fields(self) -> frozenset[FieldName]:
        return self.required_fields | self.optional_fields


EVENT_CATALOG: Mapping[EventId, EventSpec] = MappingProxyType(
    {
        EventId.SERVICE_LIFECYCLE: EventSpec(frozenset({FieldName.ACTION, FieldName.RESULT_CODE})),
        EventId.JOB_TRANSITION: EventSpec(
            frozenset({FieldName.JOB_ID, FieldName.ACTION, FieldName.RESULT_CODE}),
            frozenset({FieldName.DURATION_MS, FieldName.RETRY_NUMBER, FieldName.TRACE_ID}),
        ),
        EventId.CONNECTOR_ATTEMPT: EventSpec(
            frozenset(
                {
                    FieldName.ACTION_ID,
                    FieldName.CONNECTOR_ID,
                    FieldName.CONNECTOR_VERSION,
                    FieldName.ACTION,
                    FieldName.RESULT_CODE,
                }
            ),
            frozenset({FieldName.DURATION_MS, FieldName.RETRY_NUMBER, FieldName.TRACE_ID}),
        ),
        EventId.EGRESS_DECISION: EventSpec(
            frozenset(
                {
                    FieldName.ACTION_ID,
                    FieldName.CONNECTOR_ID,
                    FieldName.ACTION,
                    FieldName.RESULT_CODE,
                }
            ),
            frozenset({FieldName.DURATION_MS, FieldName.TRACE_ID}),
        ),
        EventId.EVIDENCE_OPERATION: EventSpec(
            frozenset({FieldName.ACTION_ID, FieldName.ACTION, FieldName.RESULT_CODE}),
            frozenset({FieldName.COUNT, FieldName.DURATION_MS, FieldName.TRACE_ID}),
        ),
        EventId.BACKUP_OPERATION: EventSpec(
            frozenset({FieldName.ACTION, FieldName.RESULT_CODE}),
            frozenset({FieldName.COUNT, FieldName.DURATION_MS, FieldName.TRACE_ID}),
        ),
        EventId.AUTH_DECISION: EventSpec(
            frozenset({FieldName.ACTION, FieldName.RESULT_CODE}),
            frozenset({FieldName.TRACE_ID}),
        ),
        EventId.EXCEPTION_CLASSIFIED: EventSpec(
            frozenset({FieldName.ACTION, FieldName.RESULT_CODE, FieldName.ERROR_CATEGORY}),
            frozenset({FieldName.JOB_ID, FieldName.ACTION_ID, FieldName.TRACE_ID}),
        ),
    }
)

_OPAQUE_ID_FIELDS = frozenset({FieldName.JOB_ID, FieldName.ACTION_ID, FieldName.TRACE_ID})


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


def _validate_field_value(field_name: FieldName, value: DiagnosticValue) -> None:
    if field_name in _OPAQUE_ID_FIELDS:
        if type(value) is not OpaqueId:
            raise TypeError(f"diagnostic field {field_name.value} must be an OpaqueId")
        return
    if field_name is FieldName.ACTION:
        if type(value) is not ActionCode:
            raise TypeError("diagnostic field action must be an ActionCode")
        return
    if field_name is FieldName.RESULT_CODE:
        if type(value) is not DiagnosticResultCode:
            raise TypeError("diagnostic field result_code must be a DiagnosticResultCode")
        return
    if field_name is FieldName.CONNECTOR_ID:
        if type(value) is not ConnectorCode:
            raise TypeError("diagnostic field connector_id must be a ConnectorCode")
        return
    if field_name is FieldName.CONNECTOR_VERSION:
        if type(value) is not ConnectorVersionCode:
            raise TypeError("diagnostic field connector_version must be a ConnectorVersionCode")
        return
    if field_name in {FieldName.DURATION_MS, FieldName.RETRY_NUMBER, FieldName.COUNT}:
        _validate_bounded_int(value, field_name)
        return
    if field_name is FieldName.ERROR_CATEGORY:
        if type(value) is not ErrorCategory:
            raise TypeError("diagnostic field error_category must be an ErrorCategory")
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
        missing = spec.required_fields - present
        unknown = present - spec.allowed_fields
        if missing:
            raise ValueError("diagnostic event is missing required fields")
        if unknown:
            raise ValueError("diagnostic event contains fields outside its catalog entry")
        object.__setattr__(self, "fields", MappingProxyType(normalized))


def classify_exception(exception: BaseException) -> ErrorCategory:
    """Return only a finite category; never inspect or retain exception text."""
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
