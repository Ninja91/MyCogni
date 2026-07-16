"""Typed diagnostic catalog and fail-closed value validation tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

import pytest

from mycogni.application.diagnostics import (
    EVENT_CATALOG,
    MAX_COUNT,
    MAX_DURATION_MS,
    MAX_RETRY_NUMBER,
    ActionCode,
    ConnectorCode,
    ConnectorVersionCode,
    DiagnosticComponent,
    DiagnosticEvent,
    DiagnosticLevel,
    DiagnosticResultCode,
    ErrorCategory,
    EventId,
    FieldName,
    classify_exception,
)
from mycogni.domain import OpaqueId

NOW = datetime(2030, 1, 1, tzinfo=UTC)
ACTION_ID = OpaqueId(UUID("2cb84782-ad9f-47ab-9fa1-7487ad1ff40c"))


def _service_event(fields: dict[Any, Any]) -> DiagnosticEvent:
    return DiagnosticEvent(
        occurred_at_utc=NOW,
        level=DiagnosticLevel.INFO,
        component=DiagnosticComponent.API,
        event_id=EventId.SERVICE_LIFECYCLE,
        fields=fields,
    )


def _synthetic_canaries() -> dict[str, str]:
    email = "pii-canary@person.example.test"
    phone = "202" + "-555-" + "0199"
    secret = "ghp_" + "A" * 36
    return {
        "url": f"https://broker.example.test/search?email={email}&phone={phone}",
        "query": f"name=Synthetic+Canary&email={email}",
        "headers": f"Authorization: Bearer {secret}",
        "exception": f"lookup failed for Synthetic Canary {email}",
        "html": f"<title>Synthetic Canary</title><p>{phone}</p>",
        "mail": f"To: {email}\nSubject: removal for Synthetic Canary",
        "proxy": f"CONNECT broker.example.test; credential={secret}",
        "browser": f"document.title=Synthetic Canary; target={email}",
    }


def test_catalog_is_total_and_has_no_ambiguous_fields() -> None:
    assert set(EVENT_CATALOG) == set(EventId)
    for spec in EVENT_CATALOG.values():
        assert spec.required_fields
        assert not spec.required_fields & spec.optional_fields
        assert spec.allowed_fields <= set(FieldName)


@pytest.mark.parametrize("surface", sorted(_synthetic_canaries()))
def test_raw_diagnostic_surface_fields_are_unrepresentable(surface: str) -> None:
    fields: dict[Any, Any] = {
        FieldName.ACTION: ActionCode.START,
        FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
        surface: _synthetic_canaries()[surface],
    }
    with pytest.raises(TypeError, match="field names must be FieldName"):
        _service_event(fields)


@pytest.mark.parametrize("canary", list(_synthetic_canaries().values()))
def test_unsafe_content_fails_closed_even_in_an_allowlisted_string_field(canary: str) -> None:
    with pytest.raises(TypeError, match="must be an ActionCode"):
        _service_event(
            {
                FieldName.ACTION: canary,
                FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
            }
        )


def test_event_rejects_missing_and_event_specific_extra_fields() -> None:
    with pytest.raises(ValueError, match="missing required"):
        _service_event({FieldName.ACTION: ActionCode.START})
    with pytest.raises(ValueError, match="outside its catalog"):
        _service_event(
            {
                FieldName.ACTION: ActionCode.START,
                FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
                FieldName.ACTION_ID: ACTION_ID,
            }
        )


@pytest.mark.parametrize("value", [True, 1.0, "1", None])
def test_bounded_integer_fields_reject_coercion(value: object) -> None:
    with pytest.raises(TypeError, match="must be an integer"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.WORKER,
            event_id=EventId.JOB_TRANSITION,
            fields={
                FieldName.JOB_ID: ACTION_ID,
                FieldName.ACTION: ActionCode.LEASE,
                FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
                FieldName.RETRY_NUMBER: cast(int, value),
            },
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        (FieldName.DURATION_MS, MAX_DURATION_MS + 1),
        (FieldName.RETRY_NUMBER, MAX_RETRY_NUMBER + 1),
        (FieldName.COUNT, MAX_COUNT + 1),
        (FieldName.DURATION_MS, -1),
    ],
)
def test_integer_fields_have_explicit_bounds(field_name: FieldName, value: int) -> None:
    event_id = (
        EventId.EVIDENCE_OPERATION if field_name is FieldName.COUNT else EventId.CONNECTOR_ATTEMPT
    )
    fields: dict[FieldName, object] = {
        FieldName.ACTION_ID: ACTION_ID,
        FieldName.ACTION: ActionCode.WRITE,
        FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
    }
    if event_id is EventId.CONNECTOR_ATTEMPT:
        fields[FieldName.CONNECTOR_ID] = ConnectorCode.SYNTHETIC_PEOPLE_SEARCH
        fields[FieldName.CONNECTOR_VERSION] = ConnectorVersionCode.SYNTHETIC_0_1_0
    fields[field_name] = value
    with pytest.raises(ValueError, match="outside its safe bound"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.CONNECTOR_BOUNDARY,
            event_id=event_id,
            fields=cast(dict[FieldName, Any], fields),
        )


def test_correlation_fields_require_opaque_ids_and_fields_are_immutable() -> None:
    source = {
        FieldName.JOB_ID: ACTION_ID,
        FieldName.ACTION: ActionCode.LEASE,
        FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
    }
    event = DiagnosticEvent(
        occurred_at_utc=NOW,
        level=DiagnosticLevel.INFO,
        component=DiagnosticComponent.WORKER,
        event_id=EventId.JOB_TRANSITION,
        fields=source,
    )
    source[FieldName.ACTION] = ActionCode.STOP
    assert event.fields[FieldName.ACTION] is ActionCode.LEASE
    with pytest.raises(TypeError):
        cast(dict[FieldName, object], event.fields)[FieldName.ACTION] = ActionCode.STOP

    with pytest.raises(TypeError, match="must be an OpaqueId"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.WORKER,
            event_id=EventId.JOB_TRANSITION,
            fields={
                FieldName.JOB_ID: str(ACTION_ID),
                FieldName.ACTION: ActionCode.LEASE,
                FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
            },
        )


def test_connector_metadata_requires_reviewed_id_and_bounded_version() -> None:
    fields = {
        FieldName.ACTION_ID: ACTION_ID,
        FieldName.CONNECTOR_ID: "synthetic-people-search",
        FieldName.CONNECTOR_VERSION: "0.1.0",
        FieldName.ACTION: ActionCode.OBSERVE,
        FieldName.RESULT_CODE: DiagnosticResultCode.ACCEPTED,
    }
    with pytest.raises(TypeError, match="connector_id must be a ConnectorCode"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.CONNECTOR_BOUNDARY,
            event_id=EventId.CONNECTOR_ATTEMPT,
            fields=cast(dict[FieldName, Any], fields),
        )

    fields[FieldName.CONNECTOR_ID] = ConnectorCode.SYNTHETIC_PEOPLE_SEARCH
    fields[FieldName.CONNECTOR_VERSION] = "0.1.0-person@example.test"
    with pytest.raises(TypeError, match="connector_version must be a ConnectorVersionCode"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.CONNECTOR_BOUNDARY,
            event_id=EventId.CONNECTOR_ATTEMPT,
            fields=cast(dict[FieldName, Any], fields),
        )

    fields[FieldName.CONNECTOR_VERSION] = ConnectorVersionCode.SYNTHETIC_0_1_0
    event = DiagnosticEvent(
        occurred_at_utc=NOW,
        level=DiagnosticLevel.INFO,
        component=DiagnosticComponent.CONNECTOR_BOUNDARY,
        event_id=EventId.CONNECTOR_ATTEMPT,
        fields=cast(dict[FieldName, Any], fields),
    )
    assert event.fields[FieldName.CONNECTOR_ID] is ConnectorCode.SYNTHETIC_PEOPLE_SEARCH


class _MessageTrapError(Exception):
    def __str__(self) -> str:
        raise AssertionError("exception text was inspected")


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (TimeoutError("synthetic canary"), ErrorCategory.TIMEOUT),
        (PermissionError("synthetic canary"), ErrorCategory.PERMISSION),
        (ValueError("synthetic canary"), ErrorCategory.VALIDATION),
        (FileExistsError("synthetic canary"), ErrorCategory.CONFLICT),
        (MemoryError("synthetic canary"), ErrorCategory.RESOURCE_EXHAUSTED),
        (InterruptedError("synthetic canary"), ErrorCategory.CANCELLED),
        (OSError("synthetic canary"), ErrorCategory.IO),
        (_MessageTrapError(), ErrorCategory.UNEXPECTED),
    ],
)
def test_exception_classification_never_needs_message_or_trace(
    exception: BaseException, expected: ErrorCategory
) -> None:
    assert classify_exception(exception) is expected
