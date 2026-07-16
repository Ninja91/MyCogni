"""Typed diagnostic catalog and fail-closed value validation tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from enum import StrEnum
from itertools import product
from typing import Any, cast
from uuid import UUID

import pytest

from mycogni.application.diagnostics import (
    EVENT_CATALOG,
    MAX_COUNT,
    MAX_DURATION_MS,
    MAX_RETRY_NUMBER,
    ActionCode,
    DiagnosticActionId,
    DiagnosticComponent,
    DiagnosticEvent,
    DiagnosticJobId,
    DiagnosticLevel,
    DiagnosticResultCode,
    DiagnosticTraceId,
    ErrorCategory,
    EventCombination,
    EventId,
    FieldName,
    classify_exception,
)
from mycogni.domain import OpaqueId

NOW = datetime(2030, 1, 1, tzinfo=UTC)


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


def _combination_sort_key(item: EventCombination) -> tuple[str, str, str, str]:
    return (item.component.value, item.action.value, item.result.value, item.level.value)


def _valid_event(event_id: EventId) -> DiagnosticEvent:
    spec = EVENT_CATALOG[event_id]
    combination = sorted(spec.combinations, key=_combination_sort_key)[0]
    fields: dict[FieldName, Any] = {
        FieldName.ACTION: combination.action,
        FieldName.RESULT_CODE: combination.result,
    }
    if FieldName.JOB_ID in spec.required_fields:
        fields[FieldName.JOB_ID] = DiagnosticJobId.new()
    if FieldName.ACTION_ID in spec.required_fields:
        fields[FieldName.ACTION_ID] = DiagnosticActionId.new()
    if FieldName.CONNECTOR_ID in spec.required_fields:
        connector, version = sorted(
            spec.connector_releases, key=lambda item: (item[0].value, item[1].value)
        )[0]
        fields[FieldName.CONNECTOR_ID] = connector
        fields[FieldName.CONNECTOR_VERSION] = version
    if FieldName.ERROR_CATEGORY in spec.required_fields:
        assert spec.exception_results is not None
        fields[FieldName.ERROR_CATEGORY] = next(
            category
            for category, result in spec.exception_results.items()
            if result is combination.result
        )
    return DiagnosticEvent(
        occurred_at_utc=NOW,
        level=combination.level,
        component=combination.component,
        event_id=event_id,
        fields=fields,
    )


def test_catalog_is_total_and_has_exact_combinations() -> None:
    assert set(EVENT_CATALOG) == set(EventId)
    for event_id, spec in EVENT_CATALOG.items():
        assert spec.required_fields >= {FieldName.ACTION, FieldName.RESULT_CODE}
        assert not spec.required_fields & spec.optional_fields
        assert spec.allowed_fields <= set(FieldName)
        assert spec.combinations
        assert _valid_event(event_id).event_id is event_id


@pytest.mark.parametrize(
    ("event_id", "dimension"), list(product(EventId, ("component", "action", "result", "level")))
)
def test_every_event_rejects_each_impossible_enum_dimension(
    event_id: EventId, dimension: str
) -> None:
    valid = _valid_event(event_id)
    fields = dict(valid.fields)
    component = valid.component
    level = valid.level
    action = cast(ActionCode, fields[FieldName.ACTION])
    result = cast(DiagnosticResultCode, fields[FieldName.RESULT_CODE])
    spec = EVENT_CATALOG[event_id]

    if dimension == "component":
        impossible = next(
            (
                candidate
                for candidate in DiagnosticComponent
                if EventCombination(candidate, action, result, level) not in spec.combinations
            ),
            None,
        )
        if impossible is None:
            assert {
                candidate
                for candidate in DiagnosticComponent
                if EventCombination(candidate, action, result, level) in spec.combinations
            } == set(DiagnosticComponent)
            return
        component = impossible
    elif dimension == "action":
        fields[FieldName.ACTION] = next(
            candidate
            for candidate in ActionCode
            if EventCombination(component, candidate, result, level) not in spec.combinations
        )
    elif dimension == "result":
        fields[FieldName.RESULT_CODE] = next(
            candidate
            for candidate in DiagnosticResultCode
            if EventCombination(component, action, candidate, level) not in spec.combinations
        )
    else:
        level = next(
            candidate
            for candidate in DiagnosticLevel
            if EventCombination(component, action, result, candidate) not in spec.combinations
        )

    with pytest.raises(ValueError, match="impossible enum combination"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=level,
            component=component,
            event_id=event_id,
            fields=fields,
        )


def test_known_covert_or_semantically_false_enum_combinations_fail() -> None:
    service = _valid_event(EventId.SERVICE_LIFECYCLE)
    fields = dict(service.fields)
    fields[FieldName.RESULT_CODE] = DiagnosticResultCode.ACCEPTED
    with pytest.raises(ValueError, match="impossible enum combination"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.API,
            event_id=EventId.SERVICE_LIFECYCLE,
            fields=fields,
        )

    connector = _valid_event(EventId.CONNECTOR_ATTEMPT)
    fields = dict(connector.fields)
    fields[FieldName.ACTION] = ActionCode.SUBMIT
    fields[FieldName.RESULT_CODE] = DiagnosticResultCode.SUCCEEDED
    with pytest.raises(ValueError, match="impossible enum combination"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.CONNECTOR_BOUNDARY,
            event_id=EventId.CONNECTOR_ATTEMPT,
            fields=fields,
        )


class _CovertAction(StrEnum):
    START = "start"


def test_equal_string_from_a_different_enum_cannot_cross_a_field_boundary() -> None:
    fields = dict(_valid_event(EventId.SERVICE_LIFECYCLE).fields)
    fields[FieldName.ACTION] = _CovertAction.START
    with pytest.raises(TypeError, match="action must be a ActionCode"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.API,
            event_id=EventId.SERVICE_LIFECYCLE,
            fields=fields,
        )


def test_exception_category_result_pair_is_enforced() -> None:
    event = _valid_event(EventId.EXCEPTION_CLASSIFIED)
    fields = dict(event.fields)
    fields[FieldName.ERROR_CATEGORY] = ErrorCategory.TIMEOUT
    fields[FieldName.RESULT_CODE] = DiagnosticResultCode.FAILED
    with pytest.raises(ValueError, match="category and result are inconsistent"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.ERROR,
            component=event.component,
            event_id=event.event_id,
            fields=fields,
        )


@pytest.mark.parametrize("surface", sorted(_synthetic_canaries()))
def test_raw_diagnostic_surface_fields_are_unrepresentable(surface: str) -> None:
    fields: dict[Any, Any] = {
        FieldName.ACTION: ActionCode.START,
        FieldName.RESULT_CODE: DiagnosticResultCode.SUCCEEDED,
        surface: _synthetic_canaries()[surface],
    }
    with pytest.raises(TypeError, match="field names must be FieldName"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.API,
            event_id=EventId.SERVICE_LIFECYCLE,
            fields=fields,
        )


@pytest.mark.parametrize("canary", list(_synthetic_canaries().values()))
def test_content_cannot_hide_in_finite_enum_fields(canary: str) -> None:
    with pytest.raises(TypeError, match="action must be a ActionCode"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=DiagnosticLevel.INFO,
            component=DiagnosticComponent.API,
            event_id=EventId.SERVICE_LIFECYCLE,
            fields={
                FieldName.ACTION: canary,
                FieldName.RESULT_CODE: DiagnosticResultCode.SUCCEEDED,
            },
        )


def test_purpose_specific_ids_are_factory_only_and_not_substitutable() -> None:
    with pytest.raises(TypeError, match="created with new"):
        DiagnosticJobId(object(), UUID("2cb84782-ad9f-47ab-9fa1-7487ad1ff40c"))

    job_id = DiagnosticJobId.new()
    action_id = DiagnosticActionId.new()
    trace_id = DiagnosticTraceId.new()
    assert type(job_id) is DiagnosticJobId
    assert type(action_id) is DiagnosticActionId
    assert type(trace_id) is DiagnosticTraceId
    assert "OPAQUE" in repr(job_id)
    private_value_attribute = "_DiagnosticCorrelationId__value"
    with pytest.raises(AttributeError, match="immutable"):
        setattr(job_id, private_value_attribute, UUID("2cb84782-ad9f-47ab-9fa1-7487ad1ff40c"))

    fields = dict(_valid_event(EventId.JOB_TRANSITION).fields)
    for wrong_value in (
        action_id,
        trace_id,
        OpaqueId.new(),
        str(OpaqueId.new()),
        "MmNiODQ3ODItYWQ5Zi00N2FiLTlmYTEtNzQ4N2FkMWZmNDBj",
    ):
        fields[FieldName.JOB_ID] = wrong_value
        with pytest.raises(TypeError, match="job_id must be a DiagnosticJobId"):
            DiagnosticEvent(
                occurred_at_utc=NOW,
                level=DiagnosticLevel.DEBUG,
                component=DiagnosticComponent.WORKER,
                event_id=EventId.JOB_TRANSITION,
                fields=fields,
            )


def test_event_fields_are_copied_and_immutable() -> None:
    original = _valid_event(EventId.JOB_TRANSITION)
    source = dict(original.fields)
    event = DiagnosticEvent(
        occurred_at_utc=NOW,
        level=original.level,
        component=original.component,
        event_id=EventId.JOB_TRANSITION,
        fields=source,
    )
    source[FieldName.ACTION] = ActionCode.STOP
    assert event.fields[FieldName.ACTION] is original.fields[FieldName.ACTION]
    with pytest.raises(TypeError):
        cast(dict[FieldName, Any], event.fields)[FieldName.ACTION] = ActionCode.STOP


@pytest.mark.parametrize("value", [True, 1.0, "1", None])
def test_bounded_integer_fields_reject_coercion(value: object) -> None:
    event = _valid_event(EventId.JOB_TRANSITION)
    fields = dict(event.fields)
    fields[FieldName.RETRY_NUMBER] = value
    with pytest.raises(TypeError, match="must be an integer"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=event.level,
            component=event.component,
            event_id=event.event_id,
            fields=fields,
        )


@pytest.mark.parametrize(
    ("field_name", "value", "event_id"),
    [
        (FieldName.DURATION_MS, MAX_DURATION_MS + 1, EventId.CONNECTOR_ATTEMPT),
        (FieldName.RETRY_NUMBER, MAX_RETRY_NUMBER + 1, EventId.CONNECTOR_ATTEMPT),
        (FieldName.COUNT, MAX_COUNT + 1, EventId.EVIDENCE_OPERATION),
        (FieldName.DURATION_MS, -1, EventId.CONNECTOR_ATTEMPT),
    ],
)
def test_integer_fields_have_explicit_bounds(
    field_name: FieldName, value: int, event_id: EventId
) -> None:
    event = _valid_event(event_id)
    fields = dict(event.fields)
    fields[field_name] = value
    with pytest.raises(ValueError, match="outside its safe bound"):
        DiagnosticEvent(
            occurred_at_utc=NOW,
            level=event.level,
            component=event.component,
            event_id=event.event_id,
            fields=fields,
        )


class _MessageTrapError(Exception):
    def __str__(self) -> str:
        raise AssertionError("exception text was inspected")


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (asyncio.CancelledError("synthetic canary"), ErrorCategory.CANCELLED),
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
