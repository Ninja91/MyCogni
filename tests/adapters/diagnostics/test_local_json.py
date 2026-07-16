"""Local JSON sink and unsafe-capture default tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO
from typing import TextIO, cast

import pytest

from mycogni.adapters.diagnostics import (
    LocalJsonSink,
    UnsafeCaptureDefaults,
    render_event_json,
    uvicorn_safe_options,
)
from mycogni.application.diagnostics import (
    ActionCode,
    DiagnosticComponent,
    DiagnosticEvent,
    DiagnosticJobId,
    DiagnosticLevel,
    DiagnosticResultCode,
    EventId,
    FieldName,
    classify_exception,
)


def _exception_event(exception: BaseException) -> DiagnosticEvent:
    return DiagnosticEvent(
        occurred_at_utc=datetime(2030, 1, 1, 0, 0, 0, 123456, tzinfo=UTC),
        level=DiagnosticLevel.ERROR,
        component=DiagnosticComponent.WORKER,
        event_id=EventId.EXCEPTION_CLASSIFIED,
        fields={
            FieldName.ACTION: ActionCode.EXECUTE,
            FieldName.RESULT_CODE: DiagnosticResultCode.FAILED,
            FieldName.ERROR_CATEGORY: classify_exception(exception),
            FieldName.JOB_ID: DiagnosticJobId.new(),
        },
    )


def _synthetic_canaries() -> tuple[str, ...]:
    email = "pii-canary@person.example.test"
    phone = "202" + "-555-" + "0199"
    secret = "ghp_" + "A" * 36
    return (
        f"https://broker.example.test/search?email={email}",
        f"name=Synthetic+Canary&phone={phone}",
        f"Authorization: Bearer {secret}",
        f"exception for Synthetic Canary {email}",
        f"<html><body>{phone}</body></html>",
        f"To: {email}\nSubject: Synthetic Canary",
        f"CONNECT broker.example.test credential={secret}",
        f"browser title Synthetic Canary {email}",
    )


def test_json_rendering_is_deterministic_and_contains_only_catalog_fields() -> None:
    event = _exception_event(RuntimeError("synthetic message must not be rendered"))
    rendered = render_event_json(event)
    assert render_event_json(event) == rendered
    parsed = json.loads(rendered)
    assert parsed == {
        "action": "execute",
        "component": "worker",
        "error_category": "unexpected",
        "event_id": "exception_classified",
        "job_id": str(event.fields[FieldName.JOB_ID]),
        "level": "error",
        "result_code": "failed",
        "time": "2030-01-01T00:00:00.123456Z",
    }
    assert "synthetic message" not in rendered


@pytest.mark.parametrize("canary", _synthetic_canaries())
def test_exception_canaries_never_reach_local_json(canary: str) -> None:
    stream = StringIO()
    LocalJsonSink(stream).emit(_exception_event(RuntimeError(canary)))
    output = stream.getvalue()
    assert canary not in output
    assert "RuntimeError" not in output
    assert "traceback" not in output.lower()
    assert output.endswith("\n")


def test_sink_rejects_untyped_input_without_fallback_stringification() -> None:
    stream = StringIO()
    with pytest.raises(TypeError, match="only DiagnosticEvent"):
        LocalJsonSink(stream).emit("unsafe raw event")  # type: ignore[arg-type]
    assert stream.getvalue() == ""


class _ShortWriter:
    def __init__(self) -> None:
        self.value = ""

    def write(self, text: str) -> int:
        self.value += text[:-1]
        return len(text) - 1


def test_sink_raises_when_stream_reports_a_short_write() -> None:
    stream = _ShortWriter()
    sink = LocalJsonSink(cast(TextIO, stream))
    with pytest.raises(OSError, match="complete event"):
        sink.emit(_exception_event(RuntimeError("synthetic message")))


def test_all_unsafe_automatic_capture_and_export_defaults_are_false() -> None:
    policy = UnsafeCaptureDefaults()
    assert policy.uvicorn_access_log is False
    assert policy.uvicorn_default_log_config is False
    assert policy.proxy_access_log is False
    assert policy.proxy_error_detail is False
    assert policy.browser_console_log is False
    assert policy.browser_network_log is False
    assert policy.browser_page_log is False
    assert policy.mail_protocol_log is False
    assert policy.remote_exporter is False

    options = uvicorn_safe_options()
    assert options == {"access_log": False, "log_config": None, "use_colors": False}
    with pytest.raises(TypeError):
        options["access_log"] = True  # type: ignore[index]
