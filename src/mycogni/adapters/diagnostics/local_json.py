"""Deterministic newline-delimited JSON sink for validated local events."""

from __future__ import annotations

import json
from datetime import UTC
from enum import StrEnum
from typing import TextIO, cast

from mycogni.application.diagnostics import DiagnosticEvent
from mycogni.domain import OpaqueId

MAX_JSON_LINE_BYTES = 4_096


def _wire_value(value: str | int | OpaqueId | StrEnum) -> str | int:
    if type(value) is OpaqueId:
        return str(value)
    if isinstance(value, StrEnum):
        return value.value
    if type(value) in {str, int}:
        return cast(str | int, value)
    raise TypeError("validated diagnostic value has no local JSON representation")


def render_event_json(event: DiagnosticEvent) -> str:
    """Render canonical JSON without accepting arbitrary objects or fallback repr."""
    if type(event) is not DiagnosticEvent:
        raise TypeError("local diagnostic sink accepts only DiagnosticEvent")
    timestamp = (
        event.occurred_at_utc.astimezone(UTC)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    record: dict[str, str | int] = {
        "component": event.component.value,
        "event_id": event.event_id.value,
        "level": event.level.value,
        "time": timestamp,
    }
    for field_name in sorted(event.fields, key=lambda item: item.value):
        record[field_name.value] = _wire_value(event.fields[field_name])
    rendered = json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if len(rendered.encode("utf-8")) > MAX_JSON_LINE_BYTES:
        raise ValueError("diagnostic event exceeds the local JSON line bound")
    return rendered


class LocalJsonSink:
    """Write validated events to an operator-provided local text stream."""

    __slots__ = ("_stream",)

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def emit(self, event: DiagnosticEvent) -> None:
        """Write one canonical JSON line without flushing or remote export."""
        self._stream.write(render_event_json(event) + "\n")
