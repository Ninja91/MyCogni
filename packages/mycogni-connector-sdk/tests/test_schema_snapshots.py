"""Fail when the reviewed wire schema changes without a snapshot update."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from connector_protocol import ActionEnvelope, ConnectorManifest, ResultEnvelope

SNAPSHOT_DIRECTORY = Path(__file__).parent / "snapshots"


@pytest.mark.parametrize(
    ("filename", "model"),
    [
        ("action-envelope-v1.schema.json", ActionEnvelope),
        ("connector-manifest-v1.schema.json", ConnectorManifest),
        ("result-envelope-v1.schema.json", ResultEnvelope),
    ],
)
def test_json_schema_matches_reviewed_snapshot(filename: str, model: type[BaseModel]) -> None:
    expected = json.loads((SNAPSHOT_DIRECTORY / filename).read_text(encoding="utf-8"))
    assert model.model_json_schema(mode="validation") == expected


def _object_schemas(schema: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = [schema, *schema.get("$defs", {}).values()]
    return [candidate for candidate in candidates if candidate.get("type") == "object"]


@pytest.mark.parametrize("model", [ActionEnvelope, ConnectorManifest, ResultEnvelope])
def test_every_object_schema_forbids_unknown_properties(model: type[BaseModel]) -> None:
    object_schemas = _object_schemas(model.model_json_schema(mode="validation"))
    assert object_schemas
    assert all(candidate.get("additionalProperties") is False for candidate in object_schemas)
