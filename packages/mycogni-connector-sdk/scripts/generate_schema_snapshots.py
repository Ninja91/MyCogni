"""Generate deterministic protocol-v1 JSON Schema review snapshots."""

from __future__ import annotations

import json
from pathlib import Path

from connector_protocol import ActionEnvelope, ConnectorManifest, ResultEnvelope

SNAPSHOT_DIRECTORY = Path(__file__).parents[1] / "tests" / "snapshots"
MODELS = {
    "action-envelope-v1.schema.json": ActionEnvelope,
    "connector-manifest-v1.schema.json": ConnectorManifest,
    "result-envelope-v1.schema.json": ResultEnvelope,
}


def main() -> None:
    """Write stable, human-reviewable schemas for the public wire models."""
    SNAPSHOT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    for filename, model in MODELS.items():
        schema = model.model_json_schema(mode="validation")
        rendered = json.dumps(schema, indent=2, sort_keys=True) + "\n"
        (SNAPSHOT_DIRECTORY / filename).write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
