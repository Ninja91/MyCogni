#!/usr/bin/env python3
"""Deterministically validate the PF-002 container boundary without a daemon."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_PLATFORMS = {"linux/amd64", "linux/arm64"}


def _load_inventory() -> dict[str, Any]:
    value = json.loads((ROOT / "docker/images.lock.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("image inventory must be a JSON object")
    return value


def validate() -> None:
    inventory = _load_inventory()
    assert inventory["schema_version"] == 1
    assert re.fullmatch(r"20\d{2}-\d{2}-\d{2}", inventory["retrieved_at"])

    dockerfile = (ROOT / "docker/Dockerfile").read_text(encoding="utf-8")
    images = inventory["images"]
    assert isinstance(images, list) and len(images) == 2

    for image in images:
        digest = image["index_digest"]
        assert DIGEST.fullmatch(digest), f"invalid index digest for {image['name']}"
        assert f"@{digest}" in dockerfile, f"unpinned Dockerfile source for {image['name']}"
        platforms = image["platforms"]
        assert set(platforms) == REQUIRED_PLATFORMS
        assert all(DIGEST.fullmatch(value) for value in platforms.values())
        assert len(set(platforms.values())) == 2, "platform manifests must be architecture-specific"
        assert image["official_sources"] and image["retrieval_command"]
        assert all(source.startswith("https://") for source in image["official_sources"])

    assert "ARG PYTHON_IMAGE" not in dockerfile and "ARG UV_IMAGE" not in dockerfile
    assert "FROM ${" not in dockerfile, "base-image pins must not be build-arg overridable"
    from_sources = re.findall(r"^FROM\s+(\S+)", dockerfile, flags=re.MULTILINE)
    assert len(from_sources) == 3
    assert all(re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", source) for source in from_sources)
    inventory_references = {
        f"{image['registry']}/{image['repository']}@{image['index_digest']}" for image in images
    }
    assert set(from_sources) == inventory_references
    forbidden_dockerfile = ("ADD ", "docker.sock", "--privileged", "--cap-add")
    assert not any(token.lower() in dockerfile.lower() for token in forbidden_dockerfile)
    assert "USER 65532:65532" in dockerfile
    assert "UV_PYTHON_DOWNLOADS=never" in dockerfile
    assert "uv sync --frozen --no-dev --no-editable --package mycogni" in dockerfile
    assert "find_spec('connector_protocol') is None" in dockerfile

    bake = (ROOT / "docker-bake.hcl").read_text(encoding="utf-8")
    assert '"linux/amd64"' in bake and '"linux/arm64"' in bake

    smoke = (ROOT / "deploy/compose.container-smoke.yml").read_text(encoding="utf-8")
    required_smoke_controls = (
        'user: "65532:65532"',
        "read_only: true",
        "network_mode: none",
        "cap_drop:",
        "- ALL",
        "no-new-privileges:true",
        "volumes: []",
    )
    assert all(control in smoke for control in required_smoke_controls)
    forbidden_smoke_controls = ("privileged:", "cap_add:", "docker.sock", "network_mode: host")
    assert not any(control in smoke for control in forbidden_smoke_controls)

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert {".git", ".venv", ".env", ".env.*", "*.pem", "*.key"} <= set(dockerignore)


if __name__ == "__main__":
    validate()
    print("PF-002 container skeleton validation passed")
