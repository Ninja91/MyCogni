#!/usr/bin/env python3
"""Deterministically validate the PF-002 container boundary without a daemon."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_PLATFORMS = {"linux/amd64", "linux/arm64"}
EXPECTED_CONTEXT_ALLOWLIST = {
    "!pyproject.toml",
    "!uv.lock",
    "!build-constraints.txt",
    "!README.md",
    "!LICENSE",
    "!NOTICE",
    "!browser-spike/",
    "!browser-spike/package.json",
    "!browser-spike/package-lock.json",
    "!browser-spike/run.mjs",
    "!browser-spike/synthetic.html",
    "!src/",
    "!src/**",
    "!packages/",
    "!packages/mycogni-connector-sdk/",
    "!packages/mycogni-connector-sdk/pyproject.toml",
    "!packages/mycogni-connector-sdk/README.md",
    "!packages/mycogni-connector-sdk/src/",
    "!packages/mycogni-connector-sdk/src/**",
    "!packages/mycogni-runner-mailbox-runtime/",
    "!packages/mycogni-runner-mailbox-runtime/pyproject.toml",
    "!packages/mycogni-runner-mailbox-runtime/src/",
    "!packages/mycogni-runner-mailbox-runtime/src/**",
    "!services/",
    "!services/runner_mailbox/",
    "!services/runner_mailbox/__init__.py",
    "!services/runner_mailbox/domain.py",
    "!services/runner_mailbox/persistent.py",
    "!services/runner_mailbox/ports.py",
    "!services/runner_mailbox/service.py",
    "!services/runner_mailbox/volatile.py",
}


class DockerInstruction(NamedTuple):
    """One logical, non-comment Dockerfile instruction."""

    name: str
    value: str


def _load_inventory() -> dict[str, Any]:
    value = json.loads((ROOT / "docker/images.lock.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError("image inventory must be a JSON object")
    return value


def parse_dockerfile(text: str) -> list[DockerInstruction]:
    """Parse logical instructions; comment lines never become executable evidence."""
    logical_lines: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not pending and (not stripped or stripped.startswith("#")):
            continue
        continued = stripped.endswith("\\")
        fragment = stripped[:-1].rstrip() if continued else stripped
        pending = f"{pending} {fragment}".strip()
        if not continued:
            logical_lines.append(pending)
            pending = ""
    assert not pending, "Dockerfile ends with an unterminated continuation"

    instructions: list[DockerInstruction] = []
    for line in logical_lines:
        name, separator, value = line.partition(" ")
        assert separator and value.strip(), f"malformed Dockerfile instruction: {line!r}"
        instructions.append(DockerInstruction(name.upper(), " ".join(value.split())))
    return instructions


def validate_dockerfile(text: str, inventory: dict[str, Any]) -> None:
    instructions = parse_dockerfile(text)
    images = inventory["images"]
    assert isinstance(images, list) and len(images) == 3
    assert [image["name"] for image in images] == [
        "python-runtime-and-build", "uv-build-tool", "playwright-browser-spike-base"
    ]

    for image in images:
        digest = image["index_digest"]
        assert DIGEST.fullmatch(digest), f"invalid index digest for {image['name']}"
        platforms = image["platforms"]
        assert set(platforms) == REQUIRED_PLATFORMS
        assert all(DIGEST.fullmatch(value) for value in platforms.values())
        assert len(set(platforms.values())) == 2, "platform manifests must be architecture-specific"
        assert image["official_sources"] and image["retrieval_command"]
        assert all(source.startswith("https://") for source in image["official_sources"])

    from_sources = [
        instruction.value.split()[0] for instruction in instructions if instruction.name == "FROM"
    ]
    assert len(from_sources) == 3
    assert all(re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", source) for source in from_sources)
    inventory_references = {
        f"{image['registry']}/{image['repository']}@{image['index_digest']}" for image in images[:2]
    }
    assert set(from_sources) == inventory_references
    assert all(
        "${" not in instruction.value for instruction in instructions if instruction.name == "FROM"
    )

    assert not any(instruction.name == "ADD" for instruction in instructions)
    forbidden_arguments = ("docker.sock", "--privileged", "--cap-add")
    assert not any(
        token in instruction.value.lower()
        for instruction in instructions
        for token in forbidden_arguments
    )

    last_from = max(
        index for index, instruction in enumerate(instructions) if instruction.name == "FROM"
    )
    runtime = instructions[last_from + 1 :]
    assert [item.value for item in runtime if item.name == "USER"] == ["65532:65532"]
    assert any(
        item.name == "ENV" and "UV_PYTHON_DOWNLOADS=never" in item.value for item in instructions
    )
    assert any(
        item.name == "RUN"
        and "uv sync --frozen --no-dev --no-editable --package mycogni" in item.value
        for item in instructions
    )
    assert not any("/build/.venv" in item.value for item in instructions)
    assert any(
        item.name == "ENV" and "UV_PROJECT_ENVIRONMENT=/opt/mycogni/.venv" in item.value
        for item in instructions
    )
    assert any(
        item.name == "RUN" and "find_spec('connector_protocol') is None" in item.value
        for item in instructions
    )
    assert any(
        item.name == "RUN"
        and "expected = '#!/opt/mycogni/.venv/bin/python'" in item.value
        and "/opt/mycogni/.venv/bin/uvicorn --version" in item.value
        and "/opt/mycogni/.venv/bin/alembic --version" in item.value
        for item in instructions
    )

    copies = [item.value for item in instructions if item.name == "COPY"]
    assert "pyproject.toml uv.lock build-constraints.txt README.md LICENSE NOTICE ./" in copies
    assert "packages/mycogni-connector-sdk ./packages/mycogni-connector-sdk" in copies
    assert "src ./src" in copies
    assert not any("packages ./packages" in value for value in copies)

    assert any(
        item.name == "RUN"
        and "install -d -o 0 -g 0 -m 0555 /opt/mycogni" in item.value
        and "install -d -o 65532 -g 65532 -m 0700 /var/lib/mycogni /tmp/mycogni" in item.value
        for item in runtime
    )
    assert "--from=build /opt/mycogni/.venv /opt/mycogni/.venv" in copies
    assert not any("--chown" in value and "/opt/mycogni" in value for value in copies)
    build_instructions = instructions[:last_from]
    assert any(
        item.name == "RUN"
        and "chown -R 0:0 /opt/mycogni" in item.value
        and "chmod -R a-w /opt/mycogni" in item.value
        for item in build_instructions
    )
    assert not any(
        item.name == "RUN"
        and ("chown -R 0:0 /opt/mycogni" in item.value or "chmod -R a-w /opt/mycogni" in item.value)
        for item in runtime
    ), "runtime hardening must not duplicate the copied virtual-environment layer"
    assert any(
        item.name == "CMD"
        and "/opt/mycogni/.venv/bin/uvicorn --version" in item.value
        and "/opt/mycogni/.venv/bin/alembic --version" in item.value
        and "/opt/mycogni/.venv/bin/python -c" in item.value
        for item in runtime
    )


def render_compose(path: Path) -> dict[str, Any]:
    """Return Docker Compose's canonical model; this does not contact a daemon."""
    result = subprocess.run(
        ["docker", "compose", "--file", str(path), "config", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    model = json.loads(result.stdout)
    assert isinstance(model, dict)
    return model


def validate_compose_model(model: dict[str, Any]) -> None:
    services = model.get("services")
    assert isinstance(services, dict) and set(services) == {"mycogni-core-smoke"}
    service = services["mycogni-core-smoke"]
    assert service.get("user") == "65532:65532"
    assert service.get("read_only") is True
    assert service.get("network_mode") == "none"
    assert service.get("cap_drop") == ["ALL"]
    assert service.get("security_opt") == ["no-new-privileges:true"]
    assert not service.get("volumes"), "smoke container must not receive host or named volumes"
    assert service.get("privileged") in (None, False)
    assert not service.get("cap_add")
    tmpfs = service.get("tmpfs")
    assert isinstance(tmpfs, list) and tmpfs == [
        "/tmp/mycogni:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700"
    ]


def validate_dockerignore(lines: list[str]) -> None:
    rules = [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]
    assert rules and rules[0] == "**", "build context must be denied by default"
    allow_rules = {rule for rule in rules[1:] if rule.startswith("!")}
    assert allow_rules == EXPECTED_CONTEXT_ALLOWLIST
    terminal_denials = ["**/__pycache__", "**/__pycache__/**", "*.pyc", "*.pyo"]
    assert [rule for rule in rules[1:] if not rule.startswith("!")] == terminal_denials
    assert rules[-4:] == terminal_denials


def validate() -> None:
    inventory = _load_inventory()
    assert inventory["schema_version"] == 1
    assert re.fullmatch(r"20\d{2}-\d{2}-\d{2}", inventory["retrieved_at"])

    dockerfile = (ROOT / "docker/Dockerfile").read_text(encoding="utf-8")
    validate_dockerfile(dockerfile, inventory)

    bake = (ROOT / "docker-bake.hcl").read_text(encoding="utf-8")
    assert '"linux/amd64"' in bake and '"linux/arm64"' in bake

    validate_compose_model(render_compose(ROOT / "deploy/compose.container-smoke.yml"))
    validate_dockerignore((ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines())


if __name__ == "__main__":
    validate()
    print("PF-002 container skeleton validation passed")
