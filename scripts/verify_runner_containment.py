#!/usr/bin/env python3
"""Strictly validate the rendered runner-mailbox sidecar containment model."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any, NamedTuple

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.runner-mailbox-smoke.yml"
DOCKERFILE = ROOT / "docker/Dockerfile.runner-mailbox"
SERVICE_NAME = "mycogni-runner-mailbox-smoke"
STATE_TARGET = "/var/lib/mycogni-runner"
TMPFS = "/tmp/mycogni-runner:rw,noexec,nosuid,nodev,size=32m,uid=65532,gid=65532,mode=0700"
FIXTURE_IMAGE = "sha256:" + "a" * 64
TOP_LEVEL_KEYS = {"name", "services", "volumes"}
SERVICE_KEYS = {
    "cap_drop",
    "cgroup",
    "command",
    "cpus",
    "entrypoint",
    "image",
    "init",
    "ipc",
    "mem_limit",
    "network_mode",
    "pids_limit",
    "pull_policy",
    "read_only",
    "restart",
    "security_opt",
    "tmpfs",
    "user",
    "volumes",
}


class DockerInstruction(NamedTuple):
    name: str
    value: str


def _parse_dockerfile(text: str) -> list[DockerInstruction]:
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


def validate_dockerfile(text: str) -> None:
    instructions = _parse_dockerfile(text)
    from_sources = [item.value.split()[0] for item in instructions if item.name == "FROM"]
    assert len(from_sources) == 3
    assert all(re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", item) for item in from_sources)
    assert not any(item.name == "ADD" for item in instructions)
    assert not any("docker.sock" in item.value.lower() for item in instructions)

    copies = [item.value for item in instructions if item.name == "COPY"]
    assert "packages/mycogni-connector-sdk ./packages/mycogni-connector-sdk" in copies
    assert (
        "packages/mycogni-runner-mailbox-runtime ./packages/mycogni-runner-mailbox-runtime"
        in copies
    )
    assert "services/runner_mailbox ./services/runner_mailbox" in copies
    assert "src ./src" not in copies
    assert not any("packages ./packages" in item for item in copies)
    assert any(
        item.name == "RUN"
        and "uv sync --frozen --no-dev --no-editable --package mycogni-runner-mailbox-runtime"
        in item.value
        and "find_spec('services.runner_mailbox') is not None" in item.value
        and "find_spec('mycogni') is None" in item.value
        for item in instructions
    )

    last_from = max(index for index, item in enumerate(instructions) if item.name == "FROM")
    runtime = instructions[last_from + 1 :]
    assert [item.value for item in runtime if item.name == "USER"] == ["65532:65532"]
    assert [item.value for item in runtime if item.name == "ENTRYPOINT"] == [
        '["/opt/mycogni-runner/.venv/bin/python", "-m", '
        '"mycogni_runner_mailbox_runtime.container_probe"]'
    ]
    assert [item.value for item in runtime if item.name == "CMD"] == [
        '["--state", "/var/lib/mycogni-runner/probe.sqlite"]'
    ]
    assert any(
        item.name == "RUN"
        and "install -d -o 0 -g 0 -m 0555 /opt/mycogni-runner" in item.value
        and "install -d -o 65532 -g 65532 -m 0700 /var/lib/mycogni-runner" in item.value
        for item in runtime
    )


def render_compose(path: Path = COMPOSE, *, image: str = FIXTURE_IMAGE) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["MYCOGNI_RUNNER_IMAGE"] = image
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            "deploy",
            "--file",
            str(path),
            "config",
            "--format",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    model = json.loads(result.stdout)
    assert isinstance(model, dict)
    return model


def validate_model(model: dict[str, Any]) -> None:
    assert set(model) == TOP_LEVEL_KEYS, "undeclared top-level Compose surface"
    assert model.get("name") == "deploy"
    services = model.get("services")
    assert isinstance(services, dict) and set(services) == {SERVICE_NAME}
    service = services[SERVICE_NAME]
    assert isinstance(service, dict) and set(service) == SERVICE_KEYS
    image = service["image"]
    assert type(image) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image)
    assert service["pull_policy"] == "never"
    assert service["entrypoint"] is None, "Compose cannot override the image entrypoint"
    assert service["command"] == ["--state", "/var/lib/mycogni-runner/probe.sqlite"]
    assert service["user"] == "65532:65532"
    assert service["read_only"] is True
    assert service["network_mode"] == "none"
    assert service["ipc"] == "private"
    assert service["cgroup"] == "private"
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["init"] is True
    assert service["restart"] == "no"
    assert service["pids_limit"] == 64
    assert service["cpus"] == 1.0
    assert service["mem_limit"] == "536870912"
    assert service["tmpfs"] == [TMPFS]
    assert service["volumes"] == [
        {
            "type": "volume",
            "source": "runner-mailbox-state",
            "target": STATE_TARGET,
            "volume": {},
        }
    ]
    assert model["volumes"] == {
        "runner-mailbox-state": {
            "name": "mycogni-runner-mailbox-state-smoke",
            "driver": "local",
        }
    }


def validate() -> None:
    validate_dockerfile(DOCKERFILE.read_text(encoding="utf-8"))
    validate_model(render_compose())


if __name__ == "__main__":
    validate()
    print("runner mailbox containment model validation passed")
