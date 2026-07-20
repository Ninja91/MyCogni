#!/usr/bin/env python3
"""Strictly validate the rendered runner-mailbox sidecar containment model."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple

if sys.flags.optimize != 0:
    raise SystemExit("runner containment verification requires unoptimized Python")

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.runner-mailbox-smoke.yml"
DOCKERFILE = ROOT / "docker/Dockerfile.runner-mailbox"
DOCKERIGNORE = ROOT / ".dockerignore"
RUNNER_SOURCE_FILES = (
    "__init__.py",
    "domain.py",
    "persistent.py",
    "ports.py",
    "service.py",
    "volatile.py",
)
EXPECTED_DOCKERIGNORE = """# Deny the repository by default. Every build input below is intentional.
**

!pyproject.toml
!uv.lock
!build-constraints.txt
!README.md
!LICENSE
!NOTICE

!src/
!src/**

!packages/
!packages/mycogni-connector-sdk/
!packages/mycogni-connector-sdk/pyproject.toml
!packages/mycogni-connector-sdk/README.md
!packages/mycogni-connector-sdk/src/
!packages/mycogni-connector-sdk/src/**
!packages/mycogni-runner-mailbox-runtime/
!packages/mycogni-runner-mailbox-runtime/pyproject.toml
!packages/mycogni-runner-mailbox-runtime/src/
!packages/mycogni-runner-mailbox-runtime/src/**

!services/
!services/runner_mailbox/
!services/runner_mailbox/__init__.py
!services/runner_mailbox/domain.py
!services/runner_mailbox/persistent.py
!services/runner_mailbox/ports.py
!services/runner_mailbox/service.py
!services/runner_mailbox/volatile.py

# Terminal exclusions override every source-tree negation above.
**/__pycache__
**/__pycache__/**
*.pyc
*.pyo
"""
SERVICE_NAME = "mycogni-runner-mailbox-smoke"
STATE_TARGET = "/var/lib/mycogni-runner"
TMPFS = "/tmp/mycogni-runner:rw,noexec,nosuid,nodev,size=32m,uid=65532,gid=65532,mode=0700"
FIXTURE_IMAGE = "sha256:" + "a" * 64
MODEL_PROJECT = "mycogni-runner-model"
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


def validate_dockerignore(text: str) -> None:
    assert text == EXPECTED_DOCKERIGNORE, ".dockerignore must match the exact build-input model"
    runner_negations = {
        line.removeprefix("!services/runner_mailbox/")
        for line in text.splitlines()
        if line.startswith("!services/runner_mailbox/") and line != "!services/runner_mailbox/"
    }
    assert runner_negations == set(RUNNER_SOURCE_FILES)
    lines = text.splitlines()
    assert lines[-4:] == ["**/__pycache__", "**/__pycache__/**", "*.pyc", "*.pyo"]


def _parse_dockerfile(text: str) -> list[DockerInstruction]:
    logical_lines: list[str] = []
    pending = ""
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if re.match(r"^#\s*(syntax|escape)\s*=", stripped, re.IGNORECASE):
            raise AssertionError("Dockerfile parser directives are not permitted")
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
    uv_image = "ghcr.io/astral-sh/uv@sha256:9a23023be68b2ed09750ae636228e903a54a05ea56ed03a934d00fe9fbeded4b"
    python_image = "docker.io/library/python@sha256:593bd06efe90efa80dc4eee3948be7c0fde4134606dd40d8dd8dbcade98e669c"
    expected = [
        DockerInstruction("ARG", 'SOURCE_DATE_EPOCH="1784419200"'),
        DockerInstruction("FROM", f"{uv_image} AS uv"),
        DockerInstruction("FROM", f"{python_image} AS build"),
        DockerInstruction("COPY", "--from=uv /uv /uvx /bin/"),
        DockerInstruction(
            "ENV",
            "PYTHONDONTWRITEBYTECODE=1 UV_COMPILE_BYTECODE=0 UV_LINK_MODE=copy UV_NO_CACHE=1 UV_NO_DEV=1 "
            "UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/opt/mycogni-runner/.venv",
        ),
        DockerInstruction("WORKDIR", "/build"),
        DockerInstruction(
            "COPY", "pyproject.toml uv.lock build-constraints.txt README.md LICENSE NOTICE ./"
        ),
        DockerInstruction(
            "COPY", "packages/mycogni-connector-sdk ./packages/mycogni-connector-sdk"
        ),
        DockerInstruction(
            "COPY",
            "packages/mycogni-runner-mailbox-runtime ./packages/mycogni-runner-mailbox-runtime",
        ),
        DockerInstruction("COPY", "services/runner_mailbox ./services/runner_mailbox"),
        DockerInstruction(
            "RUN",
            "uv sync --frozen --no-dev --no-editable --package mycogni-runner-mailbox-runtime "
            "&& for activation in /opt/mycogni-runner/.venv/lib/python3.12/site-packages/"
            "_virtualenv.pth /opt/mycogni-runner/.venv/lib/python3.12/site-packages/"
            '_virtualenv.py; do test -f "$activation"; rm "$activation"; '
            'test ! -e "$activation"; done '
            '&& PYTHONPATH=/build /opt/mycogni-runner/.venv/bin/python -c "import importlib.util; '
            "assert importlib.util.find_spec('connector_protocol') is not None; "
            "assert importlib.util.find_spec('mycogni_runner_mailbox_runtime') is not None; "
            "assert importlib.util.find_spec('services.runner_mailbox') is not None; "
            "assert importlib.util.find_spec('mycogni') is None\" "
            "&& for dist_info in /opt/mycogni-runner/.venv/lib/python3.12/site-packages/"
            "mycogni_connector_sdk-0.0.0.dist-info /opt/mycogni-runner/.venv/lib/python3.12/"
            "site-packages/mycogni_runner_mailbox_runtime-0.0.0.dist-info; do "
            'test -f "$dist_info/uv_cache.json"; test "$(grep -c \'/uv_cache\\.json,\' '
            '"$dist_info/RECORD")" -eq 1; rm "$dist_info/uv_cache.json"; '
            "sed -i '/\\/uv_cache\\.json,/d' \"$dist_info/RECORD\"; "
            "test ! -e \"$dist_info/uv_cache.json\"; ! grep -q '/uv_cache\\.json,' "
            '"$dist_info/RECORD"; done '
            "&& rm -rf /root/.cache/uv "
            "&& chown -R 0:0 /opt/mycogni-runner /build/services "
            "&& chmod -R a-w /opt/mycogni-runner /build/services",
        ),
        DockerInstruction("FROM", f"{python_image} AS runner-mailbox"),
        DockerInstruction("ARG", 'BUILD_CREATED="1970-01-01T00:00:00Z"'),
        DockerInstruction("ARG", 'VERSION="0.0.0"'),
        DockerInstruction("ARG", 'VCS_REF="unknown"'),
        DockerInstruction(
            "LABEL",
            'org.opencontainers.image.created="${BUILD_CREATED}" '
            'org.opencontainers.image.description="MyCogni synthetic runner mailbox sidecar probe" '
            'org.opencontainers.image.licenses="Apache-2.0" '
            'org.opencontainers.image.revision="${VCS_REF}" '
            'org.opencontainers.image.source="https://github.com/Ninja91/MyCogni" '
            'org.opencontainers.image.title="MyCogni runner mailbox" '
            'org.opencontainers.image.version="${VERSION}"',
        ),
        DockerInstruction(
            "ENV",
            "HOME=/tmp/mycogni-runner "
            "PATH=/opt/mycogni-runner/.venv/bin:/usr/local/bin:/usr/bin:/bin "
            "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/opt/mycogni-runner "
            "PYTHONUNBUFFERED=1 TMPDIR=/tmp/mycogni-runner",
        ),
        DockerInstruction(
            "RUN",
            "install -d -o 0 -g 0 -m 0555 /opt/mycogni-runner "
            "&& install -d -o 65532 -g 65532 -m 0700 "
            "/var/lib/mycogni-runner /tmp/mycogni-runner",
        ),
        DockerInstruction("COPY", "--chown=0:0 --chmod=0444 LICENSE NOTICE /opt/mycogni-runner/"),
        DockerInstruction(
            "COPY", "--from=build /opt/mycogni-runner/.venv /opt/mycogni-runner/.venv"
        ),
        DockerInstruction("COPY", "--from=build /build/services /opt/mycogni-runner/services"),
        DockerInstruction("WORKDIR", "/var/lib/mycogni-runner"),
        DockerInstruction("USER", "65532:65532"),
        DockerInstruction(
            "ENTRYPOINT",
            '["/opt/mycogni-runner/.venv/bin/python", "-I", "-S", '
            '"/opt/mycogni-runner/.venv/lib/python3.12/site-packages/'
            'mycogni_runner_mailbox_runtime/bootstrap.py"]',
        ),
        DockerInstruction("CMD", '["--state", "/var/lib/mycogni-runner/probe.sqlite"]'),
    ]
    assert instructions == expected, "runner Dockerfile must match the exact stage/input model"


def render_compose(path: Path = COMPOSE, *, image: str = FIXTURE_IMAGE) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["MYCOGNI_RUNNER_IMAGE"] = image
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            MODEL_PROJECT,
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
    assert model.get("name") == MODEL_PROJECT
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
            "name": f"{MODEL_PROJECT}_runner-mailbox-state",
            "driver": "local",
        }
    }


def validate() -> None:
    validate_dockerignore(DOCKERIGNORE.read_text(encoding="utf-8"))
    validate_dockerfile(DOCKERFILE.read_text(encoding="utf-8"))
    validate_model(render_compose())


if __name__ == "__main__":
    validate()
    print("runner mailbox containment model validation passed")
