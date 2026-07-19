#!/usr/bin/env python3
"""Validate executable runner-mailbox containment policy from Compose's model."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.runner-mailbox-smoke.yml"
SERVICE_NAME = "mycogni-runner-mailbox-smoke"
STATE_TARGET = "/var/lib/mycogni-runner"
TMPFS = "/tmp/mycogni-runner:rw,noexec,nosuid,nodev,size=32m,uid=65532,gid=65532,mode=0700"


def render_compose(path: Path = COMPOSE) -> dict[str, Any]:
    result = subprocess.run(
        ["docker", "compose", "--file", str(path), "config", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    model = json.loads(result.stdout)
    assert isinstance(model, dict)
    return model


def validate_model(model: dict[str, Any]) -> None:
    services = model.get("services")
    assert isinstance(services, dict) and set(services) == {SERVICE_NAME}
    service = services[SERVICE_NAME]
    assert service.get("image") == "mycogni/core:0.0.0"
    assert service.get("user") == "65532:65532"
    assert service.get("read_only") is True
    assert service.get("network_mode") == "none"
    assert service.get("cap_drop") == ["ALL"]
    assert service.get("security_opt") == ["no-new-privileges:true"]
    assert service.get("init") is True
    assert service.get("restart") == "no"
    assert service.get("pids_limit") == 64
    assert service.get("cpus") == 1.0
    assert service.get("mem_limit") == "536870912"
    assert not service.get("privileged")
    assert not service.get("cap_add")
    assert not service.get("ports")
    assert not service.get("environment"), "runner profile cannot carry reusable credentials"
    assert service.get("tmpfs") == [TMPFS]
    volumes = service.get("volumes")
    assert isinstance(volumes, list) and len(volumes) == 1
    volume = volumes[0]
    assert volume == {"type": "volume", "source": "runner-mailbox-state", "target": STATE_TARGET, "volume": {}}
    assert not any("docker.sock" in str(value) for value in volumes)
    top_volumes = model.get("volumes")
    assert top_volumes == {"runner-mailbox-state": {"name": "deploy_runner-mailbox-state", "driver": "local"}}
    command = service.get("command")
    assert isinstance(command, list) and any("docker.sock" in item for item in command)
    assert any("test ! -w /opt/mycogni" in item for item in command)
    assert any("Seccomp" in item for item in command)
    assert any("169.254.169.254" in item for item in command)
    assert any("fd00:ec2::254" in item for item in command)


def validate() -> None:
    validate_model(render_compose())


if __name__ == "__main__":
    validate()
    print("runner mailbox containment model validation passed")
