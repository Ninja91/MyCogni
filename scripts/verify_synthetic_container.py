#!/usr/bin/env python3
"""Verify the exact networkless synthetic Docker profile without a daemon."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.synthetic-preview.yml"

if sys.flags.optimize != 0:
    raise SystemExit("synthetic container verification requires unoptimized Python")


def _container_validator() -> ModuleType:
    path = ROOT / "scripts/verify_container_skeleton.py"
    spec = importlib.util.spec_from_file_location("verify_container_skeleton", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_compose_model(model: dict[str, Any]) -> None:
    assert set(model) == {"name", "services", "volumes"}
    services = model.get("services")
    assert isinstance(services, dict) and set(services) == {"mycogni-synthetic"}
    service = services["mycogni-synthetic"]
    assert set(service) == {
        "cap_drop",
        "cgroup",
        "command",
        "cpus",
        "entrypoint",
        "image",
        "mem_limit",
        "network_mode",
        "pids_limit",
        "pull_policy",
        "read_only",
        "security_opt",
        "tmpfs",
        "user",
        "volumes",
    }
    assert service.get("image") == "mycogni/core:0.0.0"
    assert service.get("pull_policy") == "never"
    assert service.get("user") == "65532:65532"
    assert service.get("read_only") is True
    assert service.get("network_mode") == "none"
    assert service.get("cgroup") == "private"
    assert service.get("cap_drop") == ["ALL"]
    assert service.get("security_opt") == ["no-new-privileges:true"]
    assert service.get("privileged") in (None, False)
    assert not service.get("cap_add")
    assert service.get("pids_limit") == 64
    assert service.get("mem_limit") == "268435456"
    assert service.get("cpus") == 1.0
    assert service.get("tmpfs") == [
        "/tmp/mycogni:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700"
    ]
    assert service.get("entrypoint") == ["/bin/sh", "-eu", "-c"]

    command = service.get("command")
    assert isinstance(command, list) and len(command) == 1
    assert command[0].splitlines() == [
        "mycogni synthetic init --state-dir /var/lib/mycogni/preview --json",
        "mycogni synthetic health --state-dir /var/lib/mycogni/preview --json",
        "exec mycogni synthetic demo --scenario resurfacing --json",
    ]

    volumes = service.get("volumes")
    assert isinstance(volumes, list) and volumes == [
        {
            "type": "volume",
            "source": "synthetic-state",
            "target": "/var/lib/mycogni",
            "volume": {},
        }
    ]
    top_volumes = model.get("volumes")
    assert isinstance(top_volumes, dict) and set(top_volumes) == {"synthetic-state"}
    volume = top_volumes["synthetic-state"]
    assert isinstance(volume, dict) and set(volume) == {"name"}
    assert isinstance(volume["name"], str) and volume["name"].endswith("_synthetic-state")

    forbidden = ("docker.sock", "/run/", "/var/run/", "type: bind")
    rendered = COMPOSE.read_text(encoding="utf-8").lower()
    assert not any(token in rendered for token in forbidden)


def validate() -> None:
    skeleton = _container_validator()
    skeleton.validate()
    validate_compose_model(skeleton.render_compose(COMPOSE))


if __name__ == "__main__":
    validate()
    print("Synthetic Docker profile static validation passed")
