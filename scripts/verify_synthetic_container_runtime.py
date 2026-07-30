#!/usr/bin/env python3
"""Inspect and execute one exact synthetic image/profile on the local Docker host."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.synthetic-preview.yml"
IMAGE = "mycogni/core:0.0.0"
PROJECT = f"mycogni-synth-{uuid.uuid4().hex}"

if sys.flags.optimize != 0:
    raise SystemExit("synthetic container verification requires unoptimized Python")


def _run(
    arguments: list[str], *, check: bool = True, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, capture_output=True, text=True, cwd=cwd)


def _one_json(arguments: list[str]) -> dict[str, Any]:
    value = json.loads(_run(arguments).stdout)
    assert isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict)
    return value[0]


def _lines(arguments: list[str]) -> list[str]:
    return [line for line in _run(arguments).stdout.splitlines() if line]


def _project_containers() -> list[str]:
    return _lines(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        ]
    )


def _project_volumes() -> list[str]:
    return _lines(
        [
            "docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={PROJECT}",
        ]
    )


def _git_revision() -> str:
    status = _run(["git", "status", "--porcelain"], check=True, cwd=ROOT).stdout
    assert status == "", "runtime proof requires a clean reviewed Git checkout"
    revision = _run(["git", "--no-replace-objects", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()
    assert re.fullmatch(r"[0-9a-f]{40}", revision)
    return revision


def _compose(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "docker",
            "compose",
            "--project-name",
            PROJECT,
            "--file",
            str(COMPOSE),
            *arguments,
        ],
        check=check,
    )


def _validate_image(image: dict[str, Any], revision: str) -> None:
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", image["Id"])
    config = image["Config"]
    assert config["User"] == "65532:65532"
    assert config["WorkingDir"] == "/var/lib/mycogni"
    assert config["Env"] and any(
        value == "PATH=/opt/mycogni/.venv/bin:/usr/local/bin:/usr/bin:/bin"
        for value in config["Env"]
    )
    assert config["Labels"]["org.opencontainers.image.revision"] == revision


def _validate_container(container: dict[str, Any], image: dict[str, Any]) -> None:
    assert container["Image"] == image["Id"]
    config = container["Config"]
    assert config["User"] == "65532:65532"
    assert config["WorkingDir"] == "/var/lib/mycogni"
    assert config["Entrypoint"] == ["/bin/sh", "-eu", "-c"]
    assert config["Cmd"] == [
        "mycogni synthetic init --state-dir /var/lib/mycogni/preview --json\n"
        "mycogni synthetic health --state-dir /var/lib/mycogni/preview --json\n"
        "exec mycogni synthetic demo --scenario resurfacing --json\n"
    ]
    assert config["Env"] == image["Config"]["Env"]
    labels = config["Labels"]
    assert labels["com.docker.compose.project"] == PROJECT
    assert labels["com.docker.compose.service"] == "mycogni-synthetic"

    host = container["HostConfig"]
    assert host["ReadonlyRootfs"] is True
    assert host["NetworkMode"] == "none"
    assert host["CgroupnsMode"] == "private"
    assert host["PidMode"] == ""
    assert host["IpcMode"] == "private"
    assert host["UTSMode"] == ""
    assert host["UsernsMode"] == ""
    assert not host["Devices"]
    assert not host["DeviceCgroupRules"]
    assert not host["DeviceRequests"]
    assert host["PortBindings"] == {}
    assert host["PublishAllPorts"] is False
    assert not host["VolumesFrom"]
    assert not host["Links"]
    assert not host["ExtraHosts"]
    assert not host["GroupAdd"]
    assert host["CapDrop"] == ["ALL"] and not host["CapAdd"]
    assert host["SecurityOpt"] == ["no-new-privileges:true"]
    assert host["Privileged"] is False
    assert host["PidsLimit"] == 64
    assert host["Memory"] == 268435456
    assert host["NanoCpus"] == 1_000_000_000
    binds = host["Binds"]
    assert isinstance(binds, list) and len(binds) == 1
    assert binds[0] == f"{PROJECT}_synthetic-state:/var/lib/mycogni:rw"
    assert host["Tmpfs"] == {
        "/tmp/mycogni": "rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=0700"
    }

    mounts = container["Mounts"]
    assert len(mounts) == 1
    assert mounts[0]["Type"] == "volume"
    assert mounts[0]["Destination"] == "/var/lib/mycogni"
    assert mounts[0]["RW"] is True
    networks = container["NetworkSettings"]["Networks"]
    assert isinstance(networks, dict) and set(networks) == {"none"}
    none_network = networks["none"]
    assert none_network["Gateway"] == ""
    assert none_network["IPAddress"] == ""
    assert none_network["IPPrefixLen"] == 0
    assert none_network["IPv6Gateway"] == ""
    assert none_network["GlobalIPv6Address"] == ""
    assert none_network["GlobalIPv6PrefixLen"] == 0


def _validate_volume(volume_name: str) -> None:
    volume = _one_json(["docker", "volume", "inspect", volume_name])
    labels = volume["Labels"]
    assert labels["com.docker.compose.project"] == PROJECT
    assert labels["com.docker.compose.volume"] == "synthetic-state"


def _validate_output(stdout: str) -> None:
    reports = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    assert len(reports) == 3
    assert [report["command"] for report in reports] == [
        "synthetic.init",
        "synthetic.health",
        "synthetic.demo",
    ]
    assert all(report["profile"] == "developer_preview_synthetic_only" for report in reports)
    for report in reports[:2]:
        checks = {check["id"]: check for check in report["checks"]}
        assert checks["runtime_network_containment"] == {
            "id": "runtime_network_containment",
            "reason": "not_proven",
            "status": "not_applicable",
        }
        assert checks["external_actions"]["reason"] == "unavailable_by_composition"
    demo = reports[2]
    assert demo["real_pii_accepted"] is False
    assert demo["live_brokers"] == 0
    assert demo["external_actions"] == "unavailable_by_composition"
    assert demo["real_removal_outcome"] == "not_applicable"
    assert demo["runtime_network_containment"] == "not_proven"


def validate() -> dict[str, Any]:
    revision = _git_revision()
    server = json.loads(_run(["docker", "version", "--format", "{{json .Server}}"]).stdout)
    assert isinstance(server, dict)
    _run(["python3", str(ROOT / "scripts/verify_synthetic_container.py")])
    image = _one_json(["docker", "image", "inspect", IMAGE])
    _validate_image(image, revision)
    assert _project_containers() == []
    assert _project_volumes() == []

    try:
        _compose("create", "--no-build", "mycogni-synthetic")
        containers = _project_containers()
        volumes = _project_volumes()
        assert len(containers) == 1
        assert len(volumes) == 1
        container_id = containers[0]
        assert re.fullmatch(r"[0-9a-f]{64}", container_id)
        _validate_volume(volumes[0])
        _validate_container(
            _one_json(["docker", "container", "inspect", container_id]),
            image,
        )

        completed = _run(["docker", "container", "start", "--attach", container_id], check=False)
        assert completed.returncode == 0, completed.stderr
        _validate_output(completed.stdout)
        stopped = _one_json(["docker", "container", "inspect", container_id])
        assert stopped["State"]["Status"] == "exited" and stopped["State"]["ExitCode"] == 0
        _validate_container(stopped, image)
    finally:
        for resource in _project_containers():
            _run(["docker", "container", "rm", "--force", resource])
        for resource in _project_volumes():
            _run(["docker", "volume", "rm", resource])
        assert _project_containers() == []
        assert _project_volumes() == []

    return {
        "architecture": server["Arch"],
        "docker_engine": server["Version"],
        "image_id": image["Id"],
        "network": "none",
        "os": server["Os"],
        "revision": revision,
        "schema_version": 1,
        "status": "passed",
    }


if __name__ == "__main__":
    print(json.dumps(validate(), sort_keys=True, separators=(",", ":")))
