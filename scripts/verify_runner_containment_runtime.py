#!/usr/bin/env python3
"""Create, run, inspect and clean one exact runner-mailbox OCI artifact."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.runner-mailbox-smoke.yml"
PROJECT = "deploy"
SERVICE = "mycogni-runner-mailbox-smoke"
VOLUME = "mycogni-runner-mailbox-state-smoke"
STATE_TARGET = "/var/lib/mycogni-runner"
ENTRYPOINT = [
    "/opt/mycogni-runner/.venv/bin/python",
    "-m",
    "mycogni_runner_mailbox_runtime.container_probe",
]
COMMAND = ["--state", "/var/lib/mycogni-runner/probe.sqlite"]
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def _compose(image: str, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(
        [
            "env",
            f"MYCOGNI_RUNNER_IMAGE={image}",
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


def _one_json(arguments: list[str]) -> dict[str, Any]:
    value = json.loads(_run(arguments).stdout)
    assert isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict)
    return value[0]


def _assert_clean_start(image: str) -> None:
    assert not _compose(image, "ps", "--all", "--quiet").stdout.strip(), (
        "runner smoke container already exists; run the documented cleanup command"
    )
    assert _run(["docker", "volume", "inspect", VOLUME], check=False).returncode != 0, (
        "runner smoke volume already exists; preserve or remove it explicitly before testing"
    )


def _validate_inspect(
    container: dict[str, Any], image_inspect: dict[str, Any], image: str, revision: str
) -> None:
    assert container["Image"] == image
    config = container["Config"]
    host = container["HostConfig"]
    assert config["Image"] == image
    assert config["User"] == "65532:65532"
    assert config["Entrypoint"] == ENTRYPOINT
    assert config["Cmd"] == COMMAND
    assert config["Env"] == image_inspect["Config"]["Env"], "Compose injected runtime environment"
    assert config["Labels"]["org.opencontainers.image.revision"] == revision
    assert host["NetworkMode"] == "none"
    assert host["ReadonlyRootfs"] is True
    assert host["Privileged"] is False
    assert host["CapDrop"] == ["ALL"]
    assert host["SecurityOpt"] == ["no-new-privileges:true"]
    assert host["IpcMode"] == "private"
    assert host["PidMode"] in ("", "private")
    assert host["CgroupnsMode"] == "private"
    assert host["PidsLimit"] == 64
    assert host["NanoCpus"] == 1_000_000_000
    assert host["Memory"] == 536_870_912
    assert host["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0}
    assert host["Tmpfs"] == {
        "/tmp/mycogni-runner": "rw,noexec,nosuid,nodev,size=32m,uid=65532,gid=65532,mode=0700"
    }
    mounts = container["Mounts"]
    assert len(mounts) == 1
    mount = mounts[0]
    assert mount["Type"] == "volume"
    assert mount["Name"] == VOLUME
    assert mount["Destination"] == STATE_TARGET
    assert mount["RW"] is True


def _validate_sentinel(output: str) -> dict[str, Any]:
    lines = [line for line in output.splitlines() if line.strip()]
    assert len(lines) == 1
    sentinel = json.loads(lines[0])
    assert sentinel == {
        "mailbox_state_created": True,
        "network_denials": {
            "dns": True,
            "host_gateway_ipv4": True,
            "metadata_ipv4": True,
            "public_ipv4": True,
            "public_ipv6": True,
            "ula_ipv6": True,
        },
        "probe": "mycogni.runner_mailbox.container.v1",
        "recovery_required": False,
        "schema": 1,
        "uid": 65532,
    }
    return sentinel


def verify(image: str, revision: str) -> dict[str, Any]:
    assert SHA256.fullmatch(image), "image must be an exact local sha256 image ID"
    assert re.fullmatch(r"[0-9a-f]{40}", revision), "revision must be an exact Git commit"
    _assert_clean_start(image)
    created = False
    container_id = ""
    try:
        _compose(image, "create", "--force-recreate")
        created = True
        ids = _compose(image, "ps", "--all", "--quiet").stdout.splitlines()
        assert len(ids) == 1
        container_id = ids[0]
        image_inspect = _one_json(["docker", "image", "inspect", image])
        before = _one_json(["docker", "container", "inspect", container_id])
        _validate_inspect(before, image_inspect, image, revision)
        started = _run(["docker", "start", "--attach", container_id])
        sentinel = _validate_sentinel(started.stdout)
        after = _one_json(["docker", "container", "inspect", container_id])
        assert after["State"]["Status"] == "exited"
        assert after["State"]["ExitCode"] == 0
        _validate_inspect(after, image_inspect, image, revision)
        return {
            "container_id": container_id,
            "image": image,
            "revision": revision,
            "sentinel": sentinel,
        }
    finally:
        if created:
            _compose(image, "down", "--volumes", "--remove-orphans", check=False)
            assert _run(["docker", "container", "inspect", container_id], check=False).returncode != 0
            assert _run(["docker", "volume", "inspect", VOLUME], check=False).returncode != 0


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--image", required=True)
    parser.add_argument("--revision", required=True)
    arguments = parser.parse_args()
    print(json.dumps(verify(arguments.image, arguments.revision), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
