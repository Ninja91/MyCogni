#!/usr/bin/env python3
"""Create, inspect, run and exactly clean one runner-mailbox OCI artifact."""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.runner-mailbox-smoke.yml"
SERVICE = "mycogni-runner-mailbox-smoke"
VOLUME_KEY = "runner-mailbox-state"
STATE_TARGET = "/var/lib/mycogni-runner"
ENTRYPOINT = [
    "/opt/mycogni-runner/.venv/bin/python",
    "-m",
    "mycogni_runner_mailbox_runtime.container_probe",
]
COMMAND = ["--state", "/var/lib/mycogni-runner/probe.sqlite"]
EXPECTED_DISTRIBUTIONS = [
    "annotated-types",
    "cffi",
    "cryptography",
    "mycogni-connector-sdk",
    "mycogni-runner-mailbox-runtime",
    "pycparser",
    "pydantic",
    "pydantic-core",
    "typing-extensions",
    "typing-inspection",
]
RUNNER_SOURCE_FILES = (
    "__init__.py",
    "domain.py",
    "persistent.py",
    "ports.py",
    "service.py",
    "volatile.py",
)
LOCAL_PACKAGE_FILES = {
    "connector_protocol": (
        "packages/mycogni-connector-sdk/src/connector_protocol",
        ("__init__.py", "manifest.py", "protocol.py", "py.typed", "result.py"),
    ),
    "mycogni_runner_mailbox_runtime": (
        "packages/mycogni-runner-mailbox-runtime/src/mycogni_runner_mailbox_runtime",
        ("__init__.py", "container_probe.py", "py.typed"),
    ),
}
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
PROJECT = re.compile(r"^mycogni-runner-[0-9a-f]{32}$")


def _run(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, capture_output=True, text=True)


def _compose(
    image: str, project: str, *arguments: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["MYCOGNI_RUNNER_IMAGE"] = image
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            project,
            "--file",
            str(COMPOSE),
            *arguments,
        ],
        check=check,
        capture_output=True,
        text=True,
        env=environment,
    )


def _one_json(arguments: list[str]) -> dict[str, Any]:
    value = json.loads(_run(arguments).stdout)
    assert isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict)
    return value[0]


def _new_project_name() -> str:
    return f"mycogni-runner-{uuid4().hex}"


def _owned_resources(project: str) -> tuple[list[str], list[str]]:
    containers = _run(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.service={SERVICE}",
        ]
    ).stdout.splitlines()
    volumes = _run(
        [
            "docker",
            "volume",
            "ls",
            "--quiet",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--filter",
            f"label=com.docker.compose.volume={VOLUME_KEY}",
        ]
    ).stdout.splitlines()
    return containers, volumes


def _validate_container_ownership(project: str, container_id: str) -> dict[str, Any]:
    container = _one_json(["docker", "container", "inspect", container_id])
    labels = container["Config"]["Labels"]
    assert labels["com.docker.compose.project"] == project
    assert labels["com.docker.compose.service"] == SERVICE
    return container


def _validate_volume_ownership(project: str, volume_name: str) -> dict[str, Any]:
    volume = _one_json(["docker", "volume", "inspect", volume_name])
    assert volume["Labels"]["com.docker.compose.project"] == project
    assert volume["Labels"]["com.docker.compose.volume"] == VOLUME_KEY
    return volume


def _cleanup_resources(container_ids: list[str], volume_names: list[str]) -> None:
    """Remove only caller-supplied exact resources; never operate on a project."""

    for container_id in container_ids:
        _run(["docker", "container", "rm", "--force", container_id], check=False)
    for volume_name in volume_names:
        _run(["docker", "volume", "rm", volume_name], check=False)
    for container_id in container_ids:
        assert _run(
            ["docker", "container", "inspect", container_id], check=False
        ).returncode != 0
    for volume_name in volume_names:
        assert _run(["docker", "volume", "inspect", volume_name], check=False).returncode != 0


def _validate_inspect(
    container: dict[str, Any],
    image_inspect: dict[str, Any],
    image: str,
    revision: str,
    project: str,
    volume_name: str,
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
    assert config["Labels"]["com.docker.compose.project"] == project
    assert config["Labels"]["com.docker.compose.service"] == SERVICE
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
    assert mount["Name"] == volume_name
    assert mount["Destination"] == STATE_TARGET
    assert mount["RW"] is True


def _git_object_bytes(revision: str, path: str) -> bytes:
    assert re.fullmatch(r"[0-9a-f]{40}", revision)
    result = subprocess.run(
        ["git", "show", f"{revision}:{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return result.stdout


def _validate_exported_filesystem(exported: bytes, revision: str) -> None:
    with tarfile.open(fileobj=io.BytesIO(exported), mode="r:") as archive:
        members: dict[str, tarfile.TarInfo] = {}
        for item in archive.getmembers():
            name = item.name.removeprefix("./").rstrip("/")
            assert name and name not in members, "export contains duplicate paths"
            members[name] = item
        for legal_file in ("LICENSE", "NOTICE"):
            name = f"opt/mycogni-runner/{legal_file}"
            assert name in members and members[name].isreg()
            extracted = archive.extractfile(members[name])
            assert extracted is not None
            assert extracted.read() == _git_object_bytes(revision, legal_file)
        service_root = "opt/mycogni-runner/services"
        runner_root = f"{service_root}/runner_mailbox"
        expected_service_paths = {service_root, runner_root} | {
            f"{runner_root}/{name}" for name in RUNNER_SOURCE_FILES
        }
        actual_service_paths = {
            name
            for name in members
            if name == service_root or name.startswith(f"{service_root}/")
        }
        assert actual_service_paths == expected_service_paths
        assert members[service_root].isdir() and members[runner_root].isdir()
        for source_file in RUNNER_SOURCE_FILES:
            name = f"{runner_root}/{source_file}"
            assert members[name].isreg(), f"runner source is not a regular file: {name}"
            extracted = archive.extractfile(members[name])
            assert extracted is not None
            source_path = f"services/runner_mailbox/{source_file}"
            assert extracted.read() == _git_object_bytes(revision, source_path)
        site_packages = "opt/mycogni-runner/.venv/lib/python3.12/site-packages"
        for package, (source_root, package_files) in LOCAL_PACKAGE_FILES.items():
            package_root = f"{site_packages}/{package}"
            expected_package_paths = {package_root} | {
                f"{package_root}/{name}" for name in package_files
            }
            actual_package_paths = {
                name
                for name in members
                if name == package_root or name.startswith(f"{package_root}/")
            }
            assert actual_package_paths == expected_package_paths
            assert members[package_root].isdir()
            for package_file in package_files:
                name = f"{package_root}/{package_file}"
                assert members[name].isreg(), f"package source is not regular: {name}"
                extracted = archive.extractfile(members[name])
                assert extracted is not None
                assert extracted.read() == _git_object_bytes(
                    revision, f"{source_root}/{package_file}"
                )
        for name in members:
            path = PurePosixPath(name)
            if name == "opt/mycogni-runner" or name.startswith("opt/mycogni-runner/"):
                assert "__pycache__" not in path.parts
                assert path.suffix not in {".pyc", ".pyo"}
        assert not any("mycogni" in PurePosixPath(name).parts for name in members)


def _validate_filesystem(container_id: str, revision: str) -> None:
    exported = subprocess.run(
        ["docker", "export", container_id], check=True, capture_output=True
    ).stdout
    _validate_exported_filesystem(exported, revision)


def _validate_sentinel(output: str) -> dict[str, Any]:
    lines = [line for line in output.splitlines() if line.strip()]
    assert len(lines) == 1
    sentinel = json.loads(lines[0])
    assert sentinel == {
        "installed_distributions": EXPECTED_DISTRIBUTIONS,
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


def verify(image: str, revision: str, *, project: str | None = None) -> dict[str, Any]:
    assert SHA256.fullmatch(image), "image must be an exact local sha256 image ID"
    assert re.fullmatch(r"[0-9a-f]{40}", revision), "revision must be an exact Git commit"
    project_name = project or _new_project_name()
    assert PROJECT.fullmatch(project_name), "project must be an invocation-scoped random name"
    assert _owned_resources(project_name) == ([], []), "unique project unexpectedly exists"
    container_ids: list[str] = []
    volume_names: list[str] = []
    try:
        _compose(image, project_name, "create")
        container_ids, volume_names = _owned_resources(project_name)
        assert len(container_ids) == 1 and len(volume_names) == 1
        container_id = container_ids[0]
        volume_name = volume_names[0]
        _validate_container_ownership(project_name, container_id)
        volume = _validate_volume_ownership(project_name, volume_name)
        image_inspect = _one_json(["docker", "image", "inspect", image])
        before = _one_json(["docker", "container", "inspect", container_id])
        _validate_inspect(
            before, image_inspect, image, revision, project_name, volume_name
        )
        _validate_filesystem(container_id, revision)
        started = _run(["docker", "start", "--attach", container_id])
        sentinel = _validate_sentinel(started.stdout)
        after = _one_json(["docker", "container", "inspect", container_id])
        assert after["State"]["Status"] == "exited"
        assert after["State"]["ExitCode"] == 0
        _validate_inspect(
            after, image_inspect, image, revision, project_name, volume_name
        )
        return {
            "container_id": container_id,
            "image": image,
            "project": project_name,
            "revision": revision,
            "sentinel": sentinel,
            "volume": {
                "labels": volume["Labels"],
                "mountpoint": volume["Mountpoint"],
                "name": volume_name,
            },
        }
    finally:
        discovered_containers, discovered_volumes = _owned_resources(project_name)
        for container_id in discovered_containers:
            _validate_container_ownership(project_name, container_id)
        for volume_name in discovered_volumes:
            _validate_volume_ownership(project_name, volume_name)
        _cleanup_resources(discovered_containers, discovered_volumes)
        assert _owned_resources(project_name) == ([], [])


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--image", required=True)
    parser.add_argument("--revision", required=True)
    arguments = parser.parse_args()
    print(json.dumps(verify(arguments.image, arguments.revision), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
