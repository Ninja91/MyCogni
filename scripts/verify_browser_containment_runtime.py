#!/usr/bin/env python3
"""Run and exactly clean one native SPIKE-BROWSER containment probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

if sys.flags.optimize != 0:
    raise SystemExit("browser containment verification requires unoptimized Python")

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/compose.browser-smoke.yml"
SECCOMP = ROOT / "docker/seccomp.browser.json"
SERVICE = "mycogni-browser-smoke"
PROJECT = re.compile(r"^mycogni-browser-[0-9a-f]{32}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
DIAGNOSTIC_LABEL = "com.mycogni.browser.verifier"
ENTRYPOINT = ["/usr/bin/node", "/opt/mycogni-browser/run.mjs"]
ENVIRONMENT = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
    "HOME=/tmp/mycogni-browser",
    "NODE_ENV=production",
    "TMPDIR=/tmp/mycogni-browser",
]
SOURCE_PATHS = {
    "browser-spike/package.json": "/opt/mycogni-browser/package.json",
    "browser-spike/package-lock.json": "/opt/mycogni-browser/package-lock.json",
    "browser-spike/run.mjs": "/opt/mycogni-browser/run.mjs",
    "browser-spike/synthetic.html": "/opt/mycogni-browser/synthetic.html",
}


def _run(
    arguments: list[str], *, check: bool = True, timeout: float = 30
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(arguments, check=check, capture_output=True, text=True, timeout=timeout)


def _git_environment() -> dict[str, str]:
    environment = {
        key: os.environ[key] for key in ("LANG", "LC_ALL", "LC_CTYPE", "PATH") if key in os.environ
    }
    environment.setdefault("PATH", "/usr/bin:/bin")
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _git_bytes(revision: str, path: str) -> bytes:
    completed = subprocess.run(
        ["git", "--no-replace-objects", "cat-file", "blob", f"{revision}:{path}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        env=_git_environment(),
        timeout=10,
    )
    return completed.stdout


def _one_inspect(kind: str, value: str) -> dict[str, Any]:
    result = json.loads(_run(["docker", kind, "inspect", value]).stdout)
    assert isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict)
    return result[0]


def _compose(image: str, project: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["MYCOGNI_BROWSER_IMAGE"] = image
    return subprocess.run(
        ["docker", "compose", "--project-name", project, "--file", str(COMPOSE), *arguments],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=environment,
    )


def _container_ids(project: str) -> list[str]:
    return _run(
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


def _diagnostic_ids(project: str) -> list[str]:
    return _run(
        [
            "docker",
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            f"label={DIAGNOSTIC_LABEL}={project}",
        ]
    ).stdout.splitlines()


def _is_owned(container: dict[str, Any], project: str) -> bool:
    labels = container["Config"]["Labels"] or {}
    return (
        labels.get("com.docker.compose.project") == project
        and labels.get("com.docker.compose.service") == SERVICE
    ) or labels.get(DIAGNOSTIC_LABEL) == project


def _cleanup(project: str, references: list[str]) -> None:
    candidates = list(
        dict.fromkeys(references + _container_ids(project) + _diagnostic_ids(project))
    )
    owned: list[tuple[str, str]] = []
    for reference in candidates:
        inspected = _run(["docker", "container", "inspect", reference], check=False)
        if inspected.returncode != 0:
            continue
        values = json.loads(inspected.stdout)
        assert isinstance(values, list) and len(values) == 1
        container = values[0]
        assert _is_owned(container, project), "cleanup reference is not invocation-owned"
        owned.append((reference, container["Id"]))
    for reference, _ in owned:
        _run(["docker", "container", "stop", "--time", "3", reference], check=False, timeout=10)
    for reference, _ in owned:
        _run(["docker", "container", "rm", "--force", reference], check=False, timeout=10)
    for reference, container_id in owned:
        assert _run(["docker", "container", "inspect", reference], check=False).returncode != 0
        assert _run(["docker", "container", "inspect", container_id], check=False).returncode != 0
    assert _container_ids(project) == [] and _diagnostic_ids(project) == []


def _validate_inspect(container: dict[str, Any], image: str, revision: str, project: str) -> None:
    assert container["Image"] == image
    config = container["Config"]
    host = container["HostConfig"]
    assert config["Image"] == image
    assert config["User"] == "65532:65532"
    assert config["Entrypoint"] == ENTRYPOINT and config["Cmd"] is None
    assert config["Env"] == ENVIRONMENT
    assert config["Labels"]["org.opencontainers.image.revision"] == revision
    assert "org.opencontainers.image.licenses" not in config["Labels"]
    assert config["Labels"]["com.docker.compose.project"] == project
    assert config["Labels"]["com.docker.compose.service"] == SERVICE
    assert host["NetworkMode"] == "none" and host["ReadonlyRootfs"] is True
    assert host["Privileged"] is False and host["CapAdd"] is None and host["CapDrop"] == ["ALL"]
    assert host["IpcMode"] == "private" and host["PidMode"] in ("", "private")
    assert host["CgroupnsMode"] == "private"
    assert host["PidsLimit"] == 128 and host["NanoCpus"] == 1_000_000_000
    assert host["Memory"] == 1_073_741_824 and host["MemorySwap"] == 1_073_741_824
    assert host["ShmSize"] == 268_435_456
    assert host["Tmpfs"] == {
        "/tmp/mycogni-browser": ("rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700")
    }
    assert host["RestartPolicy"] == {"Name": "no", "MaximumRetryCount": 0}
    assert host["LogConfig"] == {
        "Type": "local",
        "Config": {"compress": "false", "max-file": "1", "max-size": "1m"},
    }
    assert {item["Name"]: (item["Soft"], item["Hard"]) for item in host["Ulimits"]} == {
        "core": (0, 0),
        "nofile": (1024, 1024),
    }
    assert host["SecurityOpt"] == [
        "no-new-privileges:true",
        f"seccomp={SECCOMP.read_text(encoding='utf-8').strip()}",
    ]
    assert container["Mounts"] == [] and host["Binds"] is None


def _safe_diagnostic(
    image: str,
    project: str,
    registered_names: list[str],
    entrypoint: str,
    *command: str,
    timeout: float = 30,
) -> subprocess.CompletedProcess[str]:
    name = f"{project}-diag-{len(registered_names) + 1}"
    assert re.fullmatch(r"mycogni-browser-[0-9a-f]{32}-diag-[1-9][0-9]*", name)
    assert _run(["docker", "container", "inspect", name], check=False).returncode != 0
    registered_names.append(name)
    return _run(
        [
            "docker",
            "run",
            "--name",
            name,
            "--label",
            f"{DIAGNOSTIC_LABEL}={project}",
            "--network",
            "none",
            "--read-only",
            "--ipc",
            "private",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--security-opt",
            f"seccomp={SECCOMP}",
            "--user",
            "65532:65532",
            "--pids-limit",
            "128",
            "--cpus",
            "1",
            "--memory",
            "1g",
            "--memory-swap",
            "1g",
            "--shm-size",
            "256m",
            "--tmpfs",
            "/tmp/mycogni-browser:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700",
            "--entrypoint",
            entrypoint,
            image,
            *command,
        ],
        timeout=timeout,
    )


def _validate_sources(image: str, revision: str, project: str, registered_names: list[str]) -> None:
    paths = list(SOURCE_PATHS.values())
    completed = _safe_diagnostic(image, project, registered_names, "/usr/bin/sha256sum", *paths)
    observed = {
        line.split()[1]: line.split()[0] for line in completed.stdout.splitlines() if line.strip()
    }
    assert set(observed) == set(paths)
    for git_path, image_path in SOURCE_PATHS.items():
        assert observed[image_path] == hashlib.sha256(_git_bytes(revision, git_path)).hexdigest()
    inventory = _safe_diagnostic(
        image,
        project,
        registered_names,
        "/bin/sh",
        "-ceu",
        "test \"$(find /opt/mycogni-browser -mindepth 1 -maxdepth 1 -printf '%f\\n' | sort | tr '\\n' ' ')\" = "
        '"node_modules package-lock.json package.json run.mjs synthetic.html "',
    )
    assert inventory.stdout == "" and inventory.stderr == ""


def _validate_outer_denials(image: str, project: str, registered_names: list[str]) -> None:
    probe = _safe_diagnostic(
        image,
        project,
        registered_names,
        "/bin/sh",
        "-ceu",
        "! chroot / /bin/true 2>/dev/null; "
        "! mount -t tmpfs none /mnt 2>/dev/null; "
        "! touch /opt/mycogni-browser/forbidden 2>/dev/null; "
        "touch /tmp/mycogni-browser/allowed; rm /tmp/mycogni-browser/allowed",
    )
    assert probe.stdout == "" and probe.stderr == ""


def _validate_timeout_cleanup(image: str, project: str, registered_names: list[str]) -> None:
    before = len(registered_names)
    try:
        _safe_diagnostic(
            image,
            project,
            registered_names,
            "/bin/sh",
            "-ceu",
            "sleep 60",
            timeout=1,
        )
    except subprocess.TimeoutExpired:
        pass
    else:
        raise AssertionError("diagnostic timeout control did not time out")
    assert len(registered_names) == before + 1
    name = registered_names[-1]
    container = _one_inspect("container", name)
    labels = container["Config"]["Labels"]
    assert labels[DIAGNOSTIC_LABEL] == project
    assert "com.docker.compose.project" not in labels
    _cleanup(project, [name])
    assert _run(["docker", "container", "inspect", name], check=False).returncode != 0


def _validate_output(text: str) -> None:
    value = json.loads(text)
    assert value["schema"] == "mycogni.browser-spike.v1"
    assert value["fixture"] == "fixture.browser.mycogni.test"
    assert (
        value["fixtureSha256"] == "c7e66496ebde57629d55d931d61c1f8675bb1e7148dafc4e042d547c0c38b178"
    )
    assert value["chromiumSandboxRequested"] is True and value["rendererObserved"] is True
    assert value["privateShmUsed"] is True and value["outerCapabilitiesZero"] is True
    assert value["chromiumActiveCapabilitiesZero"] is True
    assert value["browserBoundingCapabilitiesZero"] is True
    assert value["seccompFiltered"] is True and value["chromiumInternalSeccompFilterAdded"] is True
    assert value["noNewPrivileges"] is True and value["uid"] == 65532
    assert value["allowedLoopbackRequests"] == 1 and value["browserAlternateRequestsDenied"] is True
    assert value["temporaryArtifacts"] == 0
    assert value["cgroup"] == {
        "cpuMax": "100000 100000",
        "memoryMax": "1073741824",
        "pidsMax": "128",
    }
    sandbox = value["sandbox"]
    assert sandbox == {
        "browserSeccompFilters": 1,
        "rendererSeccompFilters": 2,
        "rendererUserNamespaceNested": True,
        "rendererPidNamespaceNested": True,
        "rendererNetworkNamespaceNested": True,
        "rendererMountNamespaceShared": True,
        "rendererRootDistinctOrInaccessible": True,
        "rendererRootDisposition": "distinct-dev-inode",
        "rendererBoundingCapabilities": "000001ffffffffff",
    }
    assert len(value["socketDenials"]) == 8
    assert all(item["denied"] is True for item in value["socketDenials"])
    assert {item["host"] for item in value["socketDenials"]} == {
        "127.0.0.1",
        "::1",
        "198.51.100.1",
        "203.0.113.1",
        "2001:db8::1",
        "1.1.1.1",
        "169.254.169.254",
        "192.168.65.2",
    }
    assert len(value["dnsDenials"]) == 2
    assert all(item["denied"] is True for item in value["dnsDenials"])
    assert {item["name"] for item in value["dnsDenials"]} == {
        "fixture.browser.mycogni.test",
        "metadata.invalid",
    }


def validate(image: str, revision: str) -> None:
    assert SHA256.fullmatch(image)
    assert re.fullmatch(r"[0-9a-f]{40}", revision)
    commit_type = subprocess.run(
        ["git", "--no-replace-objects", "cat-file", "-t", revision],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env=_git_environment(),
    )
    assert commit_type.stdout == "commit\n"
    image_inspect = _one_inspect("image", image)
    assert image_inspect["Architecture"] == "arm64" and image_inspect["Os"] == "linux"
    assert image_inspect["Config"]["User"] == "65532:65532"
    assert image_inspect["Config"]["Entrypoint"] == ENTRYPOINT
    assert image_inspect["Config"]["Labels"] == {
        "org.opencontainers.image.created": "2026-07-20T00:00:00Z",
        "org.opencontainers.image.description": (
            "MyCogni networkless synthetic Chromium boundary probe"
        ),
        "org.opencontainers.image.revision": revision,
        "org.opencontainers.image.source": "https://github.com/Ninja91/MyCogni",
        "org.opencontainers.image.title": "MyCogni browser boundary probe",
        "org.opencontainers.image.version": "0.0.0",
    }

    project = f"mycogni-browser-{uuid4().hex}"
    assert PROJECT.fullmatch(project) and _container_ids(project) == []
    owned: list[str] = []
    diagnostics: list[str] = []
    try:
        _compose(image, project, "create", "--no-build")
        owned = _container_ids(project)
        assert len(owned) == 1
        _validate_inspect(_one_inspect("container", owned[0]), image, revision, project)
        completed = _run(["docker", "container", "start", "--attach", owned[0]], timeout=30)
        assert completed.stderr == ""
        _validate_output(completed.stdout.strip())
        stopped = _one_inspect("container", owned[0])
        assert stopped["State"]["ExitCode"] == 0 and stopped["State"]["OOMKilled"] is False
        _validate_inspect(stopped, image, revision, project)
        _validate_sources(image, revision, project, diagnostics)
        _validate_outer_denials(image, project, diagnostics)
        _validate_timeout_cleanup(image, project, diagnostics)
    finally:
        _cleanup(project, owned + diagnostics)
    assert _container_ids(project) == [] and _diagnostic_ids(project) == []


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--revision", required=True)
    arguments = parser.parse_args()
    validate(arguments.image, arguments.revision)
    print("SPIKE-BROWSER native-arm64 runtime containment validation passed")
