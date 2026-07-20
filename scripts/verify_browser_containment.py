#!/usr/bin/env python3
"""Validate the exact SPIKE-BROWSER source and Compose boundary."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

if sys.flags.optimize != 0:
    raise SystemExit("browser containment verification requires unoptimized Python")

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "docker/Dockerfile.browser"
SECCOMP = ROOT / "docker/seccomp.browser.json"
COMPOSE = ROOT / "deploy/compose.browser-smoke.yml"
PACKAGE = ROOT / "browser-spike/package.json"
LOCK = ROOT / "browser-spike/package-lock.json"
RUNNER = ROOT / "browser-spike/run.mjs"
FIXTURE = ROOT / "browser-spike/synthetic.html"
MODEL_PROJECT = "mycogni-browser-model"
SERVICE = "mycogni-browser-smoke"
FIXTURE_IMAGE = "sha256:" + "0" * 64
BASE = (
    "mcr.microsoft.com/playwright:v1.61.1-noble@"
    "sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48"
)
SECCOMP_SHA256 = "f6527f50a04e6441c2c17c98edec1d8c165e0b8d1ed6e2935a40393d647b1640"
FIXTURE_SHA256 = "c7e66496ebde57629d55d931d61c1f8675bb1e7148dafc4e042d547c0c38b178"
TMPFS = "/tmp/mycogni-browser:rw,noexec,nosuid,nodev,size=64m,uid=65532,gid=65532,mode=0700"


def validate_seccomp(raw: bytes) -> None:
    assert hashlib.sha256(raw).hexdigest() == SECCOMP_SHA256
    profile = json.loads(raw)
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    assert set(profile) == {"defaultAction", "archMap", "syscalls"}
    namespace_rule = profile["syscalls"][0]
    assert namespace_rule == {
        "comment": "Allow create user namespaces",
        "names": ["clone", "setns", "unshare"],
        "action": "SCMP_ACT_ALLOW",
        "args": [],
        "includes": {},
        "excludes": {},
    }
    assert profile["syscalls"][1] == {
        "comment": (
            "Allow Chromium chroot only after its user-namespace transition; "
            "outer capabilities remain dropped"
        ),
        "names": ["chroot"],
        "action": "SCMP_ACT_ALLOW",
        "args": [],
        "includes": {},
        "excludes": {},
    }
    assert all(rule["action"] == "SCMP_ACT_ALLOW" for rule in profile["syscalls"])


def validate_package() -> None:
    package = json.loads(PACKAGE.read_text(encoding="utf-8"))
    assert package == {
        "name": "@mycogni/browser-spike",
        "version": "0.0.0",
        "private": True,
        "description": "Networkless synthetic-only Chromium containment decision spike",
        "license": "Apache-2.0",
        "type": "module",
        "dependencies": {"playwright": "1.61.1"},
    }
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    assert lock["lockfileVersion"] == 3 and lock["requires"] is True
    assert set(lock["packages"]) == {
        "",
        "node_modules/fsevents",
        "node_modules/playwright",
        "node_modules/playwright-core",
    }
    for name in ("node_modules/playwright", "node_modules/playwright-core"):
        assert lock["packages"][name]["version"] == "1.61.1"
        assert lock["packages"][name]["license"] == "Apache-2.0"
        assert lock["packages"][name]["integrity"].startswith("sha512-")


def validate_fixture() -> None:
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256
    text = raw.decode("utf-8")
    assert 'data-fixture-origin="fixture.browser.mycogni.test"' in text
    assert "default-src 'none'" in text
    for forbidden in ("<script", "<img", "<form", "<input", "<iframe", "https://", "http://"):
        assert forbidden not in text.lower()


def validate_runner_text(text: str) -> None:
    assert f'const EXPECTED_SHA256 = "{FIXTURE_SHA256}";' in text
    assert 'server.listen({ host: "127.0.0.1", port: 0, exclusive: true }' in text
    assert "chromiumSandbox: true" in text
    assert 'ignoreDefaultArgs: ["--disable-dev-shm-usage"]' in text
    assert "20_000" in text and "process.exit(124)" in text
    assert 'serviceWorkers: "block"' in text
    assert "acceptDownloads: false" in text
    for flag in (
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-seccomp-filter-sandbox",
        "--disable-namespace-sandbox",
        "--disable-gpu-sandbox",
        "--single-process",
        "--in-process-gpu",
        "--no-zygote",
        "--no-zygote-sandbox",
    ):
        assert f'"{flag}"' in text
    assert 'process.type === "renderer"' in text
    assert "renderer.namespaces.user === nodeNamespaces.user" in text
    assert "renderer.namespaces.pid === nodeNamespaces.pid" in text
    assert "renderer.namespaces.net === nodeNamespaces.net" in text
    assert "rendererSeccompFilters <= browserSeccompFilters" in text
    assert (
        'renderer.root === browserProcess.root && renderer.root !== "inaccessible:EACCES"' in text
    )
    assert 'rendererRootDisposition = "distinct-dev-inode"' in text
    assert "Chromium renderer root exposes the outer image sentinel" in text
    assert 'cgroup.cpuMax !== "100000 100000"' in text
    assert "outer capability set is nonzero" in text
    assert 'statfs("/dev/shm")' in text
    assert "process.argv" not in text and "process.env" not in text
    assert "screenshot" not in text.lower() and "tracing" not in text.lower()
    assert "openai" not in text.lower() and "llm" not in text.lower()
    assert "https://" not in text
    assert 'denySocket("1.1.1.1", 443)' in text
    assert 'denySocket("169.254.169.254", 80)' in text
    assert 'denySocket("192.168.65.2", 80)' in text
    assert 'denySocket("2001:db8::1", 443)' in text
    assert 'denyDns("fixture.browser.mycogni.test")' in text
    assert text.count("chromium.launch(") == 1
    launch = text.split("chromium.launch(", 1)[1].split("});", 1)[0]
    assert "FORBIDDEN_SANDBOX_FLAGS" not in launch
    for flag in (
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-seccomp-filter-sandbox",
        "--disable-namespace-sandbox",
        "--disable-gpu-sandbox",
        "--single-process",
        "--in-process-gpu",
        "--no-zygote",
        "--no-zygote-sandbox",
    ):
        assert flag not in launch
    assert "Chromium process capability set is nonzero" in text


def validate_dockerfile_text(text: str) -> None:
    instructions = [
        line.strip().split(maxsplit=1)[0].upper()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and not line.startswith(" ")
    ]
    assert instructions == [
        "FROM",
        "ARG",
        "ARG",
        "ARG",
        "LABEL",
        "ENV",
        "WORKDIR",
        "COPY",
        "RUN",
        "COPY",
        "USER",
        "ENTRYPOINT",
    ]
    assert text.splitlines()[0] == f"FROM {BASE}"
    assert text.count("FROM ") == 1
    assert "USER 65532:65532" in text
    assert 'ENTRYPOINT ["/usr/bin/node", "/opt/mycogni-browser/run.mjs"]' in text
    assert "npm ci --ignore-scripts --omit=dev --no-audit --no-fund" in text
    assert "-name chrome-sandbox -o -name chrome_sandbox" in text
    assert "COPY ." not in text and "ADD " not in text and "VOLUME " not in text
    assert "EXPOSE " not in text and "HEALTHCHECK " not in text and "CMD " not in text
    assert "--no-sandbox" not in text and "SYS_ADMIN" not in text
    assert "org.opencontainers.image.licenses" not in text
    for label in (
        'org.opencontainers.image.created="${BUILD_CREATED}"',
        'org.opencontainers.image.description="MyCogni networkless synthetic Chromium boundary probe"',
        'org.opencontainers.image.revision="${VCS_REF}"',
        'org.opencontainers.image.source="https://github.com/Ninja91/MyCogni"',
        'org.opencontainers.image.title="MyCogni browser boundary probe"',
        'org.opencontainers.image.version="${VERSION}"',
    ):
        assert text.count(label) == 1


def validate_runner() -> None:
    validate_runner_text(RUNNER.read_text(encoding="utf-8"))


def validate_dockerfile() -> None:
    validate_dockerfile_text(DOCKERFILE.read_text(encoding="utf-8"))


def render_compose(path: Path = COMPOSE, *, image: str = FIXTURE_IMAGE) -> dict[str, Any]:
    environment = dict(os.environ)
    environment["MYCOGNI_BROWSER_IMAGE"] = image
    completed = subprocess.run(
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
    value = json.loads(completed.stdout)
    assert isinstance(value, dict)
    return value


def validate_model(model: dict[str, Any]) -> None:
    assert set(model) == {"name", "services"}
    assert model["name"] == MODEL_PROJECT
    assert set(model["services"]) == {SERVICE}
    service = model["services"][SERVICE]
    assert service["image"] == FIXTURE_IMAGE and service["pull_policy"] == "never"
    assert service["user"] == "65532:65532" and service["read_only"] is True
    assert service["network_mode"] == "none" and service["ipc"] == "private"
    assert service["cgroup"] == "private" and service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == [
        "no-new-privileges:true",
        "seccomp:../docker/seccomp.browser.json",
    ]
    assert service["entrypoint"] is None and service["command"] is None
    assert service["init"] is True and service["restart"] == "no"
    assert service["pids_limit"] == 128 and service["cpus"] == 1.0
    assert service["mem_limit"] == "1073741824"
    assert service["memswap_limit"] == "1073741824"
    assert service["shm_size"] == "268435456"
    assert service["ulimits"] == {
        "core": {},
        "nofile": {"soft": 1024, "hard": 1024},
    }
    assert service["logging"] == {
        "driver": "local",
        "options": {"compress": "false", "max-file": "1", "max-size": "1m"},
    }
    assert service["tmpfs"] == [TMPFS]
    for forbidden in (
        "volumes",
        "environment",
        "env_file",
        "ports",
        "expose",
        "privileged",
        "pid",
        "devices",
        "device_cgroup_rules",
        "group_add",
        "extra_hosts",
        "dns",
        "secrets",
        "configs",
        "labels",
    ):
        assert forbidden not in service


def validate() -> None:
    validate_seccomp(SECCOMP.read_bytes())
    validate_package()
    validate_fixture()
    validate_runner()
    validate_dockerfile()
    validate_model(render_compose())


if __name__ == "__main__":
    validate()
    print("SPIKE-BROWSER containment model validation passed")
