"""SPIKE-BROWSER exact boundary and mutation guards."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest


def _validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_browser_containment.py"
    spec = importlib.util.spec_from_file_location("verify_browser_containment", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime_validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_browser_containment_runtime.py"
    spec = importlib.util.spec_from_file_location("verify_browser_containment_runtime", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_browser_containment_model_is_exact() -> None:
    _validator().validate()


@pytest.mark.parametrize(
    "script", ["verify_browser_containment.py", "verify_browser_containment_runtime.py"]
)
def test_browser_verifier_refuses_optimized_python_before_docker(script: str) -> None:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment.pop("PYTHONOPTIMIZE", None)
    for command, env in (
        ([sys.executable, "-O", str(root / "scripts" / script)], environment),
        ([sys.executable, str(root / "scripts" / script)], environment | {"PYTHONOPTIMIZE": "1"}),
    ):
        completed = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
        assert completed.returncode != 0
        assert completed.stdout == ""
        assert completed.stderr == "browser containment verification requires unoptimized Python\n"


def _valid_runtime_output() -> dict[str, object]:
    return {
        "schema": "mycogni.browser-spike.v1",
        "fixture": "fixture.browser.mycogni.test",
        "fixtureSha256": "c7e66496ebde57629d55d931d61c1f8675bb1e7148dafc4e042d547c0c38b178",
        "chromiumSandboxRequested": True,
        "chromiumProcesses": 7,
        "rendererObserved": True,
        "sandbox": {
            "browserSeccompFilters": 1,
            "rendererSeccompFilters": 2,
            "rendererUserNamespaceNested": True,
            "rendererPidNamespaceNested": True,
            "rendererNetworkNamespaceNested": True,
            "rendererMountNamespaceShared": True,
            "rendererRootDistinctOrInaccessible": True,
            "rendererRootDisposition": "distinct-dev-inode",
        },
        "cgroup": {"cpuMax": "100000 100000", "memoryMax": "1073741824", "pidsMax": "128"},
        "outerCapabilitiesZero": True,
        "noSandboxFlagAbsent": True,
        "privateShmUsed": True,
        "seccompFiltered": True,
        "chromiumInternalSeccompFilterAdded": True,
        "noNewPrivileges": True,
        "uid": 65532,
        "allowedLoopbackRequests": 1,
        "browserAlternateRequestsDenied": True,
        "socketDenials": [
            {"host": host, "denied": True, "code": "DENIED"}
            for host in (
                "127.0.0.1",
                "::1",
                "198.51.100.1",
                "203.0.113.1",
                "2001:db8::1",
                "1.1.1.1",
                "169.254.169.254",
                "192.168.65.2",
            )
        ],
        "dnsDenials": [
            {"name": name, "denied": True, "code": "ENOTFOUND"}
            for name in ("fixture.browser.mycogni.test", "metadata.invalid")
        ],
        "temporaryArtifacts": 0,
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("rendererSeccompFilters", 1),
        ("rendererUserNamespaceNested", False),
        ("rendererPidNamespaceNested", False),
        ("rendererNetworkNamespaceNested", False),
        ("rendererRootDisposition", "same-root"),
    ],
)
def test_runtime_output_rejects_weakened_renderer_evidence(field: str, value: object) -> None:
    validator = _runtime_validator()
    output = _valid_runtime_output()
    output["sandbox"][field] = value  # type: ignore[index]
    with pytest.raises(AssertionError):
        validator._validate_output(json.dumps(output))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.replace("network_mode: none", "network_mode: bridge"),
        lambda value: value.replace("ipc: private", "ipc: host"),
        lambda value: value.replace("      - ALL", "      - SYS_ADMIN"),
        lambda value: value.replace("read_only: true", "read_only: false"),
        lambda value: value.replace("pids_limit: 128", "pids_limit: 0"),
        lambda value: value + "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
        lambda value: value + "    environment:\n      BROKER_TOKEN: synthetic\n",
        lambda value: value.replace("seccomp:../docker/seccomp.browser.json", "seccomp:unconfined"),
    ],
    ids=[
        "network",
        "host-ipc",
        "sys-admin",
        "writable-root",
        "pids",
        "socket",
        "secret",
        "seccomp",
    ],
)
def test_compose_mutations_are_rejected(tmp_path: Path, mutate: Callable[[str], str]) -> None:
    validator = _validator()
    path = tmp_path / "compose.yml"
    path.write_text(mutate(validator.COMPOSE.read_text(encoding="utf-8")), encoding="utf-8")
    with pytest.raises((AssertionError, KeyError, subprocess.CalledProcessError)):
        validator.validate_model(validator.render_compose(path))


def test_seccomp_profile_is_byte_pinned_and_default_deny() -> None:
    validator = _validator()
    raw = validator.SECCOMP.read_bytes()
    validator.validate_seccomp(raw)
    value = json.loads(raw)
    value["defaultAction"] = "SCMP_ACT_ALLOW"
    with pytest.raises(AssertionError):
        validator.validate_seccomp(json.dumps(value).encode())


@pytest.mark.parametrize(
    "fragment",
    [
        "chromiumSandbox: true",
        'serviceWorkers: "block"',
        "acceptDownloads: false",
        '"--disable-seccomp-filter-sandbox"',
        'denySocket("1.1.1.1", 443)',
    ],
)
def test_runtime_source_safety_guards_are_required(fragment: str) -> None:
    validator = _validator()
    source = validator.RUNNER.read_text(encoding="utf-8")
    assert fragment in source
    with pytest.raises(AssertionError):
        validator.validate_runner_text(source.replace(fragment, "", 1))


def test_dockerfile_rejects_unpinned_or_broadened_image() -> None:
    validator = _validator()
    source = validator.DOCKERFILE.read_text(encoding="utf-8")
    for mutation in (
        source.replace("@sha256:5b8f294a", "@sha256:00000000"),
        source + "\nCOPY . /opt/mycogni-browser/context\n",
        source + "\nUSER root\n",
        source + '\nCMD ["--no-sandbox"]\n',
    ):
        with pytest.raises(AssertionError):
            validator.validate_dockerfile_text(mutation)
