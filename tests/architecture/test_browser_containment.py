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
            "rendererBoundingCapabilities": "000001ffffffffff",
        },
        "cgroup": {"cpuMax": "100000 100000", "memoryMax": "1073741824", "pidsMax": "128"},
        "outerCapabilitiesZero": True,
        "chromiumActiveCapabilitiesZero": True,
        "browserBoundingCapabilitiesZero": True,
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
    "field", ["chromiumActiveCapabilitiesZero", "browserBoundingCapabilitiesZero"]
)
def test_runtime_output_rejects_nonzero_chromium_capabilities(field: str) -> None:
    validator = _runtime_validator()
    output = _valid_runtime_output()
    output[field] = False
    with pytest.raises(AssertionError):
        validator._validate_output(json.dumps(output))


def test_diagnostic_name_is_registered_before_client_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _runtime_validator()
    project = "mycogni-browser-" + "a" * 32
    registered: list[str] = []
    calls: list[tuple[list[str], float]] = []

    def fake_run(
        arguments: list[str], *, check: bool = True, timeout: float = 30
    ) -> subprocess.CompletedProcess[str]:
        del check
        calls.append((arguments, timeout))
        if arguments[:3] == ["docker", "container", "inspect"]:
            return subprocess.CompletedProcess(arguments, 1, "", "missing")
        if arguments[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(arguments, timeout)
        raise AssertionError(arguments)

    monkeypatch.setattr(validator, "_run", fake_run)
    with pytest.raises(subprocess.TimeoutExpired):
        validator._safe_diagnostic(
            "sha256:" + "b" * 64,
            project,
            registered,
            "/bin/sh",
            "-ceu",
            "sleep 60",
            timeout=0.25,
        )
    name = f"{project}-diag-1"
    assert registered == [name]
    run_arguments = calls[-1][0]
    assert "--rm" not in run_arguments
    assert run_arguments[run_arguments.index("--name") + 1] == name
    assert run_arguments[run_arguments.index("--label") + 1] == (
        f"{validator.DIAGNOSTIC_LABEL}={project}"
    )


def test_cleanup_removes_only_owned_timeout_survivor(monkeypatch: pytest.MonkeyPatch) -> None:
    validator = _runtime_validator()
    project = "mycogni-browser-" + "c" * 32
    name = f"{project}-diag-1"
    container_id = "d" * 64
    alive = True
    calls: list[list[str]] = []

    monkeypatch.setattr(validator, "_container_ids", lambda _: [])
    monkeypatch.setattr(validator, "_diagnostic_ids", lambda _: [container_id] if alive else [])

    def fake_run(
        arguments: list[str], *, check: bool = True, timeout: float = 30
    ) -> subprocess.CompletedProcess[str]:
        nonlocal alive
        del check, timeout
        calls.append(arguments)
        if arguments[:3] == ["docker", "container", "inspect"]:
            if not alive:
                return subprocess.CompletedProcess(arguments, 1, "", "missing")
            return subprocess.CompletedProcess(
                arguments,
                0,
                json.dumps(
                    [
                        {
                            "Id": container_id,
                            "Config": {"Labels": {validator.DIAGNOSTIC_LABEL: project}},
                        }
                    ]
                ),
                "",
            )
        if arguments[:3] == ["docker", "container", "stop"]:
            return subprocess.CompletedProcess(arguments, 0, "", "")
        if arguments[:3] == ["docker", "container", "rm"]:
            alive = False
            return subprocess.CompletedProcess(arguments, 0, "", "")
        raise AssertionError(arguments)

    monkeypatch.setattr(validator, "_run", fake_run)
    validator._cleanup(project, [name])
    assert not alive
    assert any(call[:4] == ["docker", "container", "rm", "--force"] for call in calls)


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
        "Chromium process active capability set is nonzero",
        "Chromium browser process bounding capability set is nonzero",
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
        source.replace(
            'org.opencontainers.image.revision="${VCS_REF}"',
            'org.opencontainers.image.licenses="Apache-2.0" '
            'org.opencontainers.image.revision="${VCS_REF}"',
        ),
    ):
        with pytest.raises(AssertionError):
            validator.validate_dockerfile_text(mutation)


def test_runner_rejects_forbidden_flag_inserted_inside_launch_options() -> None:
    validator = _validator()
    source = validator.RUNNER.read_text(encoding="utf-8")
    mutated = source.replace("  headless: true,", '  headless: true,\n  args: ["--no-sandbox"],', 1)
    with pytest.raises(AssertionError):
        validator.validate_runner_text(mutated)
