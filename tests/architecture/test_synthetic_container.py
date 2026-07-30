"""Regression checks for the one-shot synthetic Docker profile."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from copy import deepcopy
from pathlib import Path
from types import ModuleType

import pytest


def _validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_synthetic_container.py"
    spec = importlib.util.spec_from_file_location("verify_synthetic_container", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _runtime_validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_synthetic_container_runtime.py"
    spec = importlib.util.spec_from_file_location("verify_synthetic_container_runtime", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_synthetic_container_profile_is_exact_and_least_privilege() -> None:
    _validator().validate()


@pytest.mark.parametrize(
    "script",
    ["verify_synthetic_container.py", "verify_synthetic_container_runtime.py"],
)
@pytest.mark.parametrize("mode", ["flag", "environment"])
def test_synthetic_verifiers_refuse_optimized_python_before_work(script: str, mode: str) -> None:
    root = Path(__file__).resolve().parents[2]
    environment = dict(os.environ)
    environment.pop("PYTHONOPTIMIZE", None)
    command = [sys.executable]
    if mode == "flag":
        command.append("-O")
    else:
        environment["PYTHONOPTIMIZE"] = "1"
    command.append(str(root / "scripts" / script))
    completed = subprocess.run(
        command,
        cwd=root,
        capture_output=True,
        text=True,
        env=environment,
        check=False,
    )
    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == "synthetic container verification requires unoptimized Python\n"


def test_runtime_git_revision_is_anchored_to_repository(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = _runtime_validator()
    calls: list[Path | None] = []

    def fake_run(
        arguments: list[str], *, check: bool = True, cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(cwd)
        stdout = "" if "status" in arguments else f"{'a' * 40}\n"
        return subprocess.CompletedProcess(arguments, 0, stdout, "")

    monkeypatch.setattr(runtime, "_run", fake_run)
    monkeypatch.chdir(tmp_path)
    assert runtime._git_revision() == "a" * 40
    assert calls == [runtime.ROOT, runtime.ROOT]


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("environment", {"PATH": "/var/lib/mycogni"}),
        ("pid", "host"),
        ("ipc", "host"),
        ("devices", ["/dev/null:/dev/escape"]),
        ("device_requests", [{"capabilities": [["gpu"]]}]),
        ("configs", [{"source": "injected"}]),
        ("secrets", [{"source": "injected"}]),
        ("group_add", ["999"]),
    ],
)
def test_synthetic_container_profile_rejects_extra_execution_or_host_access(
    key: str, value: object
) -> None:
    validator = _validator()
    model = validator._container_validator().render_compose(validator.COMPOSE)
    mutation = deepcopy(model)
    mutation["services"]["mycogni-synthetic"][key] = value
    with pytest.raises(AssertionError):
        validator.validate_compose_model(mutation)


@pytest.mark.parametrize(
    ("fragment", "replacement"),
    [
        ("    network_mode: none\n", "    network_mode: bridge\n"),
        ("    cgroup: private\n", "    cgroup: host\n"),
        ("    read_only: true\n", "    read_only: false\n"),
        ("      - ALL\n", "      - CHOWN\n"),
        ("      - no-new-privileges:true\n", "      - no-new-privileges:false\n"),
        ("size=16m", "size=1g"),
        ("synthetic-state:/var/lib/mycogni", "./state:/var/lib/mycogni"),
    ],
)
def test_synthetic_container_profile_rejects_weakened_controls(
    tmp_path: Path, fragment: str, replacement: str
) -> None:
    validator = _validator()
    source = validator.COMPOSE.read_text(encoding="utf-8")
    assert fragment in source
    mutation = tmp_path / "compose.yml"
    mutation.write_text(source.replace(fragment, replacement), encoding="utf-8")
    skeleton = validator._container_validator()

    with pytest.raises(AssertionError):
        validator.validate_compose_model(skeleton.render_compose(mutation))
