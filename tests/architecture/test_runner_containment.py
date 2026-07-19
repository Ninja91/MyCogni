"""Runner-only Compose mutation guards."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest


def _validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_runner_containment.py"
    spec = importlib.util.spec_from_file_location("verify_runner_containment", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runner_containment_model_is_least_privilege() -> None:
    _validator().validate()


def test_runner_dockerfile_packages_only_the_mailbox_artifact() -> None:
    validator = _validator()
    source = validator.DOCKERFILE.read_text(encoding="utf-8")
    validator.validate_dockerfile(source)
    with pytest.raises(AssertionError):
        validator.validate_dockerfile(source.replace("find_spec('mycogni') is None", "True"))


@pytest.mark.parametrize(
    "fragment",
    [
        "    read_only: true\n",
        "    network_mode: none\n",
        "    cap_drop:\n      - ALL\n",
        "      - no-new-privileges:true\n",
        "    pids_limit: 64\n",
        "    mem_limit: 512m\n",
    ],
)
def test_runner_containment_mutations_fail_semantic_validation(tmp_path: Path, fragment: str) -> None:
    validator = _validator()
    source = (Path(__file__).resolve().parents[2] / "deploy/compose.runner-mailbox-smoke.yml").read_text(
        encoding="utf-8"
    )
    assert fragment in source
    mutated = tmp_path / "compose.yml"
    mutated.write_text(source.replace(fragment, ""), encoding="utf-8")
    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validator.validate_model(validator.render_compose(mutated))


@pytest.mark.parametrize(
    "injected",
    [
        '    entrypoint: ["/bin/sh"]\n',
        '    devices: ["/dev/null:/dev/null"]\n',
        '    group_add: ["0"]\n',
        '    dns: ["1.1.1.1"]\n',
        '    dns_search: ["example.test"]\n',
        '    extra_hosts: ["host.docker.internal:host-gateway"]\n',
        '    logging: {driver: json-file}\n',
        '    environment: {RUNNER_SECRET: forbidden}\n',
        '    ports: ["127.0.0.1:9000:9000"]\n',
        '    privileged: true\n',
        '    cap_add: ["NET_ADMIN"]\n',
        '    volumes_from: ["mycogni-runner-mailbox-smoke"]\n',
    ],
)
def test_rendered_undeclared_service_surfaces_fail_closed(
    tmp_path: Path, injected: str
) -> None:
    validator = _validator()
    source = (
        Path(__file__).resolve().parents[2] / "deploy/compose.runner-mailbox-smoke.yml"
    ).read_text(encoding="utf-8")
    marker = "    user: \"65532:65532\"\n"
    assert marker in source
    mutated = tmp_path / "compose.yml"
    mutated.write_text(source.replace(marker, marker + injected), encoding="utf-8")
    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validator.validate_model(validator.render_compose(mutated))


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("    ipc: private\n", "    ipc: host\n"),
        ("    cgroup: private\n", "    cgroup: host\n"),
        ("    pull_policy: never\n", "    pull_policy: always\n"),
    ],
)
def test_rendered_host_namespace_and_pull_mutations_fail_closed(
    tmp_path: Path, original: str, replacement: str
) -> None:
    validator = _validator()
    source = (
        Path(__file__).resolve().parents[2] / "deploy/compose.runner-mailbox-smoke.yml"
    ).read_text(encoding="utf-8")
    assert original in source
    mutated = tmp_path / "compose.yml"
    mutated.write_text(source.replace(original, replacement), encoding="utf-8")
    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validator.validate_model(validator.render_compose(mutated))


def test_explicit_pid_namespace_surface_fails_closed(tmp_path: Path) -> None:
    validator = _validator()
    source = (
        Path(__file__).resolve().parents[2] / "deploy/compose.runner-mailbox-smoke.yml"
    ).read_text(encoding="utf-8")
    marker = "    ipc: private\n"
    assert marker in source
    mutated = tmp_path / "compose.yml"
    mutated.write_text(source.replace(marker, marker + "    pid: host\n"), encoding="utf-8")
    with pytest.raises(AssertionError):
        validator.validate_model(validator.render_compose(mutated))


def test_rendered_top_level_secret_surface_fails_closed(tmp_path: Path) -> None:
    validator = _validator()
    source = (
        Path(__file__).resolve().parents[2] / "deploy/compose.runner-mailbox-smoke.yml"
    ).read_text(encoding="utf-8")
    (tmp_path / "synthetic-secret.test").write_text("synthetic", encoding="utf-8")
    copied = tmp_path / "compose.yml"
    marker = "    user: \"65532:65532\"\n"
    assert marker in source
    copied.write_text(
        source.replace(marker, marker + "    secrets: [forbidden]\n")
        + "\nsecrets:\n  forbidden:\n    file: ./synthetic-secret.test\n",
        encoding="utf-8",
    )
    model = validator.render_compose(copied)
    assert "secrets" in model
    with pytest.raises(AssertionError):
        validator.validate_model(model)


def test_equivalent_temp_copy_reaches_and_passes_semantic_validation(tmp_path: Path) -> None:
    validator = _validator()
    source = (
        Path(__file__).resolve().parents[2] / "deploy/compose.runner-mailbox-smoke.yml"
    ).read_text(encoding="utf-8")
    copied = tmp_path / "compose.yml"
    copied.write_text(source, encoding="utf-8")
    validator.validate_model(validator.render_compose(copied))
