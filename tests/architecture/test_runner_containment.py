"""Runner-only Compose mutation guards."""

from __future__ import annotations

import importlib.util
import io
import subprocess
import tarfile
from collections.abc import Callable
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


def _runtime_validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_runner_containment_runtime.py"
    spec = importlib.util.spec_from_file_location("verify_runner_containment_runtime", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _head_revision() -> str:
    root = Path(__file__).resolve().parents[2]
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_runner_containment_model_is_least_privilege() -> None:
    _validator().validate()


def test_dockerignore_has_exact_runner_sources_and_terminal_bytecode_denials() -> None:
    validator = _validator()
    source = validator.DOCKERIGNORE.read_text(encoding="utf-8")
    validator.validate_dockerignore(source)
    assert "!services/runner_mailbox/**" not in source


@pytest.mark.parametrize(
    "fragment",
    [
        "!services/runner_mailbox/persistent.py\n",
        "**/__pycache__\n",
        "**/__pycache__/**\n",
        "*.pyc\n",
        "*.pyo\n",
    ],
)
def test_dockerignore_rejects_source_or_terminal_exclusion_mutation(fragment: str) -> None:
    validator = _validator()
    source = validator.DOCKERIGNORE.read_text(encoding="utf-8")
    assert fragment in source
    with pytest.raises(AssertionError):
        validator.validate_dockerignore(source.replace(fragment, "", 1))


def test_dockerignore_rejects_runner_recursive_reinclude() -> None:
    validator = _validator()
    source = validator.DOCKERIGNORE.read_text(encoding="utf-8")
    marker = "!services/runner_mailbox/__init__.py\n"
    assert marker in source
    with pytest.raises(AssertionError):
        validator.validate_dockerignore(source.replace(marker, "!services/runner_mailbox/**\n"))


def test_runner_dockerfile_packages_only_the_mailbox_artifact() -> None:
    validator = _validator()
    source = validator.DOCKERFILE.read_text(encoding="utf-8")
    validator.validate_dockerfile(source)
    with pytest.raises(AssertionError):
        validator.validate_dockerfile(source.replace("find_spec('mycogni') is None", "True"))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value + "\nCOPY src /opt/mycogni-runner/mycogni\n",
        lambda value: value + "\nCOPY . /opt/mycogni-runner/build-context\n",
        lambda value: value + "\nENV CORE_MODE=enabled\n",
        lambda value: value + "\nVOLUME [\"/forbidden\"]\n",
        lambda value: value.replace(
            "assert importlib.util.find_spec('mycogni') is None",
            "print('skipped trusted-core assertion')",
        ),
        lambda value: "# syntax=docker/dockerfile:1-labs\n" + value,
        lambda value: "# escape=`\n" + value,
    ],
    ids=[
        "core-copy",
        "whole-context-copy",
        "runtime-env",
        "runtime-volume",
        "assertion-replaced",
        "syntax-directive",
        "escape-directive",
    ],
)
def test_runner_dockerfile_exact_model_rejects_added_semantics(
    mutate: Callable[[str], str]
) -> None:
    validator = _validator()
    source = validator.DOCKERFILE.read_text(encoding="utf-8")
    with pytest.raises(AssertionError):
        validator.validate_dockerfile(mutate(source))


def test_runtime_projects_are_parallel_safe_and_unique() -> None:
    validator = _runtime_validator()
    projects = {validator._new_project_name() for _ in range(64)}
    assert len(projects) == 64
    assert all(validator.PROJECT.fullmatch(project) for project in projects)


def test_runtime_cleanup_names_only_owned_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = _runtime_validator()
    calls: list[list[str]] = []

    def fake_run(
        arguments: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        del check
        calls.append(arguments)
        returncode = 1 if "inspect" in arguments else 0
        return subprocess.CompletedProcess(arguments, returncode, "", "")

    monkeypatch.setattr(validator, "_run", fake_run)
    validator._cleanup_resources(["owned-container"], ["owned-volume"])
    flattened = " ".join(" ".join(call) for call in calls)
    assert "owned-container" in flattened and "owned-volume" in flattened
    assert "sibling-core" not in flattened and "sibling-volume" not in flattened
    assert "down" not in flattened and "remove-orphans" not in flattened


def _synthetic_export(extra: dict[str, bytes | None] | None = None) -> bytes:
    root = Path(__file__).resolve().parents[2]
    runtime = _runtime_validator()
    entries: dict[str, bytes | None] = {
        "opt/mycogni-runner/services": None,
        "opt/mycogni-runner/services/runner_mailbox": None,
        "opt/mycogni-runner/LICENSE": (root / "LICENSE").read_bytes(),
        "opt/mycogni-runner/NOTICE": (root / "NOTICE").read_bytes(),
    }
    entries.update(
        {
            f"opt/mycogni-runner/services/runner_mailbox/{name}": (
                root / "services/runner_mailbox" / name
            ).read_bytes()
            for name in runtime.RUNNER_SOURCE_FILES
        }
    )
    site_packages = "opt/mycogni-runner/.venv/lib/python3.12/site-packages"
    for package, (source_root, package_files) in runtime.LOCAL_PACKAGE_FILES.items():
        package_root = f"{site_packages}/{package}"
        entries[package_root] = None
        entries.update(
            {
                f"{package_root}/{name}": (root / source_root / name).read_bytes()
                for name in package_files
            }
        )
    entries.update(extra or {})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, payload in entries.items():
            item = tarfile.TarInfo(name)
            if payload is None:
                item.type = tarfile.DIRTYPE
                item.mode = 0o555
                archive.addfile(item)
            else:
                item.size = len(payload)
                item.mode = 0o444
                archive.addfile(item, io.BytesIO(payload))
    return output.getvalue()


def test_runtime_export_accepts_only_reviewed_runner_sources() -> None:
    _runtime_validator()._validate_exported_filesystem(
        _synthetic_export(), _head_revision()
    )


@pytest.mark.parametrize(
    "extra",
    [
        {
            "opt/mycogni-runner/services/runner_mailbox/__pycache__": None,
            "opt/mycogni-runner/services/runner_mailbox/__pycache__/persistent.cpython-313.pyc": b"dirty",
        },
        {"opt/mycogni-runner/services/runner_mailbox/unreviewed.py": b"dirty"},
        {
            "opt/mycogni-runner/.venv/lib/python3.12/site-packages/connector_protocol/"
            "__pycache__/protocol.cpython-312.pyc": b"dirty"
        },
        {
            "opt/mycogni-runner/.venv/lib/python3.12/site-packages/connector_protocol/"
            "unreviewed.py": b"dirty"
        },
    ],
    ids=[
        "runner-pycache",
        "extra-runner-source",
        "local-package-pyc",
        "extra-local-package-source",
    ],
)
def test_runtime_export_rejects_dirty_or_unreviewed_files(
    extra: dict[str, bytes | None],
) -> None:
    with pytest.raises(AssertionError):
        _runtime_validator()._validate_exported_filesystem(
            _synthetic_export(extra), _head_revision()
        )


@pytest.mark.parametrize(
    "replacement",
    [
        {"opt/mycogni-runner/LICENSE": b"dirty-license"},
        {"opt/mycogni-runner/NOTICE": b"dirty-notice"},
        {
            "opt/mycogni-runner/services/runner_mailbox/persistent.py": b"dirty-source"
        },
    ],
    ids=["license", "notice", "runner-source"],
)
def test_runtime_export_binds_checkout_files_to_exact_git_revision(
    replacement: dict[str, bytes | None],
) -> None:
    with pytest.raises(AssertionError):
        _runtime_validator()._validate_exported_filesystem(
            _synthetic_export(replacement), _head_revision()
        )


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
