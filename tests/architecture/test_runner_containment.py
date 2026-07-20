"""Runner-only Compose mutation guards."""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
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


def _runtime_bootstrap() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = (
        root
        / "packages/mycogni-runner-mailbox-runtime/src/"
        "mycogni_runner_mailbox_runtime/bootstrap.py"
    )
    spec = importlib.util.spec_from_file_location("runner_runtime_bootstrap", path)
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


@pytest.mark.parametrize(
    "script",
    ["verify_runner_containment.py", "verify_runner_containment_runtime.py"],
)
@pytest.mark.parametrize("mode", ["flag", "environment"])
def test_runner_verifiers_refuse_optimized_python_before_work(
    script: str, mode: str
) -> None:
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
    assert (
        completed.stderr
        == "runner containment verification requires unoptimized Python\n"
    )


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


def _synthetic_export(
    extra: dict[str, bytes | None] | None = None,
    *,
    omit: set[str] | None = None,
    architecture: str = "arm64",
) -> bytes:
    root = Path(__file__).resolve().parents[2]
    runtime = _runtime_validator()
    entries: dict[str, bytes | None] = {
        "opt/mycogni-runner": None,
        "opt/mycogni-runner/.venv": None,
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
    entries[site_packages] = None
    expected_site_packages = runtime._expected_site_packages(architecture)
    regular_files = runtime._site_package_regular_files(architecture)
    entries.update(
        {
            f"{site_packages}/{name}": (
                b"synthetic-extension" if name in regular_files else None
            )
            for name in expected_site_packages
        }
    )
    for dist_info, name in runtime.LOCAL_DISTRIBUTION_METADATA.items():
        entries[f"{site_packages}/{dist_info}/METADATA"] = (
            "Metadata-Version: 2.4\n"
            f"Name: {name}\n"
            "Version: 0.0.0\n"
            "License-Expression: Apache-2.0\n\n"
        ).encode()
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
    for name in omit or set():
        entries.pop(name)
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
        _synthetic_export(), _head_revision(), "arm64"
    )


def test_runtime_export_accepts_exact_amd64_extension_inventory() -> None:
    _runtime_validator()._validate_exported_filesystem(
        _synthetic_export(architecture="amd64"), _head_revision(), "amd64"
    )


def test_runtime_export_rejects_architecture_inventory_mismatch() -> None:
    with pytest.raises(AssertionError):
        _runtime_validator()._validate_exported_filesystem(
            _synthetic_export(architecture="arm64"), _head_revision(), "amd64"
        )


def test_runtime_export_rejects_unsupported_architecture() -> None:
    with pytest.raises(AssertionError, match="unsupported image architecture"):
        _runtime_validator()._validate_exported_filesystem(
            _synthetic_export(), _head_revision(), "riscv64"
        )


def test_bootstrap_keeps_stdlib_first_then_site_packages_then_application() -> None:
    bootstrap = _runtime_bootstrap()
    initial = list(bootstrap._expected_initial_path())
    activated = bootstrap._sealed_path(
        initial, isolated=1, no_site=1, site_loaded=False
    )
    assert activated == [
        *initial,
        "/opt/mycogni-runner/.venv/lib/python3.12/site-packages",
        "/opt/mycogni-runner",
    ]


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
        {
            "opt/mycogni-runner/.venv/lib/python3.12/site-packages/"
            "sitecustomize.py": b"dirty"
        },
        {
            "opt/mycogni-runner/.venv/lib/python3.12/site-packages/"
            "unexpected_module.py": b"dirty"
        },
        {
            "opt/mycogni-runner/.venv/lib/python3.12/site-packages/pydantic/"
            "activation.pth": b"dirty"
        },
        {
            "opt/mycogni-runner/.venv/lib/python3.12/site-packages/pydantic/"
            "usercustomize.py": b"dirty"
        },
        {
            "opt/mycogni-runner/mycogni_runner_mailbox_runtime": None,
            "opt/mycogni-runner/mycogni_runner_mailbox_runtime/"
            "container_probe.py": b"forged-sentinel",
        },
        {"opt/mycogni-runner/mycogni_runner_mailbox_runtime.py": b"shadow"},
        {"opt/mycogni-runner/unexpected-root-child": b"dirty"},
    ],
    ids=[
        "runner-pycache",
        "extra-runner-source",
        "local-package-pyc",
        "extra-local-package-source",
        "top-level-sitecustomize",
        "unexpected-top-level-module",
        "nested-pth",
        "nested-usercustomize",
        "root-shadow-package",
        "root-shadow-module",
        "unexpected-root-child",
    ],
)
def test_runtime_export_rejects_dirty_or_unreviewed_files(
    extra: dict[str, bytes | None],
) -> None:
    with pytest.raises(AssertionError):
        _runtime_validator()._validate_exported_filesystem(
            _synthetic_export(extra), _head_revision(), "arm64"
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
            _synthetic_export(replacement), _head_revision(), "arm64"
        )


@pytest.mark.parametrize(
    ("replacement", "omit"),
    [
        ({}, {"mycogni_connector_sdk-0.0.0.dist-info/METADATA"}),
        (
            {"mycogni_connector_sdk-0.0.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: wrong\nVersion: 0.0.0\nLicense-Expression: Apache-2.0\n\n"},
            set(),
        ),
        (
            {"mycogni_runner_mailbox_runtime-0.0.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: mycogni-runner-mailbox-runtime\nVersion: 9.9.9\nLicense-Expression: Apache-2.0\n\n"},
            set(),
        ),
        (
            {"mycogni_runner_mailbox_runtime-0.0.0.dist-info/METADATA": b"Metadata-Version: 2.4\nName: mycogni-runner-mailbox-runtime\nVersion: 0.0.0\nLicense-Expression: Proprietary\n\n"},
            set(),
        ),
    ],
    ids=["missing", "wrong-name", "wrong-version", "wrong-license"],
)
def test_runtime_export_requires_exact_local_distribution_metadata(
    replacement: dict[str, bytes], omit: set[str]
) -> None:
    site_packages = "opt/mycogni-runner/.venv/lib/python3.12/site-packages"
    expanded = {f"{site_packages}/{name}": value for name, value in replacement.items()}
    omitted = {f"{site_packages}/{name}" for name in omit}
    with pytest.raises(AssertionError):
        _runtime_validator()._validate_exported_filesystem(
            _synthetic_export(expanded, omit=omitted), _head_revision(), "arm64"
        )


def test_runtime_export_rejects_tree_hash_as_revision() -> None:
    root = Path(__file__).resolve().parents[2]
    tree = subprocess.run(
        ["git", "rev-parse", "HEAD^{tree}"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    with pytest.raises(AssertionError, match="Git commit object"):
        _runtime_validator()._validate_exported_filesystem(
            _synthetic_export(), tree, "arm64"
        )


def test_git_object_binding_ignores_replace_refs_and_git_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    def git(*arguments: str, env: dict[str, str] | None = None) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
            env=env,
        ).stdout.strip()

    git("init", "--quiet")
    git("config", "user.name", "Synthetic Reviewer")
    git("config", "user.email", "reviewer@example.invalid")
    payload = repository / "payload.txt"
    payload.write_text("original\n", encoding="utf-8")
    git("add", "payload.txt")
    git("commit", "--quiet", "-m", "original")
    original = git("rev-parse", "HEAD")
    payload.write_text("replacement\n", encoding="utf-8")
    git("commit", "--quiet", "-am", "replacement")
    replacement = git("rev-parse", "HEAD")
    git("replace", original, replacement)
    assert git("show", f"{original}:payload.txt") == "replacement"

    unrelated = tmp_path / "unrelated"
    git("init", "--quiet", str(unrelated))
    monkeypatch.setenv("GIT_DIR", str(unrelated / ".git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(unrelated))
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.repositoryformatversion")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "999")
    validator = _runtime_validator()
    monkeypatch.setattr(validator, "ROOT", repository)
    assert validator._git_object_bytes(original, "payload.txt") == b"original\n"


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
