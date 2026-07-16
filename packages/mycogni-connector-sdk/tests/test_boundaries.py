"""Architecture checks for the behavior-free connector protocol package."""

from __future__ import annotations

import ast
import tomllib
from collections.abc import Iterator
from dataclasses import fields
from pathlib import Path

from connector_protocol import EvidenceReference, RuntimeBoundary

PACKAGE_ROOT = Path(__file__).parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src" / "connector_protocol"
ALLOWED_ABSOLUTE_IMPORTS = {"__future__", "connector_protocol", "dataclasses", "typing"}
FORBIDDEN_CALLS = {"exec", "input", "open", "print"}
FORBIDDEN_EVIDENCE_FIELD_PARTS = {"file", "filename", "filepath", "path"}


def _source_trees() -> Iterator[tuple[Path, ast.Module]]:
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_package_has_no_runtime_or_trusted_core_dependency() -> None:
    package_config = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert package_config["project"]["dependencies"] == []

    for path, tree in _source_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots = {alias.name.partition(".")[0] for alias in node.names}
                assert imported_roots <= ALLOWED_ABSOLUTE_IMPORTS, (
                    f"{path} imports {sorted(imported_roots)}"
                )
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported_root = (node.module or "").partition(".")[0]
                assert imported_root in ALLOWED_ABSOLUTE_IMPORTS, f"{path} imports {imported_root}"
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                raise AssertionError(f"{path} defines runtime behavior: {node.name}")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, (
                    f"{path} invokes forbidden operation: {node.func.id}"
                )


def test_evidence_reference_has_no_explicit_filesystem_path_field() -> None:
    evidence_fields = {item.name.lower() for item in fields(EvidenceReference)}
    assert not evidence_fields & FORBIDDEN_EVIDENCE_FIELD_PARTS
    assert all("path" not in field_name for field_name in evidence_fields)


def test_runtime_boundary_requires_no_privilege_or_host_access() -> None:
    boundary = RuntimeBoundary()
    assert boundary.privileged is False
    assert boundary.host_mounts == ()
    assert boundary.host_network is False
    assert boundary.docker_socket is False
    assert boundary.direct_network is False
