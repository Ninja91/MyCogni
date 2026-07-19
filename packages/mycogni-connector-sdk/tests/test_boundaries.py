"""Architecture checks for the behavior-free connector protocol package."""

from __future__ import annotations

import ast
import tomllib
from collections.abc import Iterator
from pathlib import Path

from pydantic import BaseModel

from connector_protocol import ActionEnvelope, ConnectorManifest, EvidenceReference, ResultEnvelope

PACKAGE_ROOT = Path(__file__).parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src" / "connector_protocol"
ALLOWED_ABSOLUTE_IMPORTS = {
    "__future__",
    "connector_protocol",
    "datetime",
    "enum",
    "pydantic",
    "re",
    "typing",
    "urllib",
    "uuid",
}
FORBIDDEN_IMPORTS = {
    "asyncio",
    "cryptography",
    "httpx",
    "mycogni",
    "os",
    "pathlib",
    "requests",
    "socket",
    "sqlalchemy",
    "subprocess",
}
FORBIDDEN_CALLS = {"exec", "input", "open", "print"}
FORBIDDEN_FIELD_PARTS = {"file", "filename", "filepath", "path"}


def _source_trees() -> Iterator[tuple[Path, ast.Module]]:
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _field_names(model: type[BaseModel]) -> set[str]:
    names: set[str] = set()
    pending = [model]
    visited: set[type[BaseModel]] = set()
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        names.update(current.model_fields)
        for field in current.model_fields.values():
            annotation = field.annotation
            candidates = getattr(annotation, "__args__", ()) + (annotation,)
            pending.extend(
                candidate
                for candidate in candidates
                if isinstance(candidate, type) and issubclass(candidate, BaseModel)
            )
    return names


def test_package_has_only_schema_dependency_and_no_trusted_core_import() -> None:
    package_config = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert package_config["project"]["dependencies"] == ["pydantic>=2.10,<3"]

    for path, tree in _source_trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots = {alias.name.partition(".")[0] for alias in node.names}
                assert not imported_roots & FORBIDDEN_IMPORTS
                assert imported_roots <= ALLOWED_ABSOLUTE_IMPORTS, (
                    f"{path} imports {sorted(imported_roots)}"
                )
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                imported_root = (node.module or "").partition(".")[0]
                assert imported_root not in FORBIDDEN_IMPORTS
                assert imported_root in ALLOWED_ABSOLUTE_IMPORTS, f"{path} imports {imported_root}"
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in FORBIDDEN_CALLS, (
                    f"{path} invokes forbidden operation: {node.func.id}"
                )


def test_wire_models_have_no_explicit_filesystem_path_field() -> None:
    names = set().union(
        *(_field_names(model) for model in (ConnectorManifest, ActionEnvelope, ResultEnvelope))
    )
    assert not names & FORBIDDEN_FIELD_PARTS
    assert all("path" not in field_name.lower() for field_name in names)
    assert "mailbox_object_id" in EvidenceReference.model_fields


def test_runtime_boundary_is_declaration_not_host_authority() -> None:
    boundary_schema = ConnectorManifest.model_json_schema()["$defs"]["RuntimeBoundary"]
    properties = boundary_schema["properties"]
    assert properties["privileged"]["const"] is False
    assert properties["host_network"]["const"] is False
    assert properties["docker_socket"]["const"] is False
    assert properties["direct_network"]["const"] is False
