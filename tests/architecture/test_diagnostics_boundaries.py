"""Static TEL-001 dependency-closure, field, and no-export assertions."""

from __future__ import annotations

import ast
from collections.abc import Callable
from pathlib import Path

import pytest

from mycogni.application.diagnostics import ConnectorCode, ConnectorVersionCode, FieldName

ROOT = Path(__file__).parents[2]
SOURCE_ROOT = ROOT / "src"
ROOT_MODULES = {
    "mycogni.application.diagnostics",
    "mycogni.adapters.diagnostics",
}
DIAGNOSTIC_PACKAGE_ROOT = SOURCE_ROOT / "mycogni/adapters/diagnostics"
FORBIDDEN_IMPORTS = {
    "httpx",
    "logging",
    "opentelemetry",
    "requests",
    "socket",
    "subprocess",
    "urllib",
    "uvicorn",
}
FORBIDDEN_FIELD_PARTS = {
    "body",
    "content",
    "cookie",
    "email",
    "exception_message",
    "header",
    "html",
    "mail",
    "page",
    "path",
    "peer",
    "query",
    "selector",
    "title",
    "traceback",
    "url",
}


def _module_path(module: str, source_root: Path = SOURCE_ROOT) -> Path | None:
    relative = Path(*module.split("."))
    module_file = source_root / relative.with_suffix(".py")
    if module_file.is_file():
        return module_file
    package_file = source_root / relative / "__init__.py"
    return package_file if package_file.is_file() else None


def _module_and_parents(module: str) -> set[str]:
    parts = module.split(".")
    return {".".join(parts[:index]) for index in range(1, len(parts) + 1)}


def _import_from_base(module: str, path: Path, node: ast.ImportFrom) -> str | None:
    if node.level == 0:
        return node.module

    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    package_parts = package.split(".") if package else []
    parents_to_remove = node.level - 1
    assert parents_to_remove < len(package_parts), f"{path} imports beyond its package"
    anchor = package_parts[: len(package_parts) - parents_to_remove]
    if node.module:
        anchor.extend(node.module.split("."))
    return ".".join(anchor)


def _local_imports(
    module: str,
    path: Path,
    source_root: Path = SOURCE_ROOT,
) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("mycogni"):
                    imports.update(_module_and_parents(alias.name))
        elif isinstance(node, ast.ImportFrom):
            base = _import_from_base(module, path, node)
            if not base or not base.startswith("mycogni"):
                continue
            imports.update(_module_and_parents(base))
            for alias in node.names:
                candidate = f"{base}.{alias.name}"
                if alias.name != "*" and _module_path(candidate, source_root) is not None:
                    imports.update(_module_and_parents(candidate))
    return imports


def _diagnostic_dependency_closure(
    source_root: Path = SOURCE_ROOT,
    root_modules: frozenset[str] | set[str] = ROOT_MODULES,
    diagnostic_package_root: Path = DIAGNOSTIC_PACKAGE_ROOT,
) -> dict[str, Path]:
    package_modules = {
        ".".join(path.relative_to(source_root).with_suffix("").parts).removesuffix(".__init__")
        for path in diagnostic_package_root.rglob("*.py")
    }
    pending = list(root_modules | package_modules)
    closure: dict[str, Path] = {}
    while pending:
        module = pending.pop()
        if module in closure:
            continue
        path = _module_path(module, source_root)
        assert path is not None, f"cannot resolve local module {module}"
        closure[module] = path
        pending.extend(_local_imports(module, path, source_root) - closure.keys())
    return closure


def _external_import_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    importlib_aliases: set[str] = set()
    import_module_aliases: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
            importlib_aliases.update(
                alias.asname or alias.name for alias in node.names if alias.name == "importlib"
            )
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").partition(".")[0])
            if node.module == "importlib":
                import_module_aliases.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "import_module"
                )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            assert node.func.id not in {
                "__import__",
                "eval",
                "exec",
                *import_module_aliases,
            }, f"{path} uses dynamic execution/import"
        elif isinstance(node.func, ast.Attribute):
            is_import_module = (
                node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id in importlib_aliases
            )
            assert not is_import_module, f"{path} uses dynamic execution/import"
    return roots - {"mycogni"}


def _assert_closure_safe(closure: dict[str, Path]) -> None:
    for module, path in closure.items():
        imported = _external_import_roots(path)
        assert not imported & FORBIDDEN_IMPORTS, f"{module}: {imported & FORBIDDEN_IMPORTS}"


@pytest.mark.governance_acceptance
def test_complete_diagnostic_dependency_closure_has_no_export_or_logging_dependency(
    governance_criterion: Callable[[str], None],
) -> None:
    governance_criterion("ACC-TEL-001")
    closure = _diagnostic_dependency_closure()
    assert {
        "mycogni.application.diagnostics",
        "mycogni.adapters.diagnostics",
        "mycogni.adapters.diagnostics.local_json",
        "mycogni.adapters.diagnostics.policy",
    } <= set(closure)
    _assert_closure_safe(closure)


def test_relative_import_cannot_escape_diagnostic_dependency_closure(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    adapters = source_root / "mycogni/adapters"
    diagnostics = adapters / "diagnostics"
    diagnostics.mkdir(parents=True)
    (source_root / "mycogni/__init__.py").write_text("", encoding="utf-8")
    (adapters / "__init__.py").write_text("", encoding="utf-8")
    (diagnostics / "__init__.py").write_text(
        "from .. import diagnostic_escape\n",
        encoding="utf-8",
    )
    (adapters / "diagnostic_escape.py").write_text("import socket\n", encoding="utf-8")

    closure = _diagnostic_dependency_closure(
        source_root=source_root,
        root_modules={"mycogni.adapters.diagnostics"},
        diagnostic_package_root=diagnostics,
    )

    assert "mycogni.adapters.diagnostic_escape" in closure
    with pytest.raises(AssertionError, match="socket"):
        _assert_closure_safe(closure)


@pytest.mark.parametrize(
    "source",
    [
        'import importlib\nimportlib.import_module("socket")\n',
        'import importlib as loader\nloader.import_module("socket")\n',
        'from importlib import import_module as load\nload("socket")\n',
        'module_name = "socket"\n__import__(module_name)\n',
    ],
)
def test_dynamic_import_cannot_bypass_diagnostic_guard(tmp_path: Path, source: str) -> None:
    mutation = tmp_path / "diagnostic_mutation.py"
    mutation.write_text(source, encoding="utf-8")

    with pytest.raises(AssertionError, match="dynamic execution/import"):
        _external_import_roots(mutation)


def test_field_catalog_cannot_represent_raw_capture_surfaces() -> None:
    field_names = {field.value for field in FieldName}
    assert all(
        forbidden not in field_name
        for field_name in field_names
        for forbidden in FORBIDDEN_FIELD_PARTS
    )
    assert set(ConnectorCode) == {ConnectorCode.SYNTHETIC_PEOPLE_SEARCH}
    assert set(ConnectorVersionCode) == {ConnectorVersionCode.SYNTHETIC_0_1_0}
