"""Static TEL-001 dependency-closure, field, and no-export assertions."""

from __future__ import annotations

import ast
from pathlib import Path

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


def _module_path(module: str) -> Path | None:
    relative = Path(*module.split("."))
    module_file = SOURCE_ROOT / relative.with_suffix(".py")
    if module_file.is_file():
        return module_file
    package_file = SOURCE_ROOT / relative / "__init__.py"
    return package_file if package_file.is_file() else None


def _local_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        for name in names:
            if not name.startswith("mycogni"):
                continue
            parts = name.split(".")
            imports.update(".".join(parts[:index]) for index in range(1, len(parts) + 1))
    return imports


def _diagnostic_dependency_closure() -> dict[str, Path]:
    package_modules = {
        ".".join(path.relative_to(SOURCE_ROOT).with_suffix("").parts).removesuffix(".__init__")
        for path in DIAGNOSTIC_PACKAGE_ROOT.rglob("*.py")
    }
    pending = list(ROOT_MODULES | package_modules)
    closure: dict[str, Path] = {}
    while pending:
        module = pending.pop()
        if module in closure:
            continue
        path = _module_path(module)
        assert path is not None, f"cannot resolve local module {module}"
        closure[module] = path
        pending.extend(_local_imports(path) - closure.keys())
    return closure


def _external_import_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            roots.add((node.module or "").partition(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"__import__", "eval", "exec"}, (
                f"{path} uses dynamic execution/import"
            )
    return roots - {"mycogni"}


def test_complete_diagnostic_dependency_closure_has_no_export_or_logging_dependency() -> None:
    closure = _diagnostic_dependency_closure()
    assert {
        "mycogni.application.diagnostics",
        "mycogni.adapters.diagnostics",
        "mycogni.adapters.diagnostics.local_json",
        "mycogni.adapters.diagnostics.policy",
    } <= set(closure)
    for module, path in closure.items():
        imported = _external_import_roots(path)
        assert not imported & FORBIDDEN_IMPORTS, f"{module}: {imported & FORBIDDEN_IMPORTS}"


def test_field_catalog_cannot_represent_raw_capture_surfaces() -> None:
    field_names = {field.value for field in FieldName}
    assert all(
        forbidden not in field_name
        for field_name in field_names
        for forbidden in FORBIDDEN_FIELD_PARTS
    )
    assert set(ConnectorCode) == {ConnectorCode.SYNTHETIC_PEOPLE_SEARCH}
    assert set(ConnectorVersionCode) == {ConnectorVersionCode.SYNTHETIC_0_1_0}
