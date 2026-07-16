"""Recursive structural guards for simulator imports and deterministic source."""

from __future__ import annotations

import ast
import sys
from pathlib import Path

FORBIDDEN_ESCAPE_IMPORTS = {
    "asyncio",
    "builtins",
    "ctypes",
    "ftplib",
    "http.client",
    "httpx",
    "importlib",
    "os",
    "requests",
    "smtplib",
    "socket",
    "ssl",
    "subprocess",
    "urllib.request",
}
FORBIDDEN_NONDETERMINISTIC_IMPORTS = {"random", "secrets", "uuid"}
FORBIDDEN_DYNAMIC_CALLS = {"__import__", "compile", "eval", "exec"}
FORBIDDEN_NONDETERMINISTIC_CALLS = {
    "urandom",
    "uuid1",
    "uuid4",
    "token_bytes",
    "token_hex",
    "token_urlsafe",
}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree: ast.AST) -> set[str]:
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module)
            imported.update(
                f"{node.module}.{alias.name}" for alias in node.names if alias.name != "*"
            )
    return imported


def _attribute_name(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _module_name(root: Path, path: Path, package: str) -> str:
    relative = path.relative_to(root).with_suffix("")
    parts = relative.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join((package, *parts)) if parts else package


def _resolve_from(module: str, path: Path, node: ast.ImportFrom) -> str:
    if node.level == 0:
        return node.module or ""
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    parts = package.split(".")
    remove = node.level - 1
    if remove >= len(parts):
        raise AssertionError(f"{path.name}: relative import escapes simulator package")
    anchor = parts[: len(parts) - remove]
    if node.module:
        anchor.extend(node.module.split("."))
    return ".".join(anchor)


def _module_file(root: Path, package: str, module: str) -> Path | None:
    if module == package:
        return root / "__init__.py"
    prefix = f"{package}."
    if not module.startswith(prefix):
        return None
    relative = Path(*module.removeprefix(prefix).split("."))
    file_path = (root / relative).with_suffix(".py")
    if file_path.is_file():
        return file_path
    package_path = root / relative / "__init__.py"
    return package_path if package_path.is_file() else None


def assert_structural_import_boundary(path: Path, *, root: Path, package: str) -> None:
    tree = _tree(path)
    module = _module_name(root, path, package)
    for node in ast.walk(tree):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_from(module, path, node)
            names = [base]
            for alias in node.names:
                candidate = f"{base}.{alias.name}"
                if alias.name != "*" and _module_file(root, package, candidate) is not None:
                    names.append(candidate)
        for name in names:
            top = name.partition(".")[0]
            if top == package:
                if _module_file(root, package, name) is None:
                    raise AssertionError(f"{path.name}: unresolved simulator import: {name}")
            elif top not in sys.stdlib_module_names:
                raise AssertionError(f"{path.name}: third-party import denied: {name}")


def assert_no_outbound_network_source(path: Path) -> None:
    tree = _tree(path)
    imported = _imports(tree)
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update((alias.asname or alias.name, alias.name) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            aliases.update(
                (alias.asname or alias.name, f"{node.module}.{alias.name}")
                for alias in node.names
                if alias.name != "*"
            )
    resolved_attributes: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        dotted = _attribute_name(node)
        root, separator, suffix = dotted.partition(".")
        resolved = aliases.get(root, root)
        resolved_attributes.add(f"{resolved}.{suffix}" if separator else resolved)
    violations = {
        forbidden
        for forbidden in FORBIDDEN_ESCAPE_IMPORTS
        if any(
            name == forbidden or name.startswith(f"{forbidden}.")
            for name in imported | resolved_attributes
        )
    }
    if violations:
        raise AssertionError(
            f"{path.name}: process/network escape import denied: {sorted(violations)}"
        )
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            name = node.func.attr
        dynamic_call = isinstance(node.func, ast.Name) and name in FORBIDDEN_DYNAMIC_CALLS
        process_call = name in {
            "system",
            "popen",
            "create_subprocess_exec",
            "create_subprocess_shell",
        }
        if dynamic_call or process_call:
            raise AssertionError(f"{path.name}: dynamic/process escape call denied: {name}")


def assert_deterministic_source(path: Path) -> None:
    tree = _tree(path)
    imported = _imports(tree)
    import_violations = imported & FORBIDDEN_NONDETERMINISTIC_IMPORTS
    if import_violations:
        raise AssertionError(
            f"{path.name}: nondeterministic import denied: {sorted(import_violations)}"
        )
    nondeterministic_aliases: set[str] = set()
    wall_clock_aliases = {"date", "datetime", "time"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in {"date", "datetime", "time"}:
                    wall_clock_aliases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in FORBIDDEN_NONDETERMINISTIC_CALLS:
                    nondeterministic_aliases.add(alias.asname or alias.name)
                if node.module in {"datetime", "time"} and alias.name in {
                    "date",
                    "datetime",
                    "time",
                }:
                    wall_clock_aliases.add(alias.asname or alias.name)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = ""
        if isinstance(node.func, ast.Name):
            call_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            call_name = node.func.attr
        if call_name in FORBIDDEN_NONDETERMINISTIC_CALLS | nondeterministic_aliases:
            raise AssertionError(f"{path.name}: nondeterministic call denied: {call_name}")
        wall_clock_call = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in wall_clock_aliases
            and node.func.attr in {"now", "time", "today", "utcnow"}
        )
        if wall_clock_call:
            raise AssertionError(f"{path.name}: nondeterministic wall-clock call denied")


def assert_simulator_tree(root: Path, *, package: str = "simulator") -> None:
    paths = sorted(root.rglob("*.py"))
    if not paths:
        raise AssertionError("simulator source tree is empty")
    for path in paths:
        if path.is_symlink():
            raise AssertionError(f"{path.name}: simulator source symlink denied")
        assert_structural_import_boundary(path, root=root, package=package)
        assert_no_outbound_network_source(path)
        assert_deterministic_source(path)
