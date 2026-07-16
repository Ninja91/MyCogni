"""Static fail-closed guards for simulator determinism and network isolation."""

from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_OUTBOUND_IMPORTS = {
    "ftplib",
    "http.client",
    "httpx",
    "importlib",
    "requests",
    "smtplib",
    "socket",
    "urllib.request",
}
FORBIDDEN_NONDETERMINISTIC_IMPORTS = {"random", "secrets", "uuid"}
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
    return imported


def assert_no_outbound_network_source(path: Path) -> None:
    tree = _tree(path)
    imported = _imports(tree)
    violations = {
        forbidden
        for forbidden in FORBIDDEN_OUTBOUND_IMPORTS
        if any(name == forbidden or name.startswith(f"{forbidden}.") for name in imported)
    }
    if violations:
        raise AssertionError(f"{path.name}: outbound network import denied: {sorted(violations)}")
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "__import__"
        for node in ast.walk(tree)
    ):
        raise AssertionError(f"{path.name}: dynamic import denied in simulator boundary")


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
