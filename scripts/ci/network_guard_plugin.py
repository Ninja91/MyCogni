"""Pytest lifecycle integration for the process-local network guard."""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import network_guard

MARKER = "simulator_loopback"
_TOKENS: dict[str, Any] = {}
REPOSITORY_ROOT = Path(__file__).parents[2].resolve()
AUTHORITY_REGISTRY = REPOSITORY_ROOT / "ci" / "network-loopback-authority.json"
_AUTHORIZED_NODES: frozenset[str] = frozenset()


def _load_authority_registry() -> frozenset[str]:
    document = json.loads(AUTHORITY_REGISTRY.read_text(encoding="utf-8"))
    if set(document) != {"schema_version", "source_sha256", "authorized_nodes"}:
        raise pytest.UsageError("network authority registry shape is invalid")
    if document["schema_version"] != 1:
        raise pytest.UsageError("network authority registry version is unsupported")
    sources = document["source_sha256"]
    nodes = document["authorized_nodes"]
    if not isinstance(sources, dict) or not isinstance(nodes, list):
        raise pytest.UsageError("network authority registry types are invalid")
    if nodes != sorted(set(nodes)):
        raise pytest.UsageError("network authority nodes must be sorted and unique")
    for relative, expected in sources.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise pytest.UsageError("network authority source entry is invalid")
        path = (REPOSITORY_ROOT / relative).resolve()
        try:
            path.relative_to(REPOSITORY_ROOT)
        except ValueError as error:
            raise pytest.UsageError("network authority source path escapes repository") from error
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise pytest.UsageError("network authority source digest differs from review")
    return frozenset(nodes)


def _canonical_node(item: pytest.Item) -> str:
    path = Path(str(item.path)).resolve()
    try:
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return ""
    return f"{relative}::{item.name}"


def _source_has_exact_marker(item: pytest.Item) -> bool:
    original_name = getattr(item, "originalname", None)
    if not isinstance(original_name, str):
        return False
    tree = ast.parse(Path(str(item.path)).read_text(encoding="utf-8"))
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == original_name
    ]
    if len(matches) != 1:
        return False
    decorators = []
    for decorator in matches[0].decorator_list:
        current = decorator
        parts: list[str] = []
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        decorators.append(".".join(reversed(parts)))
    return decorators.count("pytest.mark.simulator_loopback") == 1


def _is_simulator_test(item: pytest.Item) -> bool:
    path = Path(str(item.path)).resolve()
    simulator_root = REPOSITORY_ROOT / "tests" / "simulator"
    try:
        path.relative_to(simulator_root)
    except ValueError:
        return False
    return True


def pytest_configure(config: pytest.Config) -> None:
    global _AUTHORIZED_NODES
    if os.environ.get("MYCOGNI_DISABLE_NETWORK_GUARD") is not None:
        raise pytest.UsageError("network guard cannot be disabled")
    _AUTHORIZED_NODES = _load_authority_registry()
    network_guard.install()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    del config
    for item in items:
        canonical = _canonical_node(item)
        markers = list(item.iter_markers(name=MARKER))
        if not markers:
            if canonical in _AUTHORIZED_NODES:
                raise pytest.UsageError("reviewed simulator node lost its exact marker")
            continue
        own_markers = [marker for marker in item.own_markers if marker.name == MARKER]
        if len(markers) != 1 or len(own_markers) != 1 or markers[0].args or markers[0].kwargs:
            raise pytest.UsageError("simulator loopback marker must be exact and argument-free")
        if not _is_simulator_test(item):
            raise pytest.UsageError("simulator loopback marker is restricted to simulator tests")
        if canonical not in _AUTHORIZED_NODES or not _source_has_exact_marker(item):
            raise pytest.UsageError("simulator loopback marker lacks reviewed node provenance")


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> Any:
    network_guard.assert_installed()
    enabled = item.get_closest_marker(MARKER) is not None
    if enabled and _canonical_node(item) not in _AUTHORIZED_NODES:
        raise RuntimeError("network authority provenance changed after collection")
    token = network_guard.activate_test(item.nodeid, simulator_loopback=enabled)
    _TOKENS[item.nodeid] = token
    yield


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item) -> Any:
    yield
    token = _TOKENS.pop(item.nodeid, None)
    if token is None:
        raise RuntimeError("network guard test context was not installed")
    network_guard.deactivate_test(token)
    network_guard.assert_installed()


def pytest_unconfigure(config: pytest.Config) -> None:
    global _AUTHORIZED_NODES
    del config
    for handle in _TOKENS.values():
        network_guard.revoke_test(handle)
    _TOKENS.clear()
    try:
        network_guard.uninstall()
    finally:
        _AUTHORIZED_NODES = frozenset()
