"""Pytest lifecycle integration for the process-local network guard."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import network_guard

MARKER = "simulator_loopback"
REPOSITORY_ROOT = Path(__file__).parents[2].resolve()
AUTHORITY_REGISTRY = REPOSITORY_ROOT / "ci" / "network-loopback-authority.json"


@dataclass(frozen=True, slots=True)
class _CallableReview:
    ast_sha256: str
    ast_lineno: int
    code_firstlineno: int
    qualname: str


@dataclass(frozen=True, slots=True)
class _AuthorityRegistry:
    nodes: frozenset[str]
    sources: tuple[tuple[str, str], ...]
    callables: tuple[tuple[str, _CallableReview], ...]

    def callable_map(self) -> dict[str, _CallableReview]:
        return dict(self.callables)


@dataclass(frozen=True, slots=True)
class _ItemAuthority:
    canonical_nodeid: str
    callable_object: object
    code_object: object
    review: _CallableReview


_EMPTY_REGISTRY = _AuthorityRegistry(frozenset(), (), ())
_REGISTRY = _EMPTY_REGISTRY
_ITEM_AUTHORITIES: dict[int, _ItemAuthority] = {}
_HANDLES: dict[int, network_guard.AuthorityHandle] = {}


def _load_authority_registry() -> _AuthorityRegistry:
    document = json.loads(AUTHORITY_REGISTRY.read_text(encoding="utf-8"))
    if set(document) != {
        "schema_version",
        "source_sha256",
        "callable_provenance",
        "authorized_nodes",
    }:
        raise pytest.UsageError("network authority registry shape is invalid")
    if document["schema_version"] != 2:
        raise pytest.UsageError("network authority registry version is unsupported")
    sources = document["source_sha256"]
    callable_provenance = document["callable_provenance"]
    nodes = document["authorized_nodes"]
    if (
        not isinstance(sources, dict)
        or not isinstance(callable_provenance, dict)
        or not isinstance(nodes, list)
    ):
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
    reviews: list[tuple[str, _CallableReview]] = []
    for nodeid, value in callable_provenance.items():
        if not isinstance(nodeid, str) or not isinstance(value, dict):
            raise pytest.UsageError("network callable provenance entry is invalid")
        if set(value) != {"ast_sha256", "ast_lineno", "code_firstlineno", "qualname"}:
            raise pytest.UsageError("network callable provenance shape is invalid")
        try:
            review = _CallableReview(
                ast_sha256=value["ast_sha256"],
                ast_lineno=value["ast_lineno"],
                code_firstlineno=value["code_firstlineno"],
                qualname=value["qualname"],
            )
        except TypeError as error:
            raise pytest.UsageError("network callable provenance types are invalid") from error
        if (
            not isinstance(review.ast_sha256, str)
            or not isinstance(review.ast_lineno, int)
            or not isinstance(review.code_firstlineno, int)
            or not isinstance(review.qualname, str)
        ):
            raise pytest.UsageError("network callable provenance values are invalid")
        reviews.append((nodeid, review))
    if list(callable_provenance) != sorted(callable_provenance):
        raise pytest.UsageError("network callable provenance must be sorted")
    bases = {_base_node(node) for node in nodes}
    if None in bases or set(callable_provenance) != bases:
        raise pytest.UsageError("network callable provenance does not cover exact nodes")
    return _AuthorityRegistry(
        frozenset(nodes),
        tuple(sorted(sources.items())),
        tuple(reviews),
    )


def _canonical_node(item: pytest.Item) -> str:
    path = Path(str(item.path)).resolve()
    try:
        relative = path.relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return ""
    nodeid = str(item.nodeid)
    _, separator, collector_suffix = nodeid.partition("::")
    if not separator:
        return relative
    return f"{relative}::{collector_suffix}"


def _base_node(canonical_nodeid: str) -> str | None:
    parts = canonical_nodeid.split("::")
    if len(parts) != 2:
        return None
    callable_case = parts[1]
    callable_name = callable_case.split("[", 1)[0]
    if not callable_name or not callable_case.startswith(callable_name):
        return None
    return f"{parts[0]}::{callable_name}"


def _function_ast(
    item: pytest.Item, callable_name: str
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    tree = ast.parse(Path(str(item.path)).read_text(encoding="utf-8"))
    matches = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == callable_name
    ]
    return matches[0] if len(matches) == 1 else None


def _ast_sha256(node: ast.AST) -> str:
    try:
        canonical = ast.dump(
            node,
            annotate_fields=True,
            include_attributes=False,
            show_empty=True,
        )
    except TypeError:  # Python 3.12 always includes empty optional fields.
        canonical = ast.dump(node, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _source_has_exact_marker(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    decorators = []
    for decorator in node.decorator_list:
        current = decorator
        parts: list[str] = []
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        decorators.append(".".join(reversed(parts)))
    return decorators.count("pytest.mark.simulator_loopback") == 1


def _reviewed_item(item: pytest.Item) -> _ItemAuthority | None:
    canonical = _canonical_node(item)
    if canonical not in _REGISTRY.nodes:
        return None
    base = _base_node(canonical)
    if base is None:
        return None
    review = _REGISTRY.callable_map().get(base)
    if review is None:
        return None
    callable_name = base.rpartition("::")[2]
    if getattr(item, "originalname", None) != callable_name:
        return None
    if not isinstance(item.parent, pytest.Module):
        return None
    function_ast = _function_ast(item, callable_name)
    if function_ast is None or not _source_has_exact_marker(function_ast):
        return None
    if function_ast.lineno != review.ast_lineno or _ast_sha256(function_ast) != review.ast_sha256:
        return None
    callable_object = getattr(item, "obj", None)
    if not inspect.isfunction(callable_object):
        return None
    code = callable_object.__code__
    if (
        callable_object.__name__ != callable_name
        or callable_object.__qualname__ != review.qualname
        or code.co_name != callable_name
        or code.co_firstlineno != review.code_firstlineno
        or Path(code.co_filename).resolve() != Path(str(item.path)).resolve()
        or getattr(item.module, callable_name, None) is not callable_object
    ):
        return None
    markers = list(item.iter_markers(name=MARKER))
    own_markers = [marker for marker in item.own_markers if marker.name == MARKER]
    if len(markers) != 1 or len(own_markers) != 1 or markers[0].args or markers[0].kwargs:
        return None
    return _ItemAuthority(canonical, callable_object, code, review)


def _is_simulator_test(item: pytest.Item) -> bool:
    path = Path(str(item.path)).resolve()
    simulator_root = REPOSITORY_ROOT / "tests" / "simulator"
    try:
        path.relative_to(simulator_root)
    except ValueError:
        return False
    return True


def pytest_configure(config: pytest.Config) -> None:
    global _REGISTRY
    if os.environ.get("MYCOGNI_DISABLE_NETWORK_GUARD") is not None:
        raise pytest.UsageError("network guard cannot be disabled")
    _REGISTRY = _load_authority_registry()
    network_guard.install()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    del config
    for item in items:
        canonical = _canonical_node(item)
        markers = list(item.iter_markers(name=MARKER))
        authority = _reviewed_item(item)
        if not markers:
            if canonical in _REGISTRY.nodes:
                raise pytest.UsageError("reviewed simulator node lost its exact marker")
            continue
        if not _is_simulator_test(item):
            raise pytest.UsageError("simulator loopback marker is restricted to simulator tests")
        if authority is None:
            raise pytest.UsageError("simulator loopback marker lacks reviewed node provenance")
        _ITEM_AUTHORITIES[id(item)] = authority


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_setup(item: pytest.Item) -> Any:
    network_guard.assert_installed()
    yield


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> Any:
    reviewed = _ITEM_AUTHORITIES.get(id(pyfuncitem))
    current = _reviewed_item(pyfuncitem)
    marked = any(pyfuncitem.iter_markers(name=MARKER))
    if reviewed is None:
        if marked:
            raise RuntimeError("network authority provenance changed after collection")
        enabled = False
    else:
        if current != reviewed:
            raise RuntimeError("network authority provenance changed after collection")
        enabled = True
    handle = network_guard.activate_test(_canonical_node(pyfuncitem), simulator_loopback=enabled)
    _HANDLES[id(pyfuncitem)] = handle
    try:
        yield
    finally:
        active = _HANDLES.pop(id(pyfuncitem), None)
        if active is None:
            raise RuntimeError("network guard call authority was not installed")
        network_guard.deactivate_test(active)


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_teardown(item: pytest.Item) -> Any:
    yield
    if id(item) in _HANDLES:
        raise RuntimeError("network guard call authority leaked into teardown")
    _ITEM_AUTHORITIES.pop(id(item), None)
    network_guard.assert_installed()


def pytest_unconfigure(config: pytest.Config) -> None:
    global _REGISTRY
    del config
    for handle in _HANDLES.values():
        network_guard.revoke_test(handle)
    _HANDLES.clear()
    _ITEM_AUTHORITIES.clear()
    try:
        network_guard.uninstall()
    finally:
        _REGISTRY = _EMPTY_REGISTRY
