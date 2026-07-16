"""Executable checks for the PF-CORE package-boundary scaffold."""

from __future__ import annotations

import ast
import importlib
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest

PACKAGE_ROOT = Path(__file__).parents[2] / "src" / "mycogni"
LAYERS = ("domain", "application", "adapters", "entrypoints", "bootstrap")
ALLOWED_INTERNAL_IMPORTS = {
    "domain": frozenset({"domain"}),
    "application": frozenset({"domain", "application"}),
    "adapters": frozenset({"domain", "application", "adapters"}),
    "entrypoints": frozenset({"domain", "application", "entrypoints"}),
    "bootstrap": frozenset(LAYERS),
}


def _python_files(root: Path) -> Iterator[Path]:
    yield from sorted(root.rglob("*.py"))


def _imported_modules(path: Path) -> Iterator[tuple[str, int]]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, 0
        elif isinstance(node, ast.ImportFrom):
            yield node.module or "", node.level


def _internal_target(source_layer: str, module_name: str, relative_level: int) -> str | None:
    """Return the target MyCogni layer for an import, if it has one."""
    if relative_level:
        if relative_level == 1:
            return source_layer
        return module_name.partition(".")[0] or None

    if module_name == "mycogni":
        return None
    if module_name.startswith("mycogni."):
        return module_name.split(".", 2)[1]
    return None


def _assert_layer_import_allowed(
    source_layer: str, module_name: str, relative_level: int = 0
) -> None:
    target_layer = _internal_target(source_layer, module_name, relative_level)
    if target_layer is None:
        return
    assert target_layer in ALLOWED_INTERNAL_IMPORTS[source_layer], (
        f"mycogni.{source_layer} imports prohibited layer mycogni.{target_layer}"
    )


def _module_file(module: ModuleType) -> Path:
    assert module.__file__ is not None
    return Path(module.__file__).resolve()


def test_trusted_core_layer_packages_are_importable() -> None:
    for layer in LAYERS:
        module = importlib.import_module(f"mycogni.{layer}")
        assert _module_file(module).is_relative_to(PACKAGE_ROOT.resolve())


def test_domain_has_no_third_party_imports() -> None:
    for path in _python_files(PACKAGE_ROOT / "domain"):
        for module_name, relative_level in _imported_modules(path):
            if relative_level:
                continue

            top_level = module_name.partition(".")[0]
            if top_level == "mycogni":
                assert module_name == "mycogni.domain" or module_name.startswith(
                    "mycogni.domain."
                ), f"{path} imports outside the domain: {module_name}"
                continue

            assert top_level in sys.stdlib_module_names, (
                f"{path} imports non-stdlib dependency: {module_name}"
            )


def test_every_layer_obeys_the_composition_graph() -> None:
    for source_layer in LAYERS:
        for path in _python_files(PACKAGE_ROOT / source_layer):
            for module_name, relative_level in _imported_modules(path):
                _assert_layer_import_allowed(source_layer, module_name, relative_level)


@pytest.mark.parametrize(
    ("source_layer", "module_name", "relative_level"),
    [
        ("domain", "mycogni.application", 0),
        ("domain", "adapters", 2),
        ("application", "mycogni.adapters", 0),
        ("application", "entrypoints", 2),
        ("adapters", "mycogni.entrypoints", 0),
        ("adapters", "bootstrap", 2),
        ("entrypoints", "mycogni.adapters", 0),
        ("entrypoints", "bootstrap", 2),
    ],
)
def test_prohibited_edges_have_failing_fixtures(
    source_layer: str, module_name: str, relative_level: int
) -> None:
    with pytest.raises(AssertionError, match="imports prohibited layer"):
        _assert_layer_import_allowed(source_layer, module_name, relative_level)
