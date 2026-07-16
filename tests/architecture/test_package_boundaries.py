"""Executable checks for the PF-CORE package-boundary scaffold."""

from __future__ import annotations

import ast
import importlib
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

PACKAGE_ROOT = Path(__file__).parents[2] / "src" / "mycogni"
LAYERS = ("domain", "application", "adapters", "entrypoints", "bootstrap")


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
