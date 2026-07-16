"""PF-002 container boundary regression checks."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def _validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_container_skeleton.py"
    spec = importlib.util.spec_from_file_location("verify_container_skeleton", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_container_skeleton_is_digest_pinned_and_least_privilege() -> None:
    _validator().validate()
