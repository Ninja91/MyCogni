"""Runner-only Compose mutation guards."""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest


def _validator() -> ModuleType:
    root = Path(__file__).resolve().parents[2]
    path = root / "scripts/verify_runner_containment.py"
    spec = importlib.util.spec_from_file_location("verify_runner_containment", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runner_containment_model_is_least_privilege() -> None:
    _validator().validate()


@pytest.mark.parametrize(
    "fragment",
    [
        "    read_only: true\n",
        "    network_mode: none\n",
        "    cap_drop:\n      - ALL\n",
        "      - no-new-privileges:true\n",
        "    pids_limit: 64\n",
        "    mem_limit: 512m\n",
    ],
)
def test_runner_containment_mutations_fail_semantic_validation(tmp_path: Path, fragment: str) -> None:
    validator = _validator()
    source = (Path(__file__).resolve().parents[2] / "deploy/compose.runner-mailbox-smoke.yml").read_text(
        encoding="utf-8"
    )
    assert fragment in source
    mutated = tmp_path / "compose.yml"
    mutated.write_text(source.replace(fragment, ""), encoding="utf-8")
    with pytest.raises((AssertionError, subprocess.CalledProcessError)):
        validator.validate_model(validator.render_compose(mutated))
