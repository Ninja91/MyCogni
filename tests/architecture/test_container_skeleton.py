"""PF-002 container boundary regression checks."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest


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


def test_commented_user_instruction_does_not_satisfy_policy() -> None:
    validator = _validator()
    root = Path(__file__).resolve().parents[2]
    text = (root / "docker/Dockerfile").read_text(encoding="utf-8")
    inventory = validator._load_inventory()

    with pytest.raises(AssertionError):
        validator.validate_dockerfile(
            text.replace("USER 65532:65532", "# USER 65532:65532"), inventory
        )


@pytest.mark.parametrize(
    ("removed_fragment", "replacement"),
    [
        ("    read_only: true\n", "    # read_only: true\n"),
        ("    network_mode: none\n", "    # network_mode: none\n"),
        ("    cap_drop:\n      - ALL\n", "    # cap_drop:\n    #   - ALL\n"),
        (
            "    security_opt:\n      - no-new-privileges:true\n",
            "    # security_opt:\n    #   - no-new-privileges:true\n",
        ),
    ],
    ids=["read-only", "network-none", "drop-all-capabilities", "no-new-privileges"],
)
def test_missing_or_commented_compose_controls_fail_semantic_validation(
    tmp_path: Path, removed_fragment: str, replacement: str
) -> None:
    validator = _validator()
    root = Path(__file__).resolve().parents[2]
    source = (root / "deploy/compose.container-smoke.yml").read_text(encoding="utf-8")
    assert removed_fragment in source
    mutation = tmp_path / "compose.yml"
    mutation.write_text(source.replace(removed_fragment, replacement), encoding="utf-8")

    with pytest.raises(AssertionError):
        validator.validate_compose_model(validator.render_compose(mutation))
