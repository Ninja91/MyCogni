from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import threat_catalog_guard

FIXTURES = Path(__file__).parent / "fixtures" / "threat_catalog"


def _follow(document: Any, path: list[str | int]) -> Any:
    current = document
    for part in path:
        current = current[part]
    return current


def _mutate(document: dict[str, Any], mutation: dict[str, Any]) -> None:
    path = mutation["path"]
    operation = mutation["operation"]
    if operation in {"add", "set"}:
        _follow(document, path[:-1])[path[-1]] = mutation["value"]
    elif operation == "delete":
        del _follow(document, path[:-1])[path[-1]]
    elif operation == "append_copy":
        _follow(document, path).append(copy.deepcopy(_follow(document, mutation["source"])))
    elif operation == "swap":
        values = _follow(document, path)
        left, right = mutation["indices"]
        values[left], values[right] = values[right], values[left]
    else:  # pragma: no cover - fixture vocabulary is closed by review
        raise AssertionError(f"unknown fixture operation: {operation}")


def _documents() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    return (
        threat_catalog_guard._load_json(threat_catalog_guard.CATALOG_PATH),
        threat_catalog_guard._load_json(threat_catalog_guard.REGISTRY_PATH),
        threat_catalog_guard._load_json(threat_catalog_guard.HISTORY_PATH),
    )


def test_repository_catalog_is_valid_and_report_is_current() -> None:
    catalog, registry, history = _documents()
    assert (
        threat_catalog_guard.validate_catalog(
            catalog, registry, history, threat_catalog_guard.REPOSITORY_ROOT
        )
        == []
    )
    assert threat_catalog_guard.REPORT_PATH.read_text(
        encoding="utf-8"
    ) == threat_catalog_guard.render_report(catalog, registry)


@pytest.mark.parametrize(
    "fixture_path", sorted(FIXTURES.glob("*.json")), ids=lambda path: path.stem
)
def test_intentionally_broken_catalog_fixtures_fail(fixture_path: Path) -> None:
    catalog, registry, history = _documents()
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    documents = {"catalog": catalog, "registry": registry, "history": history}
    mutations = fixture.get("mutations", [fixture])
    for mutation in mutations:
        _mutate(documents[mutation["document"]], mutation)

    errors = threat_catalog_guard.validate_catalog(
        catalog, registry, history, threat_catalog_guard.REPOSITORY_ROOT
    )

    assert any(fixture["expected"] in error for error in errors), errors


def test_report_is_reproducible_and_contains_no_environment_data(tmp_path: Path) -> None:
    catalog, registry, _ = _documents()
    first = threat_catalog_guard.render_report(catalog, registry)
    second = threat_catalog_guard.render_report(copy.deepcopy(catalog), copy.deepcopy(registry))

    assert first == second
    assert str(threat_catalog_guard.REPOSITORY_ROOT) not in first
    assert str(tmp_path) not in first
    assert not any(token in first for token in ("Generated at", "UTC", "2026-"))


def test_duplicate_json_object_keys_are_rejected() -> None:
    fixture = FIXTURES / "duplicate_object_key.input"
    with pytest.raises(ValueError, match="duplicate JSON object key: schema_version"):
        threat_catalog_guard._load_json(fixture)


@pytest.mark.parametrize(
    "reference", ["/tests/test_x.py", "tests/../test_x.py", "tests\\test_x.py", "./tests/test_x.py"]
)
def test_noncanonical_paths_are_rejected(reference: str) -> None:
    assert (
        threat_catalog_guard._canonical_repo_file(threat_catalog_guard.REPOSITORY_ROOT, reference)
        is None
    )


def test_symlink_paths_are_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real.py"
    real.write_text("pass\n", encoding="utf-8")
    link = tmp_path / "link.py"
    link.symlink_to(real)
    assert threat_catalog_guard._canonical_repo_file(tmp_path, "link.py") is None
