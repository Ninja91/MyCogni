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


def _mutate(document: dict[str, Any], fixture: dict[str, Any]) -> None:
    path = fixture["path"]
    operation = fixture["operation"]
    if operation == "set":
        _follow(document, path[:-1])[path[-1]] = fixture["value"]
    elif operation == "delete":
        del _follow(document, path[:-1])[path[-1]]
    elif operation == "append_copy":
        _follow(document, path).append(copy.deepcopy(_follow(document, fixture["source"])))
    elif operation == "swap":
        values = _follow(document, path)
        left, right = fixture["indices"]
        values[left], values[right] = values[right], values[left]
    else:  # pragma: no cover - fixture vocabulary is closed by review
        raise AssertionError(f"unknown fixture operation: {operation}")


def _documents() -> tuple[dict[str, Any], dict[str, Any]]:
    return (
        json.loads(threat_catalog_guard.CATALOG_PATH.read_text(encoding="utf-8")),
        json.loads(threat_catalog_guard.REGISTRY_PATH.read_text(encoding="utf-8")),
    )


def test_repository_catalog_is_valid_and_report_is_current() -> None:
    catalog, registry = _documents()
    assert (
        threat_catalog_guard.validate_catalog(
            catalog, registry, threat_catalog_guard.REPOSITORY_ROOT
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
    catalog, registry = _documents()
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    document = catalog if fixture["document"] == "catalog" else registry
    _mutate(document, fixture)

    errors = threat_catalog_guard.validate_catalog(
        catalog, registry, threat_catalog_guard.REPOSITORY_ROOT
    )

    assert any(fixture["expected"] in error for error in errors), errors


def test_report_is_reproducible_and_contains_no_environment_data(tmp_path: Path) -> None:
    catalog, registry = _documents()
    first = threat_catalog_guard.render_report(catalog, registry)
    second = threat_catalog_guard.render_report(copy.deepcopy(catalog), copy.deepcopy(registry))

    assert first == second
    assert str(threat_catalog_guard.REPOSITORY_ROOT) not in first
    assert str(tmp_path) not in first
    assert not any(token in first for token in ("Generated at", "UTC", "2026-"))
