from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import governance_guard, threat_catalog_guard

FIXTURES = Path(__file__).parent / "fixtures/governance"


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
    elif operation == "append_copy":
        _follow(document, path).append(copy.deepcopy(_follow(document, mutation["source"])))
    else:  # pragma: no cover - closed fixture vocabulary
        raise AssertionError(operation)


def _manifest() -> dict[str, Any]:
    return governance_guard._load(governance_guard.MANIFEST_PATH)


def test_repository_governance_manifest_and_report_are_current() -> None:
    manifest = _manifest()
    errors, counts = governance_guard.validate_manifest(manifest, governance_guard.ROOT)
    assert errors == []
    assert (
        governance_guard.validate_schema(
            manifest, governance_guard._load(governance_guard.SCHEMA_PATH)
        )
        == []
    )
    assert governance_guard.REPORT_PATH.read_text(
        encoding="utf-8"
    ) == governance_guard.render_report(counts)


@pytest.mark.parametrize(
    "fixture_path", sorted(FIXTURES.glob("*.json")), ids=lambda path: path.stem
)
def test_broken_traceability_fixtures_fail(fixture_path: Path) -> None:
    manifest = _manifest()
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    for mutation in fixture.get("mutations", [fixture]):
        _mutate(manifest, mutation)
    errors, _ = governance_guard.validate_manifest(manifest, governance_guard.ROOT)
    assert any(fixture["expected"] in error for error in errors), errors


def test_duplicate_manifest_object_keys_fail() -> None:
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        governance_guard._load(FIXTURES / "duplicate_object_key.input")


def test_work_package_cycle_fails(tmp_path: Path) -> None:
    path = tmp_path / "docs/v1"
    path.mkdir(parents=True)
    (path / "WORK_PACKAGES.md").write_text(
        "| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |\n"
        "| --- | --- | --- | --- | ---: | --- |\n"
        "| CYCLE-A-001 | C | A | CYCLE-B-001 | 1 | evidence |\n"
        "| CYCLE-B-001 | C | B | CYCLE-A-001 | 1 | evidence |\n",
        encoding="utf-8",
    )
    _, errors = governance_guard.parse_work_packages(tmp_path)
    assert any("dependency cycle" in error for error in errors)


def test_destructive_traceability_schema_mutation_fails() -> None:
    schema = governance_guard._load(governance_guard.SCHEMA_PATH)
    schema["additionalProperties"] = True
    errors = governance_guard.validate_schema(_manifest(), schema)
    assert "traceability schema hash mismatch" in errors


def test_report_is_deterministic_and_environment_free(tmp_path: Path) -> None:
    _, counts = governance_guard.validate_manifest(_manifest(), governance_guard.ROOT)
    first = governance_guard.render_report(counts)
    second = governance_guard.render_report(dict(counts))
    assert first == second
    assert str(governance_guard.ROOT) not in first
    assert str(tmp_path) not in first
    assert "Generated at" not in first


def test_stale_generated_report_is_detectable() -> None:
    _, counts = governance_guard.validate_manifest(_manifest(), governance_guard.ROOT)
    assert governance_guard.validate_report("# stale report\n", counts) == [
        "Governance coverage report is stale"
    ]


def test_governance_preserves_trusted_base_id_mutation_detection() -> None:
    baseline = threat_catalog_guard._load_json(threat_catalog_guard.HISTORY_PATH)
    current = copy.deepcopy(baseline)
    current["allocations"][0]["identity"] = "coordinated-rebind"
    assert threat_catalog_guard.validate_history_against_baseline(current, baseline) == [
        "baseline: THR-AUTH-001 immutable identity changed across revisions"
    ]


@pytest.mark.parametrize(
    "reference",
    ["README.md", "../tests/test_x.py::test_x", "tests\\test_x.py::test_x"],
)
def test_arbitrary_or_noncanonical_evidence_paths_fail(reference: str) -> None:
    assert not governance_guard._assertive_node(governance_guard.ROOT, reference)
