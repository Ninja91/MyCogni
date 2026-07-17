from __future__ import annotations

import copy
import json
from collections.abc import Callable
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


@pytest.mark.threat_evidence
@pytest.mark.governance_acceptance
def test_threat_catalog_integrity_evidence(
    governance_criterion: Callable[[str], None],
) -> None:
    governance_criterion("ACC-THREAT-CATALOG-001")
    catalog, registry, history = _documents()
    assert (
        threat_catalog_guard.validate_catalog(
            catalog, registry, history, threat_catalog_guard.REPOSITORY_ROOT
        )
        == []
    )
    pairs = (
        (catalog, threat_catalog_guard.SCHEMA_PATH),
        (registry, threat_catalog_guard.REGISTRY_SCHEMA_PATH),
        (history, threat_catalog_guard.HISTORY_SCHEMA_PATH),
    )
    assert all(
        threat_catalog_guard.validate_published_schema(
            document, threat_catalog_guard._load_json(path), path.name
        )
        == []
        for document, path in pairs
    )


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


def test_coordinated_all_document_rename_fails_trusted_baseline() -> None:
    catalog, registry, baseline = _documents()
    current = copy.deepcopy(baseline)
    catalog["threats"][0]["id"] = "THR-AUTH-002"
    registry["tests"][0]["threats"][0] = "THR-AUTH-002"
    current["allocations"][0]["id"] = "THR-AUTH-002"

    assert (
        threat_catalog_guard.validate_catalog(
            catalog, registry, current, threat_catalog_guard.REPOSITORY_ROOT
        )
        == []
    )
    assert threat_catalog_guard.validate_history_against_baseline(current, baseline) == [
        "baseline: allocated ID disappeared across revisions: THR-AUTH-001"
    ]


def test_coordinated_identity_rebind_fails_trusted_baseline() -> None:
    catalog, registry, baseline = _documents()
    current = copy.deepcopy(baseline)
    catalog["threats"][0]["title"] = "Different authority failure"
    current["allocations"][0]["identity"] = "different-authority-failure"

    assert (
        threat_catalog_guard.validate_catalog(
            catalog, registry, current, threat_catalog_guard.REPOSITORY_ROOT
        )
        == []
    )
    assert threat_catalog_guard.validate_history_against_baseline(current, baseline) == [
        "baseline: THR-AUTH-001 immutable identity changed across revisions"
    ]


def test_retired_id_cannot_reactivate_in_lockstep() -> None:
    _, _, current = _documents()
    baseline = copy.deepcopy(current)
    baseline["allocations"][0]["state"] = "RETIRED"

    assert threat_catalog_guard.validate_history_against_baseline(current, baseline) == [
        "baseline: retired ID reactivated across revisions: THR-AUTH-001"
    ]


def test_baseline_revision_requires_full_hex_object_id() -> None:
    with pytest.raises(ValueError, match="full hexadecimal object ID"):
        threat_catalog_guard.load_history_from_git_base(
            threat_catalog_guard.REPOSITORY_ROOT, "main;unsafe"
        )


def test_published_schemas_are_pinned_and_enforce_real_documents() -> None:
    catalog, registry, history = _documents()
    pairs = (
        (catalog, threat_catalog_guard.SCHEMA_PATH),
        (registry, threat_catalog_guard.REGISTRY_SCHEMA_PATH),
        (history, threat_catalog_guard.HISTORY_SCHEMA_PATH),
    )
    for document, path in pairs:
        schema = threat_catalog_guard._load_json(path)
        assert threat_catalog_guard.validate_published_schema(document, schema, path.name) == []


@pytest.mark.parametrize(
    "schema_path",
    [
        threat_catalog_guard.SCHEMA_PATH,
        threat_catalog_guard.REGISTRY_SCHEMA_PATH,
        threat_catalog_guard.HISTORY_SCHEMA_PATH,
    ],
    ids=lambda path: path.name,
)
def test_destructive_published_schema_mutation_is_rejected(schema_path: Path) -> None:
    catalog, registry, history = _documents()
    documents = {
        threat_catalog_guard.SCHEMA_PATH.name: catalog,
        threat_catalog_guard.REGISTRY_SCHEMA_PATH.name: registry,
        threat_catalog_guard.HISTORY_SCHEMA_PATH.name: history,
    }
    schema = threat_catalog_guard._load_json(schema_path)
    schema["additionalProperties"] = True

    errors = threat_catalog_guard.validate_published_schema(
        documents[schema_path.name], schema, schema_path.name
    )

    assert f"{schema_path.name}: published schema hash mismatch" in errors
    assert f"{schema_path.name}: root must be an exact object schema" in errors


def _write_evidence_test(root: Path, body: str) -> str:
    tests = root / "tests"
    tests.mkdir()
    (root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\nmarkers=["threat_evidence: test"]\n', encoding="utf-8"
    )
    path = tests / "test_evidence.py"
    path.write_text("import pytest\n\n" + body, encoding="utf-8")
    return "tests/test_evidence.py::test_evidence"


@pytest.mark.parametrize(
    "body",
    [
        "@pytest.mark.threat_evidence\n@pytest.mark."
        + "skip(reason='blocked')\ndef test_evidence():\n    assert True\n",
        "@pytest.mark.threat_evidence\n@pytest.mark."
        + "xfail(reason='known')\ndef test_evidence():\n    assert True\n",
        "@pytest.mark.threat_evidence\ndef test_evidence():\n    pass\n",
    ],
    ids=["skip", "xfail-xpass", "no-op"],
)
def test_static_evidence_gate_rejects_skip_xfail_and_noop(tmp_path: Path, body: str) -> None:
    node = _write_evidence_test(tmp_path, body)
    assert not threat_catalog_guard._pytest_node_exists(tmp_path, node)


def test_runtime_evidence_gate_requires_real_passed_outcome(tmp_path: Path) -> None:
    node = _write_evidence_test(
        tmp_path,
        "@pytest.fixture\ndef unavailable():\n    pytest.skip('runtime skip')\n\n"
        "@pytest.mark.threat_evidence\ndef test_evidence(unavailable):\n    assert unavailable\n",
    )
    registry = {
        "tests": [
            {
                "id": "VFY-TEMP-001",
                "status": "IMPLEMENTED",
                "implementation": {"type": "PYTEST_NODE", "ref": node},
            }
        ]
    }

    assert threat_catalog_guard._pytest_node_exists(tmp_path, node)
    assert threat_catalog_guard._execute_pytest_nodes(registry, tmp_path) == [
        f"pytest evidence did not produce an exact PASSED outcome: {node}"
    ]


def test_pr_and_push_ci_use_immutable_base_sha_and_fetch_full_history() -> None:
    workflow = (threat_catalog_guard.REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(
        encoding="utf-8"
    )
    assert (
        "THREAT_CATALOG_BASE_REF: ${{ github.event_name == 'pull_request' && "
        "github.event.pull_request.base.sha || github.event.before }}" in workflow
    )
    assert 'MYCOGNI_GOVERNANCE_CI: "1"' in workflow
    assert "github.event.before == '0000000000000000000000000000000000000000'" in workflow
    assert workflow.count("fetch-depth: 0") == 2
    assert "THREAT_CATALOG_BASE_REF: ${{ github.sha }}" not in workflow


def test_threat_registry_semver_rejects_leading_zeroes() -> None:
    catalog, registry, history = _documents()
    catalog["catalog_version"] = "01.0.0"
    errors = threat_catalog_guard.validate_catalog(
        catalog, registry, history, threat_catalog_guard.REPOSITORY_ROOT
    )
    assert "catalog: catalog_version must be semantic x.y.z" in errors
