from __future__ import annotations

import copy
from pathlib import Path

import pytest

from scripts.ci import governance_guard


def _documents() -> dict[str, dict[str, object]]:
    return {name: governance_guard._load(path) for name, path in governance_guard.DOCUMENTS.items()}


def test_machine_governance_and_report_are_current() -> None:
    documents = _documents()
    errors, report = governance_guard.validate_governance(documents, governance_guard.ROOT)
    assert errors == []
    assert governance_guard._validate_threat_catalog(governance_guard.ROOT, execute=False) == []
    assert governance_guard.REPORT_PATH.read_text(
        encoding="utf-8"
    ) == governance_guard.render_report(report)


def test_exact_acceptance_nodes_execute_real_passes() -> None:
    for evidence in _documents()["acceptance"]["evidence"]:  # type: ignore[index]
        assert governance_guard._acceptance_node(governance_guard.ROOT, evidence)
        assert governance_guard._execute_node(governance_guard.ROOT, evidence["ref"])


@pytest.mark.parametrize(
    ("document", "mutation", "expected"),
    [
        (
            "acceptance",
            lambda doc: doc["evidence"][0].update(content_sha256="0" * 64),
            "invalid package acceptance evidence",
        ),
        (
            "attestations",
            lambda doc: doc["attestations"][0].update(reviewed_commit="0" * 40),
            "reviewed commit is not an ancestor",
        ),
        (
            "attestations",
            lambda doc: doc["attestations"][0]["review_record"].update(sha256="0" * 64),
            "review record digest mismatch",
        ),
        (
            "attestations",
            lambda doc: doc["attestations"][0].update(disposition="REJECT"),
            "missing exact ACCEPT attestation",
        ),
        (
            "manifest",
            lambda doc: doc["records"][0].update(mappings=[]),
            "package mappings must be nonempty",
        ),
        (
            "manifest",
            lambda doc: doc["records"][0]["mappings"][0].update(id="ADR-0011"),
            "non-accepting ADR cannot authorize mapping",
        ),
        (
            "manifest",
            lambda doc: doc["records"][2]["mappings"][-1].update(id="VFY-LOGS-001"),
            "planned VFY cannot count as accepted",
        ),
        (
            "status",
            lambda doc: doc["packages"][0].update(status="COMPLETE"),
            "incomplete prerequisites",
        ),
        (
            "status",
            lambda doc: doc["packages"][1].update(status="VERIFIED"),
            "VERIFIED lacks one structured milestone attestation",
        ),
    ],
    ids=[
        "test-digest",
        "commit",
        "review-digest",
        "reject",
        "empty-mapping",
        "deferred-adr",
        "planned-vfy",
        "prerequisite",
        "milestone",
    ],
)
def test_direct_governance_probes_fail(document: str, mutation: object, expected: str) -> None:
    documents = _documents()
    mutation(documents[document])  # type: ignore[operator]
    errors, _ = governance_guard.validate_governance(documents, governance_guard.ROOT)
    assert any(expected in error for error in errors), errors


def test_matrix_and_machine_status_are_bidirectional() -> None:
    documents = _documents()
    documents["status"]["packages"][0]["status"] = "BLOCKED"  # type: ignore[index]
    errors, _ = governance_guard.validate_governance(documents, governance_guard.ROOT)
    assert any("matrix status is not losslessly equal" in error for error in errors)


def test_schema_extra_and_duplicate_key_fail(tmp_path: Path) -> None:
    documents = _documents()
    documents["attestations"]["unexpected"] = True
    errors, _ = governance_guard.validate_governance(documents, governance_guard.ROOT)
    assert any("schema rejects additional key unexpected" in error for error in errors)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        governance_guard._load(duplicate)


def test_trusted_base_rejects_same_version_mutation_and_attestation_rebind() -> None:
    baseline = _documents()
    current = copy.deepcopy(baseline)
    current["status"]["packages"][0]["status"] = "BLOCKED"  # type: ignore[index]
    current["attestations"]["attestations"][0]["reviewed_commit"] = "0" * 40  # type: ignore[index]
    errors = governance_guard.validate_against_base(current, baseline)
    assert "status: content changed without version increment" in errors
    assert "attestations: content changed without version increment" in errors
    assert "trusted attestation mutated: ATT-CT-001" in errors


def test_version_regression_fails_trusted_base() -> None:
    baseline = _documents()
    current = copy.deepcopy(baseline)
    current["manifest"]["manifest_version"] = "1.0.0"
    assert (
        "manifest: version regressed across trusted base"
        in governance_guard.validate_against_base(current, baseline)
    )


def test_strict_requirement_parser_rejects_duplicate_and_malformed(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "02-requirements.md").write_text(
        "- **REQ-01** valid\n- **REQ-01** duplicate\n- **broken candidate\n", encoding="utf-8"
    )
    _, errors = governance_guard.parse_requirements(tmp_path)
    assert "duplicate requirement ID REQ-01" in errors
    assert any("malformed requirement candidate" in error for error in errors)


def test_strict_work_package_parser_rejects_cycle_and_malformed(tmp_path: Path) -> None:
    docs = tmp_path / "docs/v1"
    docs.mkdir(parents=True)
    (docs / "WORK_PACKAGES.md").write_text(
        "| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |\n"
        "| --- | --- | --- | --- | ---: | --- |\n"
        "| A-001 | C | A | B-001 | 1 | proof |\n"
        "| B-001 | C | B | A-001 | 1 | proof |\n"
        "| malformed | row |\n",
        encoding="utf-8",
    )
    _, errors = governance_guard.parse_work_packages(tmp_path)
    assert any("dependency cycle" in error for error in errors)
    assert any("malformed work-package row" in error for error in errors)


def test_report_lists_identifiers_and_never_promotes_gov() -> None:
    _, data = governance_guard.validate_governance(_documents(), governance_guard.ROOT)
    report = governance_guard.render_report(data)
    assert "`CT-001`" in report
    assert "Canonical COMPLETE packages: None" in report
    assert "GOV-001 itself remains IN_PROGRESS" in report
    assert str(governance_guard.ROOT) not in report
    assert "Generated at" not in report
