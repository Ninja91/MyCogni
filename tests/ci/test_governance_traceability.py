from __future__ import annotations

import copy
import hashlib
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import governance_guard


def _documents() -> dict[str, dict[str, Any]]:
    return {name: governance_guard._load(path) for name, path in governance_guard.DOCUMENTS.items()}


def _errors(documents: dict[str, dict[str, Any]]) -> list[str]:
    return governance_guard.validate_governance(documents, governance_guard.ROOT)[0]


def _blob_digest(blob: bytes | None) -> str:
    assert blob is not None
    return hashlib.sha256(blob).hexdigest()


def _node_digest(blob: bytes | None, function_name: str) -> str:
    assert blob is not None
    source = governance_guard._function_source_bytes(blob, function_name)
    assert source is not None
    return hashlib.sha256(source).hexdigest()


def test_machine_governance_and_report_are_current() -> None:
    documents = _documents()
    errors, report = governance_guard.validate_governance(documents, governance_guard.ROOT)
    assert errors == []
    assert governance_guard._validate_threat_catalog(governance_guard.ROOT, execute=False) == []
    assert governance_guard.REPORT_PATH.read_text(
        encoding="utf-8"
    ) == governance_guard.render_report(report)


def test_exact_acceptance_nodes_execute_runtime_criterion_witnesses() -> None:
    documents = _documents()
    for record in documents["manifest"]["records"]:
        evidence = next(
            item
            for item in documents["acceptance"]["evidence"]
            if item["id"] in record["evidence_ids"]
        )
        assert governance_guard._acceptance_node(
            governance_guard.ROOT, evidence, record["acceptance_criteria"]
        )
        assert governance_guard._execute_node(
            governance_guard.ROOT, evidence["ref"], record["acceptance_criteria"]
        )


@pytest.mark.parametrize(
    "name", ["assert_true", "assigned_true", "nested_uncalled", "tautological_len"]
)
def test_constant_or_uncalled_nested_assert_is_not_acceptance(name: str) -> None:
    relative = f"tests/ci/fixtures/governance_runtime/{name}.py"
    evidence = {
        "ref": f"{relative}::probe",
        "content_sha256": governance_guard._function_sha256(
            governance_guard.ROOT / relative, "probe"
        ),
    }
    assert not governance_guard._acceptance_node(governance_guard.ROOT, evidence, ["ACC-PROBE-001"])


@pytest.mark.parametrize("name", ["alias_skip", "alias_xfail"])
def test_alias_skip_and_xfail_cannot_produce_acceptance(name: str) -> None:
    reference = f"tests/ci/fixtures/governance_runtime/{name}.py::probe"
    assert not governance_guard._execute_node(governance_guard.ROOT, reference, ["ACC-PROBE-001"])


def test_package_registry_covers_all_work_packages_including_sim() -> None:
    documents = _documents()
    packages, _ = governance_guard.parse_work_packages(governance_guard.ROOT)
    matrix, _ = governance_guard.parse_completion(governance_guard.ROOT)
    registered = {item["id"] for item in documents["status"]["packages"]}
    assert registered == set(matrix) == set(packages)
    assert "SIM-001" in registered
    documents["status"]["packages"] = [
        item for item in documents["status"]["packages"] if item["id"] != "SIM-001"
    ]
    assert any("package inventories must be exactly equal" in error for error in _errors(documents))


def test_status_evidence_ids_exactly_match_trace_records() -> None:
    documents = _documents()
    next(item for item in documents["status"]["packages"] if item["id"] == "CT-001")[
        "evidence_ids"
    ] = []
    assert any("status evidence_ids do not exactly match" in error for error in _errors(documents))


def test_acceptance_digest_and_deferred_adr_fail() -> None:
    documents = _documents()
    documents["acceptance"]["evidence"][0]["content_sha256"] = "0" * 64
    assert any("invalid package acceptance evidence" in error for error in _errors(documents))
    documents = _documents()
    documents["manifest"]["records"][0]["mappings"][0]["id"] = "ADR-0011"
    assert any("non-accepting ADR" in error for error in _errors(documents))


def test_accepted_trace_requires_exact_threat_vfy_closure() -> None:
    documents = _documents()
    record = documents["manifest"]["records"][2]
    record["state"] = "INDEPENDENTLY_ACCEPTED"
    record["mappings"] = [item for item in record["mappings"] if item["kind"] != "THREAT"]
    assert any("not bidirectionally closed" in error for error in _errors(documents))


def test_planned_threat_and_vfy_cannot_enter_accepted_trace() -> None:
    documents = _documents()
    record = documents["manifest"]["records"][0]
    record["state"] = "INDEPENDENTLY_ACCEPTED"
    record["mappings"].extend(
        [
            {"kind": "THREAT", "id": "THR-LOGS-001"},
            {"kind": "VERIFICATION_TEST", "id": "VFY-LOGS-001"},
        ]
    )
    errors = _errors(documents)
    assert any("planned threat cannot count as accepted" in error for error in errors)
    assert any("planned VFY cannot count as accepted" in error for error in errors)


def test_verified_rejects_nonexistent_and_caller_selected_milestone_scope() -> None:
    documents = _documents()
    next(item for item in documents["status"]["packages"] if item["id"] == "CT-001")["status"] = (
        "VERIFIED"
    )
    assert any(
        "VERIFIED lacks one authenticated milestone attestation" in error
        for error in _errors(documents)
    )
    documents["status"]["milestone_attestations"] = [
        {
            "id": "MATT-M0-001",
            "definition_id": "MDEF-M0",
            "packages": ["CT-001"],
            "package_attestation_ids": ["ATT-CT-FORGED"],
            "gates": [
                {
                    "id": "M0-ALL-PACKAGES-COMPLETE",
                    "evidence_ids": ["EVD-NONEXISTENT"],
                }
            ],
            "reviewer": {
                "id": "self-asserted",
                "role": "INDEPENDENT_ADVERSARIAL_REVIEWER",
            },
            "reviewed_commit": "0" * 40,
            "review_record": {"path": "missing", "sha256": "0" * 64},
            "disposition": "ACCEPT",
            "findings": [],
            "residuals": ["not authenticated"],
        }
    ]
    errors = _errors(documents)
    assert any("package set does not equal canonical definition" in error for error in errors)
    assert any("gates do not equal canonical gate evidence" in error for error in errors)
    assert any("canonical gate evidence is missing" in error for error in errors)


def test_milestone_verified_trace_cannot_bypass_package_and_status_path() -> None:
    documents = _documents()
    record = documents["manifest"]["records"][0]
    record["state"] = "MILESTONE_VERIFIED"
    errors = _errors(documents)
    assert any("MILESTONE_VERIFIED requires canonical VERIFIED status" in error for error in errors)
    assert any("missing exact ACCEPT attestation" in error for error in errors)


def test_new_attestation_and_reviewer_are_not_self_authorized_by_version_bump() -> None:
    baseline = _documents()
    current = copy.deepcopy(baseline)
    forged = {
        "id": "ATT-FORGED-001",
        "package": "CT-001",
        "reviewer": {"id": "self-asserted", "role": "INDEPENDENT_ADVERSARIAL_REVIEWER"},
    }
    current["attestations"]["attestations"].append(forged)
    current["attestations"]["registry_version"] = "99.0.0"
    errors = governance_guard.validate_against_base(current, baseline, {})
    assert "new attestation lacks allowlisted protected approval: ATT-FORGED-001" in errors


def test_protected_approval_binds_content_and_explicit_semantic_adequacy() -> None:
    documents = _documents()
    subject = {
        "id": "ATT-CT-001",
        "reviewer": {"id": "reviewer-1"},
        "acceptance_criteria": ["ACC-CT-001"],
        "evidence_ids": ["EVD-CT-001"],
    }
    criteria = {item["id"]: item for item in documents["acceptance"]["criteria"]}
    evidence = {item["id"]: item for item in documents["acceptance"]["evidence"]}
    approval = {
        "subject_type": "PACKAGE_ATTESTATION",
        "subject_id": subject["id"],
        "reviewer_id": "reviewer-1",
        "subject_sha256": governance_guard.threat_guard._canonical_json_hash(subject),
        "criteria_sha256": governance_guard._selected_content_hash(
            criteria, subject["acceptance_criteria"]
        ),
        "evidence_sha256": governance_guard._selected_content_hash(
            evidence, subject["evidence_ids"]
        ),
        "semantic_adequacy": "APPROVED",
    }
    assert governance_guard._protected_approval_authorizes(
        approval,
        subject_type="PACKAGE_ATTESTATION",
        subject=subject,
        reviewer_id="reviewer-1",
        criteria_sha256=approval["criteria_sha256"],
        evidence_sha256=approval["evidence_sha256"],
    )
    approval["semantic_adequacy"] = "STRUCTURAL_ONLY"
    assert not governance_guard._protected_approval_authorizes(
        approval,
        subject_type="PACKAGE_ATTESTATION",
        subject=subject,
        reviewer_id="reviewer-1",
        criteria_sha256=approval["criteria_sha256"],
        evidence_sha256=approval["evidence_sha256"],
    )


def test_accept_attestation_digests_are_read_from_reviewed_commit_not_head() -> None:
    documents = _documents()
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=governance_guard.ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    review_path = "governance/README.md"
    evidence = documents["acceptance"]["evidence"][0]
    evidence_path = str(evidence["ref"]).split("::", 1)[0]
    evidence_function = str(evidence["ref"]).split("::", 1)[1]
    head_blobs = {
        path: governance_guard._git_file_bytes(governance_guard.ROOT, head, path)
        for path in (review_path, evidence_path)
    }
    assert all(blob is not None for blob in head_blobs.values())

    history = subprocess.run(
        ["git", "rev-list", "HEAD"],
        cwd=governance_guard.ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    reviewed_commit = next(
        commit
        for commit in history
        if commit != head
        and all(
            (blob := governance_guard._git_file_bytes(governance_guard.ROOT, commit, path))
            is not None
            and blob != head_blobs[path]
            for path in (review_path, evidence_path)
        )
    )
    reviewed_blobs = {
        path: governance_guard._git_file_bytes(governance_guard.ROOT, reviewed_commit, path)
        for path in (review_path, evidence_path)
    }
    assert all(blob is not None for blob in reviewed_blobs.values())

    record = documents["manifest"]["records"][0]
    record["state"] = "INDEPENDENTLY_ACCEPTED"
    record["attestation_id"] = "ATT-CT-FORGED"
    evidence["content_sha256"] = _node_digest(reviewed_blobs[evidence_path], evidence_function)
    documents["attestations"]["attestations"] = [
        {
            "id": "ATT-CT-FORGED",
            "package": "CT-001",
            "disposition": "ACCEPT",
            "reviewer": {
                "id": "self-asserted",
                "role": "INDEPENDENT_ADVERSARIAL_REVIEWER",
            },
            "reviewed_commit": reviewed_commit,
            "review_record": {
                "path": review_path,
                "sha256": _blob_digest(reviewed_blobs[review_path]),
            },
            "acceptance_criteria": ["ACC-CT-001"],
            "evidence_ids": ["EVD-CT-001"],
            "findings": [],
            "residuals": ["not authenticated"],
        }
    ]
    reviewed_tree_errors = _errors(documents)
    assert not any("review record digest mismatch" in error for error in reviewed_tree_errors)
    assert not any(
        "evidence digest is not bound to reviewed commit" in error for error in reviewed_tree_errors
    )

    documents["attestations"]["attestations"][0]["review_record"]["sha256"] = _blob_digest(
        head_blobs[review_path]
    )
    evidence["content_sha256"] = _node_digest(head_blobs[evidence_path], evidence_function)
    errors = _errors(documents)
    assert any("review record digest mismatch" in error for error in errors)
    assert any("evidence digest is not bound to reviewed commit" in error for error in errors)


def test_same_version_mutation_and_version_regression_fail_base() -> None:
    baseline = _documents()
    current = copy.deepcopy(baseline)
    current["status"]["packages"][0]["status"] = "BLOCKED"
    current["manifest"]["manifest_version"] = "1.0.0"
    errors = governance_guard.validate_against_base(current, baseline, {})
    assert "status: content changed without version increment" in errors
    assert "manifest: version regressed across trusted base" in errors


def test_version_bump_cannot_shrink_or_rebind_governance_scope() -> None:
    baseline = _documents()
    current = copy.deepcopy(baseline)
    current["status"]["registry_version"] = "3.0.0"
    current["manifest"]["manifest_version"] = "3.0.0"
    current["acceptance"]["registry_version"] = "3.0.0"
    current["status"]["packages"] = [
        item for item in current["status"]["packages"] if item["id"] != "SIM-001"
    ]
    current["manifest"]["records"] = current["manifest"]["records"][1:]
    current["acceptance"]["criteria"] = current["acceptance"]["criteria"][1:]
    current["acceptance"]["evidence"] = current["acceptance"]["evidence"][1:]
    errors = governance_guard.validate_against_base(current, baseline, {})
    assert "trusted package status disappeared: SIM-001" in errors
    assert "trusted trace record disappeared: TRC-CT-001" in errors
    assert "trusted criterion disappeared: ACC-CT-001" in errors
    assert "trusted evidence disappeared: EVD-CT-001" in errors

    current = copy.deepcopy(baseline)
    current["manifest"]["manifest_version"] = "3.0.0"
    current["manifest"]["records"][0]["package"] = "TEL-001"
    assert "trusted trace record rebound: TRC-CT-001" in governance_guard.validate_against_base(
        current, baseline, {}
    )


def test_coordinated_markdown_scope_deletion_and_protected_approval_loss_fail() -> None:
    documents = _documents()
    current_scope = {
        "work package": {"CT-001": "row"},
        "completion matrix": {"CT-001": "IN_PROGRESS"},
    }
    baseline_scope = {
        "work package": {"CT-001": "row", "SIM-001": "row2"},
        "completion matrix": {"CT-001": "IN_PROGRESS", "SIM-001": "IN_PROGRESS"},
    }
    approvals = {"ATT-CT-001": {"subject_id": "ATT-CT-001"}}
    errors = governance_guard.validate_against_base(
        documents,
        documents,
        approvals,
        current_scope=current_scope,
        baseline_scope=baseline_scope,
        current_protected_approvals={},
    )
    assert "trusted work package disappeared: SIM-001" in errors
    assert "trusted completion matrix disappeared: SIM-001" in errors
    assert "trusted protected approval disappeared: ATT-CT-001" in errors


def test_complete_to_verified_requires_protected_milestone_authorization() -> None:
    baseline = _documents()
    current = copy.deepcopy(baseline)
    next(item for item in baseline["status"]["packages"] if item["id"] == "CT-001")["status"] = (
        "COMPLETE"
    )
    next(item for item in current["status"]["packages"] if item["id"] == "CT-001")["status"] = (
        "VERIFIED"
    )
    current["status"]["registry_version"] = "3.0.0"
    current["manifest"]["records"][0]["attestation_id"] = "ATT-CT-001"
    current["status"]["milestone_attestations"] = [
        {"id": "MATT-M0-001", "packages": ["CT-001"], "definition_id": "MDEF-M0"}
    ]
    errors = governance_guard.validate_against_base(
        current, baseline, {"ATT-CT-001": {"subject_id": "ATT-CT-001"}}
    )
    assert "CT-001: VERIFIED promotion lacks protected milestone authorization" in errors


def test_untrusted_mode_rejects_any_attestation_or_promotion() -> None:
    documents = _documents()
    documents["attestations"]["attestations"].append({"id": "ATT-FORGED"})
    assert (
        "trusted base is required for ACCEPT attestations"
        in governance_guard._untrusted_promotions(documents)
    )
    documents = _documents()
    documents["status"]["packages"][0]["status"] = "COMPLETE"
    assert (
        "trusted base is required for package promotion"
        in governance_guard._untrusted_promotions(documents)
    )


def test_ci_missing_or_implicit_zero_base_fails_closed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MYCOGNI_GOVERNANCE_CI", "1")
    monkeypatch.delenv("THREAT_CATALOG_BASE_REF", raising=False)
    monkeypatch.delenv("MYCOGNI_GOVERNANCE_FIRST_BOOTSTRAP", raising=False)
    assert governance_guard.main([]) == 1
    assert "CI requires an immutable trusted base revision" in capsys.readouterr().out

    monkeypatch.setenv("THREAT_CATALOG_BASE_REF", governance_guard.ZERO_GIT_OBJECT)
    assert governance_guard.main([]) == 1
    assert (
        "zero trusted base is allowed only for explicit first bootstrap" in capsys.readouterr().out
    )


def test_explicit_first_bootstrap_still_runs_untrusted_promotion_gate(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MYCOGNI_GOVERNANCE_CI", "1")
    monkeypatch.setenv("THREAT_CATALOG_BASE_REF", governance_guard.ZERO_GIT_OBJECT)
    monkeypatch.setenv("MYCOGNI_GOVERNANCE_FIRST_BOOTSTRAP", "1")
    assert governance_guard.main([]) == 0
    assert "trusted-base state: BOOTSTRAP" in capsys.readouterr().out


def test_unused_criteria_evidence_and_attestation_fail() -> None:
    documents = _documents()
    documents["acceptance"]["criteria"].append(
        {
            "id": "ACC-UNUSED",
            "package": "CT-001",
            "description": "unused",
            "evidence_id": "EVD-CT-001",
        }
    )
    assert any(
        "criteria registry contains missing or unused" in error for error in _errors(documents)
    )


def test_registry_semver_is_unconditional() -> None:
    documents = _documents()
    documents["acceptance"]["registry_version"] = "latest"
    assert any("registry version must be semantic" in error for error in _errors(documents))
    documents = _documents()
    documents["acceptance"]["registry_version"] = "01.2.3"
    assert any("registry version must be semantic" in error for error in _errors(documents))


def test_schema_extra_and_duplicate_key_fail(tmp_path: Path) -> None:
    documents = _documents()
    documents["attestations"]["unexpected"] = True
    assert any("schema rejects additional key unexpected" in error for error in _errors(documents))
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        governance_guard._load(duplicate)


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


def test_duplicate_adr_index_row_fails(tmp_path: Path) -> None:
    adr = tmp_path / "docs/adr"
    adr.mkdir(parents=True)
    (adr / "0001-test.md").write_text("# ADR-0001: Test\n\n- Status: Accepted\n", encoding="utf-8")
    row = "| [0001](0001-test.md) | Accepted | test |\n"
    (adr / "README.md").write_text(row + row, encoding="utf-8")
    _, errors = governance_guard.parse_adrs(tmp_path)
    assert "duplicate ADR index row ADR-0001" in errors


def test_report_lists_full_registry_scope_without_promotions() -> None:
    _, data = governance_guard.validate_governance(_documents(), governance_guard.ROOT)
    report = governance_guard.render_report(data)
    assert "`SIM-001`" in report
    assert "`THR-GOV-001`" in report
    assert "`VFY-CATALOG-001`" in report
    assert "Canonical package-status scope (106)" in report
    assert "Canonical COMPLETE packages: None" in report
    assert "GOV-001 itself remains IN_PROGRESS" in report
    assert str(governance_guard.ROOT) not in report
