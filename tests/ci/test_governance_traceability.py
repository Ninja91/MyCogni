from __future__ import annotations

import copy
import hashlib
import subprocess
from pathlib import Path
from typing import Any

import pytest

from scripts.ci import governance_guard
from scripts.ci import threat_catalog_guard as threat_guard


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


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit(root: Path, message: str) -> str:
    _git(
        root,
        "-c",
        "user.name=Governance Test",
        "-c",
        "user.email=governance@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return _git(root, "rev-parse", "HEAD")


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
    "name",
    [
        "adjacent_fold_true",
        "annotated_true",
        "assert_true",
        "assigned_true",
        "computed_true",
        "division_true",
        "lambda_true",
        "nested_uncalled",
        "tautological_len",
        "unpacked_true",
        "walrus_true",
    ],
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
    assert "new attestation lacks external trust-root approval: ATT-FORGED-001" in errors


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


def test_recovery_comparison_rejects_coordinated_markdown_scope_deletion() -> None:
    documents = _documents()
    current_scope = {
        "work package": {"CT-001": "row"},
        "completion matrix": {"CT-001": "IN_PROGRESS"},
    }
    baseline_scope = {
        "work package": {"CT-001": "row", "SIM-001": "row2"},
        "completion matrix": {"CT-001": "IN_PROGRESS", "SIM-001": "IN_PROGRESS"},
    }
    errors = governance_guard.validate_against_base(
        documents,
        documents,
        {},
        current_scope=current_scope,
        baseline_scope=baseline_scope,
    )
    assert "trusted work package disappeared: SIM-001" in errors
    assert "trusted completion matrix disappeared: SIM-001" in errors


def test_branch_local_protected_approval_is_never_a_trust_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "protected-approvals.v1.json").write_text(
        '{"schema_version":2,"approvals":[]}', encoding="utf-8"
    )
    monkeypatch.delenv(governance_guard.TRUST_ROOT_SHA_ENV, raising=False)
    with pytest.raises(ValueError, match="branch-local protected approvals are forbidden"):
        governance_guard._load_external_protected_approvals(tmp_path)


def test_unconfigured_external_trust_root_cannot_authorize_later_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(governance_guard.TRUST_ROOT_SHA_ENV, raising=False)
    approvals = governance_guard._load_external_protected_approvals(governance_guard.ROOT)
    assert approvals == {}
    baseline = _documents()
    current = copy.deepcopy(baseline)
    current["attestations"]["registry_version"] = "3.0.0"
    current["attestations"]["attestations"] = [
        {
            "id": "ATT-BRANCH-LOCAL",
            "reviewer": {"id": "branch-reviewer"},
            "acceptance_criteria": ["ACC-CT-001"],
            "evidence_ids": ["EVD-CT-001"],
        }
    ]
    assert (
        "new attestation lacks external trust-root approval: ATT-BRANCH-LOCAL"
        in governance_guard.validate_against_base(current, baseline, approvals)
    )


def test_trust_root_rejects_head_ancestor_missing_and_branch_add_delete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(tmp_path, "init", "-q")
    marker = tmp_path / "marker.txt"
    marker.write_text("ordinary\n", encoding="utf-8")
    _git(tmp_path, "add", "marker.txt")
    ordinary_base = _commit(tmp_path, "ordinary base")

    governance = tmp_path / "governance"
    governance.mkdir()
    approval = governance / "protected-approvals.v1.json"
    approval.write_text('{"schema_version":2,"approvals":[]}', encoding="utf-8")
    _git(tmp_path, "add", "governance/protected-approvals.v1.json")
    branch_approval = _commit(tmp_path, "stage branch approval")
    approval.unlink()
    _git(tmp_path, "add", "-u")
    head = _commit(tmp_path, "delete branch approval")

    with pytest.raises(ValueError, match="must not equal current HEAD"):
        governance_guard._assert_trust_root_isolated(tmp_path, head, ordinary_base)
    monkeypatch.setenv(governance_guard.TRUST_ROOT_SHA_ENV, branch_approval)
    with pytest.raises(ValueError, match="shares ordinary branch history"):
        governance_guard._load_external_protected_approvals(tmp_path, ordinary_base)
    with pytest.raises(ValueError, match="shares ordinary branch history"):
        governance_guard._assert_trust_root_isolated(tmp_path, ordinary_base, ordinary_base)
    with pytest.raises(ValueError, match="not an available full commit SHA"):
        governance_guard._assert_trust_root_isolated(tmp_path, "f" * 40, ordinary_base)


def test_unrelated_orphan_trust_root_loads_and_cannot_be_the_event_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(tmp_path, "init", "-q")
    marker = tmp_path / "marker.txt"
    marker.write_text("ordinary\n", encoding="utf-8")
    _git(tmp_path, "add", "marker.txt")
    ordinary = _commit(tmp_path, "ordinary")
    branch = _git(tmp_path, "branch", "--show-current")

    _git(tmp_path, "checkout", "-q", "--orphan", "governance-trust")
    marker.unlink()
    _git(tmp_path, "add", "-u")
    governance = tmp_path / "governance"
    governance.mkdir()
    (governance / "protected-approvals.v1.json").write_text(
        """{
  "schema_version": 2,
  "approvals": [{
    "id": "PAPP-TEST-001",
    "subject_type": "PACKAGE_ATTESTATION",
    "subject_id": "ATT-TEST-001",
    "reviewer_id": "reviewer",
    "subject_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
    "criteria_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
    "evidence_sha256": "2222222222222222222222222222222222222222222222222222222222222222",
    "semantic_adequacy": "APPROVED"
  }]
}
""",
        encoding="utf-8",
    )
    _git(tmp_path, "add", "-A")
    trust_root = _commit(tmp_path, "external approval root")
    _git(tmp_path, "checkout", "-q", branch)

    governance_guard._assert_trust_root_isolated(tmp_path, trust_root, ordinary)
    monkeypatch.setenv(governance_guard.TRUST_ROOT_SHA_ENV, trust_root)
    approvals = governance_guard._load_external_protected_approvals(tmp_path, ordinary)
    assert set(approvals) == {"ATT-TEST-001"}
    with pytest.raises(ValueError, match="must not equal event base"):
        governance_guard._assert_trust_root_isolated(tmp_path, trust_root, trust_root)


def test_shallow_graph_rejects_trust_root_and_zero_base(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _git(source, "init", "-q")
    marker = source / "marker.txt"
    marker.write_text("one\n", encoding="utf-8")
    _git(source, "add", "marker.txt")
    first = _commit(source, "first")
    marker.write_text("two\n", encoding="utf-8")
    _git(source, "add", "marker.txt")
    _commit(source, "second")
    shallow = tmp_path / "shallow"
    _git(tmp_path, "clone", "-q", "--depth", "1", f"file://{source}", str(shallow))

    with pytest.raises(ValueError, match="shallow Git graph"):
        governance_guard._assert_trust_root_isolated(shallow, first, None)
    monkeypatch.delenv(threat_guard.GENESIS_SHA_ENV, raising=False)
    monkeypatch.setenv(threat_guard.RECOVERY_BASE_SHA_ENV, first)
    with pytest.raises(ValueError, match="shallow Git graph"):
        threat_guard.resolve_trusted_baseline(shallow, governance_guard.ZERO_GIT_OBJECT)


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
    assert "CT-001: VERIFIED promotion lacks external milestone authorization" in errors


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
    monkeypatch.delenv(threat_guard.GENESIS_SHA_ENV, raising=False)
    monkeypatch.delenv(threat_guard.RECOVERY_BASE_SHA_ENV, raising=False)
    assert governance_guard.main([]) == 1
    assert "CI requires an immutable trusted base revision" in capsys.readouterr().out

    monkeypatch.setenv("THREAT_CATALOG_BASE_REF", governance_guard.ZERO_GIT_OBJECT)
    assert governance_guard.main([]) == 1
    assert (
        "zero event base requires an external immutable genesis or recovery anchor"
        in capsys.readouterr().out
    )


def test_zero_base_accepts_only_exact_genesis_or_external_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    marker = tmp_path / "marker.txt"
    marker.write_text("genesis\n", encoding="utf-8")
    subprocess.run(["git", "add", "marker.txt"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Governance Test",
            "-c",
            "user.email=governance@example.invalid",
            "commit",
            "-q",
            "-m",
            "genesis",
        ],
        cwd=tmp_path,
        check=True,
    )
    genesis = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setenv(threat_guard.GENESIS_SHA_ENV, genesis)
    monkeypatch.delenv(threat_guard.RECOVERY_BASE_SHA_ENV, raising=False)
    assert threat_guard.resolve_trusted_baseline(tmp_path, governance_guard.ZERO_GIT_OBJECT) == (
        None,
        "GENESIS_BOOTSTRAP",
    )

    marker.write_text("later\n", encoding="utf-8")
    subprocess.run(["git", "add", "marker.txt"], cwd=tmp_path, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=Governance Test",
            "-c",
            "user.email=governance@example.invalid",
            "commit",
            "-q",
            "-m",
            "later",
        ],
        cwd=tmp_path,
        check=True,
    )
    with pytest.raises(ValueError, match="ref recreation requires an external recovery base"):
        threat_guard.resolve_trusted_baseline(tmp_path, governance_guard.ZERO_GIT_OBJECT)

    monkeypatch.delenv(threat_guard.GENESIS_SHA_ENV)
    monkeypatch.setenv(threat_guard.RECOVERY_BASE_SHA_ENV, genesis)
    assert threat_guard.resolve_trusted_baseline(tmp_path, governance_guard.ZERO_GIT_OBJECT) == (
        genesis,
        "EXTERNAL_RECOVERY",
    )

    head = _git(tmp_path, "rev-parse", "HEAD")
    monkeypatch.setenv(threat_guard.RECOVERY_BASE_SHA_ENV, head)
    with pytest.raises(ValueError, match="must not equal current HEAD"):
        threat_guard.resolve_trusted_baseline(tmp_path, governance_guard.ZERO_GIT_OBJECT)

    monkeypatch.setenv(threat_guard.RECOVERY_BASE_SHA_ENV, "f" * 40)
    with pytest.raises(ValueError, match="not an available full commit SHA"):
        threat_guard.resolve_trusted_baseline(tmp_path, governance_guard.ZERO_GIT_OBJECT)

    marker.write_text("descendant\n", encoding="utf-8")
    _git(tmp_path, "add", "marker.txt")
    descendant = _commit(tmp_path, "descendant recovery")
    _git(tmp_path, "checkout", "-q", "-b", "retained-head", head)
    monkeypatch.setenv(threat_guard.RECOVERY_BASE_SHA_ENV, descendant)
    with pytest.raises(ValueError, match="must be a strict ancestor"):
        threat_guard.resolve_trusted_baseline(tmp_path, governance_guard.ZERO_GIT_OBJECT)

    branch = _git(tmp_path, "branch", "--show-current")
    _git(tmp_path, "checkout", "-q", "--orphan", "unrelated-recovery")
    marker.unlink()
    unrelated_marker = tmp_path / "unrelated.txt"
    unrelated_marker.write_text("unrelated\n", encoding="utf-8")
    _git(tmp_path, "add", "-A")
    unrelated = _commit(tmp_path, "unrelated recovery")
    _git(tmp_path, "checkout", "-q", branch)
    monkeypatch.setenv(threat_guard.RECOVERY_BASE_SHA_ENV, unrelated)
    with pytest.raises(ValueError, match="must be a strict ancestor"):
        threat_guard.resolve_trusted_baseline(tmp_path, governance_guard.ZERO_GIT_OBJECT)


def test_zero_ref_recreation_runs_full_external_recovery_comparison(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    recovery = subprocess.run(
        ["git", "rev-parse", "HEAD^"],
        cwd=governance_guard.ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    monkeypatch.setenv("MYCOGNI_GOVERNANCE_CI", "1")
    monkeypatch.setenv("THREAT_CATALOG_BASE_REF", governance_guard.ZERO_GIT_OBJECT)
    monkeypatch.delenv(threat_guard.GENESIS_SHA_ENV, raising=False)
    monkeypatch.setenv(threat_guard.RECOVERY_BASE_SHA_ENV, recovery)
    monkeypatch.delenv(governance_guard.TRUST_ROOT_SHA_ENV, raising=False)
    assert governance_guard.main([]) == 0
    assert "trusted-base state: VERIFIED (EXTERNAL_RECOVERY)" in capsys.readouterr().out


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
