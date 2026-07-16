"""Fail-closed machine governance for package status, acceptance, and traceability."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.ci import threat_catalog_guard as threat_guard

ROOT = Path(__file__).parents[2]
GOVERNANCE = ROOT / "governance"
REPORT_PATH = ROOT / "docs/v1/TRACEABILITY_REPORT.md"
PROTECTED_APPROVALS_PATH = GOVERNANCE / "protected-approvals.v1.json"
DOCUMENTS = {
    "manifest": GOVERNANCE / "traceability.v1.json",
    "status": GOVERNANCE / "package-status.v1.json",
    "acceptance": GOVERNANCE / "acceptance.v1.json",
    "attestations": GOVERNANCE / "review-attestations.v1.json",
}
SCHEMAS = {
    "manifest": GOVERNANCE / "traceability.schema.json",
    "status": GOVERNANCE / "package-status.schema.json",
    "acceptance": GOVERNANCE / "acceptance.schema.json",
    "attestations": GOVERNANCE / "review-attestations.schema.json",
}
SCHEMA_HASHES = {
    "manifest": "a6e1b479f24c89109980643c147c756480af0d93ce1b87cac8f0e6614013cfbd",
    "status": "f414f057b8bbf1166e1b72c0edd01e859fed139b75e5f419840f53edee3e4ded",
    "acceptance": "37ab391d8d4f6c5d3877f8af7d7d2de108b57102b75f63905bbb0abd150670c2",
    "attestations": "18125f4f61814f6a5c748f093491e70bb2f782766a958e57d2578124b6249700",
}
STATUSES = {"NOT_STARTED", "IN_PROGRESS", "BLOCKED", "COMPLETE", "VERIFIED"}
STATUS_RANK = {"NOT_STARTED": 0, "BLOCKED": 1, "IN_PROGRESS": 1, "COMPLETE": 2, "VERIFIED": 3}
ADR_STATUSES = {
    "Accepted",
    "Accepted for initial build",
    "Accepted as a boundary; runtime deferred until post-v1 evidence",
}
ACCEPTING_ADR_STATUSES = {"Accepted", "Accepted for initial build"}
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
MILESTONE_GATES = {
    "M0": {
        "M0_ALL_PACKAGES_COMPLETE",
        "M0_ALL_SPIKES_DISPOSITIONED",
        "M0_SIMULATOR_ONLY_EXTERNAL_IO",
    },
    "M1": {"M1_CONFORMANCE", "M1_FAILURE_INJECTION", "M1_SYNTHETIC_E2E"},
    "M2": {"M2_DISCLOSURE", "M2_OBSERVATION_AUTHORITY", "M2_SYNTHETIC_E2E"},
    "M3": {"LG-2", "LG-3", "M3_GUIDED_E2E"},
    "M4": {"M4_AUTOMATION_AUTHORITY", "M4_CANARY", "M4_RECOVERY"},
    "M5": {"M5_CONFORMANCE", "M5_RESOURCE_BUDGET", "M5_SECURITY_RELEASE"},
    "M6": {"M6_DAY90_EVIDENCE", "M6_STABLE_CLAIMS", "M6_ZERO_ENABLED_P0_P1"},
}


def _load(path: Path) -> dict[str, Any]:
    return threat_guard._load_json(path)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _duplicates(values: Sequence[str]) -> set[str]:
    return {value for value in values if values.count(value) > 1}


def parse_requirements(root: Path) -> tuple[set[str], list[str]]:
    text = (root / "docs/02-requirements.md").read_text(encoding="utf-8")
    ids: list[str] = []
    errors: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith("- **"):
            continue
        match = re.fullmatch(r"- \*\*([A-Z][A-Z0-9-]+)\*\* .+", line)
        if match is None:
            errors.append(f"malformed requirement candidate at line {number}")
        else:
            ids.append(match.group(1))
    for duplicate in sorted(_duplicates(ids)):
        errors.append(f"duplicate requirement ID {duplicate}")
    return set(ids), errors


def parse_work_packages(root: Path) -> tuple[dict[str, set[str]], list[str]]:
    text = (root / "docs/v1/WORK_PACKAGES.md").read_text(encoding="utf-8")
    packages: dict[str, set[str]] = {}
    errors: list[str] = []
    in_table = False
    for number, line in enumerate(text.splitlines(), 1):
        if line == "| ID | Lane | Package | Depends on | Estimate | Acceptance evidence |":
            in_table = True
            continue
        if not in_table:
            continue
        if not line.startswith("|"):
            in_table = False
            continue
        if line.startswith("| ---"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 6 or re.fullmatch(r"[A-Z][A-Z0-9-]+", cells[0]) is None:
            errors.append(f"malformed work-package row at line {number}")
            continue
        package_id = cells[0]
        if package_id in packages:
            errors.append(f"duplicate work-package ID {package_id}")
            continue
        packages[package_id] = (
            set() if cells[3] == "—" else {value.strip() for value in cells[3].split(",")}
        )
    for package_id, dependencies in packages.items():
        for missing in sorted(dependencies - set(packages)):
            errors.append(f"{package_id}: unknown dependency {missing}")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, chain: tuple[str, ...]) -> None:
        if node in visiting:
            errors.append(f"work-package dependency cycle: {' -> '.join((*chain, node))}")
            return
        if node in visited:
            return
        visiting.add(node)
        for dependency in sorted(packages.get(node, set())):
            visit(dependency, (*chain, node))
        visiting.remove(node)
        visited.add(node)

    for package_id in sorted(packages):
        visit(package_id, ())
    return packages, sorted(set(errors))


def parse_adrs(root: Path) -> tuple[dict[str, str], list[str]]:
    adrs: dict[str, str] = {}
    errors: list[str] = []
    for path in sorted((root / "docs/adr").glob("[0-9][0-9][0-9][0-9]-*.md")):
        text = path.read_text(encoding="utf-8")
        title = re.search(r"^# ADR-(\d{4}): .+$", text, re.MULTILINE)
        status = re.search(r"^- Status: (.+)$", text, re.MULTILINE)
        if title is None or status is None or title.group(1) != path.name[:4]:
            errors.append(f"malformed ADR {path.relative_to(root)}")
            continue
        adr_id = f"ADR-{title.group(1)}"
        if adr_id in adrs:
            errors.append(f"duplicate ADR ID {adr_id}")
        if status.group(1) not in ADR_STATUSES:
            errors.append(f"{adr_id}: unknown ADR status {status.group(1)!r}")
        adrs[adr_id] = status.group(1)
    index_text = (root / "docs/adr/README.md").read_text(encoding="utf-8")
    index: dict[str, str] = {}
    for line in index_text.splitlines():
        if not re.match(r"^\| \[\d{4}\]", line):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        match = re.fullmatch(r"\[(\d{4})\]\([^)]+\)", cells[0]) if len(cells) == 3 else None
        if match is None:
            errors.append("malformed ADR index row")
            continue
        adr_id = f"ADR-{match.group(1)}"
        if adr_id in index:
            errors.append(f"duplicate ADR index row {adr_id}")
        index[adr_id] = cells[1]
    if index != adrs:
        errors.append("ADR index is not losslessly equal to canonical ADR files/statuses")
    return adrs, sorted(set(errors))


def parse_completion(root: Path) -> tuple[dict[str, str], list[str]]:
    text = (root / "docs/v1/COMPLETION_MATRIX.md").read_text(encoding="utf-8")
    rows: dict[str, str] = {}
    errors: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 5:
            continue
        package = cells[1]
        if re.fullmatch(r"[A-Z][A-Z0-9-]+", package) is None:
            continue
        status_match = re.fullmatch(r"`([A-Z_]+)`", cells[2])
        if status_match is None or status_match.group(1) not in STATUSES:
            errors.append(f"malformed package-status row at line {number}")
            continue
        if package in rows:
            errors.append(f"duplicate completion-matrix package row {package}")
        rows[package] = status_match.group(1)
    return rows, errors


def _git_commit_is_ancestor(root: Path, commit: str) -> bool:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        return False
    exists = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if exists.returncode != 0:
        return False
    ancestor = subprocess.run(
        ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return ancestor.returncode == 0


def _meaningful_assertion(function: ast.FunctionDef) -> bool:
    """Require a direct, data-dependent assertion in the executed test body."""

    dynamic = (ast.Call, ast.Name, ast.Attribute, ast.Subscript)
    for statement in function.body:
        if not isinstance(statement, ast.Assert):
            continue
        if isinstance(statement.test, ast.Constant):
            continue
        if any(isinstance(node, dynamic) for node in ast.walk(statement.test)):
            return True
    return False


def _acceptance_node(root: Path, evidence: Mapping[str, Any], criterion_ids: Sequence[str]) -> bool:
    reference = evidence.get("ref")
    if not isinstance(reference, str) or reference.count("::") != 1:
        return False
    path_text, function_name = reference.split("::")
    path = threat_guard._canonical_repo_file(root, path_text)
    if path is None or _sha256(path) != evidence.get("content_sha256"):
        return False
    module = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        ),
        None,
    )
    if function is None:
        return False
    decorators = {ast.unparse(item) for item in function.decorator_list}
    if "pytest.mark.governance_acceptance" not in decorators:
        return False
    if any(item.startswith(("pytest.mark.skip", "pytest.mark.xfail")) for item in decorators):
        return False
    direct_criterion_calls = [
        statement.value
        for statement in function.body
        if isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "governance_criterion"
    ]
    invoked = [
        call.args[0].value
        for call in direct_criterion_calls
        if len(call.args) == 1
        and not call.keywords
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    ]
    return sorted(invoked) == sorted(criterion_ids) and _meaningful_assertion(function)


def _execute_node(root: Path, reference: str, criterion_ids: Sequence[str]) -> bool:
    with tempfile.TemporaryDirectory(prefix="mycogni-governance-") as directory:
        artifact = Path(directory) / "result.json"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--runxfail", "-rA", "-q", reference],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "MYCOGNI_GOVERNANCE_EVIDENCE_SUBPROCESS": "1",
                "MYCOGNI_GOVERNANCE_ARTIFACT": str(artifact),
            },
        )
        if result.returncode != 0 or not artifact.is_file():
            return False
        try:
            payload = json.loads(artifact.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        expected_node = reference.split("::", 1)[1]
        return (
            payload.get("outcome") == "passed"
            and payload.get("wasxfail") is False
            and payload.get("skip_or_xfail_markers") == []
            and payload.get("criteria") == sorted(criterion_ids)
            and payload.get("nodeid", "").endswith(f"::{expected_node}")
            and re.search(rf"^PASSED {re.escape(reference)}$", result.stdout, re.MULTILINE)
            is not None
        )


def _git_file_bytes(root: Path, commit: str, path: str) -> bytes | None:
    canonical = threat_guard._canonical_repo_file(root, path)
    if canonical is None:
        return None
    result = subprocess.run(
        ["git", "show", f"{commit}:{canonical.relative_to(root).as_posix()}"],
        cwd=root,
        check=False,
        capture_output=True,
        timeout=20,
    )
    return result.stdout if result.returncode == 0 else None


def _validate_schemas(documents: Mapping[str, Mapping[str, Any]]) -> list[str]:
    errors: list[str] = []
    for name, document in documents.items():
        schema = _load(SCHEMAS[name])
        if threat_guard._canonical_json_hash(schema) != SCHEMA_HASHES[name]:
            errors.append(f"{name}: governance schema hash mismatch")
        errors.extend(
            f"{name} {error}" for error in threat_guard._schema_errors(document, schema, schema)
        )
    return errors


def _validate_threat_catalog(root: Path, *, execute: bool) -> list[str]:
    catalog = _load(root / "security/threat-catalog.v1.json")
    registry = _load(root / "security/verification-tests.v1.json")
    history = _load(root / "security/id-history.v1.json")
    errors = threat_guard.validate_catalog(catalog, registry, history, root)
    schemas = {
        threat_guard.SCHEMA_PATH.name: _load(threat_guard.SCHEMA_PATH),
        threat_guard.REGISTRY_SCHEMA_PATH.name: _load(threat_guard.REGISTRY_SCHEMA_PATH),
        threat_guard.HISTORY_SCHEMA_PATH.name: _load(threat_guard.HISTORY_SCHEMA_PATH),
    }
    for document, name in (
        (catalog, threat_guard.SCHEMA_PATH.name),
        (registry, threat_guard.REGISTRY_SCHEMA_PATH.name),
        (history, threat_guard.HISTORY_SCHEMA_PATH.name),
    ):
        errors.extend(threat_guard.validate_published_schema(document, schemas[name], name))
    base = os.environ.get("THREAT_CATALOG_BASE_REF", "").strip()
    if base:
        baseline = threat_guard.load_history_from_git_base(root, base)
        if baseline is not None:
            errors.extend(threat_guard.validate_history_against_baseline(history, baseline))
    if execute and not errors:
        errors.extend(threat_guard._execute_pytest_nodes(registry, root))
    return errors


def validate_governance(
    documents: Mapping[str, Mapping[str, Any]], root: Path, *, execute: bool = False
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    requirements, requirement_errors = parse_requirements(root)
    packages, package_errors = parse_work_packages(root)
    adrs, adr_errors = parse_adrs(root)
    matrix, matrix_errors = parse_completion(root)
    errors.extend(requirement_errors + package_errors + adr_errors + matrix_errors)
    manifest = documents["manifest"]
    status_doc = documents["status"]
    acceptance = documents["acceptance"]
    attestations_doc = documents["attestations"]
    records = manifest.get("records", [])
    status_rows = status_doc.get("packages", [])
    criteria_rows = acceptance.get("criteria", [])
    evidence_rows = acceptance.get("evidence", [])
    attestation_rows = attestations_doc.get("attestations", [])
    for name, document in documents.items():
        version = document.get("manifest_version") or document.get("registry_version")
        if _semver_tuple(version) is None:
            errors.append(f"{name}: registry version must be semantic x.y.z")
    for name, rows in (
        ("records", records),
        ("packages", status_rows),
        ("criteria", criteria_rows),
        ("evidence", evidence_rows),
        ("attestations", attestation_rows),
    ):
        if not isinstance(rows, list):
            errors.append(f"{name} must be an array")
            continue
        ids = [row.get("id") for row in rows if isinstance(row, dict)]
        if ids != sorted(ids, key=str):
            errors.append(f"{name} must be sorted by canonical ID")
        for duplicate in sorted(_duplicates([value for value in ids if isinstance(value, str)])):
            errors.append(f"duplicate {name} ID {duplicate}")
    status_by_id = {
        row["id"]: row
        for row in status_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    criteria = {
        row["id"]: row
        for row in criteria_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    evidence = {
        row["id"]: row
        for row in evidence_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    attestations = {
        row["id"]: row
        for row in attestation_rows
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    if set(status_by_id) != set(packages) or set(matrix) != set(packages):
        errors.append(
            "package inventories must be exactly equal across work packages, status registry, and matrix"
        )
    for package_id, row in status_by_id.items():
        if package_id not in packages:
            errors.append(f"status registry has unknown package {package_id}")
        if matrix.get(package_id) != row.get("status"):
            errors.append(
                f"{package_id}: matrix status is not losslessly equal to canonical registry"
            )
        status = row.get("status")
        if status in {"COMPLETE", "VERIFIED"}:
            missing = packages.get(package_id, set()) - {
                dependency
                for dependency, dependency_row in status_by_id.items()
                if dependency_row.get("status") in {"COMPLETE", "VERIFIED"}
            }
            if missing:
                errors.append(f"{package_id}: incomplete prerequisites {sorted(missing)}")
    threat_catalog = _load(root / "security/threat-catalog.v1.json")
    threat_registry = _load(root / "security/verification-tests.v1.json")
    threats_by_id = {item["id"]: item for item in threat_catalog["threats"]}
    tests_by_id = {item["id"]: item for item in threat_registry["tests"]}
    mapping_ids = {
        "REQUIREMENT": requirements,
        "WORK_PACKAGE": set(packages),
        "ADR": set(adrs),
        "THREAT": {item["id"] for item in threat_catalog["threats"]},
        "VERIFICATION_TEST": {item["id"] for item in threat_registry["tests"]},
    }
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        package_id = record.get("package")
        if package_id not in packages:
            errors.append(f"trace record has unknown package {package_id}")
        mappings = record.get("mappings")
        if not isinstance(mappings, list) or not mappings:
            errors.append(f"{record.get('id')}: package mappings must be nonempty")
        else:
            for mapping in mappings:
                if not isinstance(mapping, dict) or mapping.get("id") not in mapping_ids.get(
                    mapping.get("kind"), set()
                ):
                    errors.append(f"{record.get('id')}: dangling mapping {mapping}")
                if (
                    mapping.get("kind") == "ADR"
                    and adrs.get(mapping.get("id")) not in ACCEPTING_ADR_STATUSES
                ):
                    errors.append(f"{record.get('id')}: non-accepting ADR cannot authorize mapping")
                if mapping.get("kind") == "VERIFICATION_TEST":
                    vfy = next(
                        (
                            item
                            for item in threat_registry["tests"]
                            if item["id"] == mapping.get("id")
                        ),
                        None,
                    )
                    if vfy is None or vfy["status"] != "IMPLEMENTED":
                        errors.append(f"{record.get('id')}: planned VFY cannot count as accepted")
        if record.get("state") in {"INDEPENDENTLY_ACCEPTED", "MILESTONE_VERIFIED"}:
            mapped_threats = {
                item.get("id")
                for item in mappings or []
                if isinstance(item, dict) and item.get("kind") == "THREAT"
            }
            mapped_tests = {
                item.get("id")
                for item in mappings or []
                if isinstance(item, dict) and item.get("kind") == "VERIFICATION_TEST"
            }
            required_tests = {
                test_id
                for threat_id in mapped_threats
                if threat_id in threats_by_id
                for test_id in threats_by_id[threat_id]["verification_tests"]
            }
            required_threats = {
                threat_id
                for test_id in mapped_tests
                if test_id in tests_by_id
                for threat_id in tests_by_id[test_id]["threats"]
            }
            if mapped_tests != required_tests or mapped_threats != required_threats:
                errors.append(
                    f"{record.get('id')}: threat and VFY mappings are not bidirectionally closed"
                )
            for threat_id in mapped_threats:
                threat = threats_by_id.get(threat_id)
                if threat is None or threat.get("status") != "CONTROL_TESTED":
                    errors.append(f"{record.get('id')}: planned threat cannot count as accepted")
            for test_id in mapped_tests:
                test = tests_by_id.get(test_id)
                if test is None or test.get("status") != "IMPLEMENTED":
                    errors.append(f"{record.get('id')}: planned VFY cannot count as accepted")
        criterion_ids = record.get("acceptance_criteria", [])
        evidence_ids = record.get("evidence_ids", [])
        attestation = attestations.get(record.get("attestation_id"))
        if not criterion_ids or not evidence_ids:
            errors.append(f"{record.get('id')}: criteria and evidence must be nonempty")
        for criterion_id in criterion_ids:
            criterion = criteria.get(criterion_id)
            if (
                criterion is None
                or criterion.get("package") != package_id
                or criterion.get("evidence_id") not in evidence_ids
            ):
                errors.append(
                    f"{record.get('id')}: invalid package-specific criterion {criterion_id}"
                )
        for evidence_id in evidence_ids:
            item = evidence.get(evidence_id)
            if (
                item is None
                or item.get("package") != package_id
                or not _acceptance_node(root, item, criterion_ids)
            ):
                errors.append(
                    f"{record.get('id')}: invalid package acceptance evidence {evidence_id}"
                )
            elif execute and not _execute_node(root, item["ref"], criterion_ids):
                errors.append(f"{record.get('id')}: acceptance evidence did not PASS {evidence_id}")
        if record.get("state") == "INDEPENDENTLY_ACCEPTED":
            if (
                attestation is None
                or attestation.get("package") != package_id
                or attestation.get("disposition") != "ACCEPT"
            ):
                errors.append(f"{record.get('id')}: missing exact ACCEPT attestation")
            else:
                if (
                    attestation.get("acceptance_criteria") != criterion_ids
                    or attestation.get("evidence_ids") != evidence_ids
                ):
                    errors.append(f"{record.get('id')}: attestation scope does not equal record")
                commit = attestation.get("reviewed_commit")
                if not isinstance(commit, str) or not _git_commit_is_ancestor(root, commit):
                    errors.append(f"{record.get('id')}: reviewed commit is not an ancestor")
                review = attestation.get("review_record", {})
                review_bytes = (
                    _git_file_bytes(root, commit, review.get("path", ""))
                    if isinstance(commit, str) and isinstance(review, dict)
                    else None
                )
                if review_bytes is None or hashlib.sha256(review_bytes).hexdigest() != review.get(
                    "sha256"
                ):
                    errors.append(f"{record.get('id')}: review record digest mismatch")
                for evidence_id in evidence_ids:
                    evidence_item = evidence.get(evidence_id, {})
                    source_path = str(evidence_item.get("ref", "")).split("::", 1)[0]
                    source_bytes = (
                        _git_file_bytes(root, commit, source_path)
                        if isinstance(commit, str)
                        else None
                    )
                    if source_bytes is None or hashlib.sha256(
                        source_bytes
                    ).hexdigest() != evidence_item.get("content_sha256"):
                        errors.append(
                            f"{record.get('id')}: evidence digest is not bound to reviewed commit"
                        )
                if not attestation.get("residuals"):
                    errors.append(f"{record.get('id')}: attestation residuals must be explicit")
    evidence_by_package: dict[str, set[str]] = {package_id: set() for package_id in packages}
    for record in records if isinstance(records, list) else []:
        if isinstance(record, dict) and record.get("package") in evidence_by_package:
            evidence_by_package[record["package"]].update(record.get("evidence_ids", []))
    for package_id, row in status_by_id.items():
        if set(row.get("evidence_ids", [])) != evidence_by_package.get(package_id, set()):
            errors.append(f"{package_id}: status evidence_ids do not exactly match trace records")
        if row.get("status") in {"COMPLETE", "VERIFIED"}:
            matching = [
                record
                for record in records
                if isinstance(record, dict)
                and record.get("package") == package_id
                and record.get("state") in {"INDEPENDENTLY_ACCEPTED", "MILESTONE_VERIFIED"}
            ]
            if len(matching) != 1:
                errors.append(f"{package_id}: completion lacks exactly one accepted trace record")
    used_criteria = {
        value
        for record in (records if isinstance(records, list) else [])
        if isinstance(record, dict)
        for value in record.get("acceptance_criteria", [])
    }
    used_evidence = {
        value
        for record in (records if isinstance(records, list) else [])
        if isinstance(record, dict)
        for value in record.get("evidence_ids", [])
    }
    used_attestations = {
        record.get("attestation_id")
        for record in (records if isinstance(records, list) else [])
        if isinstance(record, dict) and record.get("attestation_id")
    }
    if used_criteria != set(criteria):
        errors.append("criteria registry contains missing or unused entries")
    if used_evidence != set(evidence):
        errors.append("evidence registry contains missing or unused entries")
    if used_attestations != set(attestations):
        errors.append("attestation registry contains missing or unused entries")
    milestones = status_doc.get("milestone_attestations", [])
    milestone_ids = [
        item.get("id") for item in milestones if isinstance(item, dict) and item.get("id")
    ]
    if milestone_ids != sorted(milestone_ids):
        errors.append("milestone attestations must be sorted by canonical ID")
    for duplicate in sorted(_duplicates(milestone_ids)):
        errors.append(f"duplicate milestone attestation ID {duplicate}")
    verified_ids = {
        package_id for package_id, row in status_by_id.items() if row.get("status") == "VERIFIED"
    }
    for milestone in milestones:
        if isinstance(milestone, dict) and not (set(milestone.get("packages", [])) & verified_ids):
            errors.append(f"unused milestone attestation {milestone.get('id')}")
    for package_id, row in status_by_id.items():
        if row.get("status") == "VERIFIED":
            covering = [
                item
                for item in milestones
                if isinstance(item, dict)
                and package_id in item.get("packages", [])
                and item.get("disposition") == "ACCEPT"
            ]
            if len(covering) != 1:
                errors.append(f"{package_id}: VERIFIED lacks one structured milestone attestation")
                continue
            milestone = covering[0]
            dependency_closure: set[str] = set()

            def add_dependencies(item: str, closure: set[str]) -> None:
                for dependency in packages.get(item, set()):
                    if dependency not in closure:
                        closure.add(dependency)
                        add_dependencies(dependency, closure)

            for covered_package in milestone.get("packages", []):
                add_dependencies(covered_package, dependency_closure)
            if set(milestone.get("dependency_packages", [])) != dependency_closure:
                errors.append(
                    f"{package_id}: milestone attestation has partial dependency coverage"
                )
            expected_gates = MILESTONE_GATES.get(milestone.get("milestone"))
            if expected_gates is None or set(milestone.get("gates", [])) != expected_gates:
                errors.append(f"{package_id}: milestone attestation has partial gate coverage")
            milestone_commit = milestone.get("reviewed_commit")
            if not isinstance(milestone_commit, str) or not _git_commit_is_ancestor(
                root, milestone_commit
            ):
                errors.append(f"{package_id}: milestone reviewed commit is not an ancestor")
            milestone_review = milestone.get("review_record", {})
            milestone_bytes = (
                _git_file_bytes(root, milestone_commit, milestone_review.get("path", ""))
                if isinstance(milestone_commit, str) and isinstance(milestone_review, dict)
                else None
            )
            if milestone_bytes is None or hashlib.sha256(
                milestone_bytes
            ).hexdigest() != milestone_review.get("sha256"):
                errors.append(f"{package_id}: milestone review digest mismatch")
            gate_evidence = set(milestone.get("gate_evidence_ids", []))
            expected_evidence = {
                item
                for covered_package in milestone.get("packages", [])
                for item in evidence_by_package.get(covered_package, set())
            }
            if gate_evidence != expected_evidence:
                errors.append(f"{package_id}: milestone gate evidence is partial or nonexistent")
    errors.extend(_validate_schemas(documents))
    counts = {
        "requirements": sorted(requirements),
        "packages": sorted(packages),
        "adrs": sorted(adrs),
        "records": sorted(record["id"] for record in records if isinstance(record, dict)),
        "threats": sorted(threats_by_id),
        "verification_tests": sorted(tests_by_id),
        "registry_packages": sorted(status_by_id),
        "accepted_packages": sorted(
            record["package"]
            for record in records
            if isinstance(record, dict) and record.get("state") == "INDEPENDENTLY_ACCEPTED"
        ),
        "complete_packages": sorted(
            package_id
            for package_id, row in status_by_id.items()
            if row.get("status") == "COMPLETE"
        ),
        "verified_packages": sorted(
            package_id
            for package_id, row in status_by_id.items()
            if row.get("status") == "VERIFIED"
        ),
    }
    return sorted(set(errors)), counts


def _semver_tuple(value: Any) -> tuple[int, int, int] | None:
    if not isinstance(value, str) or SEMVER.fullmatch(value) is None:
        return None
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def validate_against_base(
    current: Mapping[str, Mapping[str, Any]],
    baseline: Mapping[str, Mapping[str, Any]],
    protected_approvals: Mapping[str, Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    for name in DOCUMENTS:
        current_version = _semver_tuple(
            current[name].get("manifest_version") or current[name].get("registry_version")
        )
        baseline_version = _semver_tuple(
            baseline[name].get("manifest_version") or baseline[name].get("registry_version")
        )
        if (
            current_version is None
            or baseline_version is None
            or current_version < baseline_version
        ):
            errors.append(f"{name}: version regressed across trusted base")
        if current[name] != baseline[name] and current_version == baseline_version:
            errors.append(f"{name}: content changed without version increment")
    before = {item["id"]: item for item in baseline["attestations"].get("attestations", [])}
    after = {item["id"]: item for item in current["attestations"].get("attestations", [])}
    for attestation_id in sorted(set(before) - set(after)):
        errors.append(f"trusted attestation disappeared: {attestation_id}")
    for attestation_id in sorted(set(before) & set(after)):
        if before[attestation_id] != after[attestation_id]:
            errors.append(f"trusted attestation mutated: {attestation_id}")
    for attestation_id in sorted(set(after) - set(before)):
        attestation = after[attestation_id]
        approval = protected_approvals.get(attestation_id)
        if (
            approval is None
            or approval.get("reviewer_id") != attestation.get("reviewer", {}).get("id")
            or approval.get("attestation_sha256") != threat_guard._canonical_json_hash(attestation)
        ):
            errors.append(f"new attestation lacks allowlisted protected approval: {attestation_id}")
    before_status = {
        item["id"]: item.get("status") for item in baseline["status"].get("packages", [])
    }
    after_status = {
        item["id"]: item.get("status") for item in current["status"].get("packages", [])
    }
    records_by_package = {
        item.get("package"): item for item in current["manifest"].get("records", [])
    }
    for package_id, status in after_status.items():
        prior = before_status.get(package_id, "NOT_STARTED")
        if STATUS_RANK.get(status, -1) < 2 or STATUS_RANK.get(prior, -1) >= 2:
            continue
        attestation_id = records_by_package.get(package_id, {}).get("attestation_id")
        if not attestation_id or attestation_id not in protected_approvals:
            errors.append(f"{package_id}: promotion lacks protected-base authorization")
    return errors


def _load_base_documents(root: Path, revision: str) -> dict[str, dict[str, Any]]:
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", revision) is None:
        raise ValueError("governance base revision must be a full hexadecimal object ID")
    commit = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        timeout=20,
    )
    if commit.returncode != 0:
        raise ValueError("governance base revision is unavailable")
    result: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    for name, path in DOCUMENTS.items():
        relative = path.relative_to(root).as_posix()
        shown = subprocess.run(
            ["git", "show", f"{revision}:{relative}"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if shown.returncode != 0:
            missing.append(name)
            continue
        result[name] = threat_guard._load_json_text(shown.stdout, f"governance base {name}")
    if missing and len(missing) != len(DOCUMENTS):
        raise ValueError(f"trusted base has partial governance-document disappearance: {missing}")
    return result


def _load_protected_approvals(root: Path, revision: str) -> dict[str, Mapping[str, Any]]:
    relative = PROTECTED_APPROVALS_PATH.relative_to(root).as_posix()
    shown = subprocess.run(
        ["git", "show", f"{revision}:{relative}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if shown.returncode != 0:
        return {}
    document = threat_guard._load_json_text(shown.stdout, "protected governance approvals")
    if set(document) != {"schema_version", "approvals"} or document.get("schema_version") != 1:
        raise ValueError("protected approval registry is malformed")
    approvals = document.get("approvals")
    if not isinstance(approvals, list):
        raise ValueError("protected approval registry approvals must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    for item in approvals:
        if (
            not isinstance(item, dict)
            or set(item) != {"attestation_id", "reviewer_id", "attestation_sha256"}
            or not isinstance(item.get("attestation_id"), str)
            or not isinstance(item.get("reviewer_id"), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(item.get("attestation_sha256"))) is None
            or item["attestation_id"] in result
        ):
            raise ValueError("protected approval registry entry is malformed or duplicated")
        result[item["attestation_id"]] = item
    return result


def _untrusted_promotions(documents: Mapping[str, Mapping[str, Any]]) -> list[str]:
    errors: list[str] = []
    if documents["attestations"].get("attestations"):
        errors.append("trusted base is required for ACCEPT attestations")
    if any(
        item.get("state") in {"INDEPENDENTLY_ACCEPTED", "MILESTONE_VERIFIED"}
        for item in documents["manifest"].get("records", [])
    ):
        errors.append("trusted base is required for accepted trace states")
    if any(
        item.get("status") in {"COMPLETE", "VERIFIED"}
        for item in documents["status"].get("packages", [])
    ):
        errors.append("trusted base is required for package promotion")
    return errors


def render_report(data: Mapping[str, Any]) -> str:
    def listed(values: Sequence[str]) -> str:
        return ", ".join(f"`{value}`" for value in values) if values else "None"

    return "\n".join(
        [
            "# Governance traceability coverage",
            "",
            "Deterministic machine-registry report. No Markdown statement promotes package status.",
            "",
            "## Actual package state",
            "",
            f"- Structured accepted records: {listed(data['accepted_packages'])}",
            f"- Canonical COMPLETE packages: {listed(data['complete_packages'])}",
            f"- Canonical VERIFIED packages: {listed(data['verified_packages'])}",
            "",
            "## Canonical inventories",
            "",
            f"- Requirements ({len(data['requirements'])}): {listed(data['requirements'])}",
            f"- Work packages ({len(data['packages'])}): {listed(data['packages'])}",
            f"- ADRs ({len(data['adrs'])}): {listed(data['adrs'])}",
            f"- Trace records ({len(data['records'])}): {listed(data['records'])}",
            f"- Threats ({len(data['threats'])}): {listed(data['threats'])}",
            f"- Verification tests ({len(data['verification_tests'])}): {listed(data['verification_tests'])}",
            f"- Canonical package-status scope ({len(data['registry_packages'])}): {listed(data['registry_packages'])}",
            "",
            "## Claim boundary",
            "",
            "Implemented records are not acceptance. An ACCEPT attestation requires protected-base authorization and exact reviewed-commit evidence/review digests; canonical status remains below COMPLETE until every promotion rule passes.",
            "No milestone is verified. Planned threat controls remain planned, and the threat guard is invoked fail-closed by GOV.",
            "GOV-001 itself remains IN_PROGRESS pending independent review of these registries and guards.",
            "",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    try:
        documents = {name: _load(path) for name, path in DOCUMENTS.items()}
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Governance guard could not load machine truth: {error}")
        return 1
    errors = _validate_threat_catalog(ROOT, execute=True)
    governance_errors, report_data = validate_governance(documents, ROOT, execute=True)
    errors.extend(governance_errors)
    base_ref = os.environ.get("THREAT_CATALOG_BASE_REF", "").strip()
    base_state = "NOT CHECKED"
    if base_ref:
        try:
            baseline = _load_base_documents(ROOT, base_ref)
            approvals = _load_protected_approvals(ROOT, base_ref)
        except ValueError as error:
            errors.append(str(error))
        else:
            if not baseline:
                errors.extend(_untrusted_promotions(documents))
                base_state = "BOOTSTRAP"
            else:
                errors.extend(validate_against_base(documents, baseline, approvals))
                base_state = "VERIFIED"
    else:
        errors.extend(_untrusted_promotions(documents))
    if errors:
        print("\n".join(sorted(set(errors))))
        return 1
    report = render_report(report_data)
    if args.write_report:
        REPORT_PATH.write_text(report, encoding="utf-8")
    elif not REPORT_PATH.is_file() or REPORT_PATH.read_text(encoding="utf-8") != report:
        print("Governance report is stale")
        return 1
    print(f"Governance guard passed; trusted-base state: {base_state}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
