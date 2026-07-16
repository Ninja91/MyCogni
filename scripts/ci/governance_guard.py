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
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.ci import threat_catalog_guard as threat_guard

ROOT = Path(__file__).parents[2]
GOVERNANCE = ROOT / "governance"
REPORT_PATH = ROOT / "docs/v1/TRACEABILITY_REPORT.md"
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
    "manifest": "9da36145fa0970a415d0568c31aba863149a030a5543ae3253625a78698042af",
    "status": "8f117ed3a28e0bffca00d70357ef63a18773bee4e5ff51678babd75daa8cbbf9",
    "acceptance": "29996058fa7108738b9f30fcd0b7cc97a8408b01c28acade02b14d87df5cbe75",
    "attestations": "e5a9c33c79052960be1c9a97eec046a7b38a803f3d1de37edfdbea0fc458092a",
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
        index[f"ADR-{match.group(1)}"] = cells[1]
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


def _acceptance_node(root: Path, evidence: Mapping[str, Any]) -> bool:
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
    calls = {ast.unparse(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)}
    return not (calls & {"pytest.skip", "pytest.xfail"}) and any(
        isinstance(node, ast.Assert) for node in ast.walk(function)
    )


def _execute_node(root: Path, reference: str) -> bool:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--runxfail", "-rA", "-q", reference],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "MYCOGNI_GOVERNANCE_EVIDENCE_SUBPROCESS": "1"},
    )
    return (
        result.returncode == 0
        and re.search(rf"^PASSED {re.escape(reference)}$", result.stdout, re.MULTILINE) is not None
    )


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
                or not _acceptance_node(root, item)
            ):
                errors.append(
                    f"{record.get('id')}: invalid package acceptance evidence {evidence_id}"
                )
            elif execute and not _execute_node(root, item["ref"]):
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
                review_path = (
                    threat_guard._canonical_repo_file(root, review.get("path", ""))
                    if isinstance(review, dict)
                    else None
                )
                if review_path is None or _sha256(review_path) != review.get("sha256"):
                    errors.append(f"{record.get('id')}: review record digest mismatch")
                if not attestation.get("residuals"):
                    errors.append(f"{record.get('id')}: attestation residuals must be explicit")
    for package_id, row in status_by_id.items():
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
    milestones = status_doc.get("milestone_attestations", [])
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
    errors.extend(_validate_schemas(documents))
    counts = {
        "requirements": sorted(requirements),
        "packages": sorted(packages),
        "adrs": sorted(adrs),
        "records": sorted(record["id"] for record in records if isinstance(record, dict)),
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
    current: Mapping[str, Mapping[str, Any]], baseline: Mapping[str, Mapping[str, Any]]
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
    return errors


def _load_base_documents(root: Path, revision: str) -> dict[str, dict[str, Any]] | None:
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", revision) is None:
        raise ValueError("governance base revision must be a full hexadecimal object ID")
    result: dict[str, dict[str, Any]] = {}
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
            return None
        result[name] = threat_guard._load_json_text(shown.stdout, f"governance base {name}")
    return result


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
            "",
            "## Claim boundary",
            "",
            "An ACCEPT attestation establishes only the named reviewed package evidence. Canonical package status remains IN_PROGRESS until dependency closure and status-promotion rules pass.",
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
        except ValueError as error:
            errors.append(str(error))
        else:
            if baseline is None:
                base_state = "BOOTSTRAP NOT VERIFIED"
            else:
                errors.extend(validate_against_base(documents, baseline))
                base_state = "VERIFIED"
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
