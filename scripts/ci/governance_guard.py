"""Validate deterministic cross-document governance traceability."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from scripts.ci import threat_catalog_guard as threat_guard

ROOT = Path(__file__).parents[2]
MANIFEST_PATH = ROOT / "governance/traceability.v1.json"
SCHEMA_PATH = ROOT / "governance/traceability.schema.json"
REPORT_PATH = ROOT / "docs/v1/TRACEABILITY_REPORT.md"
SCHEMA_HASH = "1bd836beb1d9fbe90116dfd68ffd219ef77fef5bb28a997df0d6ee331257a453"
MANIFEST_KEYS = {"schema_version", "manifest_version", "records"}
RECORD_KEYS = {
    "id",
    "target",
    "state",
    "requirements",
    "adrs",
    "threats",
    "verification_tests",
    "evidence",
    "review",
}
STATES = {"CATALOGUED", "IMPLEMENTED", "INDEPENDENTLY_ACCEPTED", "MILESTONE_VERIFIED"}
TRC_ID = re.compile(r"^TRC-[A-Z0-9]+(?:-[A-Z0-9]+)*$")
REVIEW_REF = re.compile(r"^(docs/v1/reviews/[^#]+\.md)#review:(?P<target>[A-Z0-9-]+)$")


def _load(path: Path) -> dict[str, Any]:
    return threat_guard._load_json(path)


def parse_requirements(root: Path) -> set[str]:
    text = (root / "docs/02-requirements.md").read_text(encoding="utf-8")
    return set(re.findall(r"^- \*\*([A-Z][A-Z0-9-]+)\*\*", text, re.MULTILINE))


def parse_work_packages(root: Path) -> tuple[dict[str, set[str]], list[str]]:
    text = (root / "docs/v1/WORK_PACKAGES.md").read_text(encoding="utf-8")
    rows: dict[str, set[str]] = {}
    errors: list[str] = []
    for line in text.splitlines():
        if not re.match(r"^\| [A-Z]", line):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 6 or cells[0] == "ID":
            continue
        package_id, dependency_cell = cells[0], cells[3]
        if package_id in rows:
            errors.append(f"duplicate work-package ID {package_id}")
            continue
        rows[package_id] = (
            set()
            if dependency_cell == "—"
            else {value.strip() for value in dependency_cell.split(",") if value.strip()}
        )
    for package_id, dependencies in rows.items():
        for dependency in sorted(dependencies - set(rows)):
            errors.append(f"{package_id}: unknown dependency {dependency}")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str, path: tuple[str, ...]) -> None:
        if node in visiting:
            errors.append(f"work-package dependency cycle: {' -> '.join((*path, node))}")
            return
        if node in visited:
            return
        visiting.add(node)
        for dependency in sorted(rows.get(node, set())):
            visit(dependency, (*path, node))
        visiting.remove(node)
        visited.add(node)

    for package_id in sorted(rows):
        visit(package_id, ())
    return rows, sorted(set(errors))


def parse_adrs(root: Path) -> tuple[dict[str, str], list[str]]:
    errors: list[str] = []
    adrs: dict[str, str] = {}
    for path in sorted((root / "docs/adr").glob("[0-9][0-9][0-9][0-9]-*.md")):
        text = path.read_text(encoding="utf-8")
        title = re.search(r"^# ADR-(\d{4}):", text, re.MULTILINE)
        status = re.search(r"^- Status: (.+)$", text, re.MULTILINE)
        if title is None or status is None or title.group(1) != path.name[:4]:
            errors.append(f"malformed ADR file {path.relative_to(root)}")
            continue
        adr_id = f"ADR-{title.group(1)}"
        if adr_id in adrs:
            errors.append(f"duplicate ADR ID {adr_id}")
        adrs[adr_id] = status.group(1)
    index = (root / "docs/adr/README.md").read_text(encoding="utf-8")
    indexed = set(re.findall(r"^\| \[(\d{4})\]", index, re.MULTILINE))
    if indexed != {adr.removeprefix("ADR-") for adr in adrs}:
        errors.append("ADR index and canonical files do not match bidirectionally")
    return adrs, sorted(set(errors))


def parse_completion(root: Path) -> dict[str, tuple[str, str]]:
    text = (root / "docs/v1/COMPLETION_MATRIX.md").read_text(encoding="utf-8")
    results: dict[str, tuple[str, str]] = {}
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 5:
            continue
        package = cells[1]
        status = cells[2].strip("`")
        if re.fullmatch(r"[A-Z][A-Z0-9-]+", package) and status in {
            "NOT_STARTED",
            "IN_PROGRESS",
            "BLOCKED",
            "COMPLETE",
            "VERIFIED",
        }:
            results[package] = (status, cells[3])
    return results


def _assertive_node(root: Path, reference: str) -> bool:
    if reference.count("::") != 1:
        return False
    path_text, function = reference.split("::")
    path = threat_guard._canonical_repo_file(root, path_text)
    if (
        path is None
        or not (path_text.startswith("tests/") or "/tests/" in path_text)
        or not re.fullmatch(r"test_[a-z0-9_]+", function)
    ):
        return False
    module = ast.parse(path.read_text(encoding="utf-8"))
    node = next(
        (
            item
            for item in module.body
            if isinstance(item, ast.FunctionDef) and item.name == function
        ),
        None,
    )
    if node is None:
        return False
    decorators = {ast.unparse(item) for item in node.decorator_list}
    if any(value.startswith(("pytest.mark.skip", "pytest.mark.xfail")) for value in decorators):
        return False
    return any(isinstance(item, ast.Assert) for item in ast.walk(node))


def _review_accepted(root: Path, reference: str, target: str) -> bool:
    match = REVIEW_REF.fullmatch(reference)
    if match is None or match.group("target") != target:
        return False
    path = threat_guard._canonical_repo_file(root, match.group(1))
    if path is None:
        return False
    text = path.read_text(encoding="utf-8")
    if path.name == "06-foundation-acceptance-index.md":
        section = re.search(
            rf"^## {re.escape(target)}$(.*?)(?=^## |\Z)", text, re.MULTILINE | re.DOTALL
        )
        return section is not None and "Disposition: ACCEPT" in section.group(1)
    return f"Package: {target}" in text and re.search(r"`?ACCEPT`?", text) is not None


def _execute_node(root: Path, reference: str) -> bool:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--runxfail", "-rA", "-q", reference],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return (
        result.returncode == 0
        and re.search(rf"^PASSED {re.escape(reference)}$", result.stdout, re.MULTILINE) is not None
    )


def validate_manifest(
    manifest: Mapping[str, Any], root: Path, *, execute: bool = False
) -> tuple[list[str], dict[str, int]]:
    errors: list[str] = []
    requirements = parse_requirements(root)
    packages, package_errors = parse_work_packages(root)
    adrs, adr_errors = parse_adrs(root)
    completion = parse_completion(root)
    threat_catalog = _load(root / "security/threat-catalog.v1.json")
    test_registry = _load(root / "security/verification-tests.v1.json")
    threats = {item["id"]: item for item in threat_catalog["threats"]}
    vfys = {item["id"]: item for item in test_registry["tests"]}
    errors.extend(package_errors)
    errors.extend(adr_errors)
    if set(manifest) != MANIFEST_KEYS or manifest.get("schema_version") != 1:
        errors.append("manifest top-level shape/version is not exact v1")
    records = manifest.get("records")
    if not isinstance(records, list):
        return sorted({*errors, "manifest records must be an array"}), {}
    ids = [item.get("id") for item in records if isinstance(item, dict)]
    targets = [item.get("target") for item in records if isinstance(item, dict)]
    if ids != sorted(ids, key=str):
        errors.append("traceability records must be sorted by ID")
    for value in sorted({item for item in ids if isinstance(item, str) and ids.count(item) > 1}):
        errors.append(f"duplicate traceability ID {value}")
    for value in sorted(
        {item for item in targets if isinstance(item, str) and targets.count(item) > 1}
    ):
        errors.append(f"duplicate traceability target {value}")
    records_by_target: dict[str, Mapping[str, Any]] = {}
    for index, record in enumerate(records):
        label = f"records[{index}]"
        if not isinstance(record, dict):
            errors.append(f"{label}: record must be an object")
            continue
        record_id, target = record.get("id"), record.get("target")
        label = str(record_id)
        if set(record) != RECORD_KEYS:
            errors.append(f"{label}: record fields are not exact v1")
        if not isinstance(record_id, str) or TRC_ID.fullmatch(record_id) is None:
            errors.append(f"{label}: noncanonical traceability ID")
        if target not in packages:
            errors.append(f"{label}: unknown work-package target {target}")
        elif isinstance(target, str):
            records_by_target[target] = record
        if record.get("state") not in STATES:
            errors.append(f"{label}: unknown traceability state")
        for field, known in (
            ("requirements", requirements),
            ("adrs", set(adrs)),
            ("threats", set(threats)),
            ("verification_tests", set(vfys)),
        ):
            values = record.get(field)
            if not isinstance(values, list) or values != sorted(set(values)):
                errors.append(f"{label}: {field} must be a sorted unique array")
                continue
            for value in values:
                if value not in known:
                    errors.append(f"{label}: unknown {field} reference {value}")
        linked_threats = set(record.get("threats", []))
        for vfy_id in record.get("verification_tests", []):
            if vfy_id in vfys:
                expected = set(vfys[vfy_id]["threats"])
                if not expected <= linked_threats:
                    errors.append(f"{label}: VFY/threat reference is not bidirectional")
                if vfys[vfy_id]["status"] != "IMPLEMENTED":
                    errors.append(f"{label}: planned verification cannot count as tested coverage")
        evidence = record.get("evidence")
        reference = evidence.get("ref") if isinstance(evidence, dict) else None
        if (
            not isinstance(evidence, dict)
            or set(evidence) != {"type", "ref"}
            or evidence.get("type") != "PYTEST_NODE"
            or not isinstance(reference, str)
            or not _assertive_node(root, reference)
        ):
            errors.append(f"{label}: evidence must be an exact assertion-bearing pytest node")
        accepted = record.get("state") in {"INDEPENDENTLY_ACCEPTED", "MILESTONE_VERIFIED"}
        if accepted and (
            not isinstance(target, str)
            or not _review_accepted(root, str(record.get("review")), target)
        ):
            errors.append(f"{label}: accepted state lacks a real ACCEPT review record")
        if (
            accepted
            and execute
            and isinstance(reference, str)
            and not _execute_node(root, reference)
        ):
            errors.append(f"{label}: accepted executable evidence did not PASS")
        if record.get("state") == "MILESTONE_VERIFIED" and (
            not isinstance(target, str) or completion.get(target, (None, None))[0] != "VERIFIED"
        ):
            errors.append(f"{label}: milestone verification lacks a VERIFIED matrix claim")
    for package, (status, evidence_cell) in completion.items():
        if status in {"COMPLETE", "VERIFIED"}:
            record = records_by_target.get(package)
            if record is None or record.get("state") not in {
                "INDEPENDENTLY_ACCEPTED",
                "MILESTONE_VERIFIED",
            }:
                errors.append(
                    f"{package}: completion claim lacks independently accepted traceability"
                )
            if evidence_cell == "—":
                errors.append(f"{package}: completion claim has no matrix evidence")
        if status == "VERIFIED" and (
            records_by_target.get(package, {}).get("state") != "MILESTONE_VERIFIED"
        ):
            errors.append(f"{package}: VERIFIED claim lacks milestone verification")
    counts = {
        "requirements": len(requirements),
        "packages": len(packages),
        "adrs": len(adrs),
        "threats": len(threats),
        "vfys": len(vfys),
        "records": len(records),
        "catalogued": sum(
            record.get("state") == "CATALOGUED" for record in records if isinstance(record, dict)
        ),
        "implemented": sum(
            record.get("state") == "IMPLEMENTED" for record in records if isinstance(record, dict)
        ),
        "accepted": sum(
            record.get("state") == "INDEPENDENTLY_ACCEPTED"
            for record in records
            if isinstance(record, dict)
        ),
        "verified": sum(
            record.get("state") == "MILESTONE_VERIFIED"
            for record in records
            if isinstance(record, dict)
        ),
        "planned_threats": sum(item["status"] == "CONTROL_PLANNED" for item in threats.values()),
        "mapped_requirements": len(
            {
                requirement
                for record in records
                if isinstance(record, dict)
                for requirement in record.get("requirements", [])
            }
        ),
        "mapped_adrs": len(
            {
                adr
                for record in records
                if isinstance(record, dict)
                for adr in record.get("adrs", [])
            }
        ),
    }
    return sorted(set(errors)), counts


def validate_schema(manifest: Mapping[str, Any], schema: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if threat_guard._canonical_json_hash(schema) != SCHEMA_HASH:
        errors.append("traceability schema hash mismatch")
    errors.extend(threat_guard._schema_errors(manifest, schema, schema))
    return errors


def render_report(counts: Mapping[str, int]) -> str:
    return "\n".join(
        [
            "# Governance traceability coverage",
            "",
            "Generated deterministically from canonical requirements, work packages, ADRs, the selected threat catalog, the traceability manifest and the completion matrix.",
            "",
            "| Canonical inventory | Count |",
            "| --- | ---: |",
            f"| Requirements | {counts['requirements']} |",
            f"| Work packages | {counts['packages']} |",
            f"| ADRs | {counts['adrs']} |",
            f"| Selected threats | {counts['threats']} |",
            f"| Verification IDs | {counts['vfys']} |",
            f"| Traceability records | {counts['records']} |",
            f"| Requirements mapped by current records | {counts['mapped_requirements']} |",
            f"| ADRs mapped by current records | {counts['mapped_adrs']} |",
            "",
            "| Evidence state | Records |",
            "| --- | ---: |",
            f"| Catalogued only | {counts['catalogued']} |",
            f"| Implemented | {counts['implemented']} |",
            f"| Independently accepted | {counts['accepted']} |",
            f"| Milestone verified | {counts['verified']} |",
            "",
            "## Coverage boundary",
            "",
            f"The selected threat catalog still has {counts['planned_threats']} planned controls. They are catalogued risks, not tested coverage.",
            "A passing package test and ACCEPT review support only the named package. They do not verify a milestone, prove every requirement, or turn documentation into implementation.",
            "Unmapped canonical inventory remains visible in the counts above; this first manifest normalizes current COMPLETE package claims and is not 100% requirement coverage.",
            "",
        ]
    )


def validate_report(text: str, counts: Mapping[str, int]) -> list[str]:
    return [] if text == render_report(counts) else ["Governance coverage report is stale"]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    try:
        manifest, schema = _load(MANIFEST_PATH), _load(SCHEMA_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Governance guard could not load inputs: {error}")
        return 1
    errors, counts = validate_manifest(manifest, ROOT, execute=True)
    errors.extend(validate_schema(manifest, schema))
    if errors:
        print("\n".join(sorted(set(errors))))
        return 1
    report = render_report(counts)
    if args.write_report:
        REPORT_PATH.write_text(report, encoding="utf-8")
    elif not REPORT_PATH.is_file() or validate_report(
        REPORT_PATH.read_text(encoding="utf-8"), counts
    ):
        print("Governance coverage report is stale; run with --write-report")
        return 1
    print(f"Governance traceability guard passed ({counts['records']} accepted records).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
