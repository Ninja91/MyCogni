"""Validate the immutable threat and verification-test catalogs."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).parents[2]
CATALOG_PATH = REPOSITORY_ROOT / "security" / "threat-catalog.v1.json"
REGISTRY_PATH = REPOSITORY_ROOT / "security" / "verification-tests.v1.json"
SCHEMA_PATH = REPOSITORY_ROOT / "security" / "threat-catalog.schema.json"
REPORT_PATH = REPOSITORY_ROOT / "docs" / "v1" / "THREAT_CATALOG_REPORT.md"

THREAT_ID = re.compile(r"^THR-[A-Z0-9]+-[0-9]{3}$")
TEST_ID = re.compile(r"^VFY-[A-Z0-9]+-[0-9]{3}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SOURCE_ANCHOR = re.compile(
    r"^(?P<path>[^#]+)#(?P<kind>threat|requirement|work-package|heading):(?P<value>[^#]+)$"
)

SEVERITIES = {"P0", "P1", "P2", "P3"}
BOUNDARIES = {
    "CONTROL_PLANE",
    "TRUSTED_CORE",
    "VAULT",
    "CONNECTOR_RUNTIME",
    "EGRESS_GATEWAY",
    "EXTERNAL_CONTENT",
    "LOCAL_INTELLIGENCE",
    "INTEGRATIONS_DIAGNOSTICS",
}
OWNERS = {"CORE", "BOUNDARY", "INTERFACE", "CROSS_CUTTING"}
MILESTONES = {f"M{number}" for number in range(7)}
THREAT_STATUSES = {"CATALOGED", "CONTROL_PLANNED", "CONTROL_TESTED", "DEPRECATED"}
TEST_STATUSES = {"PLANNED", "IMPLEMENTED", "DEPRECATED"}
THREAT_KEYS = {
    "id",
    "title",
    "severity",
    "assets",
    "boundary",
    "failure_story",
    "mitigations",
    "requirements",
    "work_packages",
    "verification_tests",
    "evidence",
    "sources",
    "owner",
    "milestone",
    "status",
}
TEST_KEYS = {"id", "implementation", "status", "threats"}


def _duplicates(values: Sequence[str]) -> list[str]:
    return sorted({value for value in values if values.count(value) > 1})


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def _is_sorted_unique(values: Sequence[str]) -> bool:
    return list(values) == sorted(set(values))


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"JSON document must be an object: {path.name}")
    return loaded


def _known_requirement_ids(root: Path) -> set[str]:
    text = (root / "docs" / "02-requirements.md").read_text(encoding="utf-8")
    return set(re.findall(r"^- \*\*([A-Z][A-Z0-9-]+)\*\*", text, flags=re.MULTILINE))


def _known_work_package_ids(root: Path) -> set[str]:
    text = (root / "docs" / "v1" / "WORK_PACKAGES.md").read_text(encoding="utf-8")
    return set(re.findall(r"^\| ([A-Z][A-Z0-9-]+) \|", text, flags=re.MULTILINE))


def _source_anchor_exists(root: Path, source: str) -> bool:
    match = SOURCE_ANCHOR.fullmatch(source)
    if match is None:
        return False
    path = root / match.group("path")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        return False
    text = path.read_text(encoding="utf-8")
    kind = match.group("kind")
    value = match.group("value")
    if kind == "requirement":
        return re.search(rf"^- \*\*{re.escape(value)}\*\*", text, flags=re.MULTILINE) is not None
    if kind == "work-package":
        return re.search(rf"^\| {re.escape(value)} \|", text, flags=re.MULTILINE) is not None
    if kind == "heading":
        return any(
            _slug(heading) == value
            for heading in re.findall(r"^#{1,6} (.+)$", text, flags=re.MULTILINE)
        )
    threat_names = re.findall(r"^\| ([^|]+?) \| [^|]+ \| [^|]+ \|$", text, flags=re.MULTILINE)
    return any(_slug(name.strip()) == value for name in threat_names if name.strip() != "Threat")


def validate_catalog(
    catalog: Mapping[str, Any], registry: Mapping[str, Any], root: Path
) -> list[str]:
    """Return deterministic validation failures without mutating either document."""
    errors: list[str] = []
    if catalog.get("schema_version") != 1:
        errors.append("catalog: unknown schema_version (expected 1)")
    if not isinstance(catalog.get("catalog_version"), str) or not SEMVER.fullmatch(
        catalog["catalog_version"]
    ):
        errors.append("catalog: catalog_version must be semantic x.y.z")
    if registry.get("schema_version") != 1:
        errors.append("registry: unknown schema_version (expected 1)")
    if not isinstance(registry.get("registry_version"), str) or not SEMVER.fullmatch(
        registry["registry_version"]
    ):
        errors.append("registry: registry_version must be semantic x.y.z")

    threats = catalog.get("threats")
    tests = registry.get("tests")
    if not isinstance(threats, list):
        return [*errors, "catalog: threats must be an array"]
    if not isinstance(tests, list):
        return [*errors, "registry: tests must be an array"]

    threat_ids = [item.get("id") for item in threats if isinstance(item, dict)]
    test_ids = [item.get("id") for item in tests if isinstance(item, dict)]
    string_threat_ids = [value for value in threat_ids if isinstance(value, str)]
    string_test_ids = [value for value in test_ids if isinstance(value, str)]
    for duplicate in _duplicates(string_threat_ids):
        errors.append(f"catalog: duplicate threat ID {duplicate}")
    for duplicate in _duplicates(string_test_ids):
        errors.append(f"registry: duplicate verification test ID {duplicate}")
    if threat_ids != sorted(threat_ids, key=lambda value: str(value)):
        errors.append("catalog: threats must be sorted by canonical ID")
    if test_ids != sorted(test_ids, key=lambda value: str(value)):
        errors.append("registry: tests must be sorted by canonical ID")

    known_requirements = _known_requirement_ids(root)
    known_packages = _known_work_package_ids(root)
    known_threats = set(string_threat_ids)
    known_tests = set(string_test_ids)

    for index, threat in enumerate(threats):
        label = f"catalog.threats[{index}]"
        if not isinstance(threat, dict):
            errors.append(f"{label}: entry must be an object")
            continue
        threat_id = threat.get("id")
        label = str(threat_id) if isinstance(threat_id, str) else label
        if set(threat) != THREAT_KEYS:
            errors.append(f"{label}: fields must exactly match schema v1")
        if not isinstance(threat_id, str) or not THREAT_ID.fullmatch(threat_id):
            errors.append(f"{label}: noncanonical threat ID")
        for field, allowed in (
            ("severity", SEVERITIES),
            ("boundary", BOUNDARIES),
            ("owner", OWNERS),
            ("milestone", MILESTONES),
            ("status", THREAT_STATUSES),
        ):
            if threat.get(field) not in allowed:
                errors.append(f"{label}: unknown {field} {threat.get(field)!r}")
        for field in ("title", "failure_story"):
            if not isinstance(threat.get(field), str) or not threat[field].strip():
                errors.append(f"{label}: {field} must be nonempty text")
        for field in (
            "assets",
            "mitigations",
            "requirements",
            "work_packages",
            "verification_tests",
            "evidence",
            "sources",
        ):
            values = threat.get(field)
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(value, str) and value for value in values)
            ):
                errors.append(f"{label}: {field} must be a nonempty string array")
            elif len(values) != len(set(values)):
                errors.append(f"{label}: {field} must have no duplicates")
            elif field in {
                "requirements",
                "work_packages",
                "verification_tests",
                "evidence",
                "sources",
            } and not _is_sorted_unique(values):
                errors.append(f"{label}: {field} must be sorted with no duplicates")
        requirements = threat.get("requirements")
        for requirement in requirements if isinstance(requirements, list) else []:
            if isinstance(requirement, str) and requirement not in known_requirements:
                errors.append(f"{label}: unknown requirement ID {requirement}")
        work_packages = threat.get("work_packages")
        for package in work_packages if isinstance(work_packages, list) else []:
            if isinstance(package, str) and package not in known_packages:
                errors.append(f"{label}: unknown work-package ID {package}")
        verification_tests = threat.get("verification_tests")
        for test_id in verification_tests if isinstance(verification_tests, list) else []:
            if isinstance(test_id, str) and test_id not in known_tests:
                errors.append(f"{label}: unknown verification test ID {test_id}")
        evidence_items = threat.get("evidence")
        for evidence in evidence_items if isinstance(evidence_items, list) else []:
            if isinstance(evidence, str):
                evidence_path = root / evidence
                if (
                    evidence.startswith("/")
                    or not evidence_path.is_file()
                    or not evidence_path.resolve().is_relative_to(root.resolve())
                ):
                    errors.append(f"{label}: broken evidence path {evidence}")
        sources = threat.get("sources")
        for source in sources if isinstance(sources, list) else []:
            if isinstance(source, str) and not _source_anchor_exists(root, source):
                errors.append(f"{label}: broken source anchor {source}")

    reverse_edges: set[tuple[str, str]] = set()
    for index, test in enumerate(tests):
        label = f"registry.tests[{index}]"
        if not isinstance(test, dict):
            errors.append(f"{label}: entry must be an object")
            continue
        test_id = test.get("id")
        label = str(test_id) if isinstance(test_id, str) else label
        if set(test) != TEST_KEYS:
            errors.append(f"{label}: fields must exactly match registry schema v1")
        if not isinstance(test_id, str) or not TEST_ID.fullmatch(test_id):
            errors.append(f"{label}: noncanonical verification test ID")
        if test.get("status") not in TEST_STATUSES:
            errors.append(f"{label}: unknown status {test.get('status')!r}")
        implementation = test.get("implementation")
        if implementation is not None and (
            not isinstance(implementation, str)
            or implementation.startswith("/")
            or not (root / implementation).is_file()
            or not (root / implementation).resolve().is_relative_to(root.resolve())
        ):
            errors.append(f"{label}: broken implementation path {implementation}")
        if test.get("status") == "IMPLEMENTED" and implementation is None:
            errors.append(f"{label}: IMPLEMENTED test requires an implementation path")
        linked_threats = test.get("threats")
        if (
            not isinstance(linked_threats, list)
            or not linked_threats
            or not all(isinstance(value, str) for value in linked_threats)
        ):
            errors.append(f"{label}: threats must be a nonempty string array")
            continue
        if not _is_sorted_unique(linked_threats):
            errors.append(f"{label}: threats must be sorted with no duplicates")
        for linked_threat in linked_threats:
            if linked_threat not in known_threats:
                errors.append(f"{label}: unknown threat ID {linked_threat}")
            if isinstance(test_id, str):
                reverse_edges.add((linked_threat, test_id))

    forward_edges = {
        (threat["id"], test_id)
        for threat in threats
        if isinstance(threat, dict) and isinstance(threat.get("id"), str)
        for test_id in (
            threat.get("verification_tests", [])
            if isinstance(threat.get("verification_tests"), list)
            else []
        )
        if isinstance(test_id, str)
    }
    for edge in sorted(forward_edges - reverse_edges):
        errors.append(f"catalog: missing registry back-reference {edge[1]} -> {edge[0]}")
    for edge in sorted(reverse_edges - forward_edges):
        errors.append(f"registry: missing catalog back-reference {edge[0]} -> {edge[1]}")
    tests_by_id = {
        test["id"]: test
        for test in tests
        if isinstance(test, dict) and isinstance(test.get("id"), str)
    }
    for threat in threats:
        if not isinstance(threat, dict) or threat.get("status") != "CONTROL_TESTED":
            continue
        linked_tests = [
            tests_by_id.get(test_id)
            for test_id in (
                threat.get("verification_tests", [])
                if isinstance(threat.get("verification_tests"), list)
                else []
            )
            if isinstance(test_id, str)
        ]
        if not any(
            test is not None and test.get("status") == "IMPLEMENTED" for test in linked_tests
        ):
            errors.append(
                f"{threat.get('id', 'catalog threat')}: CONTROL_TESTED requires an IMPLEMENTED test"
            )
    return sorted(set(errors))


def render_report(catalog: Mapping[str, Any], registry: Mapping[str, Any]) -> str:
    """Render stable Markdown without machine-specific or clock-derived data."""
    tests = {item["id"]: item for item in registry["tests"]}
    rows = [
        "# Threat catalog report",
        "",
        "Generated from `security/threat-catalog.v1.json` and "
        "`security/verification-tests.v1.json`. Do not edit this report by hand.",
        "",
        f"Catalog version: `{catalog['catalog_version']}`. Schema version: "
        f"`{catalog['schema_version']}`.",
        "",
        "| Threat | Severity | Boundary | Owner | Milestone | Control status | Verification |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for threat in catalog["threats"]:
        verification = ", ".join(
            f"`{test_id}` ({tests[test_id]['status']})" for test_id in threat["verification_tests"]
        )
        rows.append(
            f"| `{threat['id']}` {threat['title']} | {threat['severity']} | "
            f"{threat['boundary']} | {threat['owner']} | {threat['milestone']} | "
            f"{threat['status']} | {verification} |"
        )
    planned = sum(test["status"] == "PLANNED" for test in registry["tests"])
    implemented = sum(test["status"] == "IMPLEMENTED" for test in registry["tests"])
    rows.extend(
        [
            "",
            "## Coverage boundary",
            "",
            f"This catalog contains {len(catalog['threats'])} selected high-risk threat groups, "
            f"{implemented} implemented catalog test mapping, and {planned} planned product test mappings.",
            "It is not a claim that all threats, requirements, controls, or release gates are covered. "
            "`CONTROL_PLANNED` and `PLANNED` are explicitly not implementation evidence.",
            "Full requirement/work-package/ADR coverage remains the scope of `GOV-001`.",
            "",
        ]
    )
    return "\n".join(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    try:
        catalog = _load_json(CATALOG_PATH)
        registry = _load_json(REGISTRY_PATH)
        _load_json(SCHEMA_PATH)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Threat catalog guard could not load inputs: {error}")
        return 1
    errors = validate_catalog(catalog, registry, REPOSITORY_ROOT)
    if errors:
        print("\n".join(errors))
        return 1
    expected_report = render_report(catalog, registry)
    if args.write_report:
        REPORT_PATH.write_text(expected_report, encoding="utf-8")
    elif not REPORT_PATH.is_file() or REPORT_PATH.read_text(encoding="utf-8") != expected_report:
        print("Threat catalog report drifted; run guard with --write-report")
        return 1
    print(
        f"Threat catalog guard passed ({len(catalog['threats'])} threats, "
        f"{len(registry['tests'])} verification IDs)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
