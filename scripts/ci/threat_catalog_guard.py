"""Validate immutable threat identities, typed evidence, and deterministic reporting."""

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
from pathlib import Path, PurePosixPath
from typing import Any

REPOSITORY_ROOT = Path(__file__).parents[2]
CATALOG_PATH = REPOSITORY_ROOT / "security" / "threat-catalog.v1.json"
REGISTRY_PATH = REPOSITORY_ROOT / "security" / "verification-tests.v1.json"
HISTORY_PATH = REPOSITORY_ROOT / "security" / "id-history.v1.json"
SCHEMA_PATH = REPOSITORY_ROOT / "security" / "threat-catalog.schema.json"
REGISTRY_SCHEMA_PATH = REPOSITORY_ROOT / "security" / "verification-tests.schema.json"
HISTORY_SCHEMA_PATH = REPOSITORY_ROOT / "security" / "id-history.schema.json"
REPORT_PATH = REPOSITORY_ROOT / "docs" / "v1" / "THREAT_CATALOG_REPORT.md"

THREAT_ID = re.compile(r"^THR-[A-Z0-9]+-[0-9]{3}$")
TEST_ID = re.compile(r"^VFY-[A-Z0-9]+-[0-9]{3}$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SOURCE_ANCHOR = re.compile(
    r"^(?P<path>[^#]+)#(?P<kind>threat|requirement|work-package):(?P<value>[^#]+)$"
)
SOURCE_FILES = {
    "threat": "docs/05-security-privacy-threat-model.md",
    "requirement": "docs/02-requirements.md",
    "work-package": "docs/v1/WORK_PACKAGES.md",
}

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
EVIDENCE_TYPES = {"PYTEST_NODE", "SOURCE_DOCUMENT"}
EXECUTABLE_EVIDENCE_TYPES = {"PYTEST_NODE"}
CATALOG_KEYS = {"schema_version", "catalog_version", "threats"}
REGISTRY_KEYS = {"schema_version", "registry_version", "tests"}
HISTORY_KEYS = {"schema_version", "history_version", "allocations"}
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
TEST_KEYS = {"id", "purpose", "implementation", "status", "threats"}
ALLOCATION_KEYS = {"id", "kind", "identity", "state", "introduced_in"}
EVIDENCE_KEYS = {"type", "ref"}
SCHEMA_HASHES = {
    "threat-catalog.schema.json": "7290e715730f1750a85fdc68f0ca15aa4b819e5c2c467b475651ac22d182471c",
    "verification-tests.schema.json": "48ba84af58b20bd3a4fc5d9de8e7fd4594fedaee24728386f4d41723a164059e",
    "id-history.schema.json": "102a864b58a6e3feae92b8fa0f193cf9449737bc07ea2ff7786ef0449c6010cd",
}


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _load_json(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(loaded, dict):
        raise ValueError(f"JSON document must be an object: {path.name}")
    return loaded


def _load_json_text(text: str, label: str) -> dict[str, Any]:
    loaded = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(loaded, dict):
        raise ValueError(f"JSON document must be an object: {label}")
    return loaded


def _canonical_json_hash(document: Mapping[str, Any]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _json_type_matches(instance: Any, expected: str) -> bool:
    return {
        "object": isinstance(instance, dict),
        "array": isinstance(instance, list),
        "string": isinstance(instance, str),
        "integer": isinstance(instance, int) and not isinstance(instance, bool),
        "null": instance is None,
    }.get(expected, False)


def _resolve_local_ref(root_schema: Mapping[str, Any], reference: str) -> Mapping[str, Any] | None:
    if not reference.startswith("#/"):
        return None
    current: Any = root_schema
    for token in reference[2:].split("/"):
        if not isinstance(current, dict) or token not in current:
            return None
        current = current[token]
    return current if isinstance(current, dict) else None


def _schema_errors(
    instance: Any,
    schema: Mapping[str, Any],
    root_schema: Mapping[str, Any],
    path: str = "$",
) -> list[str]:
    """Evaluate the reviewed offline JSON-Schema keyword subset used by v1 schemas."""
    if "$ref" in schema:
        resolved = _resolve_local_ref(root_schema, str(schema["$ref"]))
        if resolved is None:
            return [f"{path}: unresolved schema reference {schema['$ref']}"]
        return _schema_errors(instance, resolved, root_schema, path)
    if "oneOf" in schema:
        variants = schema["oneOf"]
        if not isinstance(variants, list):
            return [f"{path}: malformed oneOf schema"]
        matches = sum(not _schema_errors(instance, item, root_schema, path) for item in variants)
        return (
            [] if matches == 1 else [f"{path}: expected exactly one schema variant, got {matches}"]
        )
    errors: list[str] = []
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: value does not match schema const")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value is not in schema enum")
    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _json_type_matches(instance, expected_type):
        return [*errors, f"{path}: expected schema type {expected_type}"]
    if isinstance(instance, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            for key in required:
                if key not in instance:
                    errors.append(f"{path}: missing schema-required key {key}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and isinstance(properties, dict):
            for key in sorted(set(instance) - set(properties)):
                errors.append(f"{path}: schema rejects additional key {key}")
        if isinstance(properties, dict):
            for key, value in instance.items():
                child_schema = properties.get(key)
                if isinstance(child_schema, dict):
                    errors.extend(_schema_errors(value, child_schema, root_schema, f"{path}.{key}"))
    if isinstance(instance, list):
        minimum = schema.get("minItems")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{path}: fewer than schema minItems")
        if schema.get("uniqueItems") is True:
            serialized = [
                json.dumps(value, sort_keys=True, separators=(",", ":")) for value in instance
            ]
            if len(serialized) != len(set(serialized)):
                errors.append(f"{path}: schema uniqueItems violated")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, value in enumerate(instance):
                errors.extend(_schema_errors(value, item_schema, root_schema, f"{path}[{index}]"))
    if isinstance(instance, str):
        minimum = schema.get("minLength")
        maximum = schema.get("maxLength")
        if isinstance(minimum, int) and len(instance) < minimum:
            errors.append(f"{path}: shorter than schema minLength")
        if isinstance(maximum, int) and len(instance) > maximum:
            errors.append(f"{path}: longer than schema maxLength")
        pattern = schema.get("pattern")
        if isinstance(pattern, str) and re.fullmatch(pattern, instance) is None:
            errors.append(f"{path}: does not match schema pattern")
    return errors


def validate_published_schema(
    document: Mapping[str, Any], schema: Mapping[str, Any], schema_name: str
) -> list[str]:
    errors: list[str] = []
    expected_hash = SCHEMA_HASHES.get(schema_name)
    actual_hash = _canonical_json_hash(schema)
    if expected_hash != actual_hash:
        errors.append(f"{schema_name}: published schema hash mismatch")
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        errors.append(f"{schema_name}: unsupported or missing meta-schema declaration")
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        errors.append(f"{schema_name}: root must be an exact object schema")
    errors.extend(f"{schema_name} {error}" for error in _schema_errors(document, schema, schema))
    return errors


def _duplicates(values: Sequence[str]) -> list[str]:
    return sorted({value for value in values if values.count(value) > 1})


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.casefold()).strip("-")


def _is_sorted_unique(values: Sequence[str]) -> bool:
    return list(values) == sorted(set(values))


def _safe_text(value: Any, *, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value.strip())
        and value == value.strip()
        and len(value) <= maximum
        and not any(character in value for character in "\r\n\x00")
        and not any(ord(character) < 32 for character in value)
    )


def _markdown_cell(value: str) -> str:
    return value.replace("\\", "\\\\").replace("`", "\\`").replace("|", "\\|")


def _canonical_repo_file(root: Path, reference: str) -> Path | None:
    if not reference or "\\" in reference:
        return None
    pure = PurePosixPath(reference)
    if (
        pure.is_absolute()
        or str(pure) != reference
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        return None
    candidate = root.joinpath(*pure.parts)
    current = root
    for part in pure.parts:
        current /= part
        if current.is_symlink():
            return None
    if not candidate.is_file() or not candidate.resolve().is_relative_to(root.resolve()):
        return None
    return candidate


def _pytest_node_exists(root: Path, reference: str) -> bool:
    if reference.count("::") != 1:
        return False
    path_text, function_name = reference.split("::")
    if not re.fullmatch(r"test_[a-z0-9_]+", function_name):
        return False
    path = _canonical_repo_file(root, path_text)
    if path is None or path.suffix != ".py" or not path_text.startswith("tests/"):
        return False
    try:
        module = ast.parse(path.read_text(encoding="utf-8"), filename=path_text)
    except (OSError, SyntaxError, UnicodeError):
        return False
    function = next(
        (
            node
            for node in module.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ),
        None,
    )
    if function is None:
        return False
    marker_names = {
        ast.unparse(decorator)
        for decorator in function.decorator_list
        if isinstance(decorator, (ast.Attribute, ast.Call))
    }
    if "pytest.mark.threat_evidence" not in marker_names:
        return False
    if any(marker.startswith(("pytest.mark.skip", "pytest.mark.xfail")) for marker in marker_names):
        return False
    disallowed_calls = {
        ast.unparse(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)
    }
    if disallowed_calls & {"pytest.skip", "pytest.xfail"}:
        return False
    return any(isinstance(node, ast.Assert) for node in ast.walk(function))


def _evidence_valid(root: Path, evidence: Any) -> bool:
    if not isinstance(evidence, dict) or set(evidence) != EVIDENCE_KEYS:
        return False
    evidence_type = evidence.get("type")
    reference = evidence.get("ref")
    if evidence_type not in EVIDENCE_TYPES or not isinstance(reference, str):
        return False
    if evidence_type == "PYTEST_NODE":
        return _pytest_node_exists(root, reference)
    return _canonical_repo_file(root, reference) is not None and reference.startswith("docs/")


def _evidence_key(evidence: Any) -> tuple[str, str]:
    if not isinstance(evidence, dict):
        return (repr(type(evidence)), repr(evidence))
    return (str(evidence.get("type")), str(evidence.get("ref")))


def _known_requirement_ids(root: Path) -> set[str]:
    text = (root / SOURCE_FILES["requirement"]).read_text(encoding="utf-8")
    return set(re.findall(r"^- \*\*([A-Z][A-Z0-9-]+)\*\*", text, flags=re.MULTILINE))


def _known_work_package_ids(root: Path) -> set[str]:
    text = (root / SOURCE_FILES["work-package"]).read_text(encoding="utf-8")
    return set(re.findall(r"^\| ([A-Z][A-Z0-9-]+) \|", text, flags=re.MULTILINE))


def _source_anchor_exists(root: Path, source: str) -> bool:
    match = SOURCE_ANCHOR.fullmatch(source)
    if match is None or match.group("path") != SOURCE_FILES[match.group("kind")]:
        return False
    path = _canonical_repo_file(root, match.group("path"))
    if path is None:
        return False
    text = path.read_text(encoding="utf-8")
    kind = match.group("kind")
    value = match.group("value")
    if kind == "requirement":
        return re.search(rf"^- \*\*{re.escape(value)}\*\*", text, flags=re.MULTILINE) is not None
    if kind == "work-package":
        return re.search(rf"^\| {re.escape(value)} \|", text, flags=re.MULTILINE) is not None
    threat_names = re.findall(r"^\| ([^|]+?) \| [^|]+ \| [^|]+ \|$", text, flags=re.MULTILINE)
    return any(_slug(name.strip()) == value for name in threat_names if name.strip() != "Threat")


def _validate_history(
    catalog: Mapping[str, Any], registry: Mapping[str, Any], history: Mapping[str, Any]
) -> list[str]:
    errors: list[str] = []
    if set(history) != HISTORY_KEYS:
        errors.append("history: top-level fields must exactly match schema v1")
    if history.get("schema_version") != 1:
        errors.append("history: unknown schema_version (expected 1)")
    if not isinstance(history.get("history_version"), str) or not SEMVER.fullmatch(
        history.get("history_version", "")
    ):
        errors.append("history: history_version must be semantic x.y.z")
    allocations = history.get("allocations")
    if not isinstance(allocations, list):
        return [*errors, "history: allocations must be an array"]
    allocation_ids = [item.get("id") for item in allocations if isinstance(item, dict)]
    string_ids = [item for item in allocation_ids if isinstance(item, str)]
    for duplicate in _duplicates(string_ids):
        errors.append(f"history: duplicate allocated ID {duplicate}")
    if allocation_ids != sorted(allocation_ids, key=str):
        errors.append("history: allocations must be sorted by canonical ID")
    history_by_id: dict[str, Mapping[str, Any]] = {}
    identities: list[tuple[str, str]] = []
    for index, allocation in enumerate(allocations):
        label = f"history.allocations[{index}]"
        if not isinstance(allocation, dict):
            errors.append(f"{label}: entry must be an object")
            continue
        if set(allocation) != ALLOCATION_KEYS:
            errors.append(f"{label}: fields must exactly match history schema v1")
        allocation_id = allocation.get("id")
        if not isinstance(allocation_id, str) or not (
            THREAT_ID.fullmatch(allocation_id) or TEST_ID.fullmatch(allocation_id)
        ):
            errors.append(f"{label}: noncanonical allocated ID")
            continue
        history_by_id[allocation_id] = allocation
        expected_kind = "THREAT" if allocation_id.startswith("THR-") else "VERIFICATION_TEST"
        if allocation.get("kind") != expected_kind:
            errors.append(f"{allocation_id}: allocation kind does not match ID namespace")
        if allocation.get("state") not in {"ACTIVE", "RETIRED"}:
            errors.append(f"{allocation_id}: unknown allocation state {allocation.get('state')!r}")
        if not _safe_text(allocation.get("identity"), maximum=120) or not re.fullmatch(
            r"[a-z0-9]+(?:-[a-z0-9]+)*", str(allocation.get("identity"))
        ):
            errors.append(f"{allocation_id}: identity must be a bounded canonical slug")
        elif isinstance(allocation.get("kind"), str):
            identities.append((allocation["kind"], allocation["identity"]))
        if not isinstance(allocation.get("introduced_in"), str) or not SEMVER.fullmatch(
            allocation.get("introduced_in", "")
        ):
            errors.append(f"{allocation_id}: introduced_in must be semantic x.y.z")
    for kind, identity in sorted(set(identities)):
        if identities.count((kind, identity)) > 1:
            errors.append(f"history: duplicate immutable identity {kind}:{identity}")

    catalog_rows = {
        item["id"]: item
        for item in catalog.get("threats", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    test_rows = {
        item["id"]: item
        for item in registry.get("tests", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    rows = {**catalog_rows, **test_rows}
    for allocated_id in sorted(set(rows) - set(history_by_id)):
        errors.append(f"{allocated_id}: ID is not allocated in immutable history")
    for allocated_id in sorted(set(history_by_id) - set(rows)):
        errors.append(f"{allocated_id}: allocated ID row was removed; preserve it as DEPRECATED")
    for allocated_id in sorted(set(rows) & set(history_by_id)):
        row = rows[allocated_id]
        allocation = history_by_id[allocated_id]
        meaning = row.get("title") if allocated_id.startswith("THR-") else row.get("purpose")
        if isinstance(meaning, str) and _slug(meaning) != allocation.get("identity"):
            errors.append(f"{allocated_id}: immutable identity binding changed")
        expected_status = "DEPRECATED" if allocation.get("state") == "RETIRED" else None
        if expected_status is not None and row.get("status") != expected_status:
            errors.append(f"{allocated_id}: retired ID cannot be recycled as an active row")
        if allocation.get("state") == "ACTIVE" and row.get("status") == "DEPRECATED":
            errors.append(f"{allocated_id}: DEPRECATED row must be RETIRED in history")
    return errors


def validate_history_against_baseline(
    current: Mapping[str, Any], baseline: Mapping[str, Any]
) -> list[str]:
    """Enforce monotonic allocation history across a trusted Git revision."""
    errors: list[str] = []
    if set(baseline) != HISTORY_KEYS or baseline.get("schema_version") != 1:
        return ["baseline: trusted ledger does not have the exact v1 document shape"]
    baseline_allocations = baseline.get("allocations")
    if not isinstance(baseline_allocations, list) or any(
        not isinstance(item, dict) or set(item) != ALLOCATION_KEYS for item in baseline_allocations
    ):
        return ["baseline: trusted ledger does not have exact v1 allocation rows"]
    current_rows = {
        item.get("id"): item
        for item in current.get("allocations", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    baseline_rows = {
        item.get("id"): item
        for item in baseline_allocations
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for allocation_id in sorted(set(baseline_rows) - set(current_rows)):
        errors.append(f"baseline: allocated ID disappeared across revisions: {allocation_id}")
    immutable_fields = ("kind", "identity", "introduced_in")
    for allocation_id in sorted(set(baseline_rows) & set(current_rows)):
        before = baseline_rows[allocation_id]
        after = current_rows[allocation_id]
        for field in immutable_fields:
            if before.get(field) != after.get(field):
                errors.append(
                    f"baseline: {allocation_id} immutable {field} changed across revisions"
                )
        if before.get("state") == "RETIRED" and after.get("state") != "RETIRED":
            errors.append(f"baseline: retired ID reactivated across revisions: {allocation_id}")
    return errors


def load_history_from_git_base(root: Path, revision: str) -> dict[str, Any] | None:
    if re.fullmatch(r"[0-9a-fA-F]{40,64}", revision) is None:
        raise ValueError("baseline Git revision must be a full hexadecimal object ID")
    commit_check = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if commit_check.returncode != 0:
        raise ValueError(f"trusted baseline Git revision is unavailable: {revision}")
    result = subprocess.run(
        ["git", "show", f"{revision}:security/id-history.v1.json"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        return None
    return _load_json_text(result.stdout, f"Git baseline {revision}")


def validate_catalog(
    catalog: Mapping[str, Any],
    registry: Mapping[str, Any],
    history: Mapping[str, Any],
    root: Path,
) -> list[str]:
    """Return deterministic validation failures without mutating documents."""
    errors: list[str] = []
    if set(catalog) != CATALOG_KEYS:
        errors.append("catalog: top-level fields must exactly match schema v1")
    if set(registry) != REGISTRY_KEYS:
        errors.append("registry: top-level fields must exactly match schema v1")
    if catalog.get("schema_version") != 1:
        errors.append("catalog: unknown schema_version (expected 1)")
    if registry.get("schema_version") != 1:
        errors.append("registry: unknown schema_version (expected 1)")
    for document, key in ((catalog, "catalog_version"), (registry, "registry_version")):
        if not isinstance(document.get(key), str) or not SEMVER.fullmatch(document.get(key, "")):
            errors.append(f"{key.split('_')[0]}: {key} must be semantic x.y.z")
    threats = catalog.get("threats")
    tests = registry.get("tests")
    if not isinstance(threats, list):
        return sorted({*errors, "catalog: threats must be an array"})
    if not isinstance(tests, list):
        return sorted({*errors, "registry: tests must be an array"})

    threat_ids = [item.get("id") for item in threats if isinstance(item, dict)]
    test_ids = [item.get("id") for item in tests if isinstance(item, dict)]
    string_threat_ids = [value for value in threat_ids if isinstance(value, str)]
    string_test_ids = [value for value in test_ids if isinstance(value, str)]
    for duplicate in _duplicates(string_threat_ids):
        errors.append(f"catalog: duplicate threat ID {duplicate}")
    for duplicate in _duplicates(string_test_ids):
        errors.append(f"registry: duplicate verification test ID {duplicate}")
    if threat_ids != sorted(threat_ids, key=str):
        errors.append("catalog: threats must be sorted by canonical ID")
    if test_ids != sorted(test_ids, key=str):
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
        for field, maximum in (("title", 120), ("failure_story", 500)):
            if not _safe_text(threat.get(field), maximum=maximum):
                errors.append(f"{label}: {field} must be bounded single-line text")
        for field, maximum in (("assets", 80), ("mitigations", 240)):
            values = threat.get(field)
            if (
                not isinstance(values, list)
                or not values
                or not all(_safe_text(value, maximum=maximum) for value in values)
            ):
                errors.append(f"{label}: {field} must be nonempty bounded text")
            elif len(values) != len(set(values)):
                errors.append(f"{label}: {field} must have no duplicates")
        for field in ("requirements", "work_packages", "verification_tests", "sources"):
            values = threat.get(field)
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(value, str) and value for value in values)
            ):
                errors.append(f"{label}: {field} must be a nonempty string array")
            elif not _is_sorted_unique(values):
                errors.append(f"{label}: {field} must be sorted with no duplicates")
        evidence_items = threat.get("evidence")
        if not isinstance(evidence_items, list) or not evidence_items:
            errors.append(f"{label}: evidence must be a nonempty typed array")
        elif [_evidence_key(item) for item in evidence_items] != sorted(
            {_evidence_key(item) for item in evidence_items}
        ):
            errors.append(f"{label}: evidence must be sorted with no duplicates")
        else:
            for evidence in evidence_items:
                if not _evidence_valid(root, evidence):
                    errors.append(f"{label}: invalid typed evidence {_evidence_key(evidence)}")
        for requirement in (
            threat.get("requirements", []) if isinstance(threat.get("requirements"), list) else []
        ):
            if requirement not in known_requirements:
                errors.append(f"{label}: unknown requirement ID {requirement}")
        for package in (
            threat.get("work_packages", []) if isinstance(threat.get("work_packages"), list) else []
        ):
            if package not in known_packages:
                errors.append(f"{label}: unknown work-package ID {package}")
        for test_id in (
            threat.get("verification_tests", [])
            if isinstance(threat.get("verification_tests"), list)
            else []
        ):
            if test_id not in known_tests:
                errors.append(f"{label}: unknown verification test ID {test_id}")
        for source in threat.get("sources", []) if isinstance(threat.get("sources"), list) else []:
            if not _source_anchor_exists(root, source):
                errors.append(f"{label}: broken or noncanonical source anchor {source}")

    reverse_edges: set[tuple[str, str]] = set()
    tests_by_id: dict[str, Mapping[str, Any]] = {}
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
        else:
            tests_by_id[test_id] = test
        if not _safe_text(test.get("purpose"), maximum=160):
            errors.append(f"{label}: purpose must be bounded single-line text")
        if test.get("status") not in TEST_STATUSES:
            errors.append(f"{label}: unknown status {test.get('status')!r}")
        implementation = test.get("implementation")
        if implementation is not None and not _evidence_valid(root, implementation):
            errors.append(f"{label}: invalid typed implementation {_evidence_key(implementation)}")
        if test.get("status") == "IMPLEMENTED" and (
            not isinstance(implementation, dict)
            or implementation.get("type") not in EXECUTABLE_EVIDENCE_TYPES
        ):
            errors.append(f"{label}: IMPLEMENTED requires executable typed evidence")
        if test.get("status") == "PLANNED" and implementation is not None:
            errors.append(f"{label}: PLANNED test cannot claim implementation evidence")
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
    for threat in threats:
        if not isinstance(threat, dict) or threat.get("status") != "CONTROL_TESTED":
            continue
        implementations = [
            tests_by_id[test_id].get("implementation")
            for test_id in (
                threat.get("verification_tests", [])
                if isinstance(threat.get("verification_tests"), list)
                else []
            )
            if test_id in tests_by_id and tests_by_id[test_id].get("status") == "IMPLEMENTED"
        ]
        evidence = threat.get("evidence", [])
        if not any(implementation in evidence for implementation in implementations):
            errors.append(
                f"{threat.get('id')}: CONTROL_TESTED requires matching executable evidence"
            )
    errors.extend(_validate_history(catalog, registry, history))
    return sorted(set(errors))


def _execute_pytest_nodes(registry: Mapping[str, Any], root: Path) -> list[str]:
    nodes = sorted(
        {
            test["implementation"]["ref"]
            for test in registry.get("tests", [])
            if isinstance(test, dict)
            and test.get("status") == "IMPLEMENTED"
            and isinstance(test.get("implementation"), dict)
            and test["implementation"].get("type") == "PYTEST_NODE"
        }
    )
    failures: list[str] = []
    for node in nodes:
        environment = os.environ.copy()
        environment["MYCOGNI_THREAT_EVIDENCE_SUBPROCESS"] = "1"
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "--runxfail", "-rA", "-q", node],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )
        passed_line = re.compile(rf"^PASSED {re.escape(node)}$", re.MULTILINE)
        if result.returncode != 0 or passed_line.search(result.stdout) is None:
            failures.append(f"pytest evidence did not produce an exact PASSED outcome: {node}")
    return failures


def render_report(catalog: Mapping[str, Any], registry: Mapping[str, Any]) -> str:
    tests = {item["id"]: item for item in registry["tests"]}
    rows = [
        "# Threat catalog report",
        "",
        "Generated from `security/threat-catalog.v1.json`, `security/verification-tests.v1.json`, "
        "and `security/id-history.v1.json`. Do not edit this report by hand.",
        "",
        f"Catalog version: `{catalog['catalog_version']}`. Schema version: `{catalog['schema_version']}`.",
        "",
        "| Threat | Severity | Boundary | Owner | Milestone | Control status | Verification |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for threat in catalog["threats"]:
        verification = ", ".join(
            f"`{test_id}` ({tests[test_id]['status']})" for test_id in threat["verification_tests"]
        )
        rows.append(
            f"| `{threat['id']}` {_markdown_cell(threat['title'])} | {threat['severity']} | "
            f"{threat['boundary']} | {threat['owner']} | {threat['milestone']} | {threat['status']} | {verification} |"
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
            "Implemented mappings name an exact assertion-bearing test that produced PASSED under `--runxfail`; "
            "they do not prove a product control beyond that test's scope.",
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
        history = _load_json(HISTORY_PATH)
        schemas = {
            SCHEMA_PATH.name: _load_json(SCHEMA_PATH),
            REGISTRY_SCHEMA_PATH.name: _load_json(REGISTRY_SCHEMA_PATH),
            HISTORY_SCHEMA_PATH.name: _load_json(HISTORY_SCHEMA_PATH),
        }
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Threat catalog guard could not load inputs: {error}")
        return 1
    errors = validate_catalog(catalog, registry, history, REPOSITORY_ROOT)
    for document, schema_name in (
        (catalog, SCHEMA_PATH.name),
        (registry, REGISTRY_SCHEMA_PATH.name),
        (history, HISTORY_SCHEMA_PATH.name),
    ):
        errors.extend(validate_published_schema(document, schemas[schema_name], schema_name))
    baseline_revision = os.environ.get("THREAT_CATALOG_BASE_REF", "").strip()
    baseline_checked = False
    baseline_bootstrap = False
    if baseline_revision:
        try:
            baseline = load_history_from_git_base(REPOSITORY_ROOT, baseline_revision)
        except ValueError as error:
            errors.append(str(error))
        else:
            if baseline is None:
                baseline_bootstrap = True
            else:
                errors.extend(validate_history_against_baseline(history, baseline))
                baseline_checked = True
    if not errors:
        errors.extend(_execute_pytest_nodes(registry, REPOSITORY_ROOT))
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
        f"Threat catalog guard passed ({len(catalog['threats'])} threats, {len(registry['tests'])} verification IDs)."
    )
    if baseline_checked:
        print("Cross-revision ID baseline: VERIFIED.")
    elif baseline_bootstrap:
        print("Cross-revision ID baseline: BOOTSTRAP NOT VERIFIED (base has no ledger).")
    else:
        print("Cross-revision ID baseline: NOT CHECKED (no trusted base revision supplied).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
