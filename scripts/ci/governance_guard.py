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
from collections.abc import Callable, Mapping, Sequence
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
    "manifest": "dd7de835d04c2d19bca255c1a6ca793c3cde7b6806e3bd20d71f65551216e8df",
    "status": "23037e575f5eee9249e446efa2c37c012bef3861bb98ba505159efa39addde69",
    "acceptance": "dd6175abeaee7db10a8aa01e4181af78397c088096d5d066a02a44e9c1b2316b",
    "attestations": "e523ebca733d7ad86928efd4e6a2f41c3662e98adbb83ff59493a5492fcb5e70",
}
STATUSES = {"NOT_STARTED", "IN_PROGRESS", "BLOCKED", "COMPLETE", "VERIFIED"}
STATUS_RANK = {"NOT_STARTED": 0, "BLOCKED": 1, "IN_PROGRESS": 1, "COMPLETE": 2, "VERIFIED": 3}
ADR_STATUSES = {
    "Accepted",
    "Accepted for initial build",
    "Accepted as a boundary; runtime deferred until post-v1 evidence",
}
ACCEPTING_ADR_STATUSES = {"Accepted", "Accepted for initial build"}
SEMVER = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
ZERO_GIT_OBJECT = "0" * 40
TRUST_ROOT_SHA_ENV = "MYCOGNI_GOVERNANCE_TRUST_ROOT_SHA"
PROTECTED_APPROVAL_FIELDS = {
    "id",
    "subject_type",
    "subject_id",
    "reviewer_id",
    "subject_sha256",
    "criteria_sha256",
    "evidence_sha256",
    "semantic_adequacy",
}


def _load(path: Path) -> dict[str, Any]:
    return threat_guard._load_json(path)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_content_hash(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _function_source_bytes(source: bytes, function_name: str) -> bytes | None:
    try:
        text = source.decode("utf-8")
        module = ast.parse(text)
    except (UnicodeDecodeError, SyntaxError):
        return None
    function = next(
        (
            node
            for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        ),
        None,
    )
    if function is None or function.end_lineno is None:
        return None
    start = min([function.lineno, *(item.lineno for item in function.decorator_list)])
    lines = text.splitlines(keepends=True)
    return "".join(lines[start - 1 : function.end_lineno]).encode("utf-8")


def _function_sha256(path: Path, function_name: str) -> str | None:
    source = _function_source_bytes(path.read_bytes(), function_name)
    return hashlib.sha256(source).hexdigest() if source is not None else None


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


def parse_work_packages_text(text: str) -> tuple[dict[str, set[str]], dict[str, str], list[str]]:
    packages: dict[str, set[str]] = {}
    canonical_rows: dict[str, str] = {}
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
        canonical_rows[package_id] = "| " + " | ".join(cells) + " |"
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
    return packages, canonical_rows, sorted(set(errors))


def parse_work_packages(root: Path) -> tuple[dict[str, set[str]], list[str]]:
    text = (root / "docs/v1/WORK_PACKAGES.md").read_text(encoding="utf-8")
    packages, _, errors = parse_work_packages_text(text)
    return packages, errors


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


def parse_completion_text(text: str) -> tuple[dict[str, str], list[str]]:
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


def parse_completion(root: Path) -> tuple[dict[str, str], list[str]]:
    text = (root / "docs/v1/COMPLETION_MATRIX.md").read_text(encoding="utf-8")
    return parse_completion_text(text)


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


def _static_value(node: ast.expr, names: Mapping[str, Any]) -> tuple[bool, Any]:
    """Evaluate a deliberately small set of literal/tautological expressions."""

    if isinstance(node, ast.Constant):
        return True, node.value
    if isinstance(node, ast.Name) and node.id in names:
        return True, names[node.id]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_static_value(item, names) for item in node.elts]
        if not all(known for known, _ in items):
            return False, None
        values = [value for _, value in items]
        if isinstance(node, ast.Tuple):
            return True, tuple(values)
        if isinstance(node, ast.Set):
            try:
                return True, set(values)
            except TypeError:
                return False, None
        return True, values
    if isinstance(node, ast.Dict):
        keys = [_static_value(item, names) for item in node.keys if item is not None]
        values = [_static_value(item, names) for item in node.values]
        if len(keys) != len(node.keys) or not all(known for known, _ in (*keys, *values)):
            return False, None
        return True, {key: value for (_, key), (_, value) in zip(keys, values, strict=True)}
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Lambda)
        and not node.args
        and not node.keywords
        and not node.func.args.args
        and not node.func.args.posonlyargs
        and not node.func.args.kwonlyargs
        and node.func.args.vararg is None
        and node.func.args.kwarg is None
    ):
        return _static_value(node.func.body, names)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and not node.keywords:
        safe_calls: dict[str, Callable[..., Any]] = {
            "all": all,
            "any": any,
            "bool": bool,
            "len": len,
            "sorted": sorted,
        }
        function = safe_calls.get(node.func.id)
        arguments = [_static_value(item, names) for item in node.args]
        if function is not None and all(known for known, _ in arguments):
            try:
                return True, function(*(value for _, value in arguments))
            except (TypeError, ValueError):
                return False, None
    if isinstance(node, ast.UnaryOp):
        known, value = _static_value(node.operand, names)
        if known and isinstance(node.op, ast.Not):
            return True, not value
        if known and isinstance(value, (int, float)) and not isinstance(value, bool):
            if isinstance(node.op, ast.UAdd):
                return True, +value
            if isinstance(node.op, ast.USub):
                return True, -value
    if isinstance(node, ast.BinOp):
        left_known, left = _static_value(node.left, names)
        right_known, right = _static_value(node.right, names)
        if left_known and right_known:
            try:
                if isinstance(node.op, ast.Add):
                    value = left + right
                elif isinstance(node.op, ast.Sub):
                    value = left - right
                elif isinstance(node.op, ast.Mult):
                    value = left * right
                elif isinstance(node.op, ast.FloorDiv):
                    value = left // right
                elif isinstance(node.op, ast.Mod):
                    value = left % right
                else:
                    return False, None
            except (TypeError, ValueError, ZeroDivisionError, OverflowError):
                return False, None
            if isinstance(value, int) and value.bit_length() > 4096:
                return False, None
            if isinstance(value, (str, bytes, list, tuple)) and len(value) > 4096:
                return False, None
            return True, value
    if isinstance(node, ast.BoolOp):
        values = [_static_value(item, names) for item in node.values]
        if all(known for known, _ in values):
            resolved = [value for _, value in values]
            if isinstance(node.op, ast.And):
                return True, all(resolved)
            if isinstance(node.op, ast.Or):
                return True, any(resolved)
    if isinstance(node, ast.Compare):
        values = [_static_value(item, names) for item in (node.left, *node.comparators)]
        if all(known for known, _ in values):
            resolved = [value for _, value in values]
            comparisons = []
            for operator, left, right in zip(node.ops, resolved[:-1], resolved[1:], strict=True):
                if isinstance(operator, ast.Eq):
                    comparisons.append(left == right)
                elif isinstance(operator, ast.NotEq):
                    comparisons.append(left != right)
                elif isinstance(operator, ast.In):
                    comparisons.append(left in right)
                elif isinstance(operator, ast.NotIn):
                    comparisons.append(left not in right)
                elif isinstance(operator, ast.Is):
                    comparisons.append(left is right)
                elif isinstance(operator, ast.IsNot):
                    comparisons.append(left is not right)
                else:
                    return False, None
            return True, all(comparisons)
    return False, None


def _bind_static_target(target: ast.expr, value: Any, names: dict[str, Any]) -> bool:
    if isinstance(target, ast.Name):
        names[target.id] = value
        return True
    if isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (tuple, list)):
        if len(target.elts) != len(value):
            return False
        return all(
            _bind_static_target(item, item_value, names)
            for item, item_value in zip(target.elts, value, strict=True)
        )
    return False


def _forget_target(target: ast.expr, names: dict[str, Any]) -> None:
    if isinstance(target, ast.Name):
        names.pop(target.id, None)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for item in target.elts:
            _forget_target(item, names)


def _structural_runtime_witness(function: ast.FunctionDef) -> bool:
    """Reject obvious no-ops while making no claim about semantic adequacy."""

    literal_names: dict[str, Any] = {}
    for statement in function.body:
        if isinstance(statement, ast.Assign):
            known, value = _static_value(statement.value, literal_names)
            for target in statement.targets:
                if not known or not _bind_static_target(target, value, literal_names):
                    _forget_target(target, literal_names)
            continue
        if isinstance(statement, ast.AnnAssign):
            known, value = (
                _static_value(statement.value, literal_names)
                if statement.value is not None
                else (False, None)
            )
            if not known or not _bind_static_target(statement.target, value, literal_names):
                _forget_target(statement.target, literal_names)
            continue
        if not isinstance(statement, ast.Assert):
            continue
        known, _ = _static_value(statement.test, literal_names)
        if known:
            continue
        return True
    return False


def _acceptance_node(root: Path, evidence: Mapping[str, Any], criterion_ids: Sequence[str]) -> bool:
    reference = evidence.get("ref")
    if not isinstance(reference, str) or reference.count("::") != 1:
        return False
    path_text, function_name = reference.split("::")
    path = threat_guard._canonical_repo_file(root, path_text)
    if path is None:
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
    source = _function_source_bytes(path.read_bytes(), function_name)
    if source is None or hashlib.sha256(source).hexdigest() != evidence.get("content_sha256"):
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
    return sorted(invoked) == sorted(criterion_ids) and _structural_runtime_witness(function)


def _execute_node(root: Path, reference: str, criterion_ids: Sequence[str]) -> bool:
    with tempfile.TemporaryDirectory(prefix="mycogni-governance-") as directory:
        artifact = Path(directory) / "result.json"
        result = subprocess.run(
            [
                sys.executable,
                "scripts/ci/guarded_pytest.py",
                "--runxfail",
                "-rA",
                "-q",
                reference,
            ],
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


def _selected_content_hash(
    registry: Mapping[str, Mapping[str, Any]], identifiers: Sequence[str]
) -> str | None:
    if len(set(identifiers)) != len(identifiers) or any(
        item not in registry for item in identifiers
    ):
        return None
    selected = [registry[item] for item in sorted(identifiers)]
    return _canonical_content_hash(selected)


def _protected_approval_authorizes(
    approval: Mapping[str, Any] | None,
    *,
    subject_type: str,
    subject: Mapping[str, Any],
    reviewer_id: Any,
    criteria_sha256: str | None,
    evidence_sha256: str | None,
) -> bool:
    return bool(
        approval is not None
        and approval.get("subject_type") == subject_type
        and approval.get("subject_id") == subject.get("id")
        and approval.get("reviewer_id") == reviewer_id
        and approval.get("subject_sha256") == threat_guard._canonical_json_hash(subject)
        and approval.get("criteria_sha256") == criteria_sha256
        and approval.get("evidence_sha256") == evidence_sha256
        and approval.get("semantic_adequacy") == "APPROVED"
    )


def _reviewed_artifacts_valid(
    root: Path,
    subject: Mapping[str, Any],
    evidence_items: Sequence[Mapping[str, Any]],
) -> list[str]:
    errors: list[str] = []
    subject_id = subject.get("id")
    commit = subject.get("reviewed_commit")
    if not isinstance(commit, str) or not _git_commit_is_ancestor(root, commit):
        errors.append(f"{subject_id}: reviewed commit is not an ancestor")
        return errors
    review = subject.get("review_record", {})
    review_bytes = (
        _git_file_bytes(root, commit, review.get("path", "")) if isinstance(review, dict) else None
    )
    if review_bytes is None or hashlib.sha256(review_bytes).hexdigest() != review.get("sha256"):
        errors.append(f"{subject_id}: review record digest mismatch")
    for evidence_item in evidence_items:
        reference = str(evidence_item.get("ref", ""))
        if reference.count("::") != 1:
            errors.append(f"{subject_id}: malformed evidence reference ({evidence_item.get('id')})")
            continue
        source_path, function_name = reference.split("::")
        source_bytes = _git_file_bytes(root, commit, source_path)
        node_bytes = (
            _function_source_bytes(source_bytes, function_name)
            if source_bytes is not None
            else None
        )
        if node_bytes is None or hashlib.sha256(node_bytes).hexdigest() != evidence_item.get(
            "content_sha256"
        ):
            errors.append(
                f"{subject_id}: evidence digest is not bound to reviewed commit "
                f"({evidence_item.get('id')})"
            )
    return errors


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
        try:
            effective_base, base_kind = threat_guard.resolve_trusted_baseline(root, base)
            baseline = (
                threat_guard.load_history_from_git_base(root, effective_base)
                if effective_base is not None
                else None
            )
        except ValueError as error:
            errors.append(str(error))
        else:
            if base_kind != "GENESIS_BOOTSTRAP" and baseline is None:
                errors.append("trusted baseline commit lacks the threat identity ledger")
            elif baseline is not None:
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
                kind = mapping.get("kind") if isinstance(mapping, dict) else None
                allowed_ids = mapping_ids.get(kind, set()) if isinstance(kind, str) else set()
                if not isinstance(mapping, dict) or mapping.get("id") not in allowed_ids:
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
        record_state = record.get("state")
        package_status = status_by_id.get(package_id, {}).get("status")
        if record_state == "MILESTONE_VERIFIED" and package_status != "VERIFIED":
            errors.append(
                f"{record.get('id')}: MILESTONE_VERIFIED requires canonical VERIFIED status"
            )
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
        if record.get("state") in {"INDEPENDENTLY_ACCEPTED", "MILESTONE_VERIFIED"}:
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
                selected_evidence = [evidence[item] for item in evidence_ids if item in evidence]
                errors.extend(_reviewed_artifacts_valid(root, attestation, selected_evidence))
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
            elif (
                row.get("status") == "VERIFIED" and matching[0].get("state") != "MILESTONE_VERIFIED"
            ):
                errors.append(f"{package_id}: VERIFIED requires MILESTONE_VERIFIED trace state")
            elif (
                row.get("status") == "COMPLETE"
                and matching[0].get("state") != "INDEPENDENTLY_ACCEPTED"
            ):
                errors.append(f"{package_id}: COMPLETE requires INDEPENDENTLY_ACCEPTED trace state")
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
    definitions = status_doc.get("milestone_definitions", [])
    definition_ids = [
        item["id"]
        for item in definitions
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    if definition_ids != sorted(definition_ids):
        errors.append("milestone definitions must be sorted by canonical ID")
    for duplicate in sorted(_duplicates(definition_ids)):
        errors.append(f"duplicate milestone definition ID {duplicate}")
    milestone_names = [
        item["milestone"]
        for item in definitions
        if isinstance(item, dict) and isinstance(item.get("milestone"), str)
    ]
    for duplicate in sorted(_duplicates(milestone_names)):
        errors.append(f"duplicate milestone definition name {duplicate}")
    definitions_by_id = {
        item["id"]: item
        for item in definitions
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    for definition_id, definition in definitions_by_id.items():
        defined_packages = definition.get("packages", [])
        if defined_packages != sorted(defined_packages) or len(set(defined_packages)) != len(
            defined_packages
        ):
            errors.append(f"{definition_id}: packages must be sorted and unique")
        if not defined_packages or not set(defined_packages) <= set(packages):
            errors.append(f"{definition_id}: canonical package set is empty or unknown")
        for package_id in defined_packages:
            missing_dependencies = packages.get(package_id, set()) - set(defined_packages)
            if missing_dependencies:
                errors.append(
                    f"{definition_id}: canonical package set omits dependency closure "
                    f"{sorted(missing_dependencies)}"
                )
        gates = definition.get("gates", [])
        gate_ids = [
            item["id"]
            for item in gates
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ]
        if gate_ids != sorted(gate_ids) or len(set(gate_ids)) != len(gate_ids) or not gate_ids:
            errors.append(f"{definition_id}: gates must be nonempty, sorted and unique")
        for gate in gates:
            if not isinstance(gate, dict):
                continue
            gate_evidence = gate.get("evidence_ids", [])
            if (
                gate_evidence != sorted(gate_evidence)
                or len(set(gate_evidence)) != len(gate_evidence)
                or not gate_evidence
            ):
                errors.append(
                    f"{definition_id}/{gate.get('id')}: gate evidence must be named, sorted and unique"
                )

    milestones = status_doc.get("milestone_attestations", [])
    milestone_ids = [
        item["id"]
        for item in milestones
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    ]
    if milestone_ids != sorted(milestone_ids):
        errors.append("milestone attestations must be sorted by canonical ID")
    for duplicate in sorted(_duplicates(milestone_ids)):
        errors.append(f"duplicate milestone attestation ID {duplicate}")
    milestones_by_id = {
        item["id"]: item
        for item in milestones
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    verified_ids = {
        package_id for package_id, row in status_by_id.items() if row.get("status") == "VERIFIED"
    }
    records_by_package = {item.get("package"): item for item in records if isinstance(item, dict)}
    for milestone in milestones:
        if not isinstance(milestone, dict):
            continue
        if not (set(milestone.get("packages", [])) & verified_ids):
            errors.append(f"unused milestone attestation {milestone.get('id')}")
        definition_id = milestone.get("definition_id")
        milestone_definition = (
            definitions_by_id.get(definition_id) if isinstance(definition_id, str) else None
        )
        if milestone_definition is None:
            errors.append(f"{milestone.get('id')}: unknown milestone definition")
            continue
        if milestone.get("packages") != milestone_definition.get("packages"):
            errors.append(f"{milestone.get('id')}: package set does not equal canonical definition")
        if milestone.get("gates") != milestone_definition.get("gates"):
            errors.append(f"{milestone.get('id')}: gates do not equal canonical gate evidence")
        package_set = set(milestone_definition.get("packages", []))
        exact_attestation_ids = {
            records_by_package.get(package_id, {}).get("attestation_id")
            for package_id in package_set
        }
        if None in exact_attestation_ids or set(milestone.get("package_attestation_ids", [])) != (
            exact_attestation_ids - {None}
        ):
            errors.append(
                f"{milestone.get('id')}: package attestations do not equal canonical package closure"
            )
        for package_id in package_set:
            record = records_by_package.get(package_id)
            package_attestation = (
                attestations.get(record.get("attestation_id")) if isinstance(record, dict) else None
            )
            if (
                status_by_id.get(package_id, {}).get("status") != "VERIFIED"
                or record is None
                or record.get("state") != "MILESTONE_VERIFIED"
                or package_attestation is None
                or package_attestation.get("disposition") != "ACCEPT"
            ):
                errors.append(
                    f"{milestone.get('id')}: all canonical packages require valid accepted attestations"
                )
        gate_evidence_ids = {
            evidence_id
            for gate in milestone_definition.get("gates", [])
            if isinstance(gate, dict)
            for evidence_id in gate.get("evidence_ids", [])
        }
        selected_gate_evidence = [
            evidence[evidence_id]
            for evidence_id in sorted(gate_evidence_ids)
            if evidence_id in evidence
        ]
        if len(selected_gate_evidence) != len(gate_evidence_ids):
            errors.append(f"{milestone.get('id')}: canonical gate evidence is missing")
        for evidence_id in gate_evidence_ids:
            item = evidence.get(evidence_id)
            package_id = item.get("package") if isinstance(item, dict) else None
            record = records_by_package.get(package_id)
            package_attestation = (
                attestations.get(record.get("attestation_id")) if isinstance(record, dict) else None
            )
            if (
                package_id not in package_set
                or record is None
                or evidence_id not in record.get("evidence_ids", [])
                or package_attestation is None
                or evidence_id not in package_attestation.get("evidence_ids", [])
            ):
                errors.append(
                    f"{milestone.get('id')}: gate evidence {evidence_id} lacks package attestation path"
                )
        errors.extend(_reviewed_artifacts_valid(root, milestone, selected_gate_evidence))

    for package_id, row in status_by_id.items():
        if row.get("status") != "VERIFIED":
            continue
        covering = [
            item
            for item in milestones_by_id.values()
            if package_id in item.get("packages", []) and item.get("disposition") == "ACCEPT"
        ]
        if len(covering) != 1:
            errors.append(f"{package_id}: VERIFIED lacks one authenticated milestone attestation")
    errors.extend(_validate_schemas(documents))
    counts = {
        "requirements": sorted(requirements),
        "packages": sorted(packages),
        "adrs": sorted(adrs),
        "records": sorted(record["id"] for record in records if isinstance(record, dict)),
        "threats": sorted(threats_by_id),
        "verification_tests": sorted(tests_by_id),
        "registry_packages": sorted(status_by_id),
        "milestone_definitions": sorted(definitions_by_id),
        "accepted_packages": sorted(
            record["package"]
            for record in records
            if isinstance(record, dict)
            and record.get("state") in {"INDEPENDENTLY_ACCEPTED", "MILESTONE_VERIFIED"}
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
    *,
    current_scope: Mapping[str, Mapping[str, Any]] | None = None,
    baseline_scope: Mapping[str, Mapping[str, Any]] | None = None,
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

    def indexed(document: Mapping[str, Any], key: str) -> dict[str, Mapping[str, Any]]:
        return {
            item["id"]: item
            for item in document.get(key, [])
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }

    def reject_disappearance(
        label: str,
        before_items: Mapping[str, Any],
        after_items: Mapping[str, Any],
    ) -> None:
        for item_id in sorted(set(before_items) - set(after_items)):
            errors.append(f"trusted {label} disappeared: {item_id}")

    before_status_items = indexed(baseline["status"], "packages")
    after_status_items = indexed(current["status"], "packages")
    reject_disappearance("package status", before_status_items, after_status_items)

    before_records = indexed(baseline["manifest"], "records")
    after_records = indexed(current["manifest"], "records")
    reject_disappearance("trace record", before_records, after_records)
    immutable_record_fields = {
        "package",
        "mappings",
        "acceptance_criteria",
        "evidence_ids",
    }
    for record_id in sorted(set(before_records) & set(after_records)):
        if any(
            before_records[record_id].get(field) != after_records[record_id].get(field)
            for field in immutable_record_fields
        ):
            errors.append(f"trusted trace record rebound: {record_id}")

    for label, key in (("criterion", "criteria"), ("evidence", "evidence")):
        before_items = indexed(baseline["acceptance"], key)
        after_items = indexed(current["acceptance"], key)
        reject_disappearance(label, before_items, after_items)
        for item_id in sorted(set(before_items) & set(after_items)):
            if before_items[item_id] != after_items[item_id] and (
                label != "evidence" or baseline["acceptance"].get("schema_version") == 2
            ):
                errors.append(f"trusted {label} rebound: {item_id}")

    before_definitions = indexed(baseline["status"], "milestone_definitions")
    after_definitions = indexed(current["status"], "milestone_definitions")
    reject_disappearance("milestone definition", before_definitions, after_definitions)
    for definition_id in sorted(set(before_definitions) & set(after_definitions)):
        if before_definitions[definition_id] != after_definitions[definition_id]:
            errors.append(f"trusted milestone definition rebound: {definition_id}")

    if baseline_scope is not None and current_scope is not None:
        for label in ("work package", "completion matrix"):
            scope_before = baseline_scope.get(label, {})
            scope_after = current_scope.get(label, {})
            reject_disappearance(label, scope_before, scope_after)
            if label == "work package":
                for item_id in sorted(set(scope_before) & set(scope_after)):
                    if scope_before[item_id] != scope_after[item_id]:
                        errors.append(f"trusted work package rebound: {item_id}")

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
        criteria = indexed(current["acceptance"], "criteria")
        evidence = indexed(current["acceptance"], "evidence")
        if not _protected_approval_authorizes(
            approval,
            subject_type="PACKAGE_ATTESTATION",
            subject=attestation,
            reviewer_id=attestation.get("reviewer", {}).get("id"),
            criteria_sha256=_selected_content_hash(
                criteria, attestation.get("acceptance_criteria", [])
            ),
            evidence_sha256=_selected_content_hash(evidence, attestation.get("evidence_ids", [])),
        ):
            errors.append(f"new attestation lacks external trust-root approval: {attestation_id}")

    before_milestones = indexed(baseline["status"], "milestone_attestations")
    after_milestones = indexed(current["status"], "milestone_attestations")
    reject_disappearance("milestone attestation", before_milestones, after_milestones)
    for milestone_id in sorted(set(before_milestones) & set(after_milestones)):
        if before_milestones[milestone_id] != after_milestones[milestone_id]:
            errors.append(f"trusted milestone attestation mutated: {milestone_id}")
    current_evidence = indexed(current["acceptance"], "evidence")
    current_definitions = indexed(current["status"], "milestone_definitions")
    for milestone_id in sorted(set(after_milestones) - set(before_milestones)):
        milestone = after_milestones[milestone_id]
        definition = current_definitions.get(str(milestone.get("definition_id")), {})
        gate_evidence_ids = [
            evidence_id
            for gate in definition.get("gates", [])
            if isinstance(gate, dict)
            for evidence_id in gate.get("evidence_ids", [])
        ]
        approval = protected_approvals.get(milestone_id)
        if not _protected_approval_authorizes(
            approval,
            subject_type="MILESTONE_ATTESTATION",
            subject=milestone,
            reviewer_id=milestone.get("reviewer", {}).get("id"),
            criteria_sha256=(threat_guard._canonical_json_hash(definition) if definition else None),
            evidence_sha256=_selected_content_hash(current_evidence, gate_evidence_ids),
        ):
            errors.append(
                f"new milestone attestation lacks external trust-root approval: {milestone_id}"
            )

    before_status = {item_id: item.get("status") for item_id, item in before_status_items.items()}
    after_status = {item_id: item.get("status") for item_id, item in after_status_items.items()}
    records_by_package = {
        item.get("package"): item for item in current["manifest"].get("records", [])
    }
    for package_id, status in after_status.items():
        prior_value = before_status.get(package_id, "NOT_STARTED")
        prior = prior_value if isinstance(prior_value, str) else "NOT_STARTED"
        if status not in {"COMPLETE", "VERIFIED"} or STATUS_RANK.get(status, -1) <= STATUS_RANK.get(
            prior, -1
        ):
            continue
        attestation_id = records_by_package.get(package_id, {}).get("attestation_id")
        if not attestation_id or attestation_id not in protected_approvals:
            errors.append(f"{package_id}: promotion lacks external trust-root authorization")
        if status == "VERIFIED":
            covering = [
                item for item in after_milestones.values() if package_id in item.get("packages", [])
            ]
            if len(covering) != 1 or covering[0].get("id") not in protected_approvals:
                errors.append(
                    f"{package_id}: VERIFIED promotion lacks external milestone authorization"
                )
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


def _git_text(root: Path, revision: str, relative: str) -> str | None:
    shown = subprocess.run(
        ["git", "show", f"{revision}:{relative}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return shown.stdout if shown.returncode == 0 else None


def _load_base_scope(root: Path, revision: str) -> dict[str, Mapping[str, Any]]:
    work_text = _git_text(root, revision, "docs/v1/WORK_PACKAGES.md")
    matrix_text = _git_text(root, revision, "docs/v1/COMPLETION_MATRIX.md")
    if work_text is None or matrix_text is None:
        raise ValueError("trusted base lacks canonical work-package or completion-matrix scope")
    _, work_rows, work_errors = parse_work_packages_text(work_text)
    matrix, matrix_errors = parse_completion_text(matrix_text)
    if work_errors or matrix_errors:
        raise ValueError("trusted base canonical Markdown scope is malformed")
    return {"work package": work_rows, "completion matrix": matrix}


def _current_scope(root: Path) -> dict[str, Mapping[str, Any]]:
    work_text = (root / "docs/v1/WORK_PACKAGES.md").read_text(encoding="utf-8")
    matrix_text = (root / "docs/v1/COMPLETION_MATRIX.md").read_text(encoding="utf-8")
    _, work_rows, work_errors = parse_work_packages_text(work_text)
    matrix, matrix_errors = parse_completion_text(matrix_text)
    if work_errors or matrix_errors:
        raise ValueError("current canonical Markdown scope is malformed")
    return {"work package": work_rows, "completion matrix": matrix}


def _parse_protected_approvals(document: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    if set(document) != {"schema_version", "approvals"} or document.get("schema_version") != 2:
        raise ValueError("protected approval registry is malformed")
    approvals = document.get("approvals")
    if not isinstance(approvals, list):
        raise ValueError("protected approval registry approvals must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    approval_ids: set[str] = set()
    for item in approvals:
        if (
            not isinstance(item, dict)
            or set(item) != PROTECTED_APPROVAL_FIELDS
            or re.fullmatch(r"PAPP-[A-Z0-9-]+", str(item.get("id"))) is None
            or item.get("subject_type") not in {"PACKAGE_ATTESTATION", "MILESTONE_ATTESTATION"}
            or not isinstance(item.get("subject_id"), str)
            or not isinstance(item.get("reviewer_id"), str)
            or any(
                re.fullmatch(r"[0-9a-f]{64}", str(item.get(field))) is None
                for field in ("subject_sha256", "criteria_sha256", "evidence_sha256")
            )
            or item.get("semantic_adequacy") != "APPROVED"
            or item.get("id") in approval_ids
            or item["subject_id"] in result
        ):
            raise ValueError("protected approval registry entry is malformed or duplicated")
        result[item["subject_id"]] = item
        approval_ids.add(item["id"])
    return result


def _load_protected_approvals(root: Path, revision: str) -> dict[str, Mapping[str, Any]]:
    relative = PROTECTED_APPROVALS_PATH.relative_to(ROOT).as_posix()
    text = _git_text(root, revision, relative)
    if text is None:
        raise ValueError("external governance trust root lacks protected approvals")
    document = threat_guard._load_json_text(text, "protected governance approvals")
    return _parse_protected_approvals(document)


def _load_external_protected_approvals(root: Path) -> dict[str, Mapping[str, Any]]:
    local_path = root / PROTECTED_APPROVALS_PATH.relative_to(ROOT)
    if local_path.is_file():
        raise ValueError(
            "branch-local protected approvals are forbidden; configure an external trust root"
        )
    trust_root = os.environ.get(TRUST_ROOT_SHA_ENV, "").strip()
    if not trust_root:
        return {}
    if not threat_guard._commit_exists(root, trust_root):
        raise ValueError("external governance trust root is not an available full commit SHA")
    return _load_protected_approvals(root, trust_root)


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
            f"- Canonical milestone definitions ({len(data['milestone_definitions'])}): {listed(data['milestone_definitions'])}",
            "",
            "## Claim boundary",
            "",
            "Implemented records and structural runtime witnesses are not semantic acceptance. An ACCEPT attestation requires an externally configured immutable trust-root approval that explicitly owns semantic adequacy and binds the exact criterion/evidence content digests, subject digest, reviewer and reviewed commit; branch history cannot authorize promotion, and canonical status remains below COMPLETE until every promotion rule passes.",
            "No milestone is verified. Planned threat controls remain planned, and the threat guard is invoked fail-closed by GOV.",
            "GOV-001 itself remains IN_PROGRESS pending independent review of these registries and guards.",
            "",
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args(argv)
    try:
        documents = {name: _load(path) for name, path in DOCUMENTS.items()}
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Governance guard could not load machine truth: {error}")
        return 1
    errors = _validate_threat_catalog(ROOT, execute=True)
    governance_errors, report_data = validate_governance(documents, ROOT, execute=True)
    errors.extend(governance_errors)
    base_ref = os.environ.get("THREAT_CATALOG_BASE_REF", "").strip()
    ci_mode = os.environ.get("MYCOGNI_GOVERNANCE_CI", "") == "1"
    base_state = "NOT CHECKED"
    try:
        approvals = _load_external_protected_approvals(ROOT)
    except ValueError as error:
        errors.append(str(error))
        approvals = {}
    if base_ref:
        try:
            effective_base, base_kind = threat_guard.resolve_trusted_baseline(ROOT, base_ref)
        except ValueError as error:
            errors.append(str(error))
        else:
            if effective_base is None:
                errors.extend(_untrusted_promotions(documents))
                base_state = "GENESIS BOOTSTRAP"
            else:
                try:
                    baseline = _load_base_documents(ROOT, effective_base)
                    baseline_scope = _load_base_scope(ROOT, effective_base)
                    current_scope = _current_scope(ROOT)
                except ValueError as error:
                    errors.append(str(error))
                else:
                    if not baseline:
                        errors.append(
                            "trusted base cannot omit all governance documents; "
                            "configure an external recovery state"
                        )
                    else:
                        errors.extend(
                            validate_against_base(
                                documents,
                                baseline,
                                approvals,
                                current_scope=current_scope,
                                baseline_scope=baseline_scope,
                            )
                        )
                        base_state = f"VERIFIED ({base_kind})"
    else:
        if ci_mode:
            errors.append("CI requires an immutable trusted base revision")
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
