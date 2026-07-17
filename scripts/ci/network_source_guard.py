"""Static fail-closed checks for the NET-001 pytest network boundary."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
PYPROJECT = ROOT / "pyproject.toml"
CONFTEST = ROOT / "tests" / "conftest.py"
PLUGIN = "scripts.ci.network_guard_plugin"
MARKER_ATTRIBUTE = "pytest.mark.simulator_loopback"
NETWORK_TEST_FILE = ROOT / "tests" / "simulator" / "test_web_mail_safety.py"
GUARD_TEST_FILE = ROOT / "tests" / "ci" / "test_network_guard.py"
POLICY_TEST_FILE = ROOT / "tests" / "simulator" / "test_network_guard_simulator.py"
EXPECTED_LOOPBACK_TESTS = {
    "test_raw_http_success_has_deterministic_headers_without_date",
    "test_raw_http_mutations_fail_closed",
    "test_raw_http_concurrency_is_bounded",
    "test_incomplete_raw_request_is_closed_by_read_timeout",
}
EXPECTED_POLICY_TESTS = {
    "test_noncanonical_local_http_urls_fail_before_transport",
    "test_ip_family_alias_and_unix_socket_escapes_fail",
    "test_external_redirect_is_denied_before_second_transport",
    "test_valid_local_http_policy_is_exact",
    "test_proxy_environment_names_are_case_insensitive_and_forbidden",
}
NETWORK_HELPERS = {"_raw_request", "_running_server"}
FORBIDDEN_RUNTIME_IMPORTS = {
    "aiohttp",
    "ctypes",
    "ftplib",
    "http.client",
    "httpx",
    "requests",
    "smtplib",
    "socket",
    "ssl",
    "subprocess",
    "urllib.request",
}
FORBIDDEN_DYNAMIC_CALLS = {"__import__", "compile", "eval", "exec"}
TEST_ESCAPE_IMPORTS = FORBIDDEN_RUNTIME_IMPORTS | {"_socket", "builtins", "importlib"}
TEST_IMPORT_ALLOWLIST = {
    "tests/ci/test_network_guard.py": TEST_ESCAPE_IMPORTS,
    "tests/simulator/test_network_guard_simulator.py": {"httpx", "socket"},
    "tests/simulator/test_web_mail_safety.py": {"socket"},
    "tests/ci/test_governance_traceability.py": {"subprocess"},
    "tests/ci/test_toolchain_guards.py": {"subprocess"},
    "tests/architecture/test_distribution_boundaries.py": {"subprocess"},
    "tests/architecture/test_container_skeleton.py": {"importlib"},
    "tests/architecture/test_package_boundaries.py": {"importlib"},
}


def _attribute(node: ast.AST) -> str:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _decorators(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {_attribute(item) for item in function.decorator_list}


def _calls(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {_attribute(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)}


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imports.add(node.module)
            imports.update(
                f"{node.module}.{alias.name}" for alias in node.names if alias.name != "*"
            )
    return imports


def _runtime_errors() -> list[str]:
    errors: list[str] = []
    guarded = {
        ROOT / "scripts" / "ci" / "network_guard.py",
        ROOT / "scripts" / "ci" / "network_guard_plugin.py",
        ROOT / "simulator" / "web.py",
    }
    for base in (ROOT / "src", ROOT / "packages", ROOT / "simulator"):
        for path in sorted(base.rglob("*.py")):
            if path in guarded or "tests" in path.parts:
                continue
            violations = {
                forbidden
                for forbidden in FORBIDDEN_RUNTIME_IMPORTS
                if any(
                    imported == forbidden or imported.startswith(f"{forbidden}.")
                    for imported in _imports(path)
                )
            }
            if violations:
                relative = path.relative_to(ROOT).as_posix()
                errors.append(f"{relative}: unguarded network/process import")
    return errors


def _simulator_marker_errors() -> list[str]:
    errors: list[str] = []
    tree = ast.parse(NETWORK_TEST_FILE.read_text(encoding="utf-8"), filename=str(NETWORK_TEST_FILE))
    marked: set[str] = set()
    network_bearing: set[str] = set()
    for node in tree.body:
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) or not node.name.startswith("test_"):
            continue
        decorators = _decorators(node)
        calls = _calls(node)
        if MARKER_ATTRIBUTE in decorators:
            marked.add(node.name)
        if calls & NETWORK_HELPERS or any(
            call.startswith("socket.create_connection") for call in calls
        ):
            network_bearing.add(node.name)
    if marked != EXPECTED_LOOPBACK_TESTS:
        errors.append("simulator loopback marker set differs from the reviewed exact test set")
    if network_bearing - {"test_server_binds_fixed_numeric_loopback_without_dns"} != marked:
        errors.append("network-bearing simulator tests and exact loopback markers differ")

    policy_tree = ast.parse(
        POLICY_TEST_FILE.read_text(encoding="utf-8"), filename=str(POLICY_TEST_FILE)
    )
    policy_marked = {
        node.name
        for node in policy_tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and MARKER_ATTRIBUTE in _decorators(node)
    }
    if policy_marked != EXPECTED_POLICY_TESTS:
        errors.append("local HTTP policy marker set differs from the reviewed exact test set")

    simulator_root = ROOT / "tests" / "simulator"
    for path in sorted((ROOT / "tests").rglob("*.py")):
        if path in {NETWORK_TEST_FILE, POLICY_TEST_FILE, GUARD_TEST_FILE}:
            continue
        source = path.read_text(encoding="utf-8")
        if MARKER_ATTRIBUTE in source:
            errors.append(f"{path.relative_to(ROOT)}: simulator loopback marker forged")
        tree = ast.parse(source, filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call = _attribute(node.func)
                if call in FORBIDDEN_DYNAMIC_CALLS:
                    errors.append(f"{path.relative_to(ROOT)}: dynamic escape call in tests")
    try:
        NETWORK_TEST_FILE.relative_to(simulator_root)
    except ValueError:
        errors.append("reviewed network simulator test is outside tests/simulator")
    return errors


def _test_escape_errors() -> list[str]:
    errors: list[str] = []
    paths = list((ROOT / "tests").rglob("*.py"))
    paths.extend((ROOT / "packages").glob("*/tests/**/*.py"))
    for path in sorted(set(paths)):
        relative = path.relative_to(ROOT).as_posix()
        allowed = TEST_IMPORT_ALLOWLIST.get(relative, set())
        imported = _imports(path)
        violations = {
            forbidden
            for forbidden in TEST_ESCAPE_IMPORTS
            if forbidden not in allowed
            and any(name == forbidden or name.startswith(f"{forbidden}.") for name in imported)
        }
        if violations:
            errors.append(f"{relative}: unreviewed test network/process/dynamic import")
    return errors


def test_import_violations(path: Path) -> set[str]:
    """Return denied escape imports for an unreviewed test source."""

    imported = _imports(path)
    return {
        forbidden
        for forbidden in TEST_ESCAPE_IMPORTS
        if any(name == forbidden or name.startswith(f"{forbidden}.") for name in imported)
    }


def check() -> list[str]:
    errors: list[str] = []
    if PLUGIN not in CONFTEST.read_text(encoding="utf-8"):
        errors.append("root pytest configuration does not load the network guard")
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    if "simulator_loopback: permit numeric 127.0.0.1 TCP" not in pyproject:
        errors.append("exact simulator loopback marker registration is missing")
    errors.extend(_runtime_errors())
    errors.extend(_simulator_marker_errors())
    errors.extend(_test_escape_errors())
    return errors


def main() -> int:
    errors = check()
    if errors:
        print("\n".join(errors))
        return 1
    print("Network source guard passed: pytest deny harness and loopback markers are exact.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
