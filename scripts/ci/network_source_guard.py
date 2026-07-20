"""Static fail-closed checks for the NET-001 pytest network boundary."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).parents[2]
PYPROJECT = ROOT / "pyproject.toml"
CONFTEST = ROOT / "tests" / "conftest.py"
PACKAGE_CONFTEST = ROOT / "packages" / "mycogni-connector-sdk" / "tests" / "conftest.py"
MAKEFILE = ROOT / "Makefile"
AUTHORITY_REGISTRY = ROOT / "ci" / "network-loopback-authority.json"
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
PROCESS_DYNAMIC_CALLS = {
    "__import__",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "builtins.__import__",
    "builtins.compile",
    "builtins.eval",
    "builtins.exec",
    "compile",
    "eval",
    "exec",
    "importlib.import_module",
    "os.execv",
    "os.execve",
    "os.fork",
    "os.popen",
    "os.posix_spawn",
    "os.posix_spawnp",
    "os.spawnl",
    "os.spawnlp",
    "os.spawnv",
    "os.spawnvp",
    "os.system",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.run",
}
RUNTIME_IMPORT_ALLOWLIST = {
    "src/mycogni/adapters/persistence/durability.py": {"subprocess"},
}
CONTAINER_PROBE = (
    "packages/mycogni-runner-mailbox-runtime/src/mycogni_runner_mailbox_runtime/container_probe.py"
)
REVIEWED_RUNTIME_IMPORT_ALLOWLIST = {
    # Synthetic-only OCI containment probe; not imported by the mailbox service.
    CONTAINER_PROBE: (
        {"socket"},
        "0d349a164a0b0207e94af1cd2a11978a666718e00d7bd02b611ad0256f669d82",
    ),
}
TEST_IMPORT_ALLOWLIST = {
    "tests/ci/test_network_guard.py": TEST_ESCAPE_IMPORTS,
    "tests/simulator/test_network_guard_simulator.py": {"httpx", "socket"},
    "tests/simulator/test_web_mail_safety.py": {"socket"},
    "tests/ci/test_governance_traceability.py": {"subprocess"},
    "tests/ci/test_toolchain_guards.py": {"subprocess"},
    "tests/architecture/test_distribution_boundaries.py": {"subprocess"},
    "tests/architecture/test_container_skeleton.py": {"importlib"},
    "tests/architecture/test_package_boundaries.py": {"importlib"},
    "tests/architecture/test_runner_containment.py": {"importlib", "subprocess"},
    "tests/architecture/test_browser_containment.py": {"importlib", "subprocess"},
    "tests/adapters/persistence/test_durability.py": {"subprocess"},
}
PROCESS_CALL_ALLOWLIST = {
    "tests/ci/test_network_guard.py",
    "tests/ci/test_governance_traceability.py",
    "tests/ci/test_toolchain_guards.py",
    "tests/architecture/test_distribution_boundaries.py",
    "tests/architecture/test_container_skeleton.py",
    "tests/architecture/test_package_boundaries.py",
    "tests/adapters/persistence/test_durability.py",
    "tests/adapters/keys/test_owner_file.py",
    "tests/simulator/test_web_mail_safety.py",
}
EXACT_PROCESS_CALL_ALLOWLIST = {
    "tests/architecture/test_browser_containment.py": {"subprocess.run"},
    "tests/architecture/test_runner_containment.py": {"subprocess.run"},
    "tests/runner_mailbox/test_persistent.py": {"os.fork"},
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


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                bound = item.asname or item.name.partition(".")[0]
                aliases[bound] = item.name if item.asname else item.name.partition(".")[0]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    return aliases


def _canonical_calls(tree: ast.AST) -> set[str]:
    aliases = _import_aliases(tree)
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call = _attribute(node.func)
        head, separator, tail = call.partition(".")
        canonical_head = aliases.get(head, head)
        calls.add(f"{canonical_head}.{tail}" if separator else canonical_head)
    return calls


def _decorators(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {_attribute(item) for item in function.decorator_list}


def _calls(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    return {_attribute(node.func) for node in ast.walk(function) if isinstance(node, ast.Call)}


def _ast_sha256(node: ast.AST) -> str:
    try:
        canonical = ast.dump(
            node,
            annotate_fields=True,
            include_attributes=False,
            show_empty=True,
        )
    except TypeError:  # Python 3.12 always includes empty optional fields.
        canonical = ast.dump(node, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


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


def reviewed_runtime_import_provenance_valid(path: Path, relative: str) -> bool:
    """Return whether an exact runtime import exemption matches its reviewed bytes."""

    review = REVIEWED_RUNTIME_IMPORT_ALLOWLIST.get(relative)
    if review is None:
        return True
    _, expected_sha256 = review
    return hashlib.sha256(path.read_bytes()).hexdigest() == expected_sha256


def runtime_import_violations(path: Path, relative: str) -> set[str]:
    """Return runtime imports not exempted by exact path and reviewed provenance."""

    allowed = set(RUNTIME_IMPORT_ALLOWLIST.get(relative, set()))
    review = REVIEWED_RUNTIME_IMPORT_ALLOWLIST.get(relative)
    if review is not None and reviewed_runtime_import_provenance_valid(path, relative):
        allowed.update(review[0])
    imported = _imports(path)
    return {
        forbidden
        for forbidden in FORBIDDEN_RUNTIME_IMPORTS
        if forbidden not in allowed
        if any(name == forbidden or name.startswith(f"{forbidden}.") for name in imported)
    }


def _runtime_errors() -> list[str]:
    errors: list[str] = []
    guarded = {
        ROOT / "scripts" / "ci" / "network_guard.py",
        ROOT / "scripts" / "ci" / "network_guard_plugin.py",
        ROOT / "simulator" / "web.py",
    }
    for base in (ROOT / "src", ROOT / "packages", ROOT / "services", ROOT / "simulator"):
        for path in sorted(base.rglob("*.py")):
            if path in guarded or "tests" in path.parts:
                continue
            relative = path.relative_to(ROOT).as_posix()
            if not reviewed_runtime_import_provenance_valid(path, relative):
                errors.append(f"{relative}: reviewed runtime import provenance differs")
            violations = runtime_import_violations(path, relative)
            if violations:
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
        if process_call_violations(path, relative):
            errors.append(f"{relative}: unreviewed test process/dynamic call")
    return errors


def _launcher_errors() -> list[str]:
    errors: list[str] = []
    conftest = CONFTEST.read_text(encoding="utf-8")
    package_conftest = PACKAGE_CONFTEST.read_text(encoding="utf-8")
    if "pytest must run through scripts/ci/guarded_pytest.py" not in conftest:
        errors.append("root pytest guarded-launcher sentinel is missing")
    if "pytest must run through scripts/ci/guarded_pytest.py" not in package_conftest:
        errors.append("package pytest guarded-launcher sentinel is missing")
    makefile = MAKEFILE.read_text(encoding="utf-8")
    pytest_commands = [line for line in makefile.splitlines() if "pytest" in line]
    if not pytest_commands or any(
        "scripts/ci/guarded_pytest.py" not in line for line in pytest_commands
    ):
        errors.append("Makefile contains an unsupported pytest invocation")
    launcher = (ROOT / "scripts" / "ci" / "guarded_pytest.py").read_text(encoding="utf-8")
    required_launcher_controls = {
        '"--disable-plugin-autoload"',
        '"PYTEST_PLUGINS"',
        '"--config-file"',
        '"--inifile"',
        '"--override-ini"',
        '"--plugins"',
        '"_hypothesis_pytestplugin"',
        '"anyio.pytest_plugin"',
        '"pytest_cov.plugin"',
    }
    if any(control not in launcher for control in required_launcher_controls):
        errors.append("guarded launcher plugin/configuration controls are incomplete")
    for relative in (
        "scripts/ci/governance_guard.py",
        "scripts/ci/threat_catalog_guard.py",
    ):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if '"-m", "pytest"' in text or "scripts/ci/guarded_pytest.py" not in text:
            errors.append(f"{relative}: nested pytest invocation bypasses guarded launcher")
    return errors


def _authority_registry_errors() -> list[str]:
    errors: list[str] = []
    try:
        document = json.loads(AUTHORITY_REGISTRY.read_text(encoding="utf-8"))
        nodes = document["authorized_nodes"]
        sources = document["source_sha256"]
        callables = document["callable_provenance"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError):
        return ["network loopback authority registry is unreadable"]
    if (
        set(document)
        != {"schema_version", "source_sha256", "callable_provenance", "authorized_nodes"}
        or document.get("schema_version") != 2
        or nodes != sorted(set(nodes))
        or list(callables) != sorted(callables)
    ):
        errors.append("network loopback authority registry is not canonical")
    for relative, expected in sources.items():
        path = (ROOT / relative).resolve()
        try:
            path.relative_to(ROOT.resolve())
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, ValueError):
            errors.append("network loopback authority source is invalid")
            continue
        if actual != expected:
            errors.append("network loopback authority source digest differs")
    if len(nodes) != 38:
        errors.append("network loopback authority node count differs from reviewed set")
    bases: set[str] = set()
    for nodeid in nodes:
        parts = nodeid.split("::")
        if len(parts) != 2:
            errors.append("network loopback authority node has collector hierarchy")
            continue
        bases.add(f"{parts[0]}::{parts[1].split('[', 1)[0]}")
    if set(callables) != bases or len(callables) != 9:
        errors.append("network callable provenance does not cover exact top-level nodes")
    for nodeid, review in callables.items():
        relative, separator, function_name = nodeid.partition("::")
        if (
            not separator
            or not function_name
            or set(review)
            != {
                "ast_sha256",
                "ast_lineno",
                "code_firstlineno",
                "qualname",
            }
        ):
            errors.append("network callable provenance entry is invalid")
            continue
        path = ROOT / relative
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError):
            errors.append("network callable provenance source is unreadable")
            continue
        matches = [
            node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ]
        if len(matches) != 1:
            errors.append("network callable provenance is not a unique top-level function")
            continue
        function = matches[0]
        ast_digest = _ast_sha256(function)
        if (
            review["ast_sha256"] != ast_digest
            or review["ast_lineno"] != function.lineno
            or review["qualname"] != function_name
            or not isinstance(review["code_firstlineno"], int)
            or MARKER_ATTRIBUTE not in _decorators(function)
        ):
            errors.append("network callable provenance differs from reviewed AST identity")
    return errors


def test_import_violations(path: Path) -> set[str]:
    """Return denied escape imports for an unreviewed test source."""

    imported = _imports(path)
    return {
        forbidden
        for forbidden in TEST_ESCAPE_IMPORTS
        if any(name == forbidden or name.startswith(f"{forbidden}.") for name in imported)
    }


def test_call_violations(path: Path) -> set[str]:
    """Return denied process/dynamic calls for an unreviewed test source."""

    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return _canonical_calls(tree) & PROCESS_DYNAMIC_CALLS


def process_call_violations(path: Path, relative: str) -> set[str]:
    """Return process/dynamic calls outside a path's exact reviewed call set."""

    if relative in PROCESS_CALL_ALLOWLIST:
        return set()
    return test_call_violations(path) - EXACT_PROCESS_CALL_ALLOWLIST.get(relative, set())


def check() -> list[str]:
    errors: list[str] = []
    if "from scripts.ci import network_guard_plugin" not in CONFTEST.read_text(encoding="utf-8"):
        errors.append("root pytest configuration lacks the network guard sentinel")
    pyproject = PYPROJECT.read_text(encoding="utf-8")
    if "simulator_loopback: permit numeric 127.0.0.1 TCP" not in pyproject:
        errors.append("exact simulator loopback marker registration is missing")
    errors.extend(_runtime_errors())
    errors.extend(_simulator_marker_errors())
    errors.extend(_test_escape_errors())
    errors.extend(_launcher_errors())
    errors.extend(_authority_registry_errors())
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
