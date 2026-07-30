"""Static containment and distribution checks for AUTH-001C."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "src/mycogni/adapters/auth/posix_operator_terminal.py"
CONTRACT = ROOT / "src/mycogni/application/operator_terminal.py"


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_terminal_runtime_has_no_fallback_or_external_surface() -> None:
    forbidden = {
        "asyncio",
        "browser",
        "getpass",
        "httpx",
        "keyring",
        "logging",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    assert _imports(ADAPTER).isdisjoint(forbidden)
    source = ADAPTER.read_text(encoding="utf-8")
    for fragment in ("os.environ", "sys.argv", "sys.stdin", "sys.stdout", "sys.stderr"):
        assert fragment not in source


def test_terminal_contract_is_application_owned_and_adapter_is_distributed() -> None:
    contract = CONTRACT.read_text(encoding="utf-8")
    assert "class OperatorTerminal(Protocol)" in contract
    assert "def check_ready(self) -> None" in contract
    tracked = {path.relative_to(ROOT).as_posix() for path in (ROOT / "src/mycogni").rglob("*.py")}
    assert "src/mycogni/adapters/auth/posix_operator_terminal.py" in tracked
