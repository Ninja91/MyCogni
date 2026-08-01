"""Static boundaries for the synthetic authenticated web precursor."""

from __future__ import annotations

import ast
from pathlib import Path

from mycogni.adapters.web_shell import SECURITY_HEADERS

ROOT = Path(__file__).parents[2]
APPLICATION = ROOT / "src/mycogni/application/web_shell.py"
ADAPTER = ROOT / "src/mycogni/adapters/web_shell.py"
COMPOSITION = ROOT / "src/mycogni/bootstrap/web_shell.py"


def _top_level_imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
    return imports


def test_application_shell_is_framework_and_network_free() -> None:
    assert _top_level_imports(APPLICATION).isdisjoint(
        {"fastapi", "http", "httpx", "requests", "socket", "urllib", "uvicorn"}
    )


def test_web_adapter_carries_required_response_controls() -> None:
    assert SECURITY_HEADERS["Cache-Control"] == "no-store"
    assert SECURITY_HEADERS["X-Frame-Options"] == "DENY"
    assert SECURITY_HEADERS["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in SECURITY_HEADERS["Content-Security-Policy"]
    source = ADAPTER.read_text(encoding="utf-8")
    assert "openapi_url=None" in source
    assert '"Origin"' not in source
    assert 'request.headers.get("origin")' in source


def test_web_composition_is_loopback_only_and_disables_access_logging() -> None:
    source = COMPOSITION.read_text(encoding="utf-8")
    assert 'host="127.0.0.1"' in source
    assert "access_log=False" in source
    assert "log_config=None" in source
    assert "terminal.disclose" in source
    assert 'SecretField("bootstrap-code", bundle.bootstrap_code)' in source
    assert "print(bundle.bootstrap_code" not in source
