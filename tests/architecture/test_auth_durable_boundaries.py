"""Static denial surface for the networkless AUTH-001A adapter."""

from __future__ import annotations

import ast
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
AUTH_SOURCE = REPOSITORY_ROOT / "src/mycogni/adapters/auth/sqlite.py"


def test_durable_auth_adapter_has_no_network_browser_broker_or_pii_surface() -> None:
    tree = ast.parse(AUTH_SOURCE.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".", 1)[0])
    assert imports.isdisjoint(
        {"socket", "http", "httpx", "requests", "urllib", "fastapi", "playwright", "browser_spike"}
    )
    source = AUTH_SOURCE.read_text(encoding="utf-8").casefold()
    assert "broker-registry" not in source
    assert "social_security" not in source
    assert "email_address" not in source


def test_auth_migration_has_no_raw_secret_column() -> None:
    migration = (
        (REPOSITORY_ROOT / "migrations/versions/0002_auth_decision_state.py")
        .read_text(encoding="utf-8")
        .casefold()
    )
    for forbidden in ("credential", "token", "password", "plaintext", "secret_value"):
        assert f'column("{forbidden}' not in migration
