"""Static denial surface for the networkless AUTH-001A adapter."""

from __future__ import annotations

import ast
import inspect
from dataclasses import fields
from pathlib import Path
from typing import Any, get_type_hints

from mycogni.adapters.auth import SqliteAuthDecisionStore
from mycogni.adapters.auth.sqlite import _RECORD_TYPES, _V1_RECORD_FIELDS
from mycogni.application.auth import AuthDecisionStore

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


def test_durable_store_public_decision_api_has_no_variadic_or_any_types() -> None:
    for name, protocol_method in AuthDecisionStore.__dict__.items():
        if name.startswith("_") or not callable(protocol_method):
            continue
        method = getattr(SqliteAuthDecisionStore, name)
        signature = inspect.signature(method)
        assert all(
            parameter.kind not in {inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD}
            for parameter in signature.parameters.values()
        )
        hints = get_type_hints(method)
        assert Any not in hints.values()


def test_operational_record_evolution_cannot_silently_change_v1_wire_fields() -> None:
    assert set(_RECORD_TYPES) == set(_V1_RECORD_FIELDS)
    for record_name, record_type in _RECORD_TYPES.items():
        assert tuple(field.name for field in fields(record_type)) == _V1_RECORD_FIELDS[record_name]
