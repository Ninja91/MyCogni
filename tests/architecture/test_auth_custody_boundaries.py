"""Static boundary checks for AUTH-001B custody."""

from __future__ import annotations

import ast
from pathlib import Path

from mycogni.adapters.auth.owner_file_custody import (
    OwnerFileAuthCustody,
    OwnerFileAuthCustodyProvisioner,
)
from mycogni.application.auth_custody import AuthCustodyPort, AuthCustodyProvisioner
from mycogni.application.ports import SecretPort

ROOT = Path(__file__).parents[2]
ADAPTER = ROOT / "src/mycogni/adapters/auth/owner_file_custody.py"


def test_runtime_and_admin_surfaces_are_structurally_disjoint() -> None:
    runtime_public = {name for name in OwnerFileAuthCustody.__dict__ if not name.startswith("_")}
    admin_public = {
        name for name in OwnerFileAuthCustodyProvisioner.__dict__ if not name.startswith("_")
    }
    assert runtime_public == {"status", "load"}
    assert admin_public == {"provision_empty"}
    assert isinstance(OwnerFileAuthCustody, type)
    assert isinstance(OwnerFileAuthCustodyProvisioner, type)
    assert {name for name in AuthCustodyPort.__dict__ if not name.startswith("_")} == {
        "status",
        "load",
    }
    assert "provision_empty" in AuthCustodyProvisioner.__dict__
    assert "status" not in AuthCustodyProvisioner.__dict__
    assert "load" not in AuthCustodyProvisioner.__dict__


def test_auth_custody_is_not_added_to_profile_key_secret_port() -> None:
    public = {name for name in SecretPort.__dict__ if not name.startswith("_")}
    assert "load" not in public
    assert "provision_empty" not in public
    assert "read_secret" not in public


def test_runtime_adapter_has_no_discovery_fallback_or_external_surface() -> None:
    tree = ast.parse(ADAPTER.read_text(encoding="utf-8"))
    imports = {
        alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports.isdisjoint(
        {"json", "socket", "subprocess", "keyring", "sqlite3", "browser", "entrypoints"}
    )
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert calls.isdisjoint({"getenv", "chmod", "replace", "unlink", "rename"})
