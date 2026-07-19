"""Executable boundary checks for the SPIKE-KEY M0 slice."""

from __future__ import annotations

import ast
from pathlib import Path

from mycogni.application.ports import SecretPort

REPOSITORY_ROOT = Path(__file__).parents[2]
KEY_ADAPTER_ROOT = REPOSITORY_ROOT / "src" / "mycogni" / "adapters" / "keys"


def test_secret_port_never_exposes_installation_key_material() -> None:
    public_methods = {
        name
        for name, value in SecretPort.__dict__.items()
        if callable(value) and not name.startswith("_")
    }

    assert public_methods == {
        "active_kek",
        "source_status",
        "readiness",
        "create_profile_key",
        "unwrap_profile_key",
    }
    assert all("read_kek" not in method and "export" not in method for method in public_methods)


def test_owner_file_runtime_contains_no_provisioning_or_fallback_channel() -> None:
    path = KEY_ADAPTER_ROOT / "owner_file.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    method_names = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    imported_modules = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    provider_class = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "OwnerFileSecretProvider"
    )
    constructor = next(
        node
        for node in provider_class.body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    )
    constructor_arguments = {
        argument.arg for argument in (*constructor.args.args, *constructor.args.kwonlyargs)
    }
    environment_reads = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "os"
        and node.attr in {"environ", "getenv"}
    }

    assert not method_names.intersection(
        {"create_kek", "provision", "repair", "replace", "discover", "fallback", "export_kek"}
    )
    assert not imported_modules.intersection({"keyring", "subprocess", "socket"})
    assert not constructor_arguments.intersection(
        {"nonce_source", "profile_key_source", "entropy_source"}
    )
    assert not environment_reads


def test_key_adapter_does_not_import_persistence_or_delivery_layers() -> None:
    for path in KEY_ADAPTER_ROOT.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        assert not any(
            module.startswith(
                (
                    "mycogni.adapters.persistence",
                    "mycogni.bootstrap",
                    "mycogni.entrypoints",
                )
            )
            for module in imports
        )
