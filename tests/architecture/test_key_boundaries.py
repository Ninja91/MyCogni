"""Executable boundary checks for the SPIKE-KEY M0 slice."""

from __future__ import annotations

import ast
from pathlib import Path

from mycogni.application.ports import SecretPort

REPOSITORY_ROOT = Path(__file__).parents[2]
KEY_ADAPTER_ROOT = REPOSITORY_ROOT / "src" / "mycogni" / "adapters" / "keys"
SOURCE_ROOT = REPOSITORY_ROOT / "src" / "mycogni"
KEY_CATALOG_BOOTSTRAP = SOURCE_ROOT / "bootstrap" / "key_catalog.py"


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
        "prepare_profile_key",
        "complete_profile_key",
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


def test_owner_file_administration_is_not_reexported_or_imported_by_routine_layers() -> None:
    package_tree = ast.parse((KEY_ADAPTER_ROOT / "__init__.py").read_text(encoding="utf-8"))
    exported_names = {
        element.value
        for node in ast.walk(package_tree)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "__all__" for target in node.targets)
        and isinstance(node.value, (ast.Tuple, ast.List))
        for element in node.value.elts
        if isinstance(element, ast.Constant) and isinstance(element.value, str)
    }
    assert exported_names == {"OwnerFileSecretProvider"}

    admin_importers: set[Path] = set()
    for path in SOURCE_ROOT.rglob("*.py"):
        if path == KEY_ADAPTER_ROOT / "owner_file_admin.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if any(
            isinstance(node, ast.ImportFrom)
            and node.module == "mycogni.adapters.keys.owner_file_admin"
            for node in ast.walk(tree)
        ):
            admin_importers.add(path.relative_to(REPOSITORY_ROOT))
    assert admin_importers == {Path("src/mycogni/bootstrap/key_catalog.py")}


def test_routine_key_catalog_composition_cannot_call_administration_helpers() -> None:
    tree = ast.parse(
        KEY_CATALOG_BOOTSTRAP.read_text(encoding="utf-8"),
        filename=str(KEY_CATALOG_BOOTSTRAP),
    )
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    admin_helpers = {"create_readiness_sentinel", "read_source_commitment"}

    for routine_name in {"compose_native_key_catalog", "reconcile_native_profile_key"}:
        called_names = {
            node.func.id
            for node in ast.walk(functions[routine_name])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert called_names.isdisjoint(admin_helpers)


def test_native_composition_is_sealed_to_owned_catalog_and_owner_file_provider() -> None:
    tree = ast.parse(
        KEY_CATALOG_BOOTSTRAP.read_text(encoding="utf-8"),
        filename=str(KEY_CATALOG_BOOTSTRAP),
    )
    constructed_provider_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id.endswith("SecretProvider")
    }
    assert constructed_provider_names == {"OwnerFileSecretProvider"}

    composition_functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name
        in {
            "compose_native_key_catalog",
            "initialize_native_key_catalog",
            "resume_native_key_catalog_initialization",
            "reconcile_native_profile_key",
            "reconcile_native_key_catalog_initialization",
        }
    }
    assert len(composition_functions) == 5
    for function in composition_functions.values():
        exact_catalog_checks = [
            node
            for node in ast.walk(function)
            if isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Call)
            and isinstance(node.left.func, ast.Name)
            and node.left.func.id == "type"
            and len(node.left.args) == 1
            and isinstance(node.left.args[0], ast.Name)
            and node.left.args[0].id == "catalog"
            and any(
                isinstance(comparator, ast.Name) and comparator.id == "SqliteKeyCatalog"
                for comparator in node.comparators
            )
        ]
        assert exact_catalog_checks
