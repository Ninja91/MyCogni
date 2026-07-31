"""Focused tests for explicit empty-install readiness-sentinel creation."""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest

from mycogni.adapters.keys.owner_file import OWNER_KEY_FILE_HEADER, OwnerFileSecretProvider
from mycogni.adapters.keys.owner_file_admin import (
    create_readiness_sentinel,
    read_source_commitment,
)
from mycogni.application.key_catalog import KeyCatalogIdentity
from mycogni.application.keys import (
    ActiveKekRef,
    KeyReadinessState,
    SecretFailureCode,
    SecretProviderError,
)
from mycogni.domain import OpaqueId


def _id(value: str) -> OpaqueId:
    return OpaqueId.parse(value)


IDENTITY = KeyCatalogIdentity(
    installation_id=_id("71000000-0000-4000-8000-000000000001"),
    catalog_id=_id("71000000-0000-4000-8000-000000000002"),
    sentinel_id=_id("71000000-0000-4000-8000-000000000003"),
    active_kek=ActiveKekRef(
        provider_kind="owner-file",
        provider_instance_id=_id("71000000-0000-4000-8000-000000000004"),
        kek_id=_id("71000000-0000-4000-8000-000000000005"),
        kek_version=1,
    ),
    usage_limit=100,
)


@pytest.fixture
def owner_source(tmp_path: Path) -> tuple[Path, Path]:
    key_dir = tmp_path / "keys"
    key_dir.mkdir(mode=0o700)
    key_path = key_dir / "installation.kek"
    key_path.write_bytes(OWNER_KEY_FILE_HEADER + b"k" * 32)
    key_path.chmod(0o600)
    managed = tmp_path / "data"
    managed.mkdir(mode=0o700)
    return key_path, managed


def test_admin_wraps_reserved_nonce_and_runtime_authenticates_it(
    owner_source: tuple[Path, Path],
) -> None:
    key_path, managed = owner_source
    before = (key_path.stat(), key_path.read_bytes())
    commitment = read_source_commitment(key_path=key_path, managed_roots=(managed,))
    sentinel = create_readiness_sentinel(
        key_path=key_path,
        identity=IDENTITY,
        reserved_nonce=b"s" * 12,
        expected_source_commitment=commitment,
        managed_roots=(managed,),
    )

    assert sentinel.nonce == b"s" * 12
    assert sentinel.installation_id == IDENTITY.installation_id
    assert (key_path.stat(), key_path.read_bytes()) == before
    provider = OwnerFileSecretProvider(
        key_path=key_path,
        active_kek=IDENTITY.active_kek,
        installation_id=IDENTITY.installation_id,
        catalog_id=IDENTITY.catalog_id,
        sentinel_id=IDENTITY.sentinel_id,
        readiness_sentinel=sentinel,
        managed_roots=(managed,),
    )
    assert provider.readiness().state is KeyReadinessState.READY


@pytest.mark.parametrize("nonce", [b"short", b"n" * 13, bytearray(b"n" * 12)])
def test_admin_rejects_non_exact_reserved_nonce(
    owner_source: tuple[Path, Path], nonce: object
) -> None:
    key_path, managed = owner_source
    before = key_path.read_bytes()
    commitment = read_source_commitment(key_path=key_path, managed_roots=(managed,))
    with pytest.raises((TypeError, ValueError), match="nonce"):
        create_readiness_sentinel(
            key_path=key_path,
            identity=IDENTITY,
            reserved_nonce=nonce,  # type: ignore[arg-type]
            expected_source_commitment=commitment,
            managed_roots=(managed,),
        )
    assert key_path.read_bytes() == before


@pytest.mark.parametrize("condition", ["missing", "mode", "symlink", "overlap"])
def test_admin_fails_closed_without_repairing_source(
    owner_source: tuple[Path, Path], condition: str
) -> None:
    key_path, managed = owner_source
    original = key_path.read_bytes()
    commitment = read_source_commitment(key_path=key_path, managed_roots=(managed,))
    if condition == "missing":
        key_path.unlink()
    elif condition == "mode":
        key_path.chmod(0o644)
    elif condition == "symlink":
        target = key_path.with_suffix(".real")
        key_path.rename(target)
        key_path.symlink_to(target)
    elif condition == "overlap":
        managed = key_path.parent

    with pytest.raises(SecretProviderError) as caught:
        create_readiness_sentinel(
            key_path=key_path,
            identity=IDENTITY,
            reserved_nonce=b"s" * 12,
            expected_source_commitment=commitment,
            managed_roots=(managed,),
        )
    assert caught.value.code in {
        SecretFailureCode.UNAVAILABLE,
        SecretFailureCode.UNSAFE_STORAGE,
    }
    assert str(key_path) not in str(caught.value)
    if condition == "missing":
        assert not key_path.exists()
    elif condition == "mode":
        assert key_path.read_bytes() == original
        assert key_path.stat().st_mode & 0o777 == 0o644
    elif condition == "symlink":
        assert key_path.is_symlink()


def test_admin_module_has_no_persistence_environment_or_mutation_channel() -> None:
    path = Path(__file__).parents[3] / "src/mycogni/adapters/keys/owner_file_admin.py"
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not any(module.startswith("mycogni.adapters.persistence") for module in imports)
    assert not calls.intersection(
        {"write_bytes", "write_text", "chmod", "unlink", "rename", "replace", "mkdir"}
    )
    assert "environ" not in calls and "getenv" not in calls


def test_admin_error_rendering_never_discloses_path_or_key(
    owner_source: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path, managed = owner_source
    secret = key_path.read_bytes()
    commitment = read_source_commitment(key_path=key_path, managed_roots=(managed,))
    monkeypatch.setattr(os, "readv", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()))
    with pytest.raises(SecretProviderError) as caught:
        create_readiness_sentinel(
            key_path=key_path,
            identity=IDENTITY,
            reserved_nonce=b"s" * 12,
            expected_source_commitment=commitment,
            managed_roots=(managed,),
        )
    rendered = f"{caught.value!s} {caught.value!r}"
    assert str(key_path) not in rendered
    assert secret.hex() not in rendered
