"""Contract tests for provider-neutral profile-key application types."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace

import pytest

from mycogni.application.keys import (
    ActiveKekRef,
    ProfileDekHandle,
    ProfileKeyContext,
    SecretFailureCode,
    SecretProviderError,
    WrappedProfileKey,
)
from mycogni.application.ports import SecretPort
from mycogni.domain import OpaqueId


def _id(value: str) -> OpaqueId:
    return OpaqueId.parse(value)


KEK_REF = ActiveKekRef(
    provider_kind="owner-file",
    provider_instance_id=_id("10000000-0000-4000-8000-000000000001"),
    kek_id=_id("10000000-0000-4000-8000-000000000002"),
    kek_version=1,
)
CONTEXT = ProfileKeyContext(
    installation_id=_id("10000000-0000-4000-8000-000000000003"),
    profile_id=_id("10000000-0000-4000-8000-000000000004"),
    profile_key_version=1,
    catalog_schema_version=1,
)
WRAPPED = WrappedProfileKey(
    kek_ref=KEK_REF,
    profile_id=CONTEXT.profile_id,
    profile_key_version=1,
    nonce=b"n" * 12,
    ciphertext=b"c" * 48,
)


def test_wrapped_profile_key_is_exact_and_redacted() -> None:
    rendered = repr(WRAPPED)

    assert WRAPPED.suite == "A256GCM"
    assert WRAPPED.format_version == 1
    assert WRAPPED.aad_version == 1
    assert "nnnn" not in rendered
    assert "cccc" not in rendered
    assert str(CONTEXT.profile_id) not in rendered
    assert str(KEK_REF.kek_id) not in rendered
    assert str(WRAPPED) == "[REDACTED:wrapped-profile-key]"


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"format_version": 2}, "format version"),
        ({"aad_version": 2}, "AAD version"),
        ({"suite": "aesgcm"}, "suite"),
        ({"nonce": b"short"}, "exactly 12"),
        ({"ciphertext": b"short"}, "exactly 48"),
    ],
)
def test_malformed_wrapped_records_are_unrepresentable(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        replace(WRAPPED, **changes)


def test_profile_key_handle_requires_context_and_is_one_use() -> None:
    issuer = object()
    handle = ProfileDekHandle(
        b"p" * 32,
        _issuer_token=issuer,
        _issuer_check=lambda token, pid: token is issuer and pid > 0,
    )

    with pytest.raises(RuntimeError, match="not active"):
        handle.use(bytes)
    with handle as active:
        assert active.use(bytes) == b"p" * 32
        assert "pppp" not in repr(active)
    with pytest.raises(RuntimeError, match="not available"):
        handle.use(bytes)
    with pytest.raises(RuntimeError, match="not available"):
        handle.__enter__()


def test_profile_key_handle_rejects_foreign_issuer_fork_copy_and_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from mycogni.application import keys

    issuer = object()
    accepted = True

    def issuer_check(token: object, _pid: int) -> bool:
        return accepted and token is issuer

    handle = ProfileDekHandle(
        b"p" * 32,
        _issuer_token=issuer,
        _issuer_check=issuer_check,
    )
    current_pid = keys.os.getpid()

    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(handle)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(handle)
    monkeypatch.setattr(keys.os, "getpid", lambda: current_pid + 1)
    with pytest.raises(RuntimeError, match="not available"):
        handle.__enter__()
    monkeypatch.setattr(keys.os, "getpid", lambda: current_pid)
    accepted = False
    with pytest.raises(RuntimeError, match="not available"):
        handle.__enter__()


def test_secret_provider_errors_are_finite_and_redacted() -> None:
    error = SecretProviderError(SecretFailureCode.AUTHENTICATION_FAILED)

    assert str(error) == "secret provider failed closed (authentication_failed)"
    assert "key" not in repr(error).lower()


def test_secret_port_has_no_raw_kek_operation() -> None:
    assert set(SecretPort.__dict__) >= {
        "active_kek",
        "status",
        "create_profile_key",
        "unwrap_profile_key",
        "check_readiness",
    }
    assert not any("read_kek" in name or "export" in name for name in SecretPort.__dict__)
