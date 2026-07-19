"""Contract tests for persisted key bindings and provider-neutral application types."""

from __future__ import annotations

import copy
import pickle
from dataclasses import replace

import pytest

from mycogni.application.keys import (
    ActiveKekRef,
    KeyReadiness,
    KeyReadinessState,
    ProfileDekHandle,
    ProfileKeyBinding,
    SecretFailureCode,
    SecretProviderError,
    SourceStatus,
    WrappedProfileKey,
    WrappedReadinessSentinel,
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
BINDING = ProfileKeyBinding(
    installation_id=_id("10000000-0000-4000-8000-000000000003"),
    profile_id=_id("10000000-0000-4000-8000-000000000004"),
    profile_key_version=1,
    catalog_schema_version=1,
)
WRAPPED = WrappedProfileKey(
    kek_ref=KEK_REF,
    binding=BINDING,
    nonce=b"n" * 12,
    ciphertext=b"c" * 48,
)
SENTINEL = WrappedReadinessSentinel(
    kek_ref=KEK_REF,
    installation_id=BINDING.installation_id,
    catalog_id=_id("10000000-0000-4000-8000-000000000005"),
    sentinel_id=_id("10000000-0000-4000-8000-000000000006"),
    nonce=b"s" * 12,
    ciphertext=b"t" * 48,
)


def test_wrapped_profile_key_persists_every_binding_and_redacts() -> None:
    rendered = repr(WRAPPED)

    assert WRAPPED.binding == BINDING
    assert WRAPPED.suite == "A256GCM"
    assert WRAPPED.format_version == 1
    assert WRAPPED.aad_version == 1
    assert "nnnn" not in rendered
    assert "cccc" not in rendered
    assert str(BINDING.profile_id) not in rendered
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


def test_dedicated_sentinel_is_strict_redacted_and_a_distinct_type() -> None:
    assert type(SENTINEL) is WrappedReadinessSentinel
    assert type(SENTINEL) is not type(WRAPPED)
    assert "ssss" not in repr(SENTINEL)
    assert "tttt" not in repr(SENTINEL)
    with pytest.raises(ValueError, match="sentinel format"):
        replace(SENTINEL, format_version=2)


def test_source_readability_and_installation_readiness_are_separate() -> None:
    ready = KeyReadiness(KeyReadinessState.READY, SourceStatus.READABLE)
    recovery = KeyReadiness(KeyReadinessState.RECOVERY_REQUIRED, SourceStatus.UNAVAILABLE)

    assert ready.state is KeyReadinessState.READY
    assert ready.source_status is SourceStatus.READABLE
    assert recovery.state is KeyReadinessState.RECOVERY_REQUIRED
    assert "ready" not in {status.value for status in SourceStatus}


def test_profile_key_handle_allows_exactly_one_callback_and_auto_closes() -> None:
    issuer = object()
    retained_views: list[memoryview] = []
    retained_copies: list[bytes] = []
    handle = ProfileDekHandle(
        b"p" * 32,
        _issuer_token=issuer,
        _issuer_check=lambda token, pid: token is issuer and pid > 0,
    )

    with handle as active:

        def retain(view: memoryview) -> int:
            retained_views.append(view)
            retained_copies.append(bytes(view))
            return len(view)

        assert active.use(retain) == 32
        with pytest.raises(RuntimeError, match="not available"):
            active.use(bytes)

    assert bytes(retained_views[0]) == b"\x00" * 32
    assert retained_copies[0] == b"p" * 32
    # The retained immutable copy proves best-effort backing-buffer scrubbing is not zeroization.


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
    error = SecretProviderError(SecretFailureCode.CATALOG_KEY_MISMATCH)

    assert str(error) == "secret provider failed closed (catalog_key_mismatch)"
    assert "material" not in repr(error).lower()


def test_secret_port_has_only_readiness_gated_provider_neutral_operations() -> None:
    public = {name for name in SecretPort.__dict__ if not name.startswith("_")}
    assert public >= {
        "active_kek",
        "source_status",
        "readiness",
        "create_profile_key",
        "unwrap_profile_key",
    }
    assert not any("read_kek" in name or "export" in name for name in public)
