"""Representation and fail-closed invariants for synthetic auth values."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest

from mycogni.domain import OpaqueId, Sensitive
from mycogni.domain.auth import (
    AUTH_SECRET_CATEGORY,
    DEFAULT_RECOVERY_SECONDS,
    PURPOSE_SCOPE,
    RECOVERY_MAX_SECONDS,
    RECOVERY_MIN_SECONDS,
    AuthDenial,
    AuthorityGrant,
    AuthOutcome,
    AuthPolicy,
    AuthPurpose,
    AuthScope,
    OpaqueCredential,
    RecoveryRecord,
    RootCapabilityRecord,
    RootPurpose,
    SecretDigest,
    SessionRecord,
)

NOW = datetime(2030, 1, 1, tzinfo=UTC)


def _material(counter: int = 1) -> bytes:
    return hashlib.sha256(counter.to_bytes(16, "big")).digest()


def test_opaque_credential_round_trip_is_canonical_and_redacted() -> None:
    credential = OpaqueCredential.from_secret(OpaqueId.new(), _material())
    parsed = OpaqueCredential.parse_operator_code(credential.operator_code())
    assert parsed.handle == credential.handle
    assert parsed.secret.reveal() == credential.secret.reveal()
    assert credential.operator_code() not in repr(credential)
    assert str(credential) == "[REDACTED:auth_secret]"


@pytest.mark.parametrize("value", ["", "not-a-code", "a.b", "a.b.c", "x" * 129])
def test_malformed_credentials_raise_only_a_generic_error(value: str) -> None:
    with pytest.raises(ValueError, match="^malformed opaque credential$") as captured:
        OpaqueCredential.parse_operator_code(value)
    if value:
        assert value not in str(captured.value)


def test_credential_requires_typed_opaque_id_category_and_entropy() -> None:
    with pytest.raises(TypeError, match="OpaqueId"):
        OpaqueCredential.from_secret("id", _material())  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="at least 256 bits"):
        OpaqueCredential.from_secret(OpaqueId.new(), _material()[:16])
    with pytest.raises(ValueError, match="wrong category"):
        OpaqueCredential(
            handle=OpaqueId.new(),
            secret=Sensitive(_material(), category="wrong_category"),
        )
    assert AUTH_SECRET_CATEGORY == "auth_secret"


def test_secret_digest_has_a_fixed_non_rendering_shape() -> None:
    digest = SecretDigest(_material())
    assert digest.value == _material()
    assert _material().hex() not in repr(digest)
    with pytest.raises(ValueError, match="SHA-256"):
        SecretDigest(_material()[:16])


def test_purpose_scope_mapping_cannot_be_mutated_at_runtime() -> None:
    with pytest.raises(TypeError):
        PURPOSE_SCOPE[AuthPurpose.PROFILE_DELETION] = AuthScope.RESTORE_DESTRUCTIVELY  # type: ignore[index]
    assert PURPOSE_SCOPE[AuthPurpose.PROFILE_DELETION] is AuthScope.DELETE_PROFILE


@pytest.mark.parametrize(
    "policy",
    [
        AuthPolicy(bootstrap_ttl_seconds=1),
        AuthPolicy(max_attempts=1),
        AuthPolicy(activation_delay_seconds=60),
        AuthPolicy(recovery_ttl_seconds=RECOVERY_MIN_SECONDS),
        AuthPolicy(recovery_ttl_seconds=RECOVERY_MAX_SECONDS),
    ],
)
def test_policy_accepts_reviewed_bounds(policy: AuthPolicy) -> None:
    assert policy.max_attempts >= 1
    assert AuthPolicy().recovery_ttl_seconds == DEFAULT_RECOVERY_SECONDS


@pytest.mark.parametrize(
    "arguments",
    [
        {"bootstrap_ttl_seconds": 0},
        {"session_ttl_seconds": 604_801},
        {"activation_delay_seconds": -1},
        {"max_attempts": 11},
        {"recovery_ttl_seconds": RECOVERY_MIN_SECONDS - 1},
        {"recovery_ttl_seconds": RECOVERY_MAX_SECONDS + 1},
    ],
)
def test_policy_rejects_unbounded_values(arguments: dict[str, int]) -> None:
    with pytest.raises(ValueError):
        AuthPolicy(**arguments)  # type: ignore[arg-type]


def test_auth_outcome_requires_exactly_one_value_or_denial() -> None:
    assert AuthOutcome.allowed("ok").value == "ok"
    assert AuthOutcome.denied(AuthDenial.EXPIRED).denial is AuthDenial.EXPIRED
    with pytest.raises(ValueError, match="exactly one"):
        AuthOutcome[str]()
    with pytest.raises(ValueError, match="exactly one"):
        AuthOutcome(value="ok", denial=AuthDenial.EXPIRED)


def test_authority_grant_requires_exact_scope_utc_window_and_positive_epoch() -> None:
    common = {
        "actor_id": OpaqueId.new(),
        "represented_profile_id": OpaqueId.new(),
        "session_id": OpaqueId.new(),
        "authority_evidence_id": OpaqueId.new(),
        "purpose": AuthPurpose.PROFILE_DELETION,
        "scopes": frozenset({AuthScope.DELETE_PROFILE}),
        "not_before_utc": NOW,
        "expires_at_utc": NOW + timedelta(seconds=1),
        "epoch": 1,
    }
    grant = AuthorityGrant(**common)  # type: ignore[arg-type]
    assert grant.scopes == frozenset({AuthScope.DELETE_PROFILE})
    with pytest.raises(ValueError, match="scope must exactly match"):
        AuthorityGrant(**{**common, "scopes": frozenset({AuthScope.RESTORE_DESTRUCTIVELY})})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="aware UTC"):
        AuthorityGrant(**{**common, "not_before_utc": datetime(2030, 1, 1)})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="aware UTC"):
        AuthorityGrant(**{**common, "not_before_utc": NOW.astimezone(timezone(timedelta(hours=1)))})  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="positive"):
        AuthorityGrant(**{**common, "epoch": 0})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("record_type", "flag_name"),
    [
        (RootCapabilityRecord, "consumed"),
        (SessionRecord, "revoked"),
        (RecoveryRecord, "consumed"),
    ],
)
def test_mutable_records_require_exact_boolean_state_and_utc_retirement(
    record_type: type[object], flag_name: str
) -> None:
    common: dict[str, object] = {
        "handle": OpaqueId.new(),
        "actor_id": OpaqueId.new(),
        "represented_profile_id": OpaqueId.new(),
        "digest": SecretDigest(_material()),
    }
    if record_type is RootCapabilityRecord:
        common.update(installation_id=OpaqueId.new(), purpose=RootPurpose.INITIAL_BOOTSTRAP)
    else:
        common.update(
            epoch=1,
            not_before_utc=NOW,
            expires_at_utc=NOW + timedelta(days=365),
        )
    if record_type is RecoveryRecord:
        common["attempts_remaining"] = 5
    with pytest.raises(TypeError, match="state flag must be boolean"):
        record_type(**{**common, flag_name: 1})  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="aware UTC"):
        record_type(  # type: ignore[call-arg]
            **{**common, "retired_at_utc": datetime(2030, 1, 1)}
        )
