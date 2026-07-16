"""Framework-independent core contract tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from mycogni.application import Clock, UnitOfWork
from mycogni.domain import Ciphertext, OpaqueId, OptimisticVersion, Redacted, Sensitive

ID_TEXT = "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c"


@pytest.mark.governance_acceptance
def test_opaque_id_requires_canonical_uuid4() -> None:
    identifier = OpaqueId.parse(ID_TEXT)
    assert str(identifier) == ID_TEXT
    assert OpaqueId.new().value.version == 4
    with pytest.raises(ValueError):
        OpaqueId.parse("550e8400-e29b-11d4-a716-446655440000")
    with pytest.raises(ValueError):
        OpaqueId.parse(ID_TEXT.upper())


@pytest.mark.parametrize("value", [ID_TEXT, 1, b"uuid", None])
def test_opaque_id_rejects_non_uuid_runtime_values(value: object) -> None:
    with pytest.raises(TypeError, match="opaque ID value must be a UUID"):
        OpaqueId(cast(UUID, value))


def test_sensitive_and_ciphertext_rendering_never_contains_payload() -> None:
    sensitive = Sensitive("synthetic-secret", category="email")
    assert "synthetic-secret" not in str(sensitive)
    assert "synthetic-secret" not in repr(sensitive)
    assert sensitive.reveal() == "synthetic-secret"
    redacted: Redacted[str] = sensitive.redacted()
    assert str(redacted) == "[REDACTED:email]"

    ciphertext = Ciphertext(
        payload=b"synthetic-ciphertext",
        algorithm="aes-256-gcm",
        key_id=OpaqueId(UUID(ID_TEXT)),
        nonce=b"synthetic-nonce",
        aad_version=1,
    )
    assert "synthetic-ciphertext" not in repr(ciphertext)
    assert "synthetic-nonce" not in repr(ciphertext)
    assert ID_TEXT not in repr(ciphertext)
    assert str(ciphertext) == "[REDACTED:ciphertext]"


@pytest.mark.parametrize(
    "category",
    [
        "",
        "Email",
        "email address",
        "email:spoof",
        "email\nforged-log-line",
        "email\rforged-log-line",
        "email\x1b[31m",
        "a" * 65,
    ],
)
def test_redaction_category_rejects_log_injection(category: str) -> None:
    with pytest.raises(ValueError, match="lowercase ASCII slug"):
        Sensitive("synthetic-secret", category=category)
    with pytest.raises(ValueError, match="lowercase ASCII slug"):
        Redacted[object](category=category)


def test_safe_redaction_category_renders_as_one_fixed_line() -> None:
    sensitive = Sensitive("synthetic-secret", category="identity_email")
    assert str(sensitive) == "[REDACTED:identity_email]"
    assert "\n" not in str(sensitive)
    assert "\x1b" not in repr(sensitive)
    category_attribute = "category"
    with pytest.raises(AttributeError):
        setattr(sensitive, category_attribute, "email\nforged-log-line")


@pytest.mark.parametrize("value", [bytearray(b"ciphertext"), "ciphertext", memoryview(b"x")])
def test_ciphertext_payload_requires_exact_bytes(value: object) -> None:
    with pytest.raises(TypeError, match="ciphertext payload must be bytes"):
        Ciphertext(
            payload=cast(bytes, value),
            algorithm="aes-256-gcm",
            key_id=OpaqueId(UUID(ID_TEXT)),
            nonce=b"synthetic-nonce",
            aad_version=1,
        )


@pytest.mark.parametrize("value", [bytearray(b"nonce"), "nonce", memoryview(b"x")])
def test_ciphertext_nonce_requires_exact_bytes(value: object) -> None:
    with pytest.raises(TypeError, match="ciphertext nonce must be bytes"):
        Ciphertext(
            payload=b"synthetic-ciphertext",
            algorithm="aes-256-gcm",
            key_id=OpaqueId(UUID(ID_TEXT)),
            nonce=cast(bytes, value),
            aad_version=1,
        )


@pytest.mark.parametrize("value", [UUID(ID_TEXT), ID_TEXT, 1, None])
def test_ciphertext_key_id_requires_exact_opaque_id(value: object) -> None:
    with pytest.raises(TypeError, match="ciphertext key_id must be an OpaqueId"):
        Ciphertext(
            payload=b"synthetic-ciphertext",
            algorithm="aes-256-gcm",
            key_id=cast(OpaqueId, value),
            nonce=b"synthetic-nonce",
            aad_version=1,
        )


@pytest.mark.parametrize("value", [True, 1.0, "1", None])
def test_ciphertext_aad_version_requires_exact_int(value: object) -> None:
    with pytest.raises(TypeError, match="ciphertext AAD version must be an integer"):
        Ciphertext(
            payload=b"synthetic-ciphertext",
            algorithm="aes-256-gcm",
            key_id=OpaqueId(UUID(ID_TEXT)),
            nonce=b"synthetic-nonce",
            aad_version=cast(int, value),
        )


def test_ciphertext_rejects_nonpositive_aad_version() -> None:
    with pytest.raises(ValueError, match="ciphertext AAD version must be positive"):
        Ciphertext(
            payload=b"synthetic-ciphertext",
            algorithm="aes-256-gcm",
            key_id=OpaqueId(UUID(ID_TEXT)),
            nonce=b"synthetic-nonce",
            aad_version=0,
        )


def test_optimistic_version_is_nonnegative_and_monotonic() -> None:
    assert OptimisticVersion(0).next() == OptimisticVersion(1)
    with pytest.raises(ValueError):
        OptimisticVersion(-1)


@pytest.mark.parametrize("value", [True, 1.0, "1", None])
def test_optimistic_version_requires_exact_int(value: object) -> None:
    with pytest.raises(TypeError, match="optimistic version must be an integer"):
        OptimisticVersion(cast(int, value))


class _Clock:
    def now(self) -> datetime:
        return datetime(2030, 1, 1, tzinfo=UTC)


class _UnitOfWork:
    def __enter__(self) -> _UnitOfWork:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None


def test_application_ports_are_structural_and_runtime_checkable() -> None:
    assert isinstance(_Clock(), Clock)
    assert isinstance(_UnitOfWork(), UnitOfWork)
