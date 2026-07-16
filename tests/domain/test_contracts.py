"""Framework-independent core contract tests."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from mycogni.application import Clock, UnitOfWork
from mycogni.domain import Ciphertext, OpaqueId, OptimisticVersion, Redacted, Sensitive

ID_TEXT = "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c"


def test_opaque_id_requires_canonical_uuid4() -> None:
    identifier = OpaqueId.parse(ID_TEXT)
    assert str(identifier) == ID_TEXT
    assert OpaqueId.new().value.version == 4
    with pytest.raises(ValueError):
        OpaqueId.parse("550e8400-e29b-11d4-a716-446655440000")
    with pytest.raises(ValueError):
        OpaqueId.parse(ID_TEXT.upper())


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
    assert str(ciphertext) == "[REDACTED:ciphertext]"


def test_optimistic_version_is_nonnegative_and_monotonic() -> None:
    assert OptimisticVersion(0).next() == OptimisticVersion(1)
    with pytest.raises(ValueError):
        OptimisticVersion(-1)
    with pytest.raises(ValueError):
        OptimisticVersion(cast(int, True))


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
