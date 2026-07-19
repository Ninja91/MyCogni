"""Synthetic reserved-domain fixtures for the pure runner mailbox."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from services.runner_mailbox import (
    ActionBinding,
    RunnerMailboxService,
    Sha256CredentialDigester,
    VolatileMailboxRepository,
)

MAILBOX_ID = "1bea5f8c-166c-46a1-ac72-99bbdd1720d1"
ACTION_ID = "2cb84782-ad9f-47ab-9fa1-7487ad1ff40c"
INTENT_ID = "00ef8ac4-3f2a-4ab7-8c7f-4b50e4d902bd"
ATTEMPT_ID = "26fc0371-5b37-4452-8569-95564cc83edb"
PROFILE_ID = "93cb45b8-843f-4af1-8642-d70903d0919f"
EVIDENCE_ID = "470c0e4b-ce29-4eb5-8a1f-dd672e342fac"
ARTIFACT_DIGEST = "sha256:" + "a" * 64
CLAIM_CREDENTIAL = b"c" * 32
COLLECTION_CREDENTIAL = b"o" * 32
ACTION_KEY = b"k" * 32
RESULT_CREDENTIAL = b"r" * 32
MAINTENANCE_CREDENTIAL = b"m" * 32


@dataclass(slots=True)
class FakeClock:
    current: datetime

    def now(self) -> datetime:
        return self.current


@dataclass(frozen=True, slots=True)
class FixedCredentialSource:
    value: bytes = RESULT_CREDENTIAL

    def issue(self) -> bytes:
        return self.value


def encode(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(datetime(2030, 1, 1, tzinfo=UTC))


@pytest.fixture
def action_payload() -> dict[str, Any]:
    return {
        "protocol_version": 1,
        "action_id": ACTION_ID,
        "intent_id": INTENT_ID,
        "attempt_id": ATTEMPT_ID,
        "fence": 0,
        "authorization_epoch": 0,
        "capability": "observe",
        "connector_release": "synthetic-people-search@0.1.0",
        "profile_ref": PROFILE_ID,
        "attributes": [{"attribute_type": "name", "ciphertext": "sealed-synthetic-value"}],
        "allowed_origins": ["https://broker.example.test"],
        "deadline_utc": "2030-01-01T00:05:00Z",
        "attempt": 0,
        "budget": {"wall_seconds": 30, "response_bytes": 4096},
    }


@pytest.fixture
def action_json(action_payload: dict[str, Any]) -> bytes:
    return encode(action_payload)


@pytest.fixture
def repository() -> VolatileMailboxRepository:
    return VolatileMailboxRepository(
        maintenance_credential_digest=Sha256CredentialDigester().digest(MAINTENANCE_CREDENTIAL)
    )


@pytest.fixture
def service(
    repository: VolatileMailboxRepository,
    clock: FakeClock,
) -> RunnerMailboxService:
    return RunnerMailboxService(
        repository,
        clock,
        Sha256CredentialDigester(),
        FixedCredentialSource(),
    )


@pytest.fixture
def binding(service: RunnerMailboxService, action_json: bytes) -> ActionBinding:
    from uuid import UUID

    return service.bind_action(
        UUID(MAILBOX_ID),
        action_json,
        selected_artifact_digest=ARTIFACT_DIGEST,
        dispatch_epoch=0,
        claim_deadline_utc=datetime(2030, 1, 1, 0, 1, tzinfo=UTC),
    )


@pytest.fixture
def offered(
    service: RunnerMailboxService,
    binding: ActionBinding,
    action_json: bytes,
) -> RunnerMailboxService:
    service.open_empty(
        binding,
        action_credential=ACTION_KEY,
        claim_credential=CLAIM_CREDENTIAL,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    service.offer(
        binding,
        action_json,
        action_key=ACTION_KEY,
        collection_credential=COLLECTION_CREDENTIAL,
    )
    return service
