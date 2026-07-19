"""Typed ports for the pure runner-mailbox application slice."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from services.runner_mailbox.domain import (
    ActionBinding,
    ClaimedAction,
    CommittedBundle,
    CrashPoint,
    EvidenceSeal,
    EvidenceUpload,
    MailboxSnapshot,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class CredentialDigester(Protocol):
    def digest(self, credential: bytes) -> bytes: ...


class CredentialSource(Protocol):
    def issue(self) -> bytes: ...


class FailureInjector(Protocol):
    def hit(self, point: CrashPoint) -> None: ...


class MailboxRepository(Protocol):
    """Each time-sensitive operation samples ``clock`` after taking its lock."""

    def create(
        self,
        binding: ActionBinding,
        action_credential_digest: bytes,
        claim_credential_digest: bytes,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot: ...

    def offer(
        self,
        binding: ActionBinding,
        envelope_json: bytes,
        action_key: bytearray,
        action_credential_digest: bytes,
        collection_credential_digest: bytes,
        result_credential: bytearray,
        result_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot: ...

    def claim(
        self,
        binding: ActionBinding,
        claim_credential_digest: bytes,
        clock: Clock,
    ) -> ClaimedAction: ...

    def stage_evidence(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        evidence: EvidenceUpload,
        clock: Clock,
    ) -> MailboxSnapshot:
        """Atomically authenticate-wrap payload before any persistent retention."""
        ...

    def commit_result(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        result_json: bytes,
        evidence_seals: tuple[EvidenceSeal, ...],
        clock: Clock,
    ) -> MailboxSnapshot:
        """Atomically authenticate-wrap the full canonical result before retention."""
        ...

    def collect(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> CommittedBundle:
        """Authenticate and unwrap only for idempotent trusted-core delivery."""
        ...

    def acknowledge_collection(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot: ...

    def abandon(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot: ...

    def expire(self, maintenance_credential_digest: bytes, clock: Clock) -> tuple[UUID, ...]: ...

    def garbage_collect(
        self,
        maintenance_credential_digest: bytes,
        clock: Clock,
    ) -> tuple[UUID, ...]: ...

    def snapshot(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot: ...
