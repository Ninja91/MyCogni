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
    """Injected deterministic UTC clock."""

    def now(self) -> datetime:
        """Return the current aware UTC instant."""


class CredentialDigester(Protocol):
    """One-way digest port for high-entropy one-action credentials."""

    def digest(self, credential: bytes) -> bytes:
        """Return a domain-separated digest without retaining the credential."""


class CredentialSource(Protocol):
    """Injected source of independently random one-action credentials."""

    def issue(self) -> bytes:
        """Return a new credential with at least 256 bits of entropy."""


class FailureInjector(Protocol):
    """Test-only crash hook at named atomic transition edges."""

    def hit(self, point: CrashPoint) -> None:
        """Return normally or raise a synthetic crash."""


class MailboxRepository(Protocol):
    """Atomic storage operations required by the mailbox application service."""

    def create(
        self,
        binding: ActionBinding,
        claim_credential_digest: bytes,
        collection_credential_digest: bytes,
        now: datetime,
    ) -> MailboxSnapshot: ...

    def offer(
        self,
        binding: ActionBinding,
        envelope_json: bytes,
        action_key: bytearray,
        result_credential: bytearray,
        result_credential_digest: bytes,
        now: datetime,
    ) -> MailboxSnapshot: ...

    def claim(
        self,
        binding: ActionBinding,
        claim_credential_digest: bytes,
        now: datetime,
    ) -> ClaimedAction: ...

    def stage_evidence(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        evidence: EvidenceUpload,
        now: datetime,
    ) -> MailboxSnapshot: ...

    def commit_result(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        result_json: bytes,
        evidence_seals: tuple[EvidenceSeal, ...],
        now: datetime,
    ) -> MailboxSnapshot: ...

    def collect(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
    ) -> CommittedBundle: ...

    def abandon(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        now: datetime,
    ) -> MailboxSnapshot: ...

    def expire(self, now: datetime) -> tuple[UUID, ...]: ...

    def snapshot(self, mailbox_id: UUID) -> MailboxSnapshot: ...
