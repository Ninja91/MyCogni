"""Volatile atomic repository for SPIKE-RUNNER protocol and failure evidence.

This adapter is intentionally not durable and is not a production secret store.
Its bytearray erasure narrows ordinary retention but cannot guarantee Python heap,
allocator, swap, crash-dump, or host-memory erasure.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from threading import RLock
from uuid import UUID

from services.runner_mailbox.domain import (
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_ITEMS,
    ActionBinding,
    ClaimedAction,
    CommittedBundle,
    CrashPoint,
    EvidenceSeal,
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
    MailboxSnapshot,
    MailboxState,
)
from services.runner_mailbox.ports import FailureInjector

_CREDENTIAL_CONTEXT = b"mycogni.runner-mailbox.credential.v1\x00"


class Sha256CredentialDigester:
    """Digest independently generated high-entropy action credentials.

    This is not a password KDF. Callers must supply uniformly random credentials
    satisfying the application service's 256-bit minimum.
    """

    def digest(self, credential: bytes) -> bytes:
        return hashlib.sha256(_CREDENTIAL_CONTEXT + credential).digest()


class SystemCredentialSource:
    """Operating-system source for a fresh 256-bit result credential per offer."""

    def issue(self) -> bytes:
        return secrets.token_bytes(32)


class NoFailureInjector:
    """Production-shaped default that never injects a synthetic crash."""

    def hit(self, point: CrashPoint) -> None:
        del point


@dataclass(slots=True)
class _Record:
    binding: ActionBinding
    last_seen_utc: datetime
    claim_credential_digest: bytes = field(repr=False)
    collection_credential_digest: bytes = field(repr=False)
    state: MailboxState = MailboxState.EMPTY
    envelope_json: bytes | None = field(default=None, repr=False)
    action_key: bytearray | None = field(default=None, repr=False)
    result_credential: bytearray | None = field(default=None, repr=False)
    result_credential_digest: bytes | None = field(default=None, repr=False)
    evidence: dict[UUID, EvidenceUpload] = field(default_factory=dict, repr=False)
    result_json: bytes | None = field(default=None, repr=False)
    collected: bool = False


def _wipe(value: bytearray | None) -> None:
    if value is not None:
        value[:] = b"\x00" * len(value)


class VolatileMailboxRepository:
    """Lock-serialized reference semantics for one process and one restart epoch."""

    def __init__(self, failure_injector: FailureInjector | None = None) -> None:
        self._records: dict[UUID, _Record] = {}
        self._lock = RLock()
        self._failure = failure_injector or NoFailureInjector()

    def create(
        self,
        binding: ActionBinding,
        claim_credential_digest: bytes,
        collection_credential_digest: bytes,
        now: datetime,
    ) -> MailboxSnapshot:
        with self._lock:
            if binding.mailbox_id in self._records:
                raise MailboxError(MailboxDenial.ALREADY_EXISTS)
            record = _Record(
                binding=binding,
                last_seen_utc=now,
                claim_credential_digest=bytes(claim_credential_digest),
                collection_credential_digest=bytes(collection_credential_digest),
            )
            self._records[binding.mailbox_id] = record
            return self._snapshot(record)

    def offer(
        self,
        binding: ActionBinding,
        envelope_json: bytes,
        action_key: bytearray,
        result_credential: bytearray,
        result_credential_digest: bytes,
        now: datetime,
    ) -> MailboxSnapshot:
        with self._lock:
            try:
                record = self._authorized_record(binding.mailbox_id)
                self._observe_now(record, now)
                self._expire_if_due(record, now)
                self._require_binding(record, binding)
                if record.state is MailboxState.EXPIRED:
                    raise MailboxError(MailboxDenial.EXPIRED)
                if record.state is not MailboxState.EMPTY:
                    raise MailboxError(MailboxDenial.REPLAY)
                if hmac.compare_digest(
                    record.claim_credential_digest, result_credential_digest
                ) or hmac.compare_digest(
                    record.collection_credential_digest, result_credential_digest
                ):
                    raise MailboxError(MailboxDenial.INVALID_INPUT)
                record.envelope_json = bytes(envelope_json)
                record.action_key = bytearray(action_key)
                record.result_credential = bytearray(result_credential)
                record.result_credential_digest = bytes(result_credential_digest)
                record.state = MailboxState.OFFERED
                return self._snapshot(record)
            finally:
                _wipe(action_key)
                _wipe(result_credential)

    def claim(
        self,
        binding: ActionBinding,
        claim_credential_digest: bytes,
        now: datetime,
    ) -> ClaimedAction:
        with self._lock:
            record = self._authorized_record(binding.mailbox_id)
            self._observe_now(record, now)
            self._expire_if_due(record, now)
            self._require_credential(record.claim_credential_digest, claim_credential_digest)
            self._require_binding(record, binding)
            if record.state is MailboxState.EXPIRED:
                raise MailboxError(MailboxDenial.EXPIRED)
            if record.state is not MailboxState.OFFERED:
                raise MailboxError(MailboxDenial.REPLAY)
            if (
                record.envelope_json is None
                or record.action_key is None
                or record.result_credential is None
            ):
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

            self._failure.hit(CrashPoint.BEFORE_CLAIM_COMMIT)
            record.state = MailboxState.CLAIMED_ONCE
            try:
                self._failure.hit(CrashPoint.AFTER_CLAIM_COMMIT)
                return ClaimedAction(
                    binding=record.binding,
                    envelope_json=record.envelope_json,
                    action_key=bytes(record.action_key),
                    result_credential=bytes(record.result_credential),
                )
            finally:
                self._clear_claim_delivery_material(record)

    def stage_evidence(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        evidence: EvidenceUpload,
        now: datetime,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._authorized_record(binding.mailbox_id)
            self._observe_now(record, now)
            self._expire_if_due(record, now)
            self._require_result_access(record, binding, result_credential_digest)
            if evidence.object_id in record.evidence:
                raise MailboxError(MailboxDenial.REPLAY)
            if len(record.evidence) >= MAX_EVIDENCE_ITEMS:
                raise MailboxError(MailboxDenial.EVIDENCE_LIMIT)
            aggregate = sum(len(item.ciphertext) for item in record.evidence.values())
            if aggregate + len(evidence.ciphertext) > min(
                MAX_EVIDENCE_BYTES, record.binding.response_bytes
            ):
                raise MailboxError(MailboxDenial.EVIDENCE_LIMIT)

            self._failure.hit(CrashPoint.BEFORE_EVIDENCE_COMMIT)
            record.evidence[evidence.object_id] = EvidenceUpload(
                object_id=evidence.object_id,
                kind=evidence.kind,
                ciphertext_digest=evidence.ciphertext_digest,
                ciphertext=bytes(evidence.ciphertext),
            )
            self._failure.hit(CrashPoint.AFTER_EVIDENCE_COMMIT)
            return self._snapshot(record)

    def commit_result(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        result_json: bytes,
        evidence_seals: tuple[EvidenceSeal, ...],
        now: datetime,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._authorized_record(binding.mailbox_id)
            self._observe_now(record, now)
            self._expire_if_due(record, now)
            self._require_result_access(record, binding, result_credential_digest)
            referenced = {seal.object_id for seal in evidence_seals}
            staged = set(record.evidence)
            if referenced - staged:
                raise MailboxError(MailboxDenial.EVIDENCE_MISSING)
            if staged - referenced:
                raise MailboxError(MailboxDenial.EVIDENCE_UNREFERENCED)
            for seal in evidence_seals:
                item = record.evidence[seal.object_id]
                if (
                    item.kind != seal.kind
                    or item.ciphertext_digest != seal.ciphertext_digest
                    or len(item.ciphertext) != seal.byte_count
                ):
                    raise MailboxError(MailboxDenial.DIGEST_MISMATCH)

            self._failure.hit(CrashPoint.BEFORE_RESULT_COMMIT)
            record.result_json = bytes(result_json)
            record.state = MailboxState.RESULT_COMMITTED
            record.result_credential_digest = None
            self._failure.hit(CrashPoint.AFTER_RESULT_COMMIT)
            return self._snapshot(record)

    def collect(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
    ) -> CommittedBundle:
        with self._lock:
            record = self._authorized_record(mailbox_id)
            self._require_credential(
                record.collection_credential_digest,
                collection_credential_digest,
            )
            if record.state is not MailboxState.RESULT_COMMITTED:
                raise MailboxError(MailboxDenial.INVALID_STATE)
            if record.collected:
                raise MailboxError(MailboxDenial.REPLAY)
            if record.result_json is None:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            bundle = CommittedBundle(
                binding=record.binding,
                result_json=record.result_json,
                evidence=tuple(record.evidence.values()),
            )
            record.result_json = None
            record.evidence.clear()
            record.collected = True
            return bundle

    def abandon(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        now: datetime,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._authorized_record(mailbox_id)
            self._observe_now(record, now)
            self._expire_if_due(record, now)
            self._require_credential(
                record.collection_credential_digest,
                collection_credential_digest,
            )
            if record.state is MailboxState.EXPIRED:
                raise MailboxError(MailboxDenial.EXPIRED)
            if record.state not in {
                MailboxState.EMPTY,
                MailboxState.OFFERED,
                MailboxState.CLAIMED_ONCE,
            }:
                raise MailboxError(MailboxDenial.INVALID_STATE)
            self._clear_action_material(record)
            record.state = MailboxState.ABANDONED
            return self._snapshot(record)

    def expire(self, now: datetime) -> tuple[UUID, ...]:
        expired: list[UUID] = []
        with self._lock:
            for record in self._records.values():
                if now < record.last_seen_utc:
                    raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            for mailbox_id, record in self._records.items():
                self._observe_now(record, now)
                if self._expire_if_due(record, now):
                    expired.append(mailbox_id)
        return tuple(sorted(expired, key=str))

    def snapshot(self, mailbox_id: UUID) -> MailboxSnapshot:
        with self._lock:
            return self._snapshot(self._authorized_record(mailbox_id))

    def _authorized_record(self, mailbox_id: UUID) -> _Record:
        try:
            return self._records[mailbox_id]
        except KeyError:
            raise MailboxError(MailboxDenial.NOT_FOUND) from None

    @staticmethod
    def _require_credential(expected: bytes, presented: bytes) -> None:
        if not hmac.compare_digest(expected, presented):
            raise MailboxError(MailboxDenial.UNAUTHORIZED)

    @staticmethod
    def _require_binding(record: _Record, presented: ActionBinding) -> None:
        if record.binding != presented:
            raise MailboxError(MailboxDenial.BINDING_MISMATCH)

    def _require_result_access(
        self,
        record: _Record,
        binding: ActionBinding,
        result_credential_digest: bytes,
    ) -> None:
        self._require_binding(record, binding)
        if record.state is MailboxState.EXPIRED:
            raise MailboxError(MailboxDenial.EXPIRED)
        if record.state is not MailboxState.CLAIMED_ONCE:
            raise MailboxError(MailboxDenial.REPLAY)
        if record.result_credential_digest is None:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        self._require_credential(record.result_credential_digest, result_credential_digest)

    def _expire_if_due(self, record: _Record, now: datetime) -> bool:
        if (
            record.state
            in {
                MailboxState.EMPTY,
                MailboxState.OFFERED,
                MailboxState.CLAIMED_ONCE,
            }
            and now >= record.binding.deadline_utc
        ):
            self._clear_action_material(record)
            record.state = MailboxState.EXPIRED
            return True
        return False

    @staticmethod
    def _observe_now(record: _Record, now: datetime) -> None:
        if now < record.last_seen_utc:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        record.last_seen_utc = now

    @staticmethod
    def _clear_action_material(record: _Record) -> None:
        VolatileMailboxRepository._clear_claim_delivery_material(record)
        record.result_credential_digest = None
        record.result_json = None
        record.evidence.clear()

    @staticmethod
    def _clear_claim_delivery_material(record: _Record) -> None:
        _wipe(record.action_key)
        _wipe(record.result_credential)
        record.action_key = None
        record.result_credential = None
        record.envelope_json = None

    @staticmethod
    def _snapshot(record: _Record) -> MailboxSnapshot:
        return MailboxSnapshot(
            binding=record.binding,
            state=record.state,
            staged_evidence_count=len(record.evidence),
            staged_evidence_bytes=sum(len(item.ciphertext) for item in record.evidence.values()),
            result_present=record.result_json is not None,
            collected=record.collected,
            claim_material_retained=record.action_key is not None
            or record.envelope_json is not None,
            result_credential_material_retained=record.result_credential is not None,
        )
