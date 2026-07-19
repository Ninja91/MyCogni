"""Finite, lock-serialized reference repository for SPIKE-RUNNER.

This adapter is intentionally volatile. It demonstrates transactional semantics,
authenticated at-rest wrapping, quotas, two-phase collection and bounded GC; it
does not demonstrate durable storage, restart recovery, OS isolation or secure
Python heap erasure.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.runner_mailbox.domain import (
    MAX_EVIDENCE_ITEMS,
    ActionBinding,
    ClaimedAction,
    CollectionState,
    CommittedBundle,
    CrashPoint,
    EvidenceSeal,
    EvidenceUpload,
    MailboxDenial,
    MailboxError,
    MailboxLimits,
    MailboxSnapshot,
    MailboxState,
)
from services.runner_mailbox.ports import Clock, FailureInjector

_CREDENTIAL_CONTEXT = b"mycogni.runner-mailbox.credential.v1\x00"
_WRAP_CONTEXT = b"mycogni.runner-mailbox.evidence-wrap.v1\x00"


def _validated_utc_now(clock: Clock) -> datetime:
    now = clock.now()
    if type(now) is not datetime or now.utcoffset() != UTC.utcoffset(now):
        raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
    return now


class Sha256CredentialDigester:
    """Digest uniformly random action credentials; this is not a password KDF."""

    def digest(self, credential: bytes) -> bytes:
        return hashlib.sha256(_CREDENTIAL_CONTEXT + credential).digest()


class SystemCredentialSource:
    def issue(self) -> bytes:
        return secrets.token_bytes(32)


class NoFailureInjector:
    def hit(self, point: CrashPoint) -> None:
        del point


@dataclass(slots=True)
class _WrappedEvidence:
    object_id: UUID
    kind: str
    payload_digest: str
    byte_count: int
    nonce: bytes = field(repr=False)
    wrapped_payload: bytes = field(repr=False)


@dataclass(slots=True)
class _Record:
    binding: ActionBinding
    created_at: datetime
    last_seen_utc: datetime
    action_credential_digest: bytes = field(repr=False)
    claim_credential_digest: bytes = field(repr=False)
    collection_credential_digest: bytes = field(repr=False)
    state: MailboxState = MailboxState.EMPTY
    collection_state: CollectionState = CollectionState.NONE
    envelope_json: bytes | None = field(default=None, repr=False)
    action_key: bytearray | None = field(default=None, repr=False)
    result_credential: bytearray | None = field(default=None, repr=False)
    result_credential_digest: bytes | None = field(default=None, repr=False)
    evidence: dict[UUID, _WrappedEvidence] = field(default_factory=dict, repr=False)
    result_json: bytes | None = field(default=None, repr=False)
    committed_at: datetime | None = None
    terminal_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class _Tombstone:
    created_at: datetime
    expires_at: datetime


def _wipe(value: bytearray | None) -> None:
    if value is not None:
        value[:] = b"\x00" * len(value)


class VolatileMailboxRepository:
    """One-process reference semantics with finite installation capacity."""

    def __init__(
        self,
        failure_injector: FailureInjector | None = None,
        *,
        maintenance_credential_digest: bytes | None = None,
        limits: MailboxLimits | None = None,
        storage_key: bytes | None = None,
    ) -> None:
        self._records: dict[UUID, _Record] = {}
        self._tombstones: dict[UUID, _Tombstone] = {}
        self._lock = RLock()
        self._failure = failure_injector or NoFailureInjector()
        self._maintenance_credential_digest = bytes(
            maintenance_credential_digest or secrets.token_bytes(32)
        )
        self._limits = limits or MailboxLimits()
        key = storage_key or AESGCM.generate_key(bit_length=256)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("storage_key must be exactly 32 bytes")
        self._aead = AESGCM(key)
        self._total_evidence_bytes = 0
        self._total_committed_bytes = 0

    def create(
        self,
        binding: ActionBinding,
        action_credential_digest: bytes,
        claim_credential_digest: bytes,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            now = _validated_utc_now(clock)
            if binding.mailbox_id in self._records:
                raise MailboxError(MailboxDenial.ALREADY_EXISTS)
            if binding.mailbox_id in self._tombstones:
                raise MailboxError(MailboxDenial.REPLAY)
            if len(self._records) >= self._limits.max_mailboxes:
                raise MailboxError(MailboxDenial.QUOTA_EXCEEDED)
            if (
                len(
                    {
                        action_credential_digest,
                        claim_credential_digest,
                        collection_credential_digest,
                    }
                )
                != 3
            ):
                raise MailboxError(MailboxDenial.INVALID_INPUT)
            if any(
                self._credential_in_use(digest)
                for digest in (
                    action_credential_digest,
                    claim_credential_digest,
                    collection_credential_digest,
                )
            ):
                raise MailboxError(MailboxDenial.REPLAY)
            if now >= binding.claim_deadline_utc:
                raise MailboxError(MailboxDenial.EXPIRED)
            record = _Record(
                binding=binding,
                created_at=now,
                last_seen_utc=now,
                action_credential_digest=bytes(action_credential_digest),
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
        action_credential_digest: bytes,
        collection_credential_digest: bytes,
        result_credential: bytearray,
        result_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            try:
                record = self._record(binding.mailbox_id)
                now = self._validated_record_now(record, clock)
                self._require_binding(record, binding)
                self._require_credential(
                    record.collection_credential_digest, collection_credential_digest
                )
                self._require_credential(record.action_credential_digest, action_credential_digest)
                if (
                    len(
                        {
                            record.action_credential_digest,
                            record.claim_credential_digest,
                            record.collection_credential_digest,
                            result_credential_digest,
                        }
                    )
                    != 4
                ):
                    raise MailboxError(MailboxDenial.INVALID_INPUT)
                if self._credential_in_use(
                    result_credential_digest, excluding=record.binding.mailbox_id
                ):
                    raise MailboxError(MailboxDenial.REPLAY)
                if self._expire_if_due(record, now):
                    raise MailboxError(MailboxDenial.EXPIRED)
                if record.state is not MailboxState.EMPTY:
                    raise MailboxError(MailboxDenial.REPLAY)
                record.envelope_json = bytes(envelope_json)
                record.action_key = bytearray(action_key)
                record.result_credential = bytearray(result_credential)
                record.result_credential_digest = bytes(result_credential_digest)
                record.state = MailboxState.OFFERED
                record.last_seen_utc = now
                return self._snapshot(record)
            finally:
                _wipe(action_key)
                _wipe(result_credential)

    def claim(
        self,
        binding: ActionBinding,
        claim_credential_digest: bytes,
        clock: Clock,
    ) -> ClaimedAction:
        with self._lock:
            record = self._record(binding.mailbox_id)
            now = self._validated_record_now(record, clock)
            self._require_credential(record.claim_credential_digest, claim_credential_digest)
            self._require_binding(record, binding)
            if self._expire_if_due(record, now):
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
            record.last_seen_utc = now
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
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._record(binding.mailbox_id)
            now = self._validated_record_now(record, clock)
            self._require_result_access(record, binding, result_credential_digest)
            if self._expire_if_due(record, now):
                raise MailboxError(MailboxDenial.EXPIRED)
            if evidence.object_id in record.evidence:
                raise MailboxError(MailboxDenial.REPLAY)
            if len(record.evidence) >= MAX_EVIDENCE_ITEMS:
                raise MailboxError(MailboxDenial.EVIDENCE_LIMIT)
            aggregate = self._record_evidence_bytes(record)
            if aggregate + len(evidence.payload) > record.binding.response_bytes:
                raise MailboxError(MailboxDenial.EVIDENCE_LIMIT)
            if (
                self._total_evidence_bytes + len(evidence.payload)
                > self._limits.max_total_evidence_bytes
            ):
                raise MailboxError(MailboxDenial.QUOTA_EXCEEDED)
            nonce = secrets.token_bytes(12)
            aad = self._aad(
                binding.mailbox_id, evidence.object_id, evidence.kind, evidence.payload_digest
            )
            wrapped = self._aead.encrypt(nonce, evidence.payload, aad)
            item = _WrappedEvidence(
                object_id=evidence.object_id,
                kind=evidence.kind,
                payload_digest=evidence.payload_digest,
                byte_count=len(evidence.payload),
                nonce=nonce,
                wrapped_payload=wrapped,
            )
            self._failure.hit(CrashPoint.BEFORE_EVIDENCE_COMMIT)
            record.evidence[evidence.object_id] = item
            record.last_seen_utc = now
            self._total_evidence_bytes += item.byte_count
            self._failure.hit(CrashPoint.AFTER_EVIDENCE_COMMIT)
            return self._snapshot(record)

    def commit_result(
        self,
        binding: ActionBinding,
        result_credential_digest: bytes,
        result_json: bytes,
        evidence_seals: tuple[EvidenceSeal, ...],
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._record(binding.mailbox_id)
            now = self._validated_record_now(record, clock)
            self._require_result_access(record, binding, result_credential_digest)
            if self._expire_if_due(record, now):
                raise MailboxError(MailboxDenial.EXPIRED)
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
                    or item.payload_digest != seal.payload_digest
                    or item.byte_count != seal.byte_count
                ):
                    raise MailboxError(MailboxDenial.DIGEST_MISMATCH)
            response_bytes = len(result_json) + self._record_evidence_bytes(record)
            if response_bytes > record.binding.response_bytes:
                raise MailboxError(MailboxDenial.EVIDENCE_LIMIT)
            if (
                self._total_committed_bytes + response_bytes
                > self._limits.max_total_committed_bytes
            ):
                raise MailboxError(MailboxDenial.QUOTA_EXCEEDED)
            self._failure.hit(CrashPoint.BEFORE_RESULT_COMMIT)
            record.result_json = bytes(result_json)
            record.state = MailboxState.RESULT_COMMITTED
            record.collection_state = CollectionState.READY
            record.result_credential_digest = None
            record.committed_at = now
            record.last_seen_utc = now
            self._total_committed_bytes += response_bytes
            self._failure.hit(CrashPoint.AFTER_RESULT_COMMIT)
            return self._snapshot(record)

    def collect(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> CommittedBundle:
        with self._lock:
            record = self._record(mailbox_id)
            now = self._validated_record_now(record, clock)
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            if record.collection_state is CollectionState.ACKNOWLEDGED:
                raise MailboxError(MailboxDenial.REPLAY)
            if record.state is not MailboxState.RESULT_COMMITTED or record.result_json is None:
                raise MailboxError(MailboxDenial.INVALID_STATE)
            if record.collection_state not in {CollectionState.READY, CollectionState.DELIVERING}:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            evidence = tuple(
                self._unwrap(record.binding.mailbox_id, item) for item in record.evidence.values()
            )
            record.collection_state = CollectionState.DELIVERING
            record.last_seen_utc = now
            return CommittedBundle(
                binding=record.binding, result_json=record.result_json, evidence=evidence
            )

    def acknowledge_collection(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._record(mailbox_id)
            now = self._validated_record_now(record, clock)
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            if record.collection_state is CollectionState.ACKNOWLEDGED:
                return self._snapshot(record)
            if (
                record.state is not MailboxState.RESULT_COMMITTED
                or record.collection_state is not CollectionState.DELIVERING
            ):
                raise MailboxError(MailboxDenial.INVALID_STATE)
            self._failure.hit(CrashPoint.BEFORE_COLLECTION_ACK)
            self._release_record_payloads(record)
            record.collection_state = CollectionState.ACKNOWLEDGED
            record.terminal_at = now
            record.last_seen_utc = now
            self._failure.hit(CrashPoint.AFTER_COLLECTION_ACK)
            return self._snapshot(record)

    def abandon(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._record(mailbox_id)
            now = self._validated_record_now(record, clock)
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            if self._expire_if_due(record, now):
                raise MailboxError(MailboxDenial.EXPIRED)
            if record.state not in {
                MailboxState.EMPTY,
                MailboxState.OFFERED,
                MailboxState.CLAIMED_ONCE,
            }:
                raise MailboxError(MailboxDenial.INVALID_STATE)
            self._clear_action_material(record)
            record.state = MailboxState.ABANDONED
            record.terminal_at = now
            record.last_seen_utc = now
            return self._snapshot(record)

    def expire(self, maintenance_credential_digest: bytes, clock: Clock) -> tuple[UUID, ...]:
        with self._lock:
            self._require_maintenance(maintenance_credential_digest)
            sampled = [
                (record, self._validated_record_now(record, clock))
                for record in self._records.values()
            ]
            expired: list[UUID] = []
            for record, now in sampled:
                if self._expire_if_due(record, now):
                    expired.append(record.binding.mailbox_id)
                else:
                    record.last_seen_utc = now
            return tuple(sorted(expired, key=str))

    def garbage_collect(
        self, maintenance_credential_digest: bytes, clock: Clock
    ) -> tuple[UUID, ...]:
        with self._lock:
            self._require_maintenance(maintenance_credential_digest)
            now = _validated_utc_now(clock)
            for record in self._records.values():
                if now < record.last_seen_utc:
                    raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            removed: list[UUID] = []
            for mailbox_id, record in tuple(self._records.items()):
                terminal_due = (
                    record.terminal_at is not None
                    and now - record.terminal_at >= self._limits.terminal_retention
                )
                uncollected_due = (
                    record.committed_at is not None
                    and record.collection_state is not CollectionState.ACKNOWLEDGED
                    and now - record.committed_at >= self._limits.uncollected_retention
                )
                if terminal_due or uncollected_due:
                    self._discard_record(record)
                    del self._records[mailbox_id]
                    self._tombstones[mailbox_id] = _Tombstone(
                        created_at=now, expires_at=now + self._limits.tombstone_retention
                    )
                    removed.append(mailbox_id)
            for mailbox_id, tombstone in tuple(self._tombstones.items()):
                if tombstone.expires_at <= now:
                    del self._tombstones[mailbox_id]
            if len(self._tombstones) > self._limits.max_tombstones:
                oldest = sorted(
                    self._tombstones,
                    key=lambda item: (self._tombstones[item].created_at, str(item)),
                )
                for mailbox_id in oldest[: len(self._tombstones) - self._limits.max_tombstones]:
                    del self._tombstones[mailbox_id]
            return tuple(sorted(removed, key=str))

    def snapshot(self, mailbox_id: UUID, collection_credential_digest: bytes) -> MailboxSnapshot:
        with self._lock:
            record = self._record(mailbox_id)
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            return self._snapshot(record)

    def _record(self, mailbox_id: UUID) -> _Record:
        try:
            return self._records[mailbox_id]
        except KeyError:
            if mailbox_id in self._tombstones:
                raise MailboxError(MailboxDenial.REPLAY) from None
            raise MailboxError(MailboxDenial.NOT_FOUND) from None

    def _credential_in_use(self, digest: bytes, *, excluding: UUID | None = None) -> bool:
        for mailbox_id, record in self._records.items():
            if mailbox_id == excluding:
                continue
            if any(
                value is not None and hmac.compare_digest(value, digest)
                for value in (
                    record.action_credential_digest,
                    record.claim_credential_digest,
                    record.collection_credential_digest,
                    record.result_credential_digest,
                )
            ):
                return True
        return False

    @staticmethod
    def _require_credential(expected: bytes, presented: bytes) -> None:
        if not hmac.compare_digest(expected, presented):
            raise MailboxError(MailboxDenial.UNAUTHORIZED)

    def _require_maintenance(self, presented: bytes) -> None:
        self._require_credential(self._maintenance_credential_digest, presented)

    @staticmethod
    def _require_binding(record: _Record, presented: ActionBinding) -> None:
        if record.binding != presented:
            raise MailboxError(MailboxDenial.BINDING_MISMATCH)

    def _require_result_access(
        self, record: _Record, binding: ActionBinding, result_credential_digest: bytes
    ) -> None:
        self._require_binding(record, binding)
        if record.state is not MailboxState.CLAIMED_ONCE:
            raise MailboxError(MailboxDenial.REPLAY)
        if record.result_credential_digest is None:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        self._require_credential(record.result_credential_digest, result_credential_digest)

    @staticmethod
    def _validated_record_now(record: _Record, clock: Clock) -> datetime:
        now = _validated_utc_now(clock)
        if now < record.last_seen_utc:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return now

    def _expire_if_due(self, record: _Record, now: datetime) -> bool:
        if record.state is MailboxState.EXPIRED:
            return True
        deadline = (
            record.binding.claim_deadline_utc
            if record.state in {MailboxState.EMPTY, MailboxState.OFFERED}
            else record.binding.deadline_utc
        )
        if (
            record.state in {MailboxState.EMPTY, MailboxState.OFFERED, MailboxState.CLAIMED_ONCE}
            and now >= deadline
        ):
            self._clear_action_material(record)
            record.state = MailboxState.EXPIRED
            record.terminal_at = now
            record.last_seen_utc = now
            return True
        return False

    def _clear_action_material(self, record: _Record) -> None:
        self._clear_claim_delivery_material(record)
        record.result_credential_digest = None
        self._release_record_payloads(record)

    @staticmethod
    def _clear_claim_delivery_material(record: _Record) -> None:
        _wipe(record.action_key)
        _wipe(record.result_credential)
        record.action_key = None
        record.result_credential = None
        record.envelope_json = None

    def _release_record_payloads(self, record: _Record) -> None:
        evidence_bytes = self._record_evidence_bytes(record)
        committed_bytes = (
            len(record.result_json) if record.result_json is not None else 0
        ) + evidence_bytes
        self._total_evidence_bytes -= evidence_bytes
        if record.committed_at is not None:
            self._total_committed_bytes -= committed_bytes
        record.result_json = None
        record.evidence.clear()

    def _discard_record(self, record: _Record) -> None:
        self._clear_claim_delivery_material(record)
        record.result_credential_digest = None
        self._release_record_payloads(record)

    @staticmethod
    def _record_evidence_bytes(record: _Record) -> int:
        return sum(item.byte_count for item in record.evidence.values())

    @staticmethod
    def _aad(mailbox_id: UUID, object_id: UUID, kind: str, payload_digest: str) -> bytes:
        return (
            _WRAP_CONTEXT
            + mailbox_id.bytes
            + object_id.bytes
            + kind.encode()
            + b"\x00"
            + payload_digest.encode()
        )

    def _unwrap(self, mailbox_id: UUID, item: _WrappedEvidence) -> EvidenceUpload:
        aad = self._aad(mailbox_id, item.object_id, item.kind, item.payload_digest)
        try:
            payload = self._aead.decrypt(item.nonce, item.wrapped_payload, aad)
        except InvalidTag:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None
        if (
            len(payload) != item.byte_count
            or "sha256:" + hashlib.sha256(payload).hexdigest() != item.payload_digest
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return EvidenceUpload(
            object_id=item.object_id,
            kind=item.kind,
            payload_digest=item.payload_digest,
            payload=payload,
        )

    @staticmethod
    def _snapshot(record: _Record) -> MailboxSnapshot:
        return MailboxSnapshot(
            mailbox_id=record.binding.mailbox_id,
            state=record.state,
            collection_state=record.collection_state,
            staged_evidence_count=len(record.evidence),
            staged_evidence_bytes=sum(item.byte_count for item in record.evidence.values()),
            result_present=record.result_json is not None,
            claim_material_retained=record.action_key is not None
            or record.envelope_json is not None,
            result_credential_material_retained=record.result_credential is not None,
        )
