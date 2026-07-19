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
from pydantic import ValidationError

from connector_protocol import ResultEnvelope
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
_RESULT_WRAP_CONTEXT = b"mycogni.runner-mailbox.result-wrap.v1\x00"
_MANIFEST_CONTEXT = b"mycogni.runner-mailbox.committed-manifest.v1\x00"
_SEMANTIC_MAC_CONTEXT = b"mycogni.runner-mailbox.semantic-mac.v1\x00"
_INNER_DIGEST_BYTES = 32
_INNER_EVIDENCE_ID_BYTES = 16
_INNER_RESULT_BINDING_BYTES = 32


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
    byte_count: int
    storage_digest: bytes = field(repr=False)
    semantic_mac: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    wrapped_payload: bytes = field(repr=False)


@dataclass(slots=True)
class _WrappedResult:
    byte_count: int
    storage_digest: bytes = field(repr=False)
    semantic_mac: bytes = field(repr=False)
    nonce: bytes = field(repr=False)
    wrapped_payload: bytes = field(repr=False)


@dataclass(slots=True)
class _CommittedEvidenceManifest:
    item_count: int
    storage_digest: bytes = field(repr=False)
    semantic_mac: bytes = field(repr=False)


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
    result_envelope: _WrappedResult | None = field(default=None, repr=False)
    committed_evidence_manifest: _CommittedEvidenceManifest | None = field(default=None, repr=False)
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
        maintenance_credential_digest: bytes,
        limits: MailboxLimits | None = None,
        storage_key: bytes | None = None,
    ) -> None:
        self._records: dict[UUID, _Record] = {}
        self._tombstones: dict[UUID, _Tombstone] = {}
        self._lock = RLock()
        self._failure = failure_injector or NoFailureInjector()
        if (
            type(maintenance_credential_digest) is not bytes
            or len(maintenance_credential_digest) != 32
        ):
            raise ValueError("maintenance_credential_digest must be exactly 32 bytes")
        self._maintenance_credential_digest = bytes(maintenance_credential_digest)
        self._limits = limits or MailboxLimits()
        key = storage_key if storage_key is not None else AESGCM.generate_key(bit_length=256)
        if type(key) is not bytes or len(key) != 32:
            raise ValueError("storage_key must be exactly 32 bytes")
        self._aead = AESGCM(key)
        self._semantic_mac_key = hmac.new(key, _SEMANTIC_MAC_CONTEXT, hashlib.sha256).digest()
        self._installation_last_seen_utc: datetime | None = None
        self._total_active_material_bytes = 0
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
            now = self._validated_installation_now(clock)
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
                hmac.compare_digest(self._maintenance_credential_digest, digest)
                for digest in (
                    action_credential_digest,
                    claim_credential_digest,
                    collection_credential_digest,
                )
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
            self._advance_installation_time(now)
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
                self._require_binding(record, binding)
                self._require_credential(
                    record.collection_credential_digest, collection_credential_digest
                )
                self._require_credential(record.action_credential_digest, action_credential_digest)
                self._validated_record_material(record)
                now = self._validated_record_now(record, clock)
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
                if hmac.compare_digest(
                    self._maintenance_credential_digest, result_credential_digest
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
                active_bytes = len(envelope_json) + len(action_key) + len(result_credential)
                if (
                    self._total_active_material_bytes + active_bytes
                    > self._limits.max_total_active_material_bytes
                ):
                    raise MailboxError(MailboxDenial.QUOTA_EXCEEDED)
                record.envelope_json = bytes(envelope_json)
                record.action_key = bytearray(action_key)
                record.result_credential = bytearray(result_credential)
                record.result_credential_digest = bytes(result_credential_digest)
                record.state = MailboxState.OFFERED
                self._observe_time(record, now)
                self._total_active_material_bytes += active_bytes
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
            self._require_credential(record.claim_credential_digest, claim_credential_digest)
            self._require_binding(record, binding)
            self._validated_record_material(record)
            now = self._validated_record_now(record, clock)
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
            self._observe_time(record, now)
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
            self._require_result_access(record, binding, result_credential_digest)
            self._validated_record_material(record)
            now = self._validated_record_now(record, clock)
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
            raw_digest = hashlib.sha256(evidence.payload).digest()
            if "sha256:" + raw_digest.hex() != evidence.payload_digest:
                raise MailboxError(MailboxDenial.DIGEST_MISMATCH)
            nonce = secrets.token_bytes(12)
            aad = self._aad(
                binding.mailbox_id,
                evidence.object_id,
                evidence.object_id,
                evidence.kind,
                len(evidence.payload),
            )
            framed_payload = evidence.object_id.bytes + raw_digest + evidence.payload
            wrapped = self._aead.encrypt(nonce, framed_payload, aad)
            item = _WrappedEvidence(
                object_id=evidence.object_id,
                kind=evidence.kind,
                byte_count=len(evidence.payload),
                storage_digest=hashlib.sha256(wrapped).digest(),
                semantic_mac=self._semantic_mac(aad, framed_payload),
                nonce=nonce,
                wrapped_payload=wrapped,
            )
            self._unwrap(binding.mailbox_id, evidence.object_id, item)
            self._failure.hit(CrashPoint.BEFORE_EVIDENCE_COMMIT)
            record.evidence[evidence.object_id] = item
            self._observe_time(record, now)
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
            self._require_result_access(record, binding, result_credential_digest)
            validated_evidence, _ = self._validated_record_material(record)
            now = self._validated_record_now(record, clock)
            if self._expire_if_due(record, now):
                raise MailboxError(MailboxDenial.EXPIRED)
            referenced = {seal.object_id for seal in evidence_seals}
            staged = set(record.evidence)
            if referenced - staged:
                raise MailboxError(MailboxDenial.EVIDENCE_MISSING)
            if staged - referenced:
                raise MailboxError(MailboxDenial.EVIDENCE_UNREFERENCED)
            for seal in evidence_seals:
                unwrapped = validated_evidence[seal.object_id]
                if (
                    unwrapped.object_id != seal.object_id
                    or unwrapped.kind != seal.kind
                    or unwrapped.payload_digest != seal.payload_digest
                    or len(unwrapped.payload) != seal.byte_count
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
            raw_result_digest = hashlib.sha256(result_json).digest()
            result_nonce = secrets.token_bytes(12)
            result_aad = self._result_aad(record.binding, len(result_json))
            framed_result = self._binding_digest(record.binding) + raw_result_digest + result_json
            wrapped_result = self._aead.encrypt(
                result_nonce,
                framed_result,
                result_aad,
            )
            result_item = _WrappedResult(
                byte_count=len(result_json),
                storage_digest=hashlib.sha256(wrapped_result).digest(),
                semantic_mac=self._semantic_mac(result_aad, framed_result),
                nonce=result_nonce,
                wrapped_payload=wrapped_result,
            )
            self._validate_result_references(record.binding, result_json, validated_evidence)
            manifest = self._build_committed_manifest(
                record.binding,
                tuple(validated_evidence),
                result_item,
            )
            self._failure.hit(CrashPoint.BEFORE_RESULT_COMMIT)
            record.result_envelope = result_item
            record.committed_evidence_manifest = manifest
            record.state = MailboxState.RESULT_COMMITTED
            record.collection_state = CollectionState.READY
            record.result_credential_digest = None
            record.committed_at = now
            self._observe_time(record, now)
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
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            validated_evidence, result_json = self._validated_record_material(record)
            now = self._validated_record_now(record, clock)
            if record.collection_state is CollectionState.ACKNOWLEDGED:
                raise MailboxError(MailboxDenial.REPLAY)
            if record.state is not MailboxState.RESULT_COMMITTED or record.result_envelope is None:
                raise MailboxError(MailboxDenial.INVALID_STATE)
            if record.collection_state not in {CollectionState.READY, CollectionState.DELIVERING}:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            if result_json is None:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            evidence = tuple(validated_evidence.values())
            record.collection_state = CollectionState.DELIVERING
            self._observe_time(record, now)
            return CommittedBundle(
                binding=record.binding, result_json=result_json, evidence=evidence
            )

    def acknowledge_collection(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._record(mailbox_id)
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            self._validated_record_material(record)
            now = self._validated_record_now(record, clock)
            if record.collection_state is CollectionState.ACKNOWLEDGED:
                self._observe_time(record, now)
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
            self._observe_time(record, now)
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
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            self._validated_record_material(record)
            now = self._validated_record_now(record, clock)
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
            self._observe_time(record, now)
            return self._snapshot(record)

    def expire(self, maintenance_credential_digest: bytes, clock: Clock) -> tuple[UUID, ...]:
        with self._lock:
            self._require_maintenance(maintenance_credential_digest)
            for record in self._records.values():
                self._validated_record_material(record)
            now = self._validated_installation_now(clock)
            for record in self._records.values():
                if now < record.last_seen_utc:
                    raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            expired: list[UUID] = []
            for record in self._records.values():
                was_expired = record.state is MailboxState.EXPIRED
                if self._expire_if_due(record, now) and not was_expired:
                    expired.append(record.binding.mailbox_id)
                else:
                    self._observe_time(record, now)
            self._advance_installation_time(now)
            return tuple(sorted(expired, key=str))

    def garbage_collect(
        self, maintenance_credential_digest: bytes, clock: Clock
    ) -> tuple[UUID, ...]:
        with self._lock:
            self._require_maintenance(maintenance_credential_digest)
            for record in self._records.values():
                self._validated_record_material(record)
            now = self._validated_installation_now(clock)
            for record in self._records.values():
                if now < record.last_seen_utc:
                    raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            # The installation sweep is itself an observation of time. Advance
            # every surviving record's high-water in the same locked transaction
            # so a later caller cannot roll the clock back past a completed GC.
            for record in self._records.values():
                record.last_seen_utc = now
            self._advance_installation_time(now)
            for mailbox_id, tombstone in tuple(self._tombstones.items()):
                if tombstone.expires_at <= now:
                    del self._tombstones[mailbox_id]
            removed: list[UUID] = []
            ordered_records = sorted(
                self._records.items(),
                key=lambda item: (
                    item[1].terminal_at or now,
                    str(item[0]),
                ),
            )
            for mailbox_id, record in ordered_records:
                terminal_due = (
                    record.terminal_at is not None
                    and now - record.terminal_at >= self._limits.terminal_retention
                )
                if terminal_due and len(self._tombstones) < self._limits.max_tombstones:
                    self._discard_record(record)
                    del self._records[mailbox_id]
                    self._tombstones[mailbox_id] = _Tombstone(
                        created_at=now, expires_at=now + self._limits.tombstone_retention
                    )
                    removed.append(mailbox_id)
            return tuple(sorted(removed, key=str))

    def snapshot(
        self,
        mailbox_id: UUID,
        collection_credential_digest: bytes,
        clock: Clock,
    ) -> MailboxSnapshot:
        with self._lock:
            record = self._record(mailbox_id)
            self._require_credential(
                record.collection_credential_digest, collection_credential_digest
            )
            self._validated_record_material(record)
            now = self._validated_record_now(record, clock)
            if not self._expire_if_due(record, now):
                self._observe_time(record, now)
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

    def _validated_installation_now(self, clock: Clock) -> datetime:
        now = _validated_utc_now(clock)
        if self._installation_last_seen_utc is not None and now < self._installation_last_seen_utc:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return now

    def _validated_record_now(self, record: _Record, clock: Clock) -> datetime:
        now = self._validated_installation_now(clock)
        if now < record.last_seen_utc:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return now

    def _advance_installation_time(self, now: datetime) -> None:
        if self._installation_last_seen_utc is None or now > self._installation_last_seen_utc:
            self._installation_last_seen_utc = now

    def _observe_time(self, record: _Record, now: datetime) -> None:
        record.last_seen_utc = now
        self._advance_installation_time(now)

    def _expire_if_due(self, record: _Record, now: datetime) -> bool:
        if record.state is MailboxState.EXPIRED:
            self._observe_time(record, now)
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
            self._observe_time(record, now)
            return True
        return False

    def _clear_action_material(self, record: _Record) -> None:
        self._clear_claim_delivery_material(record)
        record.result_credential_digest = None
        self._release_record_payloads(record)

    def _clear_claim_delivery_material(self, record: _Record) -> None:
        active_bytes = (
            (len(record.envelope_json) if record.envelope_json is not None else 0)
            + (len(record.action_key) if record.action_key is not None else 0)
            + (len(record.result_credential) if record.result_credential is not None else 0)
        )
        self._total_active_material_bytes -= active_bytes
        _wipe(record.action_key)
        _wipe(record.result_credential)
        record.action_key = None
        record.result_credential = None
        record.envelope_json = None

    def _release_record_payloads(self, record: _Record) -> None:
        evidence_bytes = self._record_evidence_bytes(record)
        committed_bytes = (
            record.result_envelope.byte_count if record.result_envelope is not None else 0
        ) + evidence_bytes
        self._total_evidence_bytes -= evidence_bytes
        if record.committed_at is not None:
            self._total_committed_bytes -= committed_bytes
        record.result_envelope = None
        record.committed_evidence_manifest = None
        record.evidence.clear()

    def _discard_record(self, record: _Record) -> None:
        self._clear_claim_delivery_material(record)
        record.result_credential_digest = None
        self._release_record_payloads(record)

    @staticmethod
    def _record_evidence_bytes(record: _Record) -> int:
        return sum(item.byte_count for item in record.evidence.values())

    @staticmethod
    def _aad(
        mailbox_id: UUID,
        authenticated_object_id: UUID,
        repository_slot: UUID,
        kind: str,
        byte_count: int,
    ) -> bytes:
        return (
            _WRAP_CONTEXT
            + mailbox_id.bytes
            + authenticated_object_id.bytes
            + repository_slot.bytes
            + kind.encode()
            + b"\x00"
            + byte_count.to_bytes(8, "big")
        )

    def _unwrap(
        self, mailbox_id: UUID, repository_slot: UUID, item: _WrappedEvidence
    ) -> EvidenceUpload:
        if (
            type(repository_slot) is not UUID
            or type(item.object_id) is not UUID
            or repository_slot != item.object_id
            or type(item.kind) is not str
            or type(item.byte_count) is not int
            or item.byte_count <= 0
            or type(item.storage_digest) is not bytes
            or len(item.storage_digest) != 32
            or type(item.semantic_mac) is not bytes
            or len(item.semantic_mac) != 32
            or type(item.nonce) is not bytes
            or len(item.nonce) != 12
            or type(item.wrapped_payload) is not bytes
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        if not hmac.compare_digest(
            hashlib.sha256(item.wrapped_payload).digest(), item.storage_digest
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        aad = self._aad(
            mailbox_id,
            item.object_id,
            repository_slot,
            item.kind,
            item.byte_count,
        )
        try:
            framed_payload = self._aead.decrypt(item.nonce, item.wrapped_payload, aad)
        except InvalidTag:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None
        if not hmac.compare_digest(self._semantic_mac(aad, framed_payload), item.semantic_mac):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        if len(framed_payload) != _INNER_EVIDENCE_ID_BYTES + _INNER_DIGEST_BYTES + item.byte_count:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        framed_object_id = framed_payload[:_INNER_EVIDENCE_ID_BYTES]
        if not hmac.compare_digest(framed_object_id, repository_slot.bytes):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        digest_start = _INNER_EVIDENCE_ID_BYTES
        digest_end = digest_start + _INNER_DIGEST_BYTES
        raw_digest = framed_payload[digest_start:digest_end]
        payload = framed_payload[digest_end:]
        if len(payload) != item.byte_count or not hmac.compare_digest(
            hashlib.sha256(payload).digest(), raw_digest
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return EvidenceUpload(
            object_id=item.object_id,
            kind=item.kind,
            payload_digest="sha256:" + raw_digest.hex(),
            payload=payload,
        )

    def _validated_evidence_slots(self, record: _Record) -> dict[UUID, EvidenceUpload]:
        validated: dict[UUID, EvidenceUpload] = {}
        for repository_slot, item in record.evidence.items():
            evidence = self._unwrap(record.binding.mailbox_id, repository_slot, item)
            if evidence.object_id in validated:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            validated[evidence.object_id] = evidence
        if set(validated) != set(record.evidence):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return validated

    def _validated_record_material(
        self, record: _Record
    ) -> tuple[dict[UUID, EvidenceUpload], bytes | None]:
        """Authenticate all retained material without changing repository state."""

        evidence = self._validated_evidence_slots(record)
        if record.state is MailboxState.RESULT_COMMITTED:
            if record.committed_at is None:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            if record.collection_state is CollectionState.ACKNOWLEDGED:
                if (
                    evidence
                    or record.result_envelope is not None
                    or record.committed_evidence_manifest is not None
                ):
                    raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
                return evidence, None
            if record.collection_state not in {
                CollectionState.READY,
                CollectionState.DELIVERING,
            }:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            if record.result_envelope is None or record.committed_evidence_manifest is None:
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
            result_json = self._unwrap_result(record.binding, record.result_envelope)
            self._validate_result_references(record.binding, result_json, evidence)
            self._validate_committed_manifest(record, tuple(evidence))
            return evidence, result_json

        if (
            record.collection_state is not CollectionState.NONE
            or record.result_envelope is not None
            or record.committed_evidence_manifest is not None
            or record.committed_at is not None
            or (record.state is not MailboxState.CLAIMED_ONCE and evidence)
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return evidence, None

    def _build_committed_manifest(
        self,
        binding: ActionBinding,
        object_ids: tuple[UUID, ...],
        result: _WrappedResult,
    ) -> _CommittedEvidenceManifest:
        if len(set(object_ids)) != len(object_ids) or any(
            type(object_id) is not UUID for object_id in object_ids
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        sorted_ids = tuple(sorted(object_ids, key=lambda object_id: object_id.bytes))
        frame = (
            _MANIFEST_CONTEXT
            + self._binding_digest(binding)
            + result.storage_digest
            + len(sorted_ids).to_bytes(8, "big")
            + b"".join(object_id.bytes for object_id in sorted_ids)
        )
        return _CommittedEvidenceManifest(
            item_count=len(sorted_ids),
            storage_digest=hashlib.sha256(frame).digest(),
            semantic_mac=hmac.new(
                self._semantic_mac_key,
                _MANIFEST_CONTEXT + frame,
                hashlib.sha256,
            ).digest(),
        )

    def _validate_committed_manifest(self, record: _Record, object_ids: tuple[UUID, ...]) -> None:
        manifest = record.committed_evidence_manifest
        result = record.result_envelope
        if manifest is None or result is None:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        if (
            type(manifest.item_count) is not int
            or type(manifest.storage_digest) is not bytes
            or len(manifest.storage_digest) != 32
            or type(manifest.semantic_mac) is not bytes
            or len(manifest.semantic_mac) != 32
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        expected = self._build_committed_manifest(record.binding, object_ids, result)
        if (
            manifest.item_count != expected.item_count
            or not hmac.compare_digest(manifest.storage_digest, expected.storage_digest)
            or not hmac.compare_digest(manifest.semantic_mac, expected.semantic_mac)
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

    @staticmethod
    def _validate_result_references(
        binding: ActionBinding,
        result_json: bytes,
        evidence: dict[UUID, EvidenceUpload],
    ) -> None:
        try:
            result = ResultEnvelope.model_validate_json(result_json)
        except (ValidationError, TypeError, ValueError):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None
        if result.action_id != binding.action_id or result.attempt_id != binding.attempt_id:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        references = {item.mailbox_object_id: item for item in result.evidence}
        if len(references) != len(result.evidence) or set(references) != set(evidence):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        for object_id, item in references.items():
            upload = evidence[object_id]
            if (
                item.kind != upload.kind
                or item.payload_digest != upload.payload_digest
                or item.byte_count != len(upload.payload)
            ):
                raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)

    @staticmethod
    def _result_aad(binding: ActionBinding, byte_count: int) -> bytes:
        return (
            _RESULT_WRAP_CONTEXT
            + VolatileMailboxRepository._binding_digest(binding)
            + byte_count.to_bytes(8, "big")
        )

    @staticmethod
    def _binding_digest(binding: ActionBinding) -> bytes:
        parts = (
            binding.mailbox_id.bytes,
            binding.action_id.bytes,
            binding.intent_id.bytes,
            binding.attempt_id.bytes,
            binding.connector_release.encode(),
            binding.capability.encode(),
            binding.selected_artifact_digest.encode(),
            str(binding.dispatch_epoch).encode(),
            str(binding.fence).encode(),
            str(binding.authorization_epoch).encode(),
            binding.claim_deadline_utc.isoformat(timespec="microseconds").encode(),
            binding.deadline_utc.isoformat(timespec="microseconds").encode(),
            str(binding.wall_seconds).encode(),
            str(binding.response_bytes).encode(),
            binding.envelope_digest.encode(),
        )
        framed = b"".join(len(part).to_bytes(8, "big") + part for part in parts)
        return hashlib.sha256(framed).digest()

    def _unwrap_result(self, binding: ActionBinding, item: _WrappedResult) -> bytes:
        if (
            type(item.byte_count) is not int
            or item.byte_count <= 0
            or type(item.storage_digest) is not bytes
            or len(item.storage_digest) != 32
            or type(item.semantic_mac) is not bytes
            or len(item.semantic_mac) != 32
            or type(item.nonce) is not bytes
            or len(item.nonce) != 12
            or type(item.wrapped_payload) is not bytes
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        if not hmac.compare_digest(
            hashlib.sha256(item.wrapped_payload).digest(), item.storage_digest
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        aad = self._result_aad(binding, item.byte_count)
        try:
            framed_payload = self._aead.decrypt(item.nonce, item.wrapped_payload, aad)
        except InvalidTag:
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY) from None
        if not hmac.compare_digest(self._semantic_mac(aad, framed_payload), item.semantic_mac):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        if (
            len(framed_payload)
            != _INNER_RESULT_BINDING_BYTES + _INNER_DIGEST_BYTES + item.byte_count
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        expected_binding = self._binding_digest(binding)
        if not hmac.compare_digest(framed_payload[:_INNER_RESULT_BINDING_BYTES], expected_binding):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        digest_start = _INNER_RESULT_BINDING_BYTES
        digest_end = digest_start + _INNER_DIGEST_BYTES
        raw_digest = framed_payload[digest_start:digest_end]
        payload = framed_payload[digest_end:]
        if len(payload) != item.byte_count or not hmac.compare_digest(
            hashlib.sha256(payload).digest(), raw_digest
        ):
            raise MailboxError(MailboxDenial.INTERNAL_UNCERTAINTY)
        return payload

    def _semantic_mac(self, aad: bytes, framed_payload: bytes) -> bytes:
        return hmac.new(
            self._semantic_mac_key,
            aad + framed_payload,
            hashlib.sha256,
        ).digest()

    @staticmethod
    def _snapshot(record: _Record) -> MailboxSnapshot:
        return MailboxSnapshot(
            mailbox_id=record.binding.mailbox_id,
            state=record.state,
            collection_state=record.collection_state,
            staged_evidence_count=len(record.evidence),
            staged_evidence_bytes=sum(item.byte_count for item in record.evidence.values()),
            result_present=record.result_envelope is not None,
            claim_material_retained=record.action_key is not None
            or record.envelope_json is not None,
            result_credential_material_retained=record.result_credential is not None,
            observed_at_utc=record.last_seen_utc,
            claim_deadline_utc=record.binding.claim_deadline_utc,
            result_deadline_utc=record.binding.deadline_utc,
        )
