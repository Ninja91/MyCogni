"""Framework-free value types and finite state for the runner mailbox spike."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from uuid import UUID

ACTION_KEY_BYTES = 32
MIN_CREDENTIAL_BYTES = 32
MAX_CREDENTIAL_BYTES = 128
MAX_ACTION_ENVELOPE_BYTES = 8_388_608
MAX_RESULT_ENVELOPE_BYTES = 1_048_576
MAX_EVIDENCE_BYTES = 67_108_864
MAX_EVIDENCE_ITEMS = 64
MAX_WALL_SECONDS = 3_600
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CONNECTOR_RELEASE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?@"
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_CAPABILITY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


class MailboxState(StrEnum):
    """Internal mailbox states; no state is an external outcome fact."""

    EMPTY = "empty"
    OFFERED = "offered"
    CLAIMED_ONCE = "claimed_once"
    RESULT_COMMITTED = "result_committed"
    EXPIRED = "expired"
    ABANDONED = "abandoned"


class CollectionState(StrEnum):
    """Durable-consumer delivery axis, deliberately separate from mailbox state."""

    NONE = "none"
    READY = "ready"
    DELIVERING = "delivering"
    ACKNOWLEDGED = "acknowledged"


class MailboxDenial(StrEnum):
    """Stable fail-closed reasons that never interpolate caller-controlled values."""

    ALREADY_EXISTS = "already_exists"
    NOT_FOUND = "not_found"
    INVALID_INPUT = "invalid_input"
    UNAUTHORIZED = "unauthorized"
    BINDING_MISMATCH = "binding_mismatch"
    INVALID_STATE = "invalid_state"
    EXPIRED = "expired"
    REPLAY = "replay"
    OVERSIZE = "oversize"
    DIGEST_MISMATCH = "digest_mismatch"
    RESULT_MISMATCH = "result_mismatch"
    CAPABILITY_MISMATCH = "capability_mismatch"
    EVIDENCE_MISSING = "evidence_missing"
    EVIDENCE_UNREFERENCED = "evidence_unreferenced"
    EVIDENCE_LIMIT = "evidence_limit"
    QUOTA_EXCEEDED = "quota_exceeded"
    CONTENDED = "contended"
    INTERNAL_UNCERTAINTY = "internal_uncertainty"


_SAFE_MESSAGES: dict[MailboxDenial, str] = {
    MailboxDenial.ALREADY_EXISTS: "mailbox already exists",
    MailboxDenial.NOT_FOUND: "mailbox is unavailable",
    MailboxDenial.INVALID_INPUT: "mailbox input is invalid",
    MailboxDenial.UNAUTHORIZED: "mailbox access is denied",
    MailboxDenial.BINDING_MISMATCH: "mailbox binding does not match",
    MailboxDenial.INVALID_STATE: "mailbox transition is not permitted",
    MailboxDenial.EXPIRED: "mailbox has expired",
    MailboxDenial.REPLAY: "mailbox operation was already consumed",
    MailboxDenial.OVERSIZE: "mailbox payload exceeds its bound",
    MailboxDenial.DIGEST_MISMATCH: "mailbox payload digest does not match",
    MailboxDenial.RESULT_MISMATCH: "result does not match the claimed action",
    MailboxDenial.CAPABILITY_MISMATCH: "result is not permitted for the action capability",
    MailboxDenial.EVIDENCE_MISSING: "committed result references missing evidence",
    MailboxDenial.EVIDENCE_UNREFERENCED: "staged evidence is not referenced by the result",
    MailboxDenial.EVIDENCE_LIMIT: "mailbox response exceeds its aggregate bound",
    MailboxDenial.QUOTA_EXCEEDED: "mailbox installation capacity is exhausted",
    MailboxDenial.CONTENDED: "mailbox writer is temporarily contended",
    MailboxDenial.INTERNAL_UNCERTAINTY: "mailbox operation ended with internal uncertainty",
}


class MailboxError(RuntimeError):
    """Sanitized protocol failure carrying only a finite denial reason."""

    def __init__(self, denial: MailboxDenial) -> None:
        self.denial = denial
        super().__init__(_SAFE_MESSAGES[denial])


class CrashPoint(StrEnum):
    """Deterministic failure-injection edges around atomic repository mutations."""

    BEFORE_CLAIM_COMMIT = "before_claim_commit"
    AFTER_CLAIM_COMMIT = "after_claim_commit"
    BEFORE_EVIDENCE_COMMIT = "before_evidence_commit"
    AFTER_EVIDENCE_COMMIT = "after_evidence_commit"
    BEFORE_RESULT_COMMIT = "before_result_commit"
    AFTER_RESULT_COMMIT = "after_result_commit"
    BEFORE_COLLECTION_ACK = "before_collection_ack"
    AFTER_COLLECTION_ACK = "after_collection_ack"


class InjectedCrash(RuntimeError):
    """Synthetic process-loss signal containing no action material."""

    def __init__(self, point: CrashPoint) -> None:
        self.point = point
        super().__init__("synthetic mailbox crash")


def _require_exact_int(value: int, field_name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def _require_uuid4(value: UUID, field_name: str) -> None:
    if type(value) is not UUID or value.version != 4:
        raise ValueError(f"{field_name} must be a UUIDv4")


def _require_digest(value: str, field_name: str) -> None:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        raise ValueError(f"{field_name} must be a canonical SHA-256 digest")


def _require_utc(value: datetime, field_name: str) -> None:
    if type(value) is not datetime or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be an aware UTC instant")


@dataclass(frozen=True, slots=True)
class MailboxLimits:
    """Finite installation bounds and authenticated-GC retention windows."""

    max_mailboxes: int = 64
    max_total_active_material_bytes: int = 16_777_216
    max_total_evidence_bytes: int = 67_108_864
    max_total_committed_bytes: int = 67_108_864
    terminal_retention: timedelta = timedelta(days=7)
    tombstone_retention: timedelta = timedelta(days=30)
    max_tombstones: int = 4_096

    def __post_init__(self) -> None:
        for name in (
            "max_mailboxes",
            "max_total_active_material_bytes",
            "max_total_evidence_bytes",
            "max_total_committed_bytes",
            "max_tombstones",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive exact integer")
        for name in ("terminal_retention", "tombstone_retention"):
            value = getattr(self, name)
            if type(value) is not timedelta or value <= timedelta(0):
                raise ValueError(f"{name} must be a positive timedelta")


@dataclass(frozen=True, slots=True)
class ActionBinding:
    """Immutable authority-free binding selected before connector claim."""

    mailbox_id: UUID
    action_id: UUID
    intent_id: UUID
    attempt_id: UUID
    connector_release: str
    capability: str
    selected_artifact_digest: str
    dispatch_epoch: int
    fence: int
    authorization_epoch: int
    claim_deadline_utc: datetime
    deadline_utc: datetime
    wall_seconds: int
    response_bytes: int
    envelope_digest: str

    def __post_init__(self) -> None:
        for field_name in ("mailbox_id", "action_id", "intent_id", "attempt_id"):
            _require_uuid4(getattr(self, field_name), field_name)
        if (
            type(self.connector_release) is not str
            or len(self.connector_release) > 193
            or not _CONNECTOR_RELEASE.fullmatch(self.connector_release)
        ):
            raise ValueError("connector_release must be canonical and bounded")
        if type(self.capability) is not str or not _CAPABILITY.fullmatch(self.capability):
            raise ValueError("capability must be canonical and bounded")
        _require_digest(self.selected_artifact_digest, "selected_artifact_digest")
        _require_digest(self.envelope_digest, "envelope_digest")
        _require_exact_int(self.dispatch_epoch, "dispatch_epoch")
        _require_exact_int(self.fence, "fence")
        _require_exact_int(self.authorization_epoch, "authorization_epoch")
        _require_utc(self.claim_deadline_utc, "claim_deadline_utc")
        _require_utc(self.deadline_utc, "deadline_utc")
        if self.claim_deadline_utc >= self.deadline_utc:
            raise ValueError("claim deadline must precede the result deadline")
        _require_exact_int(self.wall_seconds, "wall_seconds")
        _require_exact_int(self.response_bytes, "response_bytes")
        if self.wall_seconds == 0 or self.response_bytes == 0:
            raise ValueError("action budgets must be positive")
        if self.wall_seconds > MAX_WALL_SECONDS or self.response_bytes > MAX_EVIDENCE_BYTES:
            raise ValueError("action budgets exceed protocol bounds")


@dataclass(frozen=True, slots=True)
class EvidenceUpload:
    """Untrusted sensitive connector payload; body is deliberately absent from repr.

    The digest provides integrity against accidental/caller mismatch only. The
    repository wraps the payload under a mailbox-owned authenticated-storage key
    before retaining it. This type makes no connector-side encryption claim.
    """

    object_id: UUID
    kind: str
    payload_digest: str
    payload: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _require_uuid4(self.object_id, "object_id")
        if type(self.kind) is not str or not re.fullmatch(r"^[a-z][a-z0-9_]{0,63}$", self.kind):
            raise ValueError("kind must be a canonical evidence kind")
        _require_digest(self.payload_digest, "payload_digest")
        if type(self.payload) is not bytes or not self.payload:
            raise ValueError("payload must be non-empty bytes")
        if len(self.payload) > MAX_EVIDENCE_BYTES:
            raise ValueError("payload exceeds the evidence bound")


@dataclass(frozen=True, slots=True)
class EvidenceSeal:
    object_id: UUID
    kind: str
    payload_digest: str
    byte_count: int

    def __post_init__(self) -> None:
        _require_uuid4(self.object_id, "object_id")
        if type(self.kind) is not str or not re.fullmatch(r"^[a-z][a-z0-9_]{0,63}$", self.kind):
            raise ValueError("kind must be a canonical evidence kind")
        _require_digest(self.payload_digest, "payload_digest")
        if type(self.byte_count) is not int or not 0 < self.byte_count <= MAX_EVIDENCE_BYTES:
            raise ValueError("byte_count must be a positive bounded integer")


@dataclass(frozen=True, slots=True)
class ClaimedAction:
    binding: ActionBinding
    envelope_json: bytes = field(repr=False)
    action_key: bytes = field(repr=False)
    result_credential: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.binding) is not ActionBinding:
            raise ValueError("binding must be an ActionBinding")
        if type(self.envelope_json) is not bytes or not self.envelope_json:
            raise ValueError("envelope_json must be non-empty bytes")
        if len(self.envelope_json) > MAX_ACTION_ENVELOPE_BYTES:
            raise ValueError("envelope_json exceeds its bound")
        if type(self.action_key) is not bytes or len(self.action_key) != ACTION_KEY_BYTES:
            raise ValueError("action_key must be exactly 32 bytes")
        if (
            type(self.result_credential) is not bytes
            or not MIN_CREDENTIAL_BYTES <= len(self.result_credential) <= MAX_CREDENTIAL_BYTES
        ):
            raise ValueError("result_credential must be bounded high-entropy bytes")


@dataclass(frozen=True, slots=True)
class CommittedBundle:
    """Idempotently deliverable core bundle; explicit ack completes collection."""

    binding: ActionBinding
    result_json: bytes = field(repr=False)
    evidence: tuple[EvidenceUpload, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.binding) is not ActionBinding:
            raise ValueError("binding must be an ActionBinding")
        if type(self.result_json) is not bytes or not self.result_json:
            raise ValueError("result_json must be non-empty bytes")
        if len(self.result_json) > MAX_RESULT_ENVELOPE_BYTES:
            raise ValueError("result_json exceeds its bound")
        if type(self.evidence) is not tuple or not all(
            type(item) is EvidenceUpload for item in self.evidence
        ):
            raise ValueError("evidence must be an immutable EvidenceUpload tuple")
        if len(self.evidence) > MAX_EVIDENCE_ITEMS:
            raise ValueError("evidence exceeds its item bound")
        if sum(len(item.payload) for item in self.evidence) > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence exceeds its aggregate bound")
        if (
            len(self.result_json) + sum(len(item.payload) for item in self.evidence)
            > self.binding.response_bytes
        ):
            raise ValueError("bundle exceeds the exact action response bound")


@dataclass(frozen=True, slots=True)
class MailboxSnapshot:
    """Credential-scoped redacted operational state; never an external status."""

    mailbox_id: UUID
    state: MailboxState
    collection_state: CollectionState
    staged_evidence_count: int
    staged_evidence_bytes: int
    result_present: bool
    claim_material_retained: bool
    result_credential_material_retained: bool
    observed_at_utc: datetime
    claim_deadline_utc: datetime
    result_deadline_utc: datetime

    def __post_init__(self) -> None:
        _require_uuid4(self.mailbox_id, "mailbox_id")
        if (
            type(self.state) is not MailboxState
            or type(self.collection_state) is not CollectionState
        ):
            raise ValueError("snapshot state is invalid")
        for field_name in ("staged_evidence_count", "staged_evidence_bytes"):
            _require_exact_int(getattr(self, field_name), field_name)
        for field_name in (
            "result_present",
            "claim_material_retained",
            "result_credential_material_retained",
        ):
            if type(getattr(self, field_name)) is not bool:
                raise ValueError(f"{field_name} must be an exact bool")
        for field_name in (
            "observed_at_utc",
            "claim_deadline_utc",
            "result_deadline_utc",
        ):
            _require_utc(getattr(self, field_name), field_name)
