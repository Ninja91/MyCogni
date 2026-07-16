"""Validated, bounded result envelope returned through the sealed mailbox."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import UUID4, Field, field_validator, model_validator

from connector_protocol.manifest import (
    AttributeType,
    Digest,
    FrozenWireModel,
    require_unique,
    validate_hostname,
)

MAX_EVIDENCE_ITEMS = 64
MAX_EVIDENCE_BYTES = 67_108_864
MAX_DISCLOSURE_RECORDS = 64


class ResultCode(StrEnum):
    """Finite action result vocabulary; never a removal-verification claim."""

    NOT_FOUND = "not_found"
    CANDIDATE_FOUND = "candidate_found"
    AMBIGUOUS = "ambiguous"
    CHALLENGE = "challenge"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


class ReasonCode(StrEnum):
    """Finite machine reason vocabulary for protocol version 1."""

    NO_CANDIDATE = "no_candidate"
    NAME_ADDRESS_MATCH = "name_address_match"
    EXACT_MATCH = "exact_match"
    PARTIAL_MATCH = "partial_match"
    MULTIPLE_CANDIDATES = "multiple_candidates"
    INSUFFICIENT_MATCH = "insufficient_match"
    CAPTCHA_REQUIRED = "captcha_required"
    MFA_REQUIRED = "mfa_required"
    LOGIN_REQUIRED = "login_required"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    SCHEMA_DRIFT = "schema_drift"
    EVIDENCE_UNAVAILABLE = "evidence_unavailable"
    UNEXPECTED_RESPONSE = "unexpected_response"
    INVALID_ACTION = "invalid_action"
    REVOKED_AUTHORITY = "revoked_authority"
    STALE_FENCE = "stale_fence"
    BUDGET_EXCEEDED = "budget_exceeded"
    CONNECTOR_ERROR = "connector_error"


_REASONS_BY_RESULT: dict[ResultCode, frozenset[ReasonCode]] = {
    ResultCode.NOT_FOUND: frozenset({ReasonCode.NO_CANDIDATE}),
    ResultCode.CANDIDATE_FOUND: frozenset(
        {ReasonCode.NAME_ADDRESS_MATCH, ReasonCode.EXACT_MATCH, ReasonCode.PARTIAL_MATCH}
    ),
    ResultCode.AMBIGUOUS: frozenset(
        {ReasonCode.MULTIPLE_CANDIDATES, ReasonCode.INSUFFICIENT_MATCH}
    ),
    ResultCode.CHALLENGE: frozenset(
        {
            ReasonCode.CAPTCHA_REQUIRED,
            ReasonCode.MFA_REQUIRED,
            ReasonCode.LOGIN_REQUIRED,
            ReasonCode.MANUAL_REVIEW_REQUIRED,
        }
    ),
    ResultCode.INCONCLUSIVE: frozenset(
        {
            ReasonCode.TIMEOUT,
            ReasonCode.RATE_LIMITED,
            ReasonCode.SCHEMA_DRIFT,
            ReasonCode.EVIDENCE_UNAVAILABLE,
            ReasonCode.UNEXPECTED_RESPONSE,
        }
    ),
    ResultCode.FAILED: frozenset(
        {
            ReasonCode.INVALID_ACTION,
            ReasonCode.REVOKED_AUTHORITY,
            ReasonCode.STALE_FENCE,
            ReasonCode.BUDGET_EXCEEDED,
            ReasonCode.CONNECTOR_ERROR,
        }
    ),
}


class EvidenceReference(FrozenWireModel):
    """Opaque reference to bounded ciphertext already uploaded to the mailbox."""

    kind: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[a-z][a-z0-9_]*$")]
    mailbox_object_id: UUID4
    ciphertext_digest: Digest
    byte_count: Annotated[int, Field(gt=0, le=MAX_EVIDENCE_BYTES)]


class DisclosureRecord(FrozenWireModel):
    """Typed summary of an attribute category disclosed by this action."""

    attribute_type: AttributeType
    destination: Annotated[str, Field(min_length=4, max_length=253)]

    @field_validator("destination")
    @classmethod
    def destination_is_hostname(cls, value: str) -> str:
        return validate_hostname(value, "disclosure destination")


class NextStepKind(StrEnum):
    """Finite handoff requested from the trusted core or user."""

    NONE = "none"
    USER_REVIEW = "user_review"
    RETRY_LATER = "retry_later"
    REAUTHORIZE = "reauthorize"


class NextStep(FrozenWireModel):
    """Declarative handoff; never an executable command."""

    kind: NextStepKind


class ResultEnvelope(FrozenWireModel):
    """Structured attempt result without outcome or verification inference."""

    protocol_version: Literal[1]
    action_id: UUID4
    attempt_id: UUID4
    result: ResultCode
    reason_code: ReasonCode
    external_reference: Annotated[str, Field(min_length=1, max_length=1_048_576)] | None = None
    evidence: Annotated[tuple[EvidenceReference, ...], Field(max_length=MAX_EVIDENCE_ITEMS)] = ()
    disclosures: Annotated[
        tuple[DisclosureRecord, ...], Field(max_length=MAX_DISCLOSURE_RECORDS)
    ] = ()
    next: NextStep = NextStep(kind=NextStepKind.NONE)

    @field_validator("evidence")
    @classmethod
    def evidence_is_unique(
        cls, value: tuple[EvidenceReference, ...]
    ) -> tuple[EvidenceReference, ...]:
        return require_unique(value, "evidence")

    @field_validator("disclosures")
    @classmethod
    def disclosures_are_unique(
        cls, value: tuple[DisclosureRecord, ...]
    ) -> tuple[DisclosureRecord, ...]:
        return require_unique(value, "disclosures")

    @model_validator(mode="after")
    def reason_matches_result(self) -> Self:
        if self.reason_code not in _REASONS_BY_RESULT[self.result]:
            raise ValueError(f"reason_code {self.reason_code} is invalid for result {self.result}")
        return self
