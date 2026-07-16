"""Minimal typed result envelope returned through the sealed mailbox."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

type ResultCode = Literal[
    "not_found",
    "candidate_found",
    "ambiguous",
    "challenge",
    "inconclusive",
    "failed",
]


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """Opaque reference to bounded ciphertext uploaded through the mailbox."""

    kind: str
    mailbox_object_id: str
    ciphertext_digest: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class DisclosureRecord:
    """Typed summary of an attribute category disclosed during the action."""

    attribute_type: str
    destination: str


@dataclass(frozen=True, slots=True)
class ResultEnvelope:
    """Structured result for one action attempt, without outcome inference."""

    protocol_version: int
    action_id: str
    attempt_id: str
    result: ResultCode
    reason_code: str
    evidence: tuple[EvidenceReference, ...]
    disclosures: tuple[DisclosureRecord, ...]
