"""Minimal typed input envelope for one isolated connector action."""

from __future__ import annotations

from dataclasses import dataclass

from connector_protocol.manifest import Capability


@dataclass(frozen=True, slots=True)
class SealedAttribute:
    """One opaque attribute released for this action only."""

    attribute_type: str
    ciphertext: str


@dataclass(frozen=True, slots=True)
class ActionBudget:
    """Bounds supplied to runtime enforcement layers."""

    wall_seconds: int
    response_bytes: int


@dataclass(frozen=True, slots=True)
class ActionEnvelope:
    """Short-lived declarative input for one connector attempt."""

    protocol_version: int
    action_id: str
    intent_id: str
    attempt_id: str
    fence: int
    authorization_epoch: int
    capability: Capability
    connector_release: str
    profile_ref: str
    attributes: tuple[SealedAttribute, ...]
    allowed_origins: tuple[str, ...]
    deadline_utc: str
    budget: ActionBudget
