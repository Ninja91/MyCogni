"""Typed, behavior-free messages for the isolated connector boundary."""

from connector_protocol.manifest import (
    Capability,
    ConnectorManifest,
    RuntimeBoundary,
    Transport,
)
from connector_protocol.protocol import ActionBudget, ActionEnvelope, SealedAttribute
from connector_protocol.result import (
    DisclosureRecord,
    EvidenceReference,
    ResultCode,
    ResultEnvelope,
)

__all__ = (
    "ActionBudget",
    "ActionEnvelope",
    "Capability",
    "ConnectorManifest",
    "DisclosureRecord",
    "EvidenceReference",
    "ResultCode",
    "ResultEnvelope",
    "RuntimeBoundary",
    "SealedAttribute",
    "Transport",
)
