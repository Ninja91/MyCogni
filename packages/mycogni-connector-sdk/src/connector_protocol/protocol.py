"""Validated protocol-version-1 input envelope for an isolated action."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import UUID4, AwareDatetime, Field, field_validator

from connector_protocol.manifest import (
    MAX_ORIGINS,
    AttributeType,
    Capability,
    FrozenWireModel,
    require_unique,
    validate_canonical_uuid_input,
    validate_https_origin,
    validate_utc,
)

PROTOCOL_VERSION = 1
MAX_WALL_SECONDS = 3_600
MAX_RESPONSE_BYTES = 67_108_864
MAX_ATTRIBUTES = 64
_CONNECTOR_RELEASE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?@"
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)


class SealedAttribute(FrozenWireModel):
    """One opaque attribute sealed to a one-time action key."""

    attribute_type: AttributeType
    ciphertext: Annotated[str, Field(min_length=1, max_length=1_048_576)]


class ActionBudget(FrozenWireModel):
    """Positive hard bounds supplied to separate runtime enforcement."""

    wall_seconds: Annotated[int, Field(gt=0, le=MAX_WALL_SECONDS)]
    response_bytes: Annotated[int, Field(gt=0, le=MAX_RESPONSE_BYTES)]


class ActionEnvelope(FrozenWireModel):
    """Short-lived declarative input; validation does not authorize dispatch."""

    protocol_version: Literal[1]
    action_id: UUID4
    intent_id: UUID4
    attempt_id: UUID4
    fence: Annotated[int, Field(ge=0)]
    authorization_epoch: Annotated[int, Field(ge=0)]
    capability: Capability
    connector_release: Annotated[
        str, Field(min_length=7, max_length=193, pattern=_CONNECTOR_RELEASE.pattern)
    ]
    profile_ref: UUID4
    attributes: Annotated[tuple[SealedAttribute, ...], Field(max_length=MAX_ATTRIBUTES)]
    allowed_origins: Annotated[tuple[str, ...], Field(min_length=1, max_length=MAX_ORIGINS)]
    deadline_utc: AwareDatetime
    attempt: Annotated[int, Field(ge=0)]
    budget: ActionBudget

    @field_validator("action_id", "intent_id", "attempt_id", "profile_ref", mode="before")
    @classmethod
    def ids_use_canonical_text(cls, value: Any, info: Any) -> Any:
        return validate_canonical_uuid_input(value, info.field_name)

    @field_validator("connector_release")
    @classmethod
    def release_parts_are_individually_valid(cls, value: str) -> str:
        connector_id, release = value.split("@", 1)
        if not connector_id or not release:
            raise ValueError("connector_release must contain connector ID and version")
        return value

    @field_validator("attributes")
    @classmethod
    def attributes_are_unique(
        cls, value: tuple[SealedAttribute, ...]
    ) -> tuple[SealedAttribute, ...]:
        return require_unique(value, "attributes")

    @field_validator("allowed_origins")
    @classmethod
    def origins_are_exact_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validated = tuple(validate_https_origin(origin) for origin in value)
        return require_unique(validated, "allowed_origins")

    @field_validator("deadline_utc")
    @classmethod
    def deadline_is_utc(cls, value: datetime, info: Any) -> datetime:
        return validate_utc(value, info.field_name)
