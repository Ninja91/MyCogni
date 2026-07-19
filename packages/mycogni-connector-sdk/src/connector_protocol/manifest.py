"""Versioned, validated connector manifest wire schema.

The schema is a declaration, not proof of provenance, trust, sandboxing, or
permission to execute a capability.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = 1
MAX_CAPABILITIES = 5
MAX_TRANSPORTS = 5
MAX_ORIGINS = 32
MAX_DISCLOSURES = 64
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOST = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

ConnectorId = Annotated[str, Field(min_length=1, max_length=64, pattern=_SLUG.pattern)]
BrokerId = Annotated[str, Field(min_length=1, max_length=64, pattern=_SLUG.pattern)]
ReleaseVersion = Annotated[str, Field(min_length=5, max_length=128, pattern=_SEMVER.pattern)]
Digest = Annotated[str, Field(pattern=_SHA256.pattern)]
AttributeType = Annotated[str, Field(min_length=1, max_length=64, pattern=_SLUG.pattern)]


class FrozenWireModel(BaseModel):
    """Common fail-closed Pydantic configuration for protocol records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class Capability(StrEnum):
    """Independently granted connector capability."""

    OBSERVE = "observe"
    PREPARE = "prepare"
    SUBMIT = "submit"
    POLL = "poll"
    VERIFY = "verify"


class Transport(StrEnum):
    """Declared transport family; declaration does not provide egress."""

    DECLARATIVE_HTTP = "declarative_http"
    MAIL = "mail"
    BROWSER = "browser"
    GUIDED_MANUAL = "guided_manual"
    PROTOCOL_API = "protocol_api"


def validate_utc(value: datetime, field_name: str) -> datetime:
    """Require an aware instant whose offset is exactly UTC."""
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{field_name} must be an aware UTC instant")
    return value


def validate_hostname(value: str, field_name: str) -> str:
    """Validate a canonical ASCII DNS hostname, excluding wildcard/IP syntax."""
    if value != value.lower() or "*" in value or not _HOST.fullmatch(value):
        raise ValueError(f"{field_name} must be a canonical lowercase DNS hostname")
    return value


def validate_canonical_uuid_input(value: Any, field_name: str) -> Any:
    """Reject noncanonical textual UUID spellings before Pydantic UUID parsing."""
    if isinstance(value, str):
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be a canonical UUID") from exc
        if str(parsed) != value:
            raise ValueError(f"{field_name} must use canonical lowercase UUID syntax")
    return value


def validate_https_origin(value: str) -> str:
    """Validate an exact HTTPS origin without credentials, path, query, or wildcard."""
    if value != value.lower() or "*" in value or not value.isascii():
        raise ValueError("origin must be canonical lowercase ASCII without wildcards")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("origin must use https and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("origin must not contain userinfo")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("origin must not contain a path, query, or fragment")
    validate_hostname(parsed.hostname, "origin hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("origin port is invalid") from exc
    if port == 0:
        raise ValueError("origin port must be positive")
    canonical_netloc = parsed.hostname
    if port is not None and port != 443:
        canonical_netloc = f"{canonical_netloc}:{port}"
    canonical = urlunsplit(("https", canonical_netloc, "", "", ""))
    if value != canonical:
        raise ValueError("origin must use canonical syntax")
    return canonical


def require_unique(values: tuple[Any, ...], field_name: str) -> tuple[Any, ...]:
    """Reject duplicates without silently reordering a signed declaration."""
    comparable = [
        item.model_dump_json() if isinstance(item, BaseModel) else str(item) for item in values
    ]
    if len(comparable) != len(set(comparable)):
        raise ValueError(f"{field_name} entries must be unique")
    return values


class RuntimeBoundary(FrozenWireModel):
    """Required deny-by-default properties; not a sandbox implementation."""

    privileged: Literal[False] = False
    host_mounts: tuple[()] = ()
    host_network: Literal[False] = False
    docker_socket: Literal[False] = False
    direct_network: Literal[False] = False


class DisclosureDeclaration(FrozenWireModel):
    """One attribute category a release may disclose to one destination."""

    attribute_type: AttributeType
    destination: Annotated[str, Field(min_length=4, max_length=253)]
    purpose: Annotated[str, Field(min_length=1, max_length=128, pattern=_SLUG.pattern)]

    @field_validator("destination")
    @classmethod
    def destination_is_hostname(cls, value: str) -> str:
        return validate_hostname(value, "disclosure destination")


class ConnectorManifest(FrozenWireModel):
    """Immutable identity, provenance, and capability declaration for a release."""

    schema_version: Literal[1]
    connector_id: ConnectorId
    release_version: ReleaseVersion
    broker_id: BrokerId
    source_digest: Digest
    artifact_digest: Digest
    capabilities: Annotated[
        tuple[Capability, ...], Field(min_length=1, max_length=MAX_CAPABILITIES)
    ]
    transports: Annotated[tuple[Transport, ...], Field(min_length=1, max_length=MAX_TRANSPORTS)]
    allowed_origins: Annotated[tuple[str, ...], Field(min_length=1, max_length=MAX_ORIGINS)]
    disclosures: Annotated[
        tuple[DisclosureDeclaration, ...], Field(default=(), max_length=MAX_DISCLOSURES)
    ]
    reviewed_at_utc: AwareDatetime
    expires_at_utc: AwareDatetime
    runtime_boundary: RuntimeBoundary = RuntimeBoundary()

    @field_validator("capabilities")
    @classmethod
    def capabilities_are_unique(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        return require_unique(value, "capabilities")

    @field_validator("transports")
    @classmethod
    def transports_are_unique(cls, value: tuple[Transport, ...]) -> tuple[Transport, ...]:
        return require_unique(value, "transports")

    @field_validator("allowed_origins")
    @classmethod
    def origins_are_exact_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        validated = tuple(validate_https_origin(origin) for origin in value)
        return require_unique(validated, "allowed_origins")

    @field_validator("disclosures")
    @classmethod
    def disclosures_are_unique(
        cls, value: tuple[DisclosureDeclaration, ...]
    ) -> tuple[DisclosureDeclaration, ...]:
        identities = {(item.attribute_type, item.destination) for item in value}
        if len(identities) != len(value):
            raise ValueError("disclosures must have unique attribute and destination pairs")
        return value

    @field_validator("reviewed_at_utc", "expires_at_utc")
    @classmethod
    def timestamps_are_utc(cls, value: datetime, info: Any) -> datetime:
        return validate_utc(value, info.field_name)

    @model_validator(mode="after")
    def expiry_follows_review(self) -> Self:
        if self.expires_at_utc <= self.reviewed_at_utc:
            raise ValueError("expires_at_utc must be later than reviewed_at_utc")
        allowed_hosts = {
            hostname
            for origin in self.allowed_origins
            if (hostname := urlsplit(origin).hostname) is not None
        }
        undeclared = {
            disclosure.destination
            for disclosure in self.disclosures
            if disclosure.destination not in allowed_hosts
        }
        if undeclared:
            raise ValueError(
                "disclosure destinations must equal an allowed-origin hostname: "
                f"{sorted(undeclared)}"
            )
        return self
