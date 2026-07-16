"""Minimal declarative connector manifest types.

These records describe a boundary; they do not launch or sandbox connector code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

type Capability = Literal["observe", "prepare", "submit", "poll", "verify"]
type Transport = Literal["declarative_http", "mail", "browser", "guided_manual"]


@dataclass(frozen=True, slots=True)
class RuntimeBoundary:
    """Non-negotiable runtime properties for an isolated connector artifact."""

    privileged: Literal[False] = field(default=False, init=False)
    host_mounts: tuple[()] = field(default=(), init=False)
    host_network: Literal[False] = field(default=False, init=False)
    docker_socket: Literal[False] = field(default=False, init=False)
    direct_network: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class ConnectorManifest:
    """Identity and capability declaration for one immutable connector release."""

    schema_version: int
    connector_id: str
    release_version: str
    broker_id: str
    capabilities: tuple[Capability, ...]
    transports: tuple[Transport, ...]
    allowed_origins: tuple[str, ...]
    expires_at_utc: str
    runtime_boundary: RuntimeBoundary = field(default_factory=RuntimeBoundary)
