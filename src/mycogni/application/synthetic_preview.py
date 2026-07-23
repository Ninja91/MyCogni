"""Typed contract for the synthetic-only local developer preview."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Protocol

PROFILE = "developer_preview_synthetic_only"
REPORT_SCHEMA_VERSION = 1


class PreviewReason(StrEnum):
    INITIALIZED = "initialized"
    ALREADY_INITIALIZED = "already_initialized"
    SYNTHETIC_READY = "synthetic_ready"
    USAGE_ERROR = "usage_error"
    NOT_INITIALIZED = "not_initialized"
    INITIALIZATION_INCOMPLETE = "initialization_incomplete"
    UNSAFE_STORAGE = "unsafe_storage"
    STATE_INCOMPATIBLE = "state_incompatible"
    STATE_BUSY = "state_busy"
    STORAGE_EXHAUSTED = "storage_exhausted"
    STORAGE_IO_FAILURE = "storage_io_failure"
    INTERNAL_ERROR = "internal_error"
    INTERRUPTED = "interrupted"


EXIT_CODES: dict[PreviewReason, int] = {
    PreviewReason.INITIALIZED: 0,
    PreviewReason.ALREADY_INITIALIZED: 0,
    PreviewReason.SYNTHETIC_READY: 0,
    PreviewReason.USAGE_ERROR: 2,
    PreviewReason.NOT_INITIALIZED: 20,
    PreviewReason.INITIALIZATION_INCOMPLETE: 21,
    PreviewReason.UNSAFE_STORAGE: 22,
    PreviewReason.STATE_INCOMPATIBLE: 23,
    PreviewReason.STATE_BUSY: 24,
    PreviewReason.STORAGE_EXHAUSTED: 26,
    PreviewReason.STORAGE_IO_FAILURE: 27,
    PreviewReason.INTERNAL_ERROR: 70,
    PreviewReason.INTERRUPTED: 130,
}


class SyntheticPreviewError(Exception):
    """A failure carrying only a finite, operator-safe reason."""

    def __init__(self, reason: PreviewReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class HealthCheck:
    id: str
    reason: str
    status: str


@dataclass(frozen=True, slots=True)
class PreviewReport:
    command: str
    overall: str
    checks: tuple[HealthCheck, ...]
    profile: str = PROFILE
    schema_version: int = REPORT_SCHEMA_VERSION

    def as_dict(self) -> dict[str, object]:
        return {
            "checks": [asdict(check) for check in self.checks],
            "command": self.command,
            "overall": self.overall,
            "profile": self.profile,
            "schema_version": self.schema_version,
        }


@dataclass(frozen=True, slots=True)
class DemoReport:
    fixture_result: str
    scenario: str
    safe_stop: str
    catalog_digest: str
    command: str = "synthetic.demo"
    external_actions: str = "unavailable_by_composition"
    live_brokers: int = 0
    profile: str = PROFILE
    real_pii_accepted: bool = False
    real_removal_outcome: str = "not_applicable"
    runtime_network_containment: str = "not_proven"
    schema_version: int = REPORT_SCHEMA_VERSION

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class SyntheticPreviewPort(Protocol):
    def initialize(self, state_dir: str) -> PreviewReport: ...

    def health(self, state_dir: str) -> PreviewReport: ...

    def demo(self, scenario: str) -> DemoReport: ...
