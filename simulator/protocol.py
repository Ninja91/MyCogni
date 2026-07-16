"""Typed protocol shared by synthetic connector and network tests."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

MAX_REQUEST_BODY_BYTES = 4_096
MAX_RESPONSE_BODY_BYTES = 16_384
MAX_EVIDENCE_BYTES = 4_096
MAX_MAIL_BODY_BYTES = 8_192
MAX_MAIL_SUBJECT_BYTES = 160
MAX_MAIL_MESSAGES = 16
MAX_REQUESTS_PER_SESSION = 32
MAX_SESSIONS = 64

RESERVED_MAIL_SUFFIXES = (".test", ".example", ".invalid")
MAIL_LOCAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}")
MAIL_DOMAIN = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")


class SimulatorProtocolError(RuntimeError):
    """Base fail-closed protocol error."""


class UnknownScenarioError(SimulatorProtocolError):
    """The requested scenario is not in the reviewed finite catalog."""


class UnknownTransitionError(SimulatorProtocolError):
    """The caller's expected state does not match scripted state."""


class TransitionNotReadyError(SimulatorProtocolError):
    """The deterministic clock has not reached the next scripted transition."""


class ResourceLimitError(SimulatorProtocolError):
    """A simulator-only resource budget was exceeded."""


class ScenarioName(StrEnum):
    HAPPY = "happy"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"
    CHALLENGE_CAPTCHA = "challenge_captcha"
    CHALLENGE_MFA = "challenge_mfa"
    RATE_LIMIT = "rate_limit"
    TIMEOUT_UNKNOWN = "timeout_unknown"
    SCHEMA_DRIFT = "schema_drift"
    PARTIAL = "partial"
    DENIED = "denied"
    RESURFACING = "resurfacing"


class ScenarioState(StrEnum):
    START = "start"
    CANDIDATE = "candidate"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"
    CHALLENGE_CAPTCHA = "challenge_captcha"
    CHALLENGE_MFA = "challenge_mfa"
    RATE_LIMITED = "rate_limited"
    OUTCOME_UNKNOWN = "outcome_unknown"
    SCHEMA_DRIFT = "schema_drift"
    PARTIAL = "partial"
    DENIED = "denied"
    SIMULATED_ABSENT = "simulated_absent"
    RESURFACED = "resurfaced"
    COMPLETE = "complete"


def is_reserved_mailbox(address: str) -> bool:
    if address.count("@") != 1:
        return False
    local, domain = address.split("@")
    normalized = domain.lower().rstrip(".")
    return bool(
        MAIL_LOCAL.fullmatch(local)
        and MAIL_DOMAIN.fullmatch(normalized)
        and any(
            normalized.endswith(suffix) and len(normalized) > len(suffix)
            for suffix in RESERVED_MAIL_SUFFIXES
        )
    )


@dataclass(frozen=True, slots=True)
class MailFixture:
    recipient: str
    subject: str
    body: str

    def __post_init__(self) -> None:
        if not is_reserved_mailbox(self.recipient):
            raise ValueError("mail fixture recipient must use a reserved domain")
        if len(self.subject.encode("utf-8")) > MAX_MAIL_SUBJECT_BYTES:
            raise ResourceLimitError("mail fixture subject exceeds hard cap")
        if len(self.body.encode("utf-8")) > MAX_MAIL_BODY_BYTES:
            raise ResourceLimitError("mail fixture body exceeds hard cap")


@dataclass(frozen=True, slots=True)
class ScenarioStep:
    from_state: ScenarioState
    to_state: ScenarioState
    status_code: int
    body: bytes
    evidence: bytes = b""
    available_after_seconds: int = 0
    mail: MailFixture | None = None

    def __post_init__(self) -> None:
        if not 100 <= self.status_code <= 599:
            raise ValueError("scenario status code is invalid")
        if len(self.body) > MAX_RESPONSE_BODY_BYTES:
            raise ResourceLimitError("scenario response body exceeds hard cap")
        if len(self.evidence) > MAX_EVIDENCE_BYTES:
            raise ResourceLimitError("scenario evidence exceeds hard cap")
        if self.available_after_seconds < 0:
            raise ValueError("scenario delay cannot be negative")


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    name: ScenarioName
    steps: tuple[ScenarioStep, ...]

    def __post_init__(self) -> None:
        if not self.steps:
            raise ValueError("scenario must contain at least one step")
        expected = ScenarioState.START
        for step in self.steps:
            if step.from_state is not expected:
                raise UnknownTransitionError(
                    f"scenario {self.name.value} has unknown transition from {expected.value}"
                )
            expected = step.to_state


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    scenario: ScenarioName
    state: ScenarioState
    status_code: int
    body: bytes
    evidence: bytes
    occurred_at: str
    mail: MailFixture | None
