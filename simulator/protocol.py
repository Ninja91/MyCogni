"""Closed typed protocol shared by synthetic connector and network tests."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

MAX_REQUEST_BODY_BYTES = 4_096
MAX_RESPONSE_BODY_BYTES = 16_384
MAX_HTTP_RESPONSE_BYTES = 18_432
MAX_EVIDENCE_BYTES = 4_096
MAX_MAIL_BODY_BYTES = 8_192
MAX_MAIL_SUBJECT_BYTES = 160
MAX_MAIL_MESSAGES = 16
MAX_REQUESTS_PER_SESSION = 8
MAX_SESSIONS = 64
MAX_CONCURRENT_REQUESTS = 8
MAX_SCENARIOS = 16
MAX_STEPS_PER_SCENARIO = 8
MAX_TOTAL_SCENARIO_BYTES = 65_536
MAX_STEP_DELAY_SECONDS = 366 * 24 * 60 * 60

RESERVED_MAIL_SUFFIXES = ("test", "example", "invalid")
MAIL_LOCAL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._+-]{0,62}[A-Za-z0-9])?")
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
ALLOWED_STATUS_CODES = frozenset({200, 206, 403, 409, 422, 429, 504})


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


class ReservationError(SimulatorProtocolError):
    """A transition or local mail reservation is stale or already finalized."""


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
    if address.count("@") != 1 or address != address.strip():
        return False
    local, domain = address.split("@")
    if not MAIL_LOCAL.fullmatch(local):
        return False
    labels = domain.lower().split(".")
    return (
        len(labels) >= 2
        and labels[-1] in RESERVED_MAIL_SUFFIXES
        and all(DNS_LABEL.fullmatch(label) for label in labels)
    )


def _json_object(body: bytes) -> dict[str, Any]:
    try:
        decoded = body.decode("utf-8")
        value = json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("scenario body must be valid UTF-8 JSON") from error
    if not isinstance(value, dict) or not value:
        raise ValueError("scenario body must be a non-empty JSON object")
    if not all(isinstance(key, str) for key in value):
        raise ValueError("scenario body JSON keys must be strings")
    return value


@dataclass(frozen=True, slots=True)
class MailFixture:
    recipient: str
    subject: str
    body: str

    def __post_init__(self) -> None:
        if not is_reserved_mailbox(self.recipient):
            raise ValueError("mail fixture recipient must use a strict reserved-domain mailbox")
        if not self.subject or "\r" in self.subject or "\n" in self.subject:
            raise ValueError("mail fixture subject is invalid")
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
        if self.status_code not in ALLOWED_STATUS_CODES:
            raise ValueError("scenario status code is outside the finite fixture protocol")
        if not self.body or len(self.body) > MAX_RESPONSE_BODY_BYTES:
            raise ResourceLimitError("scenario response body is empty or exceeds hard cap")
        _json_object(self.body)
        if len(self.evidence) > MAX_EVIDENCE_BYTES:
            raise ResourceLimitError("scenario evidence exceeds hard cap")
        try:
            self.evidence.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("scenario evidence must be valid UTF-8") from error
        if not 0 <= self.available_after_seconds <= MAX_STEP_DELAY_SECONDS:
            raise ValueError("scenario delay is outside the deterministic test horizon")


@dataclass(frozen=True, slots=True)
class ScenarioDefinition:
    name: ScenarioName
    steps: tuple[ScenarioStep, ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.steps) <= MAX_STEPS_PER_SCENARIO:
            raise ResourceLimitError("scenario step count is outside the finite catalog cap")
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
