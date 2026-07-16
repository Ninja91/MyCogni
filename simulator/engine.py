"""Finite deterministic scenario state machine."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from simulator.clock import ControllableClock
from simulator.corpus import canonical_json
from simulator.protocol import (
    MAX_REQUESTS_PER_SESSION,
    MAX_SESSIONS,
    MailFixture,
    ResourceLimitError,
    ScenarioDefinition,
    ScenarioName,
    ScenarioResult,
    ScenarioState,
    ScenarioStep,
    TransitionNotReadyError,
    UnknownScenarioError,
    UnknownTransitionError,
)

SESSION_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
SCENARIO_CATALOG_SCHEMA = "mycogni.synthetic-scenarios.v1"


def _body(value: str) -> bytes:
    return f'{{"fixture":"{value}"}}'.encode()


def default_scenarios() -> tuple[ScenarioDefinition, ...]:
    """Return the reviewed finite scenario catalog in canonical enum order."""
    return (
        ScenarioDefinition(
            ScenarioName.HAPPY,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.CANDIDATE,
                    200,
                    _body("candidate"),
                    evidence=b"synthetic-candidate-evidence",
                    mail=MailFixture(
                        "fixture-recipient@notices.test",
                        "Synthetic acknowledgement",
                        "Fixture-only acknowledgement; no message was delivered.",
                    ),
                ),
                ScenarioStep(
                    ScenarioState.CANDIDATE,
                    ScenarioState.COMPLETE,
                    200,
                    _body("complete"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.NOT_FOUND,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.NOT_FOUND,
                    200,
                    _body("not-found"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.AMBIGUOUS,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.AMBIGUOUS,
                    200,
                    _body("ambiguous"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.CHALLENGE_CAPTCHA,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.CHALLENGE_CAPTCHA,
                    409,
                    _body("challenge-captcha"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.CHALLENGE_MFA,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.CHALLENGE_MFA,
                    409,
                    _body("challenge-mfa"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.RATE_LIMIT,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.RATE_LIMITED,
                    429,
                    _body("rate-limited"),
                ),
                ScenarioStep(
                    ScenarioState.RATE_LIMITED,
                    ScenarioState.CANDIDATE,
                    200,
                    _body("candidate-after-clock-advance"),
                    available_after_seconds=60,
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.TIMEOUT_UNKNOWN,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.OUTCOME_UNKNOWN,
                    504,
                    _body("outcome-unknown"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.SCHEMA_DRIFT,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.SCHEMA_DRIFT,
                    422,
                    _body("schema-drift"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.PARTIAL,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.PARTIAL,
                    206,
                    _body("partial"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.DENIED,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.DENIED,
                    403,
                    _body("denied"),
                ),
            ),
        ),
        ScenarioDefinition(
            ScenarioName.RESURFACING,
            (
                ScenarioStep(
                    ScenarioState.START,
                    ScenarioState.CANDIDATE,
                    200,
                    _body("candidate"),
                ),
                ScenarioStep(
                    ScenarioState.CANDIDATE,
                    ScenarioState.SIMULATED_ABSENT,
                    200,
                    _body("simulated-absent"),
                ),
                ScenarioStep(
                    ScenarioState.SIMULATED_ABSENT,
                    ScenarioState.RESURFACED,
                    200,
                    _body("resurfaced"),
                    available_after_seconds=86_400,
                ),
            ),
        ),
    )


def scenario_catalog_payload(
    scenarios: tuple[ScenarioDefinition, ...] | None = None,
) -> dict[str, Any]:
    definitions = default_scenarios() if scenarios is None else scenarios
    return {
        "schema": SCENARIO_CATALOG_SCHEMA,
        "scenarios": [
            {
                "name": definition.name.value,
                "steps": [
                    {
                        "available_after_seconds": step.available_after_seconds,
                        "body": step.body.decode("utf-8"),
                        "evidence": step.evidence.decode("utf-8"),
                        "from_state": step.from_state.value,
                        "mail": (
                            {
                                "body": step.mail.body,
                                "recipient": step.mail.recipient,
                                "subject": step.mail.subject,
                            }
                            if step.mail is not None
                            else None
                        ),
                        "status_code": step.status_code,
                        "to_state": step.to_state.value,
                    }
                    for step in definition.steps
                ],
            }
            for definition in definitions
        ],
    }


def scenario_catalog_document(
    scenarios: tuple[ScenarioDefinition, ...] | None = None,
) -> bytes:
    payload = scenario_catalog_payload(scenarios)
    catalog_hash = sha256(canonical_json(payload)).hexdigest()
    return canonical_json({**payload, "canonical_hash": catalog_hash}) + b"\n"


@dataclass(slots=True)
class _Session:
    scenario: ScenarioName
    state: ScenarioState
    step_index: int
    request_count: int
    transitioned_at_seconds: int


class ScenarioEngine:
    def __init__(
        self,
        *,
        clock: ControllableClock,
        scenarios: tuple[ScenarioDefinition, ...] | None = None,
    ) -> None:
        definitions = default_scenarios() if scenarios is None else scenarios
        self._scenarios = {definition.name: definition for definition in definitions}
        if len(self._scenarios) != len(definitions):
            raise ValueError("scenario names must be unique")
        self._clock = clock
        self._sessions: dict[str, _Session] = {}

    @property
    def scenario_names(self) -> tuple[ScenarioName, ...]:
        return tuple(sorted(self._scenarios, key=lambda item: item.value))

    def state(self, session_id: str) -> ScenarioState:
        session = self._sessions.get(session_id)
        if session is None:
            raise UnknownTransitionError("unknown simulator session")
        return session.state

    def advance(
        self,
        *,
        scenario_name: ScenarioName,
        session_id: str,
        expected_state: ScenarioState,
    ) -> ScenarioResult:
        if not SESSION_ID.fullmatch(session_id):
            raise ValueError("session ID is outside the closed fixture grammar")
        definition = self._scenarios.get(scenario_name)
        if definition is None:
            raise UnknownScenarioError("unknown simulator scenario")
        session = self._sessions.get(session_id)
        if session is None:
            if len(self._sessions) >= MAX_SESSIONS:
                raise ResourceLimitError("simulator session hard cap reached")
            session = _Session(
                scenario=scenario_name,
                state=ScenarioState.START,
                step_index=0,
                request_count=0,
                transitioned_at_seconds=int(self._clock.now().timestamp()),
            )
            self._sessions[session_id] = session
        if session.scenario is not scenario_name:
            raise UnknownTransitionError("session is bound to a different scenario")
        session.request_count += 1
        if session.request_count > MAX_REQUESTS_PER_SESSION:
            raise ResourceLimitError("simulator request hard cap reached")
        if session.state is not expected_state:
            raise UnknownTransitionError("expected state does not match scripted state")
        if session.step_index >= len(definition.steps):
            raise UnknownTransitionError("scenario has no transition from terminal state")

        step = definition.steps[session.step_index]
        if step.from_state is not session.state:
            raise UnknownTransitionError("scenario transition is not declared")
        now_seconds = int(self._clock.now().timestamp())
        if now_seconds - session.transitioned_at_seconds < step.available_after_seconds:
            raise TransitionNotReadyError("scripted transition is not ready")
        session.state = step.to_state
        session.step_index += 1
        session.transitioned_at_seconds = now_seconds
        return ScenarioResult(
            scenario=scenario_name,
            state=step.to_state,
            status_code=step.status_code,
            body=step.body,
            evidence=step.evidence,
            occurred_at=self._clock.canonical_now(),
            mail=step.mail,
        )
