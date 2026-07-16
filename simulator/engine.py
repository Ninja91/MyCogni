"""Finite deterministic scenario state machine."""

from __future__ import annotations

import re
from _thread import RLock as RLockType
from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import Any

from simulator.clock import ControllableClock, canonical_instant
from simulator.corpus import canonical_json
from simulator.protocol import (
    MAX_REQUESTS_PER_SESSION,
    MAX_SCENARIOS,
    MAX_SESSIONS,
    MAX_TOTAL_SCENARIO_BYTES,
    MailFixture,
    ReservationError,
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
    _validate_catalog(definitions)
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


@dataclass(frozen=True, slots=True)
class EnginePlan:
    token: int
    session_id: str
    result: ScenarioResult


@dataclass(frozen=True, slots=True)
class _Reservation:
    plan: EnginePlan
    next_session: _Session
    is_new_session: bool


def _validate_catalog(definitions: tuple[ScenarioDefinition, ...]) -> None:
    if not 1 <= len(definitions) <= MAX_SCENARIOS:
        raise ResourceLimitError("scenario catalog count is outside the finite cap")
    names = [definition.name for definition in definitions]
    if any(type(name) is not ScenarioName for name in names) or len(set(names)) != len(names):
        raise ValueError("scenario catalog names must be unique reviewed enum values")
    aggregate_bytes = sum(
        len(step.body)
        + len(step.evidence)
        + (
            len(step.mail.subject.encode()) + len(step.mail.body.encode())
            if step.mail is not None
            else 0
        )
        for definition in definitions
        for step in definition.steps
    )
    if aggregate_bytes > MAX_TOTAL_SCENARIO_BYTES:
        raise ResourceLimitError("scenario catalog aggregate bytes exceed hard cap")


class ScenarioEngine:
    def __init__(
        self,
        *,
        clock: ControllableClock,
        scenarios: tuple[ScenarioDefinition, ...] | None = None,
    ) -> None:
        definitions = default_scenarios() if scenarios is None else scenarios
        _validate_catalog(definitions)
        self._scenarios = {definition.name: definition for definition in definitions}
        self._clock = clock
        self._sessions: dict[str, _Session] = {}
        self._reservations: dict[int, _Reservation] = {}
        self._reserved_sessions: set[str] = set()
        self._next_token = 1
        self._lock = RLock()

    @property
    def scenario_names(self) -> tuple[ScenarioName, ...]:
        with self._lock:
            return tuple(sorted(self._scenarios, key=lambda item: item.value))

    def state(self, session_id: str) -> ScenarioState:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise UnknownTransitionError("unknown simulator session")
            return session.state

    @property
    def session_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _reserve(
        self,
        *,
        scenario_name: ScenarioName,
        session_id: str,
        expected_state: ScenarioState,
    ) -> EnginePlan:
        with self._lock:
            return self._prepare_locked(
                scenario_name=scenario_name,
                session_id=session_id,
                expected_state=expected_state,
            )

    def _prepare_locked(
        self,
        *,
        scenario_name: ScenarioName,
        session_id: str,
        expected_state: ScenarioState,
    ) -> EnginePlan:
        if not SESSION_ID.fullmatch(session_id):
            raise ValueError("session ID is outside the closed fixture grammar")
        if session_id in self._reserved_sessions:
            raise ResourceLimitError("session transition is already reserved")
        definition = self._scenarios.get(scenario_name)
        if definition is None:
            raise UnknownScenarioError("unknown simulator scenario")
        instant = self._clock.now()
        now_seconds = int(instant.timestamp())
        session = self._sessions.get(session_id)
        is_new = session is None
        if session is None:
            reserved_new = sum(
                reservation.is_new_session for reservation in self._reservations.values()
            )
            if len(self._sessions) + reserved_new >= MAX_SESSIONS:
                raise ResourceLimitError("simulator session hard cap reached")
            session = _Session(
                scenario=scenario_name,
                state=ScenarioState.START,
                step_index=0,
                request_count=0,
                transitioned_at_seconds=now_seconds,
            )
        if session.scenario is not scenario_name:
            raise UnknownTransitionError("session is bound to a different scenario")
        next_request_count = session.request_count + 1
        if next_request_count > MAX_REQUESTS_PER_SESSION:
            raise ResourceLimitError("simulator request hard cap reached")
        if session.state is not expected_state:
            raise UnknownTransitionError("expected state does not match scripted state")
        if session.step_index >= len(definition.steps):
            raise UnknownTransitionError("scenario has no transition from terminal state")

        step = definition.steps[session.step_index]
        if step.from_state is not session.state:
            raise UnknownTransitionError("scenario transition is not declared")
        if now_seconds - session.transitioned_at_seconds < step.available_after_seconds:
            raise TransitionNotReadyError("scripted transition is not ready")
        result = ScenarioResult(
            scenario=scenario_name,
            state=step.to_state,
            status_code=step.status_code,
            body=step.body,
            evidence=step.evidence,
            occurred_at=canonical_instant(instant),
            mail=step.mail,
        )
        token = self._next_token
        self._next_token += 1
        plan = EnginePlan(token=token, session_id=session_id, result=result)
        self._reservations[token] = _Reservation(
            plan=plan,
            next_session=_Session(
                scenario=scenario_name,
                state=step.to_state,
                step_index=session.step_index + 1,
                request_count=next_request_count,
                transitioned_at_seconds=now_seconds,
            ),
            is_new_session=is_new,
        )
        self._reserved_sessions.add(session_id)
        return plan

    def transaction_lock(self) -> RLockType:
        return self._lock

    def validate_reservation_locked(self, plan: EnginePlan) -> None:
        reservation = self._reservations.get(plan.token)
        if reservation is None or reservation.plan != plan:
            raise ReservationError("engine transition reservation is stale")
        if plan.session_id not in self._reserved_sessions:
            raise ReservationError("engine session reservation is missing")

    def snapshot_locked(self, plan: EnginePlan) -> _Session | None:
        self.validate_reservation_locked(plan)
        return self._sessions.get(plan.session_id)

    def commit_reservation_locked(self, plan: EnginePlan) -> None:
        self.validate_reservation_locked(plan)
        self._sessions[plan.session_id] = self._reservations[plan.token].next_session

    def restore_snapshot_locked(self, plan: EnginePlan, snapshot: _Session | None) -> None:
        if snapshot is None:
            self._sessions.pop(plan.session_id, None)
        else:
            self._sessions[plan.session_id] = snapshot

    def finalize_reservation_locked(self, plan: EnginePlan) -> None:
        self.validate_reservation_locked(plan)
        self._reservations.pop(plan.token)
        self._reserved_sessions.remove(plan.session_id)

    def cancel_reservation_locked(self, plan: EnginePlan) -> None:
        self._reservations.pop(plan.token, None)
        self._reserved_sessions.discard(plan.session_id)

    def commit(self, plan: EnginePlan) -> None:
        with self._lock:
            snapshot = self.snapshot_locked(plan)
            try:
                self.commit_reservation_locked(plan)
                self.finalize_reservation_locked(plan)
            except BaseException:
                self.restore_snapshot_locked(plan, snapshot)
                self.cancel_reservation_locked(plan)
                raise

    def rollback(self, plan: EnginePlan) -> None:
        with self._lock:
            self.validate_reservation_locked(plan)
            self.cancel_reservation_locked(plan)

    def advance(
        self,
        *,
        scenario_name: ScenarioName,
        session_id: str,
        expected_state: ScenarioState,
    ) -> ScenarioResult:
        plan = self._reserve(
            scenario_name=scenario_name,
            session_id=session_id,
            expected_state=expected_state,
        )
        self.commit(plan)
        return plan.result
