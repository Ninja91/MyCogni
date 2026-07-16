from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import cast

import pytest

from simulator.clock import ControllableClock
from simulator.engine import ScenarioEngine, default_scenarios, scenario_catalog_document
from simulator.protocol import (
    MAX_EVIDENCE_BYTES,
    MAX_REQUESTS_PER_SESSION,
    MAX_SESSIONS,
    MAX_STEP_DELAY_SECONDS,
    ResourceLimitError,
    ScenarioDefinition,
    ScenarioName,
    ScenarioState,
    ScenarioStep,
    TransitionNotReadyError,
    UnknownScenarioError,
    UnknownTransitionError,
)

JSON_BODY = b'{"fixture":"test"}'


def _engine() -> tuple[ControllableClock, ScenarioEngine]:
    clock = ControllableClock()
    return clock, ScenarioEngine(clock=clock)


def test_scenario_catalog_matches_canonical_golden_fixture() -> None:
    fixture = Path(__file__).parents[2] / "simulator/fixtures/scenarios.v1.json"
    assert scenario_catalog_document() == fixture.read_bytes()
    assert {definition.name for definition in default_scenarios()} == set(ScenarioName)


@pytest.mark.parametrize("definition", default_scenarios(), ids=lambda item: item.name.value)
def test_every_reviewed_scenario_starts_deterministically(definition: ScenarioDefinition) -> None:
    _, engine = _engine()
    result = engine.advance(
        scenario_name=definition.name,
        session_id=f"session-{definition.name.value.replace('_', '-')}",
        expected_state=ScenarioState.START,
    )
    assert result.state is definition.steps[0].to_state
    assert result.occurred_at == "2030-01-01T00:00:00Z"


def test_rate_limit_and_resurfacing_require_explicit_clock_advances() -> None:
    clock, engine = _engine()
    first = engine.advance(
        scenario_name=ScenarioName.RATE_LIMIT,
        session_id="rate-limit",
        expected_state=ScenarioState.START,
    )
    with pytest.raises(TransitionNotReadyError):
        engine.advance(
            scenario_name=ScenarioName.RATE_LIMIT,
            session_id="rate-limit",
            expected_state=first.state,
        )
    clock.advance(seconds=60)
    assert (
        engine.advance(
            scenario_name=ScenarioName.RATE_LIMIT,
            session_id="rate-limit",
            expected_state=first.state,
        ).state
        is ScenarioState.CANDIDATE
    )

    candidate = engine.advance(
        scenario_name=ScenarioName.RESURFACING,
        session_id="resurfacing",
        expected_state=ScenarioState.START,
    )
    absent = engine.advance(
        scenario_name=ScenarioName.RESURFACING,
        session_id="resurfacing",
        expected_state=candidate.state,
    )
    with pytest.raises(TransitionNotReadyError):
        engine.advance(
            scenario_name=ScenarioName.RESURFACING,
            session_id="resurfacing",
            expected_state=absent.state,
        )
    clock.advance(seconds=86_400)
    assert (
        engine.advance(
            scenario_name=ScenarioName.RESURFACING,
            session_id="resurfacing",
            expected_state=absent.state,
        ).state
        is ScenarioState.RESURFACED
    )


def test_unknown_scenario_transition_and_active_reservation_fail_closed() -> None:
    _, engine = _engine()
    with pytest.raises(UnknownScenarioError):
        engine.advance(
            scenario_name=cast(ScenarioName, "mutation"),
            session_id="unknown-scenario",
            expected_state=ScenarioState.START,
        )
    plan = engine._reserve(
        scenario_name=ScenarioName.HAPPY,
        session_id="reserved",
        expected_state=ScenarioState.START,
    )
    with pytest.raises(ResourceLimitError, match="already reserved"):
        engine._reserve(
            scenario_name=ScenarioName.HAPPY,
            session_id="reserved",
            expected_state=ScenarioState.START,
        )
    engine.rollback(plan)
    assert (
        engine.advance(
            scenario_name=ScenarioName.HAPPY,
            session_id="reserved",
            expected_state=ScenarioState.START,
        ).state
        is ScenarioState.CANDIDATE
    )


def test_rollback_does_not_create_session_or_consume_request_budget() -> None:
    _, engine = _engine()
    for _ in range(MAX_REQUESTS_PER_SESSION + 2):
        plan = engine._reserve(
            scenario_name=ScenarioName.HAPPY,
            session_id="retryable",
            expected_state=ScenarioState.START,
        )
        engine.rollback(plan)
    assert engine.session_count == 0
    assert (
        engine.advance(
            scenario_name=ScenarioName.HAPPY,
            session_id="retryable",
            expected_state=ScenarioState.START,
        ).state
        is ScenarioState.CANDIDATE
    )


def test_same_session_race_has_exactly_one_committed_transition() -> None:
    _, engine = _engine()
    barrier = Barrier(2)

    def advance() -> str:
        barrier.wait()
        try:
            return engine.advance(
                scenario_name=ScenarioName.HAPPY,
                session_id="same-session-race",
                expected_state=ScenarioState.START,
            ).state.value
        except (ResourceLimitError, UnknownTransitionError):
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: advance(), range(2)))
    assert sorted(outcomes) == ["candidate", "denied"]
    assert engine.state("same-session-race") is ScenarioState.CANDIDATE


def test_session_cap_is_race_safe() -> None:
    _, engine = _engine()
    barrier = Barrier(MAX_SESSIONS + 8)

    def create(index: int) -> str:
        barrier.wait()
        try:
            engine.advance(
                scenario_name=ScenarioName.NOT_FOUND,
                session_id=f"cap-{index:03d}",
                expected_state=ScenarioState.START,
            )
            return "created"
        except ResourceLimitError:
            return "denied"

    with ThreadPoolExecutor(max_workers=MAX_SESSIONS + 8) as pool:
        outcomes = list(pool.map(create, range(MAX_SESSIONS + 8)))
    assert outcomes.count("created") == MAX_SESSIONS
    assert outcomes.count("denied") == 8
    assert engine.session_count == MAX_SESSIONS


def test_state_reads_are_serialized_with_transition_commit() -> None:
    clock, engine = _engine()
    engine.advance(
        scenario_name=ScenarioName.RATE_LIMIT,
        session_id="state-read",
        expected_state=ScenarioState.START,
    )
    clock.advance(seconds=60)
    barrier = Barrier(17)

    def read() -> ScenarioState:
        barrier.wait()
        return engine.state("state-read")

    def advance() -> ScenarioState:
        barrier.wait()
        return engine.advance(
            scenario_name=ScenarioName.RATE_LIMIT,
            session_id="state-read",
            expected_state=ScenarioState.RATE_LIMITED,
        ).state

    with ThreadPoolExecutor(max_workers=17) as pool:
        readers = [pool.submit(read) for _ in range(16)]
        transition = pool.submit(advance)
        observed = [future.result() for future in readers]
    assert transition.result() is ScenarioState.CANDIDATE
    assert set(observed) <= {ScenarioState.RATE_LIMITED, ScenarioState.CANDIDATE}


@pytest.mark.parametrize(
    ("body", "status", "delay", "match"),
    [
        (b"not-json", 200, 0, "UTF-8 JSON"),
        (b"\xff", 200, 0, "UTF-8 JSON"),
        (b"{}", 201, 0, "status code"),
        (JSON_BODY, 200, MAX_STEP_DELAY_SECONDS + 1, "delay"),
    ],
)
def test_invalid_step_semantics_fail_closed(
    body: bytes, status: int, delay: int, match: str
) -> None:
    with pytest.raises((ValueError, ResourceLimitError), match=match):
        ScenarioStep(
            ScenarioState.START,
            ScenarioState.COMPLETE,
            status,
            body,
            available_after_seconds=delay,
        )


def test_oversized_evidence_and_catalog_aggregate_fail_closed() -> None:
    with pytest.raises(ResourceLimitError, match="evidence"):
        ScenarioStep(
            ScenarioState.START,
            ScenarioState.COMPLETE,
            200,
            JSON_BODY,
            evidence=b"x" * (MAX_EVIDENCE_BYTES + 1),
        )
    large_body = b'{"fixture":"' + (b"x" * 8_000) + b'"}'
    steps = tuple(
        ScenarioStep(ScenarioState.START, ScenarioState.START, 200, large_body)
        for _ in range(MAX_REQUESTS_PER_SESSION)
    )
    with pytest.raises(ResourceLimitError, match="aggregate"):
        ScenarioEngine(
            clock=ControllableClock(),
            scenarios=(
                ScenarioDefinition(ScenarioName.HAPPY, steps),
                ScenarioDefinition(ScenarioName.NOT_FOUND, steps),
            ),
        )


def test_request_count_has_a_hard_cap() -> None:
    repeated = tuple(
        ScenarioStep(ScenarioState.START, ScenarioState.START, 200, JSON_BODY)
        for _ in range(MAX_REQUESTS_PER_SESSION)
    )
    engine = ScenarioEngine(
        clock=ControllableClock(),
        scenarios=(ScenarioDefinition(ScenarioName.HAPPY, repeated),),
    )
    for _ in range(MAX_REQUESTS_PER_SESSION):
        engine.advance(
            scenario_name=ScenarioName.HAPPY,
            session_id="bounded",
            expected_state=ScenarioState.START,
        )
    with pytest.raises(ResourceLimitError, match="request hard cap"):
        engine.advance(
            scenario_name=ScenarioName.HAPPY,
            session_id="bounded",
            expected_state=ScenarioState.START,
        )
