from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from simulator.clock import ControllableClock
from simulator.engine import ScenarioEngine, default_scenarios, scenario_catalog_document
from simulator.protocol import (
    MAX_EVIDENCE_BYTES,
    MAX_REQUESTS_PER_SESSION,
    ResourceLimitError,
    ScenarioDefinition,
    ScenarioName,
    ScenarioState,
    ScenarioStep,
    TransitionNotReadyError,
    UnknownScenarioError,
    UnknownTransitionError,
)


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


def test_rate_limit_requires_explicit_clock_advance() -> None:
    clock, engine = _engine()
    first = engine.advance(
        scenario_name=ScenarioName.RATE_LIMIT,
        session_id="rate-limit",
        expected_state=ScenarioState.START,
    )
    assert first.state is ScenarioState.RATE_LIMITED
    with pytest.raises(TransitionNotReadyError, match="not ready"):
        engine.advance(
            scenario_name=ScenarioName.RATE_LIMIT,
            session_id="rate-limit",
            expected_state=ScenarioState.RATE_LIMITED,
        )
    clock.advance(seconds=60)
    second = engine.advance(
        scenario_name=ScenarioName.RATE_LIMIT,
        session_id="rate-limit",
        expected_state=ScenarioState.RATE_LIMITED,
    )
    assert second.state is ScenarioState.CANDIDATE
    assert second.occurred_at == "2030-01-01T00:01:00Z"


def test_resurfacing_is_scripted_and_clock_gated() -> None:
    clock, engine = _engine()
    session = "resurfacing"
    candidate = engine.advance(
        scenario_name=ScenarioName.RESURFACING,
        session_id=session,
        expected_state=ScenarioState.START,
    )
    absent = engine.advance(
        scenario_name=ScenarioName.RESURFACING,
        session_id=session,
        expected_state=candidate.state,
    )
    with pytest.raises(TransitionNotReadyError):
        engine.advance(
            scenario_name=ScenarioName.RESURFACING,
            session_id=session,
            expected_state=absent.state,
        )
    clock.advance(seconds=86_400)
    resurfaced = engine.advance(
        scenario_name=ScenarioName.RESURFACING,
        session_id=session,
        expected_state=absent.state,
    )
    assert resurfaced.state is ScenarioState.RESURFACED


def test_unknown_scenario_and_transition_mutations_fail_closed() -> None:
    _, engine = _engine()
    with pytest.raises(UnknownScenarioError, match="unknown simulator scenario"):
        engine.advance(
            scenario_name=cast(ScenarioName, "mutation"),
            session_id="unknown-scenario",
            expected_state=ScenarioState.START,
        )
    engine.advance(
        scenario_name=ScenarioName.HAPPY,
        session_id="wrong-state",
        expected_state=ScenarioState.START,
    )
    with pytest.raises(UnknownTransitionError, match="expected state"):
        engine.advance(
            scenario_name=ScenarioName.HAPPY,
            session_id="wrong-state",
            expected_state=ScenarioState.START,
        )


def test_unknown_declared_transition_is_rejected_at_construction() -> None:
    with pytest.raises(UnknownTransitionError, match="unknown transition"):
        ScenarioDefinition(
            ScenarioName.HAPPY,
            (
                ScenarioStep(
                    ScenarioState.CANDIDATE,
                    ScenarioState.COMPLETE,
                    200,
                    b"mutation",
                ),
            ),
        )


def test_oversized_evidence_mutation_fails_closed() -> None:
    with pytest.raises(ResourceLimitError, match="evidence"):
        ScenarioStep(
            ScenarioState.START,
            ScenarioState.COMPLETE,
            200,
            b"fixture",
            evidence=b"x" * (MAX_EVIDENCE_BYTES + 1),
        )


def test_request_count_has_a_hard_cap() -> None:
    repeated = tuple(
        ScenarioStep(ScenarioState.START, ScenarioState.START, 200, b"fixture")
        for _ in range(MAX_REQUESTS_PER_SESSION + 1)
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
