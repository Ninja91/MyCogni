"""Deterministic, synthetic-only broker fixture boundary.

This package deliberately has no dependency on the trusted ``mycogni`` package.
"""

from simulator.clock import ControllableClock
from simulator.corpus import CorpusSeedID, SyntheticCorpus, build_corpus
from simulator.engine import ScenarioEngine, default_scenarios
from simulator.mail import InMemoryMailCapture
from simulator.protocol import (
    MailFixture,
    ScenarioName,
    ScenarioResult,
    ScenarioState,
    SimulatorProtocolError,
)
from simulator.web import (
    LocalWebSimulator,
    WebRequest,
    WebResponse,
    create_loopback_server,
)

__all__ = [
    "ControllableClock",
    "CorpusSeedID",
    "InMemoryMailCapture",
    "LocalWebSimulator",
    "MailFixture",
    "ScenarioEngine",
    "ScenarioName",
    "ScenarioResult",
    "ScenarioState",
    "SimulatorProtocolError",
    "SyntheticCorpus",
    "WebRequest",
    "WebResponse",
    "build_corpus",
    "create_loopback_server",
    "default_scenarios",
]
