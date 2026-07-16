"""Runtime witness for exact governance acceptance criteria.

This plugin deliberately records pytest's actual outcome and criterion calls.  It is
not an approval mechanism; the governance guard separately validates independent
review and trusted-base authorization.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

CRITERION_ID = re.compile(r"^ACC-[A-Z0-9-]+$")


@pytest.fixture
def governance_criterion(request: pytest.FixtureRequest) -> Callable[[str], None]:
    """Register that the running test exercised a named acceptance criterion."""

    invoked: list[str] = getattr(request.node, "_governance_criteria", [])
    request.node._governance_criteria = invoked  # type: ignore[attr-defined]

    def register(criterion_id: str) -> None:
        if not isinstance(criterion_id, str) or CRITERION_ID.fullmatch(criterion_id) is None:
            raise AssertionError("governance criterion must be a canonical ACC identifier")
        if criterion_id in invoked:
            raise AssertionError(f"governance criterion invoked twice: {criterion_id}")
        invoked.append(criterion_id)

    return register


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]):
    outcome = yield
    report = outcome.get_result()
    artifact = os.environ.get("MYCOGNI_GOVERNANCE_ARTIFACT", "").strip()
    if not artifact or report.when != "call":
        return
    payload = {
        "nodeid": item.nodeid,
        "outcome": report.outcome,
        "wasxfail": bool(getattr(report, "wasxfail", False)),
        "criteria": sorted(getattr(item, "_governance_criteria", [])),
        "skip_or_xfail_markers": sorted(
            {
                marker.name
                for marker in item.iter_markers()
                if marker.name in {"skip", "skipif", "xfail"}
            }
        ),
    }
    Path(artifact).write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
