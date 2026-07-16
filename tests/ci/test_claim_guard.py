"""Failure fixtures for the architecture claim guard."""

import pytest

from scripts.ci.claim_guard import read_claims, validate_claims


def test_guard_rejects_accidental_status_promotion() -> None:
    matrix = """## M6 — stable evidence hold
| Deliverable | Status | Evidence |
| --- | --- | --- |
| Stable release | `VERIFIED` | none |
"""
    claims = read_claims(matrix)
    errors = validate_claims(
        claims,
        {"M6 — stable evidence hold/Stable release": "NOT_STARTED"},
    )
    assert errors == [
        "unreviewed claim promotion: M6 — stable evidence hold/Stable release NOT_STARTED -> VERIFIED"
    ]


def test_guard_rejects_removed_claim() -> None:
    assert validate_claims({}, {"Program summary/Runtime/project skeleton": "IN_PROGRESS"}) == [
        "missing guarded claim: Program summary/Runtime/project skeleton"
    ]


def test_guard_rejects_duplicate_claim_even_when_later_row_is_lower() -> None:
    matrix = """## Program summary
| Area | Status | Evidence |
| --- | --- | --- |
| Runtime/project skeleton | `VERIFIED` | unsafe claim |
| Runtime/project skeleton | `IN_PROGRESS` | masking row |
"""
    with pytest.raises(
        ValueError,
        match="duplicate guarded claim: Program summary/Runtime/project skeleton",
    ):
        read_claims(matrix)
