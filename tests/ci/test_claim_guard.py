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


def test_guard_rejects_synthetic_preview_promotion_beyond_reviewed_baseline() -> None:
    matrix = """## Program summary
| Area | Status | Evidence |
| --- | --- | --- |
| Synthetic developer preview | `COMPLETE` | unsafe promotion |
"""
    claims = read_claims(matrix)
    assert validate_claims(
        claims,
        {"Program summary/Synthetic developer preview": "IN_PROGRESS"},
    ) == [
        "unreviewed claim promotion: Program summary/Synthetic developer preview "
        "IN_PROGRESS -> COMPLETE"
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
