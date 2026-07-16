"""Reject architecture-status promotions not mirrored in the reviewed baseline."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[2]
MATRIX = REPOSITORY_ROOT / "docs" / "v1" / "COMPLETION_MATRIX.md"
BASELINE = REPOSITORY_ROOT / "ci" / "architecture-claims.json"
STATUS_RANK = {
    "NOT_STARTED": 0,
    "BLOCKED": 1,
    "IN_PROGRESS": 1,
    "COMPLETE": 2,
    "VERIFIED": 3,
}
SECTION_PATTERN = re.compile(r"^## (?P<section>.+)$")
STATUS_PATTERN = re.compile(r"^`(?P<status>[A-Z_]+)`$")


def read_claims(text: str) -> dict[str, str]:
    """Extract guarded summary and milestone claims from the Markdown matrix."""
    section = ""
    claims: dict[str, str] = {}
    for line in text.splitlines():
        section_match = SECTION_PATTERN.match(line)
        if section_match:
            section = section_match.group("section")
            continue
        if not line.startswith("|"):
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if not cells:
            continue
        name = cells[0]
        status = next(
            (match.group("status") for cell in cells if (match := STATUS_PATTERN.match(cell))),
            None,
        )
        if status is None:
            continue
        if section == "Program summary" or name in {
            "M0 milestone",
            "M1 milestone",
            "M2 milestone",
            "M3 milestone",
            "M4 milestone",
            "Release candidate",
            "Stable release",
        }:
            key = f"{section}/{name}"
            if key in claims:
                raise ValueError(f"duplicate guarded claim: {key}")
            claims[key] = status
    return claims


def validate_claims(claims: dict[str, str], baseline: dict[str, str]) -> list[str]:
    """Return deterministic errors for missing or promoted guarded claims."""
    errors: list[str] = []
    for key, maximum in baseline.items():
        current = claims.get(key)
        if current is None:
            errors.append(f"missing guarded claim: {key}")
            continue
        if current not in STATUS_RANK or maximum not in STATUS_RANK:
            errors.append(f"unknown status for {key}: current={current}, maximum={maximum}")
            continue
        if STATUS_RANK[current] > STATUS_RANK[maximum]:
            errors.append(f"unreviewed claim promotion: {key} {maximum} -> {current}")
    return errors


def main() -> int:
    try:
        claims = read_claims(MATRIX.read_text(encoding="utf-8"))
    except ValueError as error:
        print(error)
        return 1
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    errors = validate_claims(claims, baseline)
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Architecture claim guard passed ({len(baseline)} guarded claims).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
