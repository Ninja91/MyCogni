import pytest


@pytest.mark.governance_acceptance
def probe(governance_criterion):
    governance_criterion("ACC-PROBE-001")
    result = ((1 + 2) * 3) ** 2
    assert result >= 81
