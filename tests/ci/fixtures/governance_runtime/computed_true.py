import pytest


@pytest.mark.governance_acceptance
def probe(governance_criterion):
    governance_criterion("ACC-PROBE-001")
    result = 20 + 22
    assert result == 42
