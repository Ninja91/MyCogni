import pytest


@pytest.mark.governance_acceptance
def probe(governance_criterion):
    governance_criterion("ACC-PROBE-001")
    xfail = pytest.xfail
    xfail("probe")
    assert len([1]) == 1
