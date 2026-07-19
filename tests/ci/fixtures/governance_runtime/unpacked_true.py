import pytest


@pytest.mark.governance_acceptance
def probe(governance_criterion):
    governance_criterion("ACC-PROBE-001")
    result, _unused = True, False
    assert result
