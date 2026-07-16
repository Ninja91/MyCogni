# Threat catalog report

Generated from `security/threat-catalog.v1.json`, `security/verification-tests.v1.json`, and `security/id-history.v1.json`. Do not edit this report by hand.

Catalog version: `1.1.0`. Schema version: `1`.

| Threat | Severity | Boundary | Owner | Milestone | Control status | Verification |
| --- | --- | --- | --- | --- | --- | --- |
| `THR-AUTH-001` Control-plane actor takeover | P0 | CONTROL_PLANE | CORE | M1 | CONTROL_PLANNED | `VFY-AUTH-001` (PLANNED) |
| `THR-DISPATCH-001` Duplicate, stale, or unauthorized external dispatch | P0 | TRUSTED_CORE | CORE | M1 | CONTROL_PLANNED | `VFY-DISPATCH-001` (PLANNED) |
| `THR-EGRESS-001` Connector exfiltration or network-policy bypass | P0 | EGRESS_GATEWAY | BOUNDARY | M1 | CONTROL_PLANNED | `VFY-EGRESS-001` (PLANNED) |
| `THR-GOV-001` Threat-control traceability silently drifts | P1 | INTEGRATIONS_DIAGNOSTICS | CROSS_CUTTING | M0 | CONTROL_TESTED | `VFY-CATALOG-001` (IMPLEMENTED) |
| `THR-KEYS-001` Backup theft or false cryptographic deletion | P0 | VAULT | CORE | M1 | CONTROL_PLANNED | `VFY-KEYS-001` (PLANNED) |
| `THR-LOGS-001` Raw identity data escapes through diagnostics | P1 | INTEGRATIONS_DIAGNOSTICS | BOUNDARY | M0 | CONTROL_PLANNED | `VFY-LOGS-001` (PLANNED) |
| `THR-RUNNER-001` Connector reads trusted-core secrets | P0 | CONNECTOR_RUNTIME | BOUNDARY | M1 | CONTROL_PLANNED | `VFY-RUNNER-001` (PLANNED) |
| `THR-VERIFY-001` Product reports false proof of removal | P1 | TRUSTED_CORE | CORE | M3 | CONTROL_PLANNED | `VFY-VERIFY-001` (PLANNED) |

## Coverage boundary

This catalog contains 8 selected high-risk threat groups, 1 implemented catalog test mapping, and 7 planned product test mappings.
Implemented mappings name an exact assertion-bearing test that produced PASSED under `--runxfail`; they do not prove a product control beyond that test's scope.
It is not a claim that all threats, requirements, controls, or release gates are covered. `CONTROL_PLANNED` and `PLANNED` are explicitly not implementation evidence.
Full requirement/work-package/ADR coverage remains the scope of `GOV-001`.
