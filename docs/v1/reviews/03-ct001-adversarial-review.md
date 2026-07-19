# CT-001 adversarial review record

Date: 2026-07-15  
Package: CT-001 shared contracts  
Final integrated commit: `d788d49`

## Scope

The independent review treated schemas and framework-free primitives as hostile-input boundaries. It inspected the merged implementation rather than accepting implementer test claims and used direct probes plus the focused connector/domain suite.

## Rejected iterations and remediation

The first review rejected CT-001 for P1 defects:

- redaction category labels admitted control characters and terminal/log injection;
- evidence had a 64 MiB per-item limit but no 64 MiB aggregate limit;
- disclosure destinations did not have to belong to the release's allowed origins;
- the result vocabulary could not truthfully represent successful prepare, submit, poll or verify attempts.

Remediation made redaction labels immutable safe slugs, enforced the aggregate evidence ceiling, bound disclosure hosts to an allowed-origin hostname and replaced outcome-like results with a finite attempt-fact/reason matrix. It also narrowed external references to bounded opaque tokens, removed key identifiers from ciphertext rendering and required canonical origins and textual UUIDs.

The second review rejected CT-001 because Python dataclass annotations alone did not enforce representation types. Floats could enter compare-and-swap versions and non-bytes values could enter ciphertext fields. The final patch added exact runtime type checks for UUID identifiers, bytes payloads/nonces, opaque key identifiers and integer AAD/optimistic versions, including explicit rejection of booleans and bytes-like substitutes.

## Final disposition

`ACCEPT` with zero P0 and zero P1 findings.

Evidence reproduced after final integration:

- 484 focused connector/domain tests;
- 536 repository tests on Python 3.12.12 and Python 3.13.11;
- strict mypy across 15 source files;
- Ruff format and lint;
- four import-boundary contracts;
- safety and architecture-claim guards;
- generated JSON Schema snapshot consistency.

## Residual P2 follow-ups

- Connector-produced transport-receipt and broker-acknowledgement facts must retain connector provenance during ingestion and must never be projected directly as trusted core verification.
- The SDK currently declares Pydantic `>=2.10,<3`. Add minimum/latest compatibility CI or narrow the range before the first public SDK release so downstream schema behavior cannot drift silently.

These are tracked follow-ups, not authorization for connector execution or evidence that a broker request was sent, accepted or completed.
