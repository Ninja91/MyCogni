# ADR-0003: Capability-scoped connector sandbox

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

Broker procedures change often and connectors process hostile content while holding selected identity data. A connector ecosystem is both essential and the largest code/PII supply-chain risk.

## Decision

Run connectors outside the trusted core. Each immutable release declares independent capabilities, exact destinations, maximum disclosure schema, provenance, tests, and expiry. Each action receives one short-lived envelope and key, only the minimum sealed attributes, and no database/vault credential. Enforce destination allowlists and resource/time bounds. Quarantine material drift and require separate promotion for observe, prepare, submit, poll, and verify.

## Consequences

- Connector development and packaging are more complex than scripts.
- Browser automation needs a larger isolated runtime.
- Local operating systems differ in egress sandbox strength; container/runtime guidance must be honest.
- Fine-grained capability status gives users more truthful coverage information.

## Alternatives

Loading plugins into the application process was rejected. A central remote connector service was rejected for PII custody. Pure declarative selectors are useful for simple workflows but cannot cover email, portals, or verification and are not a complete security boundary.

## Review trigger

Runtime transport changes, signed registry launch, remote browser execution, plugin-supplied native code, or a connector security incident.
