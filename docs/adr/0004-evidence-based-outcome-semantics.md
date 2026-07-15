# ADR-0004: Evidence-based outcome semantics

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

Removal services and brokers frequently report request activity or completion without proving the identified record is absent. Public and private brokers also permit different levels of verification.

## Decision

Represent candidate, confirmed present, submitted, acknowledged, in progress, broker asserted removed, independently verified removed, partial, denied/exempt, overdue, failed, and resurfaced as distinct states. `verified_removed` requires post-submission evidence satisfying a versioned method/timing policy. Preserve immutable attempts and verification occurrences; never rewrite history when data resurfaces.

## Consequences

- Dashboard numbers may look less impressive but are more meaningful.
- Private brokers may remain permanently asserted/unverified.
- Evidence storage and post-request scans add cost and retention risk.
- Effectiveness can be measured by method and confidence rather than undifferentiated completion.

## Alternatives

A single completed state was rejected as misleading. Treating broker email as verification was rejected. Cryptographically hashing receipts alone proves retained content integrity, not truth of removal.

## Review trigger

New verification method, third-party attestation, a regulator protocol, or a product request to simplify/merge outcome states.
