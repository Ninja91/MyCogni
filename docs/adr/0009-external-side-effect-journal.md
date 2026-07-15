# ADR-0009: External side-effect and unknown-outcome journal

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

A database transaction cannot atomically commit an HTTP form or email send. An idempotency key containing connector version or attempt generation changes across retry/upgrade and does not represent one user intent. Crashes, lease loss, and restore can leave an external effect unknowable.

## Decision

Assign one immutable `intent_id` to the exact authorized external action; connector upgrades and retries do not change it. Record separate `attempt_id` values. Persist the fenced state machine:

`ready → dispatch_claimed(fence) → dispatch_started → transport_proven | outcome_unknown | failed_before_send`.

In the final dispatch transaction, re-evaluate actor/profile authority, authorization epoch and plan hash, match policy, connector digest/freshness, destination/disclosure, and all pause switches. The egress gateway validates the monotonic fence before accepting the first byte and rejects stale leases or revoked authority.

Once `dispatch_started`, a timeout, crash, cancellation, or lost response becomes `outcome_unknown`. No automatic retry occurs until a non-mutating reconciliation path proves no send. Restore keeps external actions paused and marks any intent beyond the trusted journal boundary unknown until reconciled.

## Consequences

- Exactly-once external delivery is not claimed.
- The UI and operations need an explicit unknown-outcome workflow.
- Connector transports should carry the stable intent reference where safe.
- Journal durability/RPO is stricter than ordinary projections.

## Alternatives

Attempt-derived idempotency and blind backoff retries were rejected. Distributed transactions with arbitrary broker forms/email are unavailable. Treating a timeout as failure was rejected because it risks duplicate disclosure.

## Security and privacy impact

Final authorization checks prevent stale work from escaping after revocation. Avoiding duplicate sends reduces disclosure and abuse risk.

## Review trigger

New transport, gateway bypass proposal, journal backend change, restore incident, duplicate submission, or attempt to merge unknown/failure states.
