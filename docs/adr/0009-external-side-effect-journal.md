# ADR-0009: External side-effect and unknown-outcome journal

- Status: Accepted for initial build
- Date: 2026-07-15

## Context

A database transaction cannot atomically commit an HTTP form or email send. An idempotency key containing connector version or attempt generation changes across retry/upgrade and does not represent one user intent. Crashes, lease loss, and restore can leave an external effect unknowable.

## Decision

Assign one immutable `intent_id` to the exact authorized external action; connector upgrades and retries do not change it. Record separate `attempt_id` values. Persist the fenced intent/attempt state machine:

`ready → claimed(fence) → cancelled_before_send | failed_before_send | dispatch_started → transport_proven | outcome_unknown`, with reconciliation from `outcome_unknown` to `send_proven`, `no_send_proven` (which alone permits a new fence), or step-up `abandoned`.

In the final dispatch transaction, re-evaluate actor/profile authority, authorization epoch and plan hash, match policy, connector digest/freshness, destination/disclosure, and all pause switches. Immediately before dialing, the gateway calls online `authorize_and_start` with a single-use nonce and installation dispatch epoch held outside data backups. The core durably records `dispatch_started` before returning permission. Verifier/persistence uncertainty fails closed; no cached permit mode exists.

Only authoritative gateway no-begin evidence permits `failed_before_send` or return from an expired claim. Once `dispatch_started`, a timeout, crash, cancellation, or lost response becomes `outcome_unknown`. Transport proof describes only its transport fact, not acknowledgement or compliance. No automatic retry occurs until reconciliation proves no send. Restore rotates the installation dispatch epoch, invalidates all mailboxes/permits, keeps external actions paused, and marks every restored nonterminal external intent `reconciliation_required` regardless of its creation time.

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
