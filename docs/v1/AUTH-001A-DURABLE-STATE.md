# AUTH-001A — durable authentication decision state

Status: **IN_PROGRESS implementation evidence; no AUTH-001 promotion**.

This slice moves the accepted SPIKE-AUTH decision semantics behind the existing
`AuthDecisionStore` port into an owned SQLite transaction. It does not provide host-secret
custody, a production terminal driver, HTTP/browser authentication, a permissioned CLI channel,
backup recovery, or any external action authority.

## Implemented boundary

- Migration `0002_auth_decision_state` creates one versioned, singleton decision document and a
  database-enforced global registry for root/operator/service authority handles.
- The document is a strict canonical encoding of opaque UUIDs, finite enums, UTC instants,
  counters, booleans, and fixed-size SHA-256 digests. Raw `OpaqueCredential`, `Sensitive`, token,
  password, PII, broker, browser, and network values are unrepresentable.
- `SqliteAuthDecisionStore` reloads the complete decision document inside the repository-owned
  `SQLiteRuntime` unit of work. That runtime acquires the only process/engine writer lease and
  starts every application decision with `BEGIN IMMEDIATE`.
- Multiple threads entering through one service are serialized before runtime admission. A
  second process/engine remains rejected by `SQLiteRuntime`; this slice makes no multi-writer or
  distributed-auth claim.
- Every one-use consume and its replacement records commit together. A pre-commit failure rolls
  back. If commit succeeds but response delivery is interrupted, the adapter raises
  `AuthCommitOutcomeUnknown`; no credential is returned and the one-use input must never be
  automatically retried.

The volatile adapter remains the semantic oracle. The durable codec is allowlist-based and
rejects unknown collections, record types, enum types, fields, duplicate keys, invalid UUIDs,
invalid digest sizes and malformed domain records.

## Evidence in this slice

Focused tests cover migration round trips, session/replay survival after clean restart, two
concurrent clients through the single service with exactly one bootstrap winner, rollback before
commit, committed-but-undelivered outcome handling, raw-secret absence, and static denial of
network/browser/broker/PII dependencies.

This is software-level evidence only. Physical power interruption, exact-host storage behavior,
backup/restore epoch policy, externally authenticated review, and qualified human acceptance
remain open.

## Deferred blockers

AUTH-001 cannot complete until separate reviewed slices provide:

1. external host-secret storage for composition/operator authority, with no database/env/argv
   fallback;
2. a real no-echo terminal adapter with restoration and signal evidence;
3. an explicit backup/restore epoch and reconciliation policy;
4. post-commit/pre-handoff recovery or an accepted permanent fail-closed operator procedure;
5. native restart/power-loss evidence and authenticated package acceptance.

AUTH-002, AUTH-003, UX-001, browser control, connectors and every broker/network surface remain
disabled and `NOT_STARTED`.

## Rollback

Downgrade removes only `auth_decision_state`. It does not delete or rotate external operator-held
authority because this slice does not implement its custody. Rollback after use loses durable auth
decision/replay state and therefore requires explicit reprovisioning; it must not silently fall
back to the volatile adapter.
