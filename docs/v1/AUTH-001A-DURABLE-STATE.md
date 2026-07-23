# AUTH-001A — durable authentication decision state

Status: **IN_PROGRESS implementation evidence; no AUTH-001 promotion**.

This slice moves the accepted SPIKE-AUTH decision semantics behind the existing
`AuthDecisionStore` port into an owned SQLite transaction. It does not provide host-secret
custody, a production terminal driver, HTTP/browser authentication, a permissioned CLI channel,
backup recovery, or any external action authority.

The successor [AUTH-001B host-secret custody slice](AUTH-001B-HOST-SECRET-CUSTODY.md) now provides
a source-level native owner-file implementation. Its host, terminal, mutation/reconciliation,
restore, and acceptance limitations remain open and do not promote AUTH-001.

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
- Every one-use consume and its replacement records commit together. A synthetic failure before
  the commit call rolls back. Every exception crossing the actual commit call is conservatively
  `AuthCommitOutcomeUnknown`, even if the backend may have failed before committing. The adapter
  immediately abandons the owned runtime, durably creates its recovery-required latch and returns
  no credential. New and restarted auth work remains prohibited pending a future reviewed
  reconciliation procedure; the one-use input must never be automatically retried.

The volatile adapter remains the semantic oracle behind a public V1 snapshot contract. The
durable codec owns explicit V1 record-field maps and enum-value sets and never derives its wire
format from current operational dataclass fields or enum membership. It is allowlist-based and
rejects unknown collections, collection-specific record types, enum types, fields, duplicate JSON
or record keys, invalid UUIDs, invalid digest sizes, non-UTC timestamps, key/handle mismatches,
authority-registry drift and cross-map binding errors. Checked-in empty and fully populated V1
golden fixtures freeze the top-level shape and every record/tag/enum/set/nullable-terminal
representative; the populated fixture must decode and re-encode byte-for-byte.

## Evidence in this slice

Focused tests cover migration round trips, session/replay survival after clean restart, two
concurrent clients through the single service with exactly one bootstrap winner, synthetic
rollback before commit, real before/after-commit wrapper failures, restart recovery latching,
CAS failure, nonmutating reads, canonical and cross-map mutation rejection, unsupported-version
read rejection without rewrite, database/WAL/SHM raw-secret absence,
and static denial of network/browser/broker/PII dependencies. The remediation-focused auth lane
passed 92 tests, including the complete accepted volatile auth-spike oracle.

This is software-level evidence only. Physical power interruption, exact-host storage behavior,
backup/restore epoch policy, externally authenticated review, and qualified human acceptance
remain open.

## Deferred blockers

AUTH-001 cannot complete until separate reviewed slices provide:

1. exact-host conformance and reviewed mutation/reconciliation for the AUTH-001B owner-file
   source, with no database/env/argv fallback;
2. a real no-echo terminal adapter with restoration and signal evidence;
3. an explicit backup/restore epoch and reconciliation policy;
4. an explicit reviewed reconciliation procedure for the durable outcome-unknown latch;
5. native restart/power-loss evidence and authenticated package acceptance.

AUTH-002, AUTH-003, UX-001, browser control, connectors and every broker/network surface remain
disabled and `NOT_STARTED`.

## Rollback

Downgrade removes both `auth_decision_state` and its derived `auth_authority_handles` registry. It
does not delete or rotate external operator-held authority because this slice does not implement
its custody. Rollback after use loses durable auth decision/replay state and therefore requires
explicit reprovisioning; it must not silently fall back to the volatile adapter.
