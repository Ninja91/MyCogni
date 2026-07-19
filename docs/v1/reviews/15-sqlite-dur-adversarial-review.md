# SQLITE-DUR-001 adversarial review and remediation chronology

Review target: integrated decision/evidence commit `0fff920`

Remediation target: integrated code commit `1dfd256`

Current verdict: **REJECT findings remediated; independent re-review pending**.
`SQLITE-DUR-001` remains `IN_PROGRESS`. Reviewer names below are role labels,
not model identities, human qualifications, attestations or certifications.

## Independent review passes against `0fff920`

Three role-separated passes reviewed the implementation and tests without
treating the implementation narrative as proof.

### Platform and storage durability reviewer — REJECT

1. The Darwin filesystem probe used a `stat` format that did not establish a
   validated macOS filesystem/mount source, and there was no unmocked macOS
   regression.
2. Managed database, WAL, SHM, lock and lifecycle files did not uniformly reject
   hard links or wrong ownership; symlinked ancestors and path rebinding were
   insufficiently constrained.
3. Path-based validation and state changes left avoidable time-of-check/time-of-
   use exposure, and raw `OSError` context could disclose private paths.
4. The evidence overstated the portable durability result: Docker-engine restart,
   bounded real-device full and independently reviewed power-interruption drills
   had not been run.

### Backend, concurrency and lifecycle reviewer — REJECT

1. The dirty marker doubled as both open-lifecycle evidence and recovery state;
   a later clean close could erase the unresolved recovery decision.
2. No durable recovery-required latch survived clean restart/no-op operation,
   and migration could proceed while reconciliation remained unresolved.
3. Checkpoint/shutdown failure disposed the Engine and released ownership. A
   leaked checkout could therefore permit an ambiguous handoff to a second
   owner instead of retaining the lease for retry.
4. Connection checkouts were not accounted at the writer lease, so direct lease
   release could occur with a live connection.
5. Application callers could construct unguarded sessions; readiness was not
   enforced by a runtime-owned normal unit-of-work path, and failed/committed/
   rolled-back units were reusable rather than terminal.
6. A caller-selectable `poolclass` could bypass the fixed single-connection
   concurrency contract.

### Security, edge and evidence reviewer — REJECT

1. Ownership/PID validation occurred at checkout but not before every
   connection-configuration, statement and transaction boundary. A SQLAlchemy
   connection inherited across `fork` lacked a deterministic fail-closed test.
2. The security boundary did not explicitly state the residual raw DBAPI/file-
   descriptor inheritance risk after `fork`.
3. Startup recovery errors did not expose a stable typed, PII-free operator
   disposition distinguishing integrity, storage I/O and generic recovery.
4. The evidence document and completion matrix cited pre-integration commit
   hashes that were not ancestors of the integrated branch and lacked the
   rejected-review/remediation chronology.

## Remediation in `1dfd256`

| Rejected finding | Integrated disposition and deterministic evidence |
| --- | --- |
| Broken Darwin probe | Parses `/sbin/mount`, validates mount points, selects the longest real ancestor; unmocked Darwin APFS test added. |
| Weak managed-file boundary | Current-UID, regular-file, single-hard-link and mode checks cover DB/WAL/SHM/lock/dirty/latch names; symlink ancestors fail closed. Directory-relative operations retain a private directory descriptor and use no-follow flags where available. |
| Path leakage | Storage and lease `OSError` causes are replaced with fixed path-free errors; traceback canaries cover assessment and lock acquisition. |
| Marker conflated with recovery | Separate fixed-schema `.recovery-required` latch is created on dirty inheritance/fault, survives clean restart and has no public clear API. |
| Migration during unresolved recovery | Migration role refuses the latch before Engine creation; Alembic/no-op upgrade regression added. |
| Ambiguous shutdown handoff | Busy checkpoint, validation, leaked-checkout and marker-sync failures pause the runtime and retain Engine/lease; second-owner denial and successful retry are tested. |
| Lease released with live checkout | Lease-owned checkout accounting makes `release()` refuse a nonzero count; raw lease regression added. |
| Unguarded/reusable application UoW | Runtime owns the readiness-guarded UoW factory. Entry, commit, rollback and failed `BEGIN IMMEDIATE` are terminal; post-fault and write-before-commit fault regressions added. |
| Pool override | Public `poolclass` parameter removed; fixed one-connection/no-overflow `QueuePool` policy tested. |
| Incomplete PID/lease checks | Engine hooks guard connection setup, SQL execution and begin/commit/rollback; fork-inherited SQLAlchemy connection execution is denied before SQL. |
| Untyped startup recovery | `SQLiteRecoveryError.operator_state` carries fixed PII-free integrity/storage/recovery states; corrupt database and invalid marker regressions added. |
| Unreachable evidence hashes | Evidence now points to integrated ancestors `1d67f87`, `b0c4b38`, `103c977` and remediation `1dfd256`, with this chronology. |

The focused acceptance lane after remediation is 65 passing tests with Ruff and
mypy clean. The exact commands are recorded in `docs/v1/SQLITE-DUR-001.md`.

## Residual risk and next decision

This record does not convert the prior REJECT into ACCEPT. An independent pass
must review commit `1dfd256` and record its own commit-bound verdict.

SQLAlchemy hooks prevent an inherited SQLAlchemy connection from executing in a
forked child, but cannot revoke a raw SQLite/file descriptor inherited outside
that boundary. The owner process must not fork after database open. A malicious
same-UID process with permission to mutate the private directory is also outside
the path-race claim.

Physical power interruption, Docker Desktop engine/VM restart, exact-host
filesystem qualification and a bounded real filesystem/device-full drill remain
unperformed residual evidence. They are deliberately not simulated away or
treated as prerequisites for the deterministic software remediation commit, but
they block `COMPLETE`/`VERIFIED` and any stable local-lite durability claim.
