# SQLITE-DUR-001 adversarial review and remediation chronology

Review targets: integrated decision/evidence commit `0fff920`; first
remediation `1dfd256`; second remediation `7cb58fa` with evidence `d5ffc53`;
final-round remediation `02f91ce` with evidence `9ed5e28`

Remediation commits: `1dfd256`; `7cb58fa`; `02f91ce`; latest remediation
`f01b3c5`

Current verdict: **edge final REJECT finding remediated; independent re-review
pending**. `SQLITE-DUR-001` remains `IN_PROGRESS`. Reviewer names below are role
labels, not model identities, human qualifications, attestations or
certifications.

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

The focused acceptance lane after first remediation was 65 passing tests with
Ruff and mypy clean.

## Second adversarial pass against `1dfd256` — REJECT

The commit-bound lifecycle pass found that the first remediation still had
unsafe failure ordering and one check-then-act shutdown race:

1. Unit-of-work commit, rollback and failed entry set terminal/session state
   only after `Session.close()` or cleanup. A cleanup exception could leave the
   same unit reusable after a successful commit or failed begin.
2. `abandon()` set full typed pause state only after fallible marker/latch work.
   A latch synchronization failure could retain ownership while still exposing
   a readiness state that did not require external actions to remain paused.
3. Clean close separately checked the checkout count, then disposed the Engine,
   removed the dirty marker and released the lease. A checkout could win between
   the count check and removal, leaving both dirty marker and recovery latch
   absent while release failed.
4. A checkout rejected during shutdown could still trigger a checkin callback,
   underflowing lease accounting because the event record did not say whether
   that checkout had actually been counted.
5. `abandon()` had the same count-check/release race even though its marker/latch
   evidence reduced the consequence.
6. After successful `LOCK_UN`, descriptor cleanup could raise and be reported as
   “ownership retained” even though kernel ownership had already ended.
7. The interactive walkthrough still described auth/runner as unaccepted and
   multi-architecture build evidence as open.

## Second remediation in `7cb58fa`

| Second-pass finding | Integrated disposition and deterministic evidence |
| --- | --- |
| Cleanup before terminal state | UoW detaches the session and publishes terminal state before commit/rollback cleanup. A close failure after successful commit proves second commit and re-entry are denied. |
| Late abandon pause | `abandon()` enters typed `shutdown_blocked` pause before marker/latch work. Injected latch-directory-fsync failure proves pause/evidence/lease retention and retry. |
| Close checkout race | Lease shutdown sealing and checkout counting share one lock. Seal succeeds only at count zero and then denies checkout, SQL and transaction work; if checkout wins, marker/latch and ownership remain. A forced race reproduces the old window. |
| Checkin underflow | Persistent SQLAlchemy connection-record metadata records only successful checkout increments; denied checkout/checkin leaves the count unchanged. |
| Abandon checkout race | Abandon preserves marker/latch first, then uses the same atomic seal before Engine disposal/release. Forced checkout and release-failure regressions retain evidence/ownership. |
| Post-unlock false ownership | Successful `LOCK_UN` is the logical ownership boundary. Later descriptor closes are best-effort cleanup; injected close errors prove the lease becomes inactive and a replacement owner can acquire. |
| Stale walkthrough | Current-status copy now records auth/runner code acceptance, PF-002 multi-architecture evidence and SQLite second-pass remediation without promoting any package to complete. |

The focused acceptance lane after second remediation is 72 passing tests with
Ruff and mypy clean. The exact commands are recorded in
`docs/v1/SQLITE-DUR-001.md`.

## Final backend review against `7cb58fa` — REJECT (P1: 2)

1. Clean close still ran truncate checkpoint and `quick_check` before acquiring
   the shutdown seal. A direct checkout could write and return after those
   validations but before sealing; the deterministic reproduction then removed
   the marker while leaving a 4,152-byte WAL.
2. `release()` called `LOCK_UN` before changing its logical active/sealed state.
   During that unlocked-but-logically-owned interval, ownership checks and a
   concurrent release could re-enter the transition.

## Final architecture review against `7cb58fa` + `d5ffc53` — REJECT (P1: 2)

1. Lease release was serialized, but `SQLiteRuntime.close_cleanly()` and
   `abandon()` had no whole-operation lifecycle exclusion. Concurrent callers
   could unseal or release resources for the other caller.
2. A known-success commit followed by `Session.close()` failure raised a generic
   exception. A job runner could retry an already committed operation. The same
   cleanup behavior after rollback could mask an original context-body error.

Neither final review recorded acceptance.

## Latest remediation in `02f91ce`

| Final-round finding | Integrated disposition and deterministic evidence |
| --- | --- |
| Validation before seal | Clean close seals first, then a one-shot permit admits exactly one designated connection held across truncate checkpoint and `quick_check`. A forced checkout writes and returns immediately before seal; later validation leaves no WAL frames and restart is clean. |
| Broad maintenance privilege | The permit is bound to the sealing thread, consumed by one checkout and held on the fixed single-connection pool for both validations. Non-designated checkout is denied during/after maintenance. |
| Unlocked-but-active release | Explicit `ACTIVE`/`SEALED` → `RELEASING` → `INACTIVE` state is changed under the checkout lock before `LOCK_UN`. Ownership/work and concurrent release are denied while releasing; unlock failure restores the prior sealed state. A barrier test pauses immediately after real unlock. |
| Concurrent runtime lifecycle | A runtime lifecycle lock rejects concurrent close/abandon callers before they can unseal, dispose or release for each other; both operation orderings have deterministic regressions. |
| Known-success cleanup ambiguity | UoW terminalizes before cleanup. Successful commit or rollback remains success if later close fails, while a no-argument PII-free callback pauses runtime/external work. Failed commit still raises, rollback cleanup is best effort, and an original context-body exception is not masked. |

The focused lane after latest remediation is 79 passing tests with Ruff and
mypy clean. This is implementation evidence, not a review verdict.

## Edge final review against `02f91ce` — REJECT (P1: 1)

The backend reviewer accepted its exact target, but the independent edge pass
found a cleanup/shutdown interleaving that still lost recovery evidence:

1. A UoW commit succeeded and `Session.close()` performed its real connection
   checkin, then paused before raising a synthetic cleanup failure. Clean close
   could seal, validate and read `READY` during that delay, remove the marker and
   release. The delayed cleanup callback then published pause without a lease or
   latch; a replacement runtime started `READY`.

The edge review recorded REJECT, not acceptance.

## Cleanup/shutdown remediation in `f01b3c5`

| Edge finding | Integrated disposition and deterministic evidence |
| --- | --- |
| Pause lost after real checkin | Readiness admission is serialized and each runtime-owned UoW reserves the single application-work lock from entry through commit/rollback, real session close, PII-free cleanup-failure pause callback and terminal release. |
| Shutdown crosses pending cleanup | Clean close and abandon atomically deny new admission, then must acquire the same work reservation and hold it through seal, validation, marker handling and lease release. They never block on it while holding the readiness lock. |
| Exact forced interleaving | A deterministic regression delays after real checkin and before close failure. Shutdown fails with marker/latch/lease retained; the callback publishes `storage_io_failure`, commit returns known success with one row, and retry removes only the dirty marker while the recovery latch survives. |
| Reservation release correctness | Failed entry and failed/successful commit/rollback paths terminalize and release the work reservation exactly once; manual commit plus context exit cannot double-release. |

The focused lane after this remediation is 80 passing tests with Ruff and mypy
clean. This remains implementation evidence only.

## Residual risk and next decision

This record does not convert any REJECT into ACCEPT. An independent pass must
review commit `f01b3c5` and record its own commit-bound verdict.

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
