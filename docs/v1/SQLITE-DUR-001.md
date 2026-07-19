# SQLITE-DUR-001 implementation evidence

Evidence date: 2026-07-18

Implementation role: Luna-labelled Principal Core/Data Engineer (role label
only; no model identity attestation)

Integrated implementation commits: `1d67f87`, `b0c4b38`, `103c977`,
`1dfd256`, `7cb58fa`

Decision/evidence commits: `0fff920`, plus the documentation commit containing
this revision

## Decision delivered

ADR-0012 freezes the local-lite SQLite contract:

- one `all-in-one` database-owning process containing the API, one worker and
  one scheduler;
- migration uses the same exclusive kernel lock and runtime lifecycle; CLI and
  other processes never open SQLite directly;
- one Engine and one fixed physical pooled connection per ownership lease, with
  record-scoped checkout accounting, an atomic shutdown seal, PID/lease guards
  and runtime-owned, terminal `BEGIN IMMEDIATE` application units of work;
- verified WAL/`FULL`/foreign-key/timeout/trusted-schema/secure-delete/temp-store
  and autocheckpoint PRAGMAs;
- private absolute-path storage on an allowlisted local filesystem type, with
  non-symlink ancestors, owner/link/mode checks for every managed file and
  unknown/network/ephemeral/overlay/virtiofs targets rejected;
- separate fixed-schema dirty marker and durable recovery-required latch,
  startup `quick_check`, dirty-start passive checkpoint, reconciliation/pause
  decision, migration refusal and clean-only truncate checkpoint;
- fail-closed, PII-free readiness states for full disk, I/O failure, corruption
  and unexpected writer contention;
- no raw live-file copy as a managed backup.

## Requirement and threat traceability

| Source | Implemented evidence | Remaining boundary |
| --- | --- | --- |
| `REL-01` | transaction rollback, WAL recovery, one writer, explicit ownership and fault readiness | durable jobs/leases arrive in `JOB-STATE-001` |
| `REL-02` | lock ownership has no time/PID expiry; dirty marker has no age shortcut | bounded scheduler catch-up arrives in `SCHED-001` |
| `OPS-01` | raw live-file copy is explicitly unsupported | online backup/restore proof is `BAK-001`/`BAK-RESTORE-001` |
| `OPS-02` | online Alembic migration shares the runtime lock, marker and validation lifecycle and refuses unresolved recovery | multi-revision migration fixtures and reviewed latch-clear workflow remain `MIG-001` |
| `OPS-03`, `RQ-11`, `RQ-13` | dirty startup reports reconciliation required and external actions paused | restored dispatch epoch and intent reconciliation remain successor packages |
| `TEST-02`, `TEST-03` | deterministic process-kill, rollback, full-disk, lock and checkpoint tests | dispatch-journal edge tests remain `ACTION-001`/`RESTORE-INTENT-001` |
| Database corruption/duplicate writer/unsafe resume | quick checks, one owner/connection, `BEGIN IMMEDIATE`, dirty marker, persistent recovery latch and typed pause | host/root compromise, raw descriptors inherited across fork and whole-directory rollback are nonclaims |
| Diagnostic path disclosure | stable path-free exceptions, suppressed path-bearing causes and traceback canary | broader operator/API mapping arrives with `OPS-001` |

## Deterministic executable evidence

The focused suite contains 72 tests across database policy, migrations and
durability. It covers:

- required PRAGMA readback and rejection of an unexpected physical target;
- same-process and cross-process ownership refusal, including a migration-role
  contender and an artificially old lock-file mtime;
- one-Engine, fixed-pool and one-connection enforcement, including lease release
  refusal while a raw checkout remains;
- lease/PID validation before SQLAlchemy connection setup, execution and
  transaction boundaries, including a fork-inherited SQLAlchemy connection;
- runtime-owned readiness-guarded units of work whose commit, rollback and
  failed entry are terminal before fallible cleanup, including a fault between
  write and commit and a close failure after successful commit;
- WAL reader snapshot behavior while the owned writer commits;
- unexpected raw-writer contention producing `writer_contention`, readiness
  false and external pause;
- a subprocess killed with `SIGKILL` after one committed and one uncommitted
  synthetic transaction: the next startup reports dirty, `quick_check` is `ok`,
  the committed row survives and the uncommitted row is absent;
- deterministic `SQLITE_FULL` using `PRAGMA max_page_count`, without filling the
  host disk: the transaction rolls back and readiness becomes
  `storage_exhausted`;
- synthetic `SQLITE_IOERR` classification without storing raw error text;
- busy `wal_checkpoint(TRUNCATE)` and leaked-checkout shutdown refusal, proving
  the Engine/lease remain owned, a second owner is denied and retry can succeed;
- deterministic close and abandon checkout races proving the atomic seal leaves
  marker/latch evidence and ownership intact when checkout wins, plus denial
  without checkout-accounting underflow when sealing wins;
- abandon latch-directory-sync and lease-release failures proving pause is set
  before persistence and retry evidence/ownership remain available;
- post-`LOCK_UN` descriptor cleanup failure proving successful unlock is the
  truthful ownership boundary and a replacement owner can acquire;
- transient directory-fsync failure after marker unlink, proving the marker is
  recreated and a recovery latch preserved while ownership remains held;
- a recovery latch that survives a later clean restart, blocks migration/no-op
  upgrade and has no public clear API;
- corrupt database and marker typed startup dispositions plus private-path
  traceback redaction;
- hard-link, wrong-owner, symlink-ancestor and managed-file mode rejection using
  directory-relative no-follow checks;
- APFS/Btrfs/ext4/XFS eligibility plus denial of NFS, SMB/CIFS, 9p, tmpfs,
  overlayfs, FUSE, virtiofs and unknown types, with an unmocked Darwin APFS mount
  probe on macOS.

Commands used for the focused acceptance run:

```text
.venv/bin/ruff check src/mycogni/adapters/persistence tests/adapters/persistence migrations/env.py
.venv/bin/mypy -p mycogni
.venv/bin/python scripts/ci/guarded_pytest.py -q \
  tests/adapters/persistence/test_database.py \
  tests/adapters/persistence/test_migrations.py \
  tests/adapters/persistence/test_durability.py
```

## Honest limitations and residual evidence

The subprocess test proves SQLite behavior under abrupt process termination on
the test host. It is not a physical power-loss, torn-write, controller-cache,
kernel panic, storage-firmware or whole-volume rollback test. The filesystem
allowlist is eligibility, not durability certification.

SQLAlchemy hooks reject a connection inherited by a forked child before SQL
execution. They cannot revoke a raw SQLite/file descriptor inherited outside
SQLAlchemy, so the runtime must not fork after database open. Directory-relative
`O_NOFOLLOW` operations reduce path-rebinding exposure but do not claim defense
against a malicious same-UID process that can mutate the private directory.

Before a local-lite deployment can receive a stable support claim, a bounded
host conformance exercise must record exact OS, SQLite/Python/core image,
architecture, container runtime, volume kind and filesystem; restart the Docker
engine/VM during controlled writes; exercise a real bounded filesystem/device
full condition; and use an independently reviewed power-interruption method.
Those drills were deliberately not improvised on this development host, which
had about 2.3 GiB free. No test consumed the host disk.

`SQLITE-DUR-001` remains `IN_PROGRESS`, not complete or verified. Three
independent role-based reviews rejected the first implementation; commit
`1dfd256` remediated those findings. A second pass rejected terminal-cleanup,
abandon-pause and shutdown checkout-race behavior; `7cb58fa` remediates that
second pass, but independent commit-bound re-review and the required host
conformance evidence remain open. It does not promote `JOB-STATE-001`,
`MIG-001`, `BAK-001`, any dispatch journal, or any live external action. See
`docs/v1/reviews/15-sqlite-dur-adversarial-review.md` for chronology and
disposition.
