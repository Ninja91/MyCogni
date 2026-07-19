# SQLITE-DUR-001 implementation evidence

Evidence date: 2026-07-18

Implementation role: Luna-labelled Principal Core/Data Engineer (role label
only; no model identity attestation)

Implementation commits: `0c29ca5`, `222060a`, `f4870b7`

## Decision delivered

ADR-0012 freezes the local-lite SQLite contract:

- one `all-in-one` database-owning process containing the API, one worker and
  one scheduler;
- migration uses the same exclusive kernel lock and runtime lifecycle; CLI and
  other processes never open SQLite directly;
- one Engine and one physical pooled connection per ownership lease, with
  `BEGIN IMMEDIATE` application units of work;
- verified WAL/`FULL`/foreign-key/timeout/trusted-schema/secure-delete/temp-store
  and autocheckpoint PRAGMAs;
- private absolute-path storage on an allowlisted local filesystem type, with
  unknown/network/ephemeral/overlay/virtiofs targets rejected;
- a fixed-schema dirty marker, startup `quick_check`, dirty-start passive
  checkpoint, reconciliation/pause decision, and clean-only truncate checkpoint;
- fail-closed, PII-free readiness states for full disk, I/O failure, corruption
  and unexpected writer contention;
- no raw live-file copy as a managed backup.

## Requirement and threat traceability

| Source | Implemented evidence | Remaining boundary |
| --- | --- | --- |
| `REL-01` | transaction rollback, WAL recovery, one writer, explicit ownership and fault readiness | durable jobs/leases arrive in `JOB-STATE-001` |
| `REL-02` | lock ownership has no time/PID expiry; dirty marker has no age shortcut | bounded scheduler catch-up arrives in `SCHED-001` |
| `OPS-01` | raw live-file copy is explicitly unsupported | online backup/restore proof is `BAK-001`/`BAK-RESTORE-001` |
| `OPS-02` | online Alembic migration shares the runtime lock, marker and validation lifecycle | multi-revision migration fixtures remain `MIG-001` |
| `OPS-03`, `RQ-11`, `RQ-13` | dirty startup reports reconciliation required and external actions paused | restored dispatch epoch and intent reconciliation remain successor packages |
| `TEST-02`, `TEST-03` | deterministic process-kill, rollback, full-disk, lock and checkpoint tests | dispatch-journal edge tests remain `ACTION-001`/`RESTORE-INTENT-001` |
| Database corruption/duplicate writer/unsafe resume | quick checks, one owner/connection, `BEGIN IMMEDIATE`, dirty marker, typed pause | host/root compromise and whole-directory rollback are nonclaims |
| Diagnostic path disclosure | stable path-free exceptions, suppressed path-bearing causes and traceback canary | broader operator/API mapping arrives with `OPS-001` |

## Deterministic executable evidence

The focused suite contains 48 tests across database policy, migrations and
durability. It covers:

- required PRAGMA readback and rejection of an unexpected physical target;
- same-process and cross-process ownership refusal, including a migration-role
  contender and an artificially old lock-file mtime;
- one-Engine and one-connection enforcement;
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
- busy `wal_checkpoint(TRUNCATE)` refusal;
- transient directory-fsync failure after marker unlink, proving the marker is
  recreated before ownership is released;
- corrupt marker and private-path traceback redaction;
- APFS/Btrfs/ext4/XFS eligibility plus denial of NFS, SMB/CIFS, 9p, tmpfs,
  overlayfs, FUSE, virtiofs and unknown types.

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

Before a local-lite deployment can receive a stable support claim, a bounded
host conformance exercise must record exact OS, SQLite/Python/core image,
architecture, container runtime, volume kind and filesystem; restart the Docker
engine/VM during controlled writes; exercise a real bounded filesystem/device
full condition; and use an independently reviewed power-interruption method.
Those drills were deliberately not improvised on this development host, which
had about 2.3 GiB free. No test consumed the host disk.

`SQLITE-DUR-001` remains `IN_PROGRESS`, not complete or verified, until
independent commit-bound review and the required host conformance evidence
exist. It does not promote `JOB-STATE-001`, `MIG-001`, `BAK-001`, any dispatch
journal, or any live external action.
