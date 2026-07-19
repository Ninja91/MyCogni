# ADR-0012: SQLite local-lite ownership and durability eligibility

- Status: Accepted for initial build
- Date: 2026-07-18

## Context

SQLite WAL with `synchronous=FULL` does not by itself coordinate API, CLI,
worker, scheduler and migration writers, prove that a container mount honors
flushes, make copying live files a consistent backup, or decide what to do after
abrupt process termination. MyCogni may sleep for months and later resume work
that can disclose personal information, so an ambiguous shutdown must not be
treated as a clean start.

`SQLITE-DUR-001` freezes the V1 local-lite software contract. It is an
eligibility decision and deterministic prototype, not a physical power-loss or
host-filesystem certification.

## Decision

### One database-owning process

Exactly one `all-in-one` application process owns local-lite SQLite writes. Its
API, one worker and one scheduler run as components of that process. CLI and
other processes use the authenticated control-plane API; they do not open the
database. A migration process may own the database only while the application
is stopped.

Both application and migration roles acquire the same non-blocking kernel
advisory lock before opening SQLite. A process-local registry also rejects a
second owner in the same process. The lock contains only a schema and role; it
has no PID, timestamp or lease expiry. MyCogni never reclaims ownership from a
PID, file age, modification time or wall clock. The kernel releases ownership
when the descriptor/process ends.

One lease binds exactly one SQLAlchemy Engine. The application Engine uses a
one-connection pool with no overflow, so worker/scheduler transactions cannot
use concurrent SQLite connections. Every application unit of work starts with
`BEGIN IMMEDIATE`; an unexpected `SQLITE_BUSY` or `SQLITE_LOCKED` therefore
means an unsupported writer bypassed the contract and fails readiness closed.

### Connection policy

Every connection sets and reads back the following values before use:

| PRAGMA | Required value | Purpose |
| --- | --- | --- |
| `foreign_keys` | `ON` | enforce relational integrity |
| `journal_mode` | `WAL` | crash recovery and reader/writer isolation |
| `synchronous` | `FULL` | request SQLite's strongest ordinary WAL sync policy |
| `busy_timeout` | configured 1–30,000 ms | bounded contention handling |
| `trusted_schema` | `OFF` | reduce schema-controlled function risk |
| `secure_delete` | `ON` | overwrite deleted SQLite content where SQLite can |
| `temp_store` | `MEMORY` | avoid SQLite plaintext temporary files |
| `wal_autocheckpoint` | 1,000 pages | bound routine WAL growth |

Required PRAGMA acceptance, `quick_check` and WAL checkpoints run only while the
writer lease is active. A clean shutdown requires a non-busy
`wal_checkpoint(TRUNCATE)` returning `(0, 0, 0)`, followed by another successful
`quick_check`.

### Storage eligibility

The database must use an absolute path in an existing non-symlink private
directory with mode `0700` or stricter. Existing database, WAL and shared-memory
targets must be regular, non-symlink and not group/world writable.

The initial filesystem-type eligibility allowlist is APFS, Btrfs, ext4 and XFS.
Unknown types and known network, ephemeral, overlay or host-sharing types fail
closed, including NFS, SMB/CIFS, 9p, tmpfs, overlayfs, FUSE and virtiofs. Docker
Desktop host bind mounts commonly appear as virtiofs and are therefore
ineligible. A Docker named volume may appear as ext4 inside the Linux VM and can
pass this first check; that does not prove its host storage or engine-restart
behavior.

Filesystem-type detection is only eligibility for later conformance. A release
claim still requires an exact host/OS/runtime/filesystem matrix, real bounded
disk-full and Docker engine-restart drills, and an independently reviewed
power-interruption method. The implementation does not claim that `fsync`,
`FULL`, WAL or an allowlisted type proves physical media flush.

### Dirty shutdown and readiness

After ownership and storage checks, the owner creates a fixed-schema, PII-free
dirty marker and fsyncs the file and parent directory before database use.
Startup always runs `quick_check`. If the marker already existed, startup also
runs a passive WAL checkpoint and reports:

- `recovery_required`;
- not accepting new work;
- external actions must remain paused.

Committed WAL transactions may recover; an open transaction must roll back.
That fact never resolves an external-action outcome. Domain reconciliation and
step-up resume remain separate successor work.

Only successful clean-shutdown checks may remove and directory-fsync the marker.
The writer lock remains held through removal. If removal/fsync fails, the marker
is recreated and fsynced before releasing ownership; if it cannot be preserved,
the process retains the lock and fails closed. There is no marker-age shortcut.

`SQLITE_FULL`, `SQLITE_IOERR`, corruption/not-a-database, and unexpected writer
contention produce fixed PII-free operator states, stop accepting new work and
keep external actions paused. Raw exception text and filesystem paths are not
retained in readiness state.

### Backup boundary

Copying the database, `-wal`, or `-shm` files with `cp`, filesystem copy APIs or
container-volume snapshots is not a supported managed backup. A future
`BAK-001` adapter must run under writer ownership and use SQLite's online Backup
API (or an independently reviewed equivalent), bind its manifest to schema and
journal/checkpoint boundaries, and exercise restore. External operator snapshots
remain outside MyCogni's inventory and recovery claim.

## Consequences

- Local-lite has a simple, enforceable writer topology but cannot scale by
  starting more Uvicorn workers, schedulers or direct-database CLIs.
- The one-connection pool trades concurrency for deterministic correctness on a
  low-resource single-person installation.
- Dirty startup remains usable for inspection/recovery but cannot silently
  resume new or external work.
- Migrations share the same ownership, marker, integrity and checkpoint
  lifecycle as the application.
- Supported deployment documentation must distinguish eligibility from a tested
  host conformance result.

## Alternatives

Multiple SQLite writer processes with only `busy_timeout` were rejected because
they make migration, scheduler and dispatch ordering harder to reason about.
PID files and time-based stale-lock recovery were rejected because PID reuse and
clock/file-age ambiguity can admit two writers. `locking_mode=EXCLUSIVE` was not
used as a replacement for the explicit owner contract. PostgreSQL remains a
post-v1 cloud-small adapter, not a local-lite escape hatch. Raw live-file copy was
rejected because it can omit or mismatch WAL state.

## Security and privacy impact

The contract reduces corrupt state, duplicate job execution and unsafe resume
after an ambiguous stop. Private path data is excluded from public exception
messages and operator states. It does not protect against a compromised owner
process, root, kernel, storage firmware, rollback of all database/marker/lock
files, or operator copies outside the managed backup inventory.

## Review trigger

Change to process topology, connection pool, transaction begin mode, PRAGMAs,
SQLite version, filesystem allowlist, container storage, backup method, dirty
marker protocol, readiness mapping, migration flow, or any observed corruption,
duplicate writer, missed pause or failed recovery.
