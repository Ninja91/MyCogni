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
fixed one-connection `QueuePool` with no overflow and exposes no caller-selected
pool override, so worker/scheduler transactions cannot use concurrent SQLite
connections. The lease counts checked-out connections and refuses release while
any remain. Engine hooks verify the owning PID and active lease before connection
configuration, every statement and every begin/commit/rollback boundary.

The runtime owns the supported application unit-of-work factory. It checks
readiness before entry and commit, starts each unit with `BEGIN IMMEDIATE`, and
makes commit, rollback and failed entry terminal. An unexpected `SQLITE_BUSY` or
`SQLITE_LOCKED` therefore fails readiness closed and the same unit cannot be
reused after failure.

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

The database must use an absolute path below existing, non-symlink directory
ancestors and a private database directory owned by the service user with mode
`0700` or stricter. The database, WAL, shared-memory, writer-lock, dirty-marker
and recovery-latch names, when present, must be current-user-owned regular files
with exactly one hard link and no group/world write bits. Validation and state
file operations use a retained directory descriptor, directory-relative calls
and `O_NOFOLLOW` where the host supports them. Path-bearing `OSError` causes are
replaced with fixed operator-safe errors.

The initial filesystem-type eligibility allowlist is APFS, Btrfs, ext4 and XFS.
On macOS the probe parses `/sbin/mount`, validates reported mount points and
selects the longest real ancestor; an unmocked Darwin test exercises this source.
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
dirty marker and fsyncs the file and parent directory before database use. The
marker records an open lifecycle; a separate fixed-schema recovery-required
latch records an unresolved operator decision. An inherited dirty marker
durably creates the latch before database work. Startup always runs
`quick_check`; a dirty start also runs a passive WAL checkpoint and reports:

- `recovery_required`;
- not accepting new work;
- external actions must remain paused.

Committed WAL transactions may recover; an open transaction must roll back.
That fact never resolves an external-action outcome. The latch survives clean
restarts and no-op operation, has no public clear API, and blocks migrations.
Domain reconciliation plus an independently reviewed step-up/clear operation
remain separate successor work.

Only successful clean-shutdown checks may remove and directory-fsync the dirty
marker. The writer lock remains held through removal. Checkpoint, integrity,
checked-out-connection, marker removal or directory-sync failure pauses the
runtime, preserves/creates the recovery latch, and retains the Engine and writer
lease for safe retry. A second owner remains excluded. If marker removal cannot
be proven, the dirty marker is restored before returning the failure. There is
no marker-age shortcut and clean shutdown never clears the recovery latch.

`SQLITE_FULL`, `SQLITE_IOERR`, corruption/not-a-database, unexpected writer
contention and blocked shutdown produce fixed typed, PII-free operator states,
stop accepting new work and keep external actions paused. Startup recovery
exceptions carry the same typed operator disposition. Raw exception text and
filesystem paths are not retained in readiness state.

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
  lifecycle as the application, and refuse an unresolved recovery latch.
- Shutdown failure keeps the process as owner until an operator resolves the
  cause and retries; it cannot trade availability for ambiguous handoff.
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
messages and operator states. A forked child is denied at SQLAlchemy connection
and transaction hooks, but Python cannot revoke a raw DBAPI/file descriptor
already inherited across `fork`; the owner process therefore must not fork after
opening SQLite. Directory-relative validation narrows path races but cannot
defeat a malicious same-UID process with directory mutation authority. The
contract also does not protect against a compromised owner process, root,
kernel, storage firmware, rollback of all database/marker/lock/latch files, or
operator copies outside the managed backup inventory.

## Review trigger

Change to process topology, connection pool, transaction begin mode, PRAGMAs,
SQLite version, filesystem allowlist/probe, container storage, backup method,
dirty-marker or recovery-latch protocol, readiness mapping, migration flow, or
any observed corruption, duplicate writer, leaked checkout, missed pause or
failed recovery.
