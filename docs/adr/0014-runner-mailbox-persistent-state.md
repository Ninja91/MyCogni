# ADR-0014: Runner mailbox durable state and isolated artifact

- Status: Accepted for initial build
- Date: 2026-07-19

## Context

The source-accepted finite mailbox state machine previously had only volatile
storage. Restart, concurrent-process serialization and the OCI role boundary
therefore remained unproved. A durable adapter must preserve one-claim and
commit-before-reply semantics without introducing executable serialization,
unbounded frames, hidden migration, silent rollback recovery or a second state
machine. The packaging proof must also be an actual mailbox artifact, not the
trusted-core image renamed as a sidecar.

## Decision

Use one SQLite `STRICT` table and one encrypted state row. `BEGIN IMMEDIATE` is
the cross-process writer boundary. Each operation authenticates and decodes a
bounded canonical JSON v1 frame, hydrates the existing volatile domain model,
applies exactly one transition, and atomically replaces the frame before
replying only when state changed. Expected denials that do not change state
roll back without rewriting the frame. Writer lock timeout is one second;
contention returns finite `CONTENDED` backpressure and does not poison the
instance. Any write/commit ambiguity returns `INTERNAL_UNCERTAINTY`, marks
`recovery_required`, and leaves only idempotent best-effort close available.

The caller provisions pairwise-distinct exact 32-byte storage-key,
installation-epoch, restore-epoch and maintenance-digest material. HKDF derives
disjoint outer-frame and inner retained-material keys. AES-GCM associated data
binds the frame version, generation, configuration fingerprint, installation
epoch and restore epoch. At generation 100,000,000 the adapter fails closed;
the operator must rotate the storage key and create a reviewed new lineage.
This bounds random 96-bit nonce use by one state-changing generation per outer
frame and at most one retained-material creation per such transition.

Before SQLite opens the path, the adapter validates every existing ancestor as
a real non-symlink directory and the immediate parent as private/current-UID-owned. It creates a missing database
with `O_NOFOLLOW|O_CREAT|O_EXCL`, then requires a regular current-UID file with
one link, owner-only mode and stable `lstat`/`fstat` device and inode. It repeats
managed-file and identity checks around SQLite configuration and schema setup.
Inherited post-`fork` instances fail closed. This implementation is POSIX-only;
Windows is unsupported.

SQLite uses WAL, `synchronous=FULL`, foreign keys, trusted schema off, secure
delete, memory temp storage and integrity checks. All nested authenticated
frames, lifecycle/material relationships, time ordering (including committed
result no later than acknowledged terminal time), tombstone retention,
credential uniqueness, per-record budgets and global counters/ceilings are
validated before public use. After semantic decoding, the authenticated
plaintext must equal the current writer's exact encoded bytes; alternate
datetime/base64 spellings and record, evidence or tombstone ordering therefore
fail closed even when they decode to the same values. Canonical JSON v1 rejects
duplicate, unknown or missing fields, booleans as integers, nonfinite numbers,
noncanonical encoding and unknown versions. There is no in-place
migration: a future format requires a separately reviewed, offline, paused
migration with backup and rollback evidence.

Package the executable probe as `docker/Dockerfile.runner-mailbox`, installing
only the connector contract dependency anchor and `services.runner_mailbox`;
the trusted `mycogni` application package is build-time asserted absent. The
Compose proof requires an exact local `sha256` image ID, forbids pull, exposes
no ports/environment/socket/host bind/connector/core/vault, uses UID 65532,
read-only root, network none, private IPC and cgroup namespaces, Engine-default
private PID namespace, drop-all capabilities, no-new-privileges, default
seccomp, finite PID/CPU/RAM limits, no restart, one invocation/project-scoped
runner-only state volume and
one noexec/nosuid/nodev tmpfs. A strict rendered-model allowlist and exact
stage/instruction Dockerfile model reject every undeclared surface or build
input. The exact `.dockerignore` model permits only six named runner sources and
ends with global cache/bytecode exclusions after all negations. Runtime export
permits exactly those six files plus the named connector-contract/runtime-anchor
package files, compares every checkout-owned byte including `LICENSE`/`NOTICE`
to the exact revision's Git objects, rejects cache/bytecode anywhere under the
artifact root, and proves the trusted-core package is absent. Cleanup validates Compose
ownership labels and removes only exact resources created by that invocation.
The synthetic probe attempts denied
DNS, host-gateway, metadata, public IPv4, public IPv6 and ULA IPv6 connections.

For the local image-identity proof, BuildKit receives a fixed
`SOURCE_DATE_EPOCH`, fixed OCI created label and exact source revision; bytecode
is disabled and only uv's asserted nondeterministic local-package cache entries
plus matching `RECORD` rows are normalized away. Two clean Git-archive contexts
and an intentionally dirty developer context use separate no-cache builds and
the timestamp-rewriting Docker archive exporter with SBOM/provenance attestations
explicitly disabled. All three must yield the same manifest/image digest,
config digest, creation time, labels and layers. Release attestations are a
separate artifact and acceptance boundary.

## Consequences

Restart and independent-process state transitions now have an executable
durability boundary. Whole-frame rewrite keeps the authenticated format simple
and atomic but amplifies changed writes; bounded quotas cap frame size, and
unchanged denials avoid that cost. One named volume is intentionally writable.
The image is a synthetic mailbox probe, not a network service or connector.
The demonstrated reproducibility claim is limited to the exact native-arm64
local image contract; it does not cover differently tagged archive bytes,
multi-architecture indexes or signed release artifacts.

Whole-database rollback remains undetectable without an external monotonic
checkpoint. Restore-epoch mismatch intentionally fails closed; backup/restore
rebind and operator recovery remain future work. This decision does not claim
physical power-loss qualification, secure erase, signed images, SBOM/provenance,
rootless/user-namespace conformance, action-scoped credential delivery, egress
gateway enforcement, malicious connector cleanup, or real-broker capability.

## Alternatives

- Pickle or object snapshots were rejected because persistence must be bounded,
  non-executable and schema-explicit.
- Per-entity relational tables were deferred because they duplicate domain
  invariants and enlarge the initial transaction/migration surface.
- Rewriting frames after every denial was rejected because it adds nonce use and
  disk amplification without changing durable truth.
- Treating SQLite lock contention as corruption was rejected because finite
  backpressure has a known outcome; post-write ambiguity still poisons.
- Reusing the trusted-core image was rejected because it does not prove artifact
  separation or absence of core code.
- A local LLM is not in this boundary; nondeterministic advice cannot authorize
  mailbox transitions or interpret recovery.

## Security and privacy impact

Sensitive state is encrypted and authenticated at rest, but keys remain an
external provisioning responsibility and ciphertext length/timing remain
observable. Pre-open link/owner/mode checks reduce symlink, hardlink and
cross-user path substitution risk. Network-none and the strict mount/model
allowlist reduce exfiltration surfaces for this artifact. Synthetic fixed probe
keys are deliberately non-production and the probe accepts no user action or
credential input. A valid mailbox result remains an untrusted attempt fact,
never proof of broker transport, acknowledgement, compliance or removal.

## Review trigger

Review before any frame-version migration, generation/key rotation workflow,
Windows support, schema/table split, backup/restore implementation, external
checkpoint, network/API endpoint, connector co-location, new mount/environment/
namespace surface, production secret input, published artifact, or change to
SQLite durability and contention policy.
