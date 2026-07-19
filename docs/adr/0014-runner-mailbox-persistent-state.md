# ADR-0014: Runner mailbox durable state and containment successor

- Status: Proposed pending independent review
- Date: 2026-07-19

## Decision

The runner mailbox successor uses one SQLite state row under `BEGIN IMMEDIATE`
as the cross-process transition boundary. Each operation authenticates and
decodes one bounded canonical JSON frame, applies the existing finite mailbox
state machine, then replaces that frame and commits before replying. The frame
contains records, credentials digests, evidence/result wrappers, tombstones,
quota counters and time high-water. SQLite stores only the outer AES-GCM
ciphertext, nonce and ciphertext digest.

The caller must provision exact 32-byte storage-key, installation-epoch,
restore-epoch and maintenance-digest material. HKDF derives disjoint outer-frame
and inner evidence/result wrapping keys. The authenticated outer associated data
binds frame version, generation, immutable maintenance digest and limits
fingerprint through the configuration digest, plus installation and restore
epochs. A changed configuration or epoch cannot silently open the state.

The adapter validates all nested authenticated frames and recomputes every
counter before any operation. SQLite is configured WAL/FULL, foreign keys,
trusted schema off, secure delete, memory temp storage and quick check. The
instance refuses use after a DB/I/O ambiguity or after `fork`; reopening with
the same provisioned material performs the integrity scan again.

The runner containment smoke is distinct from PF-002's trusted-core smoke. It
creates a non-root, read-only, networkless role with drop-all capability,
no-new-privileges, default Docker seccomp verification, private IPC/cgroup
namespaces, PID/RAM/CPU caps, init, no restart policy, no ports, no environment
injection, no socket or host bind, one runner-only named state volume and a
noexec/nosuid/nodev tmpfs. It intentionally contains no connector artifact.

## Consequences and nonclaims

This is restart-safe local state evidence, not a release acceptance. It does
not provide a connector artifact, action-scoped credential-delivery topology,
gateway/egress path, user namespace/rootless Engine profile, signed image,
SBOM/provenance, physical power-loss proof, secure deletion/zeroization,
backup/restore rebind workflow, monotonic checkpoint against whole-store
rollback, exact-once consumer integration, malicious connector cleanup, or
real-broker capability. Restore-epoch mismatch intentionally fails closed and
requires a future paused reconciliation/rebind ceremony; it is not automatic
restore recovery.
