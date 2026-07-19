# ADR-0013: Local KEK provider and profile-key wrap format

- Status: Accepted for initial build
- Date: 2026-07-18
- Refines: ADR-0002 and ADR-0007

## Context

MyCogni needs a local installation key-encryption key (KEK) that remains outside application
data, evidence and managed archives. The earlier deployment document described an ordered list
of possible secret sources. That is unsafe: discovery or fallback can silently select a different
key, environment variables leak too easily, a root-owned secret conflicts with the image's fixed
non-root UID, and Compose secret ownership/encryption behavior is not a portable custody claim.

The wrapped profile-key record also needs a closed algorithm/version vocabulary and canonical
associated data. A generic ciphertext container cannot prevent cross-installation, cross-profile,
cross-version or cross-provider substitution by itself.

## Decision

Composition selects exactly one named provider profile and exact non-secret KEK reference. There
is no provider discovery, ordered fallback, environment-variable KEK, runtime provisioning,
automatic replacement, or legacy-format guessing. Missing, locked, unsafe, corrupt or wrong key
material leaves key readiness paused and does not mutate state. Creating a KEK is a separate,
explicit empty-install administration ceremony; replacing a lost KEK requires an explicitly
destructive full-install reset unless the exact separately retained material is recovered.

The application owns a provider-neutral `SecretPort`. Raw KEK bytes never cross it. Composition
binds the port to one installation and a dedicated existing-install readiness sentinel. Source
readability and installation readiness are different types: wrap/unwrap remains denied until the
dedicated sentinel authenticates and pins the exact key material, parent directory and file state
for that provider lifetime. A later change permanently latches recovery-required until trusted
recomposition; restoring the old file cannot clear the latch. First-sentinel creation belongs to
a separate explicit empty-install administration boundary and is absent from routine runtime.

The port creates a fresh random 32-byte profile DEK, wraps it, and opens it only as a short-lived,
context-managed, issuer/process-bound handle. A synchronized state machine permits one callback
then closes, including under concurrent entry/use/close. PID checks run before inherited handle
locks so raw-fork use cannot block. The
callback can still copy material or reach a Python backing object, so this is only an
accidental-exposure reduction, not an opaque capability or same-process security boundary. A
later paired profile-crypto boundary will own consumption. Routine callers cannot ask for
`read_kek` or `create_kek`.

Wrapped profile keys use one strict record:

- format version 1 and AAD version 1;
- AES-256-GCM only for this format;
- a 96-bit OS-random nonce;
- exactly 48 ciphertext-and-tag bytes for one 32-byte profile DEK;
- an exact provider kind, provider-instance UUID and positive KEK version;
- installation UUID, profile UUID, positive profile-key version and positive catalog-schema
  version in the binding.

AAD v1 is a fixed binary encoding, never ad hoc JSON:

```text
"MyCogni\0profile-dek-wrap\0"
|| u16be(format_version=1)
|| u16be(aad_version=1)
|| installation_uuid[16]
|| profile_uuid[16]
|| u32be(profile_key_version)
|| u16be(catalog_schema_version)
|| provider_kind_id[1]
|| provider_instance_uuid[16]
|| kek_uuid[16]
|| u32be(kek_version)
|| suite_id[1]
```

Every field and bound is validated before AEAD. Unknown formats, suites, provider kinds or
versions fail closed. The complete immutable `ProfileKeyBinding` is stored with each wrapped
record and checked against canonical application state; callers do not reconstruct historical
AAD inputs from the current global schema. Paths and timestamps are excluded from AAD.

SPIKE-KEY implements one native baseline: a pre-provisioned POSIX owner/mode file. Runtime opens it
with no-follow and close-on-exec semantics, validates the descriptor as a regular exact-owner
file with one link, exact `0400` or `0600` mode and exact versioned length, rejects symlink or
unsafe ancestors, and retraverses the configured path to revalidate parent and file identity
around use. The key path must be structurally
disjoint in both directions from every configured data, evidence and managed-archive root.
Every opened directory from the filesystem anchor through the final parent must be owned by root
or the effective UID and must not be group/world writable; the final parent must additionally be
private and owned by the effective UID.
The provider captures its creator process, checks before entropy/locks/record work and rejects use
after fork. A raw fork child cannot construct or use a provider and must `exec`/restart before
recomposition, so inherited global locks are never entered. A second live provider for the same
canonical path is rejected before readiness; after sentinel authentication, a material-digest
domain rejects a second provider even through another installation, reference, copied path or
source alias. POSIX/source checks still cannot prove mount-alias safety on every host.

New wraps use private module-owned OS entropy calls. The runtime constructor has no entropy
injection parameter; executable tests monkeypatch the private wrappers. The sole live provider
enforces a conservative process-lifetime wrap cap and remembers nonces for the actual AES-key
domain across provider recomposition. Every authenticated readiness-sentinel nonce maps to a
domain-separated commitment over its canonical AAD and ciphertext. Exact recomposition of the
same persisted sentinel is idempotent; a distinct authenticated record at the same nonce, or a
sentinel/profile collision, permanently latches new wrapping off. An authenticated sentinel is
accounted under the domain lock immediately after successful authentication, before fixed-value
comparison, source post-validation, or a later live-provider/configuration rejection, because its
nonce has already been used under that AES key. Provider activation remains separate and occurs
only after post-validation succeeds; activation atomically rechecks the record commitment and
domain latch. A later domain nonce-reuse latch invalidates both wrap and unwrap on an already-live
provider. It never retries after an ambiguous
cryptographic/provider failure.
Wrap and unwrap recheck the domain latch under its lock after AEAD plus source post-validation and
before publishing a wrapped record or plaintext handle. This is the operation linearization point;
a latch completed during the in-flight operation prevents publication. Outstanding handles also
consult provider/domain recovery state before activation.
Durable cross-process/restart nonce accounting, rotation and catalog compare-and-swap belong to
KEY-001/KEY-002 and remain prerequisites for production wrapping.

Provider profiles are distinct conformance targets:

1. **Native owner-only file:** the M0 executable baseline on macOS/Linux hosts.
2. **macOS Security.framework helper:** a future host-native helper with a narrow fixed service
   and account namespace; it is not callable from the Linux container and must not use the
   `security` CLI, stdout or environment variables for key material.
3. **Container key-only volume:** a future separately provisioned volume whose directory and
   key are owned by container UID `65532`, mounted read-only into the core and never under the
   data/evidence volume. Rootless Linux Engine and Docker Desktop require separate tests.
4. **Linux Secret Service:** experimental, explicit desktop-only helper, never auto-discovered,
   never the headless/NAS baseline, and never exposed to a container through a session bus.
5. **Cloud KMS:** post-v1 and a separate conformance profile.

Until their exact-host evidence exists, profiles 2–5 are named open rows rather than support
claims. Compose file secrets do not establish portable UID/mode behavior or encryption at rest.

## Lifecycle and recovery

Normal startup is read-only with respect to the provider. Low-level source inspection
distinguishes source-valid, unavailable, unsafe and malformed without authorizing work. Catalog
readiness is only not-ready, ready or recovery-required. Existing-install missing material,
sentinel corruption, AAD mismatch and wrong material all produce the same neutral
recovery-required/catalog-key-mismatch state; AES-GCM cannot prove which occurred. `Unprovisioned`
is reserved for the separate explicit empty-install lifecycle, never inferred from a missing
runtime file. Existing ciphertext plus any non-ready state pauses all dependent work. A dedicated
wrapped catalog sentinel binds recovery to the expected installation/provider/catalog identity;
staged recovery verifies it before committing any provider/catalog transition.

AEAD authentication failure is reported neutrally and latches recovery. Other cryptographic
backend exceptions map to redacted unavailable state, never malformed caller input. If source
revalidation also fails after an AEAD authentication failure, the stronger current source latch
is preserved rather than overwritten by the neutral authentication result. Backend return values
must be exact `bytes` values of the format-defined length; other shapes map to unavailable.
The same current-source precedence applies when bookkeeping and source post-validation fail in
one readiness operation.

Future rotation follows `PREPARED -> ACTIVE -> RETIRING -> RETIRED`. Rewrapping preserves the
same profile DEK and compare-and-swaps its catalog record. Old KEKs remain recoverable until every
known managed archive requiring them expires or is sanitized. Profile deletion still destroys
the live wrapped DEK only after external-action reconciliation and continues to report known
old-catalog archive horizons.

## Consequences

- Headless native operation has a reviewable baseline without making Docker or Keychain parity
  claims.
- Losing the exact KEK can make every encrypted profile permanently unrecoverable by design.
- The separately protected key source and recoverable wrapped catalog are both required for a
  restore.
- Python and OpenSSL may copy secret material; callback code may retain copies/backing access and
  mutable buffers are scrubbed best-effort only.
- POSIX owner/mode checks do not establish macOS ACL or bind/named-volume alias safety; exact-host
  conformance must disposition those cases before support.
- KEY-001 must add durable catalog/nonce/rotation semantics before this spike can become a
  production key subsystem.

## Alternatives

Provider fallback and environment variables were rejected because they make custody ambiguous
and increase leakage. A root-owned Compose secret was rejected as the portable local baseline
because the runtime is UID `65532`. Deriving profile keys from the KEK was already rejected by
ADR-0007 because deletion would be reversible. Storing the KEK beside data or inside managed
archives was rejected because it collapses the backup-separation boundary.

## Security and privacy impact

This decision narrows substitution, accidental disclosure and archive-co-location risk, but it
does not protect against a compromised host, root/admin, debugger, kernel, swap, process memory
inspection, malicious same-process code, or external snapshots/operator copies. It makes no
Secure Enclave, FIPS, memory-zeroization, named-volume encryption, cloud parity, backup
recoverability, rotation, deletion-completion or human cryptographic-certification claim.

## Review trigger

Provider, algorithm, wrap format/AAD, nonce-accounting, catalog, rotation, recovery, archive,
container UID/mount, shared tenancy or cloud-KMS change; any nonce collision; any failed key-loss,
restore, rotation or deletion drill.
