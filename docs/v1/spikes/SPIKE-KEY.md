# SPIKE-KEY — explicit local KEK and profile-key wrap boundary

Status: `IN_PROGRESS`. The native owner-only provider and strict wrap contract are implemented at
the source/fixture level with 59 focused tests; exact-target adversarial review is pending. macOS
Keychain, rootless Linux Engine, Docker Desktop, durable rotation/catalog and backup-recovery
evidence remain open. This document does not promote `KEY-001`, `KEY-002`,
`SPIKE-BACKUP`, `THR-KEYS-001` or `VFY-KEYS-001`.

## Question and disposition

Can a local MyCogni installation wrap independent random profile keys while keeping its
installation KEK outside data/evidence archives and failing closed across missing, wrong, unsafe,
restart and fork conditions?

ADR-0013 accepts a narrow answer for implementation: one explicitly configured provider; a
strict versioned AES-256-GCM record with canonical AAD; no fallback, runtime provisioning or
automatic repair; and one native owner-only file baseline. Container and Keychain custody remain
separate conformance rows rather than inferred equivalents.

## Trusted boundary

```text
trusted composition
  |-- exact provider profile + provider instance + KEK version
  |-- installation identity
  |-- disallowed data/evidence/archive roots
  v
application SecretPort
  |-- readiness / exact active KEK reference
  |-- create fresh random profile DEK and wrap
  |-- open wrapped DEK as short-lived opaque handle
  v
adapter-private KEK provider
  |-- canonical AAD v1 + AES-256-GCM
  |-- descriptor-safe pre-provisioned file read
  |-- PID, permissions, link and path-separation checks
  v
owner-only key source outside every managed archive root
```

Raw KEK bytes never cross the application port. Ordinary runtime code has no key-create,
overwrite, provider-discovery or fallback operation. `Sensitive[T]` remains only a rendering
guard and is not used as an access-control claim.

## Record and AAD contract

The wrapped record accepts only format/AAD version 1, suite `A256GCM`, a 12-byte nonce, 48-byte
ciphertext/tag and the exact `KekRef`. Its `ProfileKeyBinding` contains installation, profile,
profile-key version and catalog-schema version. All integers are bounded before encoding.

AAD v1 is the fixed binary sequence in ADR-0013. Substituting any installation, profile, key
version, catalog version, provider kind, provider instance, KEK UUID, KEK version or suite must
make opening fail without returning plaintext. Unknown versions and malformed lengths fail before
AEAD.

The production entropy source is the operating-system RNG. A deterministic nonce source is
injectable only into direct tests. One adapter instance enforces a conservative wrap cap and a
duplicate-nonce latch; durable accounting across processes/restarts is deferred to KEY-001 and is
a production blocker, not an implied property of the spike.

## Native owner-only provider

The spike consumes a separately pre-provisioned, versioned 32-byte KEK file. It never creates,
truncates, overwrites, chmods or repairs it. Every operation checks:

- creator PID still matches the process;
- all path ancestors are non-symlinks and not unsafe writable locations;
- configured key path and every managed root are neither equal nor ancestors/descendants;
- no-follow/close-on-exec descriptor open succeeds;
- descriptor is a regular file owned by the expected effective UID;
- mode is exactly `0400` or `0600`, link count is one and format/length are exact;
- descriptor/path identity still agrees around the cryptographic operation.

Failures use finite redacted categories. Exceptions, repr/str and diagnostics must not reveal the
path, key bytes, nonce, ciphertext, AAD or backend error text.

## Startup, restart and recovery

Routine startup never mutates provider or catalog state. It distinguishes:

| State | Meaning | Required behavior |
| --- | --- | --- |
| unprovisioned | a new install has no configured material | remain not ready; run a separate explicit administration ceremony |
| unavailable | the configured source is absent or locked | pause key-dependent and external work; do not fall back |
| configuration unsafe | type, owner, mode, link, ancestry or overlap is invalid | pause; operator repairs configuration outside runtime |
| recovery required | expected catalog sentinel cannot open with the exact KEK reference | pause; stage exact retained material and verify before commit |
| ready | provider checks and known sentinel agree | allow only the operations implemented by the current package |

A restart must preserve the same non-secret KEK reference and successfully open a synthetic
catalog sentinel before readiness. A forked child must rebuild trusted composition; inherited
provider/handle instances are poisoned. Failed recovery verification never overwrites the live
source or catalog.

## Provider conformance matrix

| Profile | M0 state | Exact evidence still required |
| --- | --- | --- |
| native owner-only file, source/fixture level | implemented; exact-target review pending | real operator path, process restart/recovery and named macOS/Linux host evidence |
| macOS Security.framework helper | open | signed host-native helper, accessibility choice, create/read/delete/update behavior and restart/recovery drill |
| rootless Linux Engine key-only volume | named blocker | UID `65532`, directory `0700`, key `0400`, read-only core mount, separate volume and restart/recovery drill |
| Docker Desktop key-only volume | named blocker | separate exact-host matrix; Linux-container Keychain access is not assumed |
| Linux Secret Service | experimental/deferred | explicit desktop helper only; no container session-bus exposure |
| cloud KMS | post-v1 | separate cloud-small custody, auth, outage, rotation and recovery conformance |

Compose file secrets, environment variables, a root-owned file consumed by UID `65532`, and a
generic keyring search are not accepted profiles. A key-only named volume is separation, not proof
of encryption at rest.

## Executable source evidence

The 59-test focused suite covers strict construction and rendering, a hardcoded exact
KEK/DEK/nonce/AAD/ciphertext/tag vector, randomized round trips, every binding substitution,
malformed format/AAD/suite/nonce/tag, wrong or missing/corrupt provider material, no fallback or
mutation, usage exhaustion, duplicate-nonce latching, forked providers/handles, sentinel checks,
symlink ancestors, hard links, wrong owner/mode/type, unsafe ancestors, archive overlap and
post-AEAD path replacement. Test values are synthetic. Ruff, strict mypy, import boundaries and
the focused guarded test launcher pass.

Host evidence must name the OS, architecture, runtime, filesystem, effective UID and exact target
commit. Docker Desktop is not evidence for rootless Linux Engine, and a native host test is not
container evidence. Unsupported rows remain blockers rather than passes.

## Rotation, deletion and backup boundary

SPIKE-KEY does not implement durable rotation. KEY-002 must stage KEKs through
`PREPARED -> ACTIVE -> RETIRING -> RETIRED`, preserve each profile DEK during rewrap, compare-and-
swap catalog records and retain old KEKs until every known dependent archive expires or is
sanitized. Profile deletion still waits for external-action reconciliation and reports every
known wrapped-catalog backup horizon. SPIKE-BACKUP must prove that managed archives contain the
wrapped catalog but no KEK canary or plaintext key.

## Nonclaims and rollback

This spike is not field/evidence encryption, a durable production catalog, backup recoverability,
rotation, cryptographic deletion, cloud/KMS parity, FIPS validation, Secure Enclave protection,
memory zeroization, host/root compromise protection, Docker-secret encryption, or independent
human cryptographic certification. Python/OpenSSL copies, swap, dumps and hostile same-process
introspection remain outside the claim.

Rollback removes the SPIKE-KEY application/adapter modules and focused tests, reverts ADR-0013,
and leaves `KEY-001`/`KEY-002` unstarted. It must never delete or replace operator key material.
