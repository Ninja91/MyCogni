# SPIKE-KEY — explicit local KEK and profile-key wrap boundary

Status: `IN_PROGRESS`. Initial exact target `2a144bf` was rejected with one P0 split-key finding;
second target `b74afdb` was rejected for an incomplete AES-key nonce domain; third target
`4f6f0ca` was rejected for an incomplete authenticated-sentinel nonce ledger; fourth target
`211c9ee` was rejected for late authenticated-record accounting and provider/source validation
gaps; fifth target `a0ae32a` was rejected for a record-to-activation race and concurrent handle
state; sixth target `89baaa3` was rejected for missing in-flight publication checks. The current
remediation candidate passes its expanded focused local suite, but a clean new exact-target
review is still pending; no rejected or unreviewed result is acceptance.
macOS Keychain, rootless Linux Engine, Docker Desktop, durable rotation/catalog and
backup-recovery evidence remain open. This document does not promote `KEY-001`, `KEY-002`,
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
  |-- installation + catalog + dedicated sentinel identity
  |-- disallowed data/evidence/archive roots
  v
application SecretPort
  |-- source status (never authorizes) / sentinel-authenticated readiness
  |-- create fresh random profile DEK and wrap
  |-- open wrapped DEK as short-lived single-callback handle
  v
adapter-private KEK provider
  |-- canonical AAD v1 + AES-256-GCM
  |-- descriptor-safe pre-provisioned file read
  |-- lifetime material/directory/file pin + PID/permissions/link/separation checks
  v
owner-only key source outside every managed archive root
```

Raw KEK bytes never cross the application port. Ordinary runtime code has no key-create,
sentinel-create, overwrite, provider-discovery or fallback operation. `Sensitive[T]` remains only
a rendering guard and is not used as an access-control claim. The profile-DEK handle synchronizes
entry, one activation/callback and close, and rejects forked use before inherited locks, but
callback code can copy bytes or reach a Python backing
object; it is not an opaque capability or same-process security boundary.

## Record and AAD contract

The wrapped record accepts only format/AAD version 1, suite `A256GCM`, a 12-byte nonce, 48-byte
ciphertext/tag and the exact `KekRef`. Its persisted immutable `ProfileKeyBinding` contains
installation, profile, profile-key version and catalog-schema version; unwrap checks it against
canonical application state. All integers are bounded before encoding. A
`WrappedReadinessSentinel` is a distinct purpose/type with its own fixed expected material and
installation/catalog/sentinel identity; an ordinary profile record cannot authorize readiness.

AAD v1 is the fixed binary sequence in ADR-0013 and authenticates format plus AAD version.
Substituting any installation, profile, key version, catalog version, provider kind, provider
instance, KEK UUID, KEK version or suite must make opening fail without returning plaintext.
Unknown versions and malformed lengths fail before AEAD. Historical inputs come from the
persisted binding rather than a mutable current global schema.

The production constructor exposes no entropy source. Private module wrappers call the
operating-system RNG and are monkeypatched only in direct tests. Before readiness, only one live
provider may own a canonical source path. Sentinel authentication binds the provider to a
process-wide material-digest domain, so another installation/reference/path using the same AES key
is denied and cannot split the wrap cap or nonce ledger. Sentinel nonces are reserved in that same
domain before profile wrapping. The nonce ledger stores a commitment to each authenticated
sentinel's canonical AAD and ciphertext: exact persisted-record recomposition is idempotent, while
a different authenticated record at the same nonce latches reuse. Authentication is accounted
immediately before fixed-value comparison, source post-validation and subsequent
live-provider/configuration rejection; final provider activation is separate and atomically
rechecks the exact commitment plus the domain latch. A later latch denies both wrap and unwrap on
an already-active provider. Wrap and unwrap recheck the latch after AEAD/source post-validation
under the domain lock before publishing a record or handle; outstanding handles consult the same
recovery state. Durable accounting across
processes/restarts is deferred to KEY-001 and is a production blocker, not an implied property of
the spike.

## Native owner-only provider

The spike consumes a separately pre-provisioned, versioned 32-byte KEK file and dedicated sentinel.
It never creates,
truncates, overwrites, chmods or repairs it. Every operation checks:

- creator PID still matches before input, entropy or lock work and after lock acquisition;
- all path ancestors are non-symlinks and not unsafe writable locations;
- every opened ancestor is owned by root or the effective UID, and the final parent is private
  and owned by the effective UID;
- configured key path and every managed root are neither equal nor ancestors/descendants;
- no-follow/close-on-exec descriptor open succeeds;
- descriptor is a regular file owned by the expected effective UID;
- mode is exactly `0400` or `0600`, link count is one and format/length are exact;
- a fresh anchor-to-parent traversal still resolves the exact pinned directory and file around
  the cryptographic operation;
- sentinel-authenticated material/directory/file state still equals the lifetime pin.

Any mismatch permanently latches recovery-required for that provider object; restoring the old
file does not resume it. Failures use finite redacted categories. Exceptions, repr/str and
diagnostics must not reveal the path, key bytes, nonce, ciphertext, AAD or backend error text.
Unexpected cryptographic backend failures map to unavailable; neutral authentication failure
cannot overwrite a stronger source-removal or unsafe-source latch discovered during post-use
revalidation. Invalid backend result types or lengths also map to unavailable.
POSIX owner/mode checks are source/fixture evidence only; macOS ACLs and mount aliases remain
exact-host qualification blockers.

## Startup, restart and recovery

Routine startup never mutates provider or catalog storage. It distinguishes:

| State | Meaning | Required behavior |
| --- | --- | --- |
| empty-install unprovisioned | an explicit administration state has no catalog/sentinel yet | runtime provider is absent; run the separate bootstrap ceremony |
| source unavailable/unsafe/malformed | low-level file state only | never authorize work; existing installation remains not ready/recovery-required |
| not ready | a new provider process/object has not authenticated its dedicated sentinel | pause all key-dependent and external work |
| recovery required | source changed, is missing, or the sentinel/catalog/key/AAD do not authenticate | latch pause; stage exact retained material and verify in a new composition before commit |
| ready | exact dedicated sentinel and lifetime source pin agree | allow only the operations implemented by the current package |

A restart always begins not ready, must preserve the same non-secret KEK reference and must
authenticate the dedicated catalog sentinel before use. Inherited provider/handle instances and
new provider construction in a raw fork child fail before entropy or inherited locks; the child
must `exec`/restart before rebuilding trusted composition. Failed recovery verification never
pins, clears a latch, or overwrites the live source/catalog.

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

The current remediation candidate's 106-test focused suite covers strict construction and rendering, a
hardcoded exact
KEK/DEK/nonce/AAD/ciphertext/tag vector, randomized round trips, every binding substitution,
malformed format/AAD/suite/nonce/tag, wrong or missing/corrupt provider material, no fallback or
mutation, readiness-before-use/restart, initial-failure and replace-then-restore latching, usage
exhaustion, process-domain duplicate accounting across installation/path recomposition, committed
sentinel records, exact persisted-sentinel recomposition, distinct-record same-nonce refusal,
rejected-concurrent-provider nonce reservation, reserved sentinel/profile nonces, concurrent
same-material provider activation with barrier-controlled contention, concurrent wrap-cap
enforcement, record-to-activation collision races, later-latch unwrap denial, combined
bookkeeping/source-failure precedence, raw-fork provider/handle use with inherited held locks,
in-flight wrap/unwrap latch refusal and outstanding-handle invalidation,
corrupted/wrong-purpose/identity-substituted sentinels, injected backend failure mapping,
invalid backend result shapes, authenticated unexpected-plaintext and post-use-failure accounting,
post-use source-latch precedence, synchronized concurrent handle entry/use/close, 32 randomized round trips,
symlink ancestors, hard links, wrong owner/mode/type, unsafe ancestors, archive overlap,
foreign-owned intermediate ancestors, configured-directory rename/replacement and typed post-use
syscall failures. Test values are synthetic. On Darwin arm64 with locked CPython 3.12.12, the
focused launcher reports `106 passed`;
Ruff and strict source mypy also pass. New exact review and both locked CI runtimes remain required.

Reproduce the focused lane from the repository root using a private temporary directory whose
ancestors are not group/world writable (the provider deliberately rejects a `/tmp` ancestry):

```sh
mkdir -p ../.mycogni-key-tests
chmod 700 ../.mycogni-key-tests
PRIVATE_TEST_TMP="$(cd ../.mycogni-key-tests && pwd)"
TMPDIR="$PRIVATE_TEST_TMP" PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python scripts/ci/guarded_pytest.py -q \
  --basetemp="$PRIVATE_TEST_TMP/pytest-root" \
  tests/application/test_keys.py tests/adapters/keys tests/architecture/test_key_boundaries.py
```

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
