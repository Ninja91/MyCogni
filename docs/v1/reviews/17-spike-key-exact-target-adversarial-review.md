# SPIKE-KEY exact-target adversarial review

Initial target: `2a144bf3a586cbaf05517f84e7c5ae9295e1ace4`.
Second target: `b74afdb67a435d5a4cc37bd78b30917e5e72a944`.

Current verdict: **REJECT**. The initial target had one P0 plus overlapping P1/P2 findings. The
second target closed those findings but introduced an incomplete AES-key nonce/accounting domain
and was also rejected. Neither may be described as code-level accepted. A third candidate exists
only as unreviewed source until a new exact commit and three clean verdicts are recorded.

This is an AI-assisted source review, not independent human cryptographic certification. Three
read-only reviewers inspected the same commit independently and made no file, network or Docker
change:

1. cryptographic format/API and secret-lifetime behavior;
2. backend/filesystem, restart/fork and concurrency behavior;
3. product/operator and open-source portability/claim behavior.

## Initial P0

### A valid inter-operation KEK replacement can split and orphan the catalog

The initial provider's `status()` checked only source shape. `check_readiness()` authenticated a
caller-supplied wrapped profile key but established no lifetime pin, and wrap/unwrap did not
require readiness. An owner-only file containing valid KEK B could therefore replace verified KEK
A between calls. The provider would emit a new record encrypted under B while labeling it with
A's configured reference; restoring A would orphan that new profile DEK. In-call descriptor
revalidation did not cover this inter-operation replacement.

Required remediation: a dedicated existing-install sentinel, a mandatory readiness transition,
composition-bound installation identity, a material/directory/file lifetime pin, and a permanent
recovery-required latch on any later replacement. First-sentinel creation remains a separate
explicit empty-install administration boundary, not a runtime fallback.

## Initial P1 findings

- Source readability was named `READY`; existing-install missing material was named
  `UNPROVISIONED`. Source state and catalog/installation readiness must be distinct, and only an
  explicit empty-install state may be unprovisioned.
- Any AEAD `InvalidTag` was rendered `WRONG_KEY`, even though corruption, wrong AAD and wrong key
  are cryptographically indistinguishable. The operator state must be neutral
  recovery-required/catalog-key mismatch.
- Public constructor entropy seams plus per-instance nonce tracking allowed two instances or a
  restart to bypass the stated per-process cap/collision latch. Runtime constructors must use OS
  RNG only; tests use private monkeypatch seams; a second live provider for the same identity must
  share accounting or fail.
- Fork rejection happened after entropy/record work and before an inherited mutex could be
  reached, allowing a forked child to block. PID checks must precede all input, entropy and locks
  and repeat after lock acquisition.
- `format_version` was not in AAD. Every security-relevant dispatch/version field must be
  authenticated.
- Installation and catalog-schema AAD inputs existed only in caller context, not the persisted
  wrapped record. A complete immutable binding must be stored per record and checked against
  canonical application state.
- The dedicated sentinel contract was absent; any ordinary wrapped profile key could be passed
  as readiness evidence.
- Post-AEAD checks reused the original parent descriptor and could miss a rename/replacement of
  the configured directory path. Revalidation must retraverse from the anchor.
- Some post-use `fstat`/`stat`/close failures could escape the finite redacted error model.
- POSIX mode checks do not establish macOS ACL or mount-alias safety. Those remain exact-host
  blockers and the support wording must be narrowed rather than inferred.

## Initial P2 findings

- The profile-DEK handle allowed repeated callbacks and exposed a backing mutable buffer through
  `memoryview.obj`; it was therefore not an opaque one-use security capability. The remediated
  API must permit only one operation and explicitly retain the same-process-copy nonclaim until a
  paired `ProfileCryptoPort` owns consumption.
- Public site prose said “architecture verified” while all relevant machine packages were
  `IN_PROGRESS`. The wording and guard must say specified/adversarially reviewed instead.
- Deployment diagrams omitted the separate owner-file, Keychain, container-volume and KMS
  conformance rows; contributor status also incorrectly said no simulator existed.
- Source evidence lacked an exact reproduction command and target/runtime record.

## Remediation acceptance gate

The next target must add executable regressions for wrong/replaced key refusal, readiness after
restart, replacement-then-restore latching, existing-install missing source, corrupted and
wrong-purpose sentinel, complete binding reconstruction, exact AAD/AEAD vector, no public entropy
seam, second-provider denial/shared accounting, fork-before-lock/entropy, configured-directory
rename/replacement, finite post-use syscall errors, site claims and provider-profile diagrams.

After remediation, all three reviewers must review the new full commit. Acceptance requires zero
P0/P1/P2 in each exact-target report. Formal package `COMPLETE` still requires authenticated
external approval and the named native/Keychain/rootless-Linux/Docker-Desktop host matrix.

## Second exact target `b74afdb` — REJECT

The second target separated `SourceStatus` from sentinel-authenticated `KeyReadiness`,
persists the complete immutable `ProfileKeyBinding`, uses a dedicated composition-bound
`WrappedReadinessSentinel`, and denies wrap/unwrap before readiness. It pins material plus parent
and file identity for the provider lifetime; a missing, changed, corrupt or non-authenticating
existing-install source permanently latches recovery-required, including after the original file
is restored. It removes public entropy seams, rejects a second live provider for the same
path/reference/installation, checks PID before and after locks, re-traverses the configured path
after AEAD, and makes the profile-DEK handle single-callback with explicit copy/backing nonclaims.

The focused Darwin arm64 / locked CPython 3.12.12 lane reported `59 passed`, including a real fork
against an inherited held lock, replacement-then-restore, initial readiness failure, diagnostic
source-change detection, configured-directory rename/replacement, exact AAD/AEAD vector and typed
post-use syscall failures. That evidence was necessary but insufficient.

The cryptographic/scientist repeat review returned **REJECT** with P0: 0, P1: 1, P2: 2. Backend
and product/OSS reviewers independently confirmed the central P1 before final report delivery; a
backend final response was unavailable because the platform filtered its detailed security
wording, so it is not counted as an acceptance verdict.

### Second-target P1

- Registry and process accounting were keyed below the actual AES-key domain by path, KEK
  reference and installation. The same raw key could therefore be active through another
  installation/path and split cap/collision state.
- The persisted readiness-sentinel nonce was not reserved from profile wrapping. Distinct AAD and
  purpose prefixes do not make same-key AES-GCM nonce reuse safe.

Required remediation: bind live-provider uniqueness and process accounting to authenticated key
material independently of installation/reference/path, reserve every authenticated sentinel
nonce before profile wrapping, and prove both with executable cross-installation/path tests.

### Second-target P2

- `WrappedReadinessSentinel` did not require exact runtime types for format/AAD versions, suite,
  nonce and ciphertext. Bool/float/string-subclass inputs could survive construction and a float
  could later escape as an untyped encoding exception.
- The committed evidence gate named corrupted, wrong-purpose and identity/AAD-substituted
  sentinels plus randomized round trips, but the 59-test suite did not execute all of them.
- Defensive backend review also identified that raw-fork recomposition could reach inherited
  global locks and that `source_status()` could return a stale latched observation after the
  current source changed again.

## Third candidate before new exact review

The current candidate scopes pre-readiness exclusivity to the canonical path and, after sentinel
authentication, scopes live-provider uniqueness plus cap/nonce accounting to a material-digest
AES-key domain. It reserves sentinel nonces before wrapping, keeps that state across in-process
recomposition, rejects raw-fork construction before global locks, reports current low-level source
condition separately from the readiness latch, and strictly validates every sentinel field.

The focused lane now reports `76 passed`. Added evidence covers concurrent and sequential
cross-installation/path use of the same material, sentinel/profile nonce collision, raw-fork
construction with the registry lock held, corrupted/wrong-purpose/identity-substituted sentinels,
strict bool/float/subclass rejection and 32 randomized round trips. This remains unreviewed until
committed and inspected independently by all three new reviewers.
