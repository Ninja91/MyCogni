# SPIKE-KEY exact-target adversarial review

Initial target: `2a144bf3a586cbaf05517f84e7c5ae9295e1ace4`.
Second target: `b74afdb67a435d5a4cc37bd78b30917e5e72a944`.
Third target: `4f6f0ca5f5b445660e85e0fcf24bc36a38e1a4cc`.
Fourth target: `211c9ee53c0300af2ee8ee970351dca82fb6a3fc`.
Fifth target: `a0ae32ab7e6076fa8e9683ea06f8869f04fca8c8`.
Sixth target: `89baaa31e0540196a669509ed77e193e78afdf64`.
Accepted seventh target: `35eda238d7d508b232f7df5ddc74dcf0f817d598`.

Current verdict: **ACCEPT for exact target `35eda238d7d508b232f7df5ddc74dcf0f817d598`**
with P0 0, P1 0 and P2 0 from each of three independent lanes. This is code-level acceptance,
not package completion, host/provider conformance, authenticated attestation or independent human
cryptographic certification. The initial target had one P0 plus overlapping P1/P2 findings. The
second target closed those findings but introduced an incomplete AES-key nonce/accounting domain.
The third target closed that split-domain issue but retained an incomplete authenticated-sentinel
nonce ledger. The fourth target completed record commitments but accounted authenticated records
too late and retained source-validation/evidence gaps. The fifth target closed those paths but
retained an activation race and unsynchronized handle state. The sixth target closed those
findings but lacked an in-flight publication check. All six were rejected and none may be
described as code-level accepted. The seventh target closes the reviewed findings and is the only
accepted exact source target in this review record.

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

## Third exact target `4f6f0ca` — REJECT

The third target scoped pre-readiness exclusivity to the canonical path and, after sentinel
authentication, scopes live-provider uniqueness plus cap/nonce accounting to a material-digest
AES-key domain. It reserves sentinel nonces before wrapping, keeps that state across in-process
recomposition, rejects raw-fork construction before global locks, reports current low-level source
condition separately from the readiness latch, and strictly validates every sentinel field.

Its focused lane reported `76 passed`. Added evidence covered concurrent and sequential
cross-installation/path use of the same material, sentinel/profile nonce collision, raw-fork
construction with the registry lock held, corrupted/wrong-purpose/identity-substituted sentinels,
strict bool/float/subclass rejection and 32 randomized round trips.

Three independent exact-target reviews nevertheless returned **REJECT**:

- cryptographic/scientist: P0 0, P1 1, P2 0, plus one stale-site P3;
- product/operator/open source: P0 0, P1 1, P2 1;
- backend/infra/edge: P0 0, P1 1, P2 2.

### Third-target P1

`sentinel_nonces` was only a set. A different authenticated sentinel record could reuse an
already-recorded sentinel nonce under the same actual AES key and be treated like idempotent
recomposition. In addition, live-provider rejection happened before the newly authenticated
record's nonce was reserved, even though that nonce had already been used under the key.

Required remediation: map each sentinel nonce to a commitment over the complete authenticated
record; allow only exact persisted-record recomposition; latch a different record at the same
nonce or any sentinel/profile collision; and account for authenticated records before later
live-provider/configuration rejection.

### Third-target P2 and claim findings

- readiness allowed unexpected AEAD backend exceptions to escape, and unwrap classified them as
  malformed input rather than redacted unavailability;
- unwrap's neutral `InvalidTag` handler could overwrite a stronger source-removal/unsafe latch
  established by post-use revalidation;
- the visible static-site badge retained `2026-07-18` while its matrix, data attribute and current
  narrative used `2026-07-19`, and the site guard did not enforce equality.

## Fourth exact target `211c9ee` — REJECT

The fourth target stored domain-separated commitments over canonical sentinel AAD and
ciphertext, permits exact record recomposition, latches distinct-record same-nonce reuse, and
accounts authenticated records before later composition rejection. Backend failures are finite
and redacted, while post-use source-latch precedence is preserved. Static-site snapshot dates are
guarded against the completion matrix.

The focused key lane reported `80 passed`; the combined key plus site-guard lane reported `92
passed`. New tests cover exact and distinct sentinel recomposition, nonce reservation by a
concurrently rejected provider, readiness/unwrap backend failures, source-latch precedence and
site-date mutation.

Three independent exact-target reviews returned **REJECT**:

- code/specification quality: P0 0, P1 1, P2 1;
- backend/infra/edge: P0 0, P1 1, P2 2;
- product/operator/open source: P0 0, P1 1, P2 1.

### Fourth-target P1

- Sentinel accounting occurred only after `_material_session` completed post-use validation. A
  record could authenticate successfully, then fail fixed-plaintext or source post-validation,
  without reserving its already-used nonce.
- Intermediate directories rejected group/world writers but accepted a `0755` component owned by
  another local UID, whose owner could rename or replace the next component.

Required remediation: separate authenticated-record accounting from provider activation; account
immediately after valid AEAD output and before fixed-value/source checks; then activate only after
source post-validation. Require every opened ancestor to be owned by root or the effective UID,
while retaining a private effective-UID final parent.

### Fourth-target P2

- Invalid AEAD result types/lengths escaped or were misclassified; validate inside the finite
  backend boundary and map to unavailable.
- “Concurrent” evidence used overlapping objects sequentially; add barrier-controlled activation,
  rejected-record accounting, collision-order and wrap-cap contention tests.
- The site guard compared date strings but accepted an impossible calendar date; parse ISO dates
  and mutation-test the visible, data-attribute and narrative forms.

## Fifth exact target `a0ae32a` — REJECT

The fifth target records a validated authenticated sentinel under the key-domain lock before
fixed-plaintext and source post-validation, while final provider activation remains after full
source validation. It validates every backend return type/length, enforces trusted ownership for
every opened ancestor, adds real thread-contention evidence, and parses the synchronized site date
as an actual ISO calendar date.

The focused key lane reported `98 passed`; the combined key plus site-guard lane reported `113
passed`.

The publication/product lane returned **ACCEPT** with P0 0, P1 0, P2 0. The two implementation
lanes returned **REJECT**:

- code/specification quality: P0 0, P1 0, P2 1;
- backend/infra/edge: P0 0, P1 1, P2 1.

### Fifth-target P1

Provider activation did not recheck `nonce_reuse_latched` under the domain lock. Another provider
could latch conflicting record reuse between the first provider's record step and activation, yet
the first could still report ready. Required remediation: activation atomically verifies the
unlatched state and exact commitment before registering the provider, and a later latch must deny
both wrap and unwrap for an already-active provider.

### Fifth-target P2

- An operation error during initial readiness could mask a simultaneous source post-validation
  failure and overwrite unavailable/unsafe with readable. Preserve the current source latch even
  when record bookkeeping failed first.
- `ProfileDekHandle` check-and-set state was not synchronized. Concurrent callbacks could both
  receive a key view despite the one-callback contract. Synchronize enter/use/close, hold coherent
  state through the callback, and check PID before inherited locks.

## Sixth exact target `89baaa3` — REJECT

The sixth target makes activation recheck the exact record and domain latch atomically,
invalidates all active-provider key use after a later latch, preserves simultaneous post-use
source failure, and implements a synchronized one-callback handle with fork-before-lock behavior.
Barrier-controlled tests cover record-to-activation collision, later-latch unwrap denial,
combined bookkeeping/source failure, concurrent handle entry/use/close and a forked child facing
an inherited held handle lock.

The focused key lane reported `104 passed`; the combined key plus site-guard lane reported `119
passed`. Code/specification and product/OSS lanes returned **ACCEPT** with P0 0, P1 0, P2 0. The
backend/infra lane returned **REJECT** with P0 0, P1 1, P2 0.

### Sixth-target P1

Wrap and unwrap checked the domain latch before AEAD but not after it. A conflicting authenticated
record could latch the domain while encrypt/decrypt was paused, yet the in-flight call could still
publish ciphertext or a plaintext handle. Required remediation: after AEAD and source
post-validation, recheck the latch under the domain lock immediately before publication and define
that check as the operation linearization point. Add barrier-controlled in-flight wrap and unwrap
tests; invalidate an outstanding handle if its provider/domain later enters recovery.

## Seventh exact target `35eda23` — ACCEPT

The accepted target performs the final domain-locked check after full source post-validation and
constructs the wrapped record or handle within that critical section. Outstanding handles consult
provider/domain recovery state before activation. Barrier-controlled tests latch the domain while
encrypt/decrypt is paused and prove no record or handle is returned.

The focused key lane reports `106 passed`; the combined key plus site-guard lane reports `121
passed`. All three independent exact-target lanes returned **ACCEPT**:

- code/specification quality: P0 0, P1 0, P2 0;
- backend/infra/edge reliability: P0 0, P1 0, P2 0;
- product/operator/open source: P0 0, P1 0, P2 0.

Ruff, strict mypy, import contracts, site/claim/safety/threat/network/governance guards and diff
hygiene passed. The broader sandbox lane reported 1,093 passes and only the same three UV
subprocess checks blocked by the Codex sandbox; GitHub's locked CPython 3.12.12/3.13.11 lanes are
authoritative for those checks.

This acceptance does not close durable cross-process/restart accounting, rotation/catalog CAS,
backup/deletion drills, native host restart/recovery, macOS ACL/mount-alias qualification,
Keychain/rootless-Linux/Docker Desktop/cloud-KMS profiles, authenticated package attestation or
the documented Python/OpenSSL memory-copy limitations.
