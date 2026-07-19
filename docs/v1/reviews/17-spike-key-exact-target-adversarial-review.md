# SPIKE-KEY exact-target adversarial review

Initial target: `2a144bf3a586cbaf05517f84e7c5ae9295e1ace4`.

Current verdict: **REJECT**. The initial target has one open P0 plus overlapping P1/P2
findings. It must not be described as code-level accepted. The remediation target and final
three-hat verdicts will be appended only after a new exact commit exists.

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

## Replacement candidate before repeat review

The replacement candidate separates `SourceStatus` from sentinel-authenticated `KeyReadiness`,
persists the complete immutable `ProfileKeyBinding`, uses a dedicated composition-bound
`WrappedReadinessSentinel`, and denies wrap/unwrap before readiness. It pins material plus parent
and file identity for the provider lifetime; a missing, changed, corrupt or non-authenticating
existing-install source permanently latches recovery-required, including after the original file
is restored. It removes public entropy seams, rejects a second live provider for the same
path/reference/installation, checks PID before and after locks, re-traverses the configured path
after AEAD, and makes the profile-DEK handle single-callback with explicit copy/backing nonclaims.

The focused Darwin arm64 / locked CPython 3.12.12 lane reports `59 passed`, including a real fork
against an inherited held lock, replacement-then-restore, initial readiness failure, diagnostic
source-change detection, configured-directory rename/replacement, exact AAD/AEAD vector and typed
post-use syscall failures. This is candidate evidence only. The exact reviewed commit and three
independent repeat verdicts must be recorded below before any code-level acceptance statement.
