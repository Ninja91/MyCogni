# SPIKE-KEY pre-implementation adversarial review

Review target: `49facb0caef93624426f4193eba0408c139f3fdc`.

Current verdict: **REJECT the earlier broad plan; ACCEPT the tightened charter for
implementation only**. This is an AI-assisted independent design review, not human cryptographic
certification or package acceptance. No code target has been reviewed yet.

## Independent review hats

Two read-only reviewers inspected the same target independently:

- **cryptography and API boundary:** key hierarchy, wrapped-record/AAD design, entropy, lifecycle,
  recovery, rotation and secret exposure;
- **edge/deployment:** macOS, native Linux, fixed non-root UID `65532`, rootless Linux Engine,
  Docker Desktop, restart/fork and archive separation.

Role labels describe review perspective. They do not assert provider Trusted Access, human
credentials or external certification. The reviewers made no file changes and ran no Docker or
live network operation.

## P0 findings and disposition

| Finding | Disposition |
| --- | --- |
| Ordered provider fallback, including environment variables, can silently choose or leak a different KEK. | ADR-0013 selects one exact provider/reference; discovery, fallback, environment KEKs and runtime replacement are prohibited. |
| Root-owned/Compose secret assumptions conflict with fixed runtime UID `65532`; Compose does not prove portable ownership or encryption. | Native owner-only file is the only M0 executable baseline. A separately provisioned key-only volume is a named rootless/Docker candidate with separate host matrices. |
| The generic ciphertext type does not bind strict suite/length/provider/profile versions. | A dedicated wrapped-profile-key record and canonical binary AAD v1 bind installation, profile, profile/catalog versions and exact KEK reference. |
| KEK/archive separation is documentary only. | The provider must reject equal, ancestor or descendant roots, symlink ancestors, hard links, unsafe permissions and non-regular sources; backup traversal remains allowlisted. |
| Startup/provisioning/loss behavior is undefined and could auto-generate a replacement. | Runtime is read-only toward the provider. Missing, unsafe or wrong material pauses. Provisioning is an explicit empty-install ceremony; failed recovery never overwrites live material. |

## P1 findings and disposition

- AES-256-GCM uses 96-bit OS-random nonces, a conservative per-process wrap cap and a duplicate
  collision latch. Durable cross-process accounting remains a named KEY-001 blocker.
- Failures use finite redacted categories and do not propagate paths, AAD, ciphertext, provider
  details or backend exception text.
- Raw KEK never crosses the application port. Opened profile material is a short-lived opaque
  issuer/process-bound handle; Python/OpenSSL memory erasure is explicitly not claimed.
- A production-inaccessible deterministic entropy seam supports exact vectors and fault tests;
  production composition uses only OS entropy.
- Rotation preserves profile DEKs and retains old KEKs through known archive horizons, but its
  durable state machine is deferred to KEY-002.
- macOS Security.framework, Linux Secret Service, rootless Linux Engine and Docker Desktop are
  separate provider/conformance profiles. None can be inferred from native code reuse.

## Implementation gate

Code may proceed only inside the tightened charter recorded by ADR-0013 and
`spikes/SPIKE-KEY.md`. After integration, three new exact-target reviewers must inspect:

1. cryptographic format/API and secret-lifetime behavior;
2. filesystem, restart/fork, concurrency and failure semantics;
3. operator/deployment claims, recovery usability and open-source portability.

Every P0/P1/P2 must be fixed or explicitly removed from the enabled surface before code-level
acceptance. Formal `COMPLETE` still requires the repository's externally rooted authenticated
attestation path and the exact-host conformance matrix.
