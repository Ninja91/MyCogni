# GOV-001 v4 adversarial review

Target: integration commit `661ff7c`.

Verdict: **REJECT** — zero P0, two P1 and one P2 finding. GOV-001 remains
`IN_PROGRESS`; no package or milestone promotion is authorized by this review.

This is an independent Sol-labelled agent review, not a claim about the underlying
model and not an authenticated human approval.

## Findings

| Severity | Finding | Required disposition |
| --- | --- | --- |
| P1 | A branch-local protected-approval addition was allowed by cross-revision validation. The same repository author could land a fabricated approval in one commit and use the now-base entry to authorize a package or milestone promotion in the next commit. CODEOWNERS alone does not establish independent cryptographic or protected-environment provenance. | A newly added branch-local record must never become a promotion trust root. Require an explicitly configured external authenticated source, or make promotion impossible. Add a two-commit staged-approval regression. |
| P1 | An all-zero push base was treated as first bootstrap even though it also represents protected-ref recreation. A recreated ref could shrink coordinated package, matrix, status and trace scope while using the bootstrap path. | Bind bootstrap to immutable repository identity/genesis state and fail closed on ref recreation, deletion or force-push unless externally trusted state proves continuity. Add scope-deletion/ref-recreation regressions. |
| P2 | The structural runtime witness rejected simple assigned constants but accepted annotated assignment, tuple/unpacking assignment and computed/lambda truth values, while the disposition claimed assigned constants were rejected generally. | Expand the structural check and regressions or narrow every claim to its exact capability. Semantic adequacy must remain outside this witness. |

## Evidence that did pass

- 84 focused governance and threat-catalog tests;
- strict SemVer, exact M0 package/dependency closure and exact gate bindings;
- package and milestone attestation paths, including `COMPLETE` to `VERIFIED`;
- monotonic 106-package/criterion/evidence/milestone/approval ID checks against a
  real trusted base;
- missing and partial-base rejection plus pull-request/push base wiring;
- honest current truth: 106 packages, three `IMPLEMENTED` traces, zero package
  attestations, zero milestone attestations and zero `COMPLETE`/`VERIFIED` packages.

The implementation lane owns remediation. Every P1 fix must return to an
independent reviewer before this verdict can change.

## First remediation re-review

Target: integration commit `143a821`.

Verdict: **REJECT** — zero P0, two P1 and one P2 finding. The remediation did
correctly forbid a working-tree approval file, default to no authority, bind exact
approval subjects/content, require configured genesis/recovery values, run ordinary
monotonic comparison for a distinct recovery base, and reject the original annotated,
unpacked, additive and lambda fixtures. It did not yet prove external-state isolation.

| Severity | Finding | Required disposition |
| --- | --- | --- |
| P1 | The repository-admin trust-root SHA could point at `HEAD`, the event base or an ordinary reachable branch commit. An approval file added in one branch commit and deleted in the next could still become the configured trust source. | Reject current/base commits and every commit reachable through ordinary branch/base ancestry. Prove an unrelated externally retained trust root and fail closed when ancestry cannot be established. |
| P1 | The recovery SHA could equal current `HEAD`; a zero-base run then compared the recreated tree to itself and reported external-recovery verification, making scope continuity vacuous. | Require a distinct externally retained prior canonical state; reject self-comparison and prove coordinated scope deletion is caught against that prior state. |
| P2 | Additional obvious constant witnesses such as division equality and a walrus-assigned literal still passed. | Reject adjacent bounded constant forms or narrow the exact structural-witness claim further; do not imply semantic proof. |

The current machine truth remained honest and unpromoted. This second rejection is
the authoritative review state until another independent re-review accepts a later
integrated revision.
