# GOV-001 adversarial review disposition

Status: remediation implemented; independent re-review pending. GOV-001 remains `IN_PROGRESS`.

The final Sol-labelled governance review rejected v3 on four P1 boundaries. This record describes the
implementation response without claiming that the response is independently accepted.

| Finding | Implemented response | Promotion boundary |
| --- | --- | --- |
| AST/runtime success was described too strongly | the guard now calls this only a structural runtime witness and rejects direct constants, assigned constants and tautological literal calls; acceptance schema v2 pins the exact decorated node source | only a protected approval with `semantic_adequacy=APPROVED` can own semantic adequacy; no protected approvals are installed |
| `MILESTONE_VERIFIED` bypassed the authenticated package path | M0 has one canonical, immutable package/dependency closure and three gates with named, gate-specific evidence; a milestone requires every exact package record and package attestation, exact reviewed-tree evidence and a separate protected milestone approval | a caller-selected package subset, evidence union, missing package attestation or unapproved milestone fails closed |
| push CI supplied no trusted prior tree | pull requests use `pull_request.base.sha`; pushes use `event.before`; both jobs fetch full history; CI rejects missing/zero bases except the explicit all-zero first-ref bootstrap | bootstrap still runs the untrusted-promotion gate, so it cannot install an ACCEPT, `COMPLETE` or `VERIFIED` claim |
| version bumps could shrink or rebind canonical scope | the trusted Git object now supplies `WORK_PACKAGES.md`, the completion matrix, all four registries and protected approvals; IDs and immutable bindings are monotonic across work packages, status/matrix scope, traces, criteria, evidence, milestone definitions and approvals | accepted attestations and milestone attestations cannot disappear or mutate; any new promotion to `COMPLETE` or `VERIFIED`, including `COMPLETE` to `VERIFIED`, requires exact protected-base authorization |

Strict SemVer now rejects leading-zero components in governance and threat registries and their published
schemas. Negative probes cover trivial witnesses, missing and implicit-zero CI bases, caller-selected milestone
scope, content-digest/semantic-adequacy mismatch, coordinated scope deletion, rebinding, approval disappearance,
and `COMPLETE`-to-`VERIFIED` escalation.

The current machine truth remains deliberately non-promotional: all 106 packages remain below `COMPLETE`,
there are three `IMPLEMENTED` trace records, zero package attestations, zero milestone attestations, zero
`COMPLETE`, and zero `VERIFIED` packages. The integration lane retains its existing SIM-001 progress row;
this governance change does not promote or regress any package status.
