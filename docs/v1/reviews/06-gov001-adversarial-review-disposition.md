# GOV-001 adversarial review disposition

Status: third remediation implemented; independent re-review pending. GOV-001 remains `IN_PROGRESS`.

The final Sol-labelled governance review rejected v3 on four P1 boundaries. This record describes the
implementation response without claiming that the response is independently accepted.

| Finding | Implemented response | Promotion boundary |
| --- | --- | --- |
| AST/runtime success was described too strongly | the guard now calls this only a structural runtime witness and rejects direct constants, ordinary/annotated/unpacked constant assignments, bounded computed constants, zero-argument constant lambdas and tautological literal calls; acceptance schema v2 pins the exact decorated node source | only an externally rooted approval with `semantic_adequacy=APPROVED` can own semantic adequacy; no trust root is configured |
| `MILESTONE_VERIFIED` bypassed the authenticated package path | M0 has one canonical, immutable package/dependency closure and three gates with named, gate-specific evidence; a milestone requires every exact package record and package attestation, exact reviewed-tree evidence and a separate protected milestone approval | a caller-selected package subset, evidence union, missing package attestation or unapproved milestone fails closed |
| push CI supplied no trusted prior tree | pull requests use `pull_request.base.sha`; pushes use `event.before`; both jobs fetch full history/tags; zero is resolved only by an external exact-genesis or recovery anchor | genesis bootstrap still runs the untrusted-promotion gate; ref recreation receives normal scope comparison and cannot shrink truth |
| version bumps could shrink or rebind canonical scope | the trusted Git object now supplies `WORK_PACKAGES.md`, the completion matrix and all four registries; IDs and immutable bindings are monotonic across work packages, status/matrix scope, traces, criteria, evidence and milestone definitions | accepted attestations and milestone attestations cannot disappear or mutate; any new promotion to `COMPLETE` or `VERIFIED`, including `COMPLETE` to `VERIFIED`, requires exact external trust-root authorization |

Strict SemVer now rejects leading-zero components in governance and threat registries and their published
schemas. Negative probes cover trivial witnesses, missing and implicit-zero CI bases, caller-selected milestone
scope, content-digest/semantic-adequacy mismatch, coordinated scope deletion, rebinding, approval disappearance,
and `COMPLETE`-to-`VERIFIED` escalation.

The first remediation was independently re-rejected with two P1 and one P2 findings. V4 still read approvals
from the ordinary branch base, so a branch could add an approval and use it in a later commit. It also treated
GitHub's all-zero `event.before` as sufficient first-bootstrap evidence, which cannot distinguish initial
creation from ref recreation. Both authorities are now outside branch control:

- `MYCOGNI_GOVERNANCE_TRUST_ROOT_SHA` is a repository-admin variable naming the only immutable commit from
  which approvals may be loaded; branch-local approval files are forbidden and an empty variable grants no
  authority;
- zero-base bootstrap requires `HEAD` to equal the externally configured, parentless repository genesis;
  any later ref recreation requires `MYCOGNI_GOVERNANCE_RECOVERY_BASE_SHA` and undergoes the normal full
  scope comparison;
- structural no-op probes now include annotated assignment, tuple unpacking, bounded arithmetic computation
  and a zero-argument constant lambda. They remain only heuristics; the external approval owns semantics.

The current machine truth remains deliberately non-promotional: all 106 packages remain below `COMPLETE`,
there are three `IMPLEMENTED` trace records, zero package attestations, zero milestone attestations, zero
`COMPLETE`, and zero `VERIFIED` packages. The integration lane retains its existing SIM-001 progress row;
this governance change does not promote or regress any package status.

The second remediation was independently re-rejected with zero P0, two P1 and one P2 findings. Merely naming
an approval commit in a repository variable did not prove that it was outside ordinary branch ancestry, and a
recovery commit equal to `HEAD` made the comparison vacuous. The bounded no-op evaluator also missed division,
named expressions and adjacent folded forms. The third remediation therefore fixes explicit graph invariants:

- an approval trust root must be an available full commit in a complete graph and have no merge base with
  either `HEAD` or the effective event/recovery base; equality and all shared ancestry fail, including an
  approval staged in commit A and deleted in ordinary-branch commit B;
- a recovery base must be an available full commit in a complete graph, differ from `HEAD`, and be a strict
  ancestor of `HEAD`; equal, descendant, unrelated, missing and shallow states fail. The retained ancestor is
  loaded through the same full registry and Markdown-scope comparison, whose negative probe catches coordinated
  work-package and completion-matrix deletion;
- the structural heuristic now recognizes division, named expressions, bounded power/bit operations, ordered
  comparisons, conditional expressions and literal subscripting in addition to the previous forms. These
  rejections reduce obvious false witnesses but make no semantic-adequacy claim.

Negative graph probes cover HEAD, event base, ancestors, branch add/delete, an unrelated orphan trust root,
strict-ancestor recovery, self-comparison, unrelated and missing recovery, and shallow clones. This disposition
does not claim independent acceptance and does not promote GOV-001.
