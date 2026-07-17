# Machine governance boundary

These exact-schema registries, not Markdown prose, own the scoped GOV-001 truth:

- `package-status.v1.json` owns tracked package status, immutable canonical milestone definitions and structured milestone attestations;
- `acceptance.v1.json` owns package-specific criteria and exact executable evidence;
- `review-attestations.v1.json` owns finite review dispositions bound to full Git commits and content digests;
- `traceability.v1.json` links only structurally supported package records to canonical IDs.

`COMPLETE` requires dependency closure, nonempty package-specific criteria, a structural runtime criterion
witness, a real `PASSED` result, and an exact `ACCEPT` attestation. The AST/runtime checks only reject known
no-ops; they do not establish that a criterion or test is semantically adequate. That judgment belongs to an
externally rooted reviewer approval which explicitly says `semantic_adequacy=APPROVED` and binds the exact
criterion, evidence, attestation, reviewer and reviewed-tree digests. Without that approval, promotion is
impossible.
Acceptance schema v2 hashes the exact decorated pytest function source rather than its whole containing file.
The v1-to-v2 transition permits only that evidence-hash representation migration; after a v2 trusted base,
an evidence ID cannot be rebound. Criteria are immutable across both versions.

`VERIFIED` additionally requires one protected milestone approval over a canonical milestone definition.
The definition owns the exact package/dependency closure and each gate's named evidence. Every canonical
package must already traverse the same valid protected package-attestation path; every named gate-evidence
item must be inside one of those exact package attestations. A caller cannot substitute a subset, union all
package evidence into an undifferentiated bucket, or reuse an unapproved milestone. Documentation, arbitrary
files, short commit names, planned VFY/threat IDs, skipped/xfail/no-op tests and review prose alone cannot
promote status.

Pull-request CI uses the protected Git base SHA; push CI uses the exact pre-push SHA. Both fetch full history
and tags and fail closed if the event base is missing. An all-zero event predecessor is never sufficient
bootstrap evidence. It is accepted only when the repository-admin `MYCOGNI_GOVERNANCE_GENESIS_SHA` equals
`HEAD` and that commit has no parent. A later ref recreation must provide an externally configured immutable
`MYCOGNI_GOVERNANCE_RECOVERY_BASE_SHA`; the guard then performs the normal full baseline comparison against
that commit. Missing, ambiguous or unavailable anchors fail closed, and genesis bootstrap still forbids
attestations and promotions.

Content changes require a monotonic registry version. Work-package/matrix IDs, status IDs, trace records,
criteria, evidence, milestone definitions and attestations cannot disappear or be rebound behind a version
bump. Review authority never comes from the PR/push base or any later branch commit. A branch-local
`governance/protected-approvals.v1.json` is a hard error. New attestations and all promotions to `COMPLETE` or
`VERIFIED` consult only the exact full commit in the repository-admin
`MYCOGNI_GOVERNANCE_TRUST_ROOT_SHA` variable. That out-of-branch commit must contain the strict approval
registry binding subject/content digests, reviewer identity and explicit semantic adequacy. Empty means no
approval authority; malformed, unavailable or missing trust-root state fails closed. The variable is not
configured yet, so authenticated external reviewer keys and workflow remain prerequisites.

The current GOV implementation is intentionally `IN_PROGRESS`. Three records are `IMPLEMENTED`, no review
attestation is authenticated, and canonical package completion is empty. The deterministic report lists
the full package, threat and verification-test registries and actual states rather than implying coverage
from counts. The threat guard is invoked fail-closed; GOV does not replace or weaken it.
