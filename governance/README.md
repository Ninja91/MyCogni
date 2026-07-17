# Machine governance boundary

These exact-schema registries, not Markdown prose, own the scoped GOV-001 truth:

- `package-status.v1.json` owns tracked package status, immutable canonical milestone definitions and structured milestone attestations;
- `acceptance.v1.json` owns package-specific criteria and exact executable evidence;
- `review-attestations.v1.json` owns finite review dispositions bound to full Git commits and content digests;
- `traceability.v1.json` links only structurally supported package records to canonical IDs.

`COMPLETE` requires dependency closure, nonempty package-specific criteria, a structural runtime criterion
witness, a real `PASSED` result, and an exact `ACCEPT` attestation. The AST/runtime checks only reject known
no-ops; they do not establish that a criterion or test is semantically adequate. That judgment belongs to a
protected reviewer approval which explicitly says `semantic_adequacy=APPROVED` and binds the exact criterion,
evidence, attestation, reviewer and reviewed-tree digests. Without that approval, promotion is impossible.
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
and fail closed if the event base is missing. The all-zero Git SHA is accepted only through the explicit
first-ref bootstrap flag, and bootstrap still forbids attestations and promotions. Content changes require a
monotonic registry version. Work-package/matrix IDs, status IDs, trace records, criteria, evidence, milestone
definitions, attestations and protected approvals cannot disappear or be rebound behind a version bump. A
new attestation or any promotion to `COMPLETE`/`VERIFIED` is rejected unless the
protected base already contains an exact `governance/protected-approvals.v1.json` allowlist entry binding
its subject and content digests, reviewer identity and explicit semantic-adequacy decision. That file is
intentionally not installed yet: authenticated external reviewer keys and a protected approval workflow
remain prerequisites, and this repository does not pretend an in-branch identity is authentication. A base
with only some governance documents is a hard failure; only the explicit all-zero first-ref bootstrap path
may have no prior documents, and it still allows no attestations or promotions.

The current GOV implementation is intentionally `IN_PROGRESS`. Three records are `IMPLEMENTED`, no review
attestation is authenticated, and canonical package completion is empty. The deterministic report lists
the full package, threat and verification-test registries and actual states rather than implying coverage
from counts. The threat guard is invoked fail-closed; GOV does not replace or weaken it.
