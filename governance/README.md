# Machine governance boundary

These exact-schema registries, not Markdown prose, own the scoped GOV-001 truth:

- `package-status.v1.json` owns tracked package status and structured milestone attestations;
- `acceptance.v1.json` owns package-specific criteria and exact executable evidence;
- `review-attestations.v1.json` owns finite review dispositions bound to full Git commits and content digests;
- `traceability.v1.json` links only structurally supported package records to canonical IDs.

`COMPLETE` requires dependency closure, nonempty package-specific criteria, a runtime criterion witness and
real `PASSED` result, and an exact `ACCEPT` attestation. `VERIFIED` additionally requires one structured
milestone attestation covering the complete transitive dependency set, the canonical milestone gate set,
and exact reviewed-commit evidence. Documentation, arbitrary files, short commit names, planned VFY/threat
IDs, skipped/xfail/no-op tests and review prose alone cannot promote status.

Pull-request CI reuses the protected Git base SHA. Content changes require a monotonic registry version;
existing attestations cannot disappear or mutate. A new attestation or promotion is rejected unless the
protected base already contains an exact `governance/protected-approvals.v1.json` allowlist entry binding
its attestation digest and reviewer identity. That file is intentionally not installed yet: authenticated
external reviewer keys and a protected approval workflow remain prerequisites, and this repository does
not pretend an in-branch identity is authentication. A base with only some governance documents is a hard
failure; an all-absent first bootstrap is allowed only while there are no attestations or promotions.

The current GOV implementation is intentionally `IN_PROGRESS`. Three records are `IMPLEMENTED`, no review
attestation is authenticated, and canonical package completion is empty. The deterministic report lists
the full package, threat and verification-test registries and actual states rather than implying coverage
from counts. The threat guard is invoked fail-closed; GOV does not replace or weaken it.
