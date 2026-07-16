# Machine governance boundary

These exact-schema registries, not Markdown prose, own the scoped GOV-001 truth:

- `package-status.v1.json` owns tracked package status and structured milestone attestations;
- `acceptance.v1.json` owns package-specific criteria and exact executable evidence;
- `review-attestations.v1.json` owns finite review dispositions bound to full Git commits and content digests;
- `traceability.v1.json` links only structurally supported package records to canonical IDs.

`COMPLETE` requires dependency closure, nonempty package-specific criteria, content-bound exact pytest nodes
that produce a real `PASSED` result under `--runxfail`, and an exact `ACCEPT` attestation. `VERIFIED` also
requires one structured milestone attestation covering its packages and gates. Documentation, arbitrary
files, short commit names, planned VFY IDs, skipped/xfail/no-op tests and review prose alone cannot promote
status.

Pull-request CI reuses the protected Git base SHA. Content changes require a monotonic registry version;
existing attestations cannot disappear or mutate. The first machine-registry introduction reports bootstrap
non-verification. This trust still depends on protected base history and review of workflow/guard changes.

The current GOV implementation is intentionally `IN_PROGRESS`. Three package review attestations are
structured, but canonical package completion remains empty because their prerequisite chains are not yet
structurally attested. The deterministic report lists identifiers and actual states rather than implying
coverage from counts. The accepted threat guard is invoked fail-closed; GOV does not replace or weaken it.
