# THREAT-CATALOG-001 adversarial review record

Date: 2026-07-15  
Package: THREAT-CATALOG-001 selected threat/test catalog  
Final integrated commit: `3000ddc`

## Three reject/fix cycles

The first independent review rejected the catalog because coordinated ID renames were possible, arbitrary existing files could masquerade as implementation evidence, duplicate JSON keys and extra fields bypassed intent, schemas were not enforced, and path/Markdown handling admitted ambiguity.

The second iteration added a permanent allocation ledger, typed pytest evidence, strict loaders and canonical paths, but was rejected again: all mutable documents could still be rewritten together; collected/xfail/skipped tests could sustain a tested-control claim; and schemas were parsed without being applied.

The final implementation roots cross-revision identity in the pull request's trusted Git base object, enforces monotonic ID binding and retired state, and reports local/bootstrap non-verification honestly. A tested control must name an allowlisted assertion-bearing pytest node that executes under `--runxfail` and produces a real `PASSED` result. The three published schemas are canonical-hash pinned, exact-object checked and evaluated offline against their documents. Negative fixtures cover coordinated rename/rebinding/reactivation, duplicate keys, schema destruction, skip/xfail/no-op evidence, paths, symlinks and report injection.

## Final disposition

`ACCEPT` with zero P0, zero P1 and zero P2 findings.

Evidence reproduced after integration:

- 51 focused catalog/guard tests;
- 677 repository tests on Python 3.12.12 and 3.13.11;
- trusted-base comparison reports `VERIFIED` when supplied a valid prior Git object;
- ordinary local runs report `NOT CHECKED`, and a pre-ledger base reports `BOOTSTRAP NOT VERIFIED`;
- all static, import-boundary, safety, claim and threat guards pass.

The catalog contains eight selected high-risk groups and eight verification IDs. It is not exhaustive requirement/work-package/ADR coverage, does not make planned controls effective, and does not complete GOV-001. Its cross-revision guarantee depends on protected base history, branch protection and review of changes to the guard/workflow trust root.
