# Governance traceability

`traceability.v1.json` maps the repository's current exact `COMPLETE` work-package claims to canonical
requirements, ADRs, selected threats/tests, executable evidence and ACCEPT review records. The generated
`docs/v1/TRACEABILITY_REPORT.md` deliberately reports inventory that is not yet mapped.

Evidence states are not synonyms:

- `CATALOGUED` means linked and known, not implemented;
- `IMPLEMENTED` requires an exact assertion-bearing pytest node;
- `INDEPENDENTLY_ACCEPTED` additionally requires an ACCEPT review record and a real PASSED node;
- `MILESTONE_VERIFIED` additionally requires the corresponding matrix claim to be `VERIFIED`.

A planned threat control or verification ID is never counted as tested coverage. A Markdown file, commit
name, directory, wildcard test selection, skipped/xfail test or arbitrary existing path is not implementation
evidence. Package acceptance does not verify a milestone.

To add a record, first add the implementation and exact test, then an independent review record, then sorted
canonical references. Update the completion matrix only after the guard accepts the same evidence state.
Schema or manifest changes require a version/hash update, destructive fixtures and regenerated deterministic
report. The accepted threat catalog retains its own protected-Git-base identity checks; GOV-001 consumes but
does not weaken or broaden that catalog.
