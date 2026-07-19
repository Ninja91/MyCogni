# Threat and verification identifiers

`threat-catalog.v1.json` is the reviewed machine-readable catalog. Its schema is
`threat-catalog.schema.json`; `verification-tests.v1.json` owns the verification ID namespace and
`id-history.v1.json` is the append-only allocation ledger. Each document has a separately parsed v1
schema, while the guard enforces its exact top-level and entry fields. The generated report is
`docs/v1/THREAT_CATALOG_REPORT.md`.

## Extension and deprecation rules

- IDs are permanent, uppercase, and canonical: `THR-<AREA>-NNN` and `VFY-<AREA>-NNN`.
- Allocate the next unused number in an area. Add its identity binding to `id-history.v1.json` in the
  same review. Never recycle, renumber, delete, or silently rename an ID.
- Correcting prose or adding mappings does not change an ID. A materially different failure story gets a
  new ID.
- Deprecation changes status to `DEPRECATED`, changes its history state to `RETIRED`, preserves the old
  row and references, and adds any replacement as a newly allocated ID. A retired ID cannot return to an
  active state. V1 deliberately has no alias mechanism: consumers must not guess.
- A breaking field or meaning change increments `schema_version` and ships a new schema/catalog filename.
  Content-only additions increment `catalog_version` or `registry_version` using semantic versioning.
- `CONTROL_TESTED` requires matching typed executable evidence from a bidirectionally linked
  `IMPLEMENTED` verification ID. V1 allowlists exact top-level pytest nodes; the guard verifies the file,
  function and real pytest collection identity. A document or arbitrary existing path is not executable
  evidence. `CONTROL_PLANNED` and `PLANNED` never imply a working control.
- Sources use semantic anchors (`threat:`, `requirement:`, or `work-package:`), each bound to its one
  canonical source document and structure. Repository paths must be normalized POSIX-relative files:
  absolute, dot/dotdot, backslash and symlink paths are rejected. Timestamps, live endpoints, and personal
  identifiers are prohibited.

## Intentional addition or update

1. Allocate a new ID and immutable identity slug in `id-history.v1.json`; never edit another ID's binding.
2. Add the sorted catalog or verification row and increment the relevant content version.
3. Use `PLANNED`/`CONTROL_PLANNED` until exact executable evidence exists. Promotion to implemented/tested
   requires the same typed evidence object on the verification row and threat row.
4. Regenerate the report, run the negative fixtures and review the allocation/history diff explicitly.

Prose that does not change identity may be clarified without a new ID, but the title/purpose identity slug
is immutable. A material failure-story or verification-purpose change receives a new ID and deprecates the
old row; it is never disguised as an edit.

## Cross-revision trust boundary

Local runs validate the current ledger but print `NOT CHECKED` for cross-revision immutability. The first PR
that introduces the ledger prints `BOOTSTRAP NOT VERIFIED`; reviewers must treat the full allocation list as
a new security baseline. Later pull-request CI checks out full Git history and supplies only the immutable
`github.event.pull_request.base.sha`. The guard reads the baseline ledger directly from that Git object and
rejects removed IDs, changed kind/identity/introduction bindings, and retired-ID reactivation—even when the
catalog, verification registry, and current ledger were edited together.

This guarantee depends on GitHub branch protection: required CI must run from the reviewed workflow, the
base branch must reject force-pushes, and changes to the workflow, guard, schemas, or ID ledger require code-
owner review. A maintainer who can rewrite the protected base or bypass required checks remains outside the
claim. Push CI and local runs without a trusted base SHA intentionally do not report cross-revision
verification.

Published schemas are not decorative. Their canonical hashes are pinned in the guard, their exact-object
shape is meta-checked, and an offline validator evaluates every keyword used by these v1 schemas against the
three real documents. Schema changes therefore require an explicit schema, guard hash, fixtures, and review
change together.

Run `python scripts/ci/threat_catalog_guard.py --write-report` only after reviewing the source catalogs.
Normal CI runs without the flag and rejects report drift.

This first catalog is intentionally selected, not exhaustive. `GOV-001` will add full requirement,
work-package, ADR, test, and evidence coverage without changing these threat/test ownership rules.
