# Threat and verification identifiers

`threat-catalog.v1.json` is the reviewed machine-readable catalog. Its schema is
`threat-catalog.schema.json`; `verification-tests.v1.json` owns the verification ID namespace.
The generated report is `docs/v1/THREAT_CATALOG_REPORT.md`.

## Extension and deprecation rules

- IDs are permanent, uppercase, and canonical: `THR-<AREA>-NNN` and `VFY-<AREA>-NNN`.
- Allocate the next unused number in an area. Never recycle, renumber, or silently rename an ID.
- Correcting prose or adding mappings does not change an ID. A materially different failure story gets a
  new ID.
- Deprecation changes status to `DEPRECATED`, preserves the old row and references, and adds a replacement
  in a schema-versioned future catalog. V1 deliberately has no alias mechanism: consumers must not guess.
- A breaking field or meaning change increments `schema_version` and ships a new schema/catalog filename.
  Content-only additions increment `catalog_version` or `registry_version` using semantic versioning.
- `CONTROL_TESTED` requires at least one bidirectionally linked `IMPLEMENTED` verification ID and an
  existing repository evidence path. `CONTROL_PLANNED` and `PLANNED` never imply a working control.
- Sources use semantic anchors (`threat:`, `requirement:`, `work-package:`, or `heading:`). Absolute paths,
  timestamps, live endpoints, and personal identifiers are prohibited.

Run `python scripts/ci/threat_catalog_guard.py --write-report` only after reviewing the source catalogs.
Normal CI runs without the flag and rejects report drift.

This first catalog is intentionally selected, not exhaustive. `GOV-001` will add full requirement,
work-package, ADR, test, and evidence coverage without changing these threat/test ownership rules.
