# Database migrations

The core/data lane is the single owner of this Alembic history. Release and
startup orchestration must acquire a deployment-level migration lock before
running `alembic upgrade`; application workers must not race migrations.

DB-001 established the migration harness. Revision `0001` deliberately
contains no business or PII-bearing tables. It proves that a fresh, file-backed
SQLite database can move between `base` and the current revision.

The default URL in `alembic.ini` is a development placeholder. Operators and
tests must supply the target URL with Alembic's `sqlalchemy.url` configuration
option. `mycogni.busy_timeout_ms` configures the same bounded, fail-closed
SQLite connection policy used by the application. SQLite URI/query modes,
in-memory targets, and non-SQLite URLs are rejected. This baseline does not yet
provide the maintenance lock, pre-migration
backup, disk-space preflight, encrypted fields, restore proof, or compatibility
matrix required by later work packages.

Revision `0003_key_catalog` adds the versioned wrapped-key catalog, dedicated
readiness sentinel, durable KEK-domain nonce reservations, and wrapped
synthetic profile-key records. The catalog stores a domain-separated SHA-256
commitment to the source bytes so interrupted initialization cannot resume
against a replacement source; it contains no KEK or plaintext profile key.
Downgrade is an explicit destructive database operation with no automated
warning in this slice. It removes only database records and never creates,
changes, repairs, or deletes an external owner-file key source.
