# Database migrations

The core/data lane is the single owner of this Alembic history. Release and
startup orchestration must acquire a deployment-level migration lock before
running `alembic upgrade`; application workers must not race migrations.

DB-001 only establishes the migration harness. Revision `0001` deliberately
contains no business or PII-bearing tables. It proves that a fresh, file-backed
SQLite database can move between `base` and the current revision.

The default URL in `alembic.ini` is a development placeholder. Operators and
tests must supply the target URL with Alembic's `sqlalchemy.url` configuration
option. This baseline does not yet provide the maintenance lock, pre-migration
backup, disk-space preflight, encrypted fields, restore proof, or compatibility
matrix required by later work packages.
