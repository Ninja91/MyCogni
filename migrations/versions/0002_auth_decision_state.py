"""Add the durable, digest-only authentication decision state.

Revision ID: 0002_auth_decision_state
Revises: 0001_database_baseline
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_auth_decision_state"
down_revision: str | Sequence[str] | None = "0001_database_baseline"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the single-installation canonical auth decision document."""
    op.create_table(
        "auth_authority_handles",
        sa.Column("handle", sa.String(length=36), nullable=False),
        sa.Column("authority_kind", sa.String(length=20), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "authority_kind IN ('root','operator','service')",
            name="ck_auth_authority_kind",
        ),
        sa.PrimaryKeyConstraint("handle", name="pk_auth_authority_handles"),
    )
    op.create_table(
        "auth_decision_state",
        sa.Column("singleton_id", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state_json", sa.Text(), nullable=False),
        sa.CheckConstraint("singleton_id = 1", name="ck_auth_state_singleton"),
        sa.CheckConstraint("schema_version = 1", name="ck_auth_state_schema_version"),
        sa.CheckConstraint("revision >= 0", name="ck_auth_state_revision"),
        sa.PrimaryKeyConstraint("singleton_id", name="pk_auth_decision_state"),
    )


def downgrade() -> None:
    """Remove auth decision state without touching external operator custody."""
    op.drop_table("auth_decision_state")
    op.drop_table("auth_authority_handles")
