"""Establish the empty trusted-core database baseline.

Revision ID: 0001_database_baseline
Revises: None
"""

from __future__ import annotations

from collections.abc import Sequence

revision: str = "0001_database_baseline"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Leave business schema empty until its contracts are accepted."""


def downgrade() -> None:
    """Return to Alembic base; there are no business objects to remove."""
