"""Add the durable wrapped-profile-key catalog.

Revision ID: 0003_key_catalog
Revises: 0002_auth_decision_state
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_key_catalog"
down_revision: str | Sequence[str] | None = "0002_auth_decision_state"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create a strict catalog, nonce ledger, sentinel, and wrapped-key table."""
    op.create_table(
        "key_catalog",
        sa.Column("singleton_id", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("catalog_id", sa.String(length=36), nullable=False),
        sa.Column("sentinel_id", sa.String(length=36), nullable=False),
        sa.Column("provider_kind", sa.String(length=32), nullable=False),
        sa.Column("provider_instance_id", sa.String(length=36), nullable=False),
        sa.Column("kek_id", sa.String(length=36), nullable=False),
        sa.Column("kek_version", sa.Integer(), nullable=False),
        sa.Column("usage_limit", sa.Integer(), nullable=False),
        sa.Column("usage_reserved", sa.Integer(), nullable=False),
        sa.Column("source_commitment", sa.LargeBinary(length=32), nullable=False),
        sa.CheckConstraint("singleton_id = 1", name="ck_key_catalog_singleton"),
        sa.CheckConstraint("schema_version = 1", name="ck_key_catalog_schema_version"),
        sa.CheckConstraint("revision >= 1", name="ck_key_catalog_revision"),
        sa.CheckConstraint(
            "state IN ('preparing','active','recovery_required')",
            name="ck_key_catalog_state",
        ),
        sa.CheckConstraint("length(installation_id) = 36", name="ck_key_catalog_install_id"),
        sa.CheckConstraint("length(catalog_id) = 36", name="ck_key_catalog_catalog_id"),
        sa.CheckConstraint("length(sentinel_id) = 36", name="ck_key_catalog_sentinel_id"),
        sa.CheckConstraint(
            "length(provider_instance_id) = 36", name="ck_key_catalog_provider_instance"
        ),
        sa.CheckConstraint("length(kek_id) = 36", name="ck_key_catalog_kek_id"),
        sa.CheckConstraint(
            "kek_version BETWEEN 1 AND 4294967295", name="ck_key_catalog_kek_version"
        ),
        sa.CheckConstraint(
            "usage_limit BETWEEN 2 AND 4294967295", name="ck_key_catalog_usage_limit"
        ),
        sa.CheckConstraint(
            "usage_reserved BETWEEN 1 AND usage_limit", name="ck_key_catalog_usage_reserved"
        ),
        sa.CheckConstraint(
            "length(source_commitment) = 32", name="ck_key_catalog_source_commitment"
        ),
        sa.PrimaryKeyConstraint("singleton_id", name="pk_key_catalog"),
        sa.UniqueConstraint("installation_id", name="uq_key_catalog_installation"),
        sa.UniqueConstraint("catalog_id", name="uq_key_catalog_id"),
        sa.UniqueConstraint("sentinel_id", name="uq_key_catalog_sentinel_id"),
    )
    op.create_table(
        "key_nonce_reservations",
        sa.Column("reservation_id", sa.String(length=36), nullable=False),
        sa.Column("catalog_id", sa.String(length=36), nullable=False),
        sa.Column("provider_instance_id", sa.String(length=36), nullable=False),
        sa.Column("kek_id", sa.String(length=36), nullable=False),
        sa.Column("kek_version", sa.Integer(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("purpose", sa.String(length=16), nullable=False),
        sa.Column("lifecycle", sa.String(length=16), nullable=False),
        sa.Column("usage_sequence", sa.Integer(), nullable=False),
        sa.Column("profile_id", sa.String(length=36), nullable=True),
        sa.Column("profile_key_version", sa.Integer(), nullable=True),
        sa.CheckConstraint("length(reservation_id) = 36", name="ck_key_nonce_reservation_id"),
        sa.CheckConstraint("length(nonce) = 12", name="ck_key_nonce_length"),
        sa.CheckConstraint("purpose IN ('sentinel','profile')", name="ck_key_nonce_purpose"),
        sa.CheckConstraint(
            "lifecycle IN ('reserved','committed','burned')", name="ck_key_nonce_lifecycle"
        ),
        sa.CheckConstraint("usage_sequence >= 1", name="ck_key_nonce_usage_sequence"),
        sa.CheckConstraint(
            "(purpose='sentinel' AND profile_id IS NULL AND profile_key_version IS NULL) OR "
            "(purpose='profile' AND profile_id IS NOT NULL AND profile_key_version >= 1)",
            name="ck_key_nonce_binding",
        ),
        sa.ForeignKeyConstraint(
            ["catalog_id"], ["key_catalog.catalog_id"], name="fk_key_nonce_catalog"
        ),
        sa.PrimaryKeyConstraint("reservation_id", name="pk_key_nonce_reservations"),
        sa.UniqueConstraint(
            "provider_instance_id", "kek_id", "kek_version", "nonce", name="uq_key_nonce_domain"
        ),
        sa.UniqueConstraint(
            "provider_instance_id",
            "kek_id",
            "kek_version",
            "usage_sequence",
            name="uq_key_nonce_usage_sequence",
        ),
        sa.UniqueConstraint(
            "profile_id",
            "profile_key_version",
            name="uq_key_nonce_profile_binding",
        ),
    )
    op.create_table(
        "key_readiness_sentinel",
        sa.Column("singleton_id", sa.Integer(), nullable=False),
        sa.Column("catalog_id", sa.String(length=36), nullable=False),
        sa.Column("sentinel_id", sa.String(length=36), nullable=False),
        sa.Column("reservation_id", sa.String(length=36), nullable=False),
        sa.Column("format_version", sa.Integer(), nullable=False),
        sa.Column("aad_version", sa.Integer(), nullable=False),
        sa.Column("suite", sa.String(length=16), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(length=48), nullable=False),
        sa.CheckConstraint("singleton_id = 1", name="ck_key_sentinel_singleton"),
        sa.CheckConstraint("length(sentinel_id) = 36", name="ck_key_sentinel_id"),
        sa.CheckConstraint("format_version = 1", name="ck_key_sentinel_format"),
        sa.CheckConstraint("aad_version = 1", name="ck_key_sentinel_aad"),
        sa.CheckConstraint("suite = 'A256GCM'", name="ck_key_sentinel_suite"),
        sa.CheckConstraint("length(ciphertext) = 48", name="ck_key_sentinel_ciphertext"),
        sa.ForeignKeyConstraint(
            ["catalog_id"], ["key_catalog.catalog_id"], name="fk_key_sentinel_catalog"
        ),
        sa.ForeignKeyConstraint(
            ["reservation_id"],
            ["key_nonce_reservations.reservation_id"],
            name="fk_key_sentinel_nonce",
        ),
        sa.PrimaryKeyConstraint("singleton_id", name="pk_key_readiness_sentinel"),
        sa.UniqueConstraint("sentinel_id", name="uq_key_sentinel_id"),
    )
    op.create_table(
        "wrapped_profile_keys",
        sa.Column("profile_id", sa.String(length=36), nullable=False),
        sa.Column("profile_key_version", sa.Integer(), nullable=False),
        sa.Column("catalog_schema_version", sa.Integer(), nullable=False),
        sa.Column("installation_id", sa.String(length=36), nullable=False),
        sa.Column("reservation_id", sa.String(length=36), nullable=False),
        sa.Column("format_version", sa.Integer(), nullable=False),
        sa.Column("aad_version", sa.Integer(), nullable=False),
        sa.Column("suite", sa.String(length=16), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(length=48), nullable=False),
        sa.CheckConstraint("length(profile_id) = 36", name="ck_wrapped_key_profile_id"),
        sa.CheckConstraint(
            "profile_key_version BETWEEN 1 AND 4294967295", name="ck_wrapped_key_version"
        ),
        sa.CheckConstraint("catalog_schema_version = 1", name="ck_wrapped_key_catalog_schema"),
        sa.CheckConstraint("length(installation_id) = 36", name="ck_wrapped_key_installation_id"),
        sa.CheckConstraint("format_version = 1", name="ck_wrapped_key_format"),
        sa.CheckConstraint("aad_version = 1", name="ck_wrapped_key_aad"),
        sa.CheckConstraint("suite = 'A256GCM'", name="ck_wrapped_key_suite"),
        sa.CheckConstraint("length(ciphertext) = 48", name="ck_wrapped_key_ciphertext"),
        sa.ForeignKeyConstraint(
            ["reservation_id"],
            ["key_nonce_reservations.reservation_id"],
            name="fk_wrapped_key_nonce",
        ),
        sa.PrimaryKeyConstraint(
            "profile_id", "profile_key_version", name="pk_wrapped_profile_keys"
        ),
        sa.UniqueConstraint("reservation_id", name="uq_wrapped_key_reservation"),
    )


def downgrade() -> None:
    """Remove only catalog data; external KEK custody is never touched."""
    op.drop_table("wrapped_profile_keys")
    op.drop_table("key_readiness_sentinel")
    op.drop_table("key_nonce_reservations")
    op.drop_table("key_catalog")
