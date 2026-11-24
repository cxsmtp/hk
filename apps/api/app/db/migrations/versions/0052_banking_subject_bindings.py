"""Add replay-safe banking subject context bindings.

Revision ID: 0052_banking_subject_bindings
Revises: 0051_tenant_scope_timestamp_defaults
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0052_banking_subject_bindings"
down_revision = "0051_tenant_scope_timestamp_defaults"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "banking_subject_bindings",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("issuer", sa.String(length=512), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("context_digest", sa.String(length=64), nullable=False),
        sa.Column("ai_transaction_id", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "issuer",
            "nonce_hash",
            name="uq_banking_subject_binding_tenant_issuer_nonce",
        ),
    )
    op.create_index(
        "idx_banking_subject_binding_expiry",
        "banking_subject_bindings",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "idx_banking_subject_binding_transaction",
        "banking_subject_bindings",
        ["tenant_id", "ai_transaction_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_banking_subject_binding_transaction",
        table_name="banking_subject_bindings",
    )
    op.drop_index(
        "idx_banking_subject_binding_expiry",
        table_name="banking_subject_bindings",
    )
    op.drop_table("banking_subject_bindings")
