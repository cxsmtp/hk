"""Add single-use banking grants and schema-1.1 receipt bindings.

Revision ID: 0053_banking_execution_grants
Revises: 0052_banking_subject_bindings
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0053_banking_execution_grants"
down_revision = "0052_banking_subject_bindings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Schema 1.1 execution receipts bind the remaining consequential
    # authorization dimensions. Columns stay nullable so pre-0053 signed
    # schema-1.0 receipts remain independently verifiable after upgrade.
    op.add_column(
        "execution_receipts",
        sa.Column("actual_chain_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "execution_receipts",
        sa.Column("actual_actor_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "execution_receipts",
        sa.Column("actual_purpose_hash", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "execution_receipts",
        sa.Column("actual_policy_snapshot_id", sa.String(length=64), nullable=True),
    )
    op.create_table(
        "banking_execution_grants",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("decision_receipt_id", sa.String(length=36), nullable=False),
        sa.Column("execution_attempt_id", sa.String(length=128), nullable=False),
        sa.Column("canonical_action", sa.JSON(), nullable=False),
        sa.Column("canonical_action_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "issued_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_status", sa.String(length=32), nullable=True),
        sa.Column("execution_receipt_id", sa.String(length=36), nullable=True),
        sa.Column("integrity_result_id", sa.String(length=36), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipts.tenant_id", "decision_receipts.receipt_id"],
            name="fk_banking_execution_grant_tenant_decision",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "decision_receipt_id",
            "execution_attempt_id",
            name="uq_banking_execution_grant_tenant_decision_attempt",
        ),
    )
    op.create_index(
        "idx_banking_execution_grant_expiry",
        "banking_execution_grants",
        ["tenant_id", "expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "idx_banking_execution_grant_expiry",
        table_name="banking_execution_grants",
    )
    op.drop_table("banking_execution_grants")
    op.drop_column("execution_receipts", "actual_policy_snapshot_id")
    op.drop_column("execution_receipts", "actual_purpose_hash")
    op.drop_column("execution_receipts", "actual_actor_hash")
    op.drop_column("execution_receipts", "actual_chain_id")
