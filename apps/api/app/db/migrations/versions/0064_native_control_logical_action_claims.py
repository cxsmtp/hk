"""Atomically reserve provider logical actions before callback authorization.

Revision ID: 0064_native_control_logical_action_claims
Revises: 0063_composed_control_plan_persistence
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0064_native_control_logical_action_claims"
down_revision = "0063_composed_control_plan_persistence"
branch_labels = None
depends_on = None


def _dialect() -> str:
    dialect = op.get_bind().dialect.name
    if dialect not in {"sqlite", "postgresql"}:
        raise RuntimeError(f"Unsupported dialect: {dialect}")
    return dialect


def _hash_check(column: str) -> str:
    remaining = column
    for character in "0123456789abcdef":
        remaining = f"replace({remaining}, '{character}', '')"
    return (
        f"{column} IS NULL OR (length({column}) = 64 AND {column} = lower({column}) "
        f"AND length({remaining}) = 0)"
    )


def upgrade() -> None:
    _dialect()
    op.create_table(
        "native_control_logical_action_claims",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("integration_instance_id", sa.String(length=36), nullable=False),
        sa.Column("provider_event_id_hash", sa.String(length=64), nullable=False),
        sa.Column("canonical_material_hash", sa.String(length=64), nullable=False),
        sa.Column("policy_snapshot_id", sa.String(length=64), nullable=False),
        sa.Column("contract_hash", sa.String(length=64), nullable=False),
        sa.Column("configuration_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("conflicted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("conflict_material_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.CheckConstraint(
            _hash_check("provider_event_id_hash"),
            name="ck_native_logical_claim_provider_event_hash",
        ),
        sa.CheckConstraint(
            _hash_check("canonical_material_hash"),
            name="ck_native_logical_claim_material_hash",
        ),
        sa.CheckConstraint(
            _hash_check("contract_hash"),
            name="ck_native_logical_claim_contract_hash",
        ),
        sa.CheckConstraint(
            _hash_check("configuration_fingerprint"),
            name="ck_native_logical_claim_configuration_hash",
        ),
        sa.CheckConstraint(
            _hash_check("conflict_material_hash"),
            name="ck_native_logical_claim_conflict_material_hash",
        ),
        sa.CheckConstraint(
            "length(trim(policy_snapshot_id)) BETWEEN 1 AND 64",
            name="ck_native_logical_claim_policy_snapshot",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_logical_claim_tenant_integration",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "integration_instance_id",
            "provider_event_id_hash",
            name="uq_native_logical_claim_tenant_provider_event",
        ),
    )
    op.create_index(
        "idx_native_logical_claim_tenant_integration_created",
        "native_control_logical_action_claims",
        ["tenant_id", "integration_instance_id", "created_at"],
    )


def downgrade() -> None:
    _dialect()
    op.drop_index(
        "idx_native_logical_claim_tenant_integration_created",
        table_name="native_control_logical_action_claims",
    )
    op.drop_table("native_control_logical_action_claims")
