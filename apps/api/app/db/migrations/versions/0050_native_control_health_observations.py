"""Add measured Native Control health observations.

Revision ID: 0050_native_control_health_observations
Revises: 0049_native_control_framework
"""

from alembic import op
import sqlalchemy as sa


revision = "0050_native_control_health_observations"
down_revision = "0049_native_control_framework"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "native_control_health_observations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("integration_instance_id", sa.String(length=36), nullable=False),
        sa.Column("credential_id", sa.String(length=128), nullable=False),
        sa.Column("credential_epoch", sa.Integer(), nullable=False),
        sa.Column("provider_event_id_hash", sa.String(length=64), nullable=False),
        sa.Column("provider_event_type", sa.String(length=64), nullable=False),
        sa.Column("callback_authenticated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence_flowing", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("evidence_ref", sa.String(length=255), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("latency_ms IS NULL OR latency_ms >= 0", name="ck_native_health_latency_nonnegative"),
        sa.CheckConstraint(
            "source IN ('signed_native_callback','endpoint_runtime_probe','health_reconciler')",
            name="ck_native_health_source",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "integration_instance_id"],
            ["native_control_integrations.tenant_id", "native_control_integrations.id"],
            name="fk_native_health_tenant_integration",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "integration_instance_id", "provider_event_id_hash",
            name="uq_native_health_tenant_provider_event",
        ),
    )
    op.create_index(
        "idx_native_health_tenant_integration_time",
        "native_control_health_observations",
        ["tenant_id", "integration_instance_id", "observed_at"],
    )
    op.create_index(
        "idx_native_health_expiry",
        "native_control_health_observations",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_native_health_expiry", table_name="native_control_health_observations")
    op.drop_index("idx_native_health_tenant_integration_time", table_name="native_control_health_observations")
    op.drop_table("native_control_health_observations")

