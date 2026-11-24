"""Add bounded metadata-only endpoint fleet inventory orchestration.

Revision ID: 0084_hmair_endpoint_metadata_inventory
Revises: 0083_user_visibility_prompt_explorer
"""

from alembic import op
import sqlalchemy as sa


revision = "0084_hmair_endpoint_metadata_inventory"
down_revision = "0083_user_visibility_prompt_explorer"
branch_labels = None
depends_on = None


def _timestamps() -> list[sa.Column]:
    return [
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
    ]


def upgrade() -> None:
    op.create_table(
        "endpoint_metadata_inventory_runs",
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "requested_by_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("request_idempotency_key", sa.String(128), nullable=False),
        sa.Column("request_digest", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("endpoint_denominator", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "limitations_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "request_idempotency_key",
            name="uq_ep_meta_inv_run_request",
        ),
        sa.CheckConstraint(
            "status IN ('queued','running','complete','partially_complete',"
            "'failed','cancelled','expired')",
            name="ck_ep_meta_inv_run_status",
        ),
        sa.CheckConstraint(
            "endpoint_denominator >= 1",
            name="ck_ep_meta_inv_run_denominator",
        ),
    )
    op.create_index(
        "idx_ep_meta_inv_run_tenant_status_expiry",
        "endpoint_metadata_inventory_runs",
        ["tenant_id", "status", "expires_at"],
    )

    op.create_table(
        "endpoint_metadata_inventory_assignments",
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "inventory_run_id",
            sa.String(36),
            sa.ForeignKey("endpoint_metadata_inventory_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "endpoint_device_identity_id",
            sa.String(36),
            sa.ForeignKey("endpoint_device_identities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("scan_id", sa.String(36), nullable=True),
        sa.Column("observations_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_code", sa.String(64), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        *_timestamps(),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "inventory_run_id",
            "endpoint_device_identity_id",
            name="uq_ep_meta_inv_assignment_scope",
        ),
        sa.CheckConstraint(
            "status IN ('pending','delivered','complete','failed','expired','cancelled')",
            name="ck_ep_meta_inv_assignment_status",
        ),
        sa.CheckConstraint(
            "observations_count >= 0",
            name="ck_ep_meta_inv_assignment_observations",
        ),
    )
    op.create_index(
        "idx_ep_meta_inv_assignment_run_status",
        "endpoint_metadata_inventory_assignments",
        ["inventory_run_id", "status"],
    )
    op.create_index(
        "idx_ep_meta_inv_assignment_tenant_endpoint_status",
        "endpoint_metadata_inventory_assignments",
        ["tenant_id", "endpoint_device_identity_id", "status"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_ep_meta_inv_assignment_tenant_endpoint_status",
        table_name="endpoint_metadata_inventory_assignments",
    )
    op.drop_index(
        "idx_ep_meta_inv_assignment_run_status",
        table_name="endpoint_metadata_inventory_assignments",
    )
    op.drop_table("endpoint_metadata_inventory_assignments")
    op.drop_index(
        "idx_ep_meta_inv_run_tenant_status_expiry",
        table_name="endpoint_metadata_inventory_runs",
    )
    op.drop_table("endpoint_metadata_inventory_runs")
