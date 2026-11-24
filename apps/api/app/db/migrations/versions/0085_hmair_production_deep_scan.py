"""Add additive Deep Scan coverage and endpoint-parent linkage.

Revision ID: 0085_hmair_production_deep_scan
Revises: 0084_hmair_endpoint_metadata_inventory
"""

from alembic import op
import sqlalchemy as sa


revision = "0085_hmair_production_deep_scan"
down_revision = "0084_hmair_endpoint_metadata_inventory"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "discovery_targets",
        sa.Column(
            "coverage_baseline_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )
    op.add_column(
        "endpoint_metadata_inventory_runs",
        sa.Column("parent_scan_id", sa.String(36), nullable=True),
    )
    op.add_column(
        "endpoint_metadata_inventory_runs",
        sa.Column("parent_assignment_id", sa.String(36), nullable=True),
    )
    op.create_index(
        "idx_ep_meta_inv_run_tenant_parent_scan",
        "endpoint_metadata_inventory_runs",
        ["tenant_id", "parent_scan_id"],
    )
    op.create_index(
        "idx_ep_meta_inv_run_tenant_parent_assignment",
        "endpoint_metadata_inventory_runs",
        ["tenant_id", "parent_assignment_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_ep_meta_inv_run_tenant_parent_assignment",
        table_name="endpoint_metadata_inventory_runs",
    )
    op.drop_index(
        "idx_ep_meta_inv_run_tenant_parent_scan",
        table_name="endpoint_metadata_inventory_runs",
    )
    op.drop_column("endpoint_metadata_inventory_runs", "parent_assignment_id")
    op.drop_column("endpoint_metadata_inventory_runs", "parent_scan_id")
    op.drop_column("discovery_targets", "coverage_baseline_json")
