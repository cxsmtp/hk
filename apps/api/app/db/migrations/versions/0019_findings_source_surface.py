"""add source_surface to findings

Revision ID: 0019_findings_source_surface
Revises: 0018_discovery_applications
Create Date: 2026-03-09 18:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0019_findings_source_surface"
down_revision = "0018_discovery_applications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    op.add_column(
        "findings",
        sa.Column("source_surface", sa.String(length=16), nullable=False, server_default="connector"),
    )
    op.execute(
        """
        UPDATE findings
        SET source_surface = CASE
            WHEN finding_type IN ('enforcement_event', 'asymmetry_signal') THEN 'gateway'
            WHEN finding_type IN ('browser_interaction_security') THEN 'browser'
            ELSE 'connector'
        END
        """
    )
    op.create_index("idx_findings_tenant_source", "findings", ["tenant_id", "source_surface"])
    if dialect != "sqlite":
        op.alter_column("findings", "source_surface", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_findings_tenant_source", table_name="findings")
    op.drop_column("findings", "source_surface")
