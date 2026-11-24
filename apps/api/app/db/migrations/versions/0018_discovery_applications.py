"""add discovery applications table

Revision ID: 0018_discovery_applications
Revises: 0017_tenant_platform_mode
Create Date: 2026-03-09 15:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0018_discovery_applications"
down_revision = "0017_tenant_platform_mode"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    json_type = _json_type()

    op.create_table(
        "discovery_applications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("tool_key", sa.String(length=128), nullable=False),
        sa.Column("tool_name", sa.String(length=255), nullable=False),
        sa.Column("vendor", sa.String(length=128), nullable=False, server_default="unknown"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="discovered"),
        sa.Column("owner_user_id", sa.String(length=36), nullable=True),
        sa.Column("owner_department", sa.String(length=128), nullable=True),
        sa.Column("provisional_risk_tier", sa.String(length=16), nullable=True),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["owner_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "tool_key", name="uq_discovery_app_tenant_tool"),
    )
    op.create_index("idx_discovery_apps_tenant_status", "discovery_applications", ["tenant_id", "status"])
    op.create_index("idx_discovery_apps_tenant_last_seen", "discovery_applications", ["tenant_id", "last_seen_at"])

    if dialect != "sqlite":
        op.alter_column("discovery_applications", "vendor", server_default=None)
        op.alter_column("discovery_applications", "status", server_default=None)
        op.alter_column("discovery_applications", "metadata_json", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_discovery_apps_tenant_last_seen", table_name="discovery_applications")
    op.drop_index("idx_discovery_apps_tenant_status", table_name="discovery_applications")
    op.drop_table("discovery_applications")
