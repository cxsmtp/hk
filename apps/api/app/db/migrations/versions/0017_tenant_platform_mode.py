"""add tenant platform mode

Revision ID: 0017_tenant_platform_mode
Revises: 0016_findings_table
Create Date: 2026-03-09 14:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0017_tenant_platform_mode"
down_revision = "0016_findings_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("platform_mode", sa.String(length=16), nullable=False, server_default="enforce"),
    )
    op.execute("UPDATE tenants SET platform_mode = 'enforce' WHERE platform_mode IS NULL")
    if op.get_bind().dialect.name != "sqlite":
        op.alter_column("tenants", "platform_mode", server_default=None)


def downgrade() -> None:
    op.drop_column("tenants", "platform_mode")
