"""add findings table and dedupe tracking

Revision ID: 0016_findings_table
Revises: 0015_guardian_contracts_v2
Create Date: 2026-03-03 00:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0016_findings_table"
down_revision = "0015_guardian_contracts_v2"
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
        "findings",
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("ai_tool", sa.String(length=128), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("department", sa.String(length=128), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("finding_type", sa.String(length=64), nullable=False),
        sa.Column("risk_category", sa.String(length=64), nullable=False),
        sa.Column("data_classification", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="open"),
        sa.Column("recommended_action", sa.Text(), nullable=False, server_default=""),
        sa.Column("policy_version_id", sa.String(length=36), nullable=True),
        sa.Column("evidence_node_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("related_control_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("dedupe_key", sa.String(length=128), nullable=False),
        sa.Column("occurrence_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("finding_id"),
        sa.CheckConstraint(
            "status in ('open','reviewing','resolved','accepted_risk')",
            name="ck_findings_status",
        ),
    )
    op.create_index("idx_findings_tenant_status", "findings", ["tenant_id", "status"])
    op.create_index("idx_findings_tenant_severity", "findings", ["tenant_id", "severity"])
    op.create_index("idx_findings_tenant_type", "findings", ["tenant_id", "finding_type"])
    op.create_index("idx_findings_tenant_system", "findings", ["tenant_id", "ai_system_id"])
    op.create_index("idx_findings_tenant_dedupe", "findings", ["tenant_id", "dedupe_key"])

    if dialect != "sqlite":
        op.alter_column("findings", "status", server_default=None)
        op.alter_column("findings", "recommended_action", server_default=None)
        op.alter_column("findings", "evidence_node_ids", server_default=None)
        op.alter_column("findings", "related_control_ids", server_default=None)
        op.alter_column("findings", "occurrence_count", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_findings_tenant_dedupe", table_name="findings")
    op.drop_index("idx_findings_tenant_system", table_name="findings")
    op.drop_index("idx_findings_tenant_type", table_name="findings")
    op.drop_index("idx_findings_tenant_severity", table_name="findings")
    op.drop_index("idx_findings_tenant_status", table_name="findings")
    op.drop_table("findings")
