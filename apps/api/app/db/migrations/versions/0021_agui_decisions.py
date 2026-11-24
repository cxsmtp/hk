"""add agui decisions table

Revision ID: 0021_agui_decisions
Revises: 0020_simulation_schedule_decisions
Create Date: 2026-03-10 10:15:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0021_agui_decisions"
down_revision = "0020_simulation_schedule_decisions"
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
        "agui_decisions",
        sa.Column("decision_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("action_id", sa.String(length=128), nullable=False),
        sa.Column("decision", sa.String(length=64), nullable=False),
        sa.Column("justification", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(length=36), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("evidence_node_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("audit_log_id", sa.String(length=36), nullable=False),
        sa.Column("source_module", sa.String(length=64), nullable=False, server_default="agui"),
        sa.Column("source_object_type", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("source_object_id", sa.String(length=128), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["audit_log_id"], ["audit_logs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("decision_id"),
    )
    op.create_index(
        "idx_agui_decisions_tenant_action",
        "agui_decisions",
        ["tenant_id", "action_id"],
    )
    op.create_index(
        "idx_agui_decisions_tenant_decided_at",
        "agui_decisions",
        ["tenant_id", "decided_at"],
    )

    if dialect != "sqlite":
        op.alter_column("agui_decisions", "evidence_node_ids", server_default=None)
        op.alter_column("agui_decisions", "source_module", server_default=None)
        op.alter_column("agui_decisions", "source_object_type", server_default=None)
        op.alter_column("agui_decisions", "source_object_id", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_agui_decisions_tenant_decided_at", table_name="agui_decisions")
    op.drop_index("idx_agui_decisions_tenant_action", table_name="agui_decisions")
    op.drop_table("agui_decisions")
