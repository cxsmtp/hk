"""add brain phase1 persistence tables

Revision ID: 0008_brain_phase1_tables
Revises: 0007_sim_templates_integrations
Create Date: 2026-02-23 01:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0008_brain_phase1_tables"
down_revision = "0007_sim_templates_integrations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "brain_session",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_brain_session_tenant", "brain_session", ["tenant_id"])
    op.create_index("idx_brain_session_user", "brain_session", ["user_id"])

    op.create_table(
        "brain_plan",
        sa.Column("session_id", sa.String(length=36), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("plan_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["session_id"], ["brain_session.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_brain_plan_session", "brain_plan", ["session_id"])

    op.create_table(
        "brain_tool_call",
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("tool_name", sa.String(length=128), nullable=False),
        sa.Column("args_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("result_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["plan_id"], ["brain_plan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_brain_tool_call_plan", "brain_tool_call", ["plan_id"])
    op.create_index("idx_brain_tool_call_tool", "brain_tool_call", ["tool_name"])

    dialect = op.get_bind().dialect.name
    if dialect != "sqlite":
        op.alter_column("brain_tool_call", "args_json", server_default=None)
        op.alter_column("brain_tool_call", "result_json", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_brain_tool_call_tool", table_name="brain_tool_call")
    op.drop_index("idx_brain_tool_call_plan", table_name="brain_tool_call")
    op.drop_table("brain_tool_call")

    op.drop_index("idx_brain_plan_session", table_name="brain_plan")
    op.drop_table("brain_plan")

    op.drop_index("idx_brain_session_user", table_name="brain_session")
    op.drop_index("idx_brain_session_tenant", table_name="brain_session")
    op.drop_table("brain_session")
