"""add brain model call and arbitration tables

Revision ID: 0009_brain_phase1_model_logs
Revises: 0008_brain_phase1_tables
Create Date: 2026-02-24 12:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0009_brain_phase1_model_logs"
down_revision = "0008_brain_phase1_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "brain_model_call",
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("task_type", sa.String(length=32), nullable=False),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("prompt_hash", sa.String(length=64), nullable=False),
        sa.Column("output_hash", sa.String(length=64), nullable=False),
        sa.Column("output_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["plan_id"], ["brain_plan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_brain_model_call_plan", "brain_model_call", ["plan_id"])
    op.create_index("idx_brain_model_call_task", "brain_model_call", ["task_type"])
    op.create_index("idx_brain_model_call_provider", "brain_model_call", ["provider"])

    op.create_table(
        "brain_arbitration",
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("task_type", sa.String(length=32), nullable=False),
        sa.Column("winner", sa.String(length=32), nullable=True),
        sa.Column("dissenters_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("reason_codes_json", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["plan_id"], ["brain_plan.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_brain_arbitration_plan", "brain_arbitration", ["plan_id"])
    op.create_index("idx_brain_arbitration_task", "brain_arbitration", ["task_type"])

    dialect = op.get_bind().dialect.name
    if dialect != "sqlite":
        op.alter_column("brain_model_call", "output_json", server_default=None)
        op.alter_column("brain_arbitration", "dissenters_json", server_default=None)
        op.alter_column("brain_arbitration", "reason_codes_json", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_brain_arbitration_task", table_name="brain_arbitration")
    op.drop_index("idx_brain_arbitration_plan", table_name="brain_arbitration")
    op.drop_table("brain_arbitration")

    op.drop_index("idx_brain_model_call_provider", table_name="brain_model_call")
    op.drop_index("idx_brain_model_call_task", table_name="brain_model_call")
    op.drop_index("idx_brain_model_call_plan", table_name="brain_model_call")
    op.drop_table("brain_model_call")
