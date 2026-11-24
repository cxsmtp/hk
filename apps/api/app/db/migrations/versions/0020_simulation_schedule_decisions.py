"""add simulation schedule decisions table

Revision ID: 0020_simulation_schedule_decisions
Revises: 0019_findings_source_surface
Create Date: 2026-03-09 23:15:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0020_simulation_schedule_decisions"
down_revision = "0019_findings_source_surface"
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
        "simulation_schedule_decisions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("target_ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("target_control_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("trigger_payload", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="scheduled"),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scheduled_simulation_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("simulation_run_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("execution_summary", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_sim_schedule_tenant_reason",
        "simulation_schedule_decisions",
        ["tenant_id", "reason_code", "scheduled_at"],
    )
    op.create_index(
        "idx_sim_schedule_tenant_ai_system",
        "simulation_schedule_decisions",
        ["tenant_id", "target_ai_system_id"],
    )
    op.create_index(
        "idx_sim_schedule_tenant_status",
        "simulation_schedule_decisions",
        ["tenant_id", "status"],
    )

    if dialect != "sqlite":
        op.alter_column("simulation_schedule_decisions", "target_control_ids", server_default=None)
        op.alter_column("simulation_schedule_decisions", "trigger_payload", server_default=None)
        op.alter_column("simulation_schedule_decisions", "status", server_default=None)
        op.alter_column("simulation_schedule_decisions", "scheduled_simulation_ids", server_default=None)
        op.alter_column("simulation_schedule_decisions", "simulation_run_ids", server_default=None)
        op.alter_column("simulation_schedule_decisions", "execution_summary", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_sim_schedule_tenant_status", table_name="simulation_schedule_decisions")
    op.drop_index("idx_sim_schedule_tenant_ai_system", table_name="simulation_schedule_decisions")
    op.drop_index("idx_sim_schedule_tenant_reason", table_name="simulation_schedule_decisions")
    op.drop_table("simulation_schedule_decisions")

