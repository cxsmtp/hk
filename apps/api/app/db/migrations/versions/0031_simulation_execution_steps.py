"""add simulation execution step trace table

Revision ID: 0031_simulation_execution_steps
Revises: 0030_shadow_scan_engine
Create Date: 2026-04-02 14:30:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0031_simulation_execution_steps"
down_revision = "0030_shadow_scan_engine"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def _table_has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    json_type = _json_type()

    if "simulation_execution_steps" not in table_names:
        op.create_table(
            "simulation_execution_steps",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("simulation_run_id", sa.String(length=36), nullable=False),
            sa.Column("iteration_index", sa.Integer(), nullable=False, server_default=sa.text("1")),
            sa.Column("step_id", sa.String(length=64), nullable=False),
            sa.Column("step_order", sa.Integer(), nullable=False),
            sa.Column("step_type", sa.String(length=64), nullable=False),
            sa.Column("title", sa.String(length=255), nullable=False),
            sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'pending'")),
            sa.Column("timestamp_started", sa.DateTime(timezone=True), nullable=True),
            sa.Column("timestamp_completed", sa.DateTime(timezone=True), nullable=True),
            sa.Column("actor", sa.String(length=64), nullable=False, server_default=sa.text("'evaluator'")),
            sa.Column("target_surface", sa.String(length=32), nullable=False, server_default=sa.text("'monitoring'")),
            sa.Column("input_payload_ref", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("output_payload_ref", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("control_refs", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("decision_ref", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("evidence_refs", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("notes", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["simulation_run_id"], ["simulation_runs.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index(
            "idx_sim_exec_step_tenant_run",
            "simulation_execution_steps",
            ["tenant_id", "simulation_run_id"],
        )
        op.create_index(
            "idx_sim_exec_step_run_iteration_order",
            "simulation_execution_steps",
            ["simulation_run_id", "iteration_index", "step_order"],
        )
        op.create_index(
            "idx_sim_exec_step_tenant_status",
            "simulation_execution_steps",
            ["tenant_id", "status"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "simulation_execution_steps" not in table_names:
        return

    for index_name in [
        "idx_sim_exec_step_tenant_status",
        "idx_sim_exec_step_run_iteration_order",
        "idx_sim_exec_step_tenant_run",
    ]:
        if _table_has_index(inspector, "simulation_execution_steps", index_name):
            op.drop_index(index_name, table_name="simulation_execution_steps")

    op.drop_table("simulation_execution_steps")
