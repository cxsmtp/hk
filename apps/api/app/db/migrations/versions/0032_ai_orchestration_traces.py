"""add ai orchestration trace table

Revision ID: 0032_ai_orchestration_traces
Revises: 0031_simulation_execution_steps
Create Date: 2026-04-02 18:20:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0032_ai_orchestration_traces"
down_revision = "0031_simulation_execution_steps"
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

    if "ai_reasoning_traces" not in table_names:
        op.create_table(
            "ai_reasoning_traces",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("actor_user_id", sa.String(length=36), nullable=True),
            sa.Column("issue_type", sa.String(length=64), nullable=False),
            sa.Column("issue_id", sa.String(length=128), nullable=False),
            sa.Column("task_type", sa.String(length=64), nullable=False),
            sa.Column("provider", sa.String(length=32), nullable=False),
            sa.Column("model", sa.String(length=128), nullable=False),
            sa.Column("model_version", sa.String(length=64), nullable=False, server_default=sa.text("''")),
            sa.Column("prompt_template_id", sa.String(length=128), nullable=False),
            sa.Column("prompt_variables_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("retrieval_refs_json", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("evidence_refs_json", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("routing_policy_id", sa.String(length=128), nullable=False),
            sa.Column("policy_route_id", sa.String(length=128), nullable=False),
            sa.Column("region_route", sa.String(length=64), nullable=False, server_default=sa.text("'global'")),
            sa.Column("pre_call_guard_results_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("post_call_guard_results_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("output_schema_valid", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("token_usage_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("cost_estimate_usd", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'completed'")),
            sa.Column("output_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("rejection_reason", sa.Text(), nullable=True),
            sa.Column("correlation_id", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )

        op.create_index(
            "idx_ai_reasoning_trace_tenant_created",
            "ai_reasoning_traces",
            ["tenant_id", "created_at"],
        )
        op.create_index(
            "idx_ai_reasoning_trace_tenant_task",
            "ai_reasoning_traces",
            ["tenant_id", "task_type"],
        )
        op.create_index(
            "idx_ai_reasoning_trace_tenant_issue",
            "ai_reasoning_traces",
            ["tenant_id", "issue_type", "issue_id"],
        )
        op.create_index(
            "idx_ai_reasoning_trace_tenant_policy",
            "ai_reasoning_traces",
            ["tenant_id", "routing_policy_id"],
        )
        op.create_index(
            "idx_ai_reasoning_trace_tenant_corr",
            "ai_reasoning_traces",
            ["tenant_id", "correlation_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_reasoning_traces" not in table_names:
        return

    for index_name in [
        "idx_ai_reasoning_trace_tenant_corr",
        "idx_ai_reasoning_trace_tenant_policy",
        "idx_ai_reasoning_trace_tenant_issue",
        "idx_ai_reasoning_trace_tenant_task",
        "idx_ai_reasoning_trace_tenant_created",
    ]:
        if _table_has_index(inspector, "ai_reasoning_traces", index_name):
            op.drop_index(index_name, table_name="ai_reasoning_traces")

    op.drop_table("ai_reasoning_traces")
