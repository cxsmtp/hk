"""harden ai orchestration trace contract

Revision ID: 0034_ai_orchestration_trace_hardening
Revises: 0033_control_graph_schema
Create Date: 2026-04-02 22:40:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0034_ai_orchestration_trace_hardening"
down_revision = "0033_control_graph_schema"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def _table_has_column(inspector, table_name: str, column_name: str) -> bool:
    return column_name in {item.get("name") for item in inspector.get_columns(table_name)}


def _table_has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_reasoning_traces" not in table_names:
        return

    json_type = _json_type()

    additions: list[tuple[str, sa.Column]] = [
        ("prompt_template_version", sa.Column("prompt_template_version", sa.String(length=32), nullable=False, server_default=sa.text("'v1'"))),
        ("prompt_template_status", sa.Column("prompt_template_status", sa.String(length=16), nullable=False, server_default=sa.text("'active'"))),
        ("retrieval_source_ids_json", sa.Column("retrieval_source_ids_json", json_type, nullable=False, server_default=sa.text("'[]'"))),
        ("runtime_event_refs_json", sa.Column("runtime_event_refs_json", json_type, nullable=False, server_default=sa.text("'[]'"))),
        ("policy_version", sa.Column("policy_version", sa.String(length=128), nullable=False, server_default=sa.text("''"))),
        ("governance_version", sa.Column("governance_version", sa.String(length=128), nullable=False, server_default=sa.text("''"))),
        ("control_id", sa.Column("control_id", sa.String(length=128), nullable=False, server_default=sa.text("''"))),
        ("control_decision_json", sa.Column("control_decision_json", json_type, nullable=False, server_default=sa.text("'{}'"))),
        ("simulation_result_json", sa.Column("simulation_result_json", json_type, nullable=False, server_default=sa.text("'{}'"))),
        ("routing_context_json", sa.Column("routing_context_json", json_type, nullable=False, server_default=sa.text("'{}'"))),
        ("risk_context_json", sa.Column("risk_context_json", json_type, nullable=False, server_default=sa.text("'{}'"))),
        ("remediation_impact_json", sa.Column("remediation_impact_json", json_type, nullable=False, server_default=sa.text("'{}'"))),
    ]

    for column_name, column in additions:
        if not _table_has_column(inspector, "ai_reasoning_traces", column_name):
            op.add_column("ai_reasoning_traces", column)

    if not _table_has_index(inspector, "ai_reasoning_traces", "idx_ai_reasoning_trace_tenant_control"):
        op.create_index(
            "idx_ai_reasoning_trace_tenant_control",
            "ai_reasoning_traces",
            ["tenant_id", "control_id"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_reasoning_traces" not in table_names:
        return

    if _table_has_index(inspector, "ai_reasoning_traces", "idx_ai_reasoning_trace_tenant_control"):
        op.drop_index("idx_ai_reasoning_trace_tenant_control", table_name="ai_reasoning_traces")

    for column_name in [
        "remediation_impact_json",
        "risk_context_json",
        "routing_context_json",
        "simulation_result_json",
        "control_decision_json",
        "control_id",
        "governance_version",
        "policy_version",
        "runtime_event_refs_json",
        "retrieval_source_ids_json",
        "prompt_template_status",
        "prompt_template_version",
    ]:
        if _table_has_column(inspector, "ai_reasoning_traces", column_name):
            op.drop_column("ai_reasoning_traces", column_name)
