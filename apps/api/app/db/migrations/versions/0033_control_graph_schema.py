"""extend controls table for governance control graph

Revision ID: 0033_control_graph_schema
Revises: 0032_ai_orchestration_traces
Create Date: 2026-04-02 20:05:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0033_control_graph_schema"
down_revision = "0032_ai_orchestration_traces"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def _table_columns(inspector, table_name: str) -> set[str]:
    return {column["name"] for column in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "controls" not in table_names:
        return

    columns = _table_columns(inspector, "controls")
    json_type = _json_type()

    if "risk_tags" not in columns:
        op.add_column(
            "controls",
            sa.Column("risk_tags", json_type, nullable=False, server_default=sa.text("'[]'")),
        )
    if "severity" not in columns:
        op.add_column(
            "controls",
            sa.Column("severity", sa.String(length=16), nullable=False, server_default=sa.text("'med'")),
        )
    if "enforcement_points" not in columns:
        op.add_column(
            "controls",
            sa.Column("enforcement_points", json_type, nullable=False, server_default=sa.text("'[]'")),
        )
    if "detection_methods" not in columns:
        op.add_column(
            "controls",
            sa.Column("detection_methods", json_type, nullable=False, server_default=sa.text("'[]'")),
        )
    if "response_actions" not in columns:
        op.add_column(
            "controls",
            sa.Column("response_actions", json_type, nullable=False, server_default=sa.text("'[]'")),
        )
    if "evidence_types" not in columns:
        op.add_column(
            "controls",
            sa.Column("evidence_types", json_type, nullable=False, server_default=sa.text("'[]'")),
        )
    if "remediation_templates" not in columns:
        op.add_column(
            "controls",
            sa.Column("remediation_templates", json_type, nullable=False, server_default=sa.text("'[]'")),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "controls" not in table_names:
        return

    columns = _table_columns(inspector, "controls")

    for column_name in [
        "remediation_templates",
        "evidence_types",
        "response_actions",
        "detection_methods",
        "enforcement_points",
        "severity",
        "risk_tags",
    ]:
        if column_name in columns:
            op.drop_column("controls", column_name)
