"""add runtime patterns table for behavior engine

Revision ID: 0027_runtime_patterns_behavior_engine
Revises: 0026_runtime_context_graph_chain_tracking
Create Date: 2026-03-28 16:10:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0027_runtime_patterns_behavior_engine"
down_revision = "0026_runtime_context_graph_chain_tracking"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "runtime_patterns" in table_names:
        return

    json_type = _json_type()
    op.create_table(
        "runtime_patterns",
        sa.Column("pattern_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("type", sa.String(length=128), nullable=False),
        sa.Column("frequency", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("severity", sa.String(length=16), nullable=False, server_default=sa.text("'low'")),
        sa.Column("affected_entities", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("pattern_id"),
        sa.UniqueConstraint("tenant_id", "type", name="uq_runtime_patterns_tenant_type"),
    )
    op.create_index("idx_runtime_patterns_tenant_type", "runtime_patterns", ["tenant_id", "type"])
    op.create_index("idx_runtime_patterns_tenant_severity", "runtime_patterns", ["tenant_id", "severity"])
    op.create_index("idx_runtime_patterns_tenant_updated", "runtime_patterns", ["tenant_id", "updated_at"])

    if bind.dialect.name != "sqlite":
        inspector = inspect(bind)
        if _has_index(inspector, "runtime_patterns", "idx_runtime_patterns_tenant_type"):
            op.alter_column("runtime_patterns", "frequency", server_default=None)
            op.alter_column("runtime_patterns", "severity", server_default=None)
            op.alter_column("runtime_patterns", "affected_entities", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "runtime_patterns" not in table_names:
        return

    for index_name in (
        "idx_runtime_patterns_tenant_updated",
        "idx_runtime_patterns_tenant_severity",
        "idx_runtime_patterns_tenant_type",
    ):
        if _has_index(inspector, "runtime_patterns", index_name):
            op.drop_index(index_name, table_name="runtime_patterns")
    op.drop_table("runtime_patterns")
