"""add runtime context graph and chain tracking fields

Revision ID: 0026_runtime_context_graph_chain_tracking
Revises: 0025_guardian_contract_v2_canonical_policy
Create Date: 2026-03-28 12:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0026_runtime_context_graph_chain_tracking"
down_revision = "0025_guardian_contract_v2_canonical_policy"
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
    dialect = bind.dialect.name

    runtime_columns = {item["name"] for item in inspector.get_columns("runtime_events")}
    if "context_id" not in runtime_columns:
        op.add_column("runtime_events", sa.Column("context_id", sa.String(length=64), nullable=True))
    if "chain_id" not in runtime_columns:
        op.add_column("runtime_events", sa.Column("chain_id", sa.String(length=64), nullable=True))
    if "parent_action_id" not in runtime_columns:
        op.add_column("runtime_events", sa.Column("parent_action_id", sa.String(length=64), nullable=True))
    if "entity_type" not in runtime_columns:
        op.add_column("runtime_events", sa.Column("entity_type", sa.String(length=32), nullable=True))
    if "entity_id" not in runtime_columns:
        op.add_column("runtime_events", sa.Column("entity_id", sa.String(length=128), nullable=True))
    if "risk_score" not in runtime_columns:
        op.add_column(
            "runtime_events",
            sa.Column("risk_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
        )

    inspector = inspect(bind)
    if not _has_index(inspector, "runtime_events", "idx_runtime_events_context"):
        op.create_index("idx_runtime_events_context", "runtime_events", ["tenant_id", "context_id"])
    if not _has_index(inspector, "runtime_events", "idx_runtime_events_chain"):
        op.create_index("idx_runtime_events_chain", "runtime_events", ["tenant_id", "chain_id"])
    if not _has_index(inspector, "runtime_events", "idx_runtime_events_entity"):
        op.create_index("idx_runtime_events_entity", "runtime_events", ["tenant_id", "entity_type", "entity_id"])

    table_names = set(inspector.get_table_names())
    json_type = _json_type()
    if "context_nodes" not in table_names:
        op.create_table(
            "context_nodes",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("context_id", sa.String(length=64), nullable=False),
            sa.Column("type", sa.String(length=32), nullable=False),
            sa.Column("entity_id", sa.String(length=128), nullable=False),
            sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "context_id", "type", "entity_id", name="uq_context_nodes_tenant_context_entity"),
        )
        op.create_index("idx_context_nodes_tenant_context", "context_nodes", ["tenant_id", "context_id"])
        op.create_index("idx_context_nodes_tenant_type", "context_nodes", ["tenant_id", "type"])

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "context_edges" not in table_names:
        op.create_table(
            "context_edges",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("context_id", sa.String(length=64), nullable=False),
            sa.Column("from_node", sa.String(length=36), nullable=False),
            sa.Column("to_node", sa.String(length=36), nullable=False),
            sa.Column("relation_type", sa.String(length=64), nullable=False),
            sa.Column("chain_id", sa.String(length=64), nullable=True),
            sa.Column("parent_action_id", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["from_node"], ["context_nodes.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["to_node"], ["context_nodes.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_context_edges_tenant_context", "context_edges", ["tenant_id", "context_id"])
        op.create_index("idx_context_edges_tenant_relation", "context_edges", ["tenant_id", "relation_type"])
        op.create_index("idx_context_edges_tenant_chain", "context_edges", ["tenant_id", "chain_id"])

    if dialect != "sqlite":
        op.alter_column("runtime_events", "risk_score", server_default=None)
        if "context_nodes" in set(inspect(bind).get_table_names()):
            op.alter_column("context_nodes", "metadata_json", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "context_edges" in table_names:
        for index_name in (
            "idx_context_edges_tenant_chain",
            "idx_context_edges_tenant_relation",
            "idx_context_edges_tenant_context",
        ):
            if _has_index(inspector, "context_edges", index_name):
                op.drop_index(index_name, table_name="context_edges")
        op.drop_table("context_edges")

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "context_nodes" in table_names:
        for index_name in (
            "idx_context_nodes_tenant_type",
            "idx_context_nodes_tenant_context",
        ):
            if _has_index(inspector, "context_nodes", index_name):
                op.drop_index(index_name, table_name="context_nodes")
        op.drop_table("context_nodes")

    inspector = inspect(bind)
    if "runtime_events" in set(inspector.get_table_names()):
        for index_name in (
            "idx_runtime_events_entity",
            "idx_runtime_events_chain",
            "idx_runtime_events_context",
        ):
            if _has_index(inspector, "runtime_events", index_name):
                op.drop_index(index_name, table_name="runtime_events")
        runtime_columns = {item["name"] for item in inspector.get_columns("runtime_events")}
        for column in ("risk_score", "entity_id", "entity_type", "parent_action_id", "chain_id", "context_id"):
            if column in runtime_columns:
                op.drop_column("runtime_events", column)
