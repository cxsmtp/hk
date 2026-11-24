"""add runtime intelligence layer tables

Revision ID: 0022_runtime_intelligence_layer
Revises: 0021_agui_decisions
Create Date: 2026-03-21 16:00:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0022_runtime_intelligence_layer"
down_revision = "0021_agui_decisions"
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
        "runtime_events",
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("source_surface", sa.String(length=16), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("app_id", sa.String(length=128), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("agent_id", sa.String(length=64), nullable=True),
        sa.Column("risk_tier", sa.String(length=16), nullable=True),
        sa.Column("policy_version_id", sa.String(length=36), nullable=True),
        sa.Column("governance_version", sa.String(length=64), nullable=True),
        sa.Column("severity", sa.String(length=16), nullable=True),
        sa.Column("confidence_tier", sa.String(length=32), nullable=True),
        sa.Column("evidence_node_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["policy_version_id"], ["policy_versions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("event_id"),
    )
    op.create_index("idx_runtime_events_tenant_created", "runtime_events", ["tenant_id", "created_at"])
    op.create_index("idx_runtime_events_tenant_source", "runtime_events", ["tenant_id", "source_surface"])
    op.create_index("idx_runtime_events_tenant_type", "runtime_events", ["tenant_id", "event_type"])
    op.create_index("idx_runtime_events_tenant_ai", "runtime_events", ["tenant_id", "ai_system_id"])
    op.create_index("idx_runtime_events_correlation", "runtime_events", ["correlation_id"])

    op.create_table(
        "runtime_behavior_edges",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=True),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("source_node_type", sa.String(length=32), nullable=False),
        sa.Column("source_node_id", sa.String(length=128), nullable=False),
        sa.Column("source_node_label", sa.String(length=255), nullable=True),
        sa.Column("target_node_type", sa.String(length=32), nullable=False),
        sa.Column("target_node_id", sa.String(length=128), nullable=False),
        sa.Column("target_node_label", sa.String(length=255), nullable=True),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        sa.Column("evidence_node_id", sa.String(length=36), nullable=True),
        sa.Column("payload", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["runtime_events.event_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["evidence_node_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_runtime_behavior_edges_tenant_event", "runtime_behavior_edges", ["tenant_id", "event_id"])
    op.create_index("idx_runtime_behavior_edges_tenant_ai", "runtime_behavior_edges", ["tenant_id", "ai_system_id"])
    op.create_index(
        "idx_runtime_behavior_edges_tenant_relation",
        "runtime_behavior_edges",
        ["tenant_id", "relationship_type"],
    )

    op.create_table(
        "runtime_simulation_triggers",
        sa.Column("trigger_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("event_id", sa.String(length=36), nullable=True),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("target_pack", sa.String(length=64), nullable=False),
        sa.Column("related_control_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("evidence_node_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("recommended_action", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="pending"),
        sa.Column("schedule_decision_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["event_id"], ["runtime_events.event_id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["schedule_decision_id"], ["simulation_schedule_decisions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("trigger_id"),
    )
    op.create_index("idx_runtime_triggers_tenant_status", "runtime_simulation_triggers", ["tenant_id", "status"])
    op.create_index("idx_runtime_triggers_tenant_ai", "runtime_simulation_triggers", ["tenant_id", "ai_system_id"])
    op.create_index("idx_runtime_triggers_tenant_reason", "runtime_simulation_triggers", ["tenant_id", "reason_code"])

    op.create_table(
        "runtime_governance_recommendations",
        sa.Column("recommendation_id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("event_id", sa.String(length=36), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("recommendation_type", sa.String(length=64), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("priority", sa.String(length=16), nullable=False, server_default="med"),
        sa.Column("payload", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="proposed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["runtime_events.event_id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("recommendation_id"),
    )
    op.create_index(
        "idx_runtime_recos_tenant_status",
        "runtime_governance_recommendations",
        ["tenant_id", "status"],
    )
    op.create_index(
        "idx_runtime_recos_tenant_ai",
        "runtime_governance_recommendations",
        ["tenant_id", "ai_system_id"],
    )
    op.create_index(
        "idx_runtime_recos_tenant_type",
        "runtime_governance_recommendations",
        ["tenant_id", "recommendation_type"],
    )

    if dialect != "sqlite":
        op.alter_column("runtime_events", "evidence_node_ids", server_default=None)
        op.alter_column("runtime_events", "metadata_json", server_default=None)
        op.alter_column("runtime_behavior_edges", "payload", server_default=None)
        op.alter_column("runtime_simulation_triggers", "related_control_ids", server_default=None)
        op.alter_column("runtime_simulation_triggers", "evidence_node_ids", server_default=None)
        op.alter_column("runtime_simulation_triggers", "recommended_action", server_default=None)
        op.alter_column("runtime_simulation_triggers", "status", server_default=None)
        op.alter_column("runtime_governance_recommendations", "priority", server_default=None)
        op.alter_column("runtime_governance_recommendations", "payload", server_default=None)
        op.alter_column("runtime_governance_recommendations", "status", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_runtime_recos_tenant_type", table_name="runtime_governance_recommendations")
    op.drop_index("idx_runtime_recos_tenant_ai", table_name="runtime_governance_recommendations")
    op.drop_index("idx_runtime_recos_tenant_status", table_name="runtime_governance_recommendations")
    op.drop_table("runtime_governance_recommendations")

    op.drop_index("idx_runtime_triggers_tenant_reason", table_name="runtime_simulation_triggers")
    op.drop_index("idx_runtime_triggers_tenant_ai", table_name="runtime_simulation_triggers")
    op.drop_index("idx_runtime_triggers_tenant_status", table_name="runtime_simulation_triggers")
    op.drop_table("runtime_simulation_triggers")

    op.drop_index("idx_runtime_behavior_edges_tenant_relation", table_name="runtime_behavior_edges")
    op.drop_index("idx_runtime_behavior_edges_tenant_ai", table_name="runtime_behavior_edges")
    op.drop_index("idx_runtime_behavior_edges_tenant_event", table_name="runtime_behavior_edges")
    op.drop_table("runtime_behavior_edges")

    op.drop_index("idx_runtime_events_correlation", table_name="runtime_events")
    op.drop_index("idx_runtime_events_tenant_ai", table_name="runtime_events")
    op.drop_index("idx_runtime_events_tenant_type", table_name="runtime_events")
    op.drop_index("idx_runtime_events_tenant_source", table_name="runtime_events")
    op.drop_index("idx_runtime_events_tenant_created", table_name="runtime_events")
    op.drop_table("runtime_events")
