"""Add tenant-scoped Agent Collective Security P0 state.

Revision ID: 0076_agent_collective_security
Revises: 0075_account_boundary_production_core
"""

from alembic import op
import sqlalchemy as sa


revision = "0076_agent_collective_security"
down_revision = "0075_account_boundary_production_core"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agent_collective_contexts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("delegation_root_context_id", sa.String(36), nullable=False),
        sa.Column("root_action_id", sa.String(64), nullable=False),
        sa.Column("originating_actor_ref", sa.String(255), nullable=False),
        sa.Column("represented_subject_ref", sa.String(255), nullable=False),
        sa.Column("business_purpose_ref", sa.String(255), nullable=False),
        sa.Column("root_objective_ref", sa.String(255), nullable=False),
        sa.Column("authority_envelope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("constraint_set", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("member_agent_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("member_delegation_context_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("active_principal_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("observed_channel_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("shared_store_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("observed_tool_classes", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("observed_external_destinations", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("active_consequential_action_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("authorized_action_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("retry_fingerprints", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("agent_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("maximum_depth", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("maximum_fan_out", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("state_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "delegation_root_context_id"],
            ["delegation_contexts_v2.tenant_id", "delegation_contexts_v2.delegation_context_id"],
            name="fk_agent_collective_delegation_root",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_agent_collective_tenant_id"),
        sa.UniqueConstraint("tenant_id", "delegation_root_context_id", name="uq_agent_collective_root"),
        sa.CheckConstraint("status IN ('ACTIVE','RESTRICTED','ABANDONED','REVOKED')", name="ck_agent_collective_status"),
        sa.CheckConstraint("state_version >= 0", name="ck_agent_collective_state_version"),
        sa.CheckConstraint("agent_count > 0", name="ck_agent_collective_agent_count"),
        sa.CheckConstraint("maximum_depth > 0", name="ck_agent_collective_depth"),
        sa.CheckConstraint("maximum_fan_out >= 0", name="ck_agent_collective_fanout"),
        sa.CheckConstraint("retry_count >= 0", name="ck_agent_collective_retry_count"),
        sa.CheckConstraint("failure_count >= 0", name="ck_agent_collective_failure_count"),
    )
    op.create_index("idx_agent_collective_tenant_status", "agent_collective_contexts", ["tenant_id", "status"])
    op.create_index("idx_agent_collective_tenant_root_action", "agent_collective_contexts", ["tenant_id", "root_action_id"])

    op.create_table(
        "agent_collective_communication_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("collective_id", sa.String(36), nullable=False),
        sa.Column("writer_agent_ref", sa.String(255), nullable=True),
        sa.Column("reader_agent_ref", sa.String(255), nullable=True),
        sa.Column("channel_type", sa.String(32), nullable=False),
        sa.Column("channel_ref", sa.String(255), nullable=False),
        sa.Column("operation", sa.String(16), nullable=False),
        sa.Column("decision", sa.String(24), nullable=False),
        sa.Column("shared_resource_ref", sa.String(255), nullable=True),
        sa.Column("originating_objective_ref", sa.String(255), nullable=False),
        sa.Column("instruction_ref", sa.String(255), nullable=True),
        sa.Column("authority_context_ref", sa.String(255), nullable=False),
        sa.Column("evidence_quality", sa.String(32), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("runtime_event_id", sa.String(36), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["tenant_id", "collective_id"],
            ["agent_collective_contexts.tenant_id", "agent_collective_contexts.id"],
            name="fk_agent_collective_communication_context",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint("decision IN ('ALLOW','MONITOR','REQUIRE_APPROVAL','BLOCK','UNKNOWN')", name="ck_agent_collective_communication_decision"),
        sa.CheckConstraint("operation IN ('SEND','RECEIVE','WRITE','READ','UNKNOWN')", name="ck_agent_collective_communication_operation"),
    )
    op.create_index("idx_agent_collective_communication_resource", "agent_collective_communication_events", ["tenant_id", "collective_id", "shared_resource_ref", "occurred_at"])
    op.create_index("idx_agent_collective_communication_channel", "agent_collective_communication_events", ["tenant_id", "channel_type", "channel_ref"])

    op.create_table(
        "agent_collective_security_signals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("collective_id", sa.String(36), nullable=False),
        sa.Column("signal_type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("agent_ref", sa.String(255), nullable=True),
        sa.Column("action_id", sa.String(64), nullable=True),
        sa.Column("reason_code", sa.String(128), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("safe_context", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("monitoring_signal_id", sa.String(36), nullable=True),
        sa.Column("runtime_event_id", sa.String(36), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["tenant_id", "collective_id"],
            ["agent_collective_contexts.tenant_id", "agent_collective_contexts.id"],
            name="fk_agent_collective_signal_context",
            ondelete="CASCADE",
        ),
    )
    op.create_index("idx_agent_collective_signal_type", "agent_collective_security_signals", ["tenant_id", "collective_id", "signal_type", "occurred_at"])

    op.create_table(
        "agent_collective_root_revocations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("collective_id", sa.String(36), nullable=False),
        sa.Column("delegation_root_context_id", sa.String(36), nullable=False),
        sa.Column("actor_ref", sa.String(255), nullable=False),
        sa.Column("reason_code", sa.String(128), nullable=False),
        sa.Column("affected_agent_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("affected_action_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("affected_authority_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("runtime_event_id", sa.String(36), nullable=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(
            ["tenant_id", "collective_id"],
            ["agent_collective_contexts.tenant_id", "agent_collective_contexts.id"],
            name="fk_agent_collective_revocation_context",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("tenant_id", "collective_id", name="uq_agent_collective_root_revocation"),
    )
    op.create_index("idx_agent_collective_revocation_root", "agent_collective_root_revocations", ["tenant_id", "delegation_root_context_id"])


def downgrade() -> None:
    op.drop_index("idx_agent_collective_revocation_root", table_name="agent_collective_root_revocations")
    op.drop_table("agent_collective_root_revocations")
    op.drop_index("idx_agent_collective_signal_type", table_name="agent_collective_security_signals")
    op.drop_table("agent_collective_security_signals")
    op.drop_index("idx_agent_collective_communication_channel", table_name="agent_collective_communication_events")
    op.drop_index("idx_agent_collective_communication_resource", table_name="agent_collective_communication_events")
    op.drop_table("agent_collective_communication_events")
    op.drop_index("idx_agent_collective_tenant_root_action", table_name="agent_collective_contexts")
    op.drop_index("idx_agent_collective_tenant_status", table_name="agent_collective_contexts")
    op.drop_table("agent_collective_contexts")

