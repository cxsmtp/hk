"""extend ai iam for agent action control and delegation tracking

Revision ID: 0024_ai_iam_agent_action_control
Revises: 0023_shadow_ai_discovery_engine
Create Date: 2026-03-23 17:20:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0024_ai_iam_agent_action_control"
down_revision = "0023_shadow_ai_discovery_engine"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    json_type = _json_type()

    op.add_column(
        "agent_identities",
        sa.Column("action_scope", json_type, nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "agent_identities",
        sa.Column("tool_registry", json_type, nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "agent_identities",
        sa.Column("external_system_access", json_type, nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "agent_identities",
        sa.Column("agent_type", sa.String(length=32), nullable=False, server_default="workflow_agent"),
    )
    op.add_column(
        "agent_identities",
        sa.Column("autonomy_level", sa.String(length=16), nullable=False, server_default="medium"),
    )

    op.create_table(
        "agent_delegations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("parent_agent_identity_id", sa.String(length=36), nullable=False),
        sa.Column("child_agent_identity_id", sa.String(length=36), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("parent_token_id", sa.String(length=36), nullable=False),
        sa.Column("child_token_id", sa.String(length=36), nullable=False),
        sa.Column("action_scope", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("chain_depth", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["parent_agent_identity_id"], ["agent_identities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["child_agent_identity_id"], ["agent_identities.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["parent_token_id"], ["capability_tokens.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["child_token_id"], ["capability_tokens.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "parent_agent_identity_id",
            "child_agent_identity_id",
            "parent_token_id",
            "child_token_id",
            name="uq_agent_delegation_link",
        ),
    )

    op.create_index(
        "idx_agent_delegation_tenant_parent",
        "agent_delegations",
        ["tenant_id", "parent_agent_identity_id"],
    )
    op.create_index(
        "idx_agent_delegation_tenant_child",
        "agent_delegations",
        ["tenant_id", "child_agent_identity_id"],
    )
    op.create_index(
        "idx_agent_delegation_tenant_status",
        "agent_delegations",
        ["tenant_id", "status"],
    )

    if dialect != "sqlite":
        op.alter_column("agent_identities", "action_scope", server_default=None)
        op.alter_column("agent_identities", "tool_registry", server_default=None)
        op.alter_column("agent_identities", "external_system_access", server_default=None)
        op.alter_column("agent_identities", "agent_type", server_default=None)
        op.alter_column("agent_identities", "autonomy_level", server_default=None)
        op.alter_column("agent_delegations", "action_scope", server_default=None)
        op.alter_column("agent_delegations", "chain_depth", server_default=None)
        op.alter_column("agent_delegations", "status", server_default=None)
        op.alter_column("agent_delegations", "metadata_json", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_agent_delegation_tenant_status", table_name="agent_delegations")
    op.drop_index("idx_agent_delegation_tenant_child", table_name="agent_delegations")
    op.drop_index("idx_agent_delegation_tenant_parent", table_name="agent_delegations")
    op.drop_table("agent_delegations")

    op.drop_column("agent_identities", "autonomy_level")
    op.drop_column("agent_identities", "agent_type")
    op.drop_column("agent_identities", "external_system_access")
    op.drop_column("agent_identities", "tool_registry")
    op.drop_column("agent_identities", "action_scope")
