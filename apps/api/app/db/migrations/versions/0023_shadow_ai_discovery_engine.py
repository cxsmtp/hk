"""add shadow ai discovery entities and signals

Revision ID: 0023_shadow_ai_discovery_engine
Revises: 0022_runtime_intelligence_layer
Create Date: 2026-03-23 12:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0023_shadow_ai_discovery_engine"
down_revision = "0022_runtime_intelligence_layer"
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
        "shadow_ai_entities",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("canonical_name", sa.String(length=255), nullable=False),
        sa.Column("discovery_status", sa.String(length=32), nullable=False, server_default="discovered"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("provisional_risk_tier", sa.String(length=16), nullable=True),
        sa.Column("source_surfaces", json_type, nullable=False, server_default=sa.text("'[]'")),
        sa.Column("vendor", sa.String(length=128), nullable=True),
        sa.Column("deployment_type", sa.String(length=64), nullable=True),
        sa.Column("ai_type", sa.String(length=64), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("linked_ai_system_id", sa.String(length=36), nullable=True),
        sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["linked_ai_system_id"], ["ai_systems.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "canonical_name", name="uq_shadow_ai_entity_tenant_canonical"),
    )
    op.create_index("idx_shadow_ai_entities_tenant_status", "shadow_ai_entities", ["tenant_id", "discovery_status"])
    op.create_index("idx_shadow_ai_entities_tenant_last_seen", "shadow_ai_entities", ["tenant_id", "last_seen"])
    op.create_index("idx_shadow_ai_entities_tenant_linked", "shadow_ai_entities", ["tenant_id", "linked_ai_system_id"])

    op.create_table(
        "shadow_ai_signals",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("shadow_ai_entity_id", sa.String(length=36), nullable=True),
        sa.Column("source_surface", sa.String(length=16), nullable=False),
        sa.Column("source_event_id", sa.String(length=64), nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=True),
        sa.Column("provider", sa.String(length=128), nullable=True),
        sa.Column("model_name", sa.String(length=128), nullable=True),
        sa.Column("tool_name", sa.String(length=255), nullable=True),
        sa.Column("api_endpoint", sa.String(length=512), nullable=True),
        sa.Column("user_id", sa.String(length=64), nullable=True),
        sa.Column("agent_id", sa.String(length=64), nullable=True),
        sa.Column("confidence_signal", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("raw_fingerprint", json_type, nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["shadow_ai_entity_id"], ["shadow_ai_entities.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_shadow_ai_signals_tenant_surface", "shadow_ai_signals", ["tenant_id", "source_surface"])
    op.create_index("idx_shadow_ai_signals_tenant_entity", "shadow_ai_signals", ["tenant_id", "shadow_ai_entity_id"])
    op.create_index("idx_shadow_ai_signals_tenant_event", "shadow_ai_signals", ["tenant_id", "source_event_id"])
    op.create_index("idx_shadow_ai_signals_tenant_created", "shadow_ai_signals", ["tenant_id", "created_at"])

    if dialect != "sqlite":
        op.alter_column("shadow_ai_entities", "discovery_status", server_default=None)
        op.alter_column("shadow_ai_entities", "confidence_score", server_default=None)
        op.alter_column("shadow_ai_entities", "source_surfaces", server_default=None)
        op.alter_column("shadow_ai_entities", "metadata_json", server_default=None)
        op.alter_column("shadow_ai_signals", "confidence_signal", server_default=None)
        op.alter_column("shadow_ai_signals", "raw_fingerprint", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_shadow_ai_signals_tenant_created", table_name="shadow_ai_signals")
    op.drop_index("idx_shadow_ai_signals_tenant_event", table_name="shadow_ai_signals")
    op.drop_index("idx_shadow_ai_signals_tenant_entity", table_name="shadow_ai_signals")
    op.drop_index("idx_shadow_ai_signals_tenant_surface", table_name="shadow_ai_signals")
    op.drop_table("shadow_ai_signals")

    op.drop_index("idx_shadow_ai_entities_tenant_linked", table_name="shadow_ai_entities")
    op.drop_index("idx_shadow_ai_entities_tenant_last_seen", table_name="shadow_ai_entities")
    op.drop_index("idx_shadow_ai_entities_tenant_status", table_name="shadow_ai_entities")
    op.drop_table("shadow_ai_entities")
