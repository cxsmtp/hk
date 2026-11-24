"""add remediation actions and finding remediation linkage

Revision ID: 0028_remediation_actions
Revises: 0027_runtime_patterns_behavior_engine
Create Date: 2026-03-28 20:40:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0028_remediation_actions"
down_revision = "0027_runtime_patterns_behavior_engine"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def _bool_false_server_default() -> sa.TextClause:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        return sa.text("0")
    return sa.false()


def _has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def _has_column(inspector, table_name: str, column_name: str) -> bool:
    return column_name in {item.get("name") for item in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    json_type = _json_type()

    if "remediation_actions" not in table_names:
        op.create_table(
            "remediation_actions",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("remediation_type", sa.String(length=64), nullable=False),
            sa.Column("target_type", sa.String(length=32), nullable=False),
            sa.Column("target_id", sa.String(length=128), nullable=False),
            sa.Column("source_trigger_type", sa.String(length=64), nullable=False),
            sa.Column("source_trigger_id", sa.String(length=64), nullable=False),
            sa.Column("recommendation_text", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("action_mode", sa.String(length=32), nullable=False, server_default=sa.text("'recommend_only'")),
            sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'proposed'")),
            sa.Column("risk_level", sa.String(length=16), nullable=False, server_default=sa.text("'medium'")),
            sa.Column("requires_approval", sa.Boolean(), nullable=False, server_default=_bool_false_server_default()),
            sa.Column("approved_by", sa.String(length=36), nullable=True),
            sa.Column("justification", sa.Text(), nullable=True),
            sa.Column("rollback_supported", sa.Boolean(), nullable=False, server_default=_bool_false_server_default()),
            sa.Column("rollback_payload", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["approved_by"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_remediation_tenant_status", "remediation_actions", ["tenant_id", "status"])
        op.create_index("idx_remediation_tenant_trigger", "remediation_actions", ["tenant_id", "source_trigger_type"])
        op.create_index("idx_remediation_tenant_target", "remediation_actions", ["tenant_id", "target_type", "target_id"])
        op.create_index("idx_remediation_tenant_risk", "remediation_actions", ["tenant_id", "risk_level"])

        if bind.dialect.name != "sqlite":
            op.alter_column("remediation_actions", "recommendation_text", server_default=None)
            op.alter_column("remediation_actions", "action_mode", server_default=None)
            op.alter_column("remediation_actions", "status", server_default=None)
            op.alter_column("remediation_actions", "risk_level", server_default=None)
            op.alter_column("remediation_actions", "requires_approval", server_default=None)
            op.alter_column("remediation_actions", "rollback_supported", server_default=None)
            op.alter_column("remediation_actions", "rollback_payload", server_default=None)

    inspector = inspect(bind)
    if "findings" in table_names and not _has_column(inspector, "findings", "remediation_action_ids"):
        op.add_column(
            "findings",
            sa.Column("remediation_action_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
        )
        if bind.dialect.name != "sqlite":
            op.alter_column("findings", "remediation_action_ids", server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "findings" in table_names and _has_column(inspector, "findings", "remediation_action_ids"):
        op.drop_column("findings", "remediation_action_ids")

    if "remediation_actions" not in table_names:
        return

    inspector = inspect(bind)
    for index_name in (
        "idx_remediation_tenant_risk",
        "idx_remediation_tenant_target",
        "idx_remediation_tenant_trigger",
        "idx_remediation_tenant_status",
    ):
        if _has_index(inspector, "remediation_actions", index_name):
            op.drop_index(index_name, table_name="remediation_actions")
    op.drop_table("remediation_actions")
