"""add shadow ai usage tracking and scan results

Revision ID: 0030_shadow_scan_engine
Revises: 0029_user_device_session_audit_trail
Create Date: 2026-04-01 10:40:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0030_shadow_scan_engine"
down_revision = "0029_user_device_session_audit_trail"
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


def _table_has_column(inspector, table_name: str, column_name: str) -> bool:
    return column_name in {column.get("name") for column in inspector.get_columns(table_name)}


def _table_has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    json_type = _json_type()

    if "scan_results" not in table_names:
        op.create_table(
            "scan_results",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("scan_id", sa.String(length=64), nullable=False),
            sa.Column("scan_type", sa.String(length=32), nullable=False, server_default=sa.text("'discovery'")),
            sa.Column("triggered_by", sa.String(length=36), nullable=True),
            sa.Column("scope", sa.String(length=64), nullable=False, server_default=sa.text("'global'")),
            sa.Column("parameters_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("start_time", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("end_time", sa.DateTime(timezone=True), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'running'")),
            sa.Column("summary_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("delta_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("snapshot_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["triggered_by"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "scan_id", name="uq_scan_results_tenant_scan"),
        )
        op.create_index("idx_scan_results_tenant_status", "scan_results", ["tenant_id", "status"])
        op.create_index("idx_scan_results_tenant_type", "scan_results", ["tenant_id", "scan_type"])
        op.create_index("idx_scan_results_tenant_start", "scan_results", ["tenant_id", "start_time"])
        op.create_index("idx_scan_results_tenant_scope", "scan_results", ["tenant_id", "scope"])

    inspector = inspect(bind)
    if "shadow_ai_usage" not in set(inspector.get_table_names()):
        op.create_table(
            "shadow_ai_usage",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("asset_id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("endpoint_id", sa.String(length=64), nullable=True),
            sa.Column("session_id", sa.String(length=64), nullable=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("interaction_type", sa.String(length=32), nullable=False, server_default=sa.text("'browse'")),
            sa.Column("sensitivity_detected", sa.Boolean(), nullable=False, server_default=_bool_false_server_default()),
            sa.Column("policy_triggered", sa.String(length=255), nullable=True),
            sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["asset_id"], ["shadow_ai_entities.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["endpoint_id"], ["deployment_endpoints.endpoint_id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["session_id"], ["ai_sessions.session_id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_shadow_ai_usage_tenant_asset", "shadow_ai_usage", ["tenant_id", "asset_id"])
        op.create_index("idx_shadow_ai_usage_tenant_user", "shadow_ai_usage", ["tenant_id", "user_id"])
        op.create_index("idx_shadow_ai_usage_tenant_endpoint", "shadow_ai_usage", ["tenant_id", "endpoint_id"])
        op.create_index("idx_shadow_ai_usage_tenant_session", "shadow_ai_usage", ["tenant_id", "session_id"])
        op.create_index("idx_shadow_ai_usage_tenant_time", "shadow_ai_usage", ["tenant_id", "timestamp"])

    inspector = inspect(bind)
    if "shadow_ai_entities" in set(inspector.get_table_names()):
        if not _table_has_column(inspector, "shadow_ai_entities", "approved_status"):
            op.add_column(
                "shadow_ai_entities",
                sa.Column("approved_status", sa.String(length=32), nullable=False, server_default=sa.text("'unknown'")),
            )
        if not _table_has_column(inspector, "shadow_ai_entities", "risk_score"):
            op.add_column(
                "shadow_ai_entities",
                sa.Column("risk_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            )
        if not _table_has_column(inspector, "shadow_ai_entities", "usage_count"):
            op.add_column(
                "shadow_ai_entities",
                sa.Column("usage_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            )
        if not _table_has_column(inspector, "shadow_ai_entities", "unique_users"):
            op.add_column(
                "shadow_ai_entities",
                sa.Column("unique_users", sa.Integer(), nullable=False, server_default=sa.text("0")),
            )
        if not _table_has_column(inspector, "shadow_ai_entities", "endpoints_count"):
            op.add_column(
                "shadow_ai_entities",
                sa.Column("endpoints_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "shadow_ai_entities" in table_names:
        columns = {column.get("name") for column in inspector.get_columns("shadow_ai_entities")}
        if "endpoints_count" in columns:
            op.drop_column("shadow_ai_entities", "endpoints_count")
        if "unique_users" in columns:
            op.drop_column("shadow_ai_entities", "unique_users")
        if "usage_count" in columns:
            op.drop_column("shadow_ai_entities", "usage_count")
        if "risk_score" in columns:
            op.drop_column("shadow_ai_entities", "risk_score")
        if "approved_status" in columns:
            op.drop_column("shadow_ai_entities", "approved_status")

    if "shadow_ai_usage" in table_names:
        for index_name in [
            "idx_shadow_ai_usage_tenant_time",
            "idx_shadow_ai_usage_tenant_session",
            "idx_shadow_ai_usage_tenant_endpoint",
            "idx_shadow_ai_usage_tenant_user",
            "idx_shadow_ai_usage_tenant_asset",
        ]:
            if _table_has_index(inspector, "shadow_ai_usage", index_name):
                op.drop_index(index_name, table_name="shadow_ai_usage")
        op.drop_table("shadow_ai_usage")

    if "scan_results" in table_names:
        for index_name in [
            "idx_scan_results_tenant_scope",
            "idx_scan_results_tenant_start",
            "idx_scan_results_tenant_type",
            "idx_scan_results_tenant_status",
        ]:
            if _table_has_index(inspector, "scan_results", index_name):
                op.drop_index(index_name, table_name="scan_results")
        op.drop_table("scan_results")
