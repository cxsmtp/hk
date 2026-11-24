"""add user/device/session/action audit trail tables

Revision ID: 0029_user_device_session_audit_trail
Revises: 0028_remediation_actions
Create Date: 2026-03-31 10:30:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0029_user_device_session_audit_trail"
down_revision = "0028_remediation_actions"
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


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    json_type = _json_type()

    if "user_registry" not in table_names:
        op.create_table(
            "user_registry",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=False),
            sa.Column("display_name", sa.String(length=255), nullable=False, server_default=sa.text("''")),
            sa.Column("email", sa.String(length=320), nullable=False, server_default=sa.text("''")),
            sa.Column("department", sa.String(length=128), nullable=True),
            sa.Column("role", sa.String(length=64), nullable=True),
            sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'active'")),
            sa.Column("risk_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            sa.Column("violation_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("deployment_surfaces", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "user_id", name="uq_user_registry_tenant_user"),
        )
        op.create_index("idx_user_registry_tenant_email", "user_registry", ["tenant_id", "email"])
        op.create_index("idx_user_registry_tenant_last_seen", "user_registry", ["tenant_id", "last_seen_at"])
        op.create_index("idx_user_registry_tenant_risk", "user_registry", ["tenant_id", "risk_score"])

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "deployment_endpoints" not in table_names:
        op.create_table(
            "deployment_endpoints",
            sa.Column("endpoint_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("hostname", sa.String(length=255), nullable=True),
            sa.Column("device_type", sa.String(length=32), nullable=True),
            sa.Column("os_type", sa.String(length=32), nullable=True),
            sa.Column("os_version", sa.String(length=64), nullable=True),
            sa.Column("browser_type", sa.String(length=32), nullable=True),
            sa.Column("browser_version", sa.String(length=64), nullable=True),
            sa.Column("extension_version", sa.String(length=64), nullable=True),
            sa.Column("ip_address", sa.String(length=64), nullable=True),
            sa.Column("location", sa.String(length=255), nullable=True),
            sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'active'")),
            sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("endpoint_id"),
        )
        op.create_index("idx_deployment_endpoints_tenant_user", "deployment_endpoints", ["tenant_id", "user_id"])
        op.create_index("idx_deployment_endpoints_tenant_last_seen", "deployment_endpoints", ["tenant_id", "last_seen_at"])
        op.create_index("idx_deployment_endpoints_tenant_browser", "deployment_endpoints", ["tenant_id", "browser_type"])

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_sessions" not in table_names:
        op.create_table(
            "ai_sessions",
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("endpoint_id", sa.String(length=64), nullable=True),
            sa.Column("source_surface", sa.String(length=32), nullable=False, server_default=sa.text("'browser'")),
            sa.Column("ai_app", sa.String(length=255), nullable=True),
            sa.Column("ai_model", sa.String(length=255), nullable=True),
            sa.Column("start_time", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("end_time", sa.DateTime(timezone=True), nullable=True),
            sa.Column("total_actions", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("risk_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            sa.Column("status", sa.String(length=32), nullable=False, server_default=sa.text("'active'")),
            sa.Column("correlation_id", sa.String(length=64), nullable=True),
            sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["endpoint_id"], ["deployment_endpoints.endpoint_id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("session_id"),
        )
        op.create_index("idx_ai_sessions_tenant_user", "ai_sessions", ["tenant_id", "user_id"])
        op.create_index("idx_ai_sessions_tenant_endpoint", "ai_sessions", ["tenant_id", "endpoint_id"])
        op.create_index("idx_ai_sessions_tenant_start", "ai_sessions", ["tenant_id", "start_time"])
        op.create_index("idx_ai_sessions_tenant_correlation", "ai_sessions", ["tenant_id", "correlation_id"])

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_actions" not in table_names:
        op.create_table(
            "ai_actions",
            sa.Column("action_id", sa.String(length=64), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=False),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("endpoint_id", sa.String(length=64), nullable=True),
            sa.Column("runtime_event_id", sa.String(length=36), nullable=True),
            sa.Column("monitoring_signal_id", sa.String(length=36), nullable=True),
            sa.Column("audit_log_id", sa.String(length=36), nullable=True),
            sa.Column("evidence_node_id", sa.String(length=36), nullable=True),
            sa.Column("finding_id", sa.String(length=36), nullable=True),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("action_type", sa.String(length=64), nullable=False),
            sa.Column("ai_app", sa.String(length=255), nullable=True),
            sa.Column("ai_model", sa.String(length=255), nullable=True),
            sa.Column("data_classification", sa.String(length=32), nullable=True),
            sa.Column("sensitivity_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            sa.Column("policy_triggered", sa.String(length=255), nullable=True),
            sa.Column("enforcement_action", sa.String(length=32), nullable=False, server_default=sa.text("'allowed'")),
            sa.Column("semantic_drift_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            sa.Column("risk_score", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            sa.Column("correlation_id", sa.String(length=64), nullable=True),
            sa.Column("metadata_json", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["session_id"], ["ai_sessions.session_id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["endpoint_id"], ["deployment_endpoints.endpoint_id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["runtime_event_id"], ["runtime_events.event_id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["monitoring_signal_id"], ["monitoring_signals.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["audit_log_id"], ["audit_logs.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["evidence_node_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.finding_id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("action_id"),
        )
        op.create_index("idx_ai_actions_tenant_user_time", "ai_actions", ["tenant_id", "user_id", "timestamp"])
        op.create_index("idx_ai_actions_tenant_endpoint_time", "ai_actions", ["tenant_id", "endpoint_id", "timestamp"])
        op.create_index("idx_ai_actions_tenant_session_time", "ai_actions", ["tenant_id", "session_id", "timestamp"])
        op.create_index("idx_ai_actions_tenant_enforcement", "ai_actions", ["tenant_id", "enforcement_action"])
        op.create_index("idx_ai_actions_tenant_action_type", "ai_actions", ["tenant_id", "action_type"])
        op.create_index("idx_ai_actions_tenant_correlation", "ai_actions", ["tenant_id", "correlation_id"])

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "prompt_payloads" not in table_names:
        op.create_table(
            "prompt_payloads",
            sa.Column("action_id", sa.String(length=64), nullable=False),
            sa.Column("raw_prompt", sa.Text(), nullable=True),
            sa.Column("redacted_prompt", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("pii_detected", sa.Boolean(), nullable=False, server_default=_bool_false_server_default()),
            sa.Column("sensitive_entities", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("storage_mode", sa.String(length=32), nullable=False, server_default=sa.text("'redacted'")),
            sa.Column("prompt_hash", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["action_id"], ["ai_actions.action_id"], ondelete="CASCADE"),
            sa.PrimaryKeyConstraint("action_id"),
        )

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_action_alerts" not in table_names:
        op.create_table(
            "ai_action_alerts",
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("action_id", sa.String(length=64), nullable=False),
            sa.Column("session_id", sa.String(length=64), nullable=True),
            sa.Column("user_id", sa.String(length=36), nullable=True),
            sa.Column("endpoint_id", sa.String(length=64), nullable=True),
            sa.Column("finding_id", sa.String(length=36), nullable=True),
            sa.Column("alert_type", sa.String(length=128), nullable=False),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default=sa.text("'med'")),
            sa.Column("policy_reason", sa.Text(), nullable=True),
            sa.Column("enforcement_action", sa.String(length=32), nullable=False, server_default=sa.text("'warned'")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["action_id"], ["ai_actions.action_id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["session_id"], ["ai_sessions.session_id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["endpoint_id"], ["deployment_endpoints.endpoint_id"], ondelete="SET NULL"),
            sa.ForeignKeyConstraint(["finding_id"], ["findings.finding_id"], ondelete="SET NULL"),
            sa.PrimaryKeyConstraint("id"),
        )
        op.create_index("idx_ai_action_alerts_tenant_user", "ai_action_alerts", ["tenant_id", "user_id"])
        op.create_index("idx_ai_action_alerts_tenant_endpoint", "ai_action_alerts", ["tenant_id", "endpoint_id"])
        op.create_index("idx_ai_action_alerts_tenant_session", "ai_action_alerts", ["tenant_id", "session_id"])
        op.create_index("idx_ai_action_alerts_tenant_severity", "ai_action_alerts", ["tenant_id", "severity"])

    # Remove server defaults for non-sqlite (keeps parity with existing migration style).
    if bind.dialect.name != "sqlite":
        inspector = inspect(bind)
        table_names = set(inspector.get_table_names())
        if "user_registry" in table_names:
            for column in ("display_name", "email", "status", "risk_score", "violation_count", "deployment_surfaces"):
                op.alter_column("user_registry", column, server_default=None)
        if "deployment_endpoints" in table_names:
            for column in ("status", "metadata_json"):
                op.alter_column("deployment_endpoints", column, server_default=None)
        if "ai_sessions" in table_names:
            for column in ("source_surface", "total_actions", "risk_score", "status", "metadata_json"):
                op.alter_column("ai_sessions", column, server_default=None)
        if "ai_actions" in table_names:
            for column in ("sensitivity_score", "enforcement_action", "semantic_drift_score", "risk_score", "metadata_json"):
                op.alter_column("ai_actions", column, server_default=None)
        if "prompt_payloads" in table_names:
            for column in ("redacted_prompt", "pii_detected", "sensitive_entities", "storage_mode"):
                op.alter_column("prompt_payloads", column, server_default=None)
        if "ai_action_alerts" in table_names:
            for column in ("severity", "enforcement_action"):
                op.alter_column("ai_action_alerts", column, server_default=None)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "ai_action_alerts" in table_names:
        for index_name in (
            "idx_ai_action_alerts_tenant_severity",
            "idx_ai_action_alerts_tenant_session",
            "idx_ai_action_alerts_tenant_endpoint",
            "idx_ai_action_alerts_tenant_user",
        ):
            if _has_index(inspector, "ai_action_alerts", index_name):
                op.drop_index(index_name, table_name="ai_action_alerts")
        op.drop_table("ai_action_alerts")

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "prompt_payloads" in table_names:
        op.drop_table("prompt_payloads")

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_actions" in table_names:
        for index_name in (
            "idx_ai_actions_tenant_correlation",
            "idx_ai_actions_tenant_action_type",
            "idx_ai_actions_tenant_enforcement",
            "idx_ai_actions_tenant_session_time",
            "idx_ai_actions_tenant_endpoint_time",
            "idx_ai_actions_tenant_user_time",
        ):
            if _has_index(inspector, "ai_actions", index_name):
                op.drop_index(index_name, table_name="ai_actions")
        op.drop_table("ai_actions")

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "ai_sessions" in table_names:
        for index_name in (
            "idx_ai_sessions_tenant_correlation",
            "idx_ai_sessions_tenant_start",
            "idx_ai_sessions_tenant_endpoint",
            "idx_ai_sessions_tenant_user",
        ):
            if _has_index(inspector, "ai_sessions", index_name):
                op.drop_index(index_name, table_name="ai_sessions")
        op.drop_table("ai_sessions")

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "deployment_endpoints" in table_names:
        for index_name in (
            "idx_deployment_endpoints_tenant_browser",
            "idx_deployment_endpoints_tenant_last_seen",
            "idx_deployment_endpoints_tenant_user",
        ):
            if _has_index(inspector, "deployment_endpoints", index_name):
                op.drop_index(index_name, table_name="deployment_endpoints")
        op.drop_table("deployment_endpoints")

    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "user_registry" in table_names:
        for index_name in (
            "idx_user_registry_tenant_risk",
            "idx_user_registry_tenant_last_seen",
            "idx_user_registry_tenant_email",
        ):
            if _has_index(inspector, "user_registry", index_name):
                op.drop_index(index_name, table_name="user_registry")
        op.drop_table("user_registry")
