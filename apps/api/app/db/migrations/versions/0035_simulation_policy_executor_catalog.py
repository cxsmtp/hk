"""add persisted simulation policy executor and catalog tables

Revision ID: 0035_simulation_policy_executor_catalog
Revises: 0034_ai_orchestration_trace_hardening
Create Date: 2026-04-03 16:10:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0035_simulation_policy_executor_catalog"
down_revision = "0034_ai_orchestration_trace_hardening"
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.JSONB()
    return sa.JSON()


def _table_has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    json_type = _json_type()

    if "simulation_policies" not in table_names:
        op.create_table(
            "simulation_policies",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(length=255), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("enabled_categories", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("enabled_surfaces", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("blocked_categories", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("minimum_severity", sa.String(length=16), nullable=False, server_default=sa.text("'low'")),
            sa.Column("require_approval_for", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("allowed_execution_modes", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("environment_scope", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("tenant_isolation_required", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("evidence_retention_days", sa.Integer(), nullable=False, server_default=sa.text("90")),
            sa.Column("max_parallel_runs", sa.Integer(), nullable=False, server_default=sa.text("2")),
            sa.Column("notify_on_fail", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("framework_filters", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("control_filters", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    if "simulation_executors" not in table_names:
        op.create_table(
            "simulation_executors",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True),
            sa.Column("is_global", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("supported_surfaces", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("supported_categories", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("supported_simulation_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'active'")),
            sa.Column("evidence_types", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("requires", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    if "simulation_catalog_entries" not in table_names:
        op.create_table(
            "simulation_catalog_entries",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("simulation_id", sa.String(length=128), nullable=False),
            sa.Column("category", sa.String(length=64), nullable=False),
            sa.Column("subcategory", sa.String(length=64), nullable=False, server_default=sa.text("''")),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default=sa.text("'med'")),
            sa.Column("control_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("framework_mappings", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("target_surface", sa.String(length=32), nullable=False, server_default=sa.text("'gateway'")),
            sa.Column("executable_status", sa.String(length=32), nullable=False, server_default=sa.text("'not_yet_executable'")),
            sa.Column("required_executor", sa.String(length=64), nullable=False, server_default=sa.text("''")),
            sa.Column("defined", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("implemented", sa.Boolean(), nullable=False, server_default=sa.false()),
            sa.Column("version", sa.String(length=32), nullable=False, server_default=sa.text("'1.0'")),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    inspector = inspect(bind)
    if "simulation_policies" in inspector.get_table_names():
        if not _table_has_index(inspector, "simulation_policies", "idx_sim_policy_tenant"):
            op.create_index("idx_sim_policy_tenant", "simulation_policies", ["tenant_id"])
        if not _table_has_index(inspector, "simulation_policies", "idx_sim_policy_tenant_active"):
            op.create_index("idx_sim_policy_tenant_active", "simulation_policies", ["tenant_id", "active"])

    if "simulation_executors" in inspector.get_table_names():
        if not _table_has_index(inspector, "simulation_executors", "idx_sim_executor_tenant"):
            op.create_index("idx_sim_executor_tenant", "simulation_executors", ["tenant_id"])
        if not _table_has_index(inspector, "simulation_executors", "idx_sim_executor_tenant_status"):
            op.create_index("idx_sim_executor_tenant_status", "simulation_executors", ["tenant_id", "status"])
        if not _table_has_index(inspector, "simulation_executors", "idx_sim_executor_name"):
            op.create_index("idx_sim_executor_name", "simulation_executors", ["name"])

    if "simulation_catalog_entries" in inspector.get_table_names():
        if not _table_has_index(inspector, "simulation_catalog_entries", "idx_sim_catalog_tenant"):
            op.create_index("idx_sim_catalog_tenant", "simulation_catalog_entries", ["tenant_id"])
        if not _table_has_index(inspector, "simulation_catalog_entries", "idx_sim_catalog_tenant_category"):
            op.create_index("idx_sim_catalog_tenant_category", "simulation_catalog_entries", ["tenant_id", "category"])
        if not _table_has_index(inspector, "simulation_catalog_entries", "idx_sim_catalog_tenant_exec_status"):
            op.create_index("idx_sim_catalog_tenant_exec_status", "simulation_catalog_entries", ["tenant_id", "executable_status"])
        if not _table_has_index(inspector, "simulation_catalog_entries", "idx_sim_catalog_tenant_simulation_id"):
            op.create_index("idx_sim_catalog_tenant_simulation_id", "simulation_catalog_entries", ["tenant_id", "simulation_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "simulation_catalog_entries" in table_names:
        for idx in [
            "idx_sim_catalog_tenant_simulation_id",
            "idx_sim_catalog_tenant_exec_status",
            "idx_sim_catalog_tenant_category",
            "idx_sim_catalog_tenant",
        ]:
            if _table_has_index(inspector, "simulation_catalog_entries", idx):
                op.drop_index(idx, table_name="simulation_catalog_entries")
        op.drop_table("simulation_catalog_entries")

    if "simulation_executors" in table_names:
        for idx in [
            "idx_sim_executor_name",
            "idx_sim_executor_tenant_status",
            "idx_sim_executor_tenant",
        ]:
            if _table_has_index(inspector, "simulation_executors", idx):
                op.drop_index(idx, table_name="simulation_executors")
        op.drop_table("simulation_executors")

    if "simulation_policies" in table_names:
        for idx in [
            "idx_sim_policy_tenant_active",
            "idx_sim_policy_tenant",
        ]:
            if _table_has_index(inspector, "simulation_policies", idx):
                op.drop_index(idx, table_name="simulation_policies")
        op.drop_table("simulation_policies")
