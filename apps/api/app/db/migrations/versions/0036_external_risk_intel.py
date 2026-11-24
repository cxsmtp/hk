"""add external risk intelligence ingestion and correlation tables

Revision ID: 0036_external_risk_intel
Revises: 0035_simulation_policy_executor_catalog
Create Date: 2026-04-03 18:20:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect
from sqlalchemy.dialects import postgresql


revision = "0036_external_risk_intel"
down_revision = "0035_simulation_policy_executor_catalog"
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

    if "external_risk_sources" not in table_names:
        op.create_table(
            "external_risk_sources",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("source", sa.String(length=64), nullable=False),
            sa.Column("display_name", sa.String(length=128), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("endpoint_url", sa.String(length=1024), nullable=False),
            sa.Column("auth_mode", sa.String(length=32), nullable=False, server_default=sa.text("'none'")),
            sa.Column("auth_config", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("source_trust_policy", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("egress_policy", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("redaction_policy", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("routing_policy", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("transport_policy", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("sync_schedule", sa.String(length=64), nullable=False, server_default=sa.text("'0 * * * *'")),
            sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_sync_status", sa.String(length=24), nullable=False, server_default=sa.text("'never'")),
            sa.Column("last_sync_error", sa.Text(), nullable=True),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "source", name="uq_external_risk_source_tenant_source"),
        )

    if "external_risk_sync_runs" not in table_names:
        op.create_table(
            "external_risk_sync_runs",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("source_id", sa.String(length=36), sa.ForeignKey("external_risk_sources.id", ondelete="SET NULL"), nullable=True),
            sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'running'")),
            sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("records_ingested", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("mappings_created", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("alerts_created", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("simulation_recommendations_created", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("transport_failures", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("error_message", sa.Text(), nullable=True),
            sa.Column("trace_payload", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.PrimaryKeyConstraint("id"),
        )

    if "external_risk_records" not in table_names:
        op.create_table(
            "external_risk_records",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("source_id", sa.String(length=36), sa.ForeignKey("external_risk_sources.id", ondelete="SET NULL"), nullable=True),
            sa.Column("source", sa.String(length=32), nullable=False),
            sa.Column("source_record_id", sa.String(length=128), nullable=False),
            sa.Column("title", sa.String(length=512), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("severity", sa.String(length=16), nullable=False, server_default=sa.text("'med'")),
            sa.Column("cvss_score", sa.Float(), nullable=True),
            sa.Column("exploit_status", sa.String(length=32), nullable=False, server_default=sa.text("'unknown'")),
            sa.Column("affected_components", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("affected_versions", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("references", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("source_updated_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("integrity_status", sa.String(length=32), nullable=False, server_default=sa.text("'partial'")),
            sa.Column("ingestion_trace_id", sa.String(length=64), nullable=True),
            sa.Column("raw_artifact_ref", sa.String(length=1024), nullable=True),
            sa.Column("raw_payload_ref", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "source", "source_record_id", name="uq_external_risk_record_tenant_source_id"),
        )

    if "external_risk_asset_mappings" not in table_names:
        op.create_table(
            "external_risk_asset_mappings",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("risk_record_id", sa.String(length=36), sa.ForeignKey("external_risk_records.id", ondelete="CASCADE"), nullable=False),
            sa.Column("asset_type", sa.String(length=64), nullable=False),
            sa.Column("asset_id", sa.String(length=128), nullable=False),
            sa.Column("environment", sa.String(length=32), nullable=False, server_default=sa.text("'unknown'")),
            sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("mapping_reason", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("control_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("simulation_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("mapping_status", sa.String(length=24), nullable=False, server_default=sa.text("'auto'")),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint(
                "tenant_id",
                "risk_record_id",
                "asset_type",
                "asset_id",
                "environment",
                name="uq_external_risk_mapping_unique",
            ),
        )

    if "external_risk_impacts" not in table_names:
        op.create_table(
            "external_risk_impacts",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("risk_record_id", sa.String(length=36), sa.ForeignKey("external_risk_records.id", ondelete="CASCADE"), nullable=False),
            sa.Column("asset_type", sa.String(length=64), nullable=False),
            sa.Column("asset_id", sa.String(length=128), nullable=False),
            sa.Column("likelihood", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("impact", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("annualized_loss_expectancy", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("residual_risk", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("rationale", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("calculation_context", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "risk_record_id", "asset_type", "asset_id", name="uq_external_risk_impact_unique"),
        )

    if "risk_triggered_simulation_recommendations" not in table_names:
        op.create_table(
            "risk_triggered_simulation_recommendations",
            sa.Column("tenant_id", sa.String(length=36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
            sa.Column("risk_record_id", sa.String(length=36), sa.ForeignKey("external_risk_records.id", ondelete="CASCADE"), nullable=False),
            sa.Column("priority", sa.String(length=16), nullable=False, server_default=sa.text("'med'")),
            sa.Column("reason", sa.Text(), nullable=False, server_default=sa.text("''")),
            sa.Column("control_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("simulation_ids", json_type, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("status", sa.String(length=24), nullable=False, server_default=sa.text("'recommended'")),
            sa.Column("run_mode", sa.String(length=24), nullable=False, server_default=sa.text("'manual'")),
            sa.Column("approval_required", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("recommendation_payload", json_type, nullable=False, server_default=sa.text("'{}'")),
            sa.Column("id", sa.String(length=36), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("tenant_id", "risk_record_id", name="uq_external_risk_simrec_unique"),
        )

    inspector = inspect(bind)

    table_indexes: dict[str, list[tuple[str, list[str]]]] = {
        "external_risk_sources": [
            ("idx_external_risk_source_tenant", ["tenant_id"]),
            ("idx_external_risk_source_tenant_enabled", ["tenant_id", "enabled"]),
        ],
        "external_risk_sync_runs": [
            ("idx_external_risk_sync_tenant", ["tenant_id"]),
            ("idx_external_risk_sync_tenant_started", ["tenant_id", "started_at"]),
        ],
        "external_risk_records": [
            ("idx_external_risk_record_tenant", ["tenant_id"]),
            ("idx_external_risk_record_tenant_severity", ["tenant_id", "severity"]),
            ("idx_external_risk_record_tenant_exploit", ["tenant_id", "exploit_status"]),
            ("idx_external_risk_record_tenant_updated", ["tenant_id", "source_updated_at"]),
        ],
        "external_risk_asset_mappings": [
            ("idx_external_risk_map_tenant", ["tenant_id"]),
            ("idx_external_risk_map_record", ["risk_record_id"]),
            ("idx_external_risk_map_asset", ["tenant_id", "asset_type", "asset_id"]),
        ],
        "external_risk_impacts": [
            ("idx_external_risk_impact_tenant", ["tenant_id"]),
            ("idx_external_risk_impact_record", ["risk_record_id"]),
            ("idx_external_risk_impact_asset", ["tenant_id", "asset_type", "asset_id"]),
        ],
        "risk_triggered_simulation_recommendations": [
            ("idx_external_risk_simrec_tenant", ["tenant_id"]),
            ("idx_external_risk_simrec_record", ["risk_record_id"]),
            ("idx_external_risk_simrec_status", ["tenant_id", "status"]),
        ],
    }

    for table_name, rows in table_indexes.items():
        if table_name not in inspector.get_table_names():
            continue
        for index_name, cols in rows:
            if not _table_has_index(inspector, table_name, index_name):
                op.create_index(index_name, table_name, cols)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    drop_order = [
        (
            "risk_triggered_simulation_recommendations",
            [
                "idx_external_risk_simrec_status",
                "idx_external_risk_simrec_record",
                "idx_external_risk_simrec_tenant",
            ],
        ),
        (
            "external_risk_impacts",
            [
                "idx_external_risk_impact_asset",
                "idx_external_risk_impact_record",
                "idx_external_risk_impact_tenant",
            ],
        ),
        (
            "external_risk_asset_mappings",
            [
                "idx_external_risk_map_asset",
                "idx_external_risk_map_record",
                "idx_external_risk_map_tenant",
            ],
        ),
        (
            "external_risk_records",
            [
                "idx_external_risk_record_tenant_updated",
                "idx_external_risk_record_tenant_exploit",
                "idx_external_risk_record_tenant_severity",
                "idx_external_risk_record_tenant",
            ],
        ),
        (
            "external_risk_sync_runs",
            [
                "idx_external_risk_sync_tenant_started",
                "idx_external_risk_sync_tenant",
            ],
        ),
        (
            "external_risk_sources",
            [
                "idx_external_risk_source_tenant_enabled",
                "idx_external_risk_source_tenant",
            ],
        ),
    ]

    for table_name, idx_names in drop_order:
        if table_name not in table_names:
            continue
        for idx in idx_names:
            if _table_has_index(inspector, table_name, idx):
                op.drop_index(idx, table_name=table_name)
        op.drop_table(table_name)
