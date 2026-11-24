"""pilot schema hardening columns for extension runtime/findings linkage

Revision ID: 0038_pilot_schema_hardening
Revises: 0037_findings_runtime_linkage
Create Date: 2026-05-18 11:20:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "0038_pilot_schema_hardening"
down_revision = "0037_findings_runtime_linkage"
branch_labels = None
depends_on = None


def _table_has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def _table_columns(inspector, table_name: str) -> set[str]:
    return {col["name"] for col in inspector.get_columns(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "findings" in table_names:
        finding_columns = _table_columns(inspector, "findings")
        if "user_email" not in finding_columns:
            op.add_column("findings", sa.Column("user_email", sa.String(length=320), nullable=True))
        if "browser_type" not in finding_columns:
            op.add_column("findings", sa.Column("browser_type", sa.String(length=32), nullable=True))
        if "application" not in finding_columns:
            op.add_column("findings", sa.Column("application", sa.String(length=255), nullable=True))
        if "decision" not in finding_columns:
            op.add_column("findings", sa.Column("decision", sa.String(length=32), nullable=True))
        if "policy_id" not in finding_columns:
            op.add_column("findings", sa.Column("policy_id", sa.String(length=64), nullable=True))
        if "evidence_status" not in finding_columns:
            op.add_column(
                "findings",
                sa.Column("evidence_status", sa.String(length=16), nullable=False, server_default="complete"),
            )
        if "related_runtime_event_id" not in finding_columns:
            op.add_column("findings", sa.Column("related_runtime_event_id", sa.String(length=64), nullable=True))

    if "runtime_events" in table_names:
        runtime_columns = _table_columns(inspector, "runtime_events")
        if "machine_id" not in runtime_columns:
            op.add_column("runtime_events", sa.Column("machine_id", sa.String(length=128), nullable=True))
        if "browser_type" not in runtime_columns:
            op.add_column("runtime_events", sa.Column("browser_type", sa.String(length=32), nullable=True))
        if "application" not in runtime_columns:
            op.add_column("runtime_events", sa.Column("application", sa.String(length=255), nullable=True))
        if "decision" not in runtime_columns:
            op.add_column("runtime_events", sa.Column("decision", sa.String(length=32), nullable=True))

    inspector = inspect(bind)
    if "findings" in set(inspector.get_table_names()) and not _table_has_index(inspector, "findings", "idx_findings_tenant_decision"):
        op.create_index("idx_findings_tenant_decision", "findings", ["tenant_id", "decision"])
    if "runtime_events" in set(inspector.get_table_names()) and not _table_has_index(
        inspector,
        "runtime_events",
        "idx_runtime_events_tenant_decision",
    ):
        op.create_index("idx_runtime_events_tenant_decision", "runtime_events", ["tenant_id", "decision"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())

    if "runtime_events" in table_names and _table_has_index(inspector, "runtime_events", "idx_runtime_events_tenant_decision"):
        op.drop_index("idx_runtime_events_tenant_decision", table_name="runtime_events")
    if "findings" in table_names and _table_has_index(inspector, "findings", "idx_findings_tenant_decision"):
        op.drop_index("idx_findings_tenant_decision", table_name="findings")

    inspector = inspect(bind)
    if "runtime_events" in table_names:
        runtime_columns = _table_columns(inspector, "runtime_events")
        for column_name in ("decision", "application", "browser_type", "machine_id"):
            if column_name in runtime_columns:
                op.drop_column("runtime_events", column_name)

    inspector = inspect(bind)
    if "findings" in table_names:
        finding_columns = _table_columns(inspector, "findings")
        for column_name in (
            "related_runtime_event_id",
            "evidence_status",
            "policy_id",
            "decision",
            "application",
            "browser_type",
            "user_email",
        ):
            if column_name in finding_columns:
                op.drop_column("findings", column_name)
