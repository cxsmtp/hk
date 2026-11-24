"""extend findings linkage with runtime identity context

Revision ID: 0037_findings_runtime_linkage
Revises: 0036_external_risk_intel
Create Date: 2026-04-17 14:10:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy import inspect


revision = "0037_findings_runtime_linkage"
down_revision = "0036_external_risk_intel"
branch_labels = None
depends_on = None


def _table_has_index(inspector, table_name: str, index_name: str) -> bool:
    return index_name in {item.get("name") for item in inspector.get_indexes(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "findings" not in table_names:
        return

    columns = {col["name"] for col in inspector.get_columns("findings")}

    if "agent_id" not in columns:
        op.add_column("findings", sa.Column("agent_id", sa.String(length=64), nullable=True))
    if "machine_id" not in columns:
        op.add_column("findings", sa.Column("machine_id", sa.String(length=128), nullable=True))
    if "related_event_ids" not in columns:
        op.add_column("findings", sa.Column("related_event_ids", sa.JSON(), nullable=False, server_default=sa.text("'[]'")))

    inspector = inspect(bind)
    if not _table_has_index(inspector, "findings", "idx_findings_tenant_agent"):
        op.create_index("idx_findings_tenant_agent", "findings", ["tenant_id", "agent_id"])
    if not _table_has_index(inspector, "findings", "idx_findings_tenant_machine"):
        op.create_index("idx_findings_tenant_machine", "findings", ["tenant_id", "machine_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    table_names = set(inspector.get_table_names())
    if "findings" not in table_names:
        return

    for index_name in ["idx_findings_tenant_machine", "idx_findings_tenant_agent"]:
        if _table_has_index(inspector, "findings", index_name):
            op.drop_index(index_name, table_name="findings")

    columns = {col["name"] for col in inspector.get_columns("findings")}
    if "related_event_ids" in columns:
        op.drop_column("findings", "related_event_ids")
    if "machine_id" in columns:
        op.drop_column("findings", "machine_id")
    if "agent_id" in columns:
        op.drop_column("findings", "agent_id")

