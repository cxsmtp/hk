"""add evidence conflict resolution table

Revision ID: 0013_evidence_conflict_resolution
Revises: 0012_control_success_criteria_engine
Create Date: 2026-02-24 20:10:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0013_evidence_conflict_resolution"
down_revision = "0012_control_success_criteria_engine"
branch_labels = None
depends_on = None


def _json_default_array() -> sa.TextClause:
    return sa.text("'[]'")


def upgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.create_table(
        "conflict_resolutions",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=False),
        sa.Column("control_id", sa.String(length=36), nullable=False),
        sa.Column("conflict_id", sa.String(length=36), nullable=True),
        sa.Column("chosen_evidence_id", sa.String(length=36), nullable=True),
        sa.Column("discarded_evidence_ids", sa.JSON(), nullable=False, server_default=_json_default_array()),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["control_id"], ["controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["conflict_id"], ["control_conflicts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["chosen_evidence_id"], ["evidence_nodes.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_conflict_resolution_tenant_control",
        "conflict_resolutions",
        ["tenant_id", "ai_system_id", "control_id"],
    )
    op.create_index(
        "idx_conflict_resolution_conflict",
        "conflict_resolutions",
        ["conflict_id"],
    )

    if dialect != "sqlite":
        op.alter_column("conflict_resolutions", "discarded_evidence_ids", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_conflict_resolution_conflict", table_name="conflict_resolutions")
    op.drop_index("idx_conflict_resolution_tenant_control", table_name="conflict_resolutions")
    op.drop_table("conflict_resolutions")
