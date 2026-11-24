"""add formal guardian contract engine tables

Revision ID: 0011_guardian_contract_engine
Revises: 0010_kb_phase0_foundations
Create Date: 2026-02-24 15:40:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0011_guardian_contract_engine"
down_revision = "0010_kb_phase0_foundations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.create_table(
        "guardian_contract",
        sa.Column("id", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("trigger_conditions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("block_conditions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("mandatory_actions", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("escalation_path", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evidence_requirements", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("framework_mappings", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "control_guardian_binding",
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("guardian_contract_id", sa.String(length=128), nullable=False),
        sa.Column("enforcement_strength", sa.String(length=16), nullable=False),
        sa.ForeignKeyConstraint(["guardian_contract_id"], ["guardian_contract.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("control_id", "guardian_contract_id"),
    )
    op.create_index("idx_control_guardian_binding_control", "control_guardian_binding", ["control_id"])
    op.create_index("idx_control_guardian_binding_guardian", "control_guardian_binding", ["guardian_contract_id"])

    op.execute("UPDATE guardian_contract SET trigger_conditions = '[]' WHERE trigger_conditions IS NULL")
    op.execute("UPDATE guardian_contract SET block_conditions = '[]' WHERE block_conditions IS NULL")
    op.execute("UPDATE guardian_contract SET mandatory_actions = '{}' WHERE mandatory_actions IS NULL")
    op.execute("UPDATE guardian_contract SET escalation_path = '{}' WHERE escalation_path IS NULL")
    op.execute("UPDATE guardian_contract SET evidence_requirements = '{}' WHERE evidence_requirements IS NULL")
    op.execute("UPDATE guardian_contract SET framework_mappings = '{}' WHERE framework_mappings IS NULL")

    if dialect != "sqlite":
        op.alter_column("guardian_contract", "trigger_conditions", server_default=None)
        op.alter_column("guardian_contract", "block_conditions", server_default=None)
        op.alter_column("guardian_contract", "mandatory_actions", server_default=None)
        op.alter_column("guardian_contract", "escalation_path", server_default=None)
        op.alter_column("guardian_contract", "evidence_requirements", server_default=None)
        op.alter_column("guardian_contract", "framework_mappings", server_default=None)


def downgrade() -> None:
    op.drop_index("idx_control_guardian_binding_guardian", table_name="control_guardian_binding")
    op.drop_index("idx_control_guardian_binding_control", table_name="control_guardian_binding")
    op.drop_table("control_guardian_binding")
    op.drop_table("guardian_contract")
