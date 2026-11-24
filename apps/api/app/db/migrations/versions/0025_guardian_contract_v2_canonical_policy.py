"""Add canonical policy payload to guardian_contract_v2

Revision ID: 0025_guardian_contract_v2_canonical_policy
Revises: 0024_ai_iam_agent_action_control
Create Date: 2026-03-23 18:30:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = "0025_guardian_contract_v2_canonical_policy"
down_revision = "0024_ai_iam_agent_action_control"
branch_labels = None
depends_on = None


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    inspector = inspect(op.get_bind())
    existing_columns = {row["name"] for row in inspector.get_columns("guardian_contract_v2")}
    if "canonical_policy" not in existing_columns:
        op.add_column(
            "guardian_contract_v2",
            sa.Column("canonical_policy", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        )
    if dialect != "sqlite":
        op.alter_column("guardian_contract_v2", "canonical_policy", server_default=None)


def downgrade() -> None:
    op.drop_column("guardian_contract_v2", "canonical_policy")
