"""add control success criteria to controls

Revision ID: 0012_control_success_criteria_engine
Revises: 0011_guardian_contract_engine
Create Date: 2026-02-24 18:05:00.000000
"""

from __future__ import annotations

import json

from alembic import op
import sqlalchemy as sa


revision = "0012_control_success_criteria_engine"
down_revision = "0011_guardian_contract_engine"
branch_labels = None
depends_on = None


_SUCCESS_CRITERIA = {
    "required_sim_pass_rate": 0.8,
    "required_evidence_sources": ["telemetry", "simulation", "config"],
    "min_maturity": 3,
}


def upgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.add_column("controls", sa.Column("success_criteria", sa.JSON(), nullable=True))
    if dialect == "postgresql":
        op.execute(
            sa.text(
                "UPDATE controls "
                "SET success_criteria = CAST(:success_criteria AS JSON) "
                "WHERE success_criteria IS NULL"
            ).bindparams(
                success_criteria=json.dumps(_SUCCESS_CRITERIA, separators=(",", ":"))
            )
        )
    else:
        controls_table = sa.table("controls", sa.column("success_criteria", sa.JSON()))
        op.execute(
            controls_table.update()
            .where(controls_table.c.success_criteria.is_(None))
            .values(success_criteria=_SUCCESS_CRITERIA)
        )

    if dialect != "sqlite":
        op.alter_column("controls", "success_criteria", nullable=False)


def downgrade() -> None:
    op.drop_column("controls", "success_criteria")
