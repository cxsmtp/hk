"""add scheduled job run tracking

Revision ID: 0005_scheduled_job_runs
Revises: 0004_auditor_defensibility
Create Date: 2026-02-20 00:00:03.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0005_scheduled_job_runs"
down_revision = "0004_auditor_defensibility"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scheduled_job_runs",
        sa.Column("job_name", sa.String(length=128), nullable=False),
        sa.Column("tenant_id", sa.String(length=36), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_scheduled_job_runs_job_started", "scheduled_job_runs", ["job_name", "started_at"])
    op.create_index("idx_scheduled_job_runs_tenant", "scheduled_job_runs", ["tenant_id"])


def downgrade() -> None:
    op.drop_index("idx_scheduled_job_runs_tenant", table_name="scheduled_job_runs")
    op.drop_index("idx_scheduled_job_runs_job_started", table_name="scheduled_job_runs")
    op.drop_table("scheduled_job_runs")
