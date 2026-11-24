"""add correlation_id fields for observability

Revision ID: 0006_observability_correlation
Revises: 0005_scheduled_job_runs
Create Date: 2026-02-20 00:00:04.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0006_observability_correlation"
down_revision = "0005_scheduled_job_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("correlation_id", sa.String(length=64), nullable=True))
    op.create_index("ix_audit_logs_correlation_id", "audit_logs", ["correlation_id"])

    op.add_column("evidence_nodes", sa.Column("correlation_id", sa.String(length=64), nullable=True))
    op.create_index("idx_evidence_node_correlation", "evidence_nodes", ["correlation_id"])

    op.add_column("enforcement_events", sa.Column("correlation_id", sa.String(length=64), nullable=True))
    op.create_index("idx_enforcement_correlation", "enforcement_events", ["correlation_id"])

    op.add_column("simulation_runs", sa.Column("correlation_id", sa.String(length=64), nullable=True))
    op.create_index("idx_sim_run_correlation", "simulation_runs", ["correlation_id"])


def downgrade() -> None:
    op.drop_index("idx_sim_run_correlation", table_name="simulation_runs")
    op.drop_column("simulation_runs", "correlation_id")

    op.drop_index("idx_enforcement_correlation", table_name="enforcement_events")
    op.drop_column("enforcement_events", "correlation_id")

    op.drop_index("idx_evidence_node_correlation", table_name="evidence_nodes")
    op.drop_column("evidence_nodes", "correlation_id")

    op.drop_index("ix_audit_logs_correlation_id", table_name="audit_logs")
    op.drop_column("audit_logs", "correlation_id")
