"""phase e auditor defensibility fields and immutability

Revision ID: 0004_auditor_defensibility
Revises: 0003_enforcement_determinism_fields
Create Date: 2026-02-20 00:00:02.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0004_auditor_defensibility"
down_revision = "0003_enforcement_determinism_fields"
branch_labels = None
depends_on = None


def _json_default_object() -> sa.TextClause:
    return sa.text("'{}'")


def _json_default_array() -> sa.TextClause:
    return sa.text("'[]'")


def _upgrade_snapshot_immutability(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_auditor_snapshots_immutable ON auditor_snapshots;")
        op.execute(
            """
            CREATE TRIGGER trg_auditor_snapshots_immutable
            BEFORE UPDATE OR DELETE ON auditor_snapshots
            FOR EACH ROW
            EXECUTE FUNCTION deny_immutable_table_mutation();
            """
        )
        return

    if dialect == "sqlite":
        op.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_auditor_snapshots_immutable_update
            BEFORE UPDATE ON auditor_snapshots
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'immutable_table:auditor_snapshots');
            END;
            """
        )
        op.execute(
            """
            CREATE TRIGGER IF NOT EXISTS trg_auditor_snapshots_immutable_delete
            BEFORE DELETE ON auditor_snapshots
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'immutable_table:auditor_snapshots');
            END;
            """
        )
        return

    raise RuntimeError(f"Unsupported dialect for snapshot immutability migration: {dialect}")


def _downgrade_snapshot_immutability(dialect: str) -> None:
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_auditor_snapshots_immutable ON auditor_snapshots;")
        return

    if dialect == "sqlite":
        op.execute("DROP TRIGGER IF EXISTS trg_auditor_snapshots_immutable_update;")
        op.execute("DROP TRIGGER IF EXISTS trg_auditor_snapshots_immutable_delete;")
        return

    raise RuntimeError(f"Unsupported dialect for snapshot immutability migration: {dialect}")


def upgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.add_column(
        "control_maturity",
        sa.Column("status", sa.String(length=32), nullable=False, server_default="needs_review"),
    )
    op.add_column(
        "control_maturity",
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "control_maturity",
        sa.Column("confidence_inputs", sa.JSON(), nullable=False, server_default=_json_default_object()),
    )
    op.execute("UPDATE control_maturity SET status = 'needs_review' WHERE status IS NULL")
    op.execute("UPDATE control_maturity SET confidence_score = 0.0 WHERE confidence_score IS NULL")
    op.execute("UPDATE control_maturity SET confidence_inputs = '{}' WHERE confidence_inputs IS NULL")

    op.add_column(
        "control_maturity_history",
        sa.Column("status", sa.String(length=32), nullable=False, server_default="needs_review"),
    )
    op.add_column(
        "control_maturity_history",
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="0"),
    )
    op.add_column(
        "control_maturity_history",
        sa.Column("confidence_inputs", sa.JSON(), nullable=False, server_default=_json_default_object()),
    )
    op.execute("UPDATE control_maturity_history SET status = 'needs_review' WHERE status IS NULL")
    op.execute("UPDATE control_maturity_history SET confidence_score = 0.0 WHERE confidence_score IS NULL")
    op.execute("UPDATE control_maturity_history SET confidence_inputs = '{}' WHERE confidence_inputs IS NULL")

    if dialect != "sqlite":
        op.alter_column("control_maturity", "status", server_default=None)
        op.alter_column("control_maturity", "confidence_score", server_default=None)
        op.alter_column("control_maturity", "confidence_inputs", server_default=None)
        op.alter_column("control_maturity_history", "status", server_default=None)
        op.alter_column("control_maturity_history", "confidence_score", server_default=None)
        op.alter_column("control_maturity_history", "confidence_inputs", server_default=None)

    op.create_table(
        "control_conflicts",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("ai_system_id", sa.String(length=36), nullable=False),
        sa.Column("control_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="open"),
        sa.Column("reason", sa.String(length=255), nullable=False, server_default="contradictory_evidence"),
        sa.Column("positive_signals", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("negative_signals", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("latest_signal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("evidence_node_ids", sa.JSON(), nullable=False, server_default=_json_default_array()),
        sa.Column("details", sa.JSON(), nullable=False, server_default=_json_default_object()),
        sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=36), nullable=True),
        sa.Column("resolution_decision", sa.String(length=32), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("audit_log_id", sa.String(length=36), nullable=True),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["ai_system_id"], ["ai_systems.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["audit_log_id"], ["audit_logs.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["control_id"], ["controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["resolved_by"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_control_conflicts_tenant_status", "control_conflicts", ["tenant_id", "status"])
    op.create_index("idx_control_conflicts_control", "control_conflicts", ["tenant_id", "ai_system_id", "control_id"])

    if dialect != "sqlite":
        op.alter_column("control_conflicts", "status", server_default=None)
        op.alter_column("control_conflicts", "reason", server_default=None)
        op.alter_column("control_conflicts", "positive_signals", server_default=None)
        op.alter_column("control_conflicts", "negative_signals", server_default=None)
        op.alter_column("control_conflicts", "evidence_node_ids", server_default=None)
        op.alter_column("control_conflicts", "details", server_default=None)
        op.alter_column("control_conflicts", "resolution_notes", server_default=None)

    op.add_column(
        "auditor_snapshots",
        sa.Column("artifact_hash", sa.String(length=64), nullable=False, server_default=""),
    )
    op.execute("UPDATE auditor_snapshots SET artifact_hash = '' WHERE artifact_hash IS NULL")
    if dialect != "sqlite":
        op.alter_column("auditor_snapshots", "artifact_hash", server_default=None)

    _upgrade_snapshot_immutability(dialect)


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    _downgrade_snapshot_immutability(dialect)

    op.drop_column("auditor_snapshots", "artifact_hash")

    op.drop_index("idx_control_conflicts_control", table_name="control_conflicts")
    op.drop_index("idx_control_conflicts_tenant_status", table_name="control_conflicts")
    op.drop_table("control_conflicts")

    op.drop_column("control_maturity_history", "confidence_inputs")
    op.drop_column("control_maturity_history", "confidence_score")
    op.drop_column("control_maturity_history", "status")

    op.drop_column("control_maturity", "confidence_inputs")
    op.drop_column("control_maturity", "confidence_score")
    op.drop_column("control_maturity", "status")
