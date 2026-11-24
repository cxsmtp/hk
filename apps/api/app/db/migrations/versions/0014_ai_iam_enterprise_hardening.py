"""phase j1 ai iam enterprise hardening

Revision ID: 0014_ai_iam_enterprise_hardening
Revises: 0013_evidence_conflict_resolution
Create Date: 2026-02-24 21:20:00.000000
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0014_ai_iam_enterprise_hardening"
down_revision = "0013_evidence_conflict_resolution"
branch_labels = None
depends_on = None


def _json_default_object() -> sa.TextClause:
    return sa.text("'{}'")


def upgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.add_column("agent_identities", sa.Column("owner_attested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("agent_identities", sa.Column("owner_attestation_expiry", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "agent_identities",
        sa.Column("capability_inheritance", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    if dialect == "sqlite":
        with op.batch_alter_table("agent_identities") as batch_op:
            batch_op.alter_column(
                "max_chain_depth",
                existing_type=sa.Integer(),
                server_default="3",
                existing_nullable=False,
            )
    else:
        op.alter_column(
            "agent_identities",
            "max_chain_depth",
            existing_type=sa.Integer(),
            server_default="3",
            existing_nullable=False,
        )

    if dialect != "sqlite":
        op.alter_column("agent_identities", "capability_inheritance", server_default=None)
        op.alter_column("agent_identities", "max_chain_depth", server_default=None)

    op.create_table(
        "agent_action_baselines",
        sa.Column("tenant_id", sa.String(length=36), nullable=False),
        sa.Column("agent_identity_id", sa.String(length=36), nullable=False),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("baseline_rate_per_hour", sa.Float(), nullable=False, server_default="1"),
        sa.Column("current_window_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_anomaly_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False, server_default=_json_default_object()),
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["agent_identity_id"], ["agent_identities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "agent_identity_id", "action", name="uq_agent_action_baseline"),
    )
    op.create_index(
        "idx_agent_action_baseline_tenant_agent",
        "agent_action_baselines",
        ["tenant_id", "agent_identity_id"],
    )
    if dialect != "sqlite":
        op.alter_column("agent_action_baselines", "baseline_rate_per_hour", server_default=None)
        op.alter_column("agent_action_baselines", "current_window_count", server_default=None)
        op.alter_column("agent_action_baselines", "metadata_json", server_default=None)


def downgrade() -> None:
    dialect = op.get_bind().dialect.name

    op.drop_index("idx_agent_action_baseline_tenant_agent", table_name="agent_action_baselines")
    op.drop_table("agent_action_baselines")

    if dialect == "sqlite":
        with op.batch_alter_table("agent_identities") as batch_op:
            batch_op.alter_column(
                "max_chain_depth",
                existing_type=sa.Integer(),
                server_default="2",
                existing_nullable=False,
            )
    else:
        op.alter_column(
            "agent_identities",
            "max_chain_depth",
            existing_type=sa.Integer(),
            server_default="2",
            existing_nullable=False,
        )
    op.drop_column("agent_identities", "capability_inheritance")
    op.drop_column("agent_identities", "owner_attestation_expiry")
    op.drop_column("agent_identities", "owner_attested_at")
