"""add deterministic enforcement support fields

Revision ID: 0003_enforcement_determinism_fields
Revises: 0002_immutable_audit_evidence
Create Date: 2026-02-20 00:00:00.000001
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0003_enforcement_determinism_fields"
down_revision = "0002_immutable_audit_evidence"
branch_labels = None
depends_on = None
ALEMBIC_VERSION_LENGTH = 128


def _ensure_alembic_version_capacity(dialect: str) -> None:
    """Expand Alembic's default 32-character revision column before this revision is recorded."""
    if dialect != "postgresql":
        return
    op.alter_column(
        "alembic_version",
        "version_num",
        existing_type=sa.String(length=32),
        type_=sa.String(length=ALEMBIC_VERSION_LENGTH),
        existing_nullable=False,
    )


def upgrade() -> None:
    dialect = op.get_bind().dialect.name
    _ensure_alembic_version_capacity(dialect)

    op.add_column(
        "approval_requests",
        sa.Column("default_if_timeout", sa.String(length=16), nullable=False, server_default="block"),
    )
    op.execute("UPDATE approval_requests SET default_if_timeout = 'block' WHERE default_if_timeout IS NULL")
    if dialect != "sqlite":
        op.alter_column("approval_requests", "default_if_timeout", server_default=None)

    op.add_column(
        "enforcement_events",
        sa.Column("policy_version_id", sa.String(length=36), nullable=True),
    )
    op.create_index("idx_enforcement_policy_version", "enforcement_events", ["policy_version_id"])

    if dialect != "sqlite":
        op.create_foreign_key(
            "fk_enforcement_events_policy_version_id",
            "enforcement_events",
            "policy_versions",
            ["policy_version_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect != "sqlite":
        op.drop_constraint("fk_enforcement_events_policy_version_id", "enforcement_events", type_="foreignkey")

    op.drop_index("idx_enforcement_policy_version", table_name="enforcement_events")
    op.drop_column("enforcement_events", "policy_version_id")

    op.drop_column("approval_requests", "default_if_timeout")
