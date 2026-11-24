"""Allow audited resource references to retain HMAIR target identifiers.

Revision ID: 0086_expand_audit_resource_reference
Revises: 0085_hmair_production_deep_scan
"""

from alembic import op
import sqlalchemy as sa


revision = "0086_expand_audit_resource_reference"
down_revision = "0085_hmair_production_deep_scan"
branch_labels = None
depends_on = None


def _alter_resource_id_length(length: int) -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("audit_logs") as batch_op:
            batch_op.alter_column(
                "resource_id",
                existing_type=sa.String(length=36 if length == 128 else 128),
                type_=sa.String(length=length),
                existing_nullable=False,
            )
        return
    op.alter_column(
        "audit_logs",
        "resource_id",
        existing_type=sa.String(length=36 if length == 128 else 128),
        type_=sa.String(length=length),
        existing_nullable=False,
    )


def upgrade() -> None:
    _alter_resource_id_length(128)


def downgrade() -> None:
    longest_resource_id = op.get_bind().execute(
        sa.text("SELECT max(length(resource_id)) FROM audit_logs")
    ).scalar_one()
    if longest_resource_id is not None and int(longest_resource_id) > 36:
        raise RuntimeError(
            "Cannot downgrade audit_logs.resource_id while long resource references exist"
        )
    _alter_resource_id_length(36)
