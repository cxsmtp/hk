"""Add signed principal assertion material to dynamic tool bindings.

Revision ID: 0079_instruction_tool_provenance_integration
Revises: 0078_instruction_tool_provenance
"""

from alembic import op
import sqlalchemy as sa


revision = "0079_instruction_tool_provenance_integration"
down_revision = "0078_instruction_tool_provenance"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("tool_principal_bindings", sa.Column("principal_assertion_algorithm", sa.String(16), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("signing_key_id", sa.String(255), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("assertion_digest", sa.String(64), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("assertion_signature", sa.String(1024), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("assertion_assurance", sa.String(64), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("assertion_nonce", sa.String(255), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("assertion_issued_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("assertion_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("tool_principal_bindings", sa.Column("principal_assertion_valid", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index(
        "idx_tool_principal_tenant_nonce",
        "tool_principal_bindings",
        ["tenant_id", "assertion_nonce"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("idx_tool_principal_tenant_nonce", table_name="tool_principal_bindings")
    op.drop_column("tool_principal_bindings", "principal_assertion_valid")
    op.drop_column("tool_principal_bindings", "assertion_expires_at")
    op.drop_column("tool_principal_bindings", "assertion_issued_at")
    op.drop_column("tool_principal_bindings", "assertion_nonce")
    op.drop_column("tool_principal_bindings", "assertion_assurance")
    op.drop_column("tool_principal_bindings", "assertion_signature")
    op.drop_column("tool_principal_bindings", "assertion_digest")
    op.drop_column("tool_principal_bindings", "signing_key_id")
    op.drop_column("tool_principal_bindings", "principal_assertion_algorithm")
