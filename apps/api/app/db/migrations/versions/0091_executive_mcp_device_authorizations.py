"""Add executive MCP device authorization records.

Revision ID: 0091_exec_mcp_device_auth
Revises: 0090_github_repo_access
"""

from alembic import op
import sqlalchemy as sa


revision = "0091_exec_mcp_device_auth"
down_revision = "0090_github_repo_access"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "executive_mcp_device_authorizations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("user_id", sa.String(36), nullable=True),
        sa.Column("role", sa.String(32), nullable=True),
        sa.Column("client_id", sa.String(255), nullable=False, server_default=""),
        sa.Column("scope", sa.String(255), nullable=False),
        sa.Column("device_code_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("user_code_hash", sa.String(128), nullable=False, unique=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="PENDING"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("denied_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index(
        "idx_exec_mcp_device_tenant_status",
        "executive_mcp_device_authorizations",
        ["tenant_id", "status"],
    )
    op.create_index(
        "idx_exec_mcp_device_code_hash",
        "executive_mcp_device_authorizations",
        ["device_code_hash"],
    )
    op.create_index(
        "idx_exec_mcp_user_code_hash",
        "executive_mcp_device_authorizations",
        ["user_code_hash"],
    )


def downgrade() -> None:
    op.drop_index("idx_exec_mcp_user_code_hash", table_name="executive_mcp_device_authorizations")
    op.drop_index("idx_exec_mcp_device_code_hash", table_name="executive_mcp_device_authorizations")
    op.drop_index("idx_exec_mcp_device_tenant_status", table_name="executive_mcp_device_authorizations")
    op.drop_table("executive_mcp_device_authorizations")
