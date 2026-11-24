"""Add hash-only local workspace bindings and repository operation controls."""

from alembic import op
import sqlalchemy as sa


revision = "0092_github_repository_runtime_controls"
down_revision = "0091_exec_mcp_device_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "github_repositories",
        sa.Column(
            "operation_controls_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{\"READ\":\"BLOCK\",\"EDIT\":\"BLOCK\",\"COMMIT\":\"BLOCK\",\"PULL\":\"BLOCK\",\"PUSH\":\"BLOCK\"}'"),
        ),
    )
    op.create_table(
        "github_repository_runtime_bindings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=True),
        sa.Column("native_integration_id", sa.String(36), nullable=False),
        sa.Column("canonical_root_sha256", sa.String(64), nullable=False),
        sa.Column("common_dir_sha256", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(32), nullable=False, server_default="EXACT_FOLDER"),
        sa.Column("state", sa.String(16), nullable=False, server_default="OBSERVED"),
        sa.Column("signed_evidence_ref", sa.String(255), nullable=False),
        sa.Column("actor_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["repository_id"], ["github_repositories.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["native_integration_id"], ["native_control_integrations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "native_integration_id", "canonical_root_sha256", "common_dir_sha256", name="uq_github_repo_runtime_binding"),
        sa.CheckConstraint("scope = 'EXACT_FOLDER'", name="ck_github_repo_runtime_scope"),
        sa.CheckConstraint("state IN ('OBSERVED','ACTIVE','REVOKED')", name="ck_github_repo_runtime_state"),
        sa.CheckConstraint("(state = 'OBSERVED' AND repository_id IS NULL) OR (state IN ('ACTIVE','REVOKED') AND repository_id IS NOT NULL)", name="ck_github_repo_runtime_repository_state"),
    )
    op.create_index("idx_github_repo_runtime_tenant_state", "github_repository_runtime_bindings", ["tenant_id", "state"])


def downgrade() -> None:
    op.drop_index("idx_github_repo_runtime_tenant_state", table_name="github_repository_runtime_bindings")
    op.drop_table("github_repository_runtime_bindings")
    op.drop_column("github_repositories", "operation_controls_json")
