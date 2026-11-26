"""GitHub repository AI agent posture and MAC-bound single-use mutation approvals.

- github_repositories.agent_policy_json: the owner/admin-set agent write posture (empty = every write needs a bound
  approval, which is what happened before).
- github_repository_mutation_approvals: one row per approved repository mutation. It holds an HMAC over the exact
  canonical action, a nonce, an expiry and a single use; the verifier recomputes the MAC from the live request.

down_revision is 0099_iam_roles; relink if another revision lands on it first.
"""

from alembic import op
import sqlalchemy as sa


revision = "0100_github_agent_controls"
down_revision = "0099_iam_roles"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "github_repositories",
        sa.Column("agent_policy_json", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )
    op.create_table(
        "github_repository_mutation_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("approval_request_id", sa.String(36), nullable=False),
        sa.Column("repository_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("action_mac", sa.String(64), nullable=False),
        sa.Column("mac_version", sa.String(16), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        sa.Column("governance_version", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("use_limit", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("uses_consumed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("state", sa.String(16), nullable=False, server_default="ACTIVE"),
        sa.Column("issued_by", sa.String(36)),
        sa.Column("consumed_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["repository_id"], ["github_repositories.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "approval_request_id"],
            ["approval_requests.tenant_id", "approval_requests.id"],
            name="fk_github_repo_mutation_approval_request",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("tenant_id", "approval_request_id", name="uq_github_repo_mutation_approval_request"),
        sa.UniqueConstraint("tenant_id", "nonce", name="uq_github_repo_mutation_approval_nonce"),
        sa.CheckConstraint("state IN ('ACTIVE','CONSUMED','REVOKED')", name="ck_github_repo_mutation_approval_state"),
        sa.CheckConstraint("use_limit = 1", name="ck_github_repo_mutation_approval_single_use"),
        sa.CheckConstraint("uses_consumed >= 0 AND uses_consumed <= use_limit", name="ck_github_repo_mutation_approval_uses"),
    )
    op.create_index(
        "idx_github_repo_mutation_approval_repository",
        "github_repository_mutation_approvals",
        ["tenant_id", "repository_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_github_repo_mutation_approval_repository", table_name="github_repository_mutation_approvals")
    op.drop_table("github_repository_mutation_approvals")
    op.drop_column("github_repositories", "agent_policy_json")
