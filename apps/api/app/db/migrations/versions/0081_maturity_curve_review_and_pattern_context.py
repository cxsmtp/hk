"""Extend Maturity Curve review, pattern, rollout, and executive context.

Revision ID: 0081_maturity_curve_review_and_pattern_context
Revises: 0080_maturity_curve_policy_intelligence
"""

from alembic import op
import sqlalchemy as sa


revision = "0081_maturity_curve_review_and_pattern_context"
down_revision = "0080_maturity_curve_policy_intelligence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "maturity_observed_usage_patterns",
        sa.Column("pattern_type", sa.String(32), nullable=False, server_default="UNKNOWN"),
    )
    op.add_column(
        "maturity_observed_usage_patterns",
        sa.Column("approval_state", sa.String(32), nullable=False, server_default="UNKNOWN"),
    )
    op.add_column(
        "maturity_observed_usage_patterns",
        sa.Column("risk_state", sa.String(16), nullable=False, server_default="UNKNOWN"),
    )
    op.add_column(
        "maturity_observed_usage_patterns",
        sa.Column("control_state", sa.String(32), nullable=False, server_default="UNKNOWN"),
    )
    op.add_column(
        "maturity_policy_recommendations",
        sa.Column("review_state", sa.String(32), nullable=False, server_default="PENDING"),
    )
    op.add_column("maturity_policy_recommendations", sa.Column("review_reason", sa.Text(), nullable=True))
    op.add_column("maturity_policy_recommendations", sa.Column("reviewed_by_ref", sa.String(255), nullable=True))
    op.add_column("maturity_policy_recommendations", sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "maturity_recommendation_reviews",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("recommendation_id", sa.String(36), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("actor_ref", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "recommendation_id"],
            ["maturity_policy_recommendations.tenant_id", "maturity_policy_recommendations.id"],
            name="fk_maturity_recommendation_review_tenant_recommendation",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "action IN ('REVIEW','APPROVE','REJECT','DEFER','ACCEPT_RISK')",
            name="ck_maturity_recommendation_review_action",
        ),
    )
    op.create_index(
        "idx_maturity_recommendation_review",
        "maturity_recommendation_reviews",
        ["tenant_id", "recommendation_id", "created_at"],
    )
    op.add_column(
        "maturity_policy_rollouts",
        sa.Column("rollout_stage", sa.String(32), nullable=False, server_default="monitor"),
    )
    op.add_column(
        "maturity_executive_snapshots",
        sa.Column("report", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
    )


def downgrade() -> None:
    op.drop_column("maturity_executive_snapshots", "report")
    op.drop_column("maturity_policy_rollouts", "rollout_stage")
    op.drop_index("idx_maturity_recommendation_review", table_name="maturity_recommendation_reviews")
    op.drop_table("maturity_recommendation_reviews")
    op.drop_column("maturity_policy_recommendations", "reviewed_at")
    op.drop_column("maturity_policy_recommendations", "reviewed_by_ref")
    op.drop_column("maturity_policy_recommendations", "review_reason")
    op.drop_column("maturity_policy_recommendations", "review_state")
    op.drop_column("maturity_observed_usage_patterns", "control_state")
    op.drop_column("maturity_observed_usage_patterns", "risk_state")
    op.drop_column("maturity_observed_usage_patterns", "approval_state")
    op.drop_column("maturity_observed_usage_patterns", "pattern_type")
