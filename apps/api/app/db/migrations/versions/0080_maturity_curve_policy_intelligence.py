"""Add Trinya maturity curve and policy-intelligence persistence.

Revision ID: 0080_maturity_curve_policy_intelligence
Revises: 0079_instruction_tool_provenance_integration
"""

from alembic import op
import sqlalchemy as sa


revision = "0080_maturity_curve_policy_intelligence"
down_revision = "0079_instruction_tool_provenance_integration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenant_maturity_entitlements",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("package_tier", sa.String(16), nullable=False, server_default="secure"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("custom_attributes_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", name="uq_maturity_entitlement_tenant"),
        sa.CheckConstraint("package_tier IN ('secure','control','assurance','enterprise')", name="ck_maturity_entitlement_tier"),
    )
    op.create_table(
        "maturity_scopes",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scope_key", sa.String(255), nullable=False),
        sa.Column("scope_type", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_scope_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_key", name="uq_maturity_scope_tenant_key"),
        sa.CheckConstraint(
            "scope_type IN ('organization','business_unit','department','group','surface','application','provider','model','agent','tool_mcp','action_class','policy_family','environment')",
            name="ck_maturity_scope_type",
        ),
    )
    op.create_index("idx_maturity_scope_tenant_type", "maturity_scopes", ["tenant_id", "scope_type", "active"])

    op.create_table(
        "maturity_observation_windows",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("source_watermarks", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("source_counts", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_window_tenant_scope", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_window_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_id", "input_digest", name="uq_maturity_window_input"),
        sa.CheckConstraint("window_end >= window_start", name="ck_maturity_window_order"),
    )
    op.create_index("idx_maturity_window_scope_time", "maturity_observation_windows", ["tenant_id", "scope_id", "window_end"])

    op.create_table(
        "maturity_assessments",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("observation_window_id", sa.String(36), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("source_diversity", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("indicators", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("missing_gates", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("blocking_gaps", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("status", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("methodology_version", sa.String(32), nullable=False, server_default="maturity-v1"),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_assessment_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_window_id"], ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"], name="fk_maturity_assessment_tenant_window", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_assessment_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_id", "observation_window_id", "methodology_version", name="uq_maturity_assessment_window"),
        sa.CheckConstraint("stage IN ('UNKNOWN','CONNECTED','MONITORING','UNDERSTANDING','POLICY_READY','CONTROLLED','ASSURED')", name="ck_maturity_assessment_stage"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_maturity_assessment_confidence"),
        sa.CheckConstraint("source_diversity >= 0", name="ck_maturity_assessment_source_diversity"),
        sa.CheckConstraint("status IN ('CURRENT','STALE','UNKNOWN','REGRESSED')", name="ck_maturity_assessment_status"),
    )
    op.create_index("idx_maturity_assessment_scope_time", "maturity_assessments", ["tenant_id", "scope_id", "computed_at"])
    op.create_index("idx_maturity_assessment_stage", "maturity_assessments", ["tenant_id", "stage", "status"])

    op.create_table(
        "maturity_usage_baselines",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("observation_window_id", sa.String(36), nullable=False),
        sa.Column("baseline_version", sa.Integer(), nullable=False),
        sa.Column("baseline_digest", sa.String(64), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source_diversity", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("aggregates", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("status", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_baseline_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_window_id"], ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"], name="fk_maturity_baseline_tenant_window", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_baseline_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_id", "observation_window_id", "baseline_version", name="uq_maturity_baseline_version"),
        sa.CheckConstraint("baseline_version > 0", name="ck_maturity_baseline_version"),
        sa.CheckConstraint("sample_count >= 0", name="ck_maturity_baseline_sample_count"),
        sa.CheckConstraint("source_diversity >= 0", name="ck_maturity_baseline_source_diversity"),
        sa.CheckConstraint("status IN ('COMPLETE','PARTIAL','UNKNOWN','STALE')", name="ck_maturity_baseline_status"),
    )
    op.create_index("idx_maturity_baseline_scope", "maturity_usage_baselines", ["tenant_id", "scope_id", "created_at"])

    op.create_table(
        "maturity_observed_usage_patterns",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("observation_window_id", sa.String(36), nullable=False),
        sa.Column("pattern_key", sa.String(255), nullable=False),
        sa.Column("dimension", sa.String(64), nullable=False),
        sa.Column("value_ref", sa.String(255), nullable=False),
        sa.Column("observation_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_pattern_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_window_id"], ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"], name="fk_maturity_pattern_tenant_window", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_pattern_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_id", "observation_window_id", "pattern_key", name="uq_maturity_pattern_window_key"),
        sa.CheckConstraint("observation_count >= 0", name="ck_maturity_pattern_count"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_maturity_pattern_confidence"),
    )
    op.create_index("idx_maturity_pattern_scope_dimension", "maturity_observed_usage_patterns", ["tenant_id", "scope_id", "dimension"])

    op.create_table(
        "maturity_policy_recommendations",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("assessment_id", sa.String(36), nullable=False),
        sa.Column("recommendation_key", sa.String(255), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="DRAFT"),
        sa.Column("policy_draft", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("assumptions", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("unknowns", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0"),
        sa.Column("estimated_impact", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("estimated_friction", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("recommendation_digest", sa.String(64), nullable=False),
        sa.Column("candidate_policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_recommendation_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "assessment_id"], ["maturity_assessments.tenant_id", "maturity_assessments.id"], name="fk_maturity_recommendation_tenant_assessment", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_recommendation_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_id", "recommendation_key", "recommendation_digest", name="uq_maturity_recommendation_digest"),
        sa.CheckConstraint("status IN ('DRAFT','REVIEW','APPROVED','REJECTED','DISMISSED','EXPIRED')", name="ck_maturity_recommendation_status"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_maturity_recommendation_confidence"),
    )
    op.create_index("idx_maturity_recommendation_scope_status", "maturity_policy_recommendations", ["tenant_id", "scope_id", "status"])

    op.create_table(
        "maturity_policy_simulations",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("recommendation_id", sa.String(36), nullable=False),
        sa.Column("policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("outcome_counts", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("scope_breakdown", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("unknown_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_simulation_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "recommendation_id"], ["maturity_policy_recommendations.tenant_id", "maturity_policy_recommendations.id"], name="fk_maturity_simulation_tenant_recommendation", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_simulation_tenant_id"),
        sa.UniqueConstraint("tenant_id", "recommendation_id", "input_digest", name="uq_maturity_simulation_input"),
        sa.CheckConstraint("sample_count >= 0", name="ck_maturity_simulation_sample_count"),
        sa.CheckConstraint("unknown_count >= 0", name="ck_maturity_simulation_unknown_count"),
    )
    op.create_index("idx_maturity_simulation_recommendation", "maturity_policy_simulations", ["tenant_id", "recommendation_id", "created_at"])

    op.create_table(
        "maturity_policy_rollouts",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("recommendation_id", sa.String(36), nullable=False),
        sa.Column("policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("state", sa.String(16), nullable=False, server_default="DRAFT"),
        sa.Column("mode", sa.String(16), nullable=False, server_default="monitor"),
        sa.Column("rollout_digest", sa.String(64), nullable=False),
        sa.Column("requested_by_ref", sa.String(255), nullable=True),
        sa.Column("approved_by_ref", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_reason", sa.Text(), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_rollout_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "recommendation_id"], ["maturity_policy_recommendations.tenant_id", "maturity_policy_recommendations.id"], name="fk_maturity_rollout_tenant_recommendation", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_rollout_tenant_id"),
        sa.CheckConstraint("state IN ('DRAFT','REVIEW','APPROVED','SHADOW','ENFORCE','MONITOR','PAUSED','ROLLED_BACK','REJECTED','EXPIRED')", name="ck_maturity_rollout_state"),
        sa.CheckConstraint("mode IN ('monitor','shadow','enforce')", name="ck_maturity_rollout_mode"),
    )
    op.create_index("idx_maturity_rollout_scope_state", "maturity_policy_rollouts", ["tenant_id", "scope_id", "state"])

    op.create_table(
        "maturity_rollout_transitions",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("rollout_id", sa.String(36), nullable=False),
        sa.Column("from_state", sa.String(16), nullable=True),
        sa.Column("to_state", sa.String(16), nullable=False),
        sa.Column("actor_ref", sa.String(255), nullable=True),
        sa.Column("reason", sa.String(500), nullable=False, server_default=""),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "rollout_id"], ["maturity_policy_rollouts.tenant_id", "maturity_policy_rollouts.id"], name="fk_maturity_rollout_transition_tenant_rollout", ondelete="CASCADE"),
    )
    op.create_index("idx_maturity_rollout_transition", "maturity_rollout_transitions", ["tenant_id", "rollout_id", "created_at"])

    op.create_table(
        "maturity_policy_exceptions",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("rollout_id", sa.String(36), nullable=False),
        sa.Column("policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scope", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="REQUESTED"),
        sa.Column("requested_by_ref", sa.String(255), nullable=False),
        sa.Column("approved_by_ref", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("audit_ref", sa.String(255), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "rollout_id"], ["maturity_policy_rollouts.tenant_id", "maturity_policy_rollouts.id"], name="fk_maturity_exception_tenant_rollout", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_exception_tenant_id"),
        sa.CheckConstraint("status IN ('REQUESTED','APPROVED','REJECTED','REVOKED','EXPIRED')", name="ck_maturity_exception_status"),
    )
    op.create_index("idx_maturity_exception_rollout_status", "maturity_policy_exceptions", ["tenant_id", "rollout_id", "status"])
    op.create_index("idx_maturity_exception_expiry", "maturity_policy_exceptions", ["tenant_id", "expires_at"])

    op.create_table(
        "maturity_policy_effectiveness_snapshots",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("rollout_id", sa.String(36), nullable=False),
        sa.Column("policy_version_id", sa.String(36), sa.ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True),
        sa.Column("observation_window_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("outcome_summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("evidence_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_effectiveness_tenant_scope", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "rollout_id"], ["maturity_policy_rollouts.tenant_id", "maturity_policy_rollouts.id"], name="fk_maturity_effectiveness_tenant_rollout", ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id", "observation_window_id"], ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"], name="fk_maturity_effectiveness_tenant_window", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_effectiveness_tenant_id"),
        sa.UniqueConstraint("tenant_id", "rollout_id", "observation_window_id", "input_digest", name="uq_maturity_effectiveness_input"),
        sa.CheckConstraint("status IN ('UNKNOWN','CURRENT','DEGRADED','REGRESSED','STALE')", name="ck_maturity_effectiveness_status"),
    )
    op.create_index("idx_maturity_effectiveness_scope_time", "maturity_policy_effectiveness_snapshots", ["tenant_id", "scope_id", "created_at"])

    op.create_table(
        "maturity_executive_snapshots",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("scope_id", sa.String(36), nullable=False),
        sa.Column("input_digest", sa.String(64), nullable=False),
        sa.Column("stage_distribution", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("coverage_refs", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
        sa.Column("gap_summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("recommendation_summary", sa.JSON(), nullable=False, server_default=sa.text("'{}'")),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["tenant_id", "scope_id"], ["maturity_scopes.tenant_id", "maturity_scopes.id"], name="fk_maturity_executive_tenant_scope", ondelete="CASCADE"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_maturity_executive_tenant_id"),
        sa.UniqueConstraint("tenant_id", "scope_id", "input_digest", name="uq_maturity_executive_input"),
    )
    op.create_index("idx_maturity_executive_scope_time", "maturity_executive_snapshots", ["tenant_id", "scope_id", "computed_at"])


def downgrade() -> None:
    op.drop_index("idx_maturity_executive_scope_time", table_name="maturity_executive_snapshots")
    op.drop_table("maturity_executive_snapshots")
    op.drop_index("idx_maturity_effectiveness_scope_time", table_name="maturity_policy_effectiveness_snapshots")
    op.drop_table("maturity_policy_effectiveness_snapshots")
    op.drop_index("idx_maturity_exception_expiry", table_name="maturity_policy_exceptions")
    op.drop_index("idx_maturity_exception_rollout_status", table_name="maturity_policy_exceptions")
    op.drop_table("maturity_policy_exceptions")
    op.drop_index("idx_maturity_rollout_transition", table_name="maturity_rollout_transitions")
    op.drop_table("maturity_rollout_transitions")
    op.drop_index("idx_maturity_rollout_scope_state", table_name="maturity_policy_rollouts")
    op.drop_table("maturity_policy_rollouts")
    op.drop_index("idx_maturity_simulation_recommendation", table_name="maturity_policy_simulations")
    op.drop_table("maturity_policy_simulations")
    op.drop_index("idx_maturity_recommendation_scope_status", table_name="maturity_policy_recommendations")
    op.drop_table("maturity_policy_recommendations")
    op.drop_index("idx_maturity_pattern_scope_dimension", table_name="maturity_observed_usage_patterns")
    op.drop_table("maturity_observed_usage_patterns")
    op.drop_index("idx_maturity_baseline_scope", table_name="maturity_usage_baselines")
    op.drop_table("maturity_usage_baselines")
    op.drop_index("idx_maturity_assessment_stage", table_name="maturity_assessments")
    op.drop_index("idx_maturity_assessment_scope_time", table_name="maturity_assessments")
    op.drop_table("maturity_assessments")
    op.drop_index("idx_maturity_window_scope_time", table_name="maturity_observation_windows")
    op.drop_table("maturity_observation_windows")
    op.drop_index("idx_maturity_scope_tenant_type", table_name="maturity_scopes")
    op.drop_table("maturity_scopes")
    op.drop_table("tenant_maturity_entitlements")
