"""Add the bounded Phase 6 continuous-assurance lifecycle.

Revision ID: 0070_phase6_continuous_assurance
Revises: 0069_phase5_stored_authority
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision = "0070_phase6_continuous_assurance"
down_revision = "0069_phase5_stored_authority"
branch_labels = None
depends_on = None


_ASSURANCE_STATES = "'UNKNOWN','CURRENT','STALE','REGRESSED'"
_SAFETY_CLASSES = (
    "'S0_METADATA_ONLY','S1_READ_ONLY_SYNTHETIC','S2_REVERSIBLE_TEST_STATE',"
    "'S3_ISOLATED_SIDE_EFFECT','S4_PRODUCTION_CANARY','S5_PROHIBITED'"
)
_VALIDATION_OUTCOMES = (
    "'PASS_CONTROLLED','PASS_DETECTED','PASS_PREVENTED','PASS_EXECUTION_MATCHED',"
    "'FAIL_MISSED','FAIL_EXECUTED','FAIL_WRONG_DECISION','FAIL_WRONG_CONTROL_POINT',"
    "'FAIL_EVIDENCE_MISSING','FAIL_SAFETY_BOUNDARY','INCONCLUSIVE','CONTROL_UNAVAILABLE',"
    "'ENVIRONMENT_UNAVAILABLE','ERROR','CANCELLED'"
)


def upgrade() -> None:
    op.create_table(
        "continuous_control_assertions",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("assertion_key", sa.String(128), nullable=False),
        sa.Column("assertion_type", sa.String(64), nullable=False),
        sa.Column("asset_ref", sa.String(255), nullable=True),
        sa.Column("action_class", sa.String(128), nullable=True),
        sa.Column("required_capability", sa.String(128), nullable=False),
        sa.Column("expected_outcome", sa.String(64), nullable=False),
        sa.Column("required_evidence_level", sa.String(64), nullable=False),
        sa.Column("assurance_state", sa.String(16), nullable=False, server_default="UNKNOWN"),
        sa.Column("assurance_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("current_baseline_id", sa.String(36), nullable=True),
        sa.Column("last_validation_run_id", sa.String(36), nullable=True),
        sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fresh_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("control_profile_id", sa.String(36), nullable=True),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"assurance_state IN ({_ASSURANCE_STATES})", name="ck_phase6_assertion_state"),
        sa.CheckConstraint("assurance_version >= 0", name="ck_phase6_assertion_version"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["control_profile_id"], ["control_capability_profiles.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "assertion_key", name="uq_phase6_assertion_key"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_phase6_assertion_tenant_id"),
    )
    op.create_index(
        "idx_phase6_assertion_tenant_state",
        "continuous_control_assertions",
        ["tenant_id", "assurance_state"],
    )

    op.create_table(
        "control_assertion_dependencies",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("assertion_id", sa.String(36), nullable=False),
        sa.Column("dependency_category", sa.String(64), nullable=False),
        sa.Column("dependency_key", sa.String(255), nullable=False),
        sa.Column("current_digest", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_dependency_assertion",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "assertion_id",
            "dependency_category",
            "dependency_key",
            name="uq_phase6_assertion_dependency",
        ),
    )
    op.create_index(
        "idx_phase6_dependency_impact",
        "control_assertion_dependencies",
        ["tenant_id", "dependency_category", "dependency_key"],
    )

    op.create_table(
        "assurance_baselines",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("assertion_id", sa.String(36), nullable=False),
        sa.Column("baseline_version", sa.Integer(), nullable=False),
        sa.Column("dependency_state", sa.JSON(), nullable=False),
        sa.Column("dependency_hash", sa.String(64), nullable=False),
        sa.Column("validation_run_id", sa.String(36), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_baseline_assertion",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id", "assertion_id", "baseline_version", name="uq_phase6_baseline_version"
        ),
    )
    op.create_index(
        "idx_phase6_baseline_assertion", "assurance_baselines", ["tenant_id", "assertion_id"]
    )

    op.create_table(
        "validation_safety_envelopes",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("allowed_action_classes", sa.JSON(), nullable=False),
        sa.Column("allowed_targets", sa.JSON(), nullable=False),
        sa.Column("allowed_control_points", sa.JSON(), nullable=False),
        sa.Column("allowed_side_effect_categories", sa.JSON(), nullable=False),
        sa.Column("cleanup_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("production_canary_authorized", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_phase6_safety_tenant_id"),
    )

    op.create_table(
        "validation_scenarios",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("assertion_id", sa.String(36), nullable=False),
        sa.Column("safety_envelope_id", sa.String(36), nullable=False),
        sa.Column("scenario_key", sa.String(128), nullable=False),
        sa.Column("action_template", sa.JSON(), nullable=False),
        sa.Column("expected_policy_result", sa.String(32), nullable=False),
        sa.Column("expected_enforcement_result", sa.String(32), nullable=False),
        sa.Column("expected_receipt_result", sa.String(32), nullable=False),
        sa.Column("safety_class", sa.String(32), nullable=False),
        sa.Column("mutations", sa.JSON(), nullable=False),
        sa.Column("expected_validation_outcome", sa.String(64), nullable=False),
        sa.Column("freshness_seconds", sa.Integer(), nullable=False, server_default="86400"),
        sa.Column("approved", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(f"safety_class IN ({_SAFETY_CLASSES})", name="ck_phase6_scenario_safety_class"),
        sa.CheckConstraint(
            f"expected_validation_outcome IN ({_VALIDATION_OUTCOMES})",
            name="ck_phase6_scenario_expected_outcome",
        ),
        sa.CheckConstraint("freshness_seconds > 0", name="ck_phase6_scenario_freshness"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_scenario_assertion",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "safety_envelope_id"],
            ["validation_safety_envelopes.tenant_id", "validation_safety_envelopes.id"],
            name="fk_phase6_scenario_safety",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "scenario_key", name="uq_phase6_scenario_key"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_phase6_scenario_tenant_id"),
    )
    op.create_index(
        "idx_phase6_scenario_assertion",
        "validation_scenarios",
        ["tenant_id", "assertion_id", "active"],
    )

    op.create_table(
        "validation_runs",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("assertion_id", sa.String(36), nullable=False),
        sa.Column("scenario_id", sa.String(36), nullable=False),
        sa.Column("trigger", sa.String(32), nullable=False),
        sa.Column("triggered_by_ref", sa.String(255), nullable=False),
        sa.Column("drift_signal_id", sa.String(36), nullable=True),
        sa.Column("remediation_id", sa.String(36), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="STARTED"),
        sa.Column("prior_assurance_state", sa.String(16), nullable=False),
        sa.Column("outcome", sa.String(64), nullable=True),
        sa.Column("reason_codes", sa.JSON(), nullable=False),
        sa.Column("evidence_bundle_id", sa.String(36), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.CheckConstraint(
            "status IN ('STARTED','COMPLETED','CANCELLED','ERROR')", name="ck_phase6_run_status"
        ),
        sa.CheckConstraint(
            f"prior_assurance_state IN ({_ASSURANCE_STATES})", name="ck_phase6_run_prior_state"
        ),
        sa.CheckConstraint(
            f"outcome IS NULL OR outcome IN ({_VALIDATION_OUTCOMES})", name="ck_phase6_run_outcome"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_run_assertion",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "scenario_id"],
            ["validation_scenarios.tenant_id", "validation_scenarios.id"],
            name="fk_phase6_run_scenario",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_phase6_run_tenant_id"),
    )
    op.create_index(
        "idx_phase6_run_assertion", "validation_runs", ["tenant_id", "assertion_id", "started_at"]
    )

    op.create_table(
        "validation_evidence_bundles",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("validation_run_id", sa.String(36), nullable=False),
        sa.Column("assertion_id", sa.String(36), nullable=False),
        sa.Column("action_id", sa.String(64), nullable=False),
        sa.Column("decision_receipt_id", sa.String(36), nullable=True),
        sa.Column("execution_receipt_id", sa.String(36), nullable=True),
        sa.Column("comparison_id", sa.String(36), nullable=True),
        sa.Column("selected_control_point_id", sa.String(64), nullable=True),
        sa.Column("policy_version", sa.String(64), nullable=True),
        sa.Column("policy_epoch", sa.Integer(), nullable=True),
        sa.Column("baseline_id", sa.String(36), nullable=True),
        sa.Column("evidence_quality", sa.String(64), nullable=False),
        sa.Column("target_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id", "validation_run_id"],
            ["validation_runs.tenant_id", "validation_runs.id"],
            name="fk_phase6_evidence_run",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_evidence_assertion",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "validation_run_id", name="uq_phase6_evidence_run"),
    )
    op.create_index(
        "idx_phase6_evidence_assertion",
        "validation_evidence_bundles",
        ["tenant_id", "assertion_id"],
    )

    op.create_table(
        "assurance_drift_signals",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("signal_hash", sa.String(64), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("dependency_key", sa.String(255), nullable=False),
        sa.Column("previous_digest", sa.String(64), nullable=False),
        sa.Column("current_digest", sa.String(64), nullable=False),
        sa.Column("source_ref", sa.String(255), nullable=False),
        sa.Column("affected_assertion_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="OPEN"),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("id", sa.String(36), nullable=False),
        sa.CheckConstraint("status IN ('OPEN','REVALIDATED')", name="ck_phase6_drift_status"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tenant_id", "signal_hash", name="uq_phase6_drift_signal_hash"),
    )
    op.create_index(
        "idx_phase6_drift_dependency",
        "assurance_drift_signals",
        ["tenant_id", "category", "dependency_key"],
    )

    op.create_table(
        "validation_remediations",
        sa.Column("tenant_id", sa.String(36), nullable=False),
        sa.Column("assertion_id", sa.String(36), nullable=False),
        sa.Column("regression_run_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(512), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="OPEN"),
        sa.Column("revalidation_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("resolved_validation_run_id", sa.String(36), nullable=True),
        sa.Column("created_by_ref", sa.String(255), nullable=False),
        sa.Column("updated_by_ref", sa.String(255), nullable=False),
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint(
            "state IN ('OPEN','READY_FOR_REVALIDATION','RESOLVED','FAILED')",
            name="ck_phase6_remediation_state",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_remediation_assertion",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "regression_run_id"],
            ["validation_runs.tenant_id", "validation_runs.id"],
            name="fk_phase6_remediation_regression_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_phase6_remediation_assertion",
        "validation_remediations",
        ["tenant_id", "assertion_id", "state"],
    )


def downgrade() -> None:
    op.drop_index("idx_phase6_remediation_assertion", table_name="validation_remediations")
    op.drop_table("validation_remediations")
    op.drop_index("idx_phase6_drift_dependency", table_name="assurance_drift_signals")
    op.drop_table("assurance_drift_signals")
    op.drop_index("idx_phase6_evidence_assertion", table_name="validation_evidence_bundles")
    op.drop_table("validation_evidence_bundles")
    op.drop_index("idx_phase6_run_assertion", table_name="validation_runs")
    op.drop_table("validation_runs")
    op.drop_index("idx_phase6_scenario_assertion", table_name="validation_scenarios")
    op.drop_table("validation_scenarios")
    op.drop_table("validation_safety_envelopes")
    op.drop_index("idx_phase6_baseline_assertion", table_name="assurance_baselines")
    op.drop_table("assurance_baselines")
    op.drop_index("idx_phase6_dependency_impact", table_name="control_assertion_dependencies")
    op.drop_table("control_assertion_dependencies")
    op.drop_index("idx_phase6_assertion_tenant_state", table_name="continuous_control_assertions")
    op.drop_table("continuous_control_assertions")
