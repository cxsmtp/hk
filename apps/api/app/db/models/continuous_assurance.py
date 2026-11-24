"""Tenant-scoped persistence for the Phase 6 continuous-assurance loop."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


ASSURANCE_STATES = ("UNKNOWN", "CURRENT", "STALE", "REGRESSED")
SAFETY_CLASSES = (
    "S0_METADATA_ONLY",
    "S1_READ_ONLY_SYNTHETIC",
    "S2_REVERSIBLE_TEST_STATE",
    "S3_ISOLATED_SIDE_EFFECT",
    "S4_PRODUCTION_CANARY",
    "S5_PROHIBITED",
)
VALIDATION_OUTCOMES = (
    "PASS_CONTROLLED",
    "PASS_DETECTED",
    "PASS_PREVENTED",
    "PASS_EXECUTION_MATCHED",
    "FAIL_MISSED",
    "FAIL_EXECUTED",
    "FAIL_WRONG_DECISION",
    "FAIL_WRONG_CONTROL_POINT",
    "FAIL_EVIDENCE_MISSING",
    "FAIL_SAFETY_BOUNDARY",
    "INCONCLUSIVE",
    "CONTROL_UNAVAILABLE",
    "ENVIRONMENT_UNAVAILABLE",
    "ERROR",
    "CANCELLED",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class ControlAssertion(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "continuous_control_assertions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "assertion_key", name="uq_phase6_assertion_key"),
        UniqueConstraint("tenant_id", "id", name="uq_phase6_assertion_tenant_id"),
        CheckConstraint(
            f"assurance_state IN ({_quoted(ASSURANCE_STATES)})",
            name="ck_phase6_assertion_state",
        ),
        CheckConstraint("assurance_version >= 0", name="ck_phase6_assertion_version"),
        Index("idx_phase6_assertion_tenant_state", "tenant_id", "assurance_state"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    assertion_key: Mapped[str] = mapped_column(String(128), nullable=False)
    assertion_type: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    action_class: Mapped[str | None] = mapped_column(String(128), nullable=True)
    required_capability: Mapped[str] = mapped_column(String(128), nullable=False)
    expected_outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    required_evidence_level: Mapped[str] = mapped_column(String(64), nullable=False)
    assurance_state: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    assurance_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_baseline_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_validation_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fresh_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    control_profile_id: Mapped[str | None] = mapped_column(
        ForeignKey("control_capability_profiles.id", ondelete="RESTRICT"), nullable=True
    )

    dependencies: Mapped[list["ControlAssertionDependency"]] = relationship(
        back_populates="assertion",
        cascade="all, delete-orphan",
        order_by="ControlAssertionDependency.dependency_category, ControlAssertionDependency.dependency_key",
    )


class ControlAssertionDependency(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "control_assertion_dependencies"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_dependency_assertion",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id",
            "assertion_id",
            "dependency_category",
            "dependency_key",
            name="uq_phase6_assertion_dependency",
        ),
        Index(
            "idx_phase6_dependency_impact",
            "tenant_id",
            "dependency_category",
            "dependency_key",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(36), nullable=False)
    dependency_category: Mapped[str] = mapped_column(String(64), nullable=False)
    dependency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    current_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    assertion: Mapped[ControlAssertion] = relationship(back_populates="dependencies")


class AssuranceBaseline(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "assurance_baselines"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_baseline_assertion",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "assertion_id", "baseline_version", name="uq_phase6_baseline_version"),
        Index("idx_phase6_baseline_assertion", "tenant_id", "assertion_id"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(36), nullable=False)
    baseline_version: Mapped[int] = mapped_column(Integer, nullable=False)
    dependency_state: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    dependency_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    validation_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ValidationSafetyEnvelope(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "validation_safety_envelopes"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_phase6_safety_tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    allowed_action_classes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    allowed_targets: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    allowed_control_points: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    allowed_side_effect_categories: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cleanup_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    production_canary_authorized: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ValidationScenario(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "validation_scenarios"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_scenario_assertion",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "safety_envelope_id"],
            ["validation_safety_envelopes.tenant_id", "validation_safety_envelopes.id"],
            name="fk_phase6_scenario_safety",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "scenario_key", name="uq_phase6_scenario_key"),
        UniqueConstraint("tenant_id", "id", name="uq_phase6_scenario_tenant_id"),
        CheckConstraint(
            f"safety_class IN ({_quoted(SAFETY_CLASSES)})",
            name="ck_phase6_scenario_safety_class",
        ),
        CheckConstraint(
            f"expected_validation_outcome IN ({_quoted(VALIDATION_OUTCOMES)})",
            name="ck_phase6_scenario_expected_outcome",
        ),
        CheckConstraint("freshness_seconds > 0", name="ck_phase6_scenario_freshness"),
        Index("idx_phase6_scenario_assertion", "tenant_id", "assertion_id", "active"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(36), nullable=False)
    safety_envelope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scenario_key: Mapped[str] = mapped_column(String(128), nullable=False)
    action_template: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    expected_policy_result: Mapped[str] = mapped_column(String(32), nullable=False)
    expected_enforcement_result: Mapped[str] = mapped_column(String(32), nullable=False)
    expected_receipt_result: Mapped[str] = mapped_column(String(32), nullable=False)
    safety_class: Mapped[str] = mapped_column(String(32), nullable=False)
    mutations: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expected_validation_outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    freshness_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=86400)
    approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ValidationRun(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "validation_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_run_assertion",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scenario_id"],
            ["validation_scenarios.tenant_id", "validation_scenarios.id"],
            name="fk_phase6_run_scenario",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_phase6_run_tenant_id"),
        CheckConstraint(
            "status IN ('STARTED','COMPLETED','CANCELLED','ERROR')",
            name="ck_phase6_run_status",
        ),
        CheckConstraint(
            f"prior_assurance_state IN ({_quoted(ASSURANCE_STATES)})",
            name="ck_phase6_run_prior_state",
        ),
        CheckConstraint(
            f"outcome IS NULL OR outcome IN ({_quoted(VALIDATION_OUTCOMES)})",
            name="ck_phase6_run_outcome",
        ),
        Index("idx_phase6_run_assertion", "tenant_id", "assertion_id", "started_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scenario_id: Mapped[str] = mapped_column(String(36), nullable=False)
    trigger: Mapped[str] = mapped_column(String(32), nullable=False)
    triggered_by_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    drift_signal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    remediation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="STARTED")
    prior_assurance_state: Mapped[str] = mapped_column(String(16), nullable=False)
    outcome: Mapped[str | None] = mapped_column(String(64), nullable=True)
    reason_codes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_bundle_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ValidationEvidenceBundle(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "validation_evidence_bundles"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "validation_run_id"],
            ["validation_runs.tenant_id", "validation_runs.id"],
            name="fk_phase6_evidence_run",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_evidence_assertion",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "validation_run_id", name="uq_phase6_evidence_run"),
        Index("idx_phase6_evidence_assertion", "tenant_id", "assertion_id"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    validation_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    comparison_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    selected_control_point_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_epoch: Mapped[int | None] = mapped_column(Integer, nullable=True)
    baseline_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    evidence_quality: Mapped[str] = mapped_column(String(64), nullable=False)
    target_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class DriftSignal(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "assurance_drift_signals"
    __table_args__ = (
        UniqueConstraint("tenant_id", "signal_hash", name="uq_phase6_drift_signal_hash"),
        CheckConstraint("status IN ('OPEN','REVALIDATED')", name="ck_phase6_drift_status"),
        Index("idx_phase6_drift_dependency", "tenant_id", "category", "dependency_key"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    signal_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    dependency_key: Mapped[str] = mapped_column(String(255), nullable=False)
    previous_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    current_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    affected_assertion_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ValidationRemediation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "validation_remediations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "assertion_id"],
            ["continuous_control_assertions.tenant_id", "continuous_control_assertions.id"],
            name="fk_phase6_remediation_assertion",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "regression_run_id"],
            ["validation_runs.tenant_id", "validation_runs.id"],
            name="fk_phase6_remediation_regression_run",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "state IN ('OPEN','READY_FOR_REVALIDATION','RESOLVED','FAILED')",
            name="ck_phase6_remediation_state",
        ),
        Index("idx_phase6_remediation_assertion", "tenant_id", "assertion_id", "state"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assertion_id: Mapped[str] = mapped_column(String(36), nullable=False)
    regression_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="OPEN")
    revalidation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    resolved_validation_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_by_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    updated_by_ref: Mapped[str] = mapped_column(String(255), nullable=False)

