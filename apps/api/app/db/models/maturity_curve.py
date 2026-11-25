"""Tenant-scoped persistence for Hawk's evidence-backed Maturity Curve.

The records in this module are derived product intelligence.  They retain
opaque source references and digests, never raw prompts or duplicated AI
action payloads.  Existing action, policy, coverage, assurance, and lineage
tables remain authoritative for their respective domains.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


MATURITY_SCOPE_TYPES = (
    "organization",
    "business_unit",
    "department",
    "group",
    "surface",
    "application",
    "provider",
    "model",
    "agent",
    "tool_mcp",
    "action_class",
    "policy_family",
    "environment",
)
MATURITY_STAGES = (
    "UNKNOWN",
    "CONNECTED",
    "MONITORING",
    "UNDERSTANDING",
    "POLICY_READY",
    "CONTROLLED",
    "ASSURED",
)
ENTITLEMENT_TIERS = ("secure", "control", "assurance", "enterprise")
BASELINE_STATUSES = ("COMPLETE", "PARTIAL", "UNKNOWN", "STALE")
RECOMMENDATION_STATUSES = ("DRAFT", "REVIEW", "APPROVED", "REJECTED", "DISMISSED", "EXPIRED")
ROLLOUT_STATES = ("DRAFT", "REVIEW", "APPROVED", "SHADOW", "ENFORCE", "MONITOR", "PAUSED", "ROLLED_BACK", "REJECTED", "EXPIRED")
ROLLOUT_MODES = ("monitor", "shadow", "enforce")
EFFECTIVENESS_STATES = ("UNKNOWN", "CURRENT", "DEGRADED", "REGRESSED", "STALE")
EXCEPTION_STATUSES = ("REQUESTED", "APPROVED", "REJECTED", "REVOKED", "EXPIRED")


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class TenantMaturityEntitlement(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tenant_maturity_entitlements"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_maturity_entitlement_tenant"),
        CheckConstraint(
            f"package_tier IN ({_quoted(ENTITLEMENT_TIERS)})",
            name="ck_maturity_entitlement_tier",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    package_tier: Mapped[str] = mapped_column(String(16), nullable=False, default="secure")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    custom_attributes_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class MaturityScope(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "maturity_scopes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_scope_tenant_id"),
        UniqueConstraint("tenant_id", "scope_key", name="uq_maturity_scope_tenant_key"),
        CheckConstraint(
            f"scope_type IN ({_quoted(MATURITY_SCOPE_TYPES)})",
            name="ck_maturity_scope_type",
        ),
        Index("idx_maturity_scope_tenant_type", "tenant_id", "scope_type", "active"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(255), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    filters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class MaturityObservationWindow(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "maturity_observation_windows"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_window_tenant_id"),
        UniqueConstraint("tenant_id", "scope_id", "input_digest", name="uq_maturity_window_input"),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_window_tenant_scope",
            ondelete="CASCADE",
        ),
        CheckConstraint("window_end >= window_start", name="ck_maturity_window_order"),
        Index("idx_maturity_window_scope_time", "tenant_id", "scope_id", "window_end"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    source_watermarks: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source_counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MaturityAssessment(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "maturity_assessments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_assessment_tenant_id"),
        UniqueConstraint(
            "tenant_id",
            "scope_id",
            "observation_window_id",
            "methodology_version",
            name="uq_maturity_assessment_window",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_assessment_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_window_id"],
            ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"],
            name="fk_maturity_assessment_tenant_window",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            f"stage IN ({_quoted(MATURITY_STAGES)})",
            name="ck_maturity_assessment_stage",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_maturity_assessment_confidence"),
        CheckConstraint("source_diversity >= 0", name="ck_maturity_assessment_source_diversity"),
        CheckConstraint("status IN ('CURRENT','STALE','UNKNOWN','REGRESSED')", name="ck_maturity_assessment_status"),
        Index("idx_maturity_assessment_scope_time", "tenant_id", "scope_id", "computed_at"),
        Index("idx_maturity_assessment_stage", "tenant_id", "stage", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observation_window_id: Mapped[str] = mapped_column(String(36), nullable=False)
    stage: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source_diversity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    indicators: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    missing_gates: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    blocking_gaps: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False, default="maturity-v1")
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MaturityUsageBaseline(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "maturity_usage_baselines"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_baseline_tenant_id"),
        UniqueConstraint(
            "tenant_id", "scope_id", "observation_window_id", "baseline_version", name="uq_maturity_baseline_version"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_baseline_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_window_id"],
            ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"],
            name="fk_maturity_baseline_tenant_window",
            ondelete="CASCADE",
        ),
        CheckConstraint("baseline_version > 0", name="ck_maturity_baseline_version"),
        CheckConstraint("sample_count >= 0", name="ck_maturity_baseline_sample_count"),
        CheckConstraint("source_diversity >= 0", name="ck_maturity_baseline_source_diversity"),
        CheckConstraint(
            f"status IN ({_quoted(BASELINE_STATUSES)})",
            name="ck_maturity_baseline_status",
        ),
        Index("idx_maturity_baseline_scope", "tenant_id", "scope_id", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observation_window_id: Mapped[str] = mapped_column(String(36), nullable=False)
    baseline_version: Mapped[int] = mapped_column(Integer, nullable=False)
    baseline_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_diversity: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    aggregates: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")


class MaturityObservedUsagePattern(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "maturity_observed_usage_patterns"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_pattern_tenant_id"),
        UniqueConstraint(
            "tenant_id", "scope_id", "observation_window_id", "pattern_key", name="uq_maturity_pattern_window_key"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_pattern_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_window_id"],
            ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"],
            name="fk_maturity_pattern_tenant_window",
            ondelete="CASCADE",
        ),
        CheckConstraint("observation_count >= 0", name="ck_maturity_pattern_count"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_maturity_pattern_confidence"),
        Index("idx_maturity_pattern_scope_dimension", "tenant_id", "scope_id", "dimension"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    observation_window_id: Mapped[str] = mapped_column(String(36), nullable=False)
    pattern_key: Mapped[str] = mapped_column(String(255), nullable=False)
    dimension: Mapped[str] = mapped_column(String(64), nullable=False)
    value_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    # These labels describe the observed security posture; they are not
    # employee scores and they never make frequent activity automatically safe.
    pattern_type: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    approval_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    risk_state: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    control_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)


class MaturityPolicyRecommendation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "maturity_policy_recommendations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_recommendation_tenant_id"),
        UniqueConstraint(
            "tenant_id", "scope_id", "recommendation_key", "recommendation_digest", name="uq_maturity_recommendation_digest"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_recommendation_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["maturity_assessments.tenant_id", "maturity_assessments.id"],
            name="fk_maturity_recommendation_tenant_assessment",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            f"status IN ({_quoted(RECOMMENDATION_STATUSES)})",
            name="ck_maturity_recommendation_status",
        ),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_maturity_recommendation_confidence"),
        Index("idx_maturity_recommendation_scope_status", "tenant_id", "scope_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assessment_id: Mapped[str] = mapped_column(String(36), nullable=False)
    recommendation_key: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="DRAFT")
    review_state: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy_draft: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    assumptions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    unknowns: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    estimated_impact: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    estimated_friction: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    recommendation_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    candidate_policy_version_id: Mapped[str | None] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True
    )


class MaturityRecommendationReview(Base, UUIDPrimaryKeyMixin):
    """Immutable human review history for evidence-backed recommendations."""

    __tablename__ = "maturity_recommendation_reviews"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "recommendation_id"],
            ["maturity_policy_recommendations.tenant_id", "maturity_policy_recommendations.id"],
            name="fk_maturity_recommendation_review_tenant_recommendation",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "action IN ('REVIEW','APPROVE','REJECT','DEFER','ACCEPT_RISK')",
            name="ck_maturity_recommendation_review_action",
        ),
        Index("idx_maturity_recommendation_review", "tenant_id", "recommendation_id", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    recommendation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MaturityPolicySimulation(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "maturity_policy_simulations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_simulation_tenant_id"),
        UniqueConstraint(
            "tenant_id", "recommendation_id", "input_digest", name="uq_maturity_simulation_input"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_simulation_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "recommendation_id"],
            ["maturity_policy_recommendations.tenant_id", "maturity_policy_recommendations.id"],
            name="fk_maturity_simulation_tenant_recommendation",
            ondelete="CASCADE",
        ),
        CheckConstraint("sample_count >= 0", name="ck_maturity_simulation_sample_count"),
        CheckConstraint("unknown_count >= 0", name="ck_maturity_simulation_unknown_count"),
        Index("idx_maturity_simulation_recommendation", "tenant_id", "recommendation_id", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    recommendation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outcome_counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    scope_breakdown: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    unknown_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MaturityPolicyRollout(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "maturity_policy_rollouts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_rollout_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_rollout_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "recommendation_id"],
            ["maturity_policy_recommendations.tenant_id", "maturity_policy_recommendations.id"],
            name="fk_maturity_rollout_tenant_recommendation",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            f"state IN ({_quoted(ROLLOUT_STATES)})",
            name="ck_maturity_rollout_state",
        ),
        CheckConstraint(
            f"mode IN ({_quoted(ROLLOUT_MODES)})",
            name="ck_maturity_rollout_mode",
        ),
        Index("idx_maturity_rollout_scope_state", "tenant_id", "scope_id", "state"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    recommendation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="DRAFT")
    mode: Mapped[str] = mapped_column(String(16), nullable=False, default="monitor")
    # ``mode`` retains the existing runtime control-mode contract.  This
    # records the customer-facing rollout phase (monitor, warn, approval,
    # enforce, validate) without inventing another policy runtime.
    rollout_stage: Mapped[str] = mapped_column(String(32), nullable=False, default="monitor")
    rollout_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    requested_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class MaturityRolloutTransition(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "maturity_rollout_transitions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "rollout_id"],
            ["maturity_policy_rollouts.tenant_id", "maturity_policy_rollouts.id"],
            name="fk_maturity_rollout_transition_tenant_rollout",
            ondelete="CASCADE",
        ),
        Index("idx_maturity_rollout_transition", "tenant_id", "rollout_id", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    rollout_id: Mapped[str] = mapped_column(String(36), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(16), nullable=True)
    to_state: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MaturityPolicyException(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "maturity_policy_exceptions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_exception_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "rollout_id"],
            ["maturity_policy_rollouts.tenant_id", "maturity_policy_rollouts.id"],
            name="fk_maturity_exception_tenant_rollout",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            f"status IN ({_quoted(EXCEPTION_STATUSES)})",
            name="ck_maturity_exception_status",
        ),
        Index("idx_maturity_exception_rollout_status", "tenant_id", "rollout_id", "status"),
        Index("idx_maturity_exception_expiry", "tenant_id", "expires_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    rollout_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="REQUESTED")
    requested_by_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    audit_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)


class MaturityPolicyEffectivenessSnapshot(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "maturity_policy_effectiveness_snapshots"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_effectiveness_tenant_id"),
        UniqueConstraint(
            "tenant_id", "rollout_id", "observation_window_id", "input_digest", name="uq_maturity_effectiveness_input"
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_effectiveness_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "rollout_id"],
            ["maturity_policy_rollouts.tenant_id", "maturity_policy_rollouts.id"],
            name="fk_maturity_effectiveness_tenant_rollout",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "observation_window_id"],
            ["maturity_observation_windows.tenant_id", "maturity_observation_windows.id"],
            name="fk_maturity_effectiveness_tenant_window",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            f"status IN ({_quoted(EFFECTIVENESS_STATES)})",
            name="ck_maturity_effectiveness_status",
        ),
        Index("idx_maturity_effectiveness_scope_time", "tenant_id", "scope_id", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    rollout_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    observation_window_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")
    outcome_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class MaturityExecutiveSnapshot(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "maturity_executive_snapshots"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_maturity_executive_tenant_id"),
        UniqueConstraint("tenant_id", "scope_id", "input_digest", name="uq_maturity_executive_input"),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["maturity_scopes.tenant_id", "maturity_scopes.id"],
            name="fk_maturity_executive_tenant_scope",
            ondelete="CASCADE",
        ),
        Index("idx_maturity_executive_scope_time", "tenant_id", "scope_id", "computed_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    stage_distribution: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    coverage_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    gap_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    recommendation_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    report: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
