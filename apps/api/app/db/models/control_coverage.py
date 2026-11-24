from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class DeploymentSurface(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "deployment_surfaces"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_deployment_surface_tenant_id"),
        UniqueConstraint("tenant_id", "source_kind", "source_id", name="uq_deployment_surface_tenant_source"),
        CheckConstraint(
            "health_status IN ('healthy','warning','degraded','offline','stale','unknown')",
            name="ck_deployment_surface_health_status",
        ),
        CheckConstraint(
            "deployment_family IN ('browser','endpoint','runtime','saas_api','unknown')",
            name="ck_deployment_surface_family",
        ),
        CheckConstraint(
            "hosting_mode IN ('saas','hybrid','private_cloud','on_premises','unknown')",
            name="ck_deployment_surface_hosting_mode",
        ),
        CheckConstraint(
            "control_capability IN ('inline','warn_only','monitor_only','external_required','unknown')",
            name="ck_deployment_surface_control_capability",
        ),
        CheckConstraint(
            "evidence_capability IN ('complete','partial','metadata_only','none','unknown')",
            name="ck_deployment_surface_evidence_capability",
        ),
        CheckConstraint(
            "containment_capability IN ('direct','surface_limited','external','none','unknown')",
            name="ck_deployment_surface_containment_capability",
        ),
        CheckConstraint(
            "bypass_detection_capability IN ('supported','unsupported','unknown')",
            name="ck_deployment_surface_bypass_capability",
        ),
        Index("idx_deployment_surface_tenant_status", "tenant_id", "status"),
        Index("idx_deployment_surface_tenant_type", "tenant_id", "surface_type"),
        Index("idx_deployment_surface_tenant_seen", "tenant_id", "last_seen_at"),
        Index("idx_deployment_surface_tenant_family", "tenant_id", "deployment_family"),
        Index("idx_deployment_surface_tenant_health", "tenant_id", "health_status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_kind: Mapped[str] = mapped_column(String(32), nullable=False)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    surface_type: Mapped[str] = mapped_column(String(64), nullable=False)
    deployment_mode: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    deployment_family: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )
    hosting_mode: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )
    environment: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    provider: Mapped[str | None] = mapped_column(String(128), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    feature_flag: Mapped[str | None] = mapped_column(String(128), nullable=True)
    capability_profile: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    capability_sources: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    control_capability: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )
    evidence_capability: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )
    containment_capability: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )
    bypass_detection_capability: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="unknown",
        server_default="unknown",
    )
    health_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    health_reason: Mapped[str] = mapped_column(String(128), nullable=False, default="insufficient_evidence")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    policy_bundle_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    collector_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ControlCoveragePath(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "control_coverage_paths"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_control_coverage_path_tenant_id"),
        UniqueConstraint("tenant_id", "path_key", name="uq_control_coverage_path_tenant_key"),
        ForeignKeyConstraint(
            ["tenant_id", "deployment_surface_id"],
            ["deployment_surfaces.tenant_id", "deployment_surfaces.id"],
            name="fk_control_coverage_path_tenant_surface",
            ondelete="RESTRICT",
        ),
        Index("idx_control_coverage_path_tenant_seen", "tenant_id", "last_seen_at"),
        Index("idx_control_coverage_path_tenant_asset", "tenant_id", "asset_ref"),
        Index("idx_control_coverage_path_tenant_identity", "tenant_id", "identity_ref"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    path_key: Mapped[str] = mapped_column(String(64), nullable=False)
    key_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    asset_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    identity_type: Mapped[str] = mapped_column(String(32), nullable=False)
    identity_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    runtime_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    deployment_surface_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    deployment_surface_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    destination_type: Mapped[str] = mapped_column(String(32), nullable=False)
    destination_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    lifecycle_status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    source_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ControlCoverageAssertion(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "control_coverage_assertions"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "path_id",
            "dimension",
            "methodology_version",
            name="uq_control_coverage_assertion_current",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "path_id"],
            ["control_coverage_paths.tenant_id", "control_coverage_paths.id"],
            name="fk_control_coverage_assertion_tenant_path",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "dimension IN ('discovery','identity','authorization','evidence','deployment','runtime','bypass','subject_binding','resource_binding','purpose_binding','authority_binding','parameter_binding','target_binding','destination_binding','approval_binding','execution_visibility','execution_verification','persistence_tracking','delegation_integrity','outcome_verification','external_capability_integrity')",
            name="ck_control_coverage_assertion_dimension",
        ),
        CheckConstraint(
            "state IN ('covered','not_covered','unknown','not_applicable')",
            name="ck_control_coverage_assertion_state",
        ),
        Index("idx_control_coverage_assertion_tenant_state", "tenant_id", "dimension", "state"),
        Index("idx_control_coverage_assertion_tenant_valid", "tenant_id", "valid_until"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    path_id: Mapped[str] = mapped_column(String(36), nullable=False)
    dimension: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    explanation: Mapped[str] = mapped_column(String(500), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    evaluator_version: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    source_watermark: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ControlCoverageSnapshot(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "control_coverage_snapshots"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_control_coverage_snapshot_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["coverage_scopes.tenant_id", "coverage_scopes.id"],
            name="fk_coverage_snapshot_tenant_scope",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "previous_snapshot_id"],
            ["control_coverage_snapshots.tenant_id", "control_coverage_snapshots.id"],
            name="fk_coverage_snapshot_tenant_previous",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id",
            "methodology_version",
            "window_start",
            "window_end",
            "input_digest",
            name="uq_control_coverage_snapshot_input",
        ),
        CheckConstraint(
            "headline_score IS NULL OR (headline_score >= 0 AND headline_score <= 100)",
            name="ck_control_coverage_snapshot_score",
        ),
        Index("idx_control_coverage_snapshot_tenant_time", "tenant_id", "computed_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    methodology_version: Mapped[str] = mapped_column(String(32), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    headline_counts: Mapped[dict] = mapped_column(JSON, nullable=False)
    headline_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    dimension_summaries: Mapped[dict] = mapped_column(JSON, nullable=False)
    input_watermarks: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    diagnostics: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    freshness_status: Mapped[str] = mapped_column(String(32), nullable=False, default="current")
    scope_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    previous_snapshot_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    snapshot_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="path_coverage")
    source_versions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    assessment_totals: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    applicable_requirement_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unknown_population: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    gap_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    comparison_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class CoverageScope(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "coverage_scopes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_coverage_scope_tenant_id"),
        UniqueConstraint("tenant_id", "scope_type", "scope_key", name="uq_coverage_scope_tenant_key"),
        CheckConstraint(
            "scope_type IN ('tenant','business_unit','department','application','asset','agent','provider','deployment_surface','environment','domain_profile','action_class','critical_action')",
            name="ck_coverage_scope_type",
        ),
        Index("idx_coverage_scope_tenant_type", "tenant_id", "scope_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scope_type: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_key: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    filters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class ControlCoverageAssessment(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "control_coverage_assessments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_control_coverage_assessment_tenant_id"),
        UniqueConstraint("tenant_id", "snapshot_id", "assessment_key", name="uq_coverage_assessment_snapshot_key"),
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["coverage_scopes.tenant_id", "coverage_scopes.id"],
            name="fk_coverage_assessment_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["control_coverage_snapshots.tenant_id", "control_coverage_snapshots.id"],
            name="fk_coverage_assessment_tenant_snapshot",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "applicability_state IN ('applicable','not_applicable','unknown')",
            name="ck_coverage_assessment_applicability",
        ),
        CheckConstraint(
            "deployment_state IN ('present','configured','missing','unknown')",
            name="ck_coverage_assessment_deployment",
        ),
        CheckConstraint(
            "capability_state IN ('verified','partial','unverified','experimental','unsupported','unknown')",
            name="ck_coverage_assessment_capability",
        ),
        CheckConstraint(
            "assurance_state IN ('current','stale','regressed','unknown')",
            name="ck_coverage_assessment_assurance",
        ),
        CheckConstraint(
            "coverage_state IN ('covered_current','covered_stale','partially_covered','configured_unvalidated','regressed','gap','unsupported','unknown','not_applicable')",
            name="ck_coverage_assessment_state",
        ),
        CheckConstraint(
            "criticality IN ('info','low','medium','high','critical')",
            name="ck_coverage_assessment_criticality",
        ),
        Index("idx_coverage_assessment_snapshot_state", "tenant_id", "snapshot_id", "coverage_state"),
        Index("idx_coverage_assessment_asset_action", "tenant_id", "asset_ref", "action_class"),
        Index("idx_coverage_assessment_surface_dimension", "tenant_id", "deployment_surface", "dimension"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assessment_key: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    action_class: Mapped[str] = mapped_column(String(128), nullable=False)
    action_path_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    domain_profile_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    deployment_surface: Mapped[str] = mapped_column(String(32), nullable=False)
    dimension: Mapped[str] = mapped_column(String(128), nullable=False)
    requirement_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    applicability_state: Mapped[str] = mapped_column(String(24), nullable=False)
    applicability_reason: Mapped[str] = mapped_column(String(512), nullable=False)
    deployment_state: Mapped[str] = mapped_column(String(24), nullable=False)
    capability_state: Mapped[str] = mapped_column(String(24), nullable=False)
    assurance_state: Mapped[str] = mapped_column(String(24), nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(64), nullable=False)
    coverage_state: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    explanation: Mapped[str] = mapped_column(String(1000), nullable=False)
    control_plan_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expected_control_points: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    contributing_control_points: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    missing_contributions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    bypass_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    validation_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    lineage_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    source_versions: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    criticality: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ControlCoverageGap(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "control_coverage_gaps"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "scope_id"],
            ["coverage_scopes.tenant_id", "coverage_scopes.id"],
            name="fk_coverage_gap_tenant_scope",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "snapshot_id"],
            ["control_coverage_snapshots.tenant_id", "control_coverage_snapshots.id"],
            name="fk_coverage_gap_tenant_snapshot",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "assessment_id"],
            ["control_coverage_assessments.tenant_id", "control_coverage_assessments.id"],
            name="fk_coverage_gap_tenant_assessment",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "snapshot_id", "assessment_id", name="uq_coverage_gap_assessment"),
        CheckConstraint("priority IN ('P0','P1','P2','P3')", name="ck_coverage_gap_priority"),
        CheckConstraint("status IN ('open','resolved')", name="ck_coverage_gap_status"),
        Index("idx_coverage_gap_snapshot_priority", "tenant_id", "snapshot_id", "priority"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    snapshot_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assessment_id: Mapped[str] = mapped_column(String(36), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    priority: Mapped[str] = mapped_column(String(2), nullable=False)
    cause: Mapped[str] = mapped_column(String(512), nullable=False)
    recommended_action: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    owner_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    remediation_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
