from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
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
    false,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin
from app.db.session import Base


def _portable_hash_check(column: str) -> str:
    stripped = column
    for character in "0123456789abcdef":
        stripped = f"replace({stripped}, '{character}', '')"
    return (
        f"length({column}) = 64 AND {column} = lower({column}) "
        f"AND {stripped} = ''"
    )


class DiscoveryTarget(Base, TimestampMixin):
    __tablename__ = "discovery_targets"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "target_id", name="uq_discovery_target_tenant_id"
        ),
        CheckConstraint(
            "target_type IN ("
            "'endpoint_group','browser_tenant','cloud_subscription',"
            "'cloud_project','kubernetes_cluster','saas_tenant',"
            "'identity_tenant','repository_org','repository','network_range',"
            "'dns_domain','api_gateway','database_platform',"
            "'ai_provider_account','mcp_environment','llm_gateway',"
            "'runtime_environment')",
            name="ck_discovery_target_type",
        ),
        CheckConstraint(
            "rate_limit >= 1 AND rate_limit <= 10000",
            name="ck_discovery_target_rate_limit",
        ),
        Index(
            "idx_discovery_target_tenant_type", "tenant_id", "target_type"
        ),
        Index(
            "idx_discovery_target_tenant_scanned",
            "tenant_id",
            "last_scanned_at",
        ),
    )

    target_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_hint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    credentials_reference: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    permitted_methods_json: Mapped[list] = mapped_column(JSON, nullable=False)
    exclusions_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    rate_limit: Mapped[int] = mapped_column(Integer, nullable=False)
    active_scan_allowed: Mapped[bool] = mapped_column(
        Boolean, server_default=false(), nullable=False
    )
    sensitive_scope: Mapped[bool] = mapped_column(
        Boolean, server_default=false(), nullable=False
    )
    coverage_baseline_json: Mapped[dict] = mapped_column(
        JSON, server_default=text("'{}'"), nullable=False
    )
    last_scanned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class DiscoveryCollector(Base, TimestampMixin):
    __tablename__ = "discovery_collectors"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "collector_id",
            name="uq_discovery_collector_tenant_id",
        ),
        CheckConstraint(
            "health IN ('healthy','warning','degraded','offline','unknown')",
            name="ck_discovery_collector_health",
        ),
        CheckConstraint(
            "control_capability IN "
            "('inline','warn_only','monitor_only','external_required','unknown')",
            name="ck_discovery_collector_control_capability",
        ),
        CheckConstraint(
            _portable_hash_check("declaration_hash"),
            name="ck_discovery_collector_declaration_hash",
        ),
        Index(
            "idx_discovery_collector_tenant_type",
            "tenant_id",
            "collector_type",
        ),
        Index(
            "idx_discovery_collector_tenant_health", "tenant_id", "health"
        ),
    )

    collector_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    collector_type: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    supported_targets_json: Mapped[list] = mapped_column(JSON, nullable=False)
    active_capabilities_json: Mapped[list] = mapped_column(JSON, nullable=False)
    passive_capabilities_json: Mapped[list] = mapped_column(JSON, nullable=False)
    permissions_required_json: Mapped[list] = mapped_column(JSON, nullable=False)
    sensitive_data_accessed_json: Mapped[list] = mapped_column(
        JSON, nullable=False
    )
    health: Mapped[str] = mapped_column(String(32), nullable=False)
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    data_residency: Mapped[str] = mapped_column(String(128), nullable=False)
    control_capability: Mapped[str] = mapped_column(String(32), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    limitations_json: Mapped[list] = mapped_column(JSON, nullable=False)
    declaration_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class DiscoveryScan(Base, TimestampMixin):
    __tablename__ = "discovery_scans"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "scan_id", name="uq_discovery_scan_tenant_id"
        ),
        UniqueConstraint(
            "tenant_id",
            "request_idempotency_key",
            name="uq_discovery_scan_tenant_request",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "rescan_of_scan_id"],
            ["discovery_scans.tenant_id", "discovery_scans.scan_id"],
            name="fk_discovery_scan_tenant_rescan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_scan_tenant_evidence_bundle",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "scan_type IN ('full_enterprise','targeted','incremental',"
            "'verification','scheduled','collector_specific')",
            name="ck_discovery_scan_type",
        ),
        CheckConstraint(
            "status IN ('queued','running','partially_complete','complete',"
            "'failed','cancelled')",
            name="ck_discovery_scan_status",
        ),
        CheckConstraint(
            "observations_count >= 0 AND assets_created >= 0 AND "
            "assets_updated >= 0 AND assets_unresolved >= 0",
            name="ck_discovery_scan_counters",
        ),
        CheckConstraint(
            _portable_hash_check("request_digest"),
            name="ck_discovery_scan_request_digest",
        ),
        CheckConstraint(
            "rescan_of_scan_id IS NULL OR rescan_of_scan_id <> scan_id",
            name="ck_discovery_scan_not_self_rescan",
        ),
        CheckConstraint(
            "(status = 'queued' AND started_at IS NULL AND completed_at IS NULL "
            "AND cancelled_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND "
            "completed_at IS NULL AND cancelled_at IS NULL) OR "
            "(status IN ('complete','partially_complete') AND "
            "started_at IS NOT NULL AND completed_at IS NOT NULL AND "
            "cancelled_at IS NULL) OR "
            "(status = 'failed' AND completed_at IS NOT NULL AND "
            "cancelled_at IS NULL) OR "
            "(status = 'cancelled' AND completed_at IS NULL AND "
            "cancelled_at IS NOT NULL)",
            name="ck_discovery_scan_lifecycle",
        ),
        Index("idx_discovery_scan_tenant_status", "tenant_id", "status"),
        Index(
            "idx_discovery_scan_tenant_created", "tenant_id", "created_at"
        ),
        Index(
            "idx_discovery_scan_tenant_rescan",
            "tenant_id",
            "rescan_of_scan_id",
        ),
    )

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    requested_by: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    safety_profile: Mapped[str] = mapped_column(String(64), nullable=False)
    request_idempotency_key: Mapped[str] = mapped_column(
        String(128), nullable=False
    )
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), server_default=text("'queued'"), nullable=False
    )
    dry_run: Mapped[bool] = mapped_column(
        Boolean, server_default=false(), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    observations_count: Mapped[int] = mapped_column(
        BigInteger, server_default=text("0"), nullable=False
    )
    assets_created: Mapped[int] = mapped_column(
        BigInteger, server_default=text("0"), nullable=False
    )
    assets_updated: Mapped[int] = mapped_column(
        BigInteger, server_default=text("0"), nullable=False
    )
    assets_unresolved: Mapped[int] = mapped_column(
        BigInteger, server_default=text("0"), nullable=False
    )
    warnings_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    errors_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    coverage_summary_json: Mapped[dict] = mapped_column(
        JSON, server_default=text("'{}'"), nullable=False
    )
    evidence_bundle_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )
    rescan_of_scan_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )


class DiscoveryScanTarget(Base, TimestampMixin):
    __tablename__ = "discovery_scan_targets"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "scan_id"],
            ["discovery_scans.tenant_id", "discovery_scans.scan_id"],
            name="fk_discovery_scan_target_tenant_scan",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "target_id"],
            ["discovery_targets.tenant_id", "discovery_targets.target_id"],
            name="fk_discovery_scan_target_tenant_target",
            ondelete="RESTRICT",
        ),
        Index(
            "idx_discovery_scan_target_tenant_target",
            "tenant_id",
            "target_id",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(128), primary_key=True)


class DiscoveryScanAssignment(Base, TimestampMixin):
    __tablename__ = "discovery_scan_assignments"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "assignment_id",
            name="uq_discovery_assignment_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id",
            "scan_id",
            "target_id",
            "collector_id",
            name="uq_discovery_assignment_tenant_work",
        ),
        UniqueConstraint(
            "tenant_id",
            "assignment_id",
            "scan_id",
            "target_id",
            "collector_id",
            name="uq_discovery_assignment_observation_parent",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scan_id", "target_id"],
            [
                "discovery_scan_targets.tenant_id",
                "discovery_scan_targets.scan_id",
                "discovery_scan_targets.target_id",
            ],
            name="fk_discovery_assignment_tenant_scan_target",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "collector_id"],
            [
                "discovery_collectors.tenant_id",
                "discovery_collectors.collector_id",
            ],
            name="fk_discovery_assignment_tenant_collector",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "status IN ('pending','running','complete','failed','cancelled',"
            "'unsupported','permission_denied','rate_limited','stale','empty')",
            name="ck_discovery_assignment_status",
        ),
        CheckConstraint(
            "observations_count >= 0",
            name="ck_discovery_assignment_observations_count",
        ),
        CheckConstraint(
            "(status = 'pending' AND started_at IS NULL AND "
            "completed_at IS NULL) OR "
            "(status = 'running' AND started_at IS NOT NULL AND "
            "completed_at IS NULL) OR "
            "(status IN ('complete','failed','cancelled','unsupported',"
            "'permission_denied','rate_limited','stale','empty') AND "
            "completed_at IS NOT NULL)",
            name="ck_discovery_assignment_lifecycle",
        ),
        Index(
            "idx_discovery_assignment_tenant_scan_status",
            "tenant_id",
            "scan_id",
            "status",
        ),
        Index(
            "idx_discovery_assignment_tenant_collector_status",
            "tenant_id",
            "collector_id",
            "status",
        ),
    )

    assignment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), server_default=text("'pending'"), nullable=False
    )
    warning: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    observations_count: Mapped[int] = mapped_column(
        BigInteger, server_default=text("0"), nullable=False
    )


class DiscoveryObservation(Base, TimestampMixin):
    __tablename__ = "discovery_observations"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "observation_id",
            name="uq_discovery_observation_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id",
            "scan_id",
            "collector_id",
            "idempotency_key",
            name="uq_discovery_observation_retry",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "scan_id"],
            ["discovery_scans.tenant_id", "discovery_scans.scan_id"],
            name="fk_discovery_observation_tenant_scan",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "target_id"],
            ["discovery_targets.tenant_id", "discovery_targets.target_id"],
            name="fk_discovery_observation_tenant_target",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "collector_id"],
            [
                "discovery_collectors.tenant_id",
                "discovery_collectors.collector_id",
            ],
            name="fk_discovery_observation_tenant_collector",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            [
                "tenant_id",
                "assignment_id",
                "scan_id",
                "target_id",
                "collector_id",
            ],
            [
                "discovery_scan_assignments.tenant_id",
                "discovery_scan_assignments.assignment_id",
                "discovery_scan_assignments.scan_id",
                "discovery_scan_assignments.target_id",
                "discovery_scan_assignments.collector_id",
            ],
            name="fk_discovery_observation_assignment_tuple",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_observation_confidence",
        ),
        CheckConstraint(
            "freshness IN ('fresh','stale','expired','unknown')",
            name="ck_discovery_observation_freshness",
        ),
        CheckConstraint(
            "source_surface IN ("
            "'endpoint','browser','cloud','saas','identity','source_code',"
            "'ci_cd','network','dns','api_gateway','service_mesh','mcp',"
            "'database','vector_store','model_endpoint','runtime',"
            "'kubernetes','container','unknown')",
            name="ck_discovery_observation_source_surface",
        ),
        CheckConstraint(
            "observed_state IN ("
            "'installed','configured','enabled','reachable','observed',"
            "'actively_used','inferred','unknown')",
            name="ck_discovery_observation_observed_state",
        ),
        CheckConstraint(
            "verification_state IN ("
            "'verified','partially_verified','inferred','contradicted',"
            "'stale','unknown')",
            name="ck_discovery_observation_verification_state",
        ),
        CheckConstraint(
            "source_trust IN ('strong','medium','weak','unknown')",
            name="ck_discovery_observation_source_trust",
        ),
        CheckConstraint(
            "evidence_mode IN ('direct','inferred','unknown')",
            name="ck_discovery_observation_evidence_mode",
        ),
        CheckConstraint(
            "evidence_mutability IN ('immutable','mutable','unknown')",
            name="ck_discovery_observation_evidence_mutability",
        ),
        CheckConstraint(
            "contradiction_state IN ("
            "'none','supported','contradicted','unresolved','unknown')",
            name="ck_discovery_observation_contradiction_state",
        ),
        CheckConstraint(
            _portable_hash_check("evidence_hash"),
            name="ck_discovery_observation_evidence_hash",
        ),
        CheckConstraint(
            _portable_hash_check("idempotency_key"),
            name="ck_discovery_observation_idempotency_key",
        ),
        CheckConstraint(
            _portable_hash_check("payload_digest"),
            name="ck_discovery_observation_payload_digest",
        ),
        Index(
            "idx_discovery_observation_tenant_scan_time",
            "tenant_id",
            "scan_id",
            "observed_at",
        ),
        Index(
            "idx_discovery_observation_tenant_collector_time",
            "tenant_id",
            "collector_id",
            "observed_at",
        ),
        Index(
            "idx_discovery_observation_tenant_type_time",
            "tenant_id",
            "observation_type",
            "observed_at",
        ),
        Index(
            "idx_discovery_observation_tenant_freshness_time",
            "tenant_id",
            "freshness",
            "observed_at",
        ),
        Index(
            "idx_discovery_observation_tenant_assignment",
            "tenant_id",
            "assignment_id",
        ),
        Index(
            "idx_discovery_observation_tenant_surface_time",
            "tenant_id",
            "source_surface",
            "observed_at",
        ),
        Index(
            "idx_discovery_observation_tenant_verification_time",
            "tenant_id",
            "verification_state",
            "observed_at",
        ),
    )

    observation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
    )
    assignment_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    collector_type: Mapped[str] = mapped_column(String(64), nullable=False)
    collector_version: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_surface: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_reference: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )
    normalized_signal_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    observation_type: Mapped[str] = mapped_column(String(128), nullable=False)
    candidate_asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    observed_state: Mapped[str] = mapped_column(String(32), nullable=False)
    identifiers_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    attributes_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    configuration_summary_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    usage_summary_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    capability_hints_json: Mapped[list] = mapped_column(JSON, nullable=False)
    identity_hints_json: Mapped[list] = mapped_column(JSON, nullable=False)
    relationship_hints_json: Mapped[list] = mapped_column(JSON, nullable=False)
    evidence_reference: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature_status: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    source_trust: Mapped[str] = mapped_column(String(16), nullable=False)
    collection_scope_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    parser_version: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_mode: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_mutability: Mapped[str] = mapped_column(String(16), nullable=False)
    contradiction_state: Mapped[str] = mapped_column(String(32), nullable=False)
    contradiction_references_json: Mapped[list] = mapped_column(
        JSON, nullable=False
    )
    sensitivity: Mapped[str] = mapped_column(String(32), nullable=False)
    redaction_status: Mapped[str] = mapped_column(String(32), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_digest: Mapped[str] = mapped_column(String(64), nullable=False)
