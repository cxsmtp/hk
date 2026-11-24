from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


def _hash_check(column: str) -> str:
    stripped = column
    for character in "0123456789abcdef":
        stripped = f"replace({stripped}, '{character}', '')"
    return (
        f"length({column}) = 64 AND {column} = lower({column}) "
        f"AND {stripped} = ''"
    )


_USAGE_STATES = (
    "'never_observed','historical','occasional','active','high_usage','unknown'"
)
_ACTOR_TYPES = "'human','agent','service','workload','automation','unknown'"
_VERIFICATION_STATES = (
    "'verified','partially_verified','inferred','contradicted','stale','unknown'"
)
_FRESHNESS_STATES = "'fresh','stale','expired','unknown'"
_MANAGEMENT_CLASSES = (
    "'enterprise_managed','enterprise_approved','personal','unmanaged','unknown'"
)
_SHADOW_TYPES = (
    "'unapproved_ai_app','personal_ai_on_managed_device','direct_model_api',"
    "'unmanaged_agent','unknown_ai_workload','unapproved_model','unmanaged_mcp',"
    "'unapproved_saas_ai','unregistered_rag','unknown_vector_store'"
)
_SEVERITIES = "'none','low','medium','high','critical'"


class DiscoveryAssetUsageFact(Base):
    __tablename__ = "discovery_asset_usage_facts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_discovery_usage_tenant",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_usage_tenant_asset",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_usage_tenant_evidence",
            ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "usage_fact_id", name="uq_discovery_usage_tenant_id"
        ),
        UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_discovery_usage_tenant_idempotency",
        ),
        CheckConstraint(
            f"usage_state IN ({_USAGE_STATES})",
            name="ck_discovery_usage_state",
        ),
        CheckConstraint(
            f"actor_type IN ({_ACTOR_TYPES})",
            name="ck_discovery_usage_actor_type",
        ),
        CheckConstraint(
            "(actor_type = 'unknown' AND actor_reference_hash IS NULL) OR "
            "(actor_type <> 'unknown' AND actor_reference_hash IS NOT NULL)",
            name="ck_discovery_usage_actor_reference",
        ),
        CheckConstraint(
            f"verification_state IN ({_VERIFICATION_STATES})",
            name="ck_discovery_usage_verification",
        ),
        CheckConstraint(
            f"freshness IN ({_FRESHNESS_STATES})",
            name="ck_discovery_usage_freshness",
        ),
        CheckConstraint("event_count >= 0", name="ck_discovery_usage_count"),
        CheckConstraint(
            "first_observed_at IS NULL OR last_observed_at IS NULL OR "
            "first_observed_at <= last_observed_at",
            name="ck_discovery_usage_seen_order",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_usage_confidence",
        ),
        CheckConstraint(
            "length(trim(source_surface)) BETWEEN 1 AND 64",
            name="ck_discovery_usage_surface_bounded",
        ),
        CheckConstraint(
            "length(trim(methodology_id)) BETWEEN 1 AND 128",
            name="ck_discovery_usage_methodology_bounded",
        ),
        CheckConstraint(
            "length(trim(idempotency_key)) BETWEEN 1 AND 128",
            name="ck_discovery_usage_idempotency_bounded",
        ),
        CheckConstraint(
            _hash_check("input_digest"), name="ck_discovery_usage_digest"
        ),
        CheckConstraint(
            "actor_reference_hash IS NULL OR " + _hash_check("actor_reference_hash"),
            name="ck_discovery_usage_actor_hash",
        ),
        CheckConstraint(
            "length(CAST(limitations_json AS TEXT)) <= 4096",
            name="ck_discovery_usage_limitations_bytes",
        ),
        Index(
            "idx_discovery_usage_tenant_asset_seen",
            "tenant_id",
            "asset_id",
            "last_observed_at",
            "usage_fact_id",
        ),
        Index(
            "idx_discovery_usage_tenant_actor",
            "tenant_id",
            "actor_type",
            "actor_reference_hash",
            "usage_fact_id",
        ),
        Index(
            "idx_discovery_usage_tenant_state",
            "tenant_id",
            "usage_state",
            "freshness",
            "usage_fact_id",
        ),
    )

    usage_fact_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(32), nullable=False)
    actor_reference_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    usage_state: Mapped[str] = mapped_column(String(32), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    source_surface: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    freshness: Mapped[str] = mapped_column(String(32), nullable=False)
    telemetry_complete: Mapped[bool] = mapped_column(Boolean, nullable=False)
    methodology_id: Mapped[str] = mapped_column(String(128), nullable=False)
    limitations_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DiscoveryShadowClassification(Base):
    __tablename__ = "discovery_shadow_classifications"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_shadow_class_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_shadow_class_tenant_asset", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "primary_evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_shadow_class_tenant_evidence", ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "classification_id",
            name="uq_discovery_shadow_class_tenant_id",
        ),
        UniqueConstraint(
            "tenant_id", "idempotency_key",
            name="uq_discovery_shadow_class_tenant_idempotency",
        ),
        CheckConstraint(
            f"management_class IN ({_MANAGEMENT_CLASSES})",
            name="ck_discovery_shadow_class_management",
        ),
        CheckConstraint(
            f"shadow_type IN ({_SHADOW_TYPES})",
            name="ck_discovery_shadow_class_type",
        ),
        CheckConstraint(
            f"severity IN ({_SEVERITIES}) AND severity <> 'none'",
            name="ck_discovery_shadow_class_severity",
        ),
        CheckConstraint(
            f"verification_state IN ({_VERIFICATION_STATES})",
            name="ck_discovery_shadow_class_verification",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_shadow_class_confidence",
        ),
        CheckConstraint(
            "first_observed_at <= last_observed_at",
            name="ck_discovery_shadow_class_seen_order",
        ),
        CheckConstraint(
            "length(CAST(evidence_node_ids_json AS TEXT)) <= 8192",
            name="ck_discovery_shadow_class_evidence_bytes",
        ),
        CheckConstraint(
            "length(CAST(limitations_json AS TEXT)) <= 4096",
            name="ck_discovery_shadow_class_limitations_bytes",
        ),
        CheckConstraint(
            "length(trim(methodology_id)) BETWEEN 1 AND 128",
            name="ck_discovery_shadow_class_methodology_bounded",
        ),
        CheckConstraint(
            "length(trim(idempotency_key)) BETWEEN 1 AND 128",
            name="ck_discovery_shadow_class_idempotency_bounded",
        ),
        CheckConstraint(
            _hash_check("input_digest"), name="ck_discovery_shadow_class_digest"
        ),
        Index(
            "idx_discovery_shadow_class_tenant_asset",
            "tenant_id", "asset_id", "last_observed_at", "classification_id",
        ),
        Index(
            "idx_discovery_shadow_class_tenant_type",
            "tenant_id", "shadow_type", "severity", "classification_id",
        ),
    )

    classification_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    management_class: Mapped[str] = mapped_column(String(32), nullable=False)
    shadow_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    primary_evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evidence_node_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    methodology_id: Mapped[str] = mapped_column(String(128), nullable=False)
    limitations_json: Mapped[list] = mapped_column(
        JSON, server_default=text("'[]'"), nullable=False
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DiscoveryAssetFinding(Base):
    __tablename__ = "discovery_asset_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"],
            name="fk_discovery_finding_tenant", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "asset_id"],
            ["discovery_ai_assets.tenant_id", "discovery_ai_assets.asset_id"],
            name="fk_discovery_finding_tenant_asset", ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "primary_evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_discovery_finding_tenant_evidence", ondelete="RESTRICT",
        ),
        UniqueConstraint(
            "tenant_id", "finding_id", name="uq_discovery_finding_tenant_id"
        ),
        UniqueConstraint(
            "tenant_id", "dedupe_key", name="uq_discovery_finding_tenant_dedupe"
        ),
        CheckConstraint(
            f"severity IN ({_SEVERITIES}) AND severity <> 'none'",
            name="ck_discovery_finding_severity",
        ),
        CheckConstraint(
            f"verification_state IN ({_VERIFICATION_STATES})",
            name="ck_discovery_finding_verification",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="ck_discovery_finding_confidence",
        ),
        CheckConstraint(
            "first_seen_at <= last_seen_at",
            name="ck_discovery_finding_seen_order",
        ),
        CheckConstraint(
            "occurrence_count >= 1", name="ck_discovery_finding_occurrence"
        ),
        CheckConstraint(
            "status IN ('open','reviewing','resolved','accepted','dismissed')",
            name="ck_discovery_finding_status",
        ),
        CheckConstraint(
            "length(trim(finding_type)) BETWEEN 1 AND 64",
            name="ck_discovery_finding_type_bounded",
        ),
        CheckConstraint(
            "length(trim(remediation)) BETWEEN 1 AND 1000",
            name="ck_discovery_finding_remediation_bounded",
        ),
        CheckConstraint(
            "length(trim(verification_action)) BETWEEN 1 AND 1000",
            name="ck_discovery_finding_verification_action_bounded",
        ),
        CheckConstraint(
            "length(trim(coverage_impact)) BETWEEN 1 AND 1000",
            name="ck_discovery_finding_coverage_impact_bounded",
        ),
        CheckConstraint(
            "length(trim(dedupe_key)) BETWEEN 1 AND 128",
            name="ck_discovery_finding_dedupe_bounded",
        ),
        CheckConstraint(
            "length(CAST(evidence_node_ids_json AS TEXT)) <= 8192",
            name="ck_discovery_finding_evidence_bytes",
        ),
        Index(
            "idx_discovery_finding_tenant_asset",
            "tenant_id", "asset_id", "status", "finding_id",
        ),
        Index(
            "idx_discovery_finding_tenant_type",
            "tenant_id", "finding_type", "severity", "finding_id",
        ),
        Index(
            "idx_discovery_finding_tenant_seen",
            "tenant_id", "last_seen_at", "finding_id",
        ),
    )

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    verification_state: Mapped[str] = mapped_column(String(32), nullable=False)
    primary_evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    evidence_node_ids_json: Mapped[list] = mapped_column(JSON, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    remediation: Mapped[str] = mapped_column(String(1000), nullable=False)
    verification_action: Mapped[str] = mapped_column(String(1000), nullable=False)
    coverage_impact: Mapped[str] = mapped_column(String(1000), nullable=False)
    dedupe_key: Mapped[str] = mapped_column(String(128), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(
        Integer, server_default=text("1"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), server_default=text("'open'"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(),
        nullable=False,
    )


__all__ = [
    "DiscoveryAssetFinding",
    "DiscoveryAssetUsageFact",
    "DiscoveryShadowClassification",
]
