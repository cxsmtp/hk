from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class ExternalRiskSource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "external_risk_sources"
    __table_args__ = (
        Index("idx_external_risk_source_tenant", "tenant_id"),
        Index("idx_external_risk_source_tenant_enabled", "tenant_id", "enabled"),
        UniqueConstraint("tenant_id", "source", name="uq_external_risk_source_tenant_source"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    endpoint_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    auth_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="none")
    auth_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    source_trust_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    egress_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    redaction_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    routing_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    transport_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    sync_schedule: Mapped[str] = mapped_column(String(64), nullable=False, default="0 * * * *")
    last_sync_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_status: Mapped[str] = mapped_column(String(24), nullable=False, default="never")
    last_sync_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class ExternalRiskSyncRun(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "external_risk_sync_runs"
    __table_args__ = (
        Index("idx_external_risk_sync_tenant", "tenant_id"),
        Index("idx_external_risk_sync_tenant_started", "tenant_id", "started_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("external_risk_sources.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="running")
    started_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    records_ingested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mappings_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    alerts_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    simulation_recommendations_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    transport_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    trace_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class ExternalRiskRecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "external_risk_records"
    __table_args__ = (
        Index("idx_external_risk_record_tenant", "tenant_id"),
        Index("idx_external_risk_record_tenant_severity", "tenant_id", "severity"),
        Index("idx_external_risk_record_tenant_exploit", "tenant_id", "exploit_status"),
        Index("idx_external_risk_record_tenant_updated", "tenant_id", "source_updated_at"),
        UniqueConstraint("tenant_id", "source", "source_record_id", name="uq_external_risk_record_tenant_source_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("external_risk_sources.id", ondelete="SET NULL"),
        nullable=True,
    )
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="med")
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    exploit_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    affected_components: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    affected_versions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    published_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    source_updated_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False, default="partial")
    ingestion_trace_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    raw_artifact_ref: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    raw_payload_ref: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class ExternalRiskAssetMapping(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "external_risk_asset_mappings"
    __table_args__ = (
        Index("idx_external_risk_map_tenant", "tenant_id"),
        Index("idx_external_risk_map_record", "risk_record_id"),
        Index("idx_external_risk_map_asset", "tenant_id", "asset_type", "asset_id"),
        UniqueConstraint(
            "tenant_id",
            "risk_record_id",
            "asset_type",
            "asset_id",
            "environment",
            name="uq_external_risk_mapping_unique",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    risk_record_id: Mapped[str] = mapped_column(ForeignKey("external_risk_records.id", ondelete="CASCADE"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mapping_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    control_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    simulation_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    mapping_status: Mapped[str] = mapped_column(String(24), nullable=False, default="auto")


class ExternalRiskImpact(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "external_risk_impacts"
    __table_args__ = (
        Index("idx_external_risk_impact_tenant", "tenant_id"),
        Index("idx_external_risk_impact_record", "risk_record_id"),
        Index("idx_external_risk_impact_asset", "tenant_id", "asset_type", "asset_id"),
        UniqueConstraint(
            "tenant_id",
            "risk_record_id",
            "asset_type",
            "asset_id",
            name="uq_external_risk_impact_unique",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    risk_record_id: Mapped[str] = mapped_column(ForeignKey("external_risk_records.id", ondelete="CASCADE"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(128), nullable=False)
    likelihood: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    impact: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    annualized_loss_expectancy: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    residual_risk: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    calculation_context: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class RiskTriggeredSimulationRecommendation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "risk_triggered_simulation_recommendations"
    __table_args__ = (
        Index("idx_external_risk_simrec_tenant", "tenant_id"),
        Index("idx_external_risk_simrec_record", "risk_record_id"),
        Index("idx_external_risk_simrec_status", "tenant_id", "status"),
        UniqueConstraint("tenant_id", "risk_record_id", name="uq_external_risk_simrec_unique"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    risk_record_id: Mapped[str] = mapped_column(ForeignKey("external_risk_records.id", ondelete="CASCADE"), nullable=False)
    priority: Mapped[str] = mapped_column(String(16), nullable=False, default="med")
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    control_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    simulation_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="recommended")
    run_mode: Mapped[str] = mapped_column(String(24), nullable=False, default="manual")
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    recommendation_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
