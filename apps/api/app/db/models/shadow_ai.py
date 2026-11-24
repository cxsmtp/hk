from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class ShadowAIEntity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "shadow_ai_entities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "canonical_name", name="uq_shadow_ai_entity_tenant_canonical"),
        Index("idx_shadow_ai_entities_tenant_status", "tenant_id", "discovery_status"),
        Index("idx_shadow_ai_entities_tenant_last_seen", "tenant_id", "last_seen"),
        Index("idx_shadow_ai_entities_tenant_linked", "tenant_id", "linked_ai_system_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    canonical_name: Mapped[str] = mapped_column(String(255), nullable=False)
    discovery_status: Mapped[str] = mapped_column(String(32), nullable=False, default="discovered")
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    provisional_risk_tier: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    source_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    vendor: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    deployment_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ai_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    linked_ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    approved_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_users: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    endpoints_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ShadowAISignal(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "shadow_ai_signals"
    __table_args__ = (
        Index("idx_shadow_ai_signals_tenant_surface", "tenant_id", "source_surface"),
        Index("idx_shadow_ai_signals_tenant_entity", "tenant_id", "shadow_ai_entity_id"),
        Index("idx_shadow_ai_signals_tenant_event", "tenant_id", "source_event_id"),
        Index("idx_shadow_ai_signals_tenant_created", "tenant_id", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    shadow_ai_entity_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("shadow_ai_entities.id", ondelete="SET NULL"),
        nullable=True,
    )
    source_surface: Mapped[str] = mapped_column(String(16), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    domain: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    model_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    tool_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    api_endpoint: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence_signal: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    raw_fingerprint: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ShadowAIUsage(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "shadow_ai_usage"
    __table_args__ = (
        Index("idx_shadow_ai_usage_tenant_asset", "tenant_id", "asset_id"),
        Index("idx_shadow_ai_usage_tenant_user", "tenant_id", "user_id"),
        Index("idx_shadow_ai_usage_tenant_endpoint", "tenant_id", "endpoint_id"),
        Index("idx_shadow_ai_usage_tenant_session", "tenant_id", "session_id"),
        Index("idx_shadow_ai_usage_tenant_time", "tenant_id", "timestamp"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[str] = mapped_column(ForeignKey("shadow_ai_entities.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    endpoint_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("deployment_endpoints.endpoint_id", ondelete="SET NULL"),
        nullable=True,
    )
    session_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_sessions.session_id", ondelete="SET NULL"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    interaction_type: Mapped[str] = mapped_column(String(32), nullable=False, default="browse")
    sensitivity_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    policy_triggered: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
