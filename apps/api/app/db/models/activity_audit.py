from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Float, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class UserRegistry(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "user_registry"
    __table_args__ = (
        UniqueConstraint("tenant_id", "user_id", name="uq_user_registry_tenant_user"),
        Index("idx_user_registry_tenant_email", "tenant_id", "email"),
        Index("idx_user_registry_tenant_last_seen", "tenant_id", "last_seen_at"),
        Index("idx_user_registry_tenant_risk", "tenant_id", "risk_score"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    email: Mapped[str] = mapped_column(String(320), nullable=False, default="")
    department: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    role: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    violation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    deployment_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class DeploymentEndpoint(Base):
    __tablename__ = "deployment_endpoints"
    __table_args__ = (
        Index("idx_deployment_endpoints_tenant_user", "tenant_id", "user_id"),
        Index("idx_deployment_endpoints_tenant_last_seen", "tenant_id", "last_seen_at"),
        Index("idx_deployment_endpoints_tenant_browser", "tenant_id", "browser_type"),
    )

    endpoint_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    os_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    os_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    browser_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    browser_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extension_version: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class AISession(Base):
    __tablename__ = "ai_sessions"
    __table_args__ = (
        Index("idx_ai_sessions_tenant_user", "tenant_id", "user_id"),
        Index("idx_ai_sessions_tenant_endpoint", "tenant_id", "endpoint_id"),
        Index("idx_ai_sessions_tenant_start", "tenant_id", "start_time"),
        Index("idx_ai_sessions_tenant_correlation", "tenant_id", "correlation_id"),
    )

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    endpoint_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("deployment_endpoints.endpoint_id", ondelete="SET NULL"),
        nullable=True,
    )
    source_surface: Mapped[str] = mapped_column(String(32), nullable=False, default="browser")
    ai_app: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ai_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    total_actions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class AIAction(Base):
    __tablename__ = "ai_actions"
    __table_args__ = (
        Index("idx_ai_actions_tenant_user_time", "tenant_id", "user_id", "timestamp"),
        Index("idx_ai_actions_tenant_endpoint_time", "tenant_id", "endpoint_id", "timestamp"),
        Index("idx_ai_actions_tenant_session_time", "tenant_id", "session_id", "timestamp"),
        Index("idx_ai_actions_tenant_enforcement", "tenant_id", "enforcement_action"),
        Index("idx_ai_actions_tenant_action_type", "tenant_id", "action_type"),
        Index("idx_ai_actions_tenant_correlation", "tenant_id", "correlation_id"),
        Index("idx_ai_actions_tenant_bundle", "tenant_id", "evidence_bundle_id"),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_ai_actions_tenant_bundle",
            ondelete="SET NULL",
        ),
    )

    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    session_id: Mapped[str] = mapped_column(ForeignKey("ai_sessions.session_id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    endpoint_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("deployment_endpoints.endpoint_id", ondelete="SET NULL"),
        nullable=True,
    )
    runtime_event_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("runtime_events.event_id", ondelete="SET NULL"),
        nullable=True,
    )
    monitoring_signal_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("monitoring_signals.id", ondelete="SET NULL"),
        nullable=True,
    )
    audit_log_id: Mapped[Optional[str]] = mapped_column(ForeignKey("audit_logs.id", ondelete="SET NULL"), nullable=True)
    evidence_node_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("evidence_nodes.id", ondelete="SET NULL"),
        nullable=True,
    )
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(ForeignKey("findings.finding_id", ondelete="SET NULL"), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    ai_app: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ai_model: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    data_classification: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    sensitivity_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    policy_triggered: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    enforcement_action: Mapped[str] = mapped_column(String(32), nullable=False, default="allowed")
    semantic_drift_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class PromptPayload(Base):
    __tablename__ = "prompt_payloads"

    action_id: Mapped[str] = mapped_column(
        ForeignKey("ai_actions.action_id", ondelete="CASCADE"),
        primary_key=True,
    )
    raw_prompt: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    redacted_prompt: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pii_detected: Mapped[bool] = mapped_column(nullable=False, default=False)
    sensitive_entities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    storage_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="redacted")
    prompt_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AIActionAlert(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "ai_action_alerts"
    __table_args__ = (
        Index("idx_ai_action_alerts_tenant_user", "tenant_id", "user_id"),
        Index("idx_ai_action_alerts_tenant_endpoint", "tenant_id", "endpoint_id"),
        Index("idx_ai_action_alerts_tenant_session", "tenant_id", "session_id"),
        Index("idx_ai_action_alerts_tenant_severity", "tenant_id", "severity"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(ForeignKey("ai_actions.action_id", ondelete="CASCADE"), nullable=False)
    session_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_sessions.session_id", ondelete="SET NULL"), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    endpoint_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("deployment_endpoints.endpoint_id", ondelete="SET NULL"),
        nullable=True,
    )
    finding_id: Mapped[Optional[str]] = mapped_column(ForeignKey("findings.finding_id", ondelete="SET NULL"), nullable=True)
    alert_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="med")
    policy_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    enforcement_action: Mapped[str] = mapped_column(String(32), nullable=False, default="warned")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
