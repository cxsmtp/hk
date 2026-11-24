from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class Connector(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "connectors"
    __table_args__ = (Index("idx_connector_tenant", "tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_key: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    auth_type: Mapped[str] = mapped_column(String(32), nullable=False, default="bearer")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    encrypted_secrets: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    kms_key_ref: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_stub: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    stub_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_pull_status: Mapped[str] = mapped_column(String(16), nullable=False, default="never")
    last_pull_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_signal_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    polling_interval_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=15)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    last_run_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)


class MonitoringSignal(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "monitoring_signals"
    __table_args__ = (Index("idx_signal_tenant_system", "tenant_id", "ai_system_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=True)
    signal_type: Mapped[str] = mapped_column(String(128), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DriftAlert(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "drift_alerts"
    __table_args__ = (Index("idx_drift_tenant_status", "tenant_id", "status"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    details: Mapped[str] = mapped_column(Text, default="", nullable=False)
