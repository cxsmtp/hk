from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class ScanResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_results"
    __table_args__ = (
        UniqueConstraint("tenant_id", "scan_id", name="uq_scan_results_tenant_scan"),
        Index("idx_scan_results_tenant_status", "tenant_id", "status"),
        Index("idx_scan_results_tenant_type", "tenant_id", "scan_type"),
        Index("idx_scan_results_tenant_start", "tenant_id", "start_time"),
        Index("idx_scan_results_tenant_scope", "tenant_id", "scope"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False, default="discovery")
    triggered_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    scope: Mapped[str] = mapped_column(String(64), nullable=False, default="global")
    parameters_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    start_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    end_time: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="running")
    summary_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    delta_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    snapshot_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
