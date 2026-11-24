from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class RemediationAction(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "remediation_actions"
    __table_args__ = (
        Index("idx_remediation_tenant_status", "tenant_id", "status"),
        Index("idx_remediation_tenant_trigger", "tenant_id", "source_trigger_type"),
        Index("idx_remediation_tenant_target", "tenant_id", "target_type", "target_id"),
        Index("idx_remediation_tenant_risk", "tenant_id", "risk_level"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    remediation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str] = mapped_column(String(32), nullable=False)
    target_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_trigger_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_trigger_id: Mapped[str] = mapped_column(String(64), nullable=False)
    recommendation_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    action_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="recommend_only")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="proposed")
    risk_level: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approved_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    rollback_supported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rollback_payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
