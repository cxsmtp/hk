from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class DiscoveryApplication(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "discovery_applications"
    __table_args__ = (
        UniqueConstraint("tenant_id", "tool_key", name="uq_discovery_app_tenant_tool"),
        Index("idx_discovery_apps_tenant_status", "tenant_id", "status"),
        Index("idx_discovery_apps_tenant_last_seen", "tenant_id", "last_seen_at"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    tool_key: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=False)
    vendor: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="discovered")

    owner_user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    owner_department: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    provisional_risk_tier: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    metadata_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
