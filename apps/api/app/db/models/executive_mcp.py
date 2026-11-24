from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class ExecutiveMCPDeviceAuthorization(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "executive_mcp_device_authorizations"
    __table_args__ = (
        Index("idx_exec_mcp_device_tenant_status", "tenant_id", "status"),
        Index("idx_exec_mcp_device_code_hash", "device_code_hash"),
        Index("idx_exec_mcp_user_code_hash", "user_code_hash"),
    )

    tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    role: Mapped[str | None] = mapped_column(String(32), nullable=True)
    client_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    scope: Mapped[str] = mapped_column(String(255), nullable=False)
    device_code_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    user_code_hash: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    denied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
