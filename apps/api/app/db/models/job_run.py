from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class ScheduledJobRun(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "scheduled_job_runs"
    __table_args__ = (
        Index("idx_scheduled_job_runs_job_started", "job_name", "started_at"),
        Index("idx_scheduled_job_runs_tenant", "tenant_id"),
    )

    job_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"),
        nullable=True,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
