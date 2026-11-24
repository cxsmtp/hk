from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class AGUIDecision(Base):
    __tablename__ = "agui_decisions"
    __table_args__ = (
        Index("idx_agui_decisions_tenant_action", "tenant_id", "action_id"),
        Index("idx_agui_decisions_tenant_decided_at", "tenant_id", "decided_at"),
    )

    decision_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    evidence_node_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    audit_log_id: Mapped[str] = mapped_column(ForeignKey("audit_logs.id", ondelete="RESTRICT"), nullable=False)
    source_module: Mapped[str] = mapped_column(String(64), nullable=False, default="agui")
    source_object_type: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    source_object_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
