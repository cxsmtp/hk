from __future__ import annotations

from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class EnforcementEvent(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "enforcement_events"
    __table_args__ = (
        Index("idx_enforcement_tenant_time", "tenant_id", "timestamp"),
        Index("idx_enforcement_correlation", "correlation_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(64), nullable=False)
    request_id: Mapped[str] = mapped_column(String(36), nullable=False, unique=True)
    timestamp: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    input_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    input_context_summary: Mapped[str] = mapped_column(Text, nullable=False)
    input_attachments_meta: Mapped[list] = mapped_column(JSON, default=list, nullable=False)

    guardian_results: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    final_decision: Mapped[str] = mapped_column(String(32), nullable=False)
    final_actions: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    evidence_nodes_created: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    controls_impacted: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    policy_version_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("policy_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    audit_log_id: Mapped[str] = mapped_column(ForeignKey("audit_logs.id", ondelete="RESTRICT"), nullable=False)
