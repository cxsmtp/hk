from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin
from app.db.session import Base


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        Index("idx_findings_tenant_status", "tenant_id", "status"),
        Index("idx_findings_tenant_severity", "tenant_id", "severity"),
        Index("idx_findings_tenant_type", "tenant_id", "finding_type"),
        Index("idx_findings_tenant_system", "tenant_id", "ai_system_id"),
        Index("idx_findings_tenant_agent", "tenant_id", "agent_id"),
        Index("idx_findings_tenant_machine", "tenant_id", "machine_id"),
        Index("idx_findings_tenant_decision", "tenant_id", "decision"),
        Index("idx_findings_tenant_dedupe", "tenant_id", "dedupe_key"),
        Index("idx_findings_tenant_canonical_action", "tenant_id", "canonical_action_id"),
        Index("idx_findings_tenant_execution_attempt", "tenant_id", "execution_attempt_id"),
    )

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    source_surface: Mapped[str] = mapped_column(String(16), nullable=False)
    ai_tool: Mapped[str] = mapped_column(String(128), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="SET NULL"), nullable=True)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    machine_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    user_email: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)
    browser_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    application: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    risk_category: Mapped[str] = mapped_column(String(64), nullable=False)
    data_classification: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False, default="")
    policy_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    policy_version_id: Mapped[Optional[str]] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    evidence_node_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    related_event_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    related_control_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    remediation_action_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_status: Mapped[str] = mapped_column(String(16), nullable=False, default="complete")
    related_runtime_event_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    canonical_action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    execution_attempt_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    dedupe_key: Mapped[str] = mapped_column(String(128), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
