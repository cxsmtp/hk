from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import UUIDPrimaryKeyMixin
from app.db.session import Base


class AIReasoningTrace(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "ai_reasoning_traces"
    __table_args__ = (
        Index("idx_ai_reasoning_trace_tenant_created", "tenant_id", "created_at"),
        Index("idx_ai_reasoning_trace_tenant_task", "tenant_id", "task_type"),
        Index("idx_ai_reasoning_trace_tenant_issue", "tenant_id", "issue_type", "issue_id"),
        Index("idx_ai_reasoning_trace_tenant_policy", "tenant_id", "routing_policy_id"),
        Index("idx_ai_reasoning_trace_tenant_control", "tenant_id", "control_id"),
        Index("idx_ai_reasoning_trace_tenant_corr", "tenant_id", "correlation_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    actor_user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    issue_type: Mapped[str] = mapped_column(String(64), nullable=False)
    issue_id: Mapped[str] = mapped_column(String(128), nullable=False)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    model_version: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    prompt_template_id: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_template_version: Mapped[str] = mapped_column(String(32), nullable=False, default="v1")
    prompt_template_status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    prompt_variables_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    retrieval_refs_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    retrieval_source_ids_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    runtime_event_refs_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    policy_version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    governance_version: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    control_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    control_decision_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    simulation_result_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    routing_context_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    risk_context_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    remediation_impact_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    routing_policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_route_id: Mapped[str] = mapped_column(String(128), nullable=False)
    region_route: Mapped[str] = mapped_column(String(64), nullable=False, default="global")
    pre_call_guard_results_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    post_call_guard_results_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    output_schema_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    token_usage_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    cost_estimate_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    output_json: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
