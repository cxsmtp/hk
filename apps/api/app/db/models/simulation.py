from __future__ import annotations

from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, JSON, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class Control(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "controls"
    __table_args__ = (
        Index("idx_control_tenant", "tenant_id"),
        Index("idx_control_tenant_category", "tenant_id", "category"),
    )

    # ``Control.id`` is a stable business identifier (for example
    # ``PROMPT_INJECTION_DETECTION``), so it is only unique within a tenant.
    # Override the UUID mixin's single-column primary key with a composite key.
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    is_global: Mapped[bool] = mapped_column(default=False, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    mapped_framework_refs: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    risk_tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="med")
    enforcement_points: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    detection_methods: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    response_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    evidence_types: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    remediation_templates: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    success_criteria: Mapped[dict] = mapped_column(
        JSON,
        default=lambda: {
            "required_sim_pass_rate": 0.8,
            "required_evidence_sources": ["telemetry", "simulation", "config"],
            "min_maturity": 3,
        },
        nullable=False,
    )


class SimulationDefinition(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_definitions"
    __table_args__ = (Index("idx_sim_def_tenant", "tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    target_module: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    dsl_json: Mapped[dict] = mapped_column(JSON, nullable=False)


class SimulationTemplate(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_templates"
    __table_args__ = (Index("idx_sim_template_tenant", "tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    target_module: Mapped[str] = mapped_column(String(64), nullable=False)
    version_prefix: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0")
    parameter_schema: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    template_body: Mapped[dict] = mapped_column(JSON, nullable=False)
    generation_defaults: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class SimulationRun(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "simulation_runs"
    __table_args__ = (
        Index("idx_sim_run_tenant", "tenant_id"),
        Index("idx_sim_run_correlation", "correlation_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    simulation_id: Mapped[str] = mapped_column(ForeignKey("simulation_definitions.id", ondelete="CASCADE"), nullable=False)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    started_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    finished_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    inputs_used: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    results: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    controls_impacted: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)


class SimulationExecutionStep(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_execution_steps"
    __table_args__ = (
        Index("idx_sim_exec_step_tenant_run", "tenant_id", "simulation_run_id"),
        Index("idx_sim_exec_step_run_iteration_order", "simulation_run_id", "iteration_index", "step_order"),
        Index("idx_sim_exec_step_tenant_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    simulation_run_id: Mapped[str] = mapped_column(
        ForeignKey("simulation_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    iteration_index: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    step_id: Mapped[str] = mapped_column(String(64), nullable=False)
    step_order: Mapped[int] = mapped_column(Integer, nullable=False)
    step_type: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    timestamp_started: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    timestamp_completed: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    actor: Mapped[str] = mapped_column(String(64), nullable=False, default="evaluator")
    target_surface: Mapped[str] = mapped_column(String(32), nullable=False, default="monitoring")
    input_payload_ref: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    output_payload_ref: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    control_refs: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    decision_ref: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)


class SimulationPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_policies"
    __table_args__ = (
        Index("idx_sim_policy_tenant", "tenant_id"),
        Index("idx_sim_policy_tenant_active", "tenant_id", "active"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    enabled_categories: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    enabled_surfaces: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    blocked_categories: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    minimum_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="low")
    require_approval_for: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    allowed_execution_modes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    environment_scope: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    tenant_isolation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    evidence_retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)
    max_parallel_runs: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    notify_on_fail: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    framework_filters: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    control_filters: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class SimulationExecutor(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_executors"
    __table_args__ = (
        Index("idx_sim_executor_tenant", "tenant_id"),
        Index("idx_sim_executor_tenant_status", "tenant_id", "status"),
        Index("idx_sim_executor_name", "name"),
    )

    tenant_id: Mapped[Optional[str]] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    is_global: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    supported_surfaces: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    supported_categories: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    supported_simulation_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="active")
    evidence_types: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    requires: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class SimulationCatalogEntry(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_catalog_entries"
    __table_args__ = (
        Index("idx_sim_catalog_tenant", "tenant_id"),
        Index("idx_sim_catalog_tenant_category", "tenant_id", "category"),
        Index("idx_sim_catalog_tenant_exec_status", "tenant_id", "executable_status"),
        Index("idx_sim_catalog_tenant_simulation_id", "tenant_id", "simulation_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    simulation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    subcategory: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="med")
    control_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    framework_mappings: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    target_surface: Mapped[str] = mapped_column(String(32), nullable=False, default="gateway")
    executable_status: Mapped[str] = mapped_column(String(32), nullable=False, default="not_yet_executable")
    required_executor: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    defined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    implemented: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0")


class SimulationScheduleDecision(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "simulation_schedule_decisions"
    __table_args__ = (
        Index("idx_sim_schedule_tenant_reason", "tenant_id", "reason_code", "scheduled_at"),
        Index("idx_sim_schedule_tenant_ai_system", "tenant_id", "target_ai_system_id"),
        Index("idx_sim_schedule_tenant_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    target_ai_system_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("ai_systems.id", ondelete="SET NULL"),
        nullable=True,
    )
    target_control_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    trigger_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="scheduled")
    scheduled_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    scheduled_simulation_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    simulation_run_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    execution_summary: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
