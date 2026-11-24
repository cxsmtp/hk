from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class PolicyPack(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_packs"
    __table_args__ = (Index("idx_policy_pack_tenant", "tenant_id"),)

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")


class PolicyVersion(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "policy_versions"
    __table_args__ = (
        Index("idx_policy_version_pack", "pack_id"),
        Index("idx_policy_version_tenant", "tenant_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    pack_id: Mapped[str] = mapped_column(ForeignKey("policy_packs.id", ondelete="CASCADE"), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    scope: Mapped[dict] = mapped_column(JSON, nullable=False)
    enforcement_defaults: Mapped[dict] = mapped_column(JSON, nullable=False)
    guardian_contracts: Mapped[list] = mapped_column(JSON, nullable=False)
    contract_json: Mapped[dict] = mapped_column(JSON, nullable=False)


class ApprovalRequest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "approval_requests"
    __table_args__ = (
        Index("idx_approval_tenant_status", "tenant_id", "status"),
        UniqueConstraint("tenant_id", "id", name="uq_approval_requests_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipt_v2_extensions.tenant_id", "decision_receipt_v2_extensions.receipt_id"],
            name="fk_phase5_approval_request_decision_extension",
            ondelete="RESTRICT",
        ),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    enforcement_event_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    ai_system_id: Mapped[str] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=False)
    request_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    required_roles: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    sla_minutes: Mapped[int] = mapped_column(nullable=False, default=60)
    default_if_timeout: Mapped[str] = mapped_column(String(16), nullable=False, default="block")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    decided_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    decided_at: Mapped[Optional[str]] = mapped_column(DateTime(timezone=True), nullable=True)
    decision: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    # V1 approval authority is inseparable from its exact signed decision.
    # Legacy requests retain NULL and are never eligible for V2 decisions.
    decision_receipt_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    # Existing rows remain legacy when this nullable marker is absent.
    authority_schema_version: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    decision_version: Mapped[int] = mapped_column(nullable=False, default=0)


class GuardianContract(Base):
    __tablename__ = "guardian_contract"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger_conditions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    block_conditions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    mandatory_actions: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    escalation_path: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    evidence_requirements: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    framework_mappings: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ControlGuardianBinding(Base):
    __tablename__ = "control_guardian_binding"
    __table_args__ = (
        Index("idx_control_guardian_binding_control", "control_id"),
        Index("idx_control_guardian_binding_guardian", "guardian_contract_id"),
    )

    control_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    guardian_contract_id: Mapped[str] = mapped_column(
        ForeignKey("guardian_contract.id", ondelete="CASCADE"),
        primary_key=True,
    )
    enforcement_strength: Mapped[str] = mapped_column(String(16), nullable=False)


class GuardianContractV2(Base):
    __tablename__ = "guardian_contract_v2"
    __table_args__ = (
        Index("idx_guardian_contract_v2_tenant", "tenant_id"),
        UniqueConstraint("tenant_id", "id", name="uq_guardian_contract_v2_tenant_id"),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
    )
    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    version: Mapped[str] = mapped_column(String(16), nullable=False, default="2.0")
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger_conditions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    block_conditions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    mandatory_actions: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    escalation_path: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    evidence_requirements: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    framework_mappings: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    canonical_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[str] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class GuardianContractBindingV2(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "guardian_contract_binding_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "guardian_contract_id"],
            ["guardian_contract_v2.tenant_id", "guardian_contract_v2.id"],
            ondelete="CASCADE",
            name="fk_guardian_binding_v2_tenant_contract",
        ),
        Index("idx_guardian_binding_v2_tenant", "tenant_id"),
        Index("idx_guardian_binding_v2_guardian", "guardian_contract_id"),
        Index("idx_guardian_binding_v2_ai_system", "ai_system_id"),
        Index("idx_guardian_binding_v2_policy_version", "policy_version_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    guardian_contract_id: Mapped[str] = mapped_column(String(128), nullable=False)
    ai_system_id: Mapped[Optional[str]] = mapped_column(ForeignKey("ai_systems.id", ondelete="CASCADE"), nullable=True)
    policy_version_id: Mapped[Optional[str]] = mapped_column(ForeignKey("policy_versions.id", ondelete="CASCADE"), nullable=True)
    enforcement_strength: Mapped[str] = mapped_column(String(16), nullable=False, default="baseline")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class TenantSectorProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tenant_sector_profiles"
    __table_args__ = (
        Index("idx_tenant_sector_profiles_tenant", "tenant_id"),
        Index("idx_tenant_sector_profiles_tenant_sector", "tenant_id", "sector"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    sector: Mapped[str] = mapped_column(String(64), nullable=False, default="generic_enterprise")
    sub_sector: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    strictness: Mapped[str] = mapped_column(String(16), nullable=False, default="review")
    regulated_data_types: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    approved_business_purposes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    blocked_business_purposes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    approved_destinations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    blocked_destinations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    coding_policy_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    sql_policy_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    exception_policy_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)


class BusinessFunctionProfile(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "business_function_profiles"
    __table_args__ = (
        Index("idx_business_function_profiles_tenant", "tenant_id"),
        Index("idx_business_function_profiles_tenant_name", "tenant_id", "name"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    allowed_purposes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    blocked_purposes: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    allowed_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    review_required_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    blocked_actions: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    allowed_destinations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    blocked_destinations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    coding_policy_override: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    sql_policy_override: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    strictness_override: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)


class UserBusinessFunctionMapping(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "user_business_function_mappings"
    __table_args__ = (
        Index("idx_user_business_function_mappings_tenant", "tenant_id"),
        Index("idx_user_business_function_mappings_user", "tenant_id", "user_id"),
        Index("idx_user_business_function_mappings_email", "tenant_id", "email"),
        Index("idx_user_business_function_mappings_claim", "tenant_id", "claim_name", "claim_value"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(320), nullable=True)
    group_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    idp_group_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    claim_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    claim_value: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    business_function: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    role_name: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    department: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    team: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    policy_groups: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    priority: Mapped[int] = mapped_column(nullable=False, default=0)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class BusinessPurposeSession(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "business_purpose_sessions"
    __table_args__ = (
        Index("idx_business_purpose_sessions_tenant_user", "tenant_id", "user_id"),
        Index("idx_business_purpose_sessions_tenant_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    declared_purpose: Mapped[str] = mapped_column(Text, default="", nullable=False)
    purpose_category: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    business_function: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    approved_scope: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")


class PurposeException(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "purpose_exceptions"
    __table_args__ = (
        Index("idx_purpose_exceptions_tenant_user", "tenant_id", "user_id"),
        Index("idx_purpose_exceptions_tenant_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    business_function: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    requested_purpose: Mapped[str] = mapped_column(Text, default="", nullable=False)
    requested_action: Mapped[str] = mapped_column(String(128), nullable=False, default="unknown")
    justification: Mapped[str] = mapped_column(Text, default="", nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ApprovalBinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "approval_bindings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_approval_bindings_tenant_id"),
        Index("idx_approval_bindings_tenant_chain", "tenant_id", "chain_id"),
        Index("idx_approval_bindings_tenant_approval", "tenant_id", "approval_id"),
        Index("idx_approval_bindings_tenant_status", "tenant_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    approval_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    receipt_material_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    signed_receipt: Mapped[str] = mapped_column(String(128), nullable=False)
    material_fields: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    approver_user_id: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    invalidation_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)


class ToolFingerprint(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tool_fingerprints"
    __table_args__ = (
        UniqueConstraint("tenant_id", "mcp_server_id", "tool_name", "tool_version", name="uq_tool_fingerprint_version"),
        Index("idx_tool_fingerprints_tenant_tool", "tenant_id", "tool_name"),
        Index("idx_tool_fingerprints_tenant_status", "tenant_id", "trust_status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    mcp_server_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(64), nullable=False, default="unknown")
    manifest_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    description_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    schema_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    examples_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    trust_status: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    last_scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    approved_by: Mapped[Optional[str]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class ToolScanResult(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tool_scan_results"
    __table_args__ = (
        Index("idx_tool_scan_results_tenant_tool", "tenant_id", "tool_name"),
        Index("idx_tool_scan_results_tenant_chain", "tenant_id", "chain_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    chain_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    tool_fingerprint_id: Mapped[str] = mapped_column(ForeignKey("tool_fingerprints.id", ondelete="CASCADE"), nullable=False)
    mcp_server_id: Mapped[str] = mapped_column(String(128), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    trust_status: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_factors: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    evidence_node_id: Mapped[Optional[str]] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="SET NULL"), nullable=True)
