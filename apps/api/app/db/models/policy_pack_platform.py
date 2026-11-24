"""Tenant-safe catalog and lifecycle records for the Policy Pack Platform.

These records describe reusable policy-pack configuration and its customer
lineage.  They never contain executable code, secrets, prompts, or action
payloads.  The existing ``PolicyPack`` and ``PolicyVersion`` tables remain the
only runtime policy representation.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


PACKAGE_TIERS = ("secure", "control", "assurance", "enterprise")
PACK_DEFINITION_STATES = ("DRAFT", "PUBLISHED", "DEPRECATED", "WITHDRAWN")
PACK_INSTANCE_STATES = (
    "DRAFT",
    "SIMULATING",
    "REVIEW_REQUIRED",
    "MONITORING",
    "WARNING",
    "APPROVAL_ENFORCED",
    "ENFORCED",
    "PAUSED",
    "UPDATE_AVAILABLE",
    "CONFLICTED",
    "ROLLED_BACK",
    "EXPIRED",
)
GROUP_TYPES = (
    "scim",
    "static",
    "dynamic_attribute",
    "role_persona",
    "application_user",
    "privileged_user",
    "temporary_rollout",
    "security_behavior",
    "nested",
)
UPDATE_STATES = ("AVAILABLE", "ACCEPTED", "REJECTED", "CONFLICTED", "SUPERSEDED")
SIMULATION_STATES = ("PENDING", "PASSED", "PARTIAL", "FAILED")
EXCEPTION_STATES = ("REQUESTED", "APPROVED", "REJECTED", "REVOKED", "EXPIRED")


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class PolicyPackPlatformEntitlement(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_platform_entitlements"
    __table_args__ = (
        UniqueConstraint("tenant_id", name="uq_policy_pack_platform_entitlement_tenant"),
        CheckConstraint(f"package_tier IN ({_quoted(PACKAGE_TIERS)})", name="ck_policy_pack_platform_entitlement_tier"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    package_tier: Mapped[str] = mapped_column(String(16), nullable=False, default="secure")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class PolicyPackDefinition(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_definitions"
    __table_args__ = (
        UniqueConstraint("publisher_ref", "stable_pack_id", "version", name="uq_policy_pack_definition_publisher_version"),
        CheckConstraint(f"state IN ({_quoted(PACK_DEFINITION_STATES)})", name="ck_policy_pack_definition_state"),
        CheckConstraint(f"package_entitlement IN ({_quoted(PACKAGE_TIERS)})", name="ck_policy_pack_definition_entitlement"),
        Index("idx_policy_pack_definition_tenant", "publisher_tenant_id", "state"),
        Index("idx_policy_pack_definition_catalog", "stable_pack_id", "version", "state"),
    )

    # ``publisher_tenant_id`` is NULL only for vendor-owned configuration. A
    # tenant can read vendor definitions but can modify only its own rows.
    publisher_tenant_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True)
    publisher_ref: Mapped[str] = mapped_column(String(128), nullable=False, default="hawk")
    stable_pack_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    vertical: Mapped[str] = mapped_column(String(128), nullable=False, default="universal")
    department_persona: Mapped[str] = mapped_column(String(128), nullable=False, default="all")
    pack_family: Mapped[str] = mapped_column(String(128), nullable=False, default="general")
    maturity_status: Mapped[str] = mapped_column(String(32), nullable=False, default="draft")
    package_entitlement: Mapped[str] = mapped_column(String(16), nullable=False, default="secure")
    applicable_jurisdictions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    framework_mappings: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    inherited_pack_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    required_signals: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    required_control_capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    supported_deployment_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    default_parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    customization_schema: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    simulation_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    default_rollout: Mapped[str] = mapped_column(String(32), nullable=False, default="MONITORING")
    exception_guidance: Mapped[str] = mapped_column(Text, nullable=False, default="")
    known_blind_spots: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    owner_publisher: Mapped[str] = mapped_column(String(255), nullable=False, default="hawk")
    release_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="DRAFT")


class PolicyPackTemplate(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_templates"
    __table_args__ = (
        UniqueConstraint("definition_id", "template_id", name="uq_policy_pack_template_definition_template"),
        CheckConstraint(
            "decision IN ('allow','warn','block','redact','require_approval','require_justification','hold_for_approval')",
            name="ck_policy_pack_template_decision",
        ),
        Index("idx_policy_pack_template_definition", "definition_id", "template_id"),
    )

    definition_id: Mapped[str] = mapped_column(ForeignKey("policy_pack_definitions.id", ondelete="CASCADE"), nullable=False)
    template_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    condition_tree: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    obligations: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    applicable_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    required_fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    required_control_capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    default_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="monitor")
    recommended_mature_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="enforce")
    criticality: Mapped[str] = mapped_column(String(32), nullable=False, default="medium")
    override_behavior: Mapped[str] = mapped_column(String(64), nullable=False, default="customer_override_allowed")
    exception_rules: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    simulation_expectations: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    evidence_requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    human_explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    reference_mappings: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    non_overridable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    explicit_revocation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class PolicyPackInstance(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_instances"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_policy_pack_instance_tenant_id"),
        CheckConstraint(f"state IN ({_quoted(PACK_INSTANCE_STATES)})", name="ck_policy_pack_instance_state"),
        Index("idx_policy_pack_instance_tenant_state", "tenant_id", "state"),
        Index("idx_policy_pack_instance_definition", "tenant_id", "definition_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    definition_id: Mapped[str] = mapped_column(ForeignKey("policy_pack_definitions.id", ondelete="RESTRICT"), nullable=False)
    source_pack_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_pack_version: Mapped[str] = mapped_column(String(64), nullable=False)
    selected_vertical: Mapped[str] = mapped_column(String(128), nullable=False, default="universal")
    selected_department_persona: Mapped[str] = mapped_column(String(128), nullable=False, default="all")
    selected_applications: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    selected_surfaces: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    customer_parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    local_overrides: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    disabled_template_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    added_customer_templates: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rollout: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # PolicyPack IDs are globally unique UUIDs. Tenant binding is additionally
    # checked at every service lookup, rather than relying on a composite FK
    # that the legacy policy_packs table does not expose as a unique key.
    runtime_policy_pack_id: Mapped[str | None] = mapped_column(ForeignKey("policy_packs.id", ondelete="SET NULL"), nullable=True)
    effective_policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    previous_effective_policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    last_simulation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    update_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    owner_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    approver_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="DRAFT")
    lineage: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class PolicyPackAssignment(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_assignments"
    __table_args__ = (
        UniqueConstraint("tenant_id", "instance_id", "assignment_key", name="uq_policy_pack_assignment_key"),
        ForeignKeyConstraint(
            ["tenant_id", "instance_id"],
            ["policy_pack_instances.tenant_id", "policy_pack_instances.id"],
            name="fk_policy_pack_assignment_tenant_instance",
            ondelete="CASCADE",
        ),
        Index("idx_policy_pack_assignment_tenant_instance", "tenant_id", "instance_id", "active"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    assignment_key: Mapped[str] = mapped_column(String(64), nullable=False)
    targets: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    precedence_layer: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    inherited_path: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class PolicyPackUserGroup(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_user_groups"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_policy_pack_user_group_tenant_id"),
        UniqueConstraint("tenant_id", "group_key", name="uq_policy_pack_user_group_key"),
        CheckConstraint(f"group_type IN ({_quoted(GROUP_TYPES)})", name="ck_policy_pack_user_group_type"),
        Index("idx_policy_pack_user_group_tenant_type", "tenant_id", "group_type", "active"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    group_key: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    group_type: Mapped[str] = mapped_column(String(32), nullable=False)
    membership_rule: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    nested_group_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    source_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class PolicyPackGroupMembership(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_group_memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "group_id", "user_id", name="uq_policy_pack_group_membership"),
        ForeignKeyConstraint(
            ["tenant_id", "group_id"],
            ["policy_pack_user_groups.tenant_id", "policy_pack_user_groups.id"],
            name="fk_policy_pack_group_membership_tenant_group",
            ondelete="CASCADE",
        ),
        Index("idx_policy_pack_group_membership_user", "tenant_id", "user_id", "active"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    group_id: Mapped[str] = mapped_column(String(36), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    source: Mapped[str] = mapped_column(String(32), nullable=False, default="static")
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)


class PolicyPackUpdate(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_updates"
    __table_args__ = (
        UniqueConstraint("tenant_id", "instance_id", "new_definition_id", name="uq_policy_pack_update_instance_definition"),
        ForeignKeyConstraint(
            ["tenant_id", "instance_id"],
            ["policy_pack_instances.tenant_id", "policy_pack_instances.id"],
            name="fk_policy_pack_update_tenant_instance",
            ondelete="CASCADE",
        ),
        CheckConstraint(f"state IN ({_quoted(UPDATE_STATES)})", name="ck_policy_pack_update_state"),
        Index("idx_policy_pack_update_tenant_state", "tenant_id", "state"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    previous_definition_id: Mapped[str] = mapped_column(ForeignKey("policy_pack_definitions.id", ondelete="RESTRICT"), nullable=False)
    new_definition_id: Mapped[str] = mapped_column(ForeignKey("policy_pack_definitions.id", ondelete="RESTRICT"), nullable=False)
    comparison: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    requires_resimulation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="AVAILABLE")
    reviewed_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class PolicyPackSimulation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_simulations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "instance_id", "input_digest", name="uq_policy_pack_simulation_input"),
        ForeignKeyConstraint(
            ["tenant_id", "instance_id"],
            ["policy_pack_instances.tenant_id", "policy_pack_instances.id"],
            name="fk_policy_pack_simulation_tenant_instance",
            ondelete="CASCADE",
        ),
        CheckConstraint(f"status IN ({_quoted(SIMULATION_STATES)})", name="ck_policy_pack_simulation_state"),
        CheckConstraint("sample_count >= 0", name="ck_policy_pack_simulation_sample_count"),
        Index("idx_policy_pack_simulation_instance", "tenant_id", "instance_id", "created_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_version_id: Mapped[str | None] = mapped_column(ForeignKey("policy_versions.id", ondelete="SET NULL"), nullable=True)
    input_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    outcome_counts: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    scope_breakdown: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class PolicyPackException(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "policy_pack_exceptions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_policy_pack_exception_tenant_id"),
        ForeignKeyConstraint(
            ["tenant_id", "instance_id"],
            ["policy_pack_instances.tenant_id", "policy_pack_instances.id"],
            name="fk_policy_pack_exception_tenant_instance",
            ondelete="CASCADE",
        ),
        CheckConstraint(f"status IN ({_quoted(EXCEPTION_STATES)})", name="ck_policy_pack_exception_state"),
        Index("idx_policy_pack_exception_tenant_instance", "tenant_id", "instance_id", "status", "expires_at"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    instance_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    requested_by_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    approved_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="APPROVED")
