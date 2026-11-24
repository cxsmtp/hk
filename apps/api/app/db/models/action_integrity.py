"""Additive persistence projections for Phase 5 V2 authority evidence."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, SmallInteger, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


class TenantPolicyEpoch(Base):
    __tablename__ = "tenant_policy_epochs"
    __table_args__ = (
        CheckConstraint("epoch > 0", name="ck_phase5_policy_epoch_positive"),
        CheckConstraint("state_version > 0", name="ck_phase5_policy_epoch_positive_state_version"),
        CheckConstraint(
            "(epoch = 1 AND state_version = 1 AND current_policy_snapshot_id IS NULL "
            "AND material_policy_digest IS NULL AND updated_by_principal_ref IS NULL "
            "AND reason_code IS NULL) OR "
            "(epoch > 1 AND state_version = epoch AND current_policy_snapshot_id IS NOT NULL "
            "AND material_policy_digest IS NOT NULL AND updated_by_principal_ref IS NOT NULL "
            "AND reason_code IS NOT NULL)",
            name="ck_phase5_policy_epoch_audit_complete",
        ),
    )
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    epoch: Mapped[int] = mapped_column(nullable=False, default=1)
    current_policy_snapshot_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    material_policy_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_by_principal_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class TenantActionIntegrityRollout(Base):
    __tablename__ = "tenant_action_integrity_rollouts"
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), primary_key=True)
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="DISABLED")
    policy_epoch: Mapped[int] = mapped_column(nullable=False, default=1)
    profile_selection_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class DomainSemanticProfileV2(Base):
    """Immutable signed profile material used by stored Phase 5 authority."""

    __tablename__ = "domain_semantic_profiles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "profile_id", "version", name="uq_phase5_profile_version"),
        UniqueConstraint("tenant_id", "profile_id", "version", "content_hash", name="uq_phase5_profile_version_content"),
        CheckConstraint("authority_binding_version IN (0, 1)", name="ck_phase5_profile_binding_version"),
        CheckConstraint(
            "(authority_binding_version = 0 AND issued_at IS NULL AND signed_envelope IS NULL) OR "
            "(authority_binding_version = 1 AND issued_at IS NOT NULL AND signed_envelope IS NOT NULL "
            "AND issued_at <= effective_at AND effective_at < expires_at)",
            name="ck_phase5_profile_v1_complete",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    authority_binding_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    effective_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class TenantDomainProfileSelectionV2(Base):
    """Append-only signed selection log; its projection is the current head."""

    __tablename__ = "tenant_domain_profile_selections"
    __table_args__ = (
        UniqueConstraint("tenant_id", "selection_id", name="uq_phase5_selection_id"),
        UniqueConstraint("tenant_id", "selection_id", "selection_hash", name="uq_phase5_selection_id_hash"),
        UniqueConstraint("tenant_id", "selection_id", "selection_hash", "selection_generation", name="uq_phase5_selection_id_hash_generation"),
        UniqueConstraint("tenant_id", "selection_id", "selection_hash", "selection_generation", "selection_sequence", name="uq_phase5_selection_id_hash_generation_sequence"),
        UniqueConstraint("tenant_id", "selection_generation", "selection_sequence", name="uq_phase5_selection_generation_sequence"),
        UniqueConstraint("tenant_id", "selection_generation", "prior_selection_id", name="uq_phase5_selection_prior_id"),
        ForeignKeyConstraint(
            ["tenant_id", "profile_id", "profile_version", "profile_content_hash"],
            [
                "domain_semantic_profiles.tenant_id",
                "domain_semantic_profiles.profile_id",
                "domain_semantic_profiles.version",
                "domain_semantic_profiles.content_hash",
            ],
            name="fk_phase5_selection_profile_content",
            ondelete="RESTRICT",
        ),
        CheckConstraint("authority_binding_version IN (0, 1)", name="ck_phase5_selection_binding_version"),
        CheckConstraint("selection_sequence > 0", name="ck_phase5_selection_positive_sequence_0069"),
        CheckConstraint("policy_epoch > 0", name="ck_phase5_selection_positive_epoch_0069"),
        CheckConstraint("selection_generation IN (0, 1)", name="ck_phase5_selection_generation"),
        CheckConstraint(
            "(authority_binding_version = 0 AND selection_generation = 0 AND issued_at IS NULL "
            "AND effective_at IS NULL AND expires_at IS NULL AND selected_by_principal_ref IS NULL "
            "AND reason_code IS NULL AND signed_envelope IS NULL AND selection_hash IS NULL) OR "
            "(authority_binding_version = 1 AND selection_generation = 1 AND issued_at IS NOT NULL "
            "AND effective_at IS NOT NULL AND expires_at IS NOT NULL "
            "AND selected_by_principal_ref IS NOT NULL AND reason_code IS NOT NULL "
            "AND signed_envelope IS NOT NULL AND selection_hash IS NOT NULL "
            "AND issued_at <= effective_at AND effective_at < expires_at)",
            name="ck_phase5_selection_v1_complete",
        ),
        CheckConstraint(
            "(selection_sequence = 1 AND prior_selection_id IS NULL AND prior_selection_hash IS NULL) OR "
            "(selection_sequence > 1 AND prior_selection_id IS NOT NULL AND prior_selection_hash IS NOT NULL)",
            name="ck_phase5_selection_prior_shape",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "prior_selection_id", "prior_selection_hash", "selection_generation"],
            [
                "tenant_domain_profile_selections.tenant_id",
                "tenant_domain_profile_selections.selection_id",
                "tenant_domain_profile_selections.selection_hash",
                "tenant_domain_profile_selections.selection_generation",
            ],
            name="fk_phase5_selection_prior_hash",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False)
    selection_id: Mapped[str] = mapped_column(String(36), nullable=False, default=lambda: str(uuid4()))
    selection_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    selection_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    selection_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    profile_version: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prior_selection_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    prior_selection_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    authority_binding_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    effective_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    selected_by_principal_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class TenantDomainProfileSelectionProjectionV2(Base):
    """Tenant-keyed CAS projection of the signed profile-selection head."""

    __tablename__ = "tenant_domain_profile_selection_projections_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "current_selection_id", "current_selection_hash", "current_selection_generation", "current_selection_sequence"],
            [
                "tenant_domain_profile_selections.tenant_id",
                "tenant_domain_profile_selections.selection_id",
                "tenant_domain_profile_selections.selection_hash",
                "tenant_domain_profile_selections.selection_generation",
                "tenant_domain_profile_selections.selection_sequence",
            ],
            name="fk_phase5_current_profile_selection_head",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "profile_id", "profile_version", "profile_content_hash"],
            [
                "domain_semantic_profiles.tenant_id",
                "domain_semantic_profiles.profile_id",
                "domain_semantic_profiles.version",
                "domain_semantic_profiles.content_hash",
            ],
            name="fk_phase5_current_profile_selection_profile",
            ondelete="RESTRICT",
        ),
        CheckConstraint("current_selection_sequence > 0", name="ck_phase5_current_selection_positive_sequence"),
        CheckConstraint("current_selection_generation = 1", name="ck_phase5_current_selection_generation"),
        CheckConstraint("policy_epoch > 0", name="ck_phase5_current_selection_positive_epoch"),
        CheckConstraint("state_version > 0", name="ck_phase5_current_selection_positive_state_version"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="RESTRICT"), primary_key=True)
    current_selection_id: Mapped[str] = mapped_column(String(36), nullable=False)
    current_selection_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    current_selection_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    current_selection_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    profile_id: Mapped[str] = mapped_column(String(128), nullable=False)
    profile_version: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class ExecutionPermitV2(Base):
    __tablename__ = "execution_permits_v2"
    __table_args__ = (
        UniqueConstraint("tenant_id", "permit_id", name="uq_execution_permits_v2_tenant_permit"),
        ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipt_v2_extensions.tenant_id", "decision_receipt_v2_extensions.receipt_id"],
            name="fk_phase5_permit_decision_extension",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "profile_selection_id", "profile_selection_hash"],
            [
                "tenant_domain_profile_selections.tenant_id",
                "tenant_domain_profile_selections.selection_id",
                "tenant_domain_profile_selections.selection_hash",
            ],
            name="fk_phase5_permit_profile_selection",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "control_selection_id"],
            ["native_control_selections.tenant_id", "native_control_selections.selection_id"],
            name="fk_phase5_permit_native_selection",
            ondelete="RESTRICT",
        ),
    )
    permit_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    material_fields_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False, default=lambda: str(uuid4()))
    decision_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    approval_binding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    permitted_variation_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_epoch: Mapped[int] = mapped_column(nullable=False, default=1)
    control_plan_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_plan_binding_type: Mapped[str] = mapped_column(String(32), nullable=False, default="STANDALONE")
    action_plan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action_plan_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action_plan_step_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action_plan_step_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False, default="HS256")
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False, default="development")
    signature: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    authority_binding_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    profile_selection_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    profile_selection_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_selection_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authoritative_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    authority_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decision_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="ISSUED")
    state_version: Mapped[int] = mapped_column(nullable=False, default=0)
    claim_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    claimed_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claim_lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reconstruction_status: Mapped[str] = mapped_column(String(16), nullable=False, default="VERIFIED")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ApprovalBindingV2Extension(Base):
    __tablename__ = "approval_binding_v2_extensions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "approval_request_id"],
            ["approval_requests.tenant_id", "approval_requests.id"],
            name="fk_phase5_approval_binding_request",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipt_v2_extensions.tenant_id", "decision_receipt_v2_extensions.receipt_id"],
            name="fk_phase5_approval_binding_decision_extension",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "control_selection_id"],
            ["native_control_selections.tenant_id", "native_control_selections.selection_id"],
            name="fk_phase5_approval_binding_native_selection",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "binding_id", name="uq_phase5_approval_binding_id"),
    )
    approval_request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(nullable=False)
    authority_binding_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    decision_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    binding_id: Mapped[str] = mapped_column(String(36), nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    material_fields_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    profile_selection_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    profile_selection_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_selection_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_plan_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_epoch: Mapped[int] = mapped_column(nullable=False)
    use_limit: Mapped[int] = mapped_column(nullable=False, default=1)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    permitted_variation_envelope_id: Mapped[str] = mapped_column(String(36), nullable=False)
    permitted_variation_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    permitted_variation_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    trusted_approval_rendering_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    binding_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)


class ApprovalAuthorityProjectionV2(Base):
    __tablename__ = "approval_authority_projections_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "approval_request_id"],
            ["approval_requests.tenant_id", "approval_requests.id"],
            name="fk_phase5_approval_projection_request",
            ondelete="CASCADE",
        ),
    )
    tenant_id: Mapped[str] = mapped_column(primary_key=True)
    approval_request_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    uses_consumed: Mapped[int] = mapped_column(nullable=False, default=0)
    state_version: Mapped[int] = mapped_column(nullable=False, default=0)
    reconstruction_status: Mapped[str] = mapped_column(String(16), nullable=False, default="VERIFIED")
    history_head_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    history_head_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    history_head_sequence: Mapped[int] = mapped_column(nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class ApprovalAuthorityEventV2(Base):
    """Immutable approval decision/use history; the projection is only a cache."""

    __tablename__ = "approval_authority_events_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "approval_request_id"],
            ["approval_requests.tenant_id", "approval_requests.id"],
            name="fk_phase5_approval_event_request",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "approval_request_id", "sequence", name="uq_phase5_approval_event_sequence"),
        UniqueConstraint("tenant_id", "approval_request_id", "idempotency_key", name="uq_phase5_approval_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    approval_request_id: Mapped[str] = mapped_column(String(36), nullable=False)
    binding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    decision: Mapped[str | None] = mapped_column(String(16), nullable=True)
    request_version: Mapped[int] = mapped_column(Integer, nullable=False)
    body_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    prior_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    prior_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ExecutionPermitAttemptV2(Base):
    __tablename__ = "execution_permit_attempts_v2"
    __table_args__ = (UniqueConstraint("tenant_id", "attempt_id", name="uq_phase5_attempt_tenant_attempt"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False, default=lambda: str(uuid4()))
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    material_fields_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ISSUED")
    action_plan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    action_plan_step_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    decision_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    execution_permit_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    terminal_execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ActionExecutionTransitionV2(Base):
    __tablename__ = "action_execution_transitions_v2"
    __table_args__ = (
        UniqueConstraint("tenant_id", "attempt_id", "sequence", name="uq_phase5_action_transition_sequence"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_phase5_action_transition_idempotency"),
        UniqueConstraint("tenant_id", "attempt_id", "id", name="uq_phase5_action_transition_attempt_id"),
        ForeignKeyConstraint(["tenant_id", "attempt_id"], ["execution_permit_attempts_v2.tenant_id", "execution_permit_attempts_v2.attempt_id"], name="fk_phase5_action_transition_attempt", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "attempt_id", "prior_transition_id"], ["action_execution_transitions_v2.tenant_id", "action_execution_transitions_v2.attempt_id", "action_execution_transitions_v2.id"], name="fk_phase5_action_transition_prior", ondelete="RESTRICT"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    prior_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    new_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    source_event_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    supersedes_transition_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    prior_transition_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    prior_transition_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ExecutionPermitTransitionV2(Base):
    __tablename__ = "execution_permit_transitions_v2"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "permit_id"], ["execution_permits_v2.tenant_id", "execution_permits_v2.permit_id"], name="fk_phase5_permit_transition", ondelete="CASCADE"),
        UniqueConstraint("tenant_id", "permit_id", "sequence", name="uq_phase5_permit_transition_sequence"),
        UniqueConstraint("tenant_id", "permit_id", "idempotency_key", name="uq_phase5_permit_transition_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    permit_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    prior_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    new_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    claim_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    claimed_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    claim_lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executor_invocation_state: Mapped[str] = mapped_column(String(32), nullable=False, default="NOT_INVOKED")
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ActionIntegrityDetailProjection(Base):
    """Durable product projection; source authority remains the linked records."""

    __tablename__ = "action_integrity_detail_projections"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "runtime_event_id"], ["runtime_events.tenant_id", "runtime_events.event_id"], name="fk_phase5_detail_runtime_event", ondelete="CASCADE"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    runtime_event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    projection: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source_watermark: Mapped[str] = mapped_column(String(128), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class DecisionReceiptV2Extension(Base):
    __tablename__ = "decision_receipt_v2_extensions"
    __table_args__ = (
        UniqueConstraint("tenant_id", "receipt_id", name="uq_phase5_decision_extension_tenant_receipt"),
        ForeignKeyConstraint(
            ["tenant_id", "receipt_id"],
            ["decision_receipts.tenant_id", "decision_receipts.receipt_id"],
            name="fk_phase5_decision_receipt_v2",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "profile_selection_id", "profile_selection_hash"],
            [
                "tenant_domain_profile_selections.tenant_id",
                "tenant_domain_profile_selections.selection_id",
                "tenant_domain_profile_selections.selection_hash",
            ],
            name="fk_phase5_decision_profile_selection",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "control_selection_id"],
            ["native_control_selections.tenant_id", "native_control_selections.selection_id"],
            name="fk_phase5_decision_native_selection",
            ondelete="RESTRICT",
        ),
    )
    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    material_fields_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    control_plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    authority_binding_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    profile_selection_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    profile_selection_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_selection_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    control_plan_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authoritative_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    authority_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decision_version: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ExecutionReceiptV2Extension(Base):
    __tablename__ = "execution_receipt_v2_extensions"
    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    permit_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actual_material_fields_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    terminal_state: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(32), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    effect_reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    effect_closure_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    provider_effect_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    effect_evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    recovery_sequence: Mapped[int | None] = mapped_column(Integer, nullable=True)


class ExecutionComparisonV2(Base):
    __tablename__ = "execution_comparisons_v2"
    __table_args__ = (UniqueConstraint("tenant_id", "attempt_id", name="uq_phase5_comparison_attempt"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    decision_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    material_differences: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    unresolved_fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ActionPlanV2(Base):
    __tablename__ = "action_plans_v2"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    parent_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    plan_version: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_boundary_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_boundary_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_boundary_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    max_total_executions: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    completion_rule: Mapped[str] = mapped_column(String(32), nullable=False, default="ALL_REQUIRED")
    compensation_action_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ActionPlanStepV2(Base):
    __tablename__ = "action_plan_steps_v2"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    step_id: Mapped[str] = mapped_column(String(36), nullable=False)
    step_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    step_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    child_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    unbound_material_fields_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_child_action_class: Mapped[str | None] = mapped_column(String(64), nullable=True)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    permitted_predecessor_step_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    max_executions: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    resource_boundary_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_boundary_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    destination_boundary_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    compensation_action_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)


class PersistentEffectV2(Base):
    __tablename__ = "persistent_effects_v2"
    __table_args__ = (UniqueConstraint("tenant_id", "id", name="uq_phase5_effect_tenant_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    downstream_object_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_object_state_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    owner_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_observed_object_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_quality: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovery_requires_remediation: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recovery_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation_attempt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    remediation_execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    remediation_outcome_verification_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    history_head_transition_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    history_head_transition_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    history_head_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reconstruction_status: Mapped[str] = mapped_column(String(16), nullable=False, default="VERIFIED")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class PersistentEffectTransitionV2(Base):
    __tablename__ = "persistent_effect_transitions_v2"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id", "effect_id"], ["persistent_effects_v2.tenant_id", "persistent_effects_v2.id"], name="fk_phase5_effect_transition", ondelete="CASCADE"),
        ForeignKeyConstraint(["tenant_id", "effect_id", "prior_transition_id"], ["persistent_effect_transitions_v2.tenant_id", "persistent_effect_transitions_v2.effect_id", "persistent_effect_transitions_v2.id"], name="fk_phase5_effect_transition_prior", ondelete="RESTRICT"),
        UniqueConstraint("tenant_id", "effect_id", "sequence", name="uq_phase5_effect_transition_sequence"),
        UniqueConstraint("tenant_id", "effect_id", "new_state_version", name="uq_phase5_effect_transition_state_version"),
        UniqueConstraint("tenant_id", "effect_id", "id", name="uq_phase5_effect_transition_effect_id"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_phase5_effect_transition_idempotency"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    effect_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    prior_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    new_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    prior_transition_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    prior_transition_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    transition_kind: Mapped[str] = mapped_column(String(32), nullable=False, default="STATE_CHANGE")
    observed_object_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence_quality: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_source_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verification_valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    recovery_basis: Mapped[str] = mapped_column(String(32), nullable=False, default="NONE")
    remediation_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    remediation_attempt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    remediation_execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    remediation_outcome_verification_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class DelegationContextV2(Base):
    __tablename__ = "delegation_contexts_v2"
    __table_args__ = (
        # The referenced key must precede the self-referential FK in the
        # migration as well as in metadata intended for native PostgreSQL DDL.
        UniqueConstraint("tenant_id", "delegation_context_id", "delegated_action_id", name="uq_phase5_delegation_context_action"),
        UniqueConstraint("tenant_id", "delegated_action_id", name="uq_phase5_delegated_action_context"),
        ForeignKeyConstraint(
            ["tenant_id", "parent_delegation_context_id", "parent_action_id"],
            [
                "delegation_contexts_v2.tenant_id",
                "delegation_contexts_v2.delegation_context_id",
                "delegation_contexts_v2.delegated_action_id",
            ],
            name="fk_phase5_delegation_parent_context",
            ondelete="RESTRICT",
        ),
        CheckConstraint("lineage_binding_version IN (0, 1)", name="ck_phase5_delegation_lineage_version"),
        CheckConstraint("depth > 0", name="ck_phase5_delegation_positive_depth"),
        CheckConstraint(
            "(lineage_binding_version = 0 AND parent_delegation_context_id IS NULL "
            "AND delegated_action_id IS NULL AND reconstruction_status = 'INVALID') "
            "OR (lineage_binding_version = 1 AND delegated_action_id IS NOT NULL "
            "AND length(trim(delegated_action_id)) > 0 AND "
            "((parent_delegation_context_id IS NULL AND depth = 1) OR "
            "(parent_delegation_context_id IS NOT NULL AND depth > 1 "
            "AND parent_delegation_context_id <> delegation_context_id)))",
            name="ck_phase5_delegation_lineage_binding",
        ),
        Index("ix_phase5_delegation_lineage_parent", "tenant_id", "parent_delegation_context_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    delegation_context_id: Mapped[str] = mapped_column(String(36), nullable=False)
    parent_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    parent_delegation_context_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    delegated_action_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lineage_binding_version: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    source_principal_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    destination_principal_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    authority_scope_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="REGISTERED")
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    history_head_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    history_head_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    history_head_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reconstruction_status: Mapped[str] = mapped_column(String(16), nullable=False, default="VERIFIED")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class DelegationLifecycleEventV2(Base):
    __tablename__ = "delegation_lifecycle_events_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "delegation_context_id"],
            ["delegation_contexts_v2.tenant_id", "delegation_contexts_v2.delegation_context_id"],
            name="fk_phase5_delegation_event_context",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "delegation_context_id", "prior_event_id"],
            [
                "delegation_lifecycle_events_v2.tenant_id",
                "delegation_lifecycle_events_v2.delegation_context_id",
                "delegation_lifecycle_events_v2.id",
            ],
            name="fk_phase5_delegation_event_prior",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "delegation_context_id", "sequence", name="uq_phase5_delegation_event_sequence"),
        UniqueConstraint("tenant_id", "delegation_context_id", "id", name="uq_phase5_delegation_event_context_id"),
        UniqueConstraint("tenant_id", "delegation_context_id", "new_state_version", name="uq_phase5_delegation_event_state_version"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_phase5_delegation_event_idempotency"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    delegation_context_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    prior_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    new_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    prior_event_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    prior_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    affected_unconsumed_descendant_refs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    evidence_refs: Mapped[list | None] = mapped_column(JSON, nullable=True)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ExpectedOutcomeV2(Base):
    __tablename__ = "expected_outcomes_v2"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    outcome_contract_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_state_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_deadline: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class OutcomeVerificationV2(Base):
    __tablename__ = "outcome_verifications_v2"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    verification_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    outcome_contract_id: Mapped[str] = mapped_column(String(36), nullable=False)
    execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    verification_source_set_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(32), nullable=False)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
