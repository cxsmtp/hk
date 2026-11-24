"""Durable provider-effect closure state beside the V2 execution permit authority."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, Integer, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base


EFFECT_CLOSURE_STATES = (
    "RESERVED",
    "PREPARED",
    "COMMITTING",
    "COMMITTED",
    "AMBIGUOUS",
    "CERTIFIED_NO_EFFECT",
    "FAILED",
    "CANCELLED",
    "TERMINAL",
)


class EffectDeliveryFenceV2(Base):
    __tablename__ = "effect_delivery_fences_v2"
    __table_args__ = (
        UniqueConstraint("tenant_id", "effect_identity_hash", name="uq_effect_fence_tenant_identity"),
        UniqueConstraint("tenant_id", "id", name="uq_effect_fence_tenant_id"),
        CheckConstraint("state_version > 0", name="ck_effect_fence_state_version"),
        Index("idx_effect_fence_tenant_state", "tenant_id", "state"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    effect_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    active_reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())


class EffectReservationV2(Base):
    __tablename__ = "effect_reservations_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "fence_id"],
            ["effect_delivery_fences_v2.tenant_id", "effect_delivery_fences_v2.id"],
            name="fk_effect_reservation_fence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "execution_permit_id"],
            ["execution_permits_v2.tenant_id", "execution_permits_v2.permit_id"],
            name="fk_effect_reservation_permit",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "predecessor_reservation_id"],
            ["effect_reservations_v2.tenant_id", "effect_reservations_v2.id"],
            name="fk_effect_reservation_predecessor",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_effect_reservation_tenant_id"),
        UniqueConstraint("tenant_id", "execution_permit_id", name="uq_effect_reservation_permit"),
        CheckConstraint("state_version > 0", name="ck_effect_reservation_state_version"),
        CheckConstraint("history_head_sequence > 0", name="ck_effect_reservation_history_sequence"),
        Index("idx_effect_reservation_tenant_state", "tenant_id", "state"),
        Index("idx_effect_reservation_tenant_identity", "tenant_id", "effect_identity_hash"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    fence_id: Mapped[str] = mapped_column(String(36), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    material_fields_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_receipt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    approval_binding_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    execution_permit_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    actor_principal_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    executing_principal_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    represented_subject_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    authority_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    target_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    destination_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    value_hashes: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    side_effect: Mapped[str] = mapped_column(String(128), nullable=False)
    persistence: Mapped[str] = mapped_column(String(64), nullable=False)
    effect_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    effect_manifest: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    manifest_match_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="EXACT")
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="RESERVED")
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    closure_outcome: Mapped[str | None] = mapped_column(String(32), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    provider_idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_effect_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    worker_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    predecessor_reservation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    successor_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    prior_terminal_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    no_effect_evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    material_differences: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    last_execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    history_head_transition_id: Mapped[str] = mapped_column(String(36), nullable=False)
    history_head_transition_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    history_head_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    reconstruction_status: Mapped[str] = mapped_column(String(16), nullable=False, default="VERIFIED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    terminal_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EffectReservationTransitionV2(Base):
    __tablename__ = "effect_reservation_transitions_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "reservation_id"],
            ["effect_reservations_v2.tenant_id", "effect_reservations_v2.id"],
            name="fk_effect_transition_reservation",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "reservation_id", "prior_transition_id"],
            ["effect_reservation_transitions_v2.tenant_id", "effect_reservation_transitions_v2.reservation_id", "effect_reservation_transitions_v2.id"],
            name="fk_effect_transition_prior",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "reservation_id", "id", name="uq_effect_transition_reservation_id"),
        UniqueConstraint("tenant_id", "reservation_id", "sequence", name="uq_effect_transition_sequence"),
        UniqueConstraint("tenant_id", "reservation_id", "new_state_version", name="uq_effect_transition_state_version"),
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_effect_transition_idempotency"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reservation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    prior_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    new_state_version: Mapped[int] = mapped_column(Integer, nullable=False)
    prior_transition_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    prior_transition_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    worker_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider_effect_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_receipt_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    evidence_quality: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class ExecutionPermitEffectBindingV2(Base):
    __tablename__ = "execution_permit_effect_bindings_v2"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "permit_id"],
            ["execution_permits_v2.tenant_id", "execution_permits_v2.permit_id"],
            name="fk_effect_binding_permit",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "reservation_id"],
            ["effect_reservations_v2.tenant_id", "effect_reservations_v2.id"],
            name="fk_effect_binding_reservation",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "permit_id", name="uq_effect_binding_permit"),
        UniqueConstraint("tenant_id", "reservation_id", name="uq_effect_binding_reservation"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    permit_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reservation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    effect_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    policy_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(String(128), nullable=False)
    signed_envelope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
