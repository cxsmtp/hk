"""Instruction provenance and dynamic-tool principal lifecycle state.

These records are tenant-scoped projections over Hawk's existing action,
policy, evidence, lineage and External Capability Integrity systems.  They do
not store instruction content and they do not create a second policy engine.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


TOOL_LIFECYCLE_STATES = (
    "DISCOVERED",
    "QUARANTINED",
    "VALIDATING",
    "VALIDATED",
    "AVAILABLE",
    "CHANGED",
    "STALE",
    "REVOKED",
    "REJECTED",
)
INSTRUCTION_AUTHORITY_SEMANTICS = (
    "INFLUENCE_ONLY",
    "AUTHORIZED_ACTION_SOURCE",
    "CONTEXT_ONLY",
    "AUTHORITY_UNKNOWN",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class InstructionProvenanceSet(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "instruction_provenance_sets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_instruction_provenance_set_tenant_id"),
        UniqueConstraint("tenant_id", "run_id", "action_id", name="uq_instruction_provenance_run_action"),
        Index("idx_instruction_provenance_set_action", "tenant_id", "action_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    run_id: Mapped[str] = mapped_column(String(255), nullable=False)
    action_id: Mapped[str] = mapped_column(String(255), nullable=False)
    parent_set_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    handoff_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    inherited_record_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class InstructionProvenanceRecord(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "instruction_provenance_records"
    __table_args__ = (
        CheckConstraint(
            f"authority_semantic IN ({_quoted(INSTRUCTION_AUTHORITY_SEMANTICS)})",
            name="ck_instruction_provenance_authority_semantic",
        ),
        Index("idx_instruction_provenance_record_set", "tenant_id", "provenance_set_id"),
        Index("idx_instruction_provenance_record_source", "tenant_id", "source_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provenance_set_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    originating_principal_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    represented_subject_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_semantic: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_semantic: Mapped[str] = mapped_column(String(64), nullable=False)
    influenced: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    authority_granted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    instruction_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    derivation_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OpenWeightAttributionEvidence(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "open_weight_attribution_evidence"
    __table_args__ = (
        Index("idx_open_weight_attribution_set", "tenant_id", "provenance_set_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    provenance_set_id: Mapped[str] = mapped_column(String(36), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(36), nullable=False)
    attribution_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_class: Mapped[str] = mapped_column(String(32), nullable=False, default="ADVISORY_CORRELATED")
    can_grant_authority: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ToolPrincipalBinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tool_principal_bindings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_tool_principal_binding_tenant_id"),
        UniqueConstraint("tenant_id", "tool_identity_hash", name="uq_tool_principal_identity"),
        CheckConstraint(
            f"lifecycle_state IN ({_quoted(TOOL_LIFECYCLE_STATES)})",
            name="ck_tool_principal_lifecycle_state",
        ),
        CheckConstraint("state_version > 0", name="ck_tool_principal_state_version"),
        Index("idx_tool_principal_tenant_state", "tenant_id", "lifecycle_state"),
        Index("idx_tool_principal_tenant_principal", "tenant_id", "principal_ref"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    visible_name: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    principal_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    origin: Mapped[str | None] = mapped_column(String(512), nullable=True)
    runtime_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    application_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    publisher_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registration_source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    material_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    material_bundle: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    cosmetic_metadata: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    lifecycle_version: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False, default="QUARANTINED")
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    capability_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    evidence_quality: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Signature material is an auditable assertion, never a private signing secret.
    principal_assertion_algorithm: Mapped[str | None] = mapped_column(String(16), nullable=True)
    signing_key_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assertion_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assertion_signature: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    assertion_assurance: Mapped[str | None] = mapped_column(String(64), nullable=True)
    assertion_nonce: Mapped[str | None] = mapped_column(String(255), nullable=True)
    assertion_issued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assertion_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    principal_assertion_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ToolLifecycleEvent(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "tool_lifecycle_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "binding_id", "sequence", name="uq_tool_lifecycle_event_sequence"),
        Index("idx_tool_lifecycle_event_binding", "tenant_id", "binding_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    binding_id: Mapped[str] = mapped_column(String(36), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    from_state: Mapped[str] = mapped_column(String(32), nullable=False)
    to_state: Mapped[str] = mapped_column(String(32), nullable=False)
    prior_material_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_material_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(String(512), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ToolActionProvenanceBinding(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "tool_action_provenance_bindings"
    __table_args__ = (
        UniqueConstraint("tenant_id", "action_id", name="uq_tool_action_provenance_action"),
        Index("idx_tool_action_provenance_tool", "tenant_id", "tool_binding_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_binding_id: Mapped[str] = mapped_column(String(36), nullable=False)
    provenance_set_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tool_identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    material_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    lifecycle_version: Mapped[str] = mapped_column(String(64), nullable=False)
    provenance_record_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    decision_receipt_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_permit_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    execution_receipt_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    actual_tool_identity_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actual_material_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    actual_identity_observed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    comparison_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNVERIFIED")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
