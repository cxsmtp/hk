"""Tenant-scoped External Capability Integrity state.

This is a reasoning and evidence projection over existing discovery, MCP,
Phase 5, Phase 6, Phase 7 and coverage primitives. It is not a second MCP
inventory.
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


EXTERNAL_CAPABILITY_TYPES = (
    "MCP_SERVER",
    "MCP_TOOL",
    "SKILL",
    "PLUGIN",
    "SUB_AGENT",
    "EXTERNAL_INSTRUCTION",
    "API_SERVICE",
)
EXTERNAL_CAPABILITY_TRUST_STATES = (
    "UNKNOWN",
    "TRUSTED_CURRENT",
    "STALE",
    "REGRESSED",
    "REVOKED",
)
EXTERNAL_CAPABILITY_DRIFT_TYPES = (
    "CAPABILITY_IDENTITY_DRIFT",
    "CAPABILITY_PROVENANCE_DRIFT",
    "MCP_DRIFT",
    "TOOL_DRIFT",
    "SCHEMA_DRIFT",
    "CONTROL_CAPABILITY_DRIFT",
)


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class ExternalCapabilityIdentity(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "external_capability_identities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "capability_ref", name="uq_eci_capability_ref"),
        UniqueConstraint("tenant_id", "id", name="uq_eci_identity_tenant_id"),
        CheckConstraint(
            f"capability_type IN ({_quoted(EXTERNAL_CAPABILITY_TYPES)})",
            name="ck_eci_identity_type",
        ),
        CheckConstraint(
            f"trust_state IN ({_quoted(EXTERNAL_CAPABILITY_TRUST_STATES)})",
            name="ck_eci_identity_trust_state",
        ),
        CheckConstraint("capability_epoch > 0", name="ck_eci_identity_epoch_positive"),
        CheckConstraint("last_observed_sequence >= 0", name="ck_eci_identity_sequence_nonnegative"),
        Index("idx_eci_identity_tenant_state", "tenant_id", "trust_state"),
        Index("idx_eci_identity_tenant_type", "tenant_id", "capability_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    capability_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    capability_type: Mapped[str] = mapped_column(String(32), nullable=False)
    configured_locator: Mapped[str] = mapped_column(String(512), nullable=False)
    registry_source: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registry_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    publisher_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)
    observed_endpoint: Mapped[str | None] = mapped_column(String(512), nullable=True)
    observed_identity: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    component_fingerprints: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    material_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    baseline_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    baseline_material_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")
    capability_epoch: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    evidence_quality: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    drift_summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_by_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ExternalCapabilityBaseline(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "external_capability_baselines"
    __table_args__ = (
        UniqueConstraint("tenant_id", "capability_id", "baseline_version", name="uq_eci_baseline_version"),
        UniqueConstraint("tenant_id", "id", name="uq_eci_baseline_tenant_id"),
        CheckConstraint(
            f"trust_state IN ({_quoted(EXTERNAL_CAPABILITY_TRUST_STATES)})",
            name="ck_eci_baseline_trust_state",
        ),
        CheckConstraint("baseline_version > 0", name="ck_eci_baseline_version_positive"),
        Index("idx_eci_baseline_capability", "tenant_id", "capability_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    capability_id: Mapped[str] = mapped_column(String(36), nullable=False)
    baseline_version: Mapped[int] = mapped_column(Integer, nullable=False)
    material_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    component_fingerprints: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    observed_identity: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    verification_source: Mapped[str] = mapped_column(String(255), nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    control_assertion_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    capability_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    trust_state: Mapped[str] = mapped_column(String(32), nullable=False, default="TRUSTED_CURRENT")
    accepted_by_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    accepted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ExternalCapabilityDrift(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "external_capability_drifts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "drift_hash", name="uq_eci_drift_hash"),
        UniqueConstraint("tenant_id", "id", name="uq_eci_drift_tenant_id"),
        CheckConstraint(
            f"drift_type IN ({_quoted(EXTERNAL_CAPABILITY_DRIFT_TYPES)})",
            name="ck_eci_drift_type",
        ),
        CheckConstraint("status IN ('OPEN','REVALIDATED','REVOKED')", name="ck_eci_drift_status"),
        Index("idx_eci_drift_capability", "tenant_id", "capability_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    capability_id: Mapped[str] = mapped_column(String(36), nullable=False)
    drift_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    drift_type: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    current_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    changed_fields: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    affected_assertion_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    drift_signal_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class ExternalCapabilityValidationLink(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "external_capability_validation_links"
    __table_args__ = (
        UniqueConstraint("tenant_id", "capability_id", "validation_run_id", name="uq_eci_validation_link"),
        Index("idx_eci_validation_capability", "tenant_id", "capability_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    capability_id: Mapped[str] = mapped_column(String(36), nullable=False)
    validation_run_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    drift_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
