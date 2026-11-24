from __future__ import annotations

from datetime import datetime
from typing import ClassVar, Optional
from uuid import uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, ForeignKeyConstraint, Index, JSON, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


class EvidenceNode(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "evidence_nodes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_evidence_nodes_tenant_id"),
        Index("idx_evidence_node_tenant", "tenant_id"),
        Index("idx_evidence_node_correlation", "correlation_id"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(128), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class EvidenceEdge(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "evidence_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "from_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_evidence_edge_tenant_from",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "to_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_evidence_edge_tenant_to",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id",
            "from_node_id",
            "edge_type",
            "integrity_key",
            name="uq_evidence_edges_canonical_integrity",
        ),
        CheckConstraint(
            "edge_type NOT IN ('bundle_manifest', 'bundle_member') OR integrity_key IS NOT NULL",
            name="ck_evidence_edges_canonical_integrity_key",
        ),
        Index("idx_evidence_edge_tenant", "tenant_id"),
        Index("idx_evidence_edge_tenant_from_type", "tenant_id", "from_node_id", "edge_type"),
    )

    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    from_node_id: Mapped[str] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="CASCADE"), nullable=False)
    to_node_id: Mapped[str] = mapped_column(ForeignKey("evidence_nodes.id", ondelete="CASCADE"), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    integrity_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class DecisionReceipt(Base):
    __tablename__ = "decision_receipts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_decision_receipts_tenant_idempotency"),
        UniqueConstraint("tenant_id", "receipt_id", name="uq_decision_receipts_tenant_receipt"),
        ForeignKeyConstraint(
            ["tenant_id", "approval_binding_id"],
            ["approval_bindings.tenant_id", "approval_bindings.id"],
            name="fk_decision_receipt_tenant_approval",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_decision_receipt_tenant_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "canonical_action_evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_decision_receipt_tenant_canonical_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "policy_snapshot_evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_decision_receipt_tenant_policy_snapshot_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_decision_receipt_tenant_bundle",
            ondelete="RESTRICT",
        ),
        Index("idx_decision_receipts_tenant_action", "tenant_id", "action_id"),
        Index("idx_decision_receipts_tenant_key", "tenant_id", "signing_key_id"),
        Index("idx_decision_receipts_tenant_bundle", "tenant_id", "evidence_bundle_id"),
    )

    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    chain_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    purpose_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    parameter_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    target_resource_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    destination_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    side_effect_class: Mapped[str] = mapped_column(String(64), nullable=False)
    approval_binding_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    approval_binding_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    policy_snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    control_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    transformations: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    canonical_action_evidence_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_snapshot_evidence_node_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    evidence_node_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)


class ExecutionReceipt(Base):
    __tablename__ = "execution_receipts"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_execution_receipts_tenant_idempotency"),
        UniqueConstraint("tenant_id", "receipt_id", name="uq_execution_receipts_tenant_receipt"),
        UniqueConstraint(
            "tenant_id",
            "decision_receipt_id",
            "execution_attempt_id",
            name="uq_execution_receipts_tenant_decision_attempt",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipts.tenant_id", "decision_receipts.receipt_id"],
            name="fk_execution_receipt_tenant_decision",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_node_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_execution_receipt_tenant_evidence",
            ondelete="RESTRICT",
        ),
        Index("idx_execution_receipts_tenant_action", "tenant_id", "action_id"),
        Index("idx_execution_receipts_tenant_decision", "tenant_id", "decision_receipt_id"),
    )

    receipt_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_receipt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    execution_attempt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actual_chain_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actual_actor_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actual_purpose_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    actual_tool_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    actual_parameter_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    actual_target_resource_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    actual_destination_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    actual_authority_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actual_side_effect_class: Mapped[str] = mapped_column(String(64), nullable=False)
    actual_policy_snapshot_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    downstream_objects: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    execution_status: Mapped[str] = mapped_column(String(32), nullable=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    collector_id: Mapped[str] = mapped_column(String(128), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_node_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)


class ExecutionIntegrityResult(Base):
    __tablename__ = "execution_integrity_results"
    __table_args__ = (
        UniqueConstraint("tenant_id", "idempotency_key", name="uq_execution_integrity_tenant_idempotency"),
        UniqueConstraint(
            "tenant_id",
            "decision_receipt_id",
            "execution_attempt_id",
            name="uq_execution_integrity_tenant_decision_attempt",
        ),
        CheckConstraint(
            "result IN ('matched','drift_detected','execution_unknown','incomplete')",
            name="ck_execution_integrity_result_closed",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "decision_receipt_id"],
            ["decision_receipts.tenant_id", "decision_receipts.receipt_id"],
            name="fk_execution_integrity_tenant_decision",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "execution_receipt_id"],
            ["execution_receipts.tenant_id", "execution_receipts.receipt_id"],
            name="fk_execution_integrity_tenant_execution",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "evidence_bundle_id"],
            ["evidence_nodes.tenant_id", "evidence_nodes.id"],
            name="fk_execution_integrity_tenant_evidence",
            ondelete="RESTRICT",
        ),
        Index("idx_execution_integrity_tenant_action", "tenant_id", "action_id"),
        Index("idx_execution_integrity_tenant_result", "tenant_id", "result"),
    )

    ALLOWED_RESULTS: ClassVar[set[str]] = {
        "matched",
        "drift_detected",
        "execution_unknown",
        "incomplete",
    }

    result_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision_receipt_id: Mapped[str] = mapped_column(String(36), nullable=False)
    execution_receipt_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    execution_attempt_id: Mapped[str] = mapped_column(String(128), nullable=False)
    result: Mapped[str] = mapped_column(String(32), nullable=False)
    drift_fields: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    response_action: Mapped[str] = mapped_column(String(32), nullable=False)
    signature: Mapped[str] = mapped_column(String(64), nullable=False)
    signing_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    evidence_bundle_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    superseded_evidence_node_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    superseded_integrity_body_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    superseded_integrity_signature: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    supersession_evidence_node_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    idempotency_key: Mapped[str] = mapped_column(String(64), nullable=False)
