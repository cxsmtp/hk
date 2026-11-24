"""Reference-only persistence for Phase 7 AI activity investigations."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    JSON,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models.base import TimestampMixin, UUIDPrimaryKeyMixin
from app.db.session import Base


LINEAGE_NODE_TYPES = (
    "HUMAN", "EXTERNAL_USER", "AGENT", "SERVICE", "WORKLOAD",
    "AI_APPLICATION", "MODEL", "RUNTIME", "TOOL", "MCP_SERVER",
    "MCP_TOOL", "API", "CONTROL_POINT", "POLICY", "APPROVAL",
    "DECISION_RECEIPT", "EXECUTION_PERMIT", "EXECUTION_RECEIPT",
    "RESOURCE", "TARGET", "DESTINATION", "PERSISTENT_EFFECT",
    "VALIDATION_RUN", "DRIFT_SIGNAL", "OUTCOME", "ACTION",
)
LINEAGE_EDGE_TYPES = (
    "INITIATED", "ACTING_ON_BEHALF_OF", "REPRESENTS", "DELEGATED_TO",
    "EXECUTED_BY", "CALLED", "USED_MODEL", "USED_TOOL", "ROUTED_THROUGH",
    "CONTROLLED_BY", "AUTHORISED_BY", "APPROVED_BY", "PERMITTED_BY",
    "TARGETED", "READ", "MODIFIED", "CREATED", "DELETED", "SENT_TO",
    "PRODUCED", "VERIFIED_BY", "DRIFTED_FROM", "CREATED_PERSISTENT_EFFECT",
    "TRIGGERED", "VALIDATED_BY", "PARENT_OF",
)
LINEAGE_CERTAINTY = ("CONFIRMED", "CORRELATED", "INFERRED", "UNKNOWN")


def _quoted(values: tuple[str, ...]) -> str:
    return ",".join(f"'{value}'" for value in values)


class ActivityLineage(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "activity_lineages"
    __table_args__ = (
        UniqueConstraint("tenant_id", "id", name="uq_phase7_lineage_tenant_id"),
        UniqueConstraint(
            "tenant_id", "lineage_key", "source_watermark",
            name="uq_phase7_lineage_snapshot",
        ),
        CheckConstraint(
            "status IN ('COMPLETE','PARTIAL')", name="ck_phase7_lineage_status"
        ),
        Index("idx_phase7_lineage_action", "tenant_id", "seed_action_id", "created_at"),
        Index("idx_phase7_lineage_event", "tenant_id", "seed_runtime_event_id"),
    )

    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    lineage_key: Mapped[str] = mapped_column(String(64), nullable=False)
    source_watermark: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    seed_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    seed_runtime_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    root_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PARTIAL")
    blind_spots: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class LineageNode(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "activity_lineage_nodes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id"],
            ["activity_lineages.tenant_id", "activity_lineages.id"],
            name="fk_phase7_node_lineage",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "lineage_id", "id", name="uq_phase7_node_tenant_id"),
        UniqueConstraint(
            "tenant_id", "lineage_id", "node_key", name="uq_phase7_lineage_node_key"
        ),
        CheckConstraint(
            f"node_type IN ({_quoted(LINEAGE_NODE_TYPES)})",
            name="ck_phase7_node_type",
        ),
        CheckConstraint(
            f"certainty IN ({_quoted(LINEAGE_CERTAINTY)})",
            name="ck_phase7_node_certainty",
        ),
        Index("idx_phase7_node_authority", "tenant_id", "authority_type", "authority_id"),
        Index("idx_phase7_node_lineage_ordinal", "tenant_id", "lineage_id", "ordinal"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    lineage_id: Mapped[str] = mapped_column(String(36), nullable=False)
    node_key: Mapped[str] = mapped_column(String(64), nullable=False)
    node_type: Mapped[str] = mapped_column(String(32), nullable=False)
    authority_type: Mapped[str] = mapped_column(String(64), nullable=False)
    authority_id: Mapped[str] = mapped_column(String(255), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    certainty: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    safe_attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ordinal: Mapped[int] = mapped_column(nullable=False, default=0)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class LineageEdge(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "activity_lineage_edges"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id"],
            ["activity_lineages.tenant_id", "activity_lineages.id"],
            name="fk_phase7_edge_lineage",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "from_node_id"],
            ["activity_lineage_nodes.tenant_id", "activity_lineage_nodes.lineage_id", "activity_lineage_nodes.id"],
            name="fk_phase7_edge_from_node",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id", "to_node_id"],
            ["activity_lineage_nodes.tenant_id", "activity_lineage_nodes.lineage_id", "activity_lineage_nodes.id"],
            name="fk_phase7_edge_to_node",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "tenant_id", "lineage_id", "edge_key", name="uq_phase7_lineage_edge_key"
        ),
        CheckConstraint(
            f"edge_type IN ({_quoted(LINEAGE_EDGE_TYPES)})",
            name="ck_phase7_edge_type",
        ),
        CheckConstraint(
            f"certainty IN ({_quoted(LINEAGE_CERTAINTY)})",
            name="ck_phase7_edge_certainty",
        ),
        Index("idx_phase7_edge_from", "tenant_id", "lineage_id", "from_node_id"),
        Index("idx_phase7_edge_to", "tenant_id", "lineage_id", "to_node_id"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    lineage_id: Mapped[str] = mapped_column(String(36), nullable=False)
    edge_key: Mapped[str] = mapped_column(String(64), nullable=False)
    from_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    to_node_id: Mapped[str] = mapped_column(String(36), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(40), nullable=False)
    certainty: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_quality: Mapped[str] = mapped_column(String(64), nullable=False, default="UNKNOWN")
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    safe_attributes: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sequence: Mapped[int] = mapped_column(nullable=False, default=0)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Investigation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "activity_investigations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "lineage_id"],
            ["activity_lineages.tenant_id", "activity_lineages.id"],
            name="fk_phase7_investigation_lineage",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_phase7_investigation_tenant_id"),
        CheckConstraint(
            "status IN ('OPEN','IN_REVIEW','RESOLVED','CLOSED')",
            name="ck_phase7_investigation_status",
        ),
        Index("idx_phase7_investigation_owner", "tenant_id", "owner_ref", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    lineage_id: Mapped[str] = mapped_column(String(36), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
    seed_action_id: Mapped[str] = mapped_column(String(64), nullable=False)
    seed_runtime_event_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    saved_query: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    time_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    time_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class InvestigationFinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "activity_investigation_findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "investigation_id"],
            ["activity_investigations.tenant_id", "activity_investigations.id"],
            name="fk_phase7_finding_investigation",
            ondelete="CASCADE",
        ),
        UniqueConstraint("tenant_id", "id", name="uq_phase7_finding_tenant_id"),
        CheckConstraint(
            "status IN ('OPEN','RESOLVED','DISMISSED')",
            name="ck_phase7_finding_status",
        ),
        CheckConstraint(
            "severity IN ('info','low','medium','high','critical')",
            name="ck_phase7_finding_severity",
        ),
        Index("idx_phase7_finding_investigation", "tenant_id", "investigation_id", "status"),
    )

    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    investigation_id: Mapped[str] = mapped_column(String(36), nullable=False)
    finding_type: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="OPEN")
    lineage_node_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    lineage_edge_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

