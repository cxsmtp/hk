from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.observability import get_correlation_id
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.services.privacy_sanitizer import sanitize_privacy_payload


def create_evidence_node(
    db: Session,
    *,
    tenant_id: str,
    node_type: str,
    signal_type: str,
    label: str,
    payload: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    node_id: str | None = None,
) -> EvidenceNode:
    node = EvidenceNode(
        **({"id": node_id} if node_id is not None else {}),
        tenant_id=tenant_id,
        correlation_id=correlation_id or get_correlation_id(),
        node_type=node_type,
        signal_type=signal_type,
        label=label,
        payload=sanitize_privacy_payload(payload or {}),
    )
    db.add(node)
    db.flush()
    return node


def link_evidence_nodes(
    db: Session,
    *,
    tenant_id: str,
    from_node_id: str,
    to_node_id: str,
    edge_type: str,
    payload: dict[str, Any] | None = None,
) -> EvidenceEdge:
    from_node = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == from_node_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    to_node = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == to_node_id,
            EvidenceNode.tenant_id == tenant_id,
        )
    )
    if not from_node or not to_node:
        raise ValueError("Evidence nodes not found for tenant")

    edge = EvidenceEdge(
        tenant_id=tenant_id,
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        edge_type=edge_type,
        payload=sanitize_privacy_payload(payload or {}),
    )
    db.add(edge)
    db.flush()
    return edge
