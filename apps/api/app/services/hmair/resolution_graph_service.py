from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes


NODE_CLASSES = frozenset(
    {
        "observation", "hypothesis", "ai_asset", "identity", "runtime",
        "model", "tool", "mcp_server", "data_asset", "network_destination",
        "repository", "cloud_resource", "saas_app", "capability", "provider",
        "configuration", "marketplace", "extension", "dependency", "project",
        "database", "process", "mcp", "usage", "user", "service_account",
        "application", "environment", "permission", "relationship",
        "ai_ecosystem",
    }
)
EDGE_TYPES = frozenset(
    {
        "supports", "contradicts", "observed_on", "runs_on", "used_by",
        "calls", "connects_to", "depends_on", "authenticates_as", "hosted_in",
        "exposes", "accesses", "possibly_same_as", "replaces", "split_from",
        "merged_from", "observed_by", "uses", "invokes", "provides",
        "connected_to", "same_identity", "same_runtime", "same_repository",
        "same_configuration", "same_provider", "same_project", "same_user",
        "potential_match", "resolved_match", "historical_match",
    }
)


class ResolutionGraphScopeError(RuntimeError):
    """Graph material is invalid or outside the caller's tenant scope."""


def _digest(domain: str, material: dict[str, object]) -> str:
    return hashlib.sha256(
        domain.encode("ascii") + canonical_json_bytes(material)
    ).hexdigest()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ResolutionGraphScopeError("graph timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def create_graph_node(
    db: Session,
    *,
    tenant_id: str,
    node_class: str,
    subject_reference: str,
    idempotency_key: str,
) -> DiscoveryResolutionGraphNode:
    if node_class not in NODE_CLASSES:
        raise ResolutionGraphScopeError("unsupported graph node class")
    if (
        not subject_reference
        or subject_reference != subject_reference.strip()
        or len(subject_reference) > 500
    ):
        raise ResolutionGraphScopeError("graph subject reference is invalid")
    material = {
        "tenant_id": tenant_id,
        "node_class": node_class,
        "subject_reference": subject_reference,
    }
    digest = _digest("hawk:discovery:erg-node:v1", material)
    existing = db.scalar(
        select(DiscoveryResolutionGraphNode).where(
            DiscoveryResolutionGraphNode.tenant_id == tenant_id,
            DiscoveryResolutionGraphNode.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != digest:
            raise ResolutionGraphScopeError("graph node idempotency conflict")
        return existing
    row = DiscoveryResolutionGraphNode(
        graph_node_id=str(uuid4()),
        tenant_id=tenant_id,
        node_class=node_class,
        subject_reference=subject_reference,
        idempotency_key=idempotency_key,
        input_digest=digest,
    )
    db.add(row)
    db.flush()
    return row


def create_graph_edge(
    db: Session,
    *,
    tenant_id: str,
    from_node_id: str,
    to_node_id: str,
    edge_type: str,
    evidence_node_id: str,
    confidence: float,
    verification_state: str,
    freshness: str,
    contradiction_state: str,
    first_observed_at: datetime,
    last_observed_at: datetime,
    idempotency_key: str,
    collector_id: str | None = None,
    source_surface: str = "unknown",
    signal_class: str = "unknown",
    observation_quality: float | None = None,
    collector_quality: float | None = None,
) -> DiscoveryResolutionGraphEdge:
    if edge_type not in EDGE_TYPES or from_node_id == to_node_id:
        raise ResolutionGraphScopeError("graph edge type or shape is invalid")
    if not source_surface or len(source_surface) > 64:
        raise ResolutionGraphScopeError("graph source surface is invalid")
    if collector_id is not None and (not collector_id or len(collector_id) > 128):
        raise ResolutionGraphScopeError("graph collector is invalid")
    if not signal_class or len(signal_class) > 64:
        raise ResolutionGraphScopeError("graph signal class is invalid")
    if any(
        value is not None and (type(value) is not float or not 0.0 <= value <= 1.0)
        for value in (observation_quality, collector_quality)
    ):
        raise ResolutionGraphScopeError("graph quality factor is invalid")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise ResolutionGraphScopeError("graph edge confidence is invalid")
    if verification_state not in {
        "verified", "partially_verified", "inferred", "unknown"
    }:
        raise ResolutionGraphScopeError("graph verification state is invalid")
    if freshness not in {"fresh", "stale", "expired", "unknown"}:
        raise ResolutionGraphScopeError("graph freshness is invalid")
    if contradiction_state not in {
        "none", "possible", "confirmed", "resolved", "unknown"
    }:
        raise ResolutionGraphScopeError("graph contradiction state is invalid")
    first_observed_at = _utc(first_observed_at)
    last_observed_at = _utc(last_observed_at)
    if first_observed_at > last_observed_at:
        raise ResolutionGraphScopeError("graph evidence timestamps are out of order")
    nodes = tuple(
        db.scalars(
            select(DiscoveryResolutionGraphNode).where(
                DiscoveryResolutionGraphNode.tenant_id == tenant_id,
                DiscoveryResolutionGraphNode.graph_node_id.in_(
                    (from_node_id, to_node_id)
                ),
            )
        )
    )
    evidence = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == evidence_node_id,
        )
    )
    if len(nodes) != 2 or evidence is None:
        raise ResolutionGraphScopeError("graph evidence or endpoint is unavailable")
    material = {
        "tenant_id": tenant_id,
        "from_node_id": from_node_id,
        "to_node_id": to_node_id,
        "edge_type": edge_type,
        "evidence_node_id": evidence_node_id,
        "collector_id": collector_id,
        "source_surface": source_surface,
        "signal_class": signal_class,
        "observation_quality": observation_quality,
        "collector_quality": collector_quality,
        "confidence": confidence,
        "verification_state": verification_state,
        "freshness": freshness,
        "contradiction_state": contradiction_state,
        "first_observed_at": first_observed_at.isoformat(),
        "last_observed_at": last_observed_at.isoformat(),
    }
    digest = _digest("hawk:discovery:erg-edge:v1", material)
    existing = db.scalar(
        select(DiscoveryResolutionGraphEdge).where(
            DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
            DiscoveryResolutionGraphEdge.idempotency_key == idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != digest:
            raise ResolutionGraphScopeError("graph edge idempotency conflict")
        return existing
    row = DiscoveryResolutionGraphEdge(
        edge_id=str(uuid4()),
        tenant_id=tenant_id,
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        edge_type=edge_type,
        evidence_node_id=evidence_node_id,
        collector_id=collector_id,
        source_surface=source_surface,
        signal_class=signal_class,
        base_confidence=confidence,
        observation_quality_factor=observation_quality,
        collector_quality_factor=collector_quality,
        confidence=confidence,
        relationship_weight=1.0,
        relationship_rule_id="legacy-resolution-graph-v1",
        relationship_rule_version="1.0.0",
        decay_policy_id="legacy-no-decay",
        decay_policy_version="1.0.0",
        verification_state=verification_state,
        freshness=freshness,
        contradiction_state=contradiction_state,
        first_observed_at=first_observed_at,
        last_observed_at=last_observed_at,
        last_validated_at=last_observed_at,
        edge_schema_version="1.0.0",
        edge_sequence=1,
        predecessor_edge_id=None,
        idempotency_key=idempotency_key,
        input_digest=digest,
    )
    db.add(row)
    db.flush()
    return row


__all__ = [
    "ResolutionGraphScopeError",
    "create_graph_edge",
    "create_graph_node",
]
