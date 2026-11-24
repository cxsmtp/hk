from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_canonical import DiscoveryCollector
from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.erg.confidence_engine import ConfidenceEngine
from app.services.hmair.erg.contracts import EdgeConfidenceInput, ERGGraphProjection
from app.services.hmair.resolution_graph_service import EDGE_TYPES


RESOLVED_MATCH_RULE_ALLOWLIST = frozenset(
    {"manual-resolution-v1", "strong-identity-v1", "strong-runtime-repository-v1"}
)


class ERGGraphScopeError(RuntimeError):
    """Graph evidence is invalid or outside the tenant boundary."""


class ERGGraphConflict(RuntimeError):
    """Immutable edge or successor material conflicts with existing history."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ERGGraphScopeError("graph timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


class EvidenceResolutionGraph:
    def __init__(self, *, confidence_engine: ConfidenceEngine | None = None) -> None:
        self._confidence_engine = confidence_engine or ConfidenceEngine()

    def append_edge_evaluation(
        self,
        db: Session,
        *,
        tenant_id: str,
        from_node_id: str,
        to_node_id: str,
        edge_type: str,
        evidence_node_id: str,
        collector_id: str | None,
        base_confidence: float,
        relationship_weight: float,
        observation_quality: float | None,
        collector_quality: float | None,
        source_surface: str,
        signal_class: str,
        verification_state: str,
        freshness: str,
        contradiction_state: str,
        first_observed_at: datetime,
        last_observed_at: datetime,
        last_validated_at: datetime,
        relationship_rule_id: str,
        relationship_rule_version: str,
        idempotency_key: str,
        predecessor_edge_id: str | None = None,
    ) -> DiscoveryResolutionGraphEdge:
        if edge_type not in EDGE_TYPES or from_node_id == to_node_id:
            raise ERGGraphScopeError("unsupported graph edge type or shape")
        if edge_type == "resolved_match" and relationship_rule_id not in RESOLVED_MATCH_RULE_ALLOWLIST:
            raise ERGGraphScopeError(
                "resolved match requires an accepted strong relationship rule"
            )
        if not idempotency_key or len(idempotency_key) > 128:
            raise ERGGraphScopeError("graph idempotency key is invalid")
        first_observed_at = _utc(first_observed_at)
        last_observed_at = _utc(last_observed_at)
        last_validated_at = _utc(last_validated_at)
        if not first_observed_at <= last_observed_at <= last_validated_at:
            raise ERGGraphScopeError("graph timestamps are out of order")
        nodes = tuple(
            db.scalars(
                select(DiscoveryResolutionGraphNode).where(
                    DiscoveryResolutionGraphNode.tenant_id == tenant_id,
                    DiscoveryResolutionGraphNode.graph_node_id.in_((from_node_id, to_node_id)),
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
            raise ERGGraphScopeError("graph nodes or evidence are outside tenant scope")
        if collector_id is not None:
            collector = db.scalar(
                select(DiscoveryCollector).where(
                    DiscoveryCollector.tenant_id == tenant_id,
                    DiscoveryCollector.collector_id == collector_id,
                )
            )
            if collector is None:
                raise ERGGraphScopeError("graph collector is outside tenant scope")
        predecessor = None
        edge_sequence = 1
        if predecessor_edge_id is not None:
            predecessor = db.scalar(
                select(DiscoveryResolutionGraphEdge).where(
                    DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                    DiscoveryResolutionGraphEdge.edge_id == predecessor_edge_id,
                )
            )
            if predecessor is None:
                raise ERGGraphScopeError("predecessor edge is outside tenant scope")
            if (
                predecessor.from_node_id != from_node_id
                or predecessor.to_node_id != to_node_id
                or predecessor.edge_type != edge_type
            ):
                raise ERGGraphConflict("successor relationship shape changed")
            edge_sequence = predecessor.edge_sequence + 1

        edge_input = EdgeConfidenceInput(
            edge_id=idempotency_key,
            signal_class=signal_class,
            source_surface=source_surface,
            collector_id=collector_id or "system",
            base_confidence=base_confidence,
            relationship_weight=relationship_weight,
            observation_quality=observation_quality,
            collector_quality=collector_quality,
            observed_at=first_observed_at,
            last_validated_at=last_validated_at,
            validation_state=verification_state,
            contradiction_state=(
                "unresolved" if contradiction_state == "confirmed" else contradiction_state
            ),
            declared_freshness=freshness,
            relationship_rule_id=relationship_rule_id,
            relationship_rule_version=relationship_rule_version,
        )
        confidence = self._confidence_engine.evaluate_edge(
            edge=edge_input, evaluated_at=last_validated_at
        )
        effective_confidence = (
            confidence.effective_confidence
            if confidence.effective_confidence is not None
            else 0.0
        )
        material = {
            "tenant_id": tenant_id,
            "from_node_id": from_node_id,
            "to_node_id": to_node_id,
            "edge_type": edge_type,
            "evidence_node_id": evidence_node_id,
            "collector_id": collector_id,
            "source_surface": source_surface,
            "signal_class": signal_class,
            "base_confidence": base_confidence,
            "observation_quality_factor": observation_quality,
            "collector_quality_factor": collector_quality,
            "effective_confidence": effective_confidence,
            "relationship_weight": relationship_weight,
            "verification_state": verification_state,
            "freshness": freshness,
            "contradiction_state": contradiction_state,
            "first_observed_at": first_observed_at.isoformat(),
            "last_observed_at": last_observed_at.isoformat(),
            "last_validated_at": last_validated_at.isoformat(),
            "relationship_rule_id": relationship_rule_id,
            "relationship_rule_version": relationship_rule_version,
            "decay_policy_id": confidence.decay_policy_id or "unknown",
            "decay_policy_version": confidence.decay_policy_version or "unknown",
            "edge_sequence": edge_sequence,
            "predecessor_edge_id": predecessor_edge_id,
        }
        input_digest = hashlib.sha256(
            b"hawk:erg:edge-evaluation:v1\x00" + canonical_json_bytes(material)
        ).hexdigest()
        replay = db.scalar(
            select(DiscoveryResolutionGraphEdge).where(
                DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                DiscoveryResolutionGraphEdge.idempotency_key == idempotency_key,
            )
        )
        if replay is not None:
            if replay.input_digest != input_digest:
                raise ERGGraphConflict("graph edge idempotency conflict")
            return replay
        if predecessor_edge_id is not None:
            successor = db.scalar(
                select(DiscoveryResolutionGraphEdge).where(
                    DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                    DiscoveryResolutionGraphEdge.predecessor_edge_id == predecessor_edge_id,
                )
            )
            if successor is not None:
                raise ERGGraphConflict("graph edge already has a successor")
        edge_id = str(
            uuid5(NAMESPACE_URL, f"hawk:erg-edge:v1:{tenant_id}:{idempotency_key}")
        )
        row = DiscoveryResolutionGraphEdge(
            edge_id=edge_id,
            tenant_id=tenant_id,
            from_node_id=from_node_id,
            to_node_id=to_node_id,
            edge_type=edge_type,
            evidence_node_id=evidence_node_id,
            collector_id=collector_id,
            source_surface=source_surface,
            signal_class=signal_class,
            base_confidence=base_confidence,
            observation_quality_factor=observation_quality,
            collector_quality_factor=collector_quality,
            confidence=effective_confidence,
            relationship_weight=relationship_weight,
            relationship_rule_id=relationship_rule_id,
            relationship_rule_version=relationship_rule_version,
            decay_policy_id=confidence.decay_policy_id or "unknown",
            decay_policy_version=confidence.decay_policy_version or "unknown",
            verification_state=(
                verification_state
                if verification_state in {"verified", "partially_verified", "inferred", "unknown"}
                else "unknown"
            ),
            freshness=freshness,
            contradiction_state=contradiction_state,
            first_observed_at=first_observed_at,
            last_observed_at=last_observed_at,
            last_validated_at=last_validated_at,
            edge_schema_version="2.0.0",
            edge_sequence=edge_sequence,
            predecessor_edge_id=predecessor_edge_id,
            idempotency_key=idempotency_key,
            input_digest=input_digest,
        )
        db.add(row)
        db.flush()
        return row

    @staticmethod
    def current_graph(
        db: Session, *, tenant_id: str, generated_at: datetime | None = None
    ) -> ERGGraphProjection:
        edges = tuple(
            db.scalars(
                select(DiscoveryResolutionGraphEdge)
                .where(DiscoveryResolutionGraphEdge.tenant_id == tenant_id)
                .order_by(DiscoveryResolutionGraphEdge.edge_id)
            )
        )
        historical = {item.predecessor_edge_id for item in edges if item.predecessor_edge_id}
        current = tuple(item for item in edges if item.edge_id not in historical)
        node_ids = tuple(
            sorted(
                {node_id for item in current for node_id in (item.from_node_id, item.to_node_id)}
            )
        )
        return ERGGraphProjection(
            node_ids=node_ids,
            current_edge_ids=tuple(item.edge_id for item in current),
            historical_edge_ids=tuple(sorted(historical)),
            generated_at=generated_at or datetime.now(timezone.utc),
        )

    @classmethod
    def connected_current_edge_ids(
        cls,
        db: Session,
        *,
        tenant_id: str,
        seed_edge_ids: tuple[str, ...],
    ) -> tuple[str, ...]:
        """Return the current connected component for the supplied CIE edges."""
        if not seed_edge_ids:
            return ()
        if len(set(seed_edge_ids)) != len(seed_edge_ids):
            raise ERGGraphScopeError("connected graph seeds must be unique")
        projection = cls.current_graph(db, tenant_id=tenant_id)
        current_ids = set(projection.current_edge_ids)
        if not set(seed_edge_ids) <= current_ids:
            raise ERGGraphScopeError("connected graph seeds must be current tenant edges")
        rows = tuple(
            db.scalars(
                select(DiscoveryResolutionGraphEdge)
                .where(
                    DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                    DiscoveryResolutionGraphEdge.edge_id.in_(projection.current_edge_ids),
                )
                .order_by(DiscoveryResolutionGraphEdge.edge_id)
            )
        )
        selected = {
            row.edge_id for row in rows if row.edge_id in set(seed_edge_ids)
        }
        connected_nodes = {
            node_id
            for row in rows
            if row.edge_id in selected
            for node_id in (row.from_node_id, row.to_node_id)
        }
        changed = True
        while changed:
            changed = False
            for row in rows:
                if row.edge_id in selected:
                    continue
                if row.from_node_id in connected_nodes or row.to_node_id in connected_nodes:
                    selected.add(row.edge_id)
                    connected_nodes.update((row.from_node_id, row.to_node_id))
                    changed = True
        return tuple(sorted(selected))


__all__ = [
    "ERGGraphConflict",
    "ERGGraphScopeError",
    "EvidenceResolutionGraph",
    "RESOLVED_MATCH_RULE_ALLOWLIST",
]
