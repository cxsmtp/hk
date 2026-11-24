from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.capability_inference import DiscoveryCapabilityEvidence, DiscoveryCapabilityInferenceRun
from app.db.models.discovery_resolution import (
    DiscoveryResolutionGraphEdge,
    DiscoveryResolutionGraphNode,
)
from app.db.models.evidence_resolution import (
    DiscoveryHypothesisEvaluation,
    DiscoveryHypothesisEvaluationEdge,
)
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.erg.confidence_engine import ConfidenceEngine
from app.services.hmair.erg.contracts import EdgeConfidenceEvaluation, EdgeConfidenceInput
from app.services.hmair.hypothesis_service import create_hypothesis, transition_hypothesis


HYPOTHESIS_RULE_ID = "erg-capability-ecosystem-hypothesis"
HYPOTHESIS_RULE_VERSION = "1.0.0"
HYPOTHESIS_METHODOLOGY_ID = "erg-explicit-factor-confidence"
HYPOTHESIS_METHODOLOGY_VERSION = "1.0.0"

_CLASS_TYPES = {
    "coding": "coding_assistant",
    "retrieval_augmented_generation": "rag_system",
    "agent_automation": "agent",
}
_CLASS_ANCHORS = {
    "coding": frozenset({"repository", "runtime", "tool"}),
    "retrieval_augmented_generation": frozenset({"database", "model", "runtime"}),
    "agent_automation": frozenset({"tool", "runtime", "mcp"}),
}


class HypothesisEvaluationConflict(RuntimeError):
    """Inference, graph, or immutable evaluation history is inconsistent."""


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise HypothesisEvaluationConflict("evaluation timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _stored_utc(value: datetime) -> datetime:
    """Normalize timestamps read from SQLite, which drops timezone metadata."""
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _digest(domain: str, material: dict[str, object]) -> str:
    return hashlib.sha256(domain.encode("ascii") + canonical_json_bytes(material)).hexdigest()


def _uuid(domain: str, tenant_id: str, key: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"hawk:{domain}:v1:{tenant_id}:{key}"))


class HypothesisEngine:
    """Append-only reasoning from CIE output and current ERG edges."""

    def __init__(self, *, confidence_engine: ConfidenceEngine | None = None) -> None:
        self._confidence_engine = confidence_engine or ConfidenceEngine()

    def evaluate(
        self,
        db: Session,
        *,
        tenant_id: str,
        inference_run_id: str,
        graph_edge_ids: tuple[str, ...],
        evaluated_at: datetime,
        idempotency_prefix: str,
    ) -> tuple[DiscoveryHypothesisEvaluation, ...]:
        evaluated_at = _utc(evaluated_at)
        if not idempotency_prefix or len(idempotency_prefix) > 96:
            raise HypothesisEvaluationConflict("evaluation idempotency prefix is invalid")
        run = db.scalar(
            select(DiscoveryCapabilityInferenceRun).where(
                DiscoveryCapabilityInferenceRun.tenant_id == tenant_id,
                DiscoveryCapabilityInferenceRun.inference_run_id == inference_run_id,
            )
        )
        if run is None:
            raise HypothesisEvaluationConflict("inference run is outside tenant scope")
        capabilities = tuple(
            db.scalars(
                select(DiscoveryCapabilityEvidence).where(
                    DiscoveryCapabilityEvidence.tenant_id == tenant_id,
                    DiscoveryCapabilityEvidence.inference_run_id == inference_run_id,
                )
            )
        )
        edges = self._current_edges(db, tenant_id=tenant_id, graph_edge_ids=graph_edge_ids)
        node_ids = {node for edge in edges for node in (edge.from_node_id, edge.to_node_id)}
        nodes = tuple(
            db.scalars(
                select(DiscoveryResolutionGraphNode).where(
                    DiscoveryResolutionGraphNode.tenant_id == tenant_id,
                    DiscoveryResolutionGraphNode.graph_node_id.in_(node_ids),
                )
            )
        ) if node_ids else ()
        if len(nodes) != len(node_ids):
            raise HypothesisEvaluationConflict("graph nodes are outside tenant scope")
        node_classes_by_id = {node.graph_node_id: node.node_class for node in nodes}
        candidates: dict[str, list[DiscoveryCapabilityEvidence]] = {}
        for capability in capabilities:
            if capability.recommended_ecosystem != "unknown":
                candidates.setdefault(capability.recommended_ecosystem, []).append(capability)
        if not candidates:
            candidates["unknown"] = []

        rows = tuple(
            self._evaluate_candidate(
                db,
                tenant_id=tenant_id,
                run=run,
                candidate_class=candidate_class,
                capability_evidence=tuple(candidate_evidence),
                edges=edges,
                node_classes_by_id=node_classes_by_id,
                evaluated_at=evaluated_at,
                idempotency_prefix=idempotency_prefix,
            )
            for candidate_class, candidate_evidence in sorted(candidates.items())
        )
        db.flush()
        return rows

    @staticmethod
    def _current_edges(
        db: Session, *, tenant_id: str, graph_edge_ids: tuple[str, ...]
    ) -> tuple[DiscoveryResolutionGraphEdge, ...]:
        if len(set(graph_edge_ids)) != len(graph_edge_ids):
            raise HypothesisEvaluationConflict("graph edge identifiers must be unique")
        edges = tuple(
            db.scalars(
                select(DiscoveryResolutionGraphEdge).where(
                    DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                    DiscoveryResolutionGraphEdge.edge_id.in_(graph_edge_ids),
                )
            )
        ) if graph_edge_ids else ()
        if len(edges) != len(graph_edge_ids):
            raise HypothesisEvaluationConflict("graph edges are outside tenant scope")
        superseded = {
            item.predecessor_edge_id
            for item in db.scalars(
                select(DiscoveryResolutionGraphEdge).where(
                    DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                    DiscoveryResolutionGraphEdge.predecessor_edge_id.in_(graph_edge_ids),
                )
            )
            if item.predecessor_edge_id
        } if graph_edge_ids else set()
        if superseded:
            raise HypothesisEvaluationConflict("historical graph edges cannot drive current resolution")
        return tuple(sorted(edges, key=lambda item: item.edge_id))

    def _evaluate_candidate(
        self,
        db: Session,
        *,
        tenant_id: str,
        run: DiscoveryCapabilityInferenceRun,
        candidate_class: str,
        capability_evidence: tuple[DiscoveryCapabilityEvidence, ...],
        edges: tuple[DiscoveryResolutionGraphEdge, ...],
        node_classes_by_id: dict[str, str],
        evaluated_at: datetime,
        idempotency_prefix: str,
    ) -> DiscoveryHypothesisEvaluation:
        base_confidence = max((item.confidence for item in capability_evidence), default=0.0)
        required_types = _CLASS_ANCHORS.get(candidate_class, frozenset())
        required_anchors = tuple(sorted({"capability", *required_types}))
        edge_evaluations = tuple(self._edge_projection(item, evaluated_at) for item in edges)
        anchor_results = tuple(
            {
                "anchor": anchor,
                "satisfied": (
                    bool(capability_evidence)
                    if anchor == "capability"
                    else anchor in set(node_classes_by_id.values())
                ),
            }
            for anchor in required_anchors
        )
        anchors_satisfied = bool(anchor_results) and all(
            item["satisfied"] for item in anchor_results
        )
        anchor_confidences: list[float] = []
        if capability_evidence:
            anchor_confidences.append(base_confidence)
        for anchor in required_types:
            values = [
                float(projected.effective_confidence)
                for row, projected in zip(edges, edge_evaluations, strict=True)
                if projected.effective_confidence is not None
                and anchor in {
                    node_classes_by_id.get(row.from_node_id),
                    node_classes_by_id.get(row.to_node_id),
                }
            ]
            if values:
                anchor_confidences.append(max(values))
        resolution = self._confidence_engine.evaluate_resolution(
            edges=edge_evaluations,
            rule_cap=max(base_confidence, 0.01),
            anchor_confidences=tuple(anchor_confidences),
            anchors_satisfied=anchors_satisfied,
            strong_relationship=any(
                item.relationship_rule_id in {
                    "strong-identity-v1", "strong-runtime-repository-v1", "manual-resolution-v1"
                }
                for item in edges
            ),
        )
        contradiction_present = any(item.contradiction_state == "confirmed" for item in edges)
        candidate_key_hash = hashlib.sha256(
            f"{run.subject_reference_hash}:{candidate_class}".encode()
        ).hexdigest()
        hypothesis = create_hypothesis(
            db,
            tenant_id=tenant_id,
            hypothesis_type=_CLASS_TYPES.get(candidate_class, "unknown_ai_workload"),
            label=f"{candidate_class.replace('_', ' ').title()} hypothesis",
            candidate_key_hash=candidate_key_hash,
            confidence=float(resolution.confidence or base_confidence),
            verification_state="inferred",
            freshness=self._freshness(edges),
            contradiction_state="confirmed" if contradiction_present else "none",
            evidence_node_id=run.evidence_node_id,
            observed_at=_stored_utc(run.first_observed_at),
            idempotency_key=f"erg-hypothesis:{candidate_key_hash}",
        )
        if hypothesis.state == "observed":
            transition_hypothesis(
                db,
                tenant_id=tenant_id,
                hypothesis_id=hypothesis.hypothesis_id,
                target_state="hypothesized",
                evidence_node_id=run.evidence_node_id,
                actor_id="erg-hypothesis-engine",
                reason="Capability evidence produced an ecosystem hypothesis",
                idempotency_key=f"erg-hypothesized:{hypothesis.hypothesis_id}",
            )
        evaluation_idempotency_key = f"{idempotency_prefix}:{candidate_class}"
        idempotent_evaluation = db.scalar(
            select(DiscoveryHypothesisEvaluation).where(
                DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                DiscoveryHypothesisEvaluation.idempotency_key
                == evaluation_idempotency_key,
            )
        )
        if idempotent_evaluation is not None:
            predecessor_id = idempotent_evaluation.predecessor_evaluation_id
            sequence = idempotent_evaluation.evaluation_sequence
        else:
            predecessor = db.scalar(
                select(DiscoveryHypothesisEvaluation)
                .where(
                    DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                    DiscoveryHypothesisEvaluation.hypothesis_id
                    == hypothesis.hypothesis_id,
                )
                .order_by(DiscoveryHypothesisEvaluation.evaluation_sequence.desc())
                .limit(1)
            )
            predecessor_id = predecessor.evaluation_id if predecessor else None
            sequence = predecessor.evaluation_sequence + 1 if predecessor else 1
        recommendation = "manual_review" if contradiction_present else resolution.recommended_action
        limitations = sorted(set(resolution.limitations))
        decay_ids = {
            (item.decay_policy_id, item.decay_policy_version)
            for item in edge_evaluations
        }
        decay_known = bool(decay_ids) and all(
            policy_id is not None and version is not None
            for policy_id, version in decay_ids
        )
        material = {
            "tenant_id": tenant_id,
            "hypothesis_id": hypothesis.hypothesis_id,
            "inference_run_id": run.inference_run_id,
            "predecessor_evaluation_id": predecessor_id,
            "evaluation_sequence": sequence,
            "candidate_ecosystem_class": candidate_class,
            "required_anchors": required_anchors,
            "required_anchor_results": anchor_results,
            "base_confidence": base_confidence,
            "effective_confidence": resolution.confidence,
            "evidence_quality": resolution.evidence_quality,
            "source_diversity": resolution.source_diversity,
            "recommended_action": recommendation,
            "edge_ids": [item.edge_id for item in edges],
            "evaluated_at": evaluated_at.isoformat(),
            "idempotency_prefix": idempotency_prefix,
        }
        input_digest = _digest("hawk:erg:hypothesis-evaluation:v1", material)
        if idempotent_evaluation is not None:
            if idempotent_evaluation.input_digest != input_digest:
                raise HypothesisEvaluationConflict(
                    "hypothesis evaluation idempotency conflict"
                )
            return idempotent_evaluation
        replay = db.scalar(
            select(DiscoveryHypothesisEvaluation).where(
                DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                DiscoveryHypothesisEvaluation.input_digest == input_digest,
            )
        )
        if replay is not None:
            return replay
        evaluation = DiscoveryHypothesisEvaluation(
            evaluation_id=_uuid("erg-hypothesis-evaluation", tenant_id, input_digest),
            tenant_id=tenant_id,
            hypothesis_id=hypothesis.hypothesis_id,
            inference_run_id=run.inference_run_id,
            predecessor_evaluation_id=predecessor_id,
            evaluation_sequence=sequence,
            candidate_ecosystem_class=candidate_class,
            required_anchors_json=list(required_anchors),
            required_anchor_results_json=list(anchor_results),
            base_confidence=base_confidence,
            effective_confidence=resolution.confidence,
            evidence_quality=resolution.evidence_quality,
            source_diversity=resolution.source_diversity,
            rule_id=HYPOTHESIS_RULE_ID,
            rule_version=HYPOTHESIS_RULE_VERSION,
            confidence_methodology_id=HYPOTHESIS_METHODOLOGY_ID,
            confidence_methodology_version=HYPOTHESIS_METHODOLOGY_VERSION,
            decay_policy_id=(
                "erg-current-edge-decay-policies" if decay_known else "unknown"
            ),
            decay_policy_version="1.0.0" if decay_known else "unknown",
            threshold_considered=resolution.create_threshold,
            recommended_action=recommendation,
            first_observed_at=_stored_utc(run.first_observed_at),
            last_observed_at=_stored_utc(run.last_observed_at),
            validated_at=evaluated_at,
            limitations_json=limitations,
            idempotency_key=evaluation_idempotency_key,
            input_digest=input_digest,
        )
        db.add(evaluation)
        db.flush()
        for edge in edges:
            contribution = "contradicting" if edge.contradiction_state == "confirmed" else "supporting"
            required_anchor = bool(
                required_types.intersection({
                    node_classes_by_id.get(edge.from_node_id, ""),
                    node_classes_by_id.get(edge.to_node_id, ""),
                })
            )
            link_material = {
                "evaluation_id": evaluation.evaluation_id,
                "graph_edge_id": edge.edge_id,
                "contribution": contribution,
                "required_anchor": required_anchor,
            }
            link_digest = _digest("hawk:erg:hypothesis-evaluation-edge:v1", link_material)
            db.add(
                DiscoveryHypothesisEvaluationEdge(
                    evaluation_edge_id=_uuid("erg-hypothesis-evaluation-edge", tenant_id, link_digest),
                    tenant_id=tenant_id,
                    evaluation_id=evaluation.evaluation_id,
                    graph_edge_id=edge.edge_id,
                    contribution=contribution,
                    required_anchor=required_anchor,
                    input_digest=link_digest,
                )
            )
        hypothesis.confidence = float(resolution.confidence or base_confidence)
        hypothesis.last_observed_at = run.last_observed_at
        hypothesis.freshness = self._freshness(edges)
        hypothesis.contradiction_state = "confirmed" if contradiction_present else "none"
        hypothesis.version += 1
        db.flush()
        return evaluation

    @staticmethod
    def _freshness(edges: tuple[DiscoveryResolutionGraphEdge, ...]) -> str:
        if any(item.freshness == "expired" for item in edges):
            return "expired"
        if any(item.freshness == "stale" for item in edges):
            return "stale"
        return "fresh" if edges else "unknown"

    def _edge_projection(
        self, row: DiscoveryResolutionGraphEdge, evaluated_at: datetime
    ) -> EdgeConfidenceEvaluation:
        return self._confidence_engine.evaluate_edge(
            edge=EdgeConfidenceInput(
                edge_id=row.edge_id,
                signal_class=row.signal_class,
                source_surface=row.source_surface,
                collector_id=row.collector_id or "system",
                base_confidence=row.base_confidence,
                relationship_weight=row.relationship_weight,
                observation_quality=row.observation_quality_factor,
                collector_quality=row.collector_quality_factor,
                observed_at=_stored_utc(row.last_observed_at),
                last_validated_at=_stored_utc(row.last_validated_at),
                validation_state=row.verification_state,
                contradiction_state=(
                    "unresolved"
                    if row.contradiction_state == "confirmed"
                    else row.contradiction_state
                ),
                declared_freshness=row.freshness,
                relationship_rule_id=row.relationship_rule_id,
                relationship_rule_version=row.relationship_rule_version,
            ),
            evaluated_at=evaluated_at,
        )


__all__ = ["HypothesisEngine", "HypothesisEvaluationConflict"]
