from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.discovery_resolution import DiscoveryResolutionGraphEdge
from app.db.models.evidence_resolution import (
    DiscoveryAIEcosystem,
    DiscoveryEcosystemMembership,
    DiscoveryHypothesisEvaluation,
    DiscoveryHypothesisEvaluationEdge,
)
from app.services.hmair.contracts import StrictContract
from app.services.hmair.erg.confidence_engine import ATTACH_THRESHOLD, CREATE_THRESHOLD
from app.services.hmair.erg.resolution_history import ResolutionHistory


class EcosystemResolutionConflict(RuntimeError):
    """The evaluation is stale, out of scope, or unsafe to resolve."""


class EcosystemResolutionOutcome(StrictContract):
    evaluation_id: str
    recommendation: str
    mutated: bool
    ecosystem_ids: tuple[str, ...] = Field(max_length=128)
    confidence: float | None
    evidence_quality: float | None
    limitations: tuple[str, ...] = Field(max_length=128)
    explanation: dict


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EcosystemResolutionConflict("resolution timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


class EcosystemResolver:
    """Conservative resolver over immutable, current hypothesis evaluations."""

    def __init__(self, *, history: ResolutionHistory | None = None) -> None:
        self._history = history or ResolutionHistory()

    def resolve(
        self,
        db: Session,
        *,
        tenant_id: str,
        evaluation_id: str,
        evidence_node_id: str,
        evaluated_at: datetime,
        idempotency_key: str,
        target_ecosystem_id: str | None = None,
    ) -> EcosystemResolutionOutcome:
        evaluated_at = _utc(evaluated_at)
        evaluation = db.scalar(
            select(DiscoveryHypothesisEvaluation).where(
                DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                DiscoveryHypothesisEvaluation.evaluation_id == evaluation_id,
            )
        )
        if evaluation is None:
            raise EcosystemResolutionConflict("hypothesis evaluation is outside tenant scope")
        successor = db.scalar(
            select(DiscoveryHypothesisEvaluation).where(
                DiscoveryHypothesisEvaluation.tenant_id == tenant_id,
                DiscoveryHypothesisEvaluation.predecessor_evaluation_id == evaluation_id,
            )
        )
        if successor is not None:
            raise EcosystemResolutionConflict("historical hypothesis evaluation cannot resolve")
        links = tuple(
            db.scalars(
                select(DiscoveryHypothesisEvaluationEdge).where(
                    DiscoveryHypothesisEvaluationEdge.tenant_id == tenant_id,
                    DiscoveryHypothesisEvaluationEdge.evaluation_id == evaluation_id,
                )
            )
        )
        edges = tuple(
            db.scalars(
                select(DiscoveryResolutionGraphEdge).where(
                    DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
                    DiscoveryResolutionGraphEdge.edge_id.in_(tuple(link.graph_edge_id for link in links)),
                )
            )
        ) if links else ()
        if len(edges) != len(links):
            raise EcosystemResolutionConflict("evaluation graph evidence is incomplete")

        limitations = set(evaluation.limitations_json)
        if evaluation.decay_policy_id == "unknown" or evaluation.decay_policy_version == "unknown":
            limitations.add("unknown_decay_policy")
        if any(link.contribution == "contradicting" for link in links):
            limitations.add("unresolved_confirmed_contradiction")
        if evaluation.source_diversity < 2:
            limitations.add("insufficient_source_diversity")
        anchor_results = tuple(evaluation.required_anchor_results_json)
        if (
            not evaluation.required_anchors_json
            or not anchor_results
            or not all(
                isinstance(item, dict) and item.get("satisfied") is True
                for item in anchor_results
            )
        ):
            limitations.add("required_anchor_missing")
        if evaluation.effective_confidence is None:
            limitations.add("edge_confidence_unknown")
        if evaluation.evidence_quality is None:
            limitations.add("evidence_quality_unknown")

        prohibited = {
            "unresolved_confirmed_contradiction",
            "unknown_decay_policy",
            "insufficient_source_diversity",
            "required_anchor_missing",
            "edge_confidence_unknown",
            "evidence_quality_unknown",
        }
        safe_create = bool(
            evaluation.recommended_action == "create_ecosystem"
            and evaluation.effective_confidence is not None
            and evaluation.effective_confidence >= CREATE_THRESHOLD
            and not limitations.intersection(prohibited)
        )
        safe_attach = bool(
            evaluation.recommended_action == "attach_observation"
            and evaluation.effective_confidence is not None
            and evaluation.effective_confidence >= ATTACH_THRESHOLD
            and not limitations.intersection(prohibited)
        )
        recommendation = "attach_observation" if safe_attach else (
            "create_ecosystem" if safe_create else (
            "unknown" if evaluation.effective_confidence is None else "manual_review"
            )
        )
        explanation = {
            "calculation_methodology": evaluation.confidence_methodology_id,
            "calculation_version": evaluation.confidence_methodology_version,
            "rule_id": evaluation.rule_id,
            "rule_version": evaluation.rule_version,
            "create_threshold": CREATE_THRESHOLD,
            "attach_threshold": ATTACH_THRESHOLD,
            "source_diversity": evaluation.source_diversity,
            "required_anchors": list(evaluation.required_anchors_json),
            "required_anchor_results": list(anchor_results),
            "supporting_edge_ids": [link.graph_edge_id for link in links if link.contribution == "supporting"],
            "contradicting_edge_ids": [link.graph_edge_id for link in links if link.contribution == "contradicting"],
        }
        if safe_attach:
            if target_ecosystem_id is None:
                limitations.add("attach_target_required")
                self._history.record_disposition(
                    db,
                    tenant_id=tenant_id,
                    action="manual_review",
                    subject_reference=f"hypothesis_evaluation:{evaluation_id}",
                    evidence_node_id=evidence_node_id,
                    confidence=evaluation.effective_confidence,
                    operator_id="erg-ecosystem-resolver",
                    operator_role="system",
                    reason="Automatic attachment requires an explicit existing ecosystem target",
                    occurred_at=evaluated_at,
                    idempotency_key=f"{idempotency_key}:disposition",
                )
                return EcosystemResolutionOutcome(
                    evaluation_id=evaluation_id,
                    recommendation="manual_review",
                    mutated=False,
                    ecosystem_ids=(),
                    confidence=evaluation.effective_confidence,
                    evidence_quality=evaluation.evidence_quality,
                    limitations=tuple(sorted(limitations)),
                    explanation=explanation,
                )
            target = db.scalar(
                select(DiscoveryAIEcosystem)
                .where(
                    DiscoveryAIEcosystem.tenant_id == tenant_id,
                    DiscoveryAIEcosystem.ecosystem_id == target_ecosystem_id,
                )
                .order_by(DiscoveryAIEcosystem.resolution_version.desc())
                .limit(1)
            )
            if target is None or target.lifecycle_state != "active":
                raise EcosystemResolutionConflict(
                    "attachment target is outside tenant scope or not active"
                )
            if target.ecosystem_class != evaluation.candidate_ecosystem_class:
                limitations.add("attach_target_class_mismatch")
                self._history.record_disposition(
                    db,
                    tenant_id=tenant_id,
                    action="manual_review",
                    subject_reference=f"hypothesis_evaluation:{evaluation_id}",
                    evidence_node_id=evidence_node_id,
                    confidence=evaluation.effective_confidence,
                    operator_id="erg-ecosystem-resolver",
                    operator_role="system",
                    reason="Attachment target class conflicts with the hypothesis",
                    occurred_at=evaluated_at,
                    idempotency_key=f"{idempotency_key}:disposition",
                )
                return EcosystemResolutionOutcome(
                    evaluation_id=evaluation_id,
                    recommendation="manual_review",
                    mutated=False,
                    ecosystem_ids=(),
                    confidence=evaluation.effective_confidence,
                    evidence_quality=evaluation.evidence_quality,
                    limitations=tuple(sorted(limitations)),
                    explanation=explanation,
                )
            graph_node_ids = tuple(
                sorted({
                    node_id
                    for edge in edges
                    for node_id in (edge.from_node_id, edge.to_node_id)
                })
            )
            member_rows = tuple(
                db.scalars(
                    select(DiscoveryEcosystemMembership)
                    .where(
                        DiscoveryEcosystemMembership.tenant_id == tenant_id,
                        DiscoveryEcosystemMembership.ecosystem_id == target_ecosystem_id,
                    )
                    .order_by(
                        DiscoveryEcosystemMembership.graph_node_id,
                        DiscoveryEcosystemMembership.membership_sequence.desc(),
                    )
                )
            )
            current_by_node: dict[str, DiscoveryEcosystemMembership] = {}
            for row in member_rows:
                current_by_node.setdefault(row.graph_node_id, row)
            new_node_ids = tuple(
                node_id
                for node_id in graph_node_ids
                if node_id not in current_by_node
                or current_by_node[node_id].membership_state != "active"
            )
            for index, graph_node_id in enumerate(new_node_ids):
                self._history.attach_observation(
                    db,
                    tenant_id=tenant_id,
                    ecosystem_id=target_ecosystem_id,
                    graph_node_id=graph_node_id,
                    evidence_node_id=evidence_node_id,
                    confidence=float(evaluation.effective_confidence),
                    evidence_quality=evaluation.evidence_quality,
                    operator_id="erg-ecosystem-resolver",
                    operator_role="system",
                    reason="Evidence passed the explicit ERG automatic-attach threshold",
                    occurred_at=evaluated_at,
                    idempotency_key=f"{idempotency_key}:attach:{index}",
                )
            return EcosystemResolutionOutcome(
                evaluation_id=evaluation_id,
                recommendation="attach_observation",
                mutated=bool(new_node_ids),
                ecosystem_ids=(target_ecosystem_id,),
                confidence=evaluation.effective_confidence,
                evidence_quality=evaluation.evidence_quality,
                limitations=tuple(sorted(limitations)),
                explanation={**explanation, "attached_graph_node_ids": list(new_node_ids)},
            )
        if not safe_create:
            self._history.record_disposition(
                db,
                tenant_id=tenant_id,
                action=recommendation,
                subject_reference=f"hypothesis_evaluation:{evaluation_id}",
                evidence_node_id=evidence_node_id,
                confidence=evaluation.effective_confidence,
                operator_id="erg-ecosystem-resolver",
                operator_role="system",
                reason=(
                    "Evidence remains insufficient for automatic ecosystem resolution"
                    if recommendation == "unknown"
                    else "Evidence requires manual ecosystem resolution review"
                ),
                occurred_at=evaluated_at,
                idempotency_key=f"{idempotency_key}:disposition",
            )
            return EcosystemResolutionOutcome(
                evaluation_id=evaluation_id,
                recommendation=recommendation,
                mutated=False,
                ecosystem_ids=(),
                confidence=evaluation.effective_confidence,
                evidence_quality=evaluation.evidence_quality,
                limitations=tuple(sorted(limitations)),
                explanation=explanation,
            )
        graph_node_ids = tuple(
            sorted({node_id for edge in edges for node_id in (edge.from_node_id, edge.to_node_id)})
        )
        if not graph_node_ids:
            raise EcosystemResolutionConflict("automatic resolution requires graph anchors")
        mutation = self._history.create_ecosystem(
            db,
            tenant_id=tenant_id,
            canonical_name=f"{evaluation.candidate_ecosystem_class.replace('_', ' ').title()} ecosystem",
            ecosystem_class=evaluation.candidate_ecosystem_class,
            graph_node_ids=graph_node_ids,
            evidence_node_id=evidence_node_id,
            confidence=evaluation.effective_confidence,
            evidence_quality=evaluation.evidence_quality,
            operator_id="erg-ecosystem-resolver",
            operator_role="system",
            reason="Evidence passed the explicit ERG automatic-create threshold",
            occurred_at=evaluated_at,
            idempotency_key=idempotency_key,
        )
        return EcosystemResolutionOutcome(
            evaluation_id=evaluation_id,
            recommendation="create_ecosystem",
            mutated=True,
            ecosystem_ids=mutation.ecosystem_ids,
            confidence=evaluation.effective_confidence,
            evidence_quality=evaluation.evidence_quality,
            limitations=tuple(sorted(limitations)),
            explanation=explanation,
        )


__all__ = ["EcosystemResolutionConflict", "EcosystemResolutionOutcome", "EcosystemResolver"]
