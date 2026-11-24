from __future__ import annotations

from datetime import timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.capability_inference import DiscoveryCapabilityEvent
from app.db.models.discovery_resolution import DiscoveryResolutionGraphEdge
from app.db.models.evidence_resolution import (
    DiscoveryEcosystemResolutionEvent,
    DiscoveryHypothesisEvaluation,
)
from app.db.models.discovery_verification import DiscoveryVerificationEvent
from app.services.hmair.erg.contracts import EvidenceTimelineItem


_DRIFT_CATEGORIES = {
    "capability_added": "capability_drift",
    "capability_removed": "capability_drift",
    "confidence_changed": "capability_drift",
    "dependency_added": "dependency_drift",
    "dependency_removed": "dependency_drift",
    "marketplace_changed": "marketplace_drift",
    "configuration_changed": "configuration_drift",
    "permission_changed": "permission_drift",
    "identity_changed": "identity_drift",
    "usage_changed": "usage_drift",
    "model_changed": "model_drift",
    "provider_changed": "provider_drift",
    "repository_changed": "repository_drift",
    "runtime_changed": "runtime_drift",
    "data_changed": "data_drift",
    "genome_changed": "capability_drift",
}


def _stored_utc(value):
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class EvidenceTimeline:
    """Read-only chronological projection across CIE and ERG append-only facts."""

    @staticmethod
    def drift_category(event_type: str) -> str:
        return _DRIFT_CATEGORIES.get(event_type, "resolution_change")

    def list(
        self, db: Session, *, tenant_id: str, limit: int = 200
    ) -> tuple[EvidenceTimelineItem, ...]:
        if not 1 <= limit <= 1000:
            raise ValueError("timeline limit must be between 1 and 1000")
        items: list[EvidenceTimelineItem] = []
        for row in db.scalars(select(DiscoveryCapabilityEvent).where(
            DiscoveryCapabilityEvent.tenant_id == tenant_id
        )):
            items.append(EvidenceTimelineItem(
                event_id=row.event_id, event_type=row.event_type,
                drift_category=self.drift_category(row.event_type),
                source_type="capability_event", source_reference=row.entity_reference,
                occurred_at=row.occurred_at, changed_resolution=False,
                ecosystem_ids=(), evidence_references=tuple(row.evidence_references_json),
                summary=f"{row.event_type.replace('_', ' ')}: {row.entity_reference}",
                before=dict(row.before_json), after=dict(row.after_json),
            ))
        for row in db.scalars(select(DiscoveryResolutionGraphEdge).where(
            DiscoveryResolutionGraphEdge.tenant_id == tenant_id,
            DiscoveryResolutionGraphEdge.predecessor_edge_id.is_not(None),
        )):
            items.append(EvidenceTimelineItem(
                event_id=f"graph:{row.edge_id}", event_type="relationship_changed",
                drift_category="relationship_drift", source_type="graph_edge",
                source_reference=row.edge_id, occurred_at=row.last_validated_at,
                changed_resolution=False, ecosystem_ids=(),
                evidence_references=(row.evidence_node_id,),
                summary=f"{row.edge_type.replace('_', ' ')} relationship re-evaluated",
                before={"predecessor_edge_id": row.predecessor_edge_id},
                after={"edge_id": row.edge_id, "confidence": row.confidence,
                       "freshness": row.freshness,
                       "contradiction_state": row.contradiction_state},
            ))
        for row in db.scalars(select(DiscoveryHypothesisEvaluation).where(
            DiscoveryHypothesisEvaluation.tenant_id == tenant_id
        )):
            items.append(EvidenceTimelineItem(
                event_id=f"hypothesis:{row.evaluation_id}",
                event_type="hypothesis_evaluated", drift_category="hypothesis_change",
                source_type="hypothesis_evaluation", source_reference=row.hypothesis_id,
                occurred_at=row.validated_at, changed_resolution=False,
                ecosystem_ids=(), evidence_references=(row.inference_run_id,),
                summary=f"{row.candidate_ecosystem_class.replace('_', ' ')} hypothesis evaluated",
                before={"predecessor_evaluation_id": row.predecessor_evaluation_id},
                after={"evaluation_id": row.evaluation_id,
                       "confidence": row.effective_confidence,
                       "recommendation": row.recommended_action},
            ))
        for row in db.scalars(select(DiscoveryEcosystemResolutionEvent).where(
            DiscoveryEcosystemResolutionEvent.tenant_id == tenant_id
        )):
            items.append(EvidenceTimelineItem(
                event_id=f"resolution:{row.resolution_event_id}",
                event_type=f"ecosystem_{row.action}", drift_category="resolution_change",
                source_type="resolution_event", source_reference=row.resolution_event_id,
                occurred_at=row.occurred_at, changed_resolution=True,
                ecosystem_ids=tuple(sorted(set(row.source_ecosystem_ids_json + row.result_ecosystem_ids_json))),
                evidence_references=(row.evidence_node_id,),
                summary=row.reason,
                before={"memberships": row.before_memberships_json},
                after={"memberships": row.after_memberships_json},
            ))
        for row in db.scalars(select(DiscoveryVerificationEvent).where(
            DiscoveryVerificationEvent.tenant_id == tenant_id
        )):
            items.append(EvidenceTimelineItem(
                event_id=f"verification:{row.event_id}",
                event_type=row.event_type,
                drift_category="verification_change",
                source_type="verification_event",
                source_reference=row.assertion_id or row.episode_id or row.event_id,
                occurred_at=row.occurred_at,
                changed_resolution=False,
                ecosystem_ids=(row.ecosystem_id,),
                evidence_references=tuple(row.evidence_node_ids_json),
                summary=row.reason,
                before=dict(row.before_json),
                after=dict(row.after_json),
            ))
        items.sort(
            key=lambda item: (
                _stored_utc(item.occurred_at), item.event_id
            ),
            reverse=True,
        )
        return tuple(items[:limit])


__all__ = ["EvidenceTimeline"]
