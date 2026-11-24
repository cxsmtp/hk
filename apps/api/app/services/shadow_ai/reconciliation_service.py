from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.ai_system import AISystem
from app.db.models.shadow_ai import ShadowAIEntity, ShadowAISignal
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.findings_service import generate_shadow_ai_entity_finding


@dataclass
class ReconciliationResult:
    ai_system_id: str | None
    promoted: bool
    reason: str


def _safe_link(
    db: Session,
    *,
    tenant_id: str,
    from_node_id: str | None,
    to_node_id: str | None,
    edge_type: str,
    payload: dict[str, Any] | None = None,
) -> None:
    if not from_node_id or not to_node_id:
        return
    try:
        link_evidence_nodes(
            db,
            tenant_id=tenant_id,
            from_node_id=from_node_id,
            to_node_id=to_node_id,
            edge_type=edge_type,
            payload=payload or {},
        )
    except Exception:
        return


def _to_ai_system_risk(risk_tier: str | None) -> str:
    normalized = str(risk_tier or "").strip().upper()
    if normalized in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"}:
        return normalized
    return "MEDIUM"


def reconcile_to_trust_center_candidate(
    db: Session,
    *,
    tenant_id: str,
    entity: ShadowAIEntity,
    confidence_score: float,
    confidence_level: str,
    evidence_node_ids: list[str],
    actor_user_id: str | None = None,
    force_promote: bool = False,
) -> ReconciliationResult:
    threshold = float(getattr(settings, "shadow_ai_auto_promote_confidence_threshold", 0.8))
    if entity.linked_ai_system_id:
        return ReconciliationResult(
            ai_system_id=entity.linked_ai_system_id,
            promoted=False,
            reason="already_linked",
        )

    if not force_promote and (confidence_score < threshold or confidence_level != "high"):
        return ReconciliationResult(
            ai_system_id=None,
            promoted=False,
            reason="confidence_below_threshold",
        )

    now = datetime.now(timezone.utc)
    ai_system = AISystem(
        tenant_id=tenant_id,
        name=entity.canonical_name,
        description="Auto-created candidate from shadow AI discovery correlation",
        risk_tier=_to_ai_system_risk(entity.provisional_risk_tier),
        status="pending_review",
        metadata_json={
            "source": "SHADOW_DISCOVERY",
            "governance_state": "REVIEW",
            "lifecycle_state": "PENDING_REVIEW",
            "ownership_state": "UNKNOWN",
            "business_owner": "UNKNOWN",
            "technical_owner": "UNKNOWN",
            "discovered_via": list(entity.source_surfaces or []),
            "evidence_summary": {"shadow_entity_id": entity.id, "evidence_node_ids": list(evidence_node_ids)},
            "confidence_score": confidence_score,
            "provisional_risk_tier": entity.provisional_risk_tier,
            "classification_inference": {
                "ai_type": str(entity.ai_type or "").strip() or None,
                "deployment_type": str(entity.deployment_type or "").strip() or None,
                "data_access": str((entity.metadata_json or {}).get("data_access") or "").strip() or "unknown",
            },
            "remediation_requirements": [
                "business_owner_assignment",
                "technical_owner_assignment",
                "risk_classification",
                "policy_mapping",
                "governance_review",
            ],
            "created_at": now.isoformat(),
        },
    )
    db.add(ai_system)
    db.flush()

    entity.linked_ai_system_id = ai_system.id
    entity.discovery_status = "promoted"
    db.flush()

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="system" if actor_user_id is None else "human",
        action="shadow_ai.entity.promoted_to_trust_center_candidate",
        resource_type="shadow_ai_entity",
        resource_id=entity.id,
        payload={
            "ai_system_id": ai_system.id,
            "status": ai_system.status,
            "confidence_score": confidence_score,
            "source": "SHADOW_DISCOVERY",
        },
    )

    entity_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_entity",
        signal_type="shadow_ai.entity",
        label=f"Shadow AI entity {entity.canonical_name}",
        payload={
            "shadow_ai_entity_id": entity.id,
            "discovery_status": entity.discovery_status,
            "confidence_score": confidence_score,
            "source_surfaces": list(entity.source_surfaces or []),
        },
    )
    ai_system_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="ai_system_candidate",
        signal_type="shadow_ai.trust_center_candidate",
        label=f"Trust Center candidate for {entity.canonical_name}",
        payload={
            "shadow_ai_entity_id": entity.id,
            "ai_system_id": ai_system.id,
            "status": "pending_review",
        },
    )
    _safe_link(
        db,
        tenant_id=tenant_id,
        from_node_id=entity_node.id,
        to_node_id=ai_system_node.id,
        edge_type="shadow_ai.entity_to_ai_system",
        payload={"ai_system_id": ai_system.id},
    )
    for node_id in evidence_node_ids:
        _safe_link(
            db,
            tenant_id=tenant_id,
            from_node_id=node_id,
            to_node_id=entity_node.id,
            edge_type="shadow_ai.evidence_to_entity",
            payload={},
        )

    generate_shadow_ai_entity_finding(
        db,
        tenant_id=tenant_id,
        entity=entity,
        finding_type="shadow_ai_discovered",
        severity="high",
        source_surface=(str(entity.source_surfaces[0]) if entity.source_surfaces else "connector"),
        evidence_node_ids=[*evidence_node_ids, entity_node.id, ai_system_node.id],
        related_control_ids=["CTRL-TENANT-ISO-001"],
        recommended_action="route_to_governance",
        ai_system_id=ai_system.id,
    )

    return ReconciliationResult(
        ai_system_id=ai_system.id,
        promoted=True,
        reason="candidate_created",
    )


def link_entity_to_ai_system(
    db: Session,
    *,
    tenant_id: str,
    entity: ShadowAIEntity,
    ai_system_id: str,
    actor_user_id: str | None = None,
) -> ShadowAIEntity:
    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.tenant_id == tenant_id,
            AISystem.id == ai_system_id,
        )
    )
    if ai_system is None:
        raise ValueError("AI system not found")

    entity.linked_ai_system_id = ai_system.id
    entity.discovery_status = "reconciled"
    db.flush()

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="shadow_ai.entity.linked_to_ai_system",
        resource_type="shadow_ai_entity",
        resource_id=entity.id,
        payload={"ai_system_id": ai_system.id},
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_action",
        signal_type="shadow_ai.entity.linked_to_ai_system",
        label=f"Shadow AI entity linked to AI system {ai_system.id}",
        payload={"shadow_ai_entity_id": entity.id, "ai_system_id": ai_system.id},
    )
    return entity


def reject_shadow_entity(
    db: Session,
    *,
    tenant_id: str,
    entity: ShadowAIEntity,
    reason: str | None,
    actor_user_id: str | None = None,
) -> ShadowAIEntity:
    entity.discovery_status = "rejected"
    metadata = dict(entity.metadata_json or {})
    metadata["rejected_reason"] = str(reason or "manual_review_rejected")
    entity.metadata_json = metadata
    db.flush()

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="shadow_ai.entity.rejected",
        resource_type="shadow_ai_entity",
        resource_id=entity.id,
        payload={"reason": reason or "manual_review_rejected"},
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_action",
        signal_type="shadow_ai.entity.rejected",
        label=f"Shadow AI entity rejected: {entity.canonical_name}",
        payload={"shadow_ai_entity_id": entity.id, "reason": reason or "manual_review_rejected"},
    )
    return entity


def merge_shadow_entities(
    db: Session,
    *,
    tenant_id: str,
    source_entity: ShadowAIEntity,
    target_entity: ShadowAIEntity,
    actor_user_id: str | None = None,
) -> ShadowAIEntity:
    if source_entity.id == target_entity.id:
        return target_entity
    if source_entity.tenant_id != tenant_id or target_entity.tenant_id != tenant_id:
        raise ValueError("entity tenant mismatch")

    target_entity.source_surfaces = sorted(
        {
            *[str(item).strip().lower() for item in (target_entity.source_surfaces or []) if str(item).strip()],
            *[str(item).strip().lower() for item in (source_entity.source_surfaces or []) if str(item).strip()],
        }
    )
    target_entity.first_seen = min(target_entity.first_seen, source_entity.first_seen)
    target_entity.last_seen = max(target_entity.last_seen, source_entity.last_seen)
    target_entity.confidence_score = max(float(target_entity.confidence_score or 0.0), float(source_entity.confidence_score or 0.0))
    if not target_entity.linked_ai_system_id and source_entity.linked_ai_system_id:
        target_entity.linked_ai_system_id = source_entity.linked_ai_system_id

    source_signals = db.scalars(
        select(ShadowAISignal).where(
            ShadowAISignal.tenant_id == tenant_id,
            ShadowAISignal.shadow_ai_entity_id == source_entity.id,
        )
    ).all()
    for signal in source_signals:
        signal.shadow_ai_entity_id = target_entity.id

    source_entity.discovery_status = "rejected"
    source_metadata = dict(source_entity.metadata_json or {})
    source_metadata["merged_into"] = target_entity.id
    source_entity.metadata_json = source_metadata
    db.flush()

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="shadow_ai.entity.merged",
        resource_type="shadow_ai_entity",
        resource_id=source_entity.id,
        payload={"merged_into": target_entity.id},
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="shadow_ai_action",
        signal_type="shadow_ai.entity.merged",
        label=f"Shadow AI entity merged into {target_entity.canonical_name}",
        payload={"source_shadow_ai_entity_id": source_entity.id, "target_shadow_ai_entity_id": target_entity.id},
    )
    return target_entity
