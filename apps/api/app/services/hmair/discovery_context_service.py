from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryAICapability,
    DiscoveryEvidenceClaim,
)
from app.db.models.discovery_attribution import (
    DiscoveryAssetIdentityLink,
    DiscoveryAssetOwnershipAssertion,
    DiscoveryAssetReachability,
)
from app.db.models.discovery_intelligence import (
    DiscoveryAssetFinding,
    DiscoveryAssetUsageFact,
    DiscoveryShadowClassification,
)
from app.db.models.discovery_resolution import DiscoveryAssetHypothesis
from app.services.hmair.evidence_claim_service import EvidenceClaimScopeError


def get_discovery_context(
    db: Session, *, tenant_id: str, asset_id: str
) -> dict[str, object]:
    asset = db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )
    if asset is None:
        raise EvidenceClaimScopeError("discovery asset is unavailable")
    capabilities = tuple(
        db.scalars(
            select(DiscoveryAICapability)
            .where(
                DiscoveryAICapability.tenant_id == tenant_id,
                DiscoveryAICapability.asset_id == asset_id,
            )
            .order_by(
                DiscoveryAICapability.capability_name,
                DiscoveryAICapability.assertion_sequence.desc(),
            )
        )
    )
    latest_capabilities: dict[str, DiscoveryAICapability] = {}
    for row in capabilities:
        latest_capabilities.setdefault(row.capability_name, row)
    reachability = tuple(db.scalars(select(DiscoveryAssetReachability).where(DiscoveryAssetReachability.tenant_id == tenant_id, DiscoveryAssetReachability.asset_id == asset_id).order_by(DiscoveryAssetReachability.created_at, DiscoveryAssetReachability.reachability_id)))
    identities = tuple(db.scalars(select(DiscoveryAssetIdentityLink).where(DiscoveryAssetIdentityLink.tenant_id == tenant_id, DiscoveryAssetIdentityLink.asset_id == asset_id).order_by(DiscoveryAssetIdentityLink.created_at, DiscoveryAssetIdentityLink.identity_link_id)))
    ownership = tuple(db.scalars(select(DiscoveryAssetOwnershipAssertion).where(DiscoveryAssetOwnershipAssertion.tenant_id == tenant_id, DiscoveryAssetOwnershipAssertion.asset_id == asset_id).order_by(DiscoveryAssetOwnershipAssertion.created_at, DiscoveryAssetOwnershipAssertion.ownership_assertion_id)))
    usage = tuple(
        db.scalars(
            select(DiscoveryAssetUsageFact)
            .where(
                DiscoveryAssetUsageFact.tenant_id == tenant_id,
                DiscoveryAssetUsageFact.asset_id == asset_id,
            )
            .order_by(
                DiscoveryAssetUsageFact.created_at.desc(),
                DiscoveryAssetUsageFact.usage_fact_id.desc(),
            )
        )
    )
    classifications = tuple(
        db.scalars(
            select(DiscoveryShadowClassification)
            .where(
                DiscoveryShadowClassification.tenant_id == tenant_id,
                DiscoveryShadowClassification.asset_id == asset_id,
            )
            .order_by(
                DiscoveryShadowClassification.created_at.desc(),
                DiscoveryShadowClassification.classification_id.desc(),
            )
        )
    )
    findings = tuple(
        db.scalars(
            select(DiscoveryAssetFinding)
            .where(
                DiscoveryAssetFinding.tenant_id == tenant_id,
                DiscoveryAssetFinding.asset_id == asset_id,
            )
            .order_by(
                DiscoveryAssetFinding.last_seen_at.desc(),
                DiscoveryAssetFinding.finding_id.desc(),
            )
        )
    )
    hypotheses = tuple(
        db.scalars(
            select(DiscoveryAssetHypothesis)
            .where(
                DiscoveryAssetHypothesis.tenant_id == tenant_id,
                DiscoveryAssetHypothesis.promoted_asset_id == asset_id,
            )
            .order_by(
                DiscoveryAssetHypothesis.last_observed_at.desc(),
                DiscoveryAssetHypothesis.hypothesis_id.desc(),
            )
        )
    )
    claims = tuple(
        db.scalars(
            select(DiscoveryEvidenceClaim)
            .where(
                DiscoveryEvidenceClaim.tenant_id == tenant_id,
                DiscoveryEvidenceClaim.subject_asset_id == asset_id,
            )
            .order_by(
                DiscoveryEvidenceClaim.created_at.desc(),
                DiscoveryEvidenceClaim.claim_id.desc(),
            )
        )
    )
    return {
        "asset": {
            "asset_id": asset.asset_id,
            "asset_type": asset.asset_type,
            "canonical_name": asset.canonical_name,
            "provider": asset.provider,
            "environment": asset.environment,
            "governance_state": asset.approved_status,
            "resolution_confidence": float(asset.resolution_confidence),
            "evidence_bundle_id": asset.evidence_bundle_id,
        },
        "capabilities": [
            {
                "name": row.capability_name,
                "state": row.capability_state,
                "evidence_claim_id": row.evidence_claim_id,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
                "freshness": row.freshness,
                "observed_usage": row.observed_usage,
                "declared_only": row.declared_only,
                "inferred_only": row.inferred_only,
                "first_seen": row.first_observed_at.isoformat(),
                "last_seen": row.last_observed_at.isoformat(),
            }
            for row in latest_capabilities.values()
        ],
        "reachability": [
            {
                "target_category": row.target_category,
                "target_reference_hash": row.target_reference_hash,
                "state": row.reachability_state,
                "evidence_node_id": row.evidence_node_id,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
                "freshness": row.freshness,
                "observed_usage": row.observed_usage,
                "limitations": list(row.limitations_json),
            }
            for row in reachability
        ],
        "identities": [
            {
                "identity_type": row.identity_type,
                "identity_reference_hash": row.identity_reference_hash,
                "access_state": row.access_state,
                "usage_proven": row.usage_proven,
                "evidence_node_id": row.evidence_node_id,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
            }
            for row in identities
        ],
        "ownership": [
            {
                "owner_type": row.owner_type,
                "owner_reference_hash": row.owner_reference_hash,
                "state": row.ownership_state,
                "evidence_node_id": row.evidence_node_id,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
            }
            for row in ownership
        ],
        "dependencies": [],
        "usage": [
            {
                "usage_fact_id": row.usage_fact_id,
                "usage_state": row.usage_state,
                "actor_type": row.actor_type,
                "actor_reference_hash": row.actor_reference_hash,
                "event_count": row.event_count,
                "source_surface": row.source_surface,
                "evidence_node_id": row.evidence_node_id,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
                "freshness": row.freshness,
                "telemetry_complete": row.telemetry_complete,
                "methodology_id": row.methodology_id,
                "first_seen": row.first_observed_at.isoformat()
                if row.first_observed_at
                else None,
                "last_seen": row.last_observed_at.isoformat()
                if row.last_observed_at
                else None,
                "limitations": list(row.limitations_json),
            }
            for row in usage
        ],
        "shadow_classifications": [
            {
                "classification_id": row.classification_id,
                "management_class": row.management_class,
                "shadow_type": row.shadow_type,
                "severity": row.severity,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
                "evidence_node_ids": list(row.evidence_node_ids_json),
                "methodology_id": row.methodology_id,
                "limitations": list(row.limitations_json),
            }
            for row in classifications
        ],
        "findings": [
            {
                "finding_id": row.finding_id,
                "finding_type": row.finding_type,
                "severity": row.severity,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
                "evidence_node_ids": list(row.evidence_node_ids_json),
                "remediation": row.remediation,
                "verification_action": row.verification_action,
                "coverage_impact": row.coverage_impact,
                "status": row.status,
            }
            for row in findings
        ],
        "hypotheses": [
            {
                "hypothesis_id": row.hypothesis_id,
                "hypothesis_type": row.hypothesis_type,
                "state": row.state,
                "confidence": float(row.confidence),
                "verification_state": row.verification_state,
                "freshness": row.freshness,
                "contradiction_state": row.contradiction_state,
                "evidence_node_id": row.evidence_node_id,
            }
            for row in hypotheses
        ],
        "evidence": [
            {
                "claim_id": row.claim_id,
                "claim_type": row.claim_type,
                "claim_result": row.claim_result,
                "claim_method": row.claim_method,
                "evidence_node_id": row.evidence_node_id,
                "confidence": float(row.confidence),
                "freshness": row.freshness,
                "observed_at": row.observed_at.isoformat(),
                "limitations": list(row.limitations_json),
            }
            for row in claims
        ],
        "control_coverage_ref": None,
    }


__all__ = ["get_discovery_context"]
