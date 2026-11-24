from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_attribution import DiscoveryAssetReachability
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.evidence_claim_service import EvidenceClaimScopeError


TARGET_CATEGORIES = frozenset({"model", "mcp", "internal_api", "external_api", "database", "vector_db", "filesystem", "cloud_control_plane", "saas", "ci_cd", "source_repo", "internal_network", "internet"})
REACHABILITY_STATES = frozenset({"configured", "observed", "potential", "verified", "unknown"})


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceClaimScopeError("reachability timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def assert_reachability(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    target_category: str,
    target_reference_hash: str,
    reachability_state: str,
    evidence_node_id: str,
    confidence: float,
    verification_state: str,
    freshness: str,
    observed_usage: bool,
    first_observed_at: datetime,
    last_observed_at: datetime,
    limitations: tuple[str, ...],
    idempotency_key: str,
) -> DiscoveryAssetReachability:
    if target_category not in TARGET_CATEGORIES or reachability_state not in REACHABILITY_STATES:
        raise EvidenceClaimScopeError("reachability category or state is invalid")
    if len(target_reference_hash) != 64 or any(c not in "0123456789abcdef" for c in target_reference_hash):
        raise EvidenceClaimScopeError("reachability target must be pseudonymous")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise EvidenceClaimScopeError("reachability confidence is invalid")
    if verification_state not in {"verified", "partially_verified", "inferred", "unknown"} or freshness not in {"fresh", "stale", "expired", "unknown"}:
        raise EvidenceClaimScopeError("reachability truth state is invalid")
    if type(observed_usage) is not bool:
        raise EvidenceClaimScopeError("reachability usage truth must be explicit")
    if len(limitations) > 32 or any(not item or len(item) > 255 for item in limitations):
        raise EvidenceClaimScopeError("reachability limitations are invalid")
    first_observed_at, last_observed_at = _utc(first_observed_at), _utc(last_observed_at)
    if first_observed_at > last_observed_at:
        raise EvidenceClaimScopeError("reachability timestamps are out of order")
    asset = db.scalar(select(DiscoveryAIAsset).where(DiscoveryAIAsset.tenant_id == tenant_id, DiscoveryAIAsset.asset_id == asset_id))
    evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id == evidence_node_id))
    if asset is None or evidence is None:
        raise EvidenceClaimScopeError("reachability authority is unavailable")
    material = {"tenant_id": tenant_id, "asset_id": asset_id, "target_category": target_category, "target_reference_hash": target_reference_hash, "reachability_state": reachability_state, "evidence_node_id": evidence_node_id, "confidence": confidence, "verification_state": verification_state, "freshness": freshness, "observed_usage": observed_usage, "first_observed_at": first_observed_at.isoformat(), "last_observed_at": last_observed_at.isoformat(), "limitations": limitations}
    digest = hashlib.sha256(b"hawk:discovery:reachability:v1" + canonical_json_bytes(material)).hexdigest()
    existing = db.scalar(select(DiscoveryAssetReachability).where(DiscoveryAssetReachability.tenant_id == tenant_id, DiscoveryAssetReachability.idempotency_key == idempotency_key))
    if existing is not None:
        if existing.input_digest != digest:
            raise EvidenceClaimScopeError("reachability idempotency conflict")
        return existing
    row = DiscoveryAssetReachability(reachability_id=str(uuid4()), tenant_id=tenant_id, asset_id=asset_id, target_category=target_category, target_reference_hash=target_reference_hash, reachability_state=reachability_state, evidence_node_id=evidence_node_id, confidence=confidence, verification_state=verification_state, freshness=freshness, observed_usage=observed_usage, first_observed_at=first_observed_at, last_observed_at=last_observed_at, limitations_json=list(limitations), idempotency_key=idempotency_key, input_digest=digest)
    db.add(row)
    db.flush()
    return row


__all__ = ["REACHABILITY_STATES", "TARGET_CATEGORIES", "assert_reachability"]
