from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_attribution import DiscoveryAssetIdentityLink
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.evidence_claim_service import EvidenceClaimScopeError


IDENTITY_TYPES = frozenset({"user", "group", "service_principal", "managed_identity", "oauth_app", "api_key_reference", "workload_identity", "agent_identity", "unknown"})
ACCESS_STATES = frozenset({"assigned", "configured", "observed", "active", "unknown"})


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceClaimScopeError("identity timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def link_identity(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    identity_type: str,
    identity_reference_hash: str,
    access_state: str,
    evidence_node_id: str,
    confidence: float,
    verification_state: str,
    usage_proven: bool,
    first_observed_at: datetime,
    last_observed_at: datetime,
    idempotency_key: str,
) -> DiscoveryAssetIdentityLink:
    if identity_type not in IDENTITY_TYPES or access_state not in ACCESS_STATES:
        raise EvidenceClaimScopeError("identity type or access state is invalid")
    if len(identity_reference_hash) != 64 or any(c not in "0123456789abcdef" for c in identity_reference_hash):
        raise EvidenceClaimScopeError("identity reference must be pseudonymous")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise EvidenceClaimScopeError("identity confidence is invalid")
    if verification_state not in {"verified", "partially_verified", "inferred", "unknown"} or type(usage_proven) is not bool:
        raise EvidenceClaimScopeError("identity truth is invalid")
    first_observed_at, last_observed_at = _utc(first_observed_at), _utc(last_observed_at)
    if first_observed_at > last_observed_at:
        raise EvidenceClaimScopeError("identity timestamps are out of order")
    asset = db.scalar(select(DiscoveryAIAsset).where(DiscoveryAIAsset.tenant_id == tenant_id, DiscoveryAIAsset.asset_id == asset_id))
    evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id == evidence_node_id))
    if asset is None or evidence is None:
        raise EvidenceClaimScopeError("identity authority is unavailable")
    material = {"tenant_id": tenant_id, "asset_id": asset_id, "identity_type": identity_type, "identity_reference_hash": identity_reference_hash, "access_state": access_state, "evidence_node_id": evidence_node_id, "confidence": confidence, "verification_state": verification_state, "usage_proven": usage_proven, "first_observed_at": first_observed_at.isoformat(), "last_observed_at": last_observed_at.isoformat()}
    digest = hashlib.sha256(b"hawk:discovery:identity-link:v1" + canonical_json_bytes(material)).hexdigest()
    existing = db.scalar(select(DiscoveryAssetIdentityLink).where(DiscoveryAssetIdentityLink.tenant_id == tenant_id, DiscoveryAssetIdentityLink.idempotency_key == idempotency_key))
    if existing is not None:
        if existing.input_digest != digest:
            raise EvidenceClaimScopeError("identity idempotency conflict")
        return existing
    row = DiscoveryAssetIdentityLink(identity_link_id=str(uuid4()), tenant_id=tenant_id, asset_id=asset_id, identity_type=identity_type, identity_reference_hash=identity_reference_hash, access_state=access_state, evidence_node_id=evidence_node_id, confidence=confidence, verification_state=verification_state, usage_proven=usage_proven, first_observed_at=first_observed_at, last_observed_at=last_observed_at, idempotency_key=idempotency_key, input_digest=digest)
    db.add(row)
    db.flush()
    return row


__all__ = ["ACCESS_STATES", "IDENTITY_TYPES", "link_identity"]
