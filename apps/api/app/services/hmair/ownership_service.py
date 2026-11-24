from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_attribution import DiscoveryAssetOwnershipAssertion
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.evidence_claim_service import EvidenceClaimScopeError


OWNER_TYPES = frozenset({"business_owner", "technical_owner", "team", "department", "repository_owner", "cloud_account", "saas_admin", "cost_center", "unknown"})


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceClaimScopeError("ownership timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def assert_ownership(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    owner_type: str,
    owner_reference_hash: str | None,
    ownership_state: str,
    evidence_node_id: str,
    confidence: float,
    verification_state: str,
    first_observed_at: datetime,
    last_observed_at: datetime,
    idempotency_key: str,
) -> DiscoveryAssetOwnershipAssertion:
    if owner_type not in OWNER_TYPES or ownership_state not in {"asserted", "inferred", "verified", "unknown", "contradicted"}:
        raise EvidenceClaimScopeError("ownership type or state is invalid")
    if (owner_type == "unknown") != (owner_reference_hash is None):
        raise EvidenceClaimScopeError("unknown ownership must remain unassigned")
    if owner_reference_hash is not None and (len(owner_reference_hash) != 64 or any(c not in "0123456789abcdef" for c in owner_reference_hash)):
        raise EvidenceClaimScopeError("owner reference must be pseudonymous")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0 or verification_state not in {"verified", "partially_verified", "inferred", "unknown"}:
        raise EvidenceClaimScopeError("ownership truth is invalid")
    first_observed_at, last_observed_at = _utc(first_observed_at), _utc(last_observed_at)
    if first_observed_at > last_observed_at:
        raise EvidenceClaimScopeError("ownership timestamps are out of order")
    asset = db.scalar(select(DiscoveryAIAsset).where(DiscoveryAIAsset.tenant_id == tenant_id, DiscoveryAIAsset.asset_id == asset_id))
    evidence = db.scalar(select(EvidenceNode).where(EvidenceNode.tenant_id == tenant_id, EvidenceNode.id == evidence_node_id))
    if asset is None or evidence is None:
        raise EvidenceClaimScopeError("ownership authority is unavailable")
    material = {"tenant_id": tenant_id, "asset_id": asset_id, "owner_type": owner_type, "owner_reference_hash": owner_reference_hash, "ownership_state": ownership_state, "evidence_node_id": evidence_node_id, "confidence": confidence, "verification_state": verification_state, "first_observed_at": first_observed_at.isoformat(), "last_observed_at": last_observed_at.isoformat()}
    digest = hashlib.sha256(b"hawk:discovery:ownership:v1" + canonical_json_bytes(material)).hexdigest()
    existing = db.scalar(select(DiscoveryAssetOwnershipAssertion).where(DiscoveryAssetOwnershipAssertion.tenant_id == tenant_id, DiscoveryAssetOwnershipAssertion.idempotency_key == idempotency_key))
    if existing is not None:
        if existing.input_digest != digest:
            raise EvidenceClaimScopeError("ownership idempotency conflict")
        return existing
    row = DiscoveryAssetOwnershipAssertion(ownership_assertion_id=str(uuid4()), tenant_id=tenant_id, asset_id=asset_id, owner_type=owner_type, owner_reference_hash=owner_reference_hash, ownership_state=ownership_state, evidence_node_id=evidence_node_id, confidence=confidence, verification_state=verification_state, first_observed_at=first_observed_at, last_observed_at=last_observed_at, idempotency_key=idempotency_key, input_digest=digest)
    db.add(row)
    db.flush()
    return row


__all__ = ["OWNER_TYPES", "assert_ownership"]
