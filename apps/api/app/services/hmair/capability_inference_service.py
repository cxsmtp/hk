from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAICapability
from app.services.hmair.contracts import DiscoveryCapabilityType, canonical_json_bytes
from app.services.hmair.evidence_claim_service import (
    EvidenceClaimScopeError,
    require_evidence_claim,
)
from app.services.hmair.fingerprint_service import (
    AssertionChainConflict,
    _asset_and_observation,
)


PHASE2_CAPABILITY_TAXONOMY = frozenset(
    item.value for item in DiscoveryCapabilityType
)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise EvidenceClaimScopeError("capability timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def infer_capability(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    source_observation_id: str,
    evidence_claim_id: str,
    name: str,
    state: str,
    confidence: float,
    verification_state: str,
    freshness: str,
    observed_usage: bool,
    declared_only: bool,
    inferred_only: bool,
    first_observed_at: datetime,
    last_observed_at: datetime,
    extractor_version: str,
    idempotency_key: str,
) -> DiscoveryAICapability:
    if name not in PHASE2_CAPABILITY_TAXONOMY:
        raise EvidenceClaimScopeError("capability is outside the Phase 2 taxonomy")
    if state not in {"declared", "configured", "observed", "inferred", "denied", "unknown"}:
        raise EvidenceClaimScopeError("capability state is invalid")
    if type(confidence) is not float or not 0.0 <= confidence <= 1.0:
        raise EvidenceClaimScopeError("capability confidence is invalid")
    if verification_state not in {"verified", "partially_verified", "inferred", "unknown"}:
        raise EvidenceClaimScopeError("capability verification state is invalid")
    if freshness not in {"fresh", "stale", "expired", "unknown"}:
        raise EvidenceClaimScopeError("capability freshness is invalid")
    if type(observed_usage) is not bool or type(declared_only) is not bool or type(inferred_only) is not bool:
        raise EvidenceClaimScopeError("capability truth dimensions must be explicit")
    if declared_only and inferred_only:
        raise EvidenceClaimScopeError("capability cannot be declared-only and inferred-only")
    first_observed_at = _utc(first_observed_at)
    last_observed_at = _utc(last_observed_at)
    if first_observed_at > last_observed_at:
        raise EvidenceClaimScopeError("capability timestamps are out of order")
    if not extractor_version or len(extractor_version) > 64:
        raise EvidenceClaimScopeError("capability extractor version is invalid")
    asset, observation = _asset_and_observation(
        db,
        tenant_id=tenant_id,
        asset_id=asset_id,
        observation_id=source_observation_id,
    )
    claim = require_evidence_claim(
        db, tenant_id=tenant_id, claim_id=evidence_claim_id, require_fresh=True
    )
    if (
        claim.source_observation_id != observation.observation_id
        or (
            claim.subject_asset_id != asset.asset_id
            and claim.subject_observation_id != observation.observation_id
        )
    ):
        raise EvidenceClaimScopeError("capability evidence does not bind the asset")
    material = {
        "tenant_id": tenant_id,
        "asset_id": asset_id,
        "source_observation_id": source_observation_id,
        "evidence_claim_id": evidence_claim_id,
        "name": name,
        "state": state,
        "confidence": confidence,
        "verification_state": verification_state,
        "freshness": freshness,
        "observed_usage": observed_usage,
        "declared_only": declared_only,
        "inferred_only": inferred_only,
        "first_observed_at": first_observed_at.isoformat(),
        "last_observed_at": last_observed_at.isoformat(),
        "extractor_version": extractor_version,
        "idempotency_key": idempotency_key,
    }
    digest = hashlib.sha256(
        b"hawk:discovery:capability-intelligence:v1"
        + canonical_json_bytes(material)
    ).hexdigest()
    replay = db.scalar(
        select(DiscoveryAICapability).where(
            DiscoveryAICapability.tenant_id == tenant_id,
            DiscoveryAICapability.asset_id == asset_id,
            DiscoveryAICapability.capability_name == name,
            DiscoveryAICapability.input_digest == digest,
        )
    )
    if replay is not None:
        return replay
    current = db.scalar(
        select(DiscoveryAICapability)
        .where(
            DiscoveryAICapability.tenant_id == tenant_id,
            DiscoveryAICapability.asset_id == asset_id,
            DiscoveryAICapability.capability_name == name,
        )
        .order_by(
            DiscoveryAICapability.assertion_sequence.desc(),
            DiscoveryAICapability.capability_id.desc(),
        )
        .limit(1)
    )
    row = DiscoveryAICapability(
        capability_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_id=asset_id,
        source_observation_id=source_observation_id,
        evidence_claim_id=evidence_claim_id,
        capability_name=name,
        capability_state=state,
        extractor_version=extractor_version,
        assertion_sequence=(current.assertion_sequence + 1 if current else 1),
        supersedes_capability_id=(current.capability_id if current else None),
        input_digest=digest,
        confidence=confidence,
        verification_state=verification_state,
        freshness=freshness,
        observed_usage=observed_usage,
        declared_only=declared_only,
        inferred_only=inferred_only,
        first_observed_at=first_observed_at,
        last_observed_at=last_observed_at,
    )
    db.add(row)
    db.flush()
    return row


__all__ = ["PHASE2_CAPABILITY_TAXONOMY", "infer_capability"]
