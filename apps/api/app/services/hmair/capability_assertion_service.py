from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAICapability
from app.services.hmair.contracts import (
    AICapabilityAssertionCreate,
    _canonicalize_ai_capability_input,
)
from app.services.hmair.evidence_claim_service import (
    EvidenceClaimScopeError,
    require_evidence_claim,
)
from app.services.hmair.fingerprint_service import (
    AssertionChainConflict,
    _asset_and_observation,
)


def persist_capability_assertion(
    db: Session,
    *,
    tenant_id: str,
    payload: AICapabilityAssertionCreate,
) -> DiscoveryAICapability:
    _asset, observation = _asset_and_observation(
        db,
        tenant_id=tenant_id,
        asset_id=payload.asset_id,
        observation_id=payload.source_observation_id,
    )
    claim = require_evidence_claim(
        db,
        tenant_id=tenant_id,
        claim_id=payload.evidence_claim_id,
        require_fresh=True,
    )
    if (
        claim.source_observation_id != observation.observation_id
        or (
            claim.subject_asset_id != payload.asset_id
            and claim.subject_observation_id != payload.source_observation_id
        )
    ):
        raise EvidenceClaimScopeError("capability claim does not bind the asset")

    material = _canonicalize_ai_capability_input(
        tenant_id=tenant_id, payload=payload
    )
    replay = db.scalar(
        select(DiscoveryAICapability).where(
            DiscoveryAICapability.tenant_id == tenant_id,
            DiscoveryAICapability.asset_id == payload.asset_id,
            DiscoveryAICapability.capability_name == payload.name.value,
            DiscoveryAICapability.capability_state == payload.state.value,
            DiscoveryAICapability.extractor_version == payload.extractor_version,
            DiscoveryAICapability.input_digest == material.input_digest,
        )
    )
    if replay is not None:
        return replay

    current = db.scalar(
        select(DiscoveryAICapability)
        .where(
            DiscoveryAICapability.tenant_id == tenant_id,
            DiscoveryAICapability.asset_id == payload.asset_id,
            DiscoveryAICapability.capability_name == payload.name.value,
        )
        .order_by(
            DiscoveryAICapability.assertion_sequence.desc(),
            DiscoveryAICapability.capability_id.desc(),
        )
        .limit(1)
    )
    if current is None:
        if payload.supersedes_capability_id is not None:
            raise AssertionChainConflict("capability root has a predecessor")
        sequence = 1
    else:
        if payload.supersedes_capability_id != current.capability_id:
            raise AssertionChainConflict("capability predecessor is not current")
        sequence = current.assertion_sequence + 1

    row = DiscoveryAICapability(
        capability_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_id=payload.asset_id,
        source_observation_id=payload.source_observation_id,
        evidence_claim_id=payload.evidence_claim_id,
        capability_name=payload.name.value,
        capability_state=payload.state.value,
        extractor_version=payload.extractor_version,
        assertion_sequence=sequence,
        supersedes_capability_id=payload.supersedes_capability_id,
        input_digest=material.input_digest,
        confidence=payload.confidence,
        verification_state="unknown",
        freshness="unknown",
        observed_usage=False,
        declared_only=payload.state.value == "declared",
        inferred_only=payload.state.value == "inferred",
        first_observed_at=payload.first_observed_at,
        last_observed_at=payload.last_observed_at,
    )
    db.add(row)
    db.flush()
    return row


__all__ = ["persist_capability_assertion"]
