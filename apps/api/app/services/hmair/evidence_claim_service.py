from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryEvidenceClaim,
)
from app.db.models.discovery_canonical import DiscoveryObservation
from app.db.models.evidence import EvidenceNode
from app.services.hmair.contracts import (
    EvidenceClaimCreate,
    _canonicalize_evidence_claim_input,
)


class EvidenceClaimScopeError(RuntimeError):
    """Referenced evidence is unavailable in the tenant scope."""


class EvidenceClaimConflict(RuntimeError):
    """An idempotency key was reused with different canonical material."""


def _utc_moment(value: datetime) -> datetime:
    """Compare database-normalized and wire timestamps as the same UTC instant."""

    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _same_moment(left: datetime, right: datetime) -> bool:
    return _utc_moment(left) == _utc_moment(right)


def _tenant_observation(
    db: Session, *, tenant_id: str, observation_id: str
) -> DiscoveryObservation | None:
    return db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.tenant_id == tenant_id,
            DiscoveryObservation.observation_id == observation_id,
        )
    )


def _tenant_asset(
    db: Session, *, tenant_id: str, asset_id: str
) -> DiscoveryAIAsset | None:
    return db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )


def _tenant_evidence_node(
    db: Session, *, tenant_id: str, node_id: str
) -> EvidenceNode | None:
    return db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id == node_id,
        )
    )


def require_evidence_claim(
    db: Session,
    *,
    tenant_id: str,
    claim_id: str,
    evidence_node_id: str | None = None,
    require_fresh: bool = False,
) -> DiscoveryEvidenceClaim:
    claim = db.scalar(
        select(DiscoveryEvidenceClaim).where(
            DiscoveryEvidenceClaim.tenant_id == tenant_id,
            DiscoveryEvidenceClaim.claim_id == claim_id,
        )
    )
    if claim is None:
        raise EvidenceClaimScopeError("evidence claim is unavailable")
    if evidence_node_id is not None and claim.evidence_node_id != evidence_node_id:
        raise EvidenceClaimScopeError("evidence claim authority does not match")
    if require_fresh and claim.freshness != "fresh":
        raise EvidenceClaimScopeError("evidence claim is not fresh")
    source = _tenant_observation(
        db,
        tenant_id=tenant_id,
        observation_id=claim.source_observation_id,
    )
    node = _tenant_evidence_node(
        db, tenant_id=tenant_id, node_id=claim.evidence_node_id
    )
    if (
        source is None
        or node is None
        or not _same_moment(claim.observed_at, source.observed_at)
    ):
        raise EvidenceClaimScopeError("evidence claim provenance is unavailable")
    if require_fresh and source.freshness != "fresh":
        raise EvidenceClaimScopeError("source observation is not fresh")
    return claim


def persist_evidence_claim(
    db: Session,
    *,
    tenant_id: str,
    payload: EvidenceClaimCreate,
) -> DiscoveryEvidenceClaim:
    source = _tenant_observation(
        db,
        tenant_id=tenant_id,
        observation_id=payload.source_observation_id,
    )
    node = _tenant_evidence_node(
        db, tenant_id=tenant_id, node_id=payload.evidence_node_id
    )
    subject_observation = (
        _tenant_observation(
            db,
            tenant_id=tenant_id,
            observation_id=payload.subject_observation_id,
        )
        if payload.subject_observation_id is not None
        else None
    )
    subject_asset = (
        _tenant_asset(
            db, tenant_id=tenant_id, asset_id=payload.subject_asset_id
        )
        if payload.subject_asset_id is not None
        else None
    )
    if (
        source is None
        or node is None
        or not _same_moment(payload.observed_at, source.observed_at)
        or (
            payload.subject_observation_id is not None
            and subject_observation is None
        )
        or (payload.subject_asset_id is not None and subject_asset is None)
    ):
        raise EvidenceClaimScopeError("evidence claim scope is unavailable")

    material = _canonicalize_evidence_claim_input(
        tenant_id=tenant_id, payload=payload
    )
    existing = db.scalar(
        select(DiscoveryEvidenceClaim).where(
            DiscoveryEvidenceClaim.tenant_id == tenant_id,
            DiscoveryEvidenceClaim.idempotency_key == payload.idempotency_key,
        )
    )
    if existing is not None:
        if existing.input_digest != material.input_digest:
            raise EvidenceClaimConflict("evidence claim idempotency conflict")
        return existing

    claim = DiscoveryEvidenceClaim(
        claim_id=str(uuid4()),
        tenant_id=tenant_id,
        claim_type=payload.claim_type,
        subject_observation_id=payload.subject_observation_id,
        subject_asset_id=payload.subject_asset_id,
        source_observation_id=payload.source_observation_id,
        evidence_node_id=payload.evidence_node_id,
        claim_result=payload.claim_result,
        claim_method=payload.claim_method,
        limitations_json=list(payload.limitations),
        confidence=payload.confidence,
        freshness=payload.freshness.value,
        observed_at=payload.observed_at,
        idempotency_key=payload.idempotency_key,
        input_digest=material.input_digest,
    )
    db.add(claim)
    db.flush()
    return claim


__all__ = [
    "EvidenceClaimConflict",
    "EvidenceClaimScopeError",
    "persist_evidence_claim",
    "require_evidence_claim",
]
