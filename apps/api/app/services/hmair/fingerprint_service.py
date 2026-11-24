from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import (
    DiscoveryAIAsset,
    DiscoveryAssetFingerprint,
)
from app.db.models.discovery_canonical import DiscoveryObservation
from app.services.hmair.contracts import (
    AssetFingerprintCreate,
    _canonicalize_asset_fingerprint_input,
)
from app.services.hmair.evidence_claim_service import (
    EvidenceClaimScopeError,
    require_evidence_claim,
)


class AssertionChainConflict(RuntimeError):
    """An immutable assertion chain cannot be extended as requested."""


def _derive_drift_summary(
    *,
    current: DiscoveryAssetFingerprint | None,
    payload: AssetFingerprintCreate,
) -> dict[str, object]:
    """Return a compact, non-sensitive description of a successor delta.

    Callers cannot supply drift text.  This deliberately stores only changed
    categories, never the underlying hashes, identifiers, or observed values.
    """
    if current is None:
        return {
            "status": "baseline",
            "changed_component_categories": [],
            "changed_collections": [],
        }

    prior_components = dict(current.component_hashes_json or {})
    next_components = {
        key.value: value for key, value in payload.component_hashes.items()
    }
    changed_component_categories = sorted(
        key
        for key in set(prior_components) | set(next_components)
        if prior_components.get(key) != next_components.get(key)
    )
    collections = (
        (
            "products",
            tuple(current.detected_products_json or ()),
            payload.detected_products,
        ),
        (
            "frameworks",
            tuple(current.detected_frameworks_json or ()),
            payload.detected_frameworks,
        ),
        (
            "models",
            tuple(current.detected_models_json or ()),
            payload.detected_models,
        ),
        (
            "protocols",
            tuple(current.detected_protocols_json or ()),
            payload.detected_protocols,
        ),
        (
            "capabilities",
            tuple(current.detected_capabilities_json or ()),
            tuple(item.value for item in payload.detected_capabilities),
        ),
        (
            "destinations",
            tuple(current.observed_destinations_json or ()),
            payload.observed_destinations,
        ),
    )
    changed_collections = sorted(
        name for name, prior, successor in collections if prior != successor
    )
    return {
        "status": (
            "changed"
            if changed_component_categories or changed_collections
            else "unchanged"
        ),
        "changed_component_categories": changed_component_categories,
        "changed_collections": changed_collections,
    }


def _asset_and_observation(
    db: Session,
    *,
    tenant_id: str,
    asset_id: str,
    observation_id: str,
) -> tuple[DiscoveryAIAsset, DiscoveryObservation]:
    asset = db.scalar(
        select(DiscoveryAIAsset).where(
            DiscoveryAIAsset.tenant_id == tenant_id,
            DiscoveryAIAsset.asset_id == asset_id,
        )
    )
    observation = db.scalar(
        select(DiscoveryObservation).where(
            DiscoveryObservation.tenant_id == tenant_id,
            DiscoveryObservation.observation_id == observation_id,
        )
    )
    if asset is None or observation is None:
        raise EvidenceClaimScopeError("assertion scope is unavailable")
    return asset, observation


def persist_fingerprint(
    db: Session,
    *,
    tenant_id: str,
    payload: AssetFingerprintCreate,
) -> DiscoveryAssetFingerprint:
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
        raise EvidenceClaimScopeError("fingerprint claim does not bind the asset")

    material = _canonicalize_asset_fingerprint_input(
        tenant_id=tenant_id, payload=payload
    )
    replay = db.scalar(
        select(DiscoveryAssetFingerprint).where(
            DiscoveryAssetFingerprint.tenant_id == tenant_id,
            DiscoveryAssetFingerprint.asset_id == payload.asset_id,
            DiscoveryAssetFingerprint.fingerprint_version
            == payload.fingerprint_version,
            DiscoveryAssetFingerprint.input_digest == material.input_digest,
        )
    )
    if replay is not None:
        return replay

    current = db.scalar(
        select(DiscoveryAssetFingerprint)
        .where(
            DiscoveryAssetFingerprint.tenant_id == tenant_id,
            DiscoveryAssetFingerprint.asset_id == payload.asset_id,
        )
        .order_by(
            DiscoveryAssetFingerprint.chain_sequence.desc(),
            DiscoveryAssetFingerprint.fingerprint_id.desc(),
        )
        .limit(1)
    )
    if current is None:
        if payload.supersedes_fingerprint_id is not None:
            raise AssertionChainConflict("fingerprint root has a predecessor")
        sequence = 1
    else:
        if payload.supersedes_fingerprint_id != current.fingerprint_id:
            raise AssertionChainConflict("fingerprint predecessor is not current")
        sequence = current.chain_sequence + 1

    row = DiscoveryAssetFingerprint(
        fingerprint_id=str(uuid4()),
        tenant_id=tenant_id,
        asset_id=payload.asset_id,
        source_observation_id=payload.source_observation_id,
        evidence_claim_id=payload.evidence_claim_id,
        fingerprint_version=payload.fingerprint_version,
        chain_sequence=sequence,
        supersedes_fingerprint_id=payload.supersedes_fingerprint_id,
        input_digest=material.input_digest,
        component_hashes_json={
            key.value: value for key, value in payload.component_hashes.items()
        },
        detected_products_json=list(payload.detected_products),
        detected_frameworks_json=list(payload.detected_frameworks),
        detected_models_json=list(payload.detected_models),
        detected_protocols_json=list(payload.detected_protocols),
        detected_capabilities_json=[
            item.value for item in payload.detected_capabilities
        ],
        observed_destinations_json=list(payload.observed_destinations),
        confidence=payload.confidence,
        drift_summary_json=_derive_drift_summary(current=current, payload=payload),
    )
    db.add(row)
    db.flush()
    return row


__all__ = ["AssertionChainConflict", "persist_fingerprint"]
