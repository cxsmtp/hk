"""Bounded digest-driven incremental enrichment planning for HMAIR H5."""

from __future__ import annotations

import hashlib

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import (
    DiscoveryEvidenceClaim,
    DiscoveryObservationAssetLink,
)
from app.db.models.discovery_canonical import DiscoveryObservation

from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.governance_contracts import (
    IncrementalAssetDigest,
    IncrementalEnrichmentPlan,
)


def plan_incremental_enrichment(
    *,
    tenant_id: str,
    current: tuple[IncrementalAssetDigest, ...],
    previous: tuple[IncrementalAssetDigest, ...],
    requested_at,
    limit: int = 100,
) -> IncrementalEnrichmentPlan:
    """Select changed assets only; execution remains in existing scan workers."""

    if not 1 <= limit <= 500:
        raise ValueError("incremental enrichment limit must be between 1 and 500")
    if len(current) > 100_000 or len(previous) > 100_000:
        raise ValueError("incremental enrichment input is unbounded")
    current_map = {item.asset_id: item.input_digest for item in current}
    previous_map = {item.asset_id: item.input_digest for item in previous}
    if len(current_map) != len(current) or len(previous_map) != len(previous):
        raise ValueError("incremental enrichment asset IDs must be unique")
    changed = tuple(
        asset_id for asset_id in sorted(current_map)
        if previous_map.get(asset_id) != current_map[asset_id]
    )
    unchanged = tuple(
        asset_id for asset_id in sorted(current_map)
        if previous_map.get(asset_id) == current_map[asset_id]
    )
    selected = changed[:limit]
    cursor_material = {
        "tenant_id": tenant_id,
        "current": tuple(sorted(current_map.items())),
        "previous": tuple(sorted(previous_map.items())),
    }
    cursor = hashlib.sha256(
        b"hawk:hmair:h5-incremental-cursor:v1\x00"
        + canonical_json_bytes(cursor_material)
    ).hexdigest()
    key_material = {
        "tenant_id": tenant_id,
        "cursor": cursor,
        "selected": selected,
        "requested_at": requested_at.isoformat(),
    }
    request_digest = hashlib.sha256(
        b"hawk:hmair:h5-incremental-plan:v1\x00"
        + canonical_json_bytes(key_material)
    ).hexdigest()
    return IncrementalEnrichmentPlan(
        tenant_id=tenant_id,
        selected_asset_ids=selected,
        unchanged_asset_ids=unchanged[:500],
        remaining_changed=max(0, len(changed) - len(selected)),
        cursor_digest=cursor,
        idempotency_key=f"h5-incremental:{request_digest}",
        requested_at=requested_at,
        limitations=(
            "This plan schedules changed canonical assets; it does not synchronously query an estate.",
            "Source-specific permissions, health, freshness, and completion remain required.",
        ),
    )


def create_incremental_rescan_from_plan(
    db: Session,
    *,
    tenant_id: str,
    source_scan_id: str,
    plan: IncrementalEnrichmentPlan,
    requested_by: str | None,
):
    """Resolve changed assets to their source targets and reuse scan workers."""

    if plan.tenant_id != tenant_id:
        raise ValueError("incremental enrichment plan is outside tenant scope")
    if not plan.selected_asset_ids:
        raise ValueError("incremental enrichment plan contains no changed assets")
    pairs = tuple(
        db.execute(
            select(
                DiscoveryObservationAssetLink.asset_id,
                DiscoveryObservation.target_id,
            )
            .join(
                DiscoveryObservation,
                (
                    DiscoveryObservation.tenant_id
                    == DiscoveryObservationAssetLink.tenant_id
                )
                & (
                    DiscoveryObservation.observation_id
                    == DiscoveryObservationAssetLink.observation_id
                ),
            )
            .where(
                DiscoveryObservationAssetLink.tenant_id == tenant_id,
                DiscoveryObservationAssetLink.asset_id.in_(
                    plan.selected_asset_ids
                ),
                DiscoveryObservationAssetLink.link_kind != "reverse",
            )
            .distinct()
        )
    )
    resolved_assets = {str(asset_id) for asset_id, _ in pairs if asset_id is not None}
    missing_assets = set(plan.selected_asset_ids) - resolved_assets
    if missing_assets:
        claim_pairs = tuple(
            db.execute(
                select(
                    DiscoveryEvidenceClaim.subject_asset_id,
                    DiscoveryObservation.target_id,
                )
                .join(
                    DiscoveryObservation,
                    (
                        DiscoveryObservation.tenant_id
                        == DiscoveryEvidenceClaim.tenant_id
                    )
                    & (
                        DiscoveryObservation.observation_id
                        == DiscoveryEvidenceClaim.source_observation_id
                    ),
                )
                .where(
                    DiscoveryEvidenceClaim.tenant_id == tenant_id,
                    DiscoveryEvidenceClaim.subject_asset_id.in_(missing_assets),
                    DiscoveryEvidenceClaim.claim_result == "supported",
                    DiscoveryEvidenceClaim.freshness == "fresh",
                )
                .distinct()
            )
        )
        pairs = (*pairs, *claim_pairs)
        resolved_assets.update(
            str(asset_id) for asset_id, _ in claim_pairs if asset_id is not None
        )
    if resolved_assets != set(plan.selected_asset_ids):
        raise LookupError("one or more changed assets lack a canonical source target")
    target_ids = tuple(sorted({str(target_id) for _, target_id in pairs}))
    from app.services.hmair.scan_service import incremental_rescan_with_outcome

    return incremental_rescan_with_outcome(
        db,
        tenant_id=tenant_id,
        scan_id=source_scan_id,
        target_ids=target_ids,
        asset_ids=plan.selected_asset_ids,
        requested_by=requested_by,
        request_idempotency_key=plan.idempotency_key,
    )


__all__ = [
    "create_incremental_rescan_from_plan",
    "plan_incremental_enrichment",
]
