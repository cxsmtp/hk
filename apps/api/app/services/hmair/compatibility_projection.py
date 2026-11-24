from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery import DiscoveryApplication
from app.db.models.discovery_canonical import DiscoveryScan
from app.db.models.discovery_intelligence import DiscoveryShadowClassification
from app.db.models.scan import ScanResult
from app.db.models.shadow_ai import ShadowAIEntity
from app.services.discovery_service import tool_key_for_name
from app.services.hmair.contracts import StrictContract


COMPATIBILITY_PROJECTION_VERSION = "hmair-h1-compatibility-1.0"
_MAX_LINKS = 200
_MAX_SOURCE_ROWS = 1_000
_APPLICATION_ASSET_TYPES = (
    "ai_application",
    "ai_saas",
    "ai_feature",
    "ide",
    "cli",
    "endpoint_application",
)


class CompatibilityLink(StrictContract):
    legacy_record_id: str
    canonical_record_id: str
    match_basis: str
    relationship_confidence: str
    verification_state: str


class CompatibilityDomainSummary(StrictContract):
    legacy_authority: str
    canonical_authority: str
    mode: str
    legacy_count: int
    canonical_count: int
    correlated_count: int
    unmatched_legacy_count: int
    unmatched_canonical_count: int
    links: tuple[CompatibilityLink, ...]
    links_truncated: bool
    limitations: tuple[str, ...]


class HMAIRCompatibilitySummary(StrictContract):
    tenant_id: str
    projection_version: str
    generated_at: datetime
    write_behavior: str
    raw_content_included: bool
    scans: CompatibilityDomainSummary
    discovery_applications: CompatibilityDomainSummary
    shadow_ai: CompatibilityDomainSummary


def _domain(
    *,
    legacy_authority: str,
    canonical_authority: str,
    mode: str,
    legacy_count: int,
    canonical_count: int,
    evaluated_legacy_count: int,
    evaluated_canonical_count: int,
    links: list[CompatibilityLink],
    source_truncated: bool,
    limitations: tuple[str, ...],
) -> CompatibilityDomainSummary:
    bounded = tuple(links[:_MAX_LINKS])
    correlated_legacy = {row.legacy_record_id for row in links}
    correlated_canonical = {row.canonical_record_id for row in links}
    return CompatibilityDomainSummary(
        legacy_authority=legacy_authority,
        canonical_authority=canonical_authority,
        mode=mode,
        legacy_count=legacy_count,
        canonical_count=canonical_count,
        correlated_count=len(links),
        unmatched_legacy_count=max(
            0, evaluated_legacy_count - len(correlated_legacy)
        ),
        unmatched_canonical_count=max(
            0, evaluated_canonical_count - len(correlated_canonical)
        ),
        links=bounded,
        links_truncated=source_truncated or len(links) > _MAX_LINKS,
        limitations=(
            *limitations,
            *(
                (
                    "Compatibility comparison is bounded to the first "
                    f"{_MAX_SOURCE_ROWS} records per authority; unmatched counts "
                    "describe only the evaluated rows.",
                )
                if source_truncated
                else ()
            ),
        ),
    )


def _application_summary(
    db: Session, *, tenant_id: str
) -> CompatibilityDomainSummary:
    legacy_count = int(
        db.scalar(
            select(func.count(DiscoveryApplication.id)).where(
                DiscoveryApplication.tenant_id == tenant_id
            )
        )
        or 0
    )
    canonical_count = int(
        db.scalar(
            select(func.count(DiscoveryAIAsset.asset_id)).where(
                DiscoveryAIAsset.tenant_id == tenant_id,
                DiscoveryAIAsset.asset_type.in_(_APPLICATION_ASSET_TYPES),
            )
        )
        or 0
    )
    legacy_rows = list(
        db.scalars(
            select(DiscoveryApplication)
            .where(DiscoveryApplication.tenant_id == tenant_id)
            .order_by(DiscoveryApplication.id)
            .limit(_MAX_SOURCE_ROWS + 1)
        )
    )
    canonical_rows = list(
        db.scalars(
            select(DiscoveryAIAsset)
            .where(
                DiscoveryAIAsset.tenant_id == tenant_id,
                DiscoveryAIAsset.asset_type.in_(_APPLICATION_ASSET_TYPES),
            )
            .order_by(DiscoveryAIAsset.asset_id)
            .limit(_MAX_SOURCE_ROWS + 1)
        )
    )
    source_truncated = (
        len(legacy_rows) > _MAX_SOURCE_ROWS
        or len(canonical_rows) > _MAX_SOURCE_ROWS
    )
    legacy = legacy_rows[:_MAX_SOURCE_ROWS]
    canonical = canonical_rows[:_MAX_SOURCE_ROWS]
    assets_by_key: dict[str, list[DiscoveryAIAsset]] = defaultdict(list)
    for row in canonical:
        assets_by_key[tool_key_for_name(row.canonical_name)].append(row)
    links: list[CompatibilityLink] = []
    for row in legacy:
        candidates = assets_by_key.get(row.tool_key, [])
        if len(candidates) != 1:
            continue
        links.append(
            CompatibilityLink(
                legacy_record_id=row.id,
                canonical_record_id=candidates[0].asset_id,
                match_basis="exact_normalized_display_name",
                relationship_confidence="correlated",
                verification_state="unverified",
            )
        )
    return _domain(
        legacy_authority="discovery_applications",
        canonical_authority="discovery_ai_assets",
        mode="read_projection",
        legacy_count=legacy_count,
        canonical_count=canonical_count,
        evaluated_legacy_count=len(legacy),
        evaluated_canonical_count=len(canonical),
        links=links,
        source_truncated=source_truncated,
        limitations=(
            "A normalized-name correlation is not identity proof or authorization.",
            "Ambiguous and unmatched records remain separate.",
        ),
    )


def _shadow_summary(db: Session, *, tenant_id: str) -> CompatibilityDomainSummary:
    legacy_count = int(
        db.scalar(
            select(func.count(ShadowAIEntity.id)).where(
                ShadowAIEntity.tenant_id == tenant_id
            )
        )
        or 0
    )
    legacy_rows = list(
        db.scalars(
            select(ShadowAIEntity)
            .where(ShadowAIEntity.tenant_id == tenant_id)
            .order_by(ShadowAIEntity.id)
            .limit(_MAX_SOURCE_ROWS + 1)
        )
    )
    classification_count = int(
        db.scalar(
            select(
                func.count(func.distinct(DiscoveryShadowClassification.asset_id))
            ).where(DiscoveryShadowClassification.tenant_id == tenant_id)
        )
        or 0
    )
    classified_ids = (
        select(DiscoveryShadowClassification.asset_id)
        .where(DiscoveryShadowClassification.tenant_id == tenant_id)
        .scalar_subquery()
    )
    canonical_count = int(
        db.scalar(
            select(func.count(DiscoveryAIAsset.asset_id)).where(
                DiscoveryAIAsset.tenant_id == tenant_id,
                (
                    DiscoveryAIAsset.asset_id.in_(classified_ids)
                    if classification_count
                    else DiscoveryAIAsset.shadow_ai_status != "unknown"
                ),
            )
        )
        or 0
    )
    canonical_rows = list(
        db.scalars(
            select(DiscoveryAIAsset)
            .where(
                DiscoveryAIAsset.tenant_id == tenant_id,
                (
                    DiscoveryAIAsset.asset_id.in_(classified_ids)
                    if classification_count
                    else DiscoveryAIAsset.shadow_ai_status != "unknown"
                ),
            )
            .order_by(DiscoveryAIAsset.asset_id)
            .limit(_MAX_SOURCE_ROWS + 1)
        )
    )
    source_truncated = (
        len(legacy_rows) > _MAX_SOURCE_ROWS
        or len(canonical_rows) > _MAX_SOURCE_ROWS
    )
    legacy = legacy_rows[:_MAX_SOURCE_ROWS]
    canonical = canonical_rows[:_MAX_SOURCE_ROWS]
    assets_by_key: dict[str, list[DiscoveryAIAsset]] = defaultdict(list)
    for row in canonical:
        assets_by_key[tool_key_for_name(row.canonical_name)].append(row)
    links: list[CompatibilityLink] = []
    for row in legacy:
        candidates = assets_by_key.get(tool_key_for_name(row.canonical_name), [])
        if len(candidates) != 1:
            continue
        links.append(
            CompatibilityLink(
                legacy_record_id=row.id,
                canonical_record_id=candidates[0].asset_id,
                match_basis="exact_normalized_display_name",
                relationship_confidence="correlated",
                verification_state="unverified",
            )
        )
    return _domain(
        legacy_authority="shadow_ai_entities",
        canonical_authority="discovery_shadow_classifications",
        mode="parallel_read_with_unknown_queue_fallback",
        legacy_count=legacy_count,
        canonical_count=canonical_count,
        evaluated_legacy_count=len(legacy),
        evaluated_canonical_count=len(canonical),
        links=links,
        source_truncated=source_truncated,
        limitations=(
            "Legacy Shadow AI remains readable during canonical rollout.",
            "Legacy inventory alone does not establish current coverage.",
        ),
    )


def build_hmair_compatibility_summary(
    db: Session,
    *,
    tenant_id: str,
    generated_at: datetime | None = None,
) -> HMAIRCompatibilitySummary:
    canonical_scans = int(
        db.scalar(
            select(func.count(DiscoveryScan.scan_id)).where(
                DiscoveryScan.tenant_id == tenant_id
            )
        )
        or 0
    )
    legacy_scans = int(
        db.scalar(
            select(func.count(ScanResult.id)).where(ScanResult.tenant_id == tenant_id)
        )
        or 0
    )
    return HMAIRCompatibilitySummary(
        tenant_id=tenant_id,
        projection_version=COMPATIBILITY_PROJECTION_VERSION,
        generated_at=generated_at or datetime.now(timezone.utc),
        write_behavior="read_only_no_cross_write",
        raw_content_included=False,
        scans=_domain(
            legacy_authority="scan_results",
            canonical_authority="discovery_scans",
            mode="parallel_read",
            legacy_count=legacy_scans,
            canonical_count=canonical_scans,
            evaluated_legacy_count=legacy_scans,
            evaluated_canonical_count=canonical_scans,
            links=[],
            source_truncated=False,
            limitations=(
                "Legacy and HMAIR scan identifiers are separate authorities.",
                "No result, coverage, or completeness claim is cross-written.",
            ),
        ),
        discovery_applications=_application_summary(db, tenant_id=tenant_id),
        shadow_ai=_shadow_summary(db, tenant_id=tenant_id),
    )


__all__ = [
    "COMPATIBILITY_PROJECTION_VERSION",
    "CompatibilityDomainSummary",
    "CompatibilityLink",
    "HMAIRCompatibilitySummary",
    "build_hmair_compatibility_summary",
]
