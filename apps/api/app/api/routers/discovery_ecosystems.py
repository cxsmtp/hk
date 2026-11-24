from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.api.routers.discovery_assets import DiscoveryFindingResponse
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.ai_asset import DiscoveryAIAsset
from app.db.models.discovery_canonical import DiscoveryCollector
from app.db.models.discovery_intelligence import (
    DiscoveryAssetFinding,
    DiscoveryAssetUsageFact,
    DiscoveryShadowClassification,
)
from app.db.models.discovery_resolution import DiscoveryAssetHypothesis
from app.db.models.shadow_ai import ShadowAIEntity
from app.db.session import get_db
from app.services.control_coverage.discovery_coverage import (
    calculate_discovery_coverage,
)
from app.services.control_graph_service import (
    project_discovery_coverage_relationships,
)
from app.services.findings_service import discovery_coverage_gap_candidates
from app.services.hmair.ecosystem_resolution_service import (
    AIEcosystemProjection,
    resolve_ai_ecosystems,
)
from app.services.hmair.compatibility_projection import (
    HMAIRCompatibilitySummary,
    build_hmair_compatibility_summary,
)


router = APIRouter(prefix="/discovery/intelligence", tags=["discovery-intelligence"])


class EstateSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assets_total: int
    confirmed_assets: int
    probable_assets: int
    ambiguous_assets: int
    active_assets: int
    shadow_assets: int
    personal_assets: int
    unowned_assets: int
    open_findings: int
    providers: int
    environments: int
    unknown_denominator: bool
    denominator_explanation: str
    generated_at: datetime


class EcosystemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ecosystem_id: str
    provider: str
    environment: str
    asset_count: int
    active_count: int
    shadow_count: int
    finding_count: int
    asset_ids: list[str]
    asset_types: list[str]
    confidence: float
    resolution_method: str
    evidence_refs: list[str]
    discovery_sources: list[str]
    first_seen_at: datetime
    last_seen_at: datetime
    limitations: list[str]
    enrichment: dict[str, object]
    algorithm_version: str


class UnknownAIResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subject_id: str
    subject_kind: str
    label: str
    probable_type: str
    confidence: float
    verification_state: str
    freshness: str
    contradiction_state: str
    evidence_node_id: str
    required_action: str
    last_seen_at: datetime


class CollectorHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    collector_id: str
    collector_type: str
    version: str
    status: str
    last_success_at: datetime | None
    last_failure_at: datetime | None
    lag_seconds: int | None
    supported_targets: list[str]
    permissions_required: list[str]
    limitations: list[str]
    data_residency: str
    control_capability: str


class DiscoveryDenominatorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str
    known_assets: int
    unresolved_hypotheses: int
    inaccessible_sources: int
    stale_sources: int
    unknown_sources: list[str]
    unsupported_sources: list[str]
    enterprise_denominator_complete: bool
    evidence_ref: str | None
    explanation: str


class DiscoveryCoverageDimensionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    covered_count: int
    not_covered_count: int
    unknown_count: int
    covered_asset_ids: list[str]
    not_covered_asset_ids: list[str]
    unknown_asset_ids: list[str]
    score: float | None
    score_withheld_reason: str | None
    methodology: str
    evidence_refs: list[str]
    missing_evidence: list[str]
    improvement_actions: list[str]


class DiscoveryCoverageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    methodology_version: str
    generated_at: datetime
    denominator: DiscoveryDenominatorResponse
    dimensions: dict[str, DiscoveryCoverageDimensionResponse]
    relationships: list[dict[str, object]]
    gap_candidates: list[dict[str, object]]
    limitations: list[str]


def _resolution_bucket(confidence: float) -> str:
    if confidence >= 0.85:
        return "confirmed"
    if confidence >= 0.60:
        return "probable"
    return "ambiguous"


def _latest_usage_by_asset(
    db: Session, *, tenant_id: str
) -> dict[str, DiscoveryAssetUsageFact]:
    rows = list(
        db.scalars(
            select(DiscoveryAssetUsageFact)
            .where(DiscoveryAssetUsageFact.tenant_id == tenant_id)
            .order_by(
                DiscoveryAssetUsageFact.created_at.desc(),
                DiscoveryAssetUsageFact.usage_fact_id.desc(),
            )
        )
    )
    output: dict[str, DiscoveryAssetUsageFact] = {}
    for row in rows:
        output.setdefault(row.asset_id, row)
    return output


def _latest_shadow_by_asset(
    db: Session, *, tenant_id: str
) -> dict[str, DiscoveryShadowClassification]:
    rows = list(
        db.scalars(
            select(DiscoveryShadowClassification)
            .where(DiscoveryShadowClassification.tenant_id == tenant_id)
            .order_by(
                DiscoveryShadowClassification.created_at.desc(),
                DiscoveryShadowClassification.classification_id.desc(),
            )
        )
    )
    output: dict[str, DiscoveryShadowClassification] = {}
    for row in rows:
        output.setdefault(row.asset_id, row)
    return output


def _ecosystem_responses(
    db: Session,
    *,
    tenant_id: str,
    ecosystems: tuple[AIEcosystemProjection, ...],
) -> list[EcosystemResponse]:
    usage = _latest_usage_by_asset(db, tenant_id=tenant_id)
    shadow = _latest_shadow_by_asset(db, tenant_id=tenant_id)
    finding_counts = {
        asset_id: int(count)
        for asset_id, count in db.execute(
            select(DiscoveryAssetFinding.asset_id, func.count())
            .where(
                DiscoveryAssetFinding.tenant_id == tenant_id,
                DiscoveryAssetFinding.status.in_(["open", "reviewing"]),
            )
            .group_by(DiscoveryAssetFinding.asset_id)
        )
    }
    active_states = {"occasional", "active", "high_usage"}
    return [
        EcosystemResponse(
            ecosystem_id=row.ecosystem_id,
            provider=row.provider,
            environment=row.environment,
            asset_count=len(row.asset_ids),
            active_count=sum(
                1
                for asset_id in row.asset_ids
                if asset_id in usage
                and usage[asset_id].usage_state in active_states
            ),
            shadow_count=sum(
                1 for asset_id in row.asset_ids if asset_id in shadow
            ),
            finding_count=sum(
                finding_counts.get(asset_id, 0)
                for asset_id in row.asset_ids
            ),
            asset_ids=list(row.asset_ids),
            asset_types=list(row.asset_types),
            confidence=row.confidence,
            resolution_method=row.resolution_method,
            evidence_refs=list(row.evidence_refs),
            discovery_sources=list(row.discovery_sources),
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
            limitations=list(row.limitations),
            enrichment=row.enrichment,
            algorithm_version=row.algorithm_version,
        )
        for row in ecosystems
    ]


@router.get("/estate", response_model=EstateSummaryResponse)
def get_estate_summary(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> EstateSummaryResponse:
    assets = list(
        db.scalars(
            select(DiscoveryAIAsset).where(
                DiscoveryAIAsset.tenant_id == ctx.tenant.id
            )
        )
    )


    usage = _latest_usage_by_asset(db, tenant_id=ctx.tenant.id)
    shadow = _latest_shadow_by_asset(db, tenant_id=ctx.tenant.id)
    buckets = [_resolution_bucket(float(row.resolution_confidence)) for row in assets]
    active_states = {"occasional", "active", "high_usage"}
    open_findings = int(
        db.scalar(
            select(func.count(DiscoveryAssetFinding.finding_id)).where(
                DiscoveryAssetFinding.tenant_id == ctx.tenant.id,
                DiscoveryAssetFinding.status.in_(["open", "reviewing"]),
            )
        )
        or 0
    )
    return EstateSummaryResponse(
        assets_total=len(assets),
        confirmed_assets=buckets.count("confirmed"),
        probable_assets=buckets.count("probable"),
        ambiguous_assets=buckets.count("ambiguous"),
        active_assets=sum(
            1
            for row in assets
            if row.asset_id in usage and usage[row.asset_id].usage_state in active_states
        ),
        shadow_assets=len(shadow),
        personal_assets=sum(
            1 for row in shadow.values() if row.management_class == "personal"
        ),
        unowned_assets=sum(
            1
            for row in assets
            if row.shadow_ai_status in {"owner_unknown", "unknown", "confirmed_shadow", "suspected_shadow"}
        ),
        open_findings=open_findings,
        providers=len({row.provider for row in assets if row.provider}),
        environments=len({row.environment for row in assets if row.environment}),
        unknown_denominator=True,
        denominator_explanation=(
            "No reconciled authoritative enterprise population denominator is attached; "
            "counts describe only the evidence-backed known estate."
        ),
        generated_at=datetime.now(timezone.utc),
    )


@router.get("/compatibility", response_model=HMAIRCompatibilitySummary)
def get_compatibility_summary(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> HMAIRCompatibilitySummary:
    return build_hmair_compatibility_summary(
        db, tenant_id=ctx.tenant.id
    )


@router.get("/coverage", response_model=DiscoveryCoverageResponse)
def get_discovery_coverage(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> DiscoveryCoverageResponse:
    projection = calculate_discovery_coverage(
        db,
        tenant_id=ctx.tenant.id,
        now=datetime.now(timezone.utc),
    )
    return DiscoveryCoverageResponse(
        tenant_id=projection.tenant_id,
        methodology_version=projection.methodology_version,
        generated_at=projection.generated_at,
        denominator=DiscoveryDenominatorResponse(
            **{
                **projection.denominator.__dict__,
                "unknown_sources": list(projection.denominator.unknown_sources),
                "unsupported_sources": list(
                    projection.denominator.unsupported_sources
                ),
            }
        ),
        dimensions={
            name: DiscoveryCoverageDimensionResponse(
                **{
                    **dimension.__dict__,
                    "covered_asset_ids": list(dimension.covered_asset_ids),
                    "not_covered_asset_ids": list(
                        dimension.not_covered_asset_ids
                    ),
                    "unknown_asset_ids": list(dimension.unknown_asset_ids),
                    "evidence_refs": list(dimension.evidence_refs),
                    "missing_evidence": list(dimension.missing_evidence),
                    "improvement_actions": list(
                        dimension.improvement_actions
                    ),
                }
            )
            for name, dimension in projection.dimensions.items()
        },
        relationships=project_discovery_coverage_relationships(projection),
        gap_candidates=discovery_coverage_gap_candidates(projection),
        limitations=list(projection.limitations),
    )


@router.get("/ecosystems", response_model=ListEnvelope[EcosystemResponse])
def list_ecosystems(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ListEnvelope[EcosystemResponse]:
    ecosystems = resolve_ai_ecosystems(db, tenant_id=ctx.tenant.id)
    items = _ecosystem_responses(
        db, tenant_id=ctx.tenant.id, ecosystems=ecosystems
    )
    page_items, total, safe_page, safe_size = paginate_rows(
        items, page=page, page_size=page_size
    )
    return ListEnvelope[EcosystemResponse](
        items=page_items, total=total, page=safe_page, page_size=safe_size
    )


@router.get("/ecosystems/{ecosystem_id}", response_model=EcosystemResponse)
def get_ecosystem(
    ecosystem_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> EcosystemResponse:
    matches = tuple(
        row
        for row in resolve_ai_ecosystems(db, tenant_id=ctx.tenant.id)
        if row.ecosystem_id == ecosystem_id
    )
    if len(matches) != 1:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI ecosystem not found",
        )
    return _ecosystem_responses(
        db, tenant_id=ctx.tenant.id, ecosystems=matches
    )[0]


@router.get("/unknown", response_model=ListEnvelope[UnknownAIResponse])
def list_unknown_ai(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ListEnvelope[UnknownAIResponse]:
    hypotheses = list(
        db.scalars(
            select(DiscoveryAssetHypothesis)
            .where(
                DiscoveryAssetHypothesis.tenant_id == ctx.tenant.id,
                DiscoveryAssetHypothesis.state.in_([
                    "observed", "hypothesized", "verifying", "ambiguous"
                ]),
            )
            .order_by(DiscoveryAssetHypothesis.last_observed_at.desc())
        )
    )
    assets = list(
        db.scalars(
            select(DiscoveryAIAsset)
            .where(
                DiscoveryAIAsset.tenant_id == ctx.tenant.id,
                DiscoveryAIAsset.asset_type == "unknown_ai_candidate",
            )
            .order_by(DiscoveryAIAsset.last_seen_at.desc())
        )
    )
    legacy_shadow_entities = list(
        db.scalars(
            select(ShadowAIEntity)
            .where(
                ShadowAIEntity.tenant_id == ctx.tenant.id,
                ShadowAIEntity.discovery_status == "discovered",
                ShadowAIEntity.approved_status == "unknown",
            )
            .order_by(ShadowAIEntity.last_seen.desc())
        )
    )
    items = [
        UnknownAIResponse(
            subject_id=row.hypothesis_id,
            subject_kind="hypothesis",
            label=row.label,
            probable_type=row.hypothesis_type,
            confidence=float(row.confidence),
            verification_state=row.verification_state,
            freshness=row.freshness,
            contradiction_state=row.contradiction_state,
            evidence_node_id=row.evidence_node_id,
            required_action="Run the bounded verification task for this hypothesis.",
            last_seen_at=row.last_observed_at,
        )
        for row in hypotheses
    ]
    items.extend(
        UnknownAIResponse(
            subject_id=row.asset_id,
            subject_kind="asset",
            label=row.canonical_name,
            probable_type="unknown_ai_candidate",
            confidence=float(row.resolution_confidence),
            verification_state=_resolution_bucket(float(row.resolution_confidence)),
            freshness="unknown",
            contradiction_state="unknown",
            evidence_node_id=row.evidence_bundle_id,
            required_action="Inspect evidence and initiate safe metadata verification.",
            last_seen_at=row.last_seen_at,
        )
        for row in assets
    )
    known_labels = {item.label.casefold() for item in items}
    items.extend(
        UnknownAIResponse(
            subject_id=row.id,
            subject_kind="legacy_shadow_entity",
            label=row.canonical_name,
            probable_type=str(row.ai_type or "ai_application"),
            confidence=float(row.confidence_score),
            verification_state="unknown",
            freshness="unknown",
            contradiction_state="none",
            evidence_node_id=f"legacy-shadow-ai-entity:{row.id}",
            required_action=(
                "Review the legacy Shadow AI record and start a bounded metadata "
                "verification; legacy inventory alone does not establish current coverage."
            ),
            last_seen_at=row.last_seen,
        )
        for row in legacy_shadow_entities
        if row.canonical_name.casefold() not in known_labels
    )
    items.sort(key=lambda row: row.last_seen_at, reverse=True)
    page_items, total, safe_page, safe_size = paginate_rows(
        items, page=page, page_size=page_size
    )
    return ListEnvelope[UnknownAIResponse](
        items=page_items, total=total, page=safe_page, page_size=safe_size
    )


@router.get("/findings", response_model=ListEnvelope[DiscoveryFindingResponse])
def list_discovery_findings(
    status_filter: str | None = Query(default=None, max_length=32),
    severity: str | None = Query(default=None, max_length=16),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ListEnvelope[DiscoveryFindingResponse]:
    query = select(DiscoveryAssetFinding).where(
        DiscoveryAssetFinding.tenant_id == ctx.tenant.id
    )
    if status_filter:
        query = query.where(DiscoveryAssetFinding.status == status_filter)
    if severity:
        query = query.where(DiscoveryAssetFinding.severity == severity)
    rows = list(
        db.scalars(
            query.order_by(
                DiscoveryAssetFinding.last_seen_at.desc(),
                DiscoveryAssetFinding.finding_id.desc(),
            )
        )
    )
    items = [
        DiscoveryFindingResponse(
            finding_id=row.finding_id,
            asset_id=row.asset_id,
            finding_type=row.finding_type,
            severity=row.severity,
            confidence=float(row.confidence),
            verification_state=row.verification_state,
            evidence_node_ids=list(row.evidence_node_ids_json),
            first_seen_at=row.first_seen_at,
            last_seen_at=row.last_seen_at,
            remediation=row.remediation,
            verification_action=row.verification_action,
            coverage_impact=row.coverage_impact,
            occurrence_count=row.occurrence_count,
            status=row.status,
        )
        for row in rows
    ]
    page_items, total, safe_page, safe_size = paginate_rows(
        items, page=page, page_size=page_size
    )
    return ListEnvelope[DiscoveryFindingResponse](
        items=page_items, total=total, page=safe_page, page_size=safe_size
    )


@router.get("/collector-health", response_model=list[CollectorHealthResponse])
def list_collector_health(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> list[CollectorHealthResponse]:
    now = datetime.now(timezone.utc)
    rows = list(
        db.scalars(
            select(DiscoveryCollector)
            .where(DiscoveryCollector.tenant_id == ctx.tenant.id)
            .order_by(DiscoveryCollector.collector_id)
        )
    )
    output: list[CollectorHealthResponse] = []
    for row in rows:
        last_success = row.last_success_at
        lag: int | None = None
        if last_success is not None:
            if last_success.tzinfo is None:
                last_success = last_success.replace(tzinfo=timezone.utc)
            lag = max(0, int((now - last_success.astimezone(timezone.utc)).total_seconds()))
        output.append(
            CollectorHealthResponse(
                collector_id=row.collector_id,
                collector_type=row.collector_type,
                version=row.version,
                status=row.health,
                last_success_at=row.last_success_at,
                last_failure_at=row.last_failure_at,
                lag_seconds=lag,
                supported_targets=list(row.supported_targets_json or []),
                permissions_required=list(row.permissions_required_json or []),
                limitations=list(row.limitations_json or []),
                data_residency=row.data_residency,
                control_capability=row.control_capability,
            )
        )
    return output


__all__ = [
    "CollectorHealthResponse",
    "EcosystemResponse",
    "EstateSummaryResponse",
    "UnknownAIResponse",
    "get_ecosystem",
    "get_estate_summary",
    "get_discovery_coverage",
    "list_collector_health",
    "list_discovery_findings",
    "list_ecosystems",
    "list_unknown_ai",
    "router",
]
