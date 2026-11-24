from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.hmair.exposure.category_catalog import load_category_catalog
from app.services.hmair.exposure.contracts import (
    CalculationStatus,
    ExposureGraph,
    ExposureProjection,
    ExposureTimelineEntry,
)
from app.services.hmair.exposure.reasoning_service import (
    ExposureCategoryUnavailable,
    ExposureReasoningService,
    REASONING_METHODOLOGY_ID,
    REASONING_RULE_VERSION,
)
from app.services.hmair.exposure.source_reader import ExposureAssetUnavailable
from app.services.hmair.exposure.source_reader import EXPOSURE_SOURCE_AUTHORITIES


router = APIRouter(prefix="/discovery", tags=["discovery-exposure"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _resolve_as_of(value: datetime | None) -> datetime:
    now = _utc_now()
    if value is None:
        return now
    if value.tzinfo is None or value.utcoffset() is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="as_of must be timezone-aware",
        )
    resolved = value.astimezone(timezone.utc)
    if resolved > now:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="as_of cannot be in the future",
        )
    return resolved


class ExposureTimelineResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    as_of: datetime
    calculation_status: CalculationStatus
    reasoning_methodology_id: str
    reasoning_rule_version: str
    category_catalog_version: str
    source_input_digest: str
    items: tuple[ExposureTimelineEntry, ...]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=200)
    failed_authorities: tuple[str, ...]
    limitations: tuple[str, ...]
    truncated: bool


class ExposureGraphResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    asset_id: str
    category_id: str
    as_of: datetime
    calculation_status: CalculationStatus
    reasoning_methodology_id: str
    reasoning_rule_version: str
    category_catalog_version: str
    source_input_digest: str
    graph: ExposureGraph
    failed_authorities: tuple[str, ...]
    limitations: tuple[str, ...]
    truncated: bool


class ExposureMethodologyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    as_of: datetime
    calculation_status: CalculationStatus
    reasoning_methodology_id: str
    reasoning_rule_version: str
    category_catalog_version: str
    source_input_digest: str
    aggregate_score: None
    extent_definitions: dict[str, str]
    confidence_methodology: str
    supported_authorities: tuple[str, ...]
    known_limitations: tuple[str, ...]
    failed_authorities: tuple[str, ...]
    truncated: bool


def _require_exposure() -> None:
    if not settings.cie_core:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI Exposure Reasoning is not enabled",
        )


def _not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not Found")


@router.get("/assets/{asset_id}/exposure", response_model=ExposureProjection)
def get_asset_exposure(
    asset_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ExposureProjection:
    _require_exposure()
    try:
        return ExposureReasoningService().project(
            db,
            tenant_id=ctx.tenant.id,
            asset_id=asset_id,
            as_of=_utc_now(),
        )
    except ExposureAssetUnavailable:
        raise _not_found() from None


@router.get(
    "/assets/{asset_id}/exposure/timeline",
    response_model=ExposureTimelineResponse,
)
def get_asset_exposure_timeline(
    asset_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    lookback_days: int = Query(default=30, ge=1, le=3650),
    as_of: datetime | None = Query(default=None),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ExposureTimelineResponse:
    _require_exposure()
    as_of = _resolve_as_of(as_of)
    service = ExposureReasoningService()
    try:
        projection = service.project(
            db,
            tenant_id=ctx.tenant.id,
            asset_id=asset_id,
            as_of=as_of,
        )
        timeline_projection = (
            None
            if projection.calculation_status is CalculationStatus.UNAVAILABLE
            else service.timeline(
                projection=projection,
                as_of=as_of,
                lookback_days=lookback_days,
                limit=200,
            )
        )
    except ExposureAssetUnavailable:
        raise _not_found() from None
    entries = timeline_projection.items if timeline_projection is not None else ()
    timeline_limitations = (
        timeline_projection.limitations if timeline_projection is not None else ()
    )
    total = len(entries)
    start = (page - 1) * page_size
    items = entries[start:start + page_size]
    return ExposureTimelineResponse(
        asset_id=asset_id,
        as_of=as_of,
        calculation_status=projection.calculation_status,
        reasoning_methodology_id=projection.reasoning_methodology_id,
        reasoning_rule_version=projection.reasoning_rule_version,
        category_catalog_version=projection.category_catalog_version,
        source_input_digest=projection.source_input_digest,
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        failed_authorities=projection.failed_authorities,
        limitations=tuple(sorted(set(projection.limitations) | set(timeline_limitations))),
        truncated=projection.truncated or total == 200,
    )


@router.get(
    "/assets/{asset_id}/exposure/graph",
    response_model=ExposureGraphResponse,
)
def get_asset_exposure_graph(
    asset_id: str,
    category_id: str | None = Query(default=None, min_length=3, max_length=64),
    max_nodes: int = Query(default=200, ge=1, le=200),
    max_edges: int = Query(default=400, ge=1, le=400),
    as_of: datetime | None = Query(default=None),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> ExposureGraphResponse:
    _require_exposure()
    as_of = _resolve_as_of(as_of)
    service = ExposureReasoningService()
    try:
        projection = service.project(
            db,
            tenant_id=ctx.tenant.id,
            asset_id=asset_id,
            as_of=as_of,
        )
        selected = category_id or (
            projection.exposures[0].category_id if projection.exposures else "unknown_exposure"
        )
        graph = (
            ExposureGraph(nodes=(), edges=(), truncated=False)
            if projection.calculation_status is CalculationStatus.UNAVAILABLE
            else service.graph_from_projection(
                projection=projection,
                category_id=selected,
                max_nodes=max_nodes,
                max_edges=max_edges,
            )
        )
    except (ExposureAssetUnavailable, ExposureCategoryUnavailable):
        raise _not_found() from None
    return ExposureGraphResponse(
        asset_id=asset_id,
        category_id=selected,
        as_of=as_of,
        calculation_status=projection.calculation_status,
        reasoning_methodology_id=projection.reasoning_methodology_id,
        reasoning_rule_version=projection.reasoning_rule_version,
        category_catalog_version=projection.category_catalog_version,
        source_input_digest=projection.source_input_digest,
        graph=graph,
        failed_authorities=projection.failed_authorities,
        limitations=projection.limitations,
        truncated=projection.truncated or graph.truncated,
    )


@router.get("/exposure/methodology", response_model=ExposureMethodologyResponse)
def get_exposure_methodology(
    _ctx: TenantContext = Depends(require_role(min_role="viewer")),
) -> ExposureMethodologyResponse:
    _require_exposure()
    catalog = load_category_catalog()
    return ExposureMethodologyResponse(
        as_of=_utc_now(),
        calculation_status=CalculationStatus.COMPLETE,
        reasoning_methodology_id=REASONING_METHODOLOGY_ID,
        reasoning_rule_version=REASONING_RULE_VERSION,
        category_catalog_version=catalog.version,
        source_input_digest=catalog.digest,
        aggregate_score=None,
        extent_definitions={
            "none": "Current verified evidence proves the exposure path is not reachable.",
            "limited": "Current verified constraints bound the exposure path.",
            "material": "Capability, usable authority, and reach are currently supported.",
            "broad": "Broad reach, authority, identity, and scale are currently supported.",
            "unknown": "Required evidence is missing, stale, failed, or contradictory.",
        },
        confidence_methodology=(
            "Conservative minimum of required contributing source confidences; "
            "missing required confidence remains Unknown."
        ),
        supported_authorities=EXPOSURE_SOURCE_AUTHORITIES,
        known_limitations=(
            "Exposure is a computed projection, not a persisted inventory or risk score.",
            "Missing evidence never proves no exposure.",
            "Exact action blocks do not erase broader capability or reachability.",
            "Containment remains Unknown unless current deployment evidence proves it.",
        ),
        failed_authorities=(),
        truncated=False,
    )


__all__ = [
    "ExposureGraphResponse",
    "ExposureMethodologyResponse",
    "ExposureTimelineResponse",
    "get_asset_exposure",
    "get_asset_exposure_graph",
    "get_asset_exposure_timeline",
    "get_exposure_methodology",
    "router",
]
