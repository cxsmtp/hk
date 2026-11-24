"""Tenant-scoped Control Coverage queries and authoritative snapshot refresh."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.control_coverage import METHODOLOGY_VERSION, PHASE5_METHODOLOGY_VERSION, CoverageDimension, Phase5CoverageDimension
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.control_coverage import (
    ControlCoverageAssertion,
    ControlCoveragePath,
    ControlCoverageSnapshot,
    DeploymentSurface,
)
from app.db.models.finding import Finding
from app.db.session import get_db
from app.services.control_coverage.recommendations import (
    CoverageAssertionView,
    CoverageFindingView,
    CoveragePathView,
    DIMENSION_REQUIREMENTS,
    build_blind_spots,
)
from app.services.control_coverage.executive import (
    compare_coverage_snapshots,
    get_coverage_assessment_explanation,
    get_executive_coverage_summary,
    list_coverage_assessments,
    refresh_executive_coverage_snapshot,
)
from app.services.control_coverage.executive_sources import collect_executive_coverage_inputs


def _require_control_coverage_api_enabled() -> None:
    if not settings.control_coverage_api_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")


router = APIRouter(
    prefix="/control-coverage",
    tags=["control-coverage"],
    dependencies=[Depends(_require_control_coverage_api_enabled)],
)

DimensionLiteral = Literal["discovery", "identity", "authorization", "evidence", "deployment", "runtime", "bypass"]
StateLiteral = Literal["covered", "not_covered", "unknown", "not_applicable"]
IdentityTypeLiteral = Literal["user", "agent", "service_identity", "unknown"]

KNOWN_ESTATE_LIMITATION = (
    "Scores apply only to unique AI paths observed by Hawk in the selected window; "
    "unobserved estate remains outside the measured denominator."
)

SUMMARY_FINDING_LIMIT = 100
SUMMARY_REFERENCE_LIMIT = 100
BLIND_SPOT_FINDING_TYPES = (
    "unprotected_path",
    "bypass",
    "disconnected_gateway",
    "missing_evidence",
    "unmanaged_runtime",
    "unmanaged_browser",
    "unmanaged_mcp",
    "unknown_sdk",
)


class AssertionCountsResponse(BaseModel):
    covered: int = Field(ge=0)
    not_covered: int = Field(ge=0)
    unknown: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    denominator: int = Field(ge=0)


class ScoreResponse(BaseModel):
    score: float | None = Field(default=None, ge=0, le=100)
    counts: AssertionCountsResponse


class DimensionCoverageResponse(ScoreResponse):
    dimension: str
    methodology: str
    missing_reasons: dict[str, int] = Field(default_factory=dict)


class DiagnosticResponse(BaseModel):
    code: str
    message: str


class ControlCoverageResponse(BaseModel):
    tenant_id: str
    methodology_version: str
    window_days: int
    window_start: datetime
    window_end: datetime
    computed_at: datetime
    freshness_status: str
    known_estate_limitation: str
    headline: ScoreResponse
    dimensions: dict[str, DimensionCoverageResponse]
    surface_summary: dict[str, int]
    blind_spots: list[dict[str, object]]
    deployment_improvements: list[dict[str, object]]
    input_watermarks: dict[str, str]
    diagnostics: list[DiagnosticResponse]


class AssertionResponse(BaseModel):
    assertion_id: str
    dimension: str
    state: str
    reason_code: str
    explanation: str
    evidence_refs: list[str]
    observed_at: datetime
    evaluated_at: datetime
    valid_until: datetime | None


class CoveragePathResponse(BaseModel):
    path_id: str
    path_key: str
    key_version: str
    asset_ref: str
    identity_type: str
    identity_ref: str
    runtime_ref: str
    deployment_surface_ref: str
    destination_type: str
    destination_ref: str
    lifecycle_status: str
    first_seen_at: datetime
    last_seen_at: datetime
    source_refs: list[str]
    assertions: list[AssertionResponse]


class CoveragePathListResponse(BaseModel):
    page: int
    page_size: int
    total: int
    items: list[CoveragePathResponse]


class MethodologyResponse(BaseModel):
    methodology_version: str
    path_key_version: str
    default_window_days: int
    maximum_window_days: int
    dimensions: list[str]
    formula: str
    weighted: bool
    unknown_in_denominator: bool
    not_applicable_in_denominator: bool
    known_estate_limitation: str


class ExecutiveCoverageRefreshRequest(BaseModel):
    scope_type: Literal["tenant", "deployment_surface", "asset", "action_class"] = "tenant"
    scope_key: str = Field(default="all", min_length=1, max_length=255)
    display_name: str = Field(default="Enterprise AI estate", min_length=1, max_length=255)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _empty_counts() -> dict[str, int]:
    return {"covered": 0, "not_covered": 0, "unknown": 0, "not_applicable": 0, "denominator": 0}


def _safe_refs(values: list | tuple) -> list[str]:
    allowed_prefixes = (
        "runtime_event:",
        "ai_action:",
        "decision_receipt:",
        "execution_receipt:",
        "evidence:",
        "finding:",
    )
    output: list[str] = []
    for value in values or []:
        text = str(value or "").strip()
        if len(text) <= 255 and text.startswith(allowed_prefixes) and not any(token in text for token in ("?", "#", "&", "\n", "\r")):
            output.append(text)
    return output


def _latest_snapshot(
    db: Session,
    *,
    tenant_id: str,
    window_days: int,
    methodology_version: str = METHODOLOGY_VERSION,
) -> ControlCoverageSnapshot | None:
    rows = db.scalars(
        select(ControlCoverageSnapshot)
        .where(
            ControlCoverageSnapshot.tenant_id == tenant_id,
            ControlCoverageSnapshot.methodology_version == methodology_version,
        )
        .order_by(ControlCoverageSnapshot.computed_at.desc(), ControlCoverageSnapshot.id.desc())
    ).all()
    expected = timedelta(days=window_days)
    return next((row for row in rows if abs((_aware(row.window_end) - _aware(row.window_start)) - expected) < timedelta(seconds=1)), None)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _assertions_for_paths(
    db: Session,
    *,
    tenant_id: str,
    path_ids: list[str],
) -> dict[str, list[ControlCoverageAssertion]]:
    if not path_ids:
        return {}
    rows = db.scalars(
        select(ControlCoverageAssertion)
        .where(
            ControlCoverageAssertion.tenant_id == tenant_id,
            ControlCoverageAssertion.path_id.in_(path_ids),
            ControlCoverageAssertion.methodology_version == METHODOLOGY_VERSION,
        )
        .order_by(ControlCoverageAssertion.dimension)
    ).all()
    grouped: dict[str, list[ControlCoverageAssertion]] = {}
    for row in rows:
        grouped.setdefault(row.path_id, []).append(row)
    return grouped


def _assertion_response(row: ControlCoverageAssertion) -> AssertionResponse:
    return AssertionResponse(
        assertion_id=row.id,
        dimension=row.dimension,
        state=row.state,
        reason_code=row.reason_code,
        explanation=row.explanation,
        evidence_refs=_safe_refs(row.evidence_refs or []),
        observed_at=row.observed_at,
        evaluated_at=row.evaluated_at,
        valid_until=row.valid_until,
    )


def _path_response(
    row: ControlCoveragePath,
    assertions: list[ControlCoverageAssertion],
) -> CoveragePathResponse:
    return CoveragePathResponse(
        path_id=row.id,
        path_key=row.path_key,
        key_version=row.key_version,
        asset_ref=row.asset_ref,
        identity_type=row.identity_type,
        identity_ref=row.identity_ref,
        runtime_ref=row.runtime_ref,
        deployment_surface_ref=row.deployment_surface_ref,
        destination_type=row.destination_type,
        destination_ref=row.destination_ref,
        lifecycle_status=row.lifecycle_status,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        source_refs=_safe_refs(row.source_refs or []),
        assertions=[_assertion_response(assertion) for assertion in assertions],
    )


def _surface_summary(surfaces: list[DeploymentSurface]) -> dict[str, int]:
    counts = {
        "protected": 0,
        "monitor_only": 0,
        "outside_control": 0,
        "offline": 0,
        "unknown": 0,
        "total": len(surfaces),
    }
    for surface in surfaces:
        profile = dict(surface.capability_profile or {})
        if surface.health_status in {"offline", "degraded"}:
            counts["offline"] += 1
        elif surface.health_status == "healthy" and (
            profile.get("inline_authorization") == "yes"
            or profile.get("containment") in {"surface", "end_to_end"}
        ):
            counts["protected"] += 1
        elif surface.deployment_mode in {"monitor_only", "connector", "endpoint_metadata"}:
            counts["monitor_only"] += 1
        elif (
            profile.get("inline_authorization") == "no" and profile.get("containment") == "none"
        ):
            counts["outside_control"] += 1
        else:
            counts["unknown"] += 1
    return counts


def _bounded_deployment_improvements(
    *,
    unresolved_rows: list[tuple[str, str, str]],
    surfaces: list[DeploymentSurface],
    reference_limit: int = SUMMARY_REFERENCE_LIMIT,
) -> list[dict[str, object]]:
    """Return exact aggregate counts with bounded drill-down references.

    The summary endpoint is loaded by several product pages. Returning every
    assertion and path ID for every candidate surface makes response size grow
    as O(surfaces * assertions) and can exhaust an API worker on a large estate.
    Exact counts remain authoritative; detailed records stay available through
    the paginated path endpoints.
    """

    by_dimension: dict[str, list[tuple[str, str]]] = {}
    for assertion_id, path_id, dimension in unresolved_rows:
        by_dimension.setdefault(dimension, []).append((assertion_id, path_id))

    dimensions_by_surface_type: dict[str, set[str]] = {}
    for surface in surfaces:
        profile = dict(surface.capability_profile or {})
        addressable_dimensions = dimensions_by_surface_type.setdefault(surface.surface_type, set())
        for dimension, (capability, accepted_values) in DIMENSION_REQUIREMENTS.items():
            current_value = str(profile.get(capability) or "").strip().lower().replace("-", "_").replace(" ", "_")
            if current_value in accepted_values and by_dimension.get(dimension):
                addressable_dimensions.add(dimension)

    results: list[dict[str, object]] = []
    for surface_type, dimension_set in dimensions_by_surface_type.items():
        addressable_dimensions = sorted(dimension_set)
        if not addressable_dimensions:
            continue

        addressable = [row for dimension in addressable_dimensions for row in by_dimension[dimension]]
        assertion_ids = sorted({row[0] for row in addressable})
        path_ids = sorted({row[1] for row in addressable})
        results.append(
            {
                "deployment_type": surface_type,
                "addressable_assertion_count": len(assertion_ids),
                "impacted_path_count": len(path_ids),
                "dimensions": sorted(addressable_dimensions),
                "path_ids": path_ids[:reference_limit],
                "assertion_ids": assertion_ids[:reference_limit],
                "evidence_refs": [],
                "prerequisites": [
                    f"Validate and deploy a healthy {surface_type} surface for the affected paths."
                ],
                "conditional": True,
                "references_truncated": len(path_ids) > reference_limit or len(assertion_ids) > reference_limit,
                "reference_limit": reference_limit,
            }
        )
    return sorted(
        results,
        key=lambda item: (
            -int(item["addressable_assertion_count"]),
            -int(item["impacted_path_count"]),
            str(item["deployment_type"]),
        ),
    )


def _operational_context(
    db: Session,
    *,
    tenant_id: str,
    methodology_version: str = METHODOLOGY_VERSION,
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, int], dict[str, dict[str, int]]]:
    surfaces = db.scalars(select(DeploymentSurface).where(DeploymentSurface.tenant_id == tenant_id)).all()
    unresolved_rows = [
        (str(row.id), str(row.path_id), str(row.dimension))
        for row in db.execute(
            select(
                ControlCoverageAssertion.id,
                ControlCoverageAssertion.path_id,
                ControlCoverageAssertion.dimension,
            ).where(
                ControlCoverageAssertion.tenant_id == tenant_id,
                ControlCoverageAssertion.methodology_version == methodology_version,
                ControlCoverageAssertion.state.in_(("not_covered", "unknown")),
            )
        )
    ]
    improvements = _bounded_deployment_improvements(
        unresolved_rows=unresolved_rows,
        surfaces=surfaces,
    )

    findings = db.scalars(
        select(Finding)
        .where(
            Finding.tenant_id == tenant_id,
            Finding.finding_type.in_(BLIND_SPOT_FINDING_TYPES),
        )
        .order_by(Finding.last_seen_at.desc(), Finding.finding_id)
        .limit(SUMMARY_FINDING_LIMIT)
    ).all()
    finding_source_refs = {
        f"runtime_event:{event_id}"
        for row in findings
        for event_id in ([row.related_runtime_event_id] if row.related_runtime_event_id else list(row.related_event_ids or []))
        if event_id
    }
    path_rows = [
        (str(row.id), tuple(_safe_refs(row.source_refs or [])))
        for row in db.scalars(
            select(ControlCoveragePath).where(ControlCoveragePath.tenant_id == tenant_id)
        ).all()
    ] if finding_source_refs else []
    matching_paths = [row for row in path_rows if finding_source_refs.intersection(row[1])]
    matching_path_ids = [row[0] for row in matching_paths]
    matching_assertions = db.scalars(
        select(ControlCoverageAssertion).where(
            ControlCoverageAssertion.tenant_id == tenant_id,
            ControlCoverageAssertion.path_id.in_(matching_path_ids),
            ControlCoverageAssertion.methodology_version == methodology_version,
        )
    ).all() if matching_path_ids else []

    path_views = [CoveragePathView(path_id=path_id, source_refs=source_refs) for path_id, source_refs in matching_paths]
    assertion_views = [
        CoverageAssertionView(
            assertion_id=row.id,
            path_id=row.path_id,
            dimension=row.dimension,
            state=row.state,
            evidence_refs=tuple(_safe_refs(row.evidence_refs or [])),
        )
        for row in matching_assertions
    ]
    finding_views: list[CoverageFindingView] = []
    for row in findings:
        event_id = row.related_runtime_event_id or next(iter(row.related_event_ids or []), None)
        finding_views.append(
            CoverageFindingView(
                finding_id=row.finding_id,
                kind=row.finding_type,
                path_id=None,
                source_ref=f"runtime_event:{event_id}" if event_id else None,
                evidence_ids=tuple(str(item) for item in (row.evidence_node_ids or []) if item),
            )
        )
    blind_spots = [asdict(item) for item in build_blind_spots(paths=path_views, findings=finding_views, assertions=assertion_views)]
    dimensions = Phase5CoverageDimension if methodology_version == PHASE5_METHODOLOGY_VERSION else CoverageDimension
    missing_reasons: dict[str, dict[str, int]] = {dimension.value: {} for dimension in dimensions}
    reason_rows = db.execute(
        select(
            ControlCoverageAssertion.dimension,
            ControlCoverageAssertion.reason_code,
            func.count(ControlCoverageAssertion.id),
        )
        .where(
            ControlCoverageAssertion.tenant_id == tenant_id,
            ControlCoverageAssertion.methodology_version == methodology_version,
            ControlCoverageAssertion.state != "covered",
        )
        .group_by(ControlCoverageAssertion.dimension, ControlCoverageAssertion.reason_code)
    )
    for dimension, reason_code, count in reason_rows:
        if dimension in missing_reasons:
            missing_reasons[dimension][reason_code] = int(count)
    return blind_spots, improvements, _surface_summary(surfaces), missing_reasons


@router.get("", response_model=ControlCoverageResponse)
def control_coverage_summary(
    window_days: int = Query(default=30, ge=1, le=90),
    methodology_version: Literal["1.0", "2.0"] = Query(default="1.0"),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    current = _now()
    selected_methodology = PHASE5_METHODOLOGY_VERSION if methodology_version == "2.0" else METHODOLOGY_VERSION
    dimensions_to_render = Phase5CoverageDimension if methodology_version == "2.0" else CoverageDimension
    snapshot = _latest_snapshot(
        db,
        tenant_id=ctx.tenant.id,
        window_days=window_days,
        methodology_version=selected_methodology,
    )
    blind_spots, improvements, surface_summary, missing_reasons = _operational_context(
        db,
        tenant_id=ctx.tenant.id,
        methodology_version=selected_methodology,
    )
    if snapshot is None:
        dimensions = {
            dimension.value: DimensionCoverageResponse(
                dimension=dimension.value,
                methodology=METHODOLOGY_VERSION,
                score=None,
                counts=AssertionCountsResponse(**_empty_counts()),
                missing_reasons={},
            )
            for dimension in dimensions_to_render
        }
        return ControlCoverageResponse(
            tenant_id=ctx.tenant.id,
            methodology_version=selected_methodology,
            window_days=window_days,
            window_start=current - timedelta(days=window_days),
            window_end=current,
            computed_at=current,
            freshness_status="unknown",
            known_estate_limitation=KNOWN_ESTATE_LIMITATION,
            headline=ScoreResponse(score=None, counts=AssertionCountsResponse(**_empty_counts())),
            dimensions=dimensions,
            surface_summary=surface_summary,
            blind_spots=blind_spots,
            deployment_improvements=improvements,
            input_watermarks={},
            diagnostics=[
                DiagnosticResponse(
                    code="snapshot_missing",
                    message="No materialized Control Coverage snapshot exists for this window.",
                )
            ],
        )

    dimension_payload = dict(snapshot.dimension_summaries or {})
    dimensions = {}
    for dimension in dimensions_to_render:
        item = dict(dimension_payload.get(dimension.value) or {})
        counts = dict(item.get("counts") or _empty_counts())
        dimensions[dimension.value] = DimensionCoverageResponse(
            dimension=dimension.value,
            methodology=selected_methodology,
            score=item.get("score"),
            counts=AssertionCountsResponse(**counts),
            missing_reasons=missing_reasons.get(dimension.value, {}),
        )
    freshness = snapshot.freshness_status
    if _aware(snapshot.computed_at) < current - timedelta(minutes=30):
        freshness = "stale"
    diagnostics = [
        DiagnosticResponse(code=str(code), message=str(code).replace("_", " ").capitalize())
        for code in (snapshot.diagnostics or [])
    ]
    return ControlCoverageResponse(
        tenant_id=ctx.tenant.id,
        methodology_version=snapshot.methodology_version,
        window_days=window_days,
        window_start=snapshot.window_start,
        window_end=snapshot.window_end,
        computed_at=snapshot.computed_at,
        freshness_status=freshness,
        known_estate_limitation=KNOWN_ESTATE_LIMITATION,
        headline=ScoreResponse(
            score=snapshot.headline_score,
            counts=AssertionCountsResponse(**dict(snapshot.headline_counts or _empty_counts())),
        ),
        dimensions=dimensions,
        surface_summary=surface_summary,
        blind_spots=blind_spots,
        deployment_improvements=improvements,
        input_watermarks=dict(snapshot.input_watermarks or {}),
        diagnostics=diagnostics,
    )


def _list_paths(
    db: Session,
    *,
    tenant_id: str,
    page: int,
    page_size: int,
    dimension: str | None = None,
    state: str | None = None,
    asset_ref: str | None = None,
    identity_ref: str | None = None,
    identity_type: str | None = None,
    runtime_ref: str | None = None,
    surface_ref: str | None = None,
    application: str | None = None,
    destination: str | None = None,
    tool: str | None = None,
) -> CoveragePathListResponse:
    statement = select(ControlCoveragePath).where(ControlCoveragePath.tenant_id == tenant_id)
    if dimension is not None or state is not None:
        matching_assertion = select(ControlCoverageAssertion.id).where(
            ControlCoverageAssertion.tenant_id == ControlCoveragePath.tenant_id,
            ControlCoverageAssertion.path_id == ControlCoveragePath.id,
            ControlCoverageAssertion.methodology_version == METHODOLOGY_VERSION,
        )
        if dimension is not None:
            matching_assertion = matching_assertion.where(ControlCoverageAssertion.dimension == dimension)
        if state is not None:
            matching_assertion = matching_assertion.where(ControlCoverageAssertion.state == state)
        statement = statement.where(matching_assertion.exists())
    if asset_ref is not None:
        statement = statement.where(ControlCoveragePath.asset_ref == asset_ref)
    if application is not None:
        statement = statement.where(ControlCoveragePath.asset_ref == f"application:{application.strip().lower()}")
    if identity_ref is not None:
        statement = statement.where(ControlCoveragePath.identity_ref == identity_ref)
    if identity_type is not None:
        statement = statement.where(ControlCoveragePath.identity_type == identity_type)
    if runtime_ref is not None:
        statement = statement.where(ControlCoveragePath.runtime_ref == runtime_ref)
    if surface_ref is not None:
        statement = statement.where(ControlCoveragePath.deployment_surface_ref == surface_ref)
    if destination is not None:
        statement = statement.where(ControlCoveragePath.destination_ref == destination)
    if tool is not None:
        statement = statement.where(ControlCoveragePath.destination_ref == f"tool:{tool.strip().lower()}")
    rows = db.scalars(statement.order_by(ControlCoveragePath.last_seen_at.desc(), ControlCoveragePath.id)).all()
    total = len(rows)
    selected = rows[(page - 1) * page_size : page * page_size]
    grouped = _assertions_for_paths(db, tenant_id=tenant_id, path_ids=[row.id for row in selected])
    return CoveragePathListResponse(
        page=page,
        page_size=page_size,
        total=total,
        items=[_path_response(row, grouped.get(row.id, [])) for row in selected],
    )


@router.get("/paths", response_model=CoveragePathListResponse)
def control_coverage_paths(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    dimension: DimensionLiteral | None = Query(default=None),
    state: StateLiteral | None = Query(default=None),
    asset_ref: str | None = Query(default=None, max_length=255),
    identity_ref: str | None = Query(default=None, max_length=255),
    identity_type: IdentityTypeLiteral | None = Query(default=None),
    runtime_ref: str | None = Query(default=None, max_length=255),
    surface_ref: str | None = Query(default=None, max_length=255),
    application: str | None = Query(default=None, max_length=180),
    destination: str | None = Query(default=None, max_length=255),
    tool: str | None = Query(default=None, max_length=180),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return _list_paths(
        db,
        tenant_id=ctx.tenant.id,
        page=page,
        page_size=page_size,
        dimension=dimension,
        state=state,
        asset_ref=asset_ref,
        identity_ref=identity_ref,
        identity_type=identity_type,
        runtime_ref=runtime_ref,
        surface_ref=surface_ref,
        application=application,
        destination=destination,
        tool=tool,
    )


@router.get("/paths/{path_id}", response_model=CoveragePathResponse)
def control_coverage_path_detail(
    path_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(ControlCoveragePath).where(
            ControlCoveragePath.tenant_id == ctx.tenant.id,
            ControlCoveragePath.id == path_id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control Coverage path not found")
    grouped = _assertions_for_paths(db, tenant_id=ctx.tenant.id, path_ids=[row.id])
    return _path_response(row, grouped.get(row.id, []))


@router.get("/assets/{asset_ref:path}", response_model=CoveragePathListResponse)
def control_coverage_asset(
    asset_ref: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    result = _list_paths(db, tenant_id=ctx.tenant.id, page=page, page_size=page_size, asset_ref=asset_ref)
    if result.total == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control Coverage asset not found")
    return result


@router.get("/identities/{identity_type}/{identity_ref:path}", response_model=CoveragePathListResponse)
def control_coverage_identity(
    identity_type: IdentityTypeLiteral,
    identity_ref: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    result = _list_paths(
        db,
        tenant_id=ctx.tenant.id,
        page=page,
        page_size=page_size,
        identity_ref=identity_ref,
        identity_type=identity_type,
    )
    if result.total == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Control Coverage identity not found")
    return result


@router.get("/methodology", response_model=MethodologyResponse)
def control_coverage_methodology(
    version: Literal["1.0", "2.0"] = "1.0",
    _ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    phase5 = version == "2.0"
    return MethodologyResponse(
        methodology_version=PHASE5_METHODOLOGY_VERSION if phase5 else METHODOLOGY_VERSION,
        path_key_version="1.0",
        default_window_days=30,
        maximum_window_days=90,
        dimensions=[dimension.value for dimension in (Phase5CoverageDimension if phase5 else CoverageDimension)],
        formula="covered / (covered + not_covered + unknown) * 100",
        weighted=False,
        unknown_in_denominator=True,
        not_applicable_in_denominator=False,
        known_estate_limitation=KNOWN_ESTATE_LIMITATION,
    )


def _filter_executive_inputs(inputs, *, scope_type: str, scope_key: str):
    if scope_type == "tenant":
        return list(inputs)
    field = {
        "deployment_surface": "deployment_surface",
        "asset": "asset_ref",
        "action_class": "action_class",
    }[scope_type]
    return [item for item in inputs if getattr(item, field) == scope_key]


@router.post("/executive/refresh")
def refresh_executive_coverage(
    payload: ExecutiveCoverageRefreshRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    current = _now()
    inputs, source_versions = collect_executive_coverage_inputs(
        db, tenant_id=ctx.tenant.id, assessed_at=current
    )
    filtered = _filter_executive_inputs(
        inputs, scope_type=payload.scope_type, scope_key=payload.scope_key
    )
    snapshot = refresh_executive_coverage_snapshot(
        db,
        tenant_id=ctx.tenant.id,
        scope_type=payload.scope_type,
        scope_key=payload.scope_key,
        display_name=payload.display_name,
        filters={payload.scope_type: payload.scope_key} if payload.scope_type != "tenant" else {},
        inputs=filtered,
        source_versions=source_versions,
        assessed_at=current,
    )
    result = get_executive_coverage_summary(
        db, tenant_id=ctx.tenant.id, snapshot_id=snapshot.id
    )
    assert result is not None
    db.commit()
    return result


@router.get("/executive")
def executive_coverage_summary(
    scope_type: Literal["tenant", "deployment_surface", "asset", "action_class"] = Query(default="tenant"),
    scope_key: str = Query(default="all", min_length=1, max_length=255),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    result = get_executive_coverage_summary(
        db, tenant_id=ctx.tenant.id, scope_type=scope_type, scope_key=scope_key
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Executive Control Coverage snapshot not found")
    return result


@router.get("/executive/snapshots/{snapshot_id}/assessments")
def executive_coverage_assessments(
    snapshot_id: str,
    state: str | None = Query(default=None, pattern="^(covered_current|covered_stale|partially_covered|configured_unvalidated|regressed|gap|unsupported|unknown|not_applicable)$"),
    surface: str | None = Query(default=None, pattern="^(browser|endpoint|runtime|saas_api|unknown)$"),
    dimension: str | None = Query(default=None, max_length=128),
    asset_ref: str | None = Query(default=None, max_length=255),
    action_class: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    summary = get_executive_coverage_summary(
        db, tenant_id=ctx.tenant.id, snapshot_id=snapshot_id
    )
    if summary is None:
        raise HTTPException(status_code=404, detail="Executive Control Coverage snapshot not found")
    items = list_coverage_assessments(
        db,
        tenant_id=ctx.tenant.id,
        snapshot_id=snapshot_id,
        state=state,
        surface=surface,
        dimension=dimension,
        asset_ref=asset_ref,
        action_class=action_class,
        limit=limit,
    )
    return {"snapshot_id": snapshot_id, "count": len(items), "items": items, "limit": limit}


@router.get("/executive/assessments/{assessment_id}")
def executive_coverage_assessment_explanation(
    assessment_id: str,
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    result = get_coverage_assessment_explanation(
        db, tenant_id=ctx.tenant.id, assessment_id=assessment_id
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Control Coverage assessment not found")
    return result


@router.get("/executive/snapshots/{snapshot_id}/compare")
def executive_coverage_comparison(
    snapshot_id: str,
    previous_snapshot_id: str = Query(min_length=1, max_length=36),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    result = compare_coverage_snapshots(
        db,
        tenant_id=ctx.tenant.id,
        current_snapshot_id=snapshot_id,
        previous_snapshot_id=previous_snapshot_id,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Comparable Control Coverage snapshots not found")
    return result


@router.get("/executive/snapshots/{snapshot_id}/evidence")
def executive_coverage_evidence_references(
    snapshot_id: str,
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    summary = get_executive_coverage_summary(
        db, tenant_id=ctx.tenant.id, snapshot_id=snapshot_id
    )
    if summary is None:
        raise HTTPException(status_code=404, detail="Executive Control Coverage snapshot not found")
    items = list_coverage_assessments(
        db, tenant_id=ctx.tenant.id, snapshot_id=snapshot_id, limit=200
    )
    evidence_refs = sorted(
        {str(ref) for item in items for ref in item.get("evidence_refs", []) if ref}
    )
    return {
        "snapshot_id": snapshot_id,
        "evidence_refs": evidence_refs,
        "assessment_count": len(items),
        "bounded": True,
    }
