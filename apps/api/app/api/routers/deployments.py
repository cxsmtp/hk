"""Read-only deployment-family inventory routes."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.deployment_family_read_service import (
    read_families,
    read_instance,
    read_instances,
    read_overview,
)
from app.services.deployment_family_coverage_service import (
    read_deployment_family_coverage,
)
from app.services.deployment_family_operations_service import (
    read_deployment_blind_spots,
    read_deployment_health,
)


DeploymentFamilyLiteral = Literal[
    "browser",
    "endpoint",
    "runtime",
    "saas_api",
    "unknown",
]
HostingModeLiteral = Literal[
    "saas",
    "hybrid",
    "private_cloud",
    "on_premises",
    "unknown",
]
HealthStatusLiteral = Literal[
    "healthy",
    "warning",
    "degraded",
    "offline",
    "stale",
    "unknown",
]


def _require_deployment_family_experience_enabled() -> None:
    if not settings.deployment_family_experience_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )


def _require_deployment_family_coverage_enabled() -> None:
    if not settings.deployment_family_coverage_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )


router = APIRouter(
    prefix="/deployments",
    tags=["deployments"],
    dependencies=[Depends(_require_deployment_family_experience_enabled)],
)


class DeploymentOverviewResponse(BaseModel):
    tenant_id: str
    generated_at: datetime
    total_instances: int = Field(ge=0)
    family_counts: dict[str, int]
    health_counts: dict[str, int]
    status_counts: dict[str, int]


class DeploymentFamilyResponse(BaseModel):
    family: DeploymentFamilyLiteral
    label: str
    instance_count: int = Field(ge=0)
    technical_surface_counts: dict[str, int]
    deployment_mode_counts: dict[str, int]
    hosting_mode_counts: dict[str, int]
    health_counts: dict[str, int]
    status_counts: dict[str, int]


class DeploymentFamilyListResponse(BaseModel):
    items: list[DeploymentFamilyResponse]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=200)


class DeploymentInstanceResponse(BaseModel):
    id: str
    tenant_id: str
    name: str
    deployment_family: DeploymentFamilyLiteral
    technical_surface_type: str
    deployment_mode: str
    hosting_mode: HostingModeLiteral
    environment: str
    provider: str | None
    region: str | None
    status: str
    feature_flag: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    last_health_check_at: datetime | None
    policy_bundle_version: str | None
    collector_version: str | None
    control_capability: Literal[
        "inline",
        "warn_only",
        "monitor_only",
        "external_required",
        "unknown",
    ]
    evidence_capability: Literal[
        "complete",
        "partial",
        "metadata_only",
        "none",
        "unknown",
    ]
    containment_capability: Literal[
        "direct",
        "surface_limited",
        "external",
        "none",
        "unknown",
    ]
    bypass_detection_capability: Literal[
        "supported",
        "unsupported",
        "unknown",
    ]
    health_status: HealthStatusLiteral
    health_reason: str


class DeploymentInstanceListResponse(BaseModel):
    items: list[DeploymentInstanceResponse]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=200)


class DeploymentCoverageDimensionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Literal[
        "discovery",
        "identity",
        "authorization",
        "evidence",
        "containment",
        "bypass_detection",
    ]
    status: Literal["sufficient_data", "insufficient_data"]
    covered_count: int = Field(ge=0)
    not_covered_count: int = Field(ge=0)
    total_known_eligible_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)
    percentage_nullable: float | None = Field(default=None, ge=0, le=100)
    confidence: Literal["high", "medium", "low", "unknown"]
    methodology: Literal["deployment-family-coverage/1.0"]
    evidence_refs: list[str]
    calculated_at: datetime


class DeploymentCoverageOverallResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    covered_count: int = Field(ge=0)
    not_covered_count: int = Field(ge=0)
    total_known_eligible_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    excluded_count: int = Field(ge=0)
    percentage_nullable: float = Field(ge=0, le=100)
    confidence: Literal["high", "medium", "low", "unknown"]
    confidence_basis: str
    methodology: Literal["deployment-family-coverage/1.0"]
    calculated_at: datetime


class DeploymentCoverageFamilyBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: DeploymentFamilyLiteral
    label: str
    dimensions: list[DeploymentCoverageDimensionResponse]
    estate_unknown_percentage_nullable: float | None = Field(
        default=None,
        ge=0,
        le=100,
    )


class DeploymentCoverageFamilyInsufficientResponse(
    DeploymentCoverageFamilyBase
):
    pass


class DeploymentCoverageFamilySufficientResponse(
    DeploymentCoverageFamilyBase
):
    overall: DeploymentCoverageOverallResponse


DeploymentCoverageFamilyResponse = (
    DeploymentCoverageFamilySufficientResponse
    | DeploymentCoverageFamilyInsufficientResponse
)


class DeploymentCoverageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    methodology: Literal["deployment-family-coverage/1.0"]
    calculated_at: datetime
    input_watermarks: dict[str, str]
    known_estate_limitation: str
    freshness_status: Literal["current", "stale", "unknown"]
    confidence_basis: str
    diagnostics: list[str]
    items: list[DeploymentCoverageFamilyResponse]


class DeploymentCoverageDetailResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    methodology: Literal["deployment-family-coverage/1.0"]
    calculated_at: datetime
    input_watermarks: dict[str, str]
    known_estate_limitation: str
    freshness_status: Literal["current", "stale", "unknown"]
    confidence_basis: str
    diagnostics: list[str]
    item: DeploymentCoverageFamilyResponse


class DeploymentHealthItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_id: str
    deployment_family: DeploymentFamilyLiteral
    technical_surface_type: str
    health_status: HealthStatusLiteral
    health_reason: str
    last_heartbeat_at: datetime | None
    last_action_at: datetime | None
    collector_version: str | None
    gateway_version: str | None
    active_policy_id: str | None
    active_policy_version: str | None
    policy_age_seconds: int | None = Field(default=None, ge=0)
    cache_state: str | None
    decision_latency_ms: float | None = Field(default=None, ge=0)
    evidence_lag_seconds: float | None = Field(default=None, ge=0)
    event_lag_seconds: float | None = Field(default=None, ge=0)
    export_state: str | None
    degraded_mode: bool | None
    bypass_state: str | None
    upgrade_state: str | None
    fail_open_count: int | None = Field(default=None, ge=0)
    fail_safe_count: int | None = Field(default=None, ge=0)
    evidence_refs: list[str]


class DeploymentHealthFamilyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deployment_family: DeploymentFamilyLiteral
    count: int = Field(ge=0)
    health_counts: dict[str, int]
    last_heartbeat_at: datetime | None
    last_action_at: datetime | None
    operational_field_counts: dict[str, dict[Literal["known", "unknown"], int]]


class DeploymentHealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    generated_at: datetime
    items: list[DeploymentHealthItemResponse]
    families: list[DeploymentHealthFamilyResponse]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=200)
    diagnostics: list[str]


class DeploymentBlindSpotItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    finding_type: Literal[
        "UNPROTECTED_LLM_ROUTE",
        "UNPROTECTED_MCP_ROUTE",
        "DEPLOYMENT_SURFACE_OFFLINE",
        "DEPLOYMENT_POLICY_STALE",
        "DEPLOYMENT_IDENTITY_UNRESOLVED",
        "EVIDENCE_SOURCE_MISSING",
        "UNMANAGED_AI_ACCOUNT",
        "UNKNOWN_AI_RUNTIME",
        "UNKNOWN_MCP_SERVER",
        "GATEWAY_BYPASS_SUSPECTED",
        "DISCOVERY_COVERAGE_GAP",
        "AUTHORIZATION_COVERAGE_GAP",
        "CONTAINMENT_COVERAGE_GAP",
    ]
    observed_fact: str
    observing_source: str
    reason: str
    confidence: Literal["high", "medium", "low", "unknown"]
    freshness_status: Literal["current", "stale", "unknown"]
    deployment_family: DeploymentFamilyLiteral
    technical_surface_type: str
    deployment_instance_id: str
    path_id: str
    assertion_ids: list[str]
    control_mode: str
    evidence_refs: list[str]
    recommended_deployment_action: str
    conditional: Literal[True]


class DeploymentBlindSpotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    methodology: Literal["deployment-family-coverage/1.0"]
    calculated_at: datetime
    freshness_status: Literal["current", "stale", "unknown"]
    items: list[DeploymentBlindSpotItemResponse]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=200)
    diagnostics: list[str]


def _coverage_payload(
    db: Session,
    *,
    tenant_id: str,
    window_days: int,
) -> dict[str, object]:
    calculated_at = datetime.now(timezone.utc)
    calculation = read_deployment_family_coverage(
        db,
        tenant_id=tenant_id,
        calculated_at=calculated_at,
        window_days=window_days,
    )
    return {"tenant_id": tenant_id, **calculation.as_dict()}


@router.get("/overview", response_model=DeploymentOverviewResponse)
def deployment_overview(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return read_overview(db, tenant_id=ctx.tenant.id)


@router.get("/families", response_model=DeploymentFamilyListResponse)
def deployment_families(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return read_families(
        db,
        tenant_id=ctx.tenant.id,
        page=page,
        page_size=page_size,
    )


@router.get("/instances", response_model=DeploymentInstanceListResponse)
def deployment_instances(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    deployment_family: DeploymentFamilyLiteral | None = Query(default=None),
    technical_surface_type: str | None = Query(
        default=None,
        min_length=1,
        max_length=64,
    ),
    deployment_mode: str | None = Query(
        default=None,
        min_length=1,
        max_length=64,
    ),
    hosting_mode: HostingModeLiteral | None = Query(default=None),
    environment: str | None = Query(
        default=None,
        min_length=1,
        max_length=64,
    ),
    provider: str | None = Query(
        default=None,
        min_length=1,
        max_length=128,
    ),
    region: str | None = Query(
        default=None,
        min_length=1,
        max_length=64,
    ),
    status_filter: str | None = Query(
        default=None,
        alias="status",
        min_length=1,
        max_length=32,
    ),
    feature_flag: str | None = Query(
        default=None,
        min_length=1,
        max_length=128,
    ),
    health_status: HealthStatusLiteral | None = Query(default=None),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return read_instances(
        db,
        tenant_id=ctx.tenant.id,
        page=page,
        page_size=page_size,
        deployment_family=deployment_family,
        technical_surface_type=technical_surface_type,
        deployment_mode=deployment_mode,
        hosting_mode=hosting_mode,
        environment=environment,
        provider=provider,
        region=region,
        status=status_filter,
        feature_flag=feature_flag,
        health_status=health_status,
    )


@router.get(
    "/coverage",
    response_model=DeploymentCoverageResponse,
    dependencies=[Depends(_require_deployment_family_coverage_enabled)],
)
def deployment_coverage(
    window_days: int = Query(
        default=settings.control_coverage_default_window_days,
        ge=1,
        le=90,
    ),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return _coverage_payload(
        db,
        tenant_id=ctx.tenant.id,
        window_days=window_days,
    )


@router.get(
    "/coverage/{family}",
    response_model=DeploymentCoverageDetailResponse,
    dependencies=[Depends(_require_deployment_family_coverage_enabled)],
)
def deployment_coverage_detail(
    family: DeploymentFamilyLiteral,
    window_days: int = Query(
        default=settings.control_coverage_default_window_days,
        ge=1,
        le=90,
    ),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = _coverage_payload(
        db,
        tenant_id=ctx.tenant.id,
        window_days=window_days,
    )
    items = payload.pop("items")
    item = next(
        value
        for value in items
        if isinstance(value, dict) and value.get("family") == family
    )
    return {**payload, "item": item}


@router.get(
    "/blind-spots",
    response_model=DeploymentBlindSpotResponse,
    dependencies=[Depends(_require_deployment_family_coverage_enabled)],
)
def deployment_blind_spots(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return read_deployment_blind_spots(
        db,
        tenant_id=ctx.tenant.id,
    )


@router.get("/health", response_model=DeploymentHealthResponse)
def deployment_health(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return read_deployment_health(
        db,
        tenant_id=ctx.tenant.id,
        page=page,
        page_size=page_size,
    )


@router.get("/instances/{id}", response_model=DeploymentInstanceResponse)
def deployment_instance_detail(
    id: str = Path(min_length=1, max_length=36),
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    item = read_instance(
        db,
        tenant_id=ctx.tenant.id,
        instance_id=id,
    )
    if item is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )
    return item
