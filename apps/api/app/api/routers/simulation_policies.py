from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.deps_control_plane import require_control_plane_healthy
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.simulation import SimulationExecutor, SimulationPolicy
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.simulation_catalog_service import get_catalog_coverage, sync_simulation_catalog
from app.services.simulation_executor_registry import list_executors
from app.services.simulation_policy_service import (
    activate_simulation_policy,
    create_simulation_policy,
    ensure_default_policy,
    get_active_policy,
    get_simulation_policy,
    list_simulation_policies,
    patch_simulation_policy,
)


router = APIRouter(
    prefix="/simulation-policies",
    tags=["simulation-policies"],
    dependencies=[Depends(require_control_plane_healthy(module="simulations"))],
)


class SimulationPolicyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    enabled: bool = True
    enabled_categories: list[str] = Field(default_factory=list)
    enabled_surfaces: list[str] = Field(default_factory=list)
    blocked_categories: list[str] = Field(default_factory=list)
    minimum_severity: str = "low"
    require_approval_for: list[str] = Field(default_factory=list)
    allowed_execution_modes: list[str] = Field(default_factory=list)
    environment_scope: list[str] = Field(default_factory=list)
    tenant_isolation_required: bool = True
    evidence_retention_days: int = 90
    max_parallel_runs: int = 2
    notify_on_fail: bool = True
    framework_filters: list[str] = Field(default_factory=list)
    control_filters: list[str] = Field(default_factory=list)
    active: bool = False


class SimulationPolicyPatchPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    enabled: bool | None = None
    enabled_categories: list[str] | None = None
    enabled_surfaces: list[str] | None = None
    blocked_categories: list[str] | None = None
    minimum_severity: str | None = None
    require_approval_for: list[str] | None = None
    allowed_execution_modes: list[str] | None = None
    environment_scope: list[str] | None = None
    tenant_isolation_required: bool | None = None
    evidence_retention_days: int | None = None
    max_parallel_runs: int | None = None
    notify_on_fail: bool | None = None
    framework_filters: list[str] | None = None
    control_filters: list[str] | None = None
    active: bool | None = None


class SimulationPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    enabled: bool
    enabled_categories: list[str]
    enabled_surfaces: list[str]
    blocked_categories: list[str]
    minimum_severity: str
    require_approval_for: list[str]
    allowed_execution_modes: list[str]
    environment_scope: list[str]
    tenant_isolation_required: bool
    evidence_retention_days: int
    max_parallel_runs: int
    notify_on_fail: bool
    framework_filters: list[str]
    control_filters: list[str]
    active: bool
    created_at: datetime
    updated_at: datetime


class SimulationExecutorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str | None
    is_global: bool
    name: str
    supported_surfaces: list[str]
    supported_categories: list[str]
    supported_simulation_ids: list[str]
    status: str
    evidence_types: list[str]
    requires: list[str]
    created_at: datetime
    updated_at: datetime


def _raise_policy_validation(error_text: str) -> None:
    details = [item for item in str(error_text or "").split(";") if item]
    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"errors": details})


@router.get("", response_model=ListEnvelope[SimulationPolicyResponse])
def list_policies(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("simulations.view")),
    db: Session = Depends(get_db),
):
    rows = list_simulation_policies(db, tenant_id=ctx.tenant.id)
    db.commit()
    dto = [SimulationPolicyResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto, page=page, page_size=page_size)
    return ListEnvelope[SimulationPolicyResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("", response_model=SimulationPolicyResponse)
def create_policy(
    payload: SimulationPolicyPayload,
    ctx: TenantContext = Depends(require_permission("simulations.manage")),
    db: Session = Depends(get_db),
):
    try:
        row, _errors = create_simulation_policy(db, tenant_id=ctx.tenant.id, payload=payload.model_dump())
    except ValueError as exc:
        _raise_policy_validation(str(exc))

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.policy.create",
        resource_type="simulation_policy",
        resource_id=row.id,
        payload={"name": row.name, "active": row.active},
    )
    db.commit()
    db.refresh(row)
    return SimulationPolicyResponse.model_validate(row)


@router.get("/active", response_model=SimulationPolicyResponse)
def get_active(
    ctx: TenantContext = Depends(require_permission("simulations.view")),
    db: Session = Depends(get_db),
):
    row = get_active_policy(db, tenant_id=ctx.tenant.id)
    db.commit()
    db.refresh(row)
    return SimulationPolicyResponse.model_validate(row)


@router.get("/executors", response_model=ListEnvelope[SimulationExecutorResponse])
def get_executors(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("simulations.view")),
    db: Session = Depends(get_db),
):
    rows = list_executors(db, tenant_id=ctx.tenant.id)
    db.commit()
    dto = [SimulationExecutorResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto, page=page, page_size=page_size)
    return ListEnvelope[SimulationExecutorResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/catalog/coverage")
def get_catalog_state(
    sync: bool = True,
    ctx: TenantContext = Depends(require_permission("simulations.view")),
    db: Session = Depends(get_db),
):
    if sync:
        summary = sync_simulation_catalog(db, tenant_id=ctx.tenant.id)
        db.commit()
        return summary
    return get_catalog_coverage(db, tenant_id=ctx.tenant.id)


@router.post("/catalog/sync")
def sync_catalog_state(
    ctx: TenantContext = Depends(require_permission("simulations.operate")),
    db: Session = Depends(get_db),
):
    summary = sync_simulation_catalog(db, tenant_id=ctx.tenant.id)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.catalog.sync",
        resource_type="simulation_catalog",
        resource_id=ctx.tenant.id,
        payload=summary,
    )
    db.commit()
    return summary


@router.get("/{policy_id}", response_model=SimulationPolicyResponse)
def get_policy(
    policy_id: str,
    ctx: TenantContext = Depends(require_permission("simulations.view")),
    db: Session = Depends(get_db),
):
    row = get_simulation_policy(db, tenant_id=ctx.tenant.id, policy_id=policy_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation policy not found")
    return SimulationPolicyResponse.model_validate(row)


@router.patch("/{policy_id}", response_model=SimulationPolicyResponse)
def patch_policy(
    policy_id: str,
    payload: SimulationPolicyPatchPayload,
    ctx: TenantContext = Depends(require_permission("simulations.manage")),
    db: Session = Depends(get_db),
):
    try:
        row, _errors = patch_simulation_policy(
            db,
            tenant_id=ctx.tenant.id,
            policy_id=policy_id,
            payload=payload.model_dump(exclude_unset=True),
        )
    except ValueError as exc:
        message = str(exc)
        if message == "simulation_policy_not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation policy not found") from exc
        _raise_policy_validation(message)

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.policy.update",
        resource_type="simulation_policy",
        resource_id=row.id,
        payload={"name": row.name, "active": row.active},
    )
    db.commit()
    db.refresh(row)
    return SimulationPolicyResponse.model_validate(row)


@router.post("/{policy_id}/activate", response_model=SimulationPolicyResponse)
def activate_policy(
    policy_id: str,
    ctx: TenantContext = Depends(require_permission("simulations.manage")),
    db: Session = Depends(get_db),
):
    try:
        row = activate_simulation_policy(db, tenant_id=ctx.tenant.id, policy_id=policy_id)
    except ValueError as exc:
        message = str(exc)
        if message == "simulation_policy_not_found":
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Simulation policy not found") from exc
        _raise_policy_validation(message)

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="simulation.policy.activate",
        resource_type="simulation_policy",
        resource_id=row.id,
        payload={"active": True, "name": row.name},
    )
    db.commit()
    db.refresh(row)
    return SimulationPolicyResponse.model_validate(row)


# Ensure default policy exists for each tenant immediately when this router is hit.
@router.post("/ensure-default", response_model=SimulationPolicyResponse)
def ensure_default(
    ctx: TenantContext = Depends(require_permission("simulations.operate")),
    db: Session = Depends(get_db),
):
    row = ensure_default_policy(db, tenant_id=ctx.tenant.id)
    db.commit()
    db.refresh(row)
    return SimulationPolicyResponse.model_validate(row)
