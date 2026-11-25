from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.policy import GuardianContractBindingV2, GuardianContractV2
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.guardian_contract_v2_service import (
    create_v2_contract,
    delete_v2_contract,
    get_v2_contract,
    get_v2_matrix,
    list_v2_bindings,
    list_v2_contracts,
    update_v2_contract,
    upsert_v2_binding,
)
from app.services.tenant_default_seed_service import persist_tenant_guardian_defaults


router = APIRouter(prefix="/guardian-contracts/v2", tags=["guardian-contracts-v2"])


class GuardianContractV2Create(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    version: str = "2.0"
    name: str
    trigger_conditions: list[dict] = Field(default_factory=list)
    block_conditions: list[dict] = Field(default_factory=list)
    mandatory_actions: dict = Field(default_factory=dict)
    escalation_path: dict = Field(default_factory=dict)
    evidence_requirements: dict = Field(default_factory=dict)
    framework_mappings: dict = Field(default_factory=dict)
    canonical_policy: dict = Field(default_factory=dict)


class GuardianContractV2Update(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str | None = None
    name: str | None = None
    trigger_conditions: list[dict] | None = None
    block_conditions: list[dict] | None = None
    mandatory_actions: dict | None = None
    escalation_path: dict | None = None
    evidence_requirements: dict | None = None
    framework_mappings: dict | None = None
    canonical_policy: dict | None = None


class GuardianContractV2Response(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    version: str
    name: str
    trigger_conditions: list[dict]
    block_conditions: list[dict]
    mandatory_actions: dict
    escalation_path: dict
    evidence_requirements: dict
    framework_mappings: dict
    canonical_policy: dict
    created_at: datetime


class GuardianContractBindingV2Create(BaseModel):
    model_config = ConfigDict(extra="forbid")

    guardian_contract_id: str
    ai_system_id: str | None = None
    policy_version_id: str | None = None
    enforcement_strength: str = "baseline"
    enabled: bool = True


class GuardianContractBindingV2Response(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    guardian_contract_id: str
    ai_system_id: str | None
    policy_version_id: str | None
    enforcement_strength: str
    enabled: bool
    created_at: datetime
    updated_at: datetime


class GuardianContractV2MatrixItemResponse(BaseModel):
    guardian_contract_id: str
    version: str
    name: str
    trigger_conditions: list[dict]
    block_conditions: list[dict]
    mandatory_actions: dict
    escalation_path: dict
    evidence_requirements: dict
    framework_mappings: dict
    canonical_policy: dict
    bindings: list[dict]


class GuardianContractDeleteResponse(BaseModel):
    id: str
    deleted: bool


@router.get("", response_model=ListEnvelope[GuardianContractV2Response])
def list_contracts(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("policies.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    rows = list_v2_contracts(db, tenant_id=ctx.tenant.id)
    dto_rows = [GuardianContractV2Response.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[GuardianContractV2Response](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("", response_model=GuardianContractV2Response)
def create_contract(
    payload: GuardianContractV2Create,
    ctx: TenantContext = Depends(require_permission("policies.manage")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    existing = get_v2_contract(db, tenant_id=ctx.tenant.id, contract_id=payload.id)
    if existing is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Guardian contract v2 already exists")

    try:
        row = create_v2_contract(db, tenant_id=ctx.tenant.id, payload=payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="guardian_contract_v2.create",
        resource_type="guardian_contract_v2",
        resource_id=row.id,
        payload={"version": row.version, "name": row.name},
    )
    db.commit()
    db.refresh(row)
    return GuardianContractV2Response.model_validate(row)


@router.get("/bindings", response_model=ListEnvelope[GuardianContractBindingV2Response])
def list_bindings(
    ai_system_id: str | None = None,
    policy_version_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("policies.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    rows = list_v2_bindings(
        db,
        tenant_id=ctx.tenant.id,
        ai_system_id=ai_system_id,
        policy_version_id=policy_version_id,
    )
    dto_rows = [GuardianContractBindingV2Response.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[GuardianContractBindingV2Response](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.post("/bindings", response_model=GuardianContractBindingV2Response)
def create_or_update_binding(
    payload: GuardianContractBindingV2Create,
    ctx: TenantContext = Depends(require_permission("policies.manage")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    contract = get_v2_contract(
        db,
        tenant_id=ctx.tenant.id,
        contract_id=payload.guardian_contract_id,
    )
    if contract is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardian contract v2 not found")

    try:
        row = upsert_v2_binding(
            db,
            tenant_id=ctx.tenant.id,
            guardian_contract_id=payload.guardian_contract_id,
            ai_system_id=payload.ai_system_id,
            policy_version_id=payload.policy_version_id,
            enforcement_strength=str(payload.enforcement_strength).strip().lower(),
            enabled=payload.enabled,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="guardian_contract_v2.binding.upsert",
        resource_type="guardian_contract_binding_v2",
        resource_id=row.id,
        payload={
            "guardian_contract_id": row.guardian_contract_id,
            "ai_system_id": row.ai_system_id,
            "policy_version_id": row.policy_version_id,
            "enforcement_strength": row.enforcement_strength,
            "enabled": row.enabled,
        },
    )
    db.commit()
    db.refresh(row)
    return GuardianContractBindingV2Response.model_validate(row)


@router.get("/matrix", response_model=ListEnvelope[GuardianContractV2MatrixItemResponse])
def matrix(
    ai_system_id: str | None = None,
    policy_version_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_permission("policies.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    rows = get_v2_matrix(
        db,
        tenant_id=ctx.tenant.id,
        ai_system_id=ai_system_id,
        policy_version_id=policy_version_id,
    )
    page_items, total, safe_page, safe_page_size = paginate_rows(rows, page=page, page_size=page_size)
    return ListEnvelope[GuardianContractV2MatrixItemResponse](
        items=[GuardianContractV2MatrixItemResponse.model_validate(item) for item in page_items],
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/{contract_id}", response_model=GuardianContractV2Response)
def get_contract(
    contract_id: str,
    ctx: TenantContext = Depends(require_permission("policies.view")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    row = get_v2_contract(db, tenant_id=ctx.tenant.id, contract_id=contract_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardian contract v2 not found")
    return GuardianContractV2Response.model_validate(row)


@router.patch("/{contract_id}", response_model=GuardianContractV2Response)
def update_contract(
    contract_id: str,
    payload: GuardianContractV2Update,
    ctx: TenantContext = Depends(require_permission("policies.manage")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    row = get_v2_contract(db, tenant_id=ctx.tenant.id, contract_id=contract_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardian contract v2 not found")

    update_payload = payload.model_dump(exclude_none=True)
    try:
        row = update_v2_contract(
            db,
            tenant_id=ctx.tenant.id,
            row=row,
            payload=update_payload,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="guardian_contract_v2.update",
        resource_type="guardian_contract_v2",
        resource_id=row.id,
        payload=update_payload,
    )
    db.commit()
    db.refresh(row)
    return GuardianContractV2Response.model_validate(row)


@router.delete("/{contract_id}", response_model=GuardianContractDeleteResponse)
def delete_contract(
    contract_id: str,
    ctx: TenantContext = Depends(require_permission("policies.manage")),
    db: Session = Depends(get_db),
):
    persist_tenant_guardian_defaults(db, tenant_id=ctx.tenant.id)
    row = get_v2_contract(db, tenant_id=ctx.tenant.id, contract_id=contract_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Guardian contract v2 not found")

    delete_v2_contract(db, tenant_id=ctx.tenant.id, row=row)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="guardian_contract_v2.delete",
        resource_type="guardian_contract_v2",
        resource_id=contract_id,
        payload={},
    )
    db.commit()
    return GuardianContractDeleteResponse(id=contract_id, deleted=True)
