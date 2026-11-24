from __future__ import annotations

import csv
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.policy import (
    BusinessFunctionProfile,
    PolicyPack,
    PolicyVersion,
    PurposeException,
    TenantSectorProfile,
    UserBusinessFunctionMapping,
)
from app.db.session import get_db
from app.services.audit_service import write_audit_log
from app.services.browser_extension_service import build_extension_policy_sync
from app.services.guardian_contract_service import get_guardian_contract_matrix, sync_policy_guardians_to_contracts
from app.services.policy_scope_service import normalize_scoped_rule_list, validate_scoped_rule_list
from app.services.policy_service import (
    DEFAULT_FUNCTION_PURPOSES,
    SECTOR_PURPOSES,
    SUPPORTED_SECTORS,
    build_default_policy_contract,
    build_intent_aware_action_control_policy,
    build_pilot_policy_contract,
    ensure_business_purpose_defaults,
    evaluate_business_purpose_boundary,
    resolve_user_business_context,
)
from app.services.agentic_action_integrity_service import bind_or_verify_approval, scan_approval_request


router = APIRouter(prefix="/policies", tags=["policies"])


class PolicyPackCreate(BaseModel):
    name: str
    description: str = ""
    status: str = "draft"


class PolicyPackUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None


class PolicyVersionCreate(BaseModel):
    version: str
    scope: dict
    enforcement_defaults: dict
    guardian_contracts: list[dict]


class PolicyPackResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: str
    status: str


class PolicyVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    pack_id: str
    version: str
    created_at: datetime
    scope: dict
    enforcement_defaults: dict
    guardian_contracts: list[dict]


class PolicyPackCreateResponse(BaseModel):
    pack: PolicyPackResponse
    default_version: PolicyVersionResponse


class ApprovalScanRequest(BaseModel):
    chain_id: str
    canonical_action: dict[str, Any]
    original_user_intent: str = ""
    agent_summary: str = ""
    source_context_type: str = "unknown"
    source_trust_level: str = "unknown"


class ApprovalBindRequest(BaseModel):
    chain_id: str
    approval_id: str
    canonical_action: dict[str, Any]
    approver_user_id: str | None = None
    expires_at: datetime | None = None
    verify_binding_id: str | None = None


class GuardianMatrixItemResponse(BaseModel):
    guardian_contract_id: str
    name: str
    trigger_conditions: list[dict]
    block_conditions: list[dict]
    mandatory_actions: dict
    escalation_path: dict
    evidence_requirements: dict
    framework_mappings: dict
    control_bindings: list[dict]


class RunningPolicyVersionResponse(BaseModel):
    id: str
    pack_id: str
    pack_name: str
    pack_status: str
    version: str
    created_at: datetime
    guardian_count: int
    default_decision: str
    escalation: str


class RunningPolicyStatusResponse(BaseModel):
    enforced_policy_version_id: str
    platform_mode: str
    active_pack_count: int
    running_versions: list[RunningPolicyVersionResponse]


class ScopedRulesUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scoped_rules: list[dict[str, Any]] = Field(default_factory=list)


class ScopedRulesResponse(BaseModel):
    policy_version_id: str
    scoped_rules: list[dict[str, Any]]
    rule_count: int


class BrowserAutomationActionOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)


class BrowserAutomationScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    tenant_id: str
    surfaces: list[str] = Field(default_factory=lambda: ["browser_extension"])
    domains_allowlist: list[str] = Field(default_factory=list)
    domains_blocklist: list[str] = Field(default_factory=list)
    url_patterns_allowlist: list[str] = Field(default_factory=list)
    url_patterns_blocklist: list[str] = Field(default_factory=list)


class BrowserAutomationDetection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detection_required: bool = True
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    sources: list[str] = Field(default_factory=list)


class BrowserAutomationDecisions(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_allowed_browsing: str = "allow"
    on_automation_detected: str = "warn"
    on_blocked_domain: str = "block"
    on_disallowed_domain: str = "warn"
    on_blocked_action: str = "block"
    on_scope_violation: str = "block"
    on_unknown_automation_source: str = "warn"
    on_sensitive_data_or_secret: str = "block"


class BrowserAutomationControlPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    name: str
    category: str = "BROWSER_AUTOMATION_CONTROL"
    mode: Literal["monitor", "warn", "block"] = "block"
    enabled: bool = True
    scope: BrowserAutomationScope
    automation: BrowserAutomationDetection
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    action_overrides: list[BrowserAutomationActionOverride] = Field(default_factory=list)
    decisions: BrowserAutomationDecisions


class IntentAwareActionControlScope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    tenant_id: str
    surfaces: list[str] = Field(default_factory=lambda: ["browser_extension"])
    applications: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    destination_trust_levels: list[str] = Field(default_factory=list)


class IntentActionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent_category: str
    allowed_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    input_sensitivity_threshold: str = "medium"
    output_sensitivity_threshold: str = "medium"
    destination_trust_level: str = "public"
    decision: Literal["allow", "warn", "block"] = "block"


class IntentCopyExportRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output_contains: list[str] = Field(default_factory=list)
    output_sensitivity_threshold: str = "medium"
    action: Literal["copy_output", "download_output", "export_output", "share_output"]
    decision: Literal["allow", "warn", "block"] = "block"


class IntentAlignmentRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent_category: str
    out_of_scope_actions: list[str] = Field(default_factory=list)
    decision: Literal["warn", "block"] = "block"


class IntentAwareActionControlPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: str
    schema_version: str = "intent-aware-ai-action-control/v1"
    name: str
    category: str = "INTENT_AWARE_AI_ACTION_CONTROL"
    mode: Literal["monitor", "shadow", "warn", "block"] = "block"
    enabled: bool = True
    scope: IntentAwareActionControlScope
    allowed_intents: list[str] = Field(default_factory=list)
    blocked_intents: list[str] = Field(default_factory=list)
    intent_action_rules: list[IntentActionRule] = Field(default_factory=list)
    copy_export_rules: list[IntentCopyExportRule] = Field(default_factory=list)
    alignment_rules: list[IntentAlignmentRule] = Field(default_factory=list)


class PilotPolicyPackEnsureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    activate: bool = True


class PilotPolicyPackEnsureResponse(BaseModel):
    pack: PolicyPackResponse
    policy_version: PolicyVersionResponse
    applied: Literal["created", "updated"]


class BusinessPurposeProfilePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sector: str = "generic_enterprise"
    sub_sector: str | None = None
    strictness: Literal["monitor", "shadow", "warn", "review", "block"] = "review"
    regulated_data_types: list[str] = Field(default_factory=list)
    approved_business_purposes: list[str] = Field(default_factory=list)
    blocked_business_purposes: list[str] = Field(default_factory=list)
    approved_destinations: list[str] = Field(default_factory=list)
    blocked_destinations: list[str] = Field(default_factory=list)
    coding_policy_id: str | None = None
    sql_policy_id: str | None = None
    exception_policy_id: str | None = None


class BusinessPurposeProfileResponse(BusinessPurposeProfilePayload):
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime


class BusinessFunctionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = ""
    allowed_purposes: list[str] = Field(default_factory=list)
    blocked_purposes: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    review_required_actions: list[str] = Field(default_factory=list)
    blocked_actions: list[str] = Field(default_factory=list)
    allowed_destinations: list[str] = Field(default_factory=list)
    blocked_destinations: list[str] = Field(default_factory=list)
    coding_policy_override: dict[str, Any] | None = None
    sql_policy_override: dict[str, Any] | None = None
    strictness_override: str | None = None


class BusinessFunctionResponse(BusinessFunctionPayload):
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime


class BusinessPurposeMappingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str | None = None
    email: str | None = None
    group_name: str | None = None
    idp_group_id: str | None = None
    claim_name: str | None = None
    claim_value: str | None = None
    business_function: str
    role_name: str | None = None
    department: str | None = None
    team: str | None = None
    policy_groups: list[str] = Field(default_factory=list)
    priority: int = 100
    source: Literal["manual", "csv", "scim", "oidc_claim", "saml_claim", "entra", "google_workspace"] = "manual"
    enabled: bool = True


class BusinessPurposeMappingResponse(BusinessPurposeMappingPayload):
    id: str
    tenant_id: str
    created_at: datetime
    updated_at: datetime


class BusinessPurposeMappingTestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str | None = None
    email: str | None = None
    claims: dict[str, Any] = Field(default_factory=dict)
    extension_role_hint: str | None = None


class BusinessPurposeEvalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str | None = None
    email: str | None = None
    prompt_text: str | None = None
    action_type: str = "prompt_submit"
    destination_domain: str | None = None
    destination_trust_level: str | None = None
    source_surface: str = "browser"
    claims: dict[str, Any] = Field(default_factory=dict)
    extension_role_hint: str | None = None


class BusinessPurposeCsvImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    csv_text: str


class PurposeExceptionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    business_function: str
    requested_purpose: str
    requested_action: str
    justification: str
    status: Literal["pending", "approved", "denied", "expired"] = "pending"
    expires_at: datetime | None = None


def _profile_response(row: TenantSectorProfile) -> BusinessPurposeProfileResponse:
    return BusinessPurposeProfileResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        sector=row.sector,
        sub_sector=row.sub_sector,
        strictness=row.strictness,
        regulated_data_types=list(row.regulated_data_types or []),
        approved_business_purposes=list(row.approved_business_purposes or []),
        blocked_business_purposes=list(row.blocked_business_purposes or []),
        approved_destinations=list(row.approved_destinations or []),
        blocked_destinations=list(row.blocked_destinations or []),
        coding_policy_id=row.coding_policy_id,
        sql_policy_id=row.sql_policy_id,
        exception_policy_id=row.exception_policy_id,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _function_response(row: BusinessFunctionProfile) -> BusinessFunctionResponse:
    return BusinessFunctionResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        description=row.description,
        allowed_purposes=list(row.allowed_purposes or []),
        blocked_purposes=list(row.blocked_purposes or []),
        allowed_actions=list(row.allowed_actions or []),
        review_required_actions=list(row.review_required_actions or []),
        blocked_actions=list(row.blocked_actions or []),
        allowed_destinations=list(row.allowed_destinations or []),
        blocked_destinations=list(row.blocked_destinations or []),
        coding_policy_override=row.coding_policy_override,
        sql_policy_override=row.sql_policy_override,
        strictness_override=row.strictness_override,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _mapping_response(row: UserBusinessFunctionMapping) -> BusinessPurposeMappingResponse:
    return BusinessPurposeMappingResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        user_id=row.user_id,
        email=row.email,
        group_name=row.group_name,
        idp_group_id=row.idp_group_id,
        claim_name=row.claim_name,
        claim_value=row.claim_value,
        business_function=row.business_function,
        role_name=row.role_name,
        department=row.department,
        team=row.team,
        policy_groups=list(row.policy_groups or []),
        priority=row.priority,
        source=row.source,
        enabled=row.enabled,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _extract_scoped_rules(row: PolicyVersion) -> list[dict[str, Any]]:
    scope = row.scope if isinstance(row.scope, dict) else {}
    contract_json = row.contract_json if isinstance(row.contract_json, dict) else {}
    containers = [
        scope,
        (contract_json.get("scope") if isinstance(contract_json.get("scope"), dict) else {}),
    ]
    for container in containers:
        scoped_rules = container.get("scoped_rules")
        if isinstance(scoped_rules, list):
            return [dict(item) for item in scoped_rules if isinstance(item, dict)]
    return []


@router.get("/business-purpose/sector-packs")
def list_business_purpose_sector_packs(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    return {
        "tenant_id": ctx.tenant.id,
        "sectors": sorted(SUPPORTED_SECTORS),
        "default_purposes": SECTOR_PURPOSES,
        "default_business_functions": DEFAULT_FUNCTION_PURPOSES,
    }


@router.get("/business-purpose/profile", response_model=BusinessPurposeProfileResponse)
def get_business_purpose_profile(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(TenantSectorProfile)
        .where(TenantSectorProfile.tenant_id == ctx.tenant.id)
        .order_by(TenantSectorProfile.updated_at.desc())
    )
    if row is None:
        ensure_business_purpose_defaults(db, tenant_id=ctx.tenant.id)
        db.commit()
        row = db.scalar(
            select(TenantSectorProfile)
            .where(TenantSectorProfile.tenant_id == ctx.tenant.id)
            .order_by(TenantSectorProfile.updated_at.desc())
        )
    assert row is not None
    return _profile_response(row)


@router.put("/business-purpose/profile", response_model=BusinessPurposeProfileResponse)
def upsert_business_purpose_profile(
    payload: BusinessPurposeProfilePayload,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    if payload.sector not in SUPPORTED_SECTORS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported sector")
    row = db.scalar(
        select(TenantSectorProfile)
        .where(TenantSectorProfile.tenant_id == ctx.tenant.id)
        .order_by(TenantSectorProfile.updated_at.desc())
    )
    if row is None:
        row = TenantSectorProfile(tenant_id=ctx.tenant.id, sector=payload.sector)
        db.add(row)
    for field, value in payload.model_dump().items():
        setattr(row, field, value)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="business_purpose.profile.upsert",
        resource_type="tenant_sector_profile",
        resource_id=row.id,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(row)
    return _profile_response(row)


@router.get("/business-purpose/functions", response_model=ListEnvelope[BusinessFunctionResponse])
def list_business_purpose_functions(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(BusinessFunctionProfile)
        .where(BusinessFunctionProfile.tenant_id == ctx.tenant.id)
        .order_by(BusinessFunctionProfile.name.asc())
    ).all()
    dto_rows = [_function_response(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[BusinessFunctionResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.post("/business-purpose/functions", response_model=BusinessFunctionResponse)
def upsert_business_purpose_function(
    payload: BusinessFunctionPayload,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    name = payload.name.strip().lower()
    if not name:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Function name is required")
    row = db.scalar(
        select(BusinessFunctionProfile).where(
            BusinessFunctionProfile.tenant_id == ctx.tenant.id,
            BusinessFunctionProfile.name == name,
        )
    )
    if row is None:
        row = BusinessFunctionProfile(tenant_id=ctx.tenant.id, name=name)
        db.add(row)
    for field, value in payload.model_dump(exclude={"name"}).items():
        setattr(row, field, value)
    row.name = name
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="business_purpose.function.upsert",
        resource_type="business_function_profile",
        resource_id=row.id,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(row)
    return _function_response(row)


@router.get("/business-purpose/mappings", response_model=ListEnvelope[BusinessPurposeMappingResponse])
def list_business_purpose_mappings(
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(UserBusinessFunctionMapping)
        .where(UserBusinessFunctionMapping.tenant_id == ctx.tenant.id)
        .order_by(UserBusinessFunctionMapping.priority.desc(), UserBusinessFunctionMapping.updated_at.desc())
    ).all()
    dto_rows = [_mapping_response(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[BusinessPurposeMappingResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.post("/business-purpose/mappings", response_model=BusinessPurposeMappingResponse)
def create_business_purpose_mapping(
    payload: BusinessPurposeMappingPayload,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    if not any([payload.user_id, payload.email, payload.group_name, payload.idp_group_id, payload.claim_name]):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="At least one match condition is required")
    row = UserBusinessFunctionMapping(tenant_id=ctx.tenant.id, **payload.model_dump())
    db.add(row)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="business_purpose.mapping.create",
        resource_type="user_business_function_mapping",
        resource_id=row.id,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(row)
    return _mapping_response(row)


@router.put("/business-purpose/mappings/{mapping_id}", response_model=BusinessPurposeMappingResponse)
def update_business_purpose_mapping(
    mapping_id: str,
    payload: BusinessPurposeMappingPayload,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(UserBusinessFunctionMapping).where(
            UserBusinessFunctionMapping.id == mapping_id,
            UserBusinessFunctionMapping.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business purpose mapping not found")
    for field, value in payload.model_dump().items():
        setattr(row, field, value)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="business_purpose.mapping.update",
        resource_type="user_business_function_mapping",
        resource_id=row.id,
        payload=payload.model_dump(),
    )
    db.commit()
    db.refresh(row)
    return _mapping_response(row)


@router.delete("/business-purpose/mappings/{mapping_id}")
def delete_business_purpose_mapping(
    mapping_id: str,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(UserBusinessFunctionMapping).where(
            UserBusinessFunctionMapping.id == mapping_id,
            UserBusinessFunctionMapping.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Business purpose mapping not found")
    row.enabled = False
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="business_purpose.mapping.disable",
        resource_type="user_business_function_mapping",
        resource_id=row.id,
        payload={"enabled": False},
    )
    db.commit()
    return {"status": "disabled", "id": mapping_id}


@router.post("/business-purpose/mappings/test")
def test_business_purpose_mapping(
    payload: BusinessPurposeMappingTestRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return resolve_user_business_context(
        db,
        tenant_id=ctx.tenant.id,
        user_id=payload.user_id,
        email=payload.email,
        claims=payload.claims,
        extension_role_hint=payload.extension_role_hint,
    )


@router.post("/business-purpose/csv-import")
def import_business_purpose_mappings_csv(
    payload: BusinessPurposeCsvImportRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    reader = csv.DictReader(StringIO(payload.csv_text))
    created = 0
    for row_payload in reader:
        email = str(row_payload.get("email") or "").strip().lower()
        business_function = str(row_payload.get("business_function") or "").strip().lower()
        if not email or not business_function:
            continue
        existing = db.scalar(
            select(UserBusinessFunctionMapping).where(
                UserBusinessFunctionMapping.tenant_id == ctx.tenant.id,
                UserBusinessFunctionMapping.email == email,
                UserBusinessFunctionMapping.source == "csv",
            )
        )
        if existing is not None:
            target = existing
        else:
            target = UserBusinessFunctionMapping(tenant_id=ctx.tenant.id, email=email, source="csv")
            db.add(target)
            created += 1
        target.business_function = business_function
        target.role_name = str(row_payload.get("role") or row_payload.get("role_name") or "").strip() or None
        target.department = str(row_payload.get("department") or "").strip() or None
        target.team = str(row_payload.get("team") or "").strip() or None
        target.policy_groups = [
            item.strip()
            for item in str(row_payload.get("policy_group") or row_payload.get("policy_groups") or "").split(";")
            if item.strip()
        ]
        target.priority = int(row_payload.get("priority") or 80)
        target.enabled = True
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="business_purpose.mapping.csv_import",
        resource_type="user_business_function_mapping",
        resource_id=None,
        payload={"created_or_updated": created},
    )
    db.commit()
    return {"status": "ok", "created_or_updated": created}


@router.post("/business-purpose/evaluate")
def evaluate_business_purpose(
    payload: BusinessPurposeEvalRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return evaluate_business_purpose_boundary(
        db,
        tenant_id=ctx.tenant.id,
        user_id=payload.user_id,
        email=payload.email,
        prompt_text=payload.prompt_text,
        action_type=payload.action_type,
        destination_domain=payload.destination_domain,
        destination_trust_level=payload.destination_trust_level,
        source_surface=payload.source_surface,
        claims=payload.claims,
        extension_role_hint=payload.extension_role_hint,
    )


@router.post("/business-purpose/exceptions")
def create_business_purpose_exception(
    payload: PurposeExceptionPayload,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = PurposeException(
        tenant_id=ctx.tenant.id,
        user_id=payload.user_id,
        business_function=payload.business_function,
        requested_purpose=payload.requested_purpose,
        requested_action=payload.requested_action,
        justification=payload.justification,
        approved_by=ctx.user.id if payload.status == "approved" else None,
        status=payload.status,
        expires_at=payload.expires_at,
    )
    db.add(row)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="business_purpose.exception.create",
        resource_type="purpose_exception",
        resource_id=row.id,
        payload=payload.model_dump(mode="json"),
    )
    db.commit()
    db.refresh(row)
    return {"status": "ok", "id": row.id}


@router.get("/packs", response_model=ListEnvelope[PolicyPackResponse])
def list_packs(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(PolicyPack).where(PolicyPack.tenant_id == ctx.tenant.id)).all()
    dto_rows = [PolicyPackResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[PolicyPackResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.post("/packs", response_model=PolicyPackCreateResponse)
def create_pack(
    payload: PolicyPackCreate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = PolicyPack(
        tenant_id=ctx.tenant.id,
        name=payload.name,
        description=payload.description,
        status=payload.status,
    )
    db.add(row)
    db.flush()

    contract = build_default_policy_contract(row.id, created_by="system")
    ver = PolicyVersion(
        tenant_id=ctx.tenant.id,
        pack_id=row.id,
        version=contract["version"],
        created_by=None,
        scope=contract["scope"],
        enforcement_defaults=contract["enforcement_defaults"],
        guardian_contracts=contract["guardian_contracts"],
        contract_json=contract,
    )
    db.add(ver)
    db.flush()
    sync_policy_guardians_to_contracts(db, policy_version=ver)

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="policy_pack.create",
        resource_type="policy_pack",
        resource_id=row.id,
        payload={"default_policy_version_id": ver.id},
    )

    db.commit()
    db.refresh(row)
    db.refresh(ver)
    return PolicyPackCreateResponse(
        pack=PolicyPackResponse.model_validate(row),
        default_version=PolicyVersionResponse.model_validate(ver),
    )


@router.patch("/packs/{pack_id}", response_model=PolicyPackResponse)
def update_pack(
    pack_id: str,
    payload: PolicyPackUpdate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(select(PolicyPack).where(PolicyPack.id == pack_id, PolicyPack.tenant_id == ctx.tenant.id))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy pack not found")

    for field in ["name", "description", "status"]:
        value = getattr(payload, field)
        if value is not None:
            setattr(row, field, value)

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="policy_pack.update",
        resource_type="policy_pack",
        resource_id=row.id,
        payload=payload.model_dump(exclude_none=True),
    )
    db.commit()
    db.refresh(row)
    return PolicyPackResponse.model_validate(row)


@router.get("/packs/{pack_id}/versions", response_model=ListEnvelope[PolicyVersionResponse])
def list_versions(
    pack_id: str,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(PolicyVersion).where(PolicyVersion.pack_id == pack_id, PolicyVersion.tenant_id == ctx.tenant.id)
    ).all()
    dto_rows = [PolicyVersionResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[PolicyVersionResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.post("/packs/{pack_id}/versions", response_model=PolicyVersionResponse)
def create_version(
    pack_id: str,
    payload: PolicyVersionCreate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    pack = db.scalar(select(PolicyPack).where(PolicyPack.id == pack_id, PolicyPack.tenant_id == ctx.tenant.id))
    if not pack:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy pack not found")

    incoming_scope = dict(payload.scope or {})
    if "scoped_rules" in incoming_scope:
        scoped_errors = validate_scoped_rule_list(incoming_scope.get("scoped_rules"))
        if scoped_errors:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={"message": "Invalid scoped_rules payload", "errors": scoped_errors},
            )
        incoming_scope["scoped_rules"] = normalize_scoped_rule_list(incoming_scope.get("scoped_rules"))

    contract = {
        "id": f"{pack_id}-{payload.version}",
        "pack_id": pack_id,
        "version": payload.version,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": "api_user",
        "scope": incoming_scope,
        "enforcement_defaults": payload.enforcement_defaults,
        "guardian_contracts": payload.guardian_contracts,
    }

    row = PolicyVersion(
        tenant_id=ctx.tenant.id,
        pack_id=pack_id,
        version=payload.version,
        created_by=None,
        scope=incoming_scope,
        enforcement_defaults=payload.enforcement_defaults,
        guardian_contracts=payload.guardian_contracts,
        contract_json=contract,
    )
    db.add(row)
    db.flush()
    sync_policy_guardians_to_contracts(db, policy_version=row)

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="policy_version.create",
        resource_type="policy_version",
        resource_id=row.id,
        payload={"pack_id": pack_id, "version": payload.version},
    )

    db.commit()
    db.refresh(row)
    return PolicyVersionResponse.model_validate(row)


@router.get("/versions/{policy_version_id}/scoped-rules", response_model=ScopedRulesResponse)
def get_scoped_rules(
    policy_version_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy version not found")

    scoped_rules = normalize_scoped_rule_list(_extract_scoped_rules(row))
    return ScopedRulesResponse(
        policy_version_id=row.id,
        scoped_rules=scoped_rules,
        rule_count=len(scoped_rules),
    )


@router.patch("/versions/{policy_version_id}/scoped-rules", response_model=ScopedRulesResponse)
def update_scoped_rules(
    policy_version_id: str,
    payload: ScopedRulesUpdateRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy version not found")

    validation_errors = validate_scoped_rule_list(payload.scoped_rules)
    if validation_errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Invalid scoped_rules payload", "errors": validation_errors},
        )
    normalized_rules = normalize_scoped_rule_list(payload.scoped_rules)

    scope = dict(row.scope or {})
    scope["scoped_rules"] = normalized_rules
    row.scope = scope

    contract_json = dict(row.contract_json or {})
    contract_scope = dict(contract_json.get("scope") or {})
    contract_scope["scoped_rules"] = normalized_rules
    contract_json["scope"] = contract_scope
    row.contract_json = contract_json

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="policy_version.scoped_rules_update",
        resource_type="policy_version",
        resource_id=row.id,
        payload={"rule_count": len(normalized_rules)},
    )

    db.commit()
    db.refresh(row)
    return ScopedRulesResponse(
        policy_version_id=row.id,
        scoped_rules=normalized_rules,
        rule_count=len(normalized_rules),
    )


@router.post("/pilot-pack/ensure", response_model=PilotPolicyPackEnsureResponse)
def ensure_pilot_pack(
    payload: PilotPolicyPackEnsureRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    pack_name = "Pilot Safe Browser Extension Pack"
    pack = db.scalar(
        select(PolicyPack).where(
            PolicyPack.tenant_id == ctx.tenant.id,
            PolicyPack.name == pack_name,
        )
    )
    applied: Literal["created", "updated"] = "updated"
    if pack is None:
        pack = PolicyPack(
            tenant_id=ctx.tenant.id,
            name=pack_name,
            description=(
                "Hardened pilot defaults for browser-extension rollout: safe automation scope, "
                "secret blocking, conservative warning paths, and explicit guardrails."
            ),
            status="active" if payload.activate else "draft",
        )
        db.add(pack)
        db.flush()
        applied = "created"
    elif payload.activate and str(pack.status or "").strip().lower() != "active":
        pack.status = "active"
        applied = "updated"

    policy_rows = db.scalars(
        select(PolicyVersion)
        .where(
            PolicyVersion.pack_id == pack.id,
            PolicyVersion.tenant_id == ctx.tenant.id,
        )
        .order_by(PolicyVersion.created_at.desc())
    ).all()
    policy_row = next(
        (
            row
            for row in policy_rows
            if isinstance(row.contract_json, dict)
            and str(row.contract_json.get("profile") or "").strip().lower() == "pilot_p0_safe_defaults"
        ),
        None,
    )

    contract = build_pilot_policy_contract(pack.id, created_by="system", tenant_id=ctx.tenant.id)
    if policy_row is None:
        policy_row = PolicyVersion(
            tenant_id=ctx.tenant.id,
            pack_id=pack.id,
            version=str(contract.get("version") or "1.0.0-pilot.1"),
            created_by=None,
            scope=dict(contract.get("scope") or {}),
            enforcement_defaults=dict(contract.get("enforcement_defaults") or {}),
            guardian_contracts=list(contract.get("guardian_contracts") or []),
            contract_json=contract,
        )
        db.add(policy_row)
        db.flush()
        applied = "created"
    else:
        policy_row.scope = dict(contract.get("scope") or {})
        policy_row.enforcement_defaults = dict(contract.get("enforcement_defaults") or {})
        policy_row.guardian_contracts = list(contract.get("guardian_contracts") or [])
        policy_row.contract_json = contract
        applied = "updated"

    sync_policy_guardians_to_contracts(db, policy_version=policy_row)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="policy_pack.ensure_pilot",
        resource_type="policy_pack",
        resource_id=pack.id,
        payload={
            "policy_version_id": policy_row.id,
            "applied": applied,
            "status": pack.status,
        },
    )
    db.commit()
    db.refresh(pack)
    db.refresh(policy_row)
    return PilotPolicyPackEnsureResponse(
        pack=PolicyPackResponse.model_validate(pack),
        policy_version=PolicyVersionResponse.model_validate(policy_row),
        applied=applied,
    )


def _read_browser_automation_control_from_policy(row: PolicyVersion) -> dict[str, Any] | None:
    scope = row.scope if isinstance(row.scope, dict) else {}
    contract_json = row.contract_json if isinstance(row.contract_json, dict) else {}
    contract_scope = contract_json.get("scope") if isinstance(contract_json.get("scope"), dict) else {}
    candidates = [
        scope.get("browser_automation_control"),
        contract_scope.get("browser_automation_control"),
        contract_json.get("browser_automation_control"),
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            return dict(candidate)
    return None


def _read_intent_aware_action_control_from_policy(row: PolicyVersion) -> dict[str, Any] | None:
    scope = row.scope if isinstance(row.scope, dict) else {}
    contract_json = row.contract_json if isinstance(row.contract_json, dict) else {}
    contract_scope = contract_json.get("scope") if isinstance(contract_json.get("scope"), dict) else {}
    candidates = [
        scope.get("intent_aware_action_control"),
        contract_scope.get("intent_aware_action_control"),
        contract_json.get("intent_aware_action_control"),
    ]
    for candidate in candidates:
        if isinstance(candidate, dict):
            return dict(candidate)
    return None


@router.get(
    "/versions/{policy_version_id}/browser-automation-control",
    response_model=BrowserAutomationControlPolicy,
)
def get_browser_automation_control(
    policy_version_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy version not found")

    stored = _read_browser_automation_control_from_policy(row)
    if not stored:
        policy_sync = build_extension_policy_sync(db, tenant_id=ctx.tenant.id)
        stored = dict(policy_sync.browser_automation_control or {})
    stored["scope"] = dict(stored.get("scope") or {})
    stored["scope"]["tenant_id"] = ctx.tenant.id
    return BrowserAutomationControlPolicy.model_validate(stored)


@router.patch(
    "/versions/{policy_version_id}/browser-automation-control",
    response_model=BrowserAutomationControlPolicy,
)
def update_browser_automation_control(
    policy_version_id: str,
    payload: BrowserAutomationControlPolicy,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy version not found")

    policy_payload = payload.model_dump(mode="json")
    scope = dict(row.scope or {})
    scope["browser_automation_control"] = policy_payload
    row.scope = scope

    contract_json = dict(row.contract_json or {})
    contract_scope = dict(contract_json.get("scope") or {})
    contract_scope["browser_automation_control"] = policy_payload
    contract_json["scope"] = contract_scope
    contract_json["browser_automation_control"] = policy_payload
    row.contract_json = contract_json

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="policy_version.browser_automation_control_update",
        resource_type="policy_version",
        resource_id=row.id,
        payload={
            "policy_id": policy_payload.get("policy_id"),
            "mode": policy_payload.get("mode"),
            "enabled": bool(policy_payload.get("enabled")),
        },
    )
    db.commit()
    db.refresh(row)
    persisted = _read_browser_automation_control_from_policy(row) or policy_payload
    persisted["scope"] = dict(persisted.get("scope") or {})
    persisted["scope"]["tenant_id"] = ctx.tenant.id
    return BrowserAutomationControlPolicy.model_validate(persisted)


@router.get(
    "/versions/{policy_version_id}/intent-aware-action-control",
    response_model=IntentAwareActionControlPolicy,
)
def get_intent_aware_action_control(
    policy_version_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy version not found")

    stored = _read_intent_aware_action_control_from_policy(row)
    if not stored:
        stored = build_intent_aware_action_control_policy(tenant_id=ctx.tenant.id)
    stored["scope"] = dict(stored.get("scope") or {})
    stored["scope"]["tenant_id"] = ctx.tenant.id
    return IntentAwareActionControlPolicy.model_validate(stored)


@router.patch(
    "/versions/{policy_version_id}/intent-aware-action-control",
    response_model=IntentAwareActionControlPolicy,
)
def update_intent_aware_action_control(
    policy_version_id: str,
    payload: IntentAwareActionControlPolicy,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant.id,
        )
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy version not found")

    policy_payload = payload.model_dump(mode="json")
    scope = dict(row.scope or {})
    scope["intent_aware_action_control"] = policy_payload
    row.scope = scope

    contract_json = dict(row.contract_json or {})
    contract_scope = dict(contract_json.get("scope") or {})
    contract_scope["intent_aware_action_control"] = policy_payload
    contract_json["scope"] = contract_scope
    contract_json["intent_aware_action_control"] = policy_payload
    row.contract_json = contract_json

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="policy_version.intent_aware_action_control_update",
        resource_type="policy_version",
        resource_id=row.id,
        payload={
            "policy_id": policy_payload.get("policy_id"),
            "mode": policy_payload.get("mode"),
            "enabled": bool(policy_payload.get("enabled")),
        },
    )
    db.commit()
    db.refresh(row)
    persisted = _read_intent_aware_action_control_from_policy(row) or policy_payload
    persisted["scope"] = dict(persisted.get("scope") or {})
    persisted["scope"]["tenant_id"] = ctx.tenant.id
    return IntentAwareActionControlPolicy.model_validate(persisted)


@router.get("/guardian-matrix", response_model=ListEnvelope[GuardianMatrixItemResponse])
def guardian_matrix(
    policy_version_id: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    policy_version = None
    if policy_version_id:
        policy_version = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.id == policy_version_id,
                PolicyVersion.tenant_id == ctx.tenant.id,
            )
        )
        if policy_version is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy version not found")

    matrix = get_guardian_contract_matrix(db, policy_version=policy_version)
    items = matrix.get("items", [])
    page_items, total, safe_page, safe_page_size = paginate_rows(items, page=page, page_size=page_size)
    return ListEnvelope[GuardianMatrixItemResponse](
        items=[GuardianMatrixItemResponse.model_validate(item) for item in page_items],
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/running", response_model=RunningPolicyStatusResponse)
def running_policies(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    active_packs = db.scalars(
        select(PolicyPack).where(
            PolicyPack.tenant_id == ctx.tenant.id,
            PolicyPack.status == "active",
        )
    ).all()
    active_pack_ids = {row.id for row in active_packs}
    active_pack_map = {row.id: row for row in active_packs}

    active_versions: list[PolicyVersion] = []
    if active_pack_ids:
        active_versions = db.scalars(
            select(PolicyVersion)
            .where(
                PolicyVersion.tenant_id == ctx.tenant.id,
                PolicyVersion.pack_id.in_(list(active_pack_ids)),
            )
            .order_by(PolicyVersion.created_at.desc())
        ).all()

    policy_sync = build_extension_policy_sync(db, tenant_id=ctx.tenant.id)
    running_versions: list[RunningPolicyVersionResponse] = []
    for row in active_versions:
        pack = active_pack_map.get(row.pack_id)
        if pack is None:
            continue
        enforcement_defaults = row.enforcement_defaults or {}
        running_versions.append(
            RunningPolicyVersionResponse(
                id=row.id,
                pack_id=row.pack_id,
                pack_name=pack.name,
                pack_status=pack.status,
                version=row.version,
                created_at=row.created_at,
                guardian_count=len(row.guardian_contracts or []),
                default_decision=str(enforcement_defaults.get("default_decision") or "allow"),
                escalation=str(enforcement_defaults.get("escalation") or "notify"),
            )
        )

    return RunningPolicyStatusResponse(
        enforced_policy_version_id=str(policy_sync.policy_version or "none"),
        platform_mode=str(policy_sync.platform_mode or "enforce"),
        active_pack_count=len(active_packs),
        running_versions=running_versions,
    )


@router.post("/approvals/scan")
def scan_agentic_approval(
    payload: ApprovalScanRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    return scan_approval_request(
        db,
        tenant_id=ctx.tenant.id,
        chain_id=payload.chain_id,
        canonical_action=payload.canonical_action,
        original_user_intent=payload.original_user_intent,
        agent_summary=payload.agent_summary,
        source_context_type=payload.source_context_type,
        source_trust_level=payload.source_trust_level,
    )


@router.post("/approvals/bind")
def bind_agentic_approval(
    payload: ApprovalBindRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    try:
        return bind_or_verify_approval(
            db,
            tenant_id=ctx.tenant.id,
            chain_id=payload.chain_id,
            approval_id=payload.approval_id,
            canonical_action=payload.canonical_action,
            approver_user_id=payload.approver_user_id or ctx.user.id,
            expires_at=payload.expires_at,
            verify_binding_id=payload.verify_binding_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
