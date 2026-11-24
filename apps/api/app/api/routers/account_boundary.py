from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services.account_boundary import AccountBoundaryAuthorityUnavailable, AccountBoundaryService


router = APIRouter(prefix="/account-boundary", tags=["account-boundary"])


def _require_flag(name: str) -> None:
    if not bool(getattr(settings, name, False)):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account-boundary capability disabled")


def _service(db: Session) -> AccountBoundaryService:
    try:
        if not settings.ai_account_boundary:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="account-boundary disabled")
        provider = db.info.get("account_boundary_signing_provider") or db.info.get("phase5_signing_provider")
        if provider is None:
            raise AccountBoundaryAuthorityUnavailable("account-boundary signing authority unavailable")
        return AccountBoundaryService(
            pseudonymization_key=settings.account_boundary_pseudonymization_key,
            signing_provider=provider,
        )
    except (AccountBoundaryAuthorityUnavailable, AttributeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="account-boundary authority unavailable") from exc


class StartAuthTransactionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_identity_ref: str = Field(min_length=1, max_length=255)
    device_id: str = Field(min_length=1, max_length=255)
    application_asset_id: str | None = Field(default=None, max_length=255)
    application_family: str = Field(min_length=1, max_length=128)
    provider: str = Field(min_length=1, max_length=64)
    product: str = Field(min_length=1, max_length=128)
    surface: str = Field(min_length=1, max_length=64)
    initiating_process_instance: str | None = Field(default=None, max_length=255)
    initiating_browser_profile: str | None = Field(default=None, max_length=255)
    initiating_tab_or_navigation_id: str | None = Field(default=None, max_length=255)
    auth_protocol: str = Field(min_length=1, max_length=32)
    expected_issuer: str | None = Field(default=None, max_length=512)
    expected_client_id: str | None = Field(default=None, max_length=255)
    expected_redirect_uri: str | None = Field(default=None, max_length=512)
    state: str | None = Field(default=None, max_length=2048)
    nonce: str | None = Field(default=None, max_length=2048)
    intended_enterprise_org_ids: list[str] = Field(default_factory=list)
    intended_workspace_ids: list[str] = Field(default_factory=list)
    intended_tenant_ids: list[str] = Field(default_factory=list)
    policy_id: str | None = Field(default=None, max_length=128)
    policy_version: str | None = Field(default=None, max_length=64)


class CorrelateAuthEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auth_transaction_id: str = Field(min_length=1, max_length=96)
    issuer: str | None = Field(default=None, max_length=512)
    client_id: str | None = Field(default=None, max_length=255)
    redirect_uri: str | None = Field(default=None, max_length=512)
    state: str | None = Field(default=None, max_length=2048)
    nonce: str | None = Field(default=None, max_length=2048)
    referrer: str | None = Field(default=None, max_length=512)
    callback_process_instance: str | None = Field(default=None, max_length=255)
    callback_browser_profile: str | None = Field(default=None, max_length=255)
    callback_tab_or_navigation_id: str | None = Field(default=None, max_length=255)


class VerifyAccountIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integration_id: str = Field(min_length=1, max_length=36)
    provider_subject_ref: str = Field(min_length=1, max_length=255)
    email: str | None = Field(default=None, max_length=320)


class CreateAccountSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integration_id: str = Field(min_length=1, max_length=36)
    surface: str = Field(min_length=1, max_length=64)
    user_identity_ref: str = Field(min_length=1, max_length=255)
    account_identity_id: str = Field(min_length=1, max_length=36)
    device_id: str = Field(min_length=1, max_length=255)
    process_instance: str | None = Field(default=None, max_length=255)
    browser_profile: str | None = Field(default=None, max_length=255)
    tab_or_app_session: str | None = Field(default=None, max_length=255)
    organisation_id: str | None = Field(default=None, max_length=255)
    workspace_id: str | None = Field(default=None, max_length=255)
    policy_version: str | None = Field(default=None, max_length=64)


class SelectBoundaryPlanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integration_id: str = Field(min_length=1, max_length=36)
    surface: str = Field(min_length=1, max_length=64)
    required_assurance: str = Field(min_length=3, max_length=3)
    device_managed: bool


class IssuePermitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=36)
    device_id: str = Field(min_length=1, max_length=255)
    process_instance: str | None = Field(default=None, max_length=255)
    allowed_destination_scope: list[str] = Field(default_factory=list)
    allowed_data_classes: list[str] = Field(default_factory=list)
    allowed_business_purposes: list[str] = Field(default_factory=list)
    policy_epoch: int = Field(ge=0)
    ttl_seconds: int = Field(default=300, ge=1, le=3600)


class VerifyPermitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permit_id: str = Field(min_length=1, max_length=36)
    device_id: str = Field(min_length=1, max_length=255)
    process_instance: str | None = Field(default=None, max_length=255)
    provider: str = Field(min_length=1, max_length=64)
    product: str = Field(min_length=1, max_length=128)
    surface: str = Field(min_length=1, max_length=64)
    destination: str = Field(min_length=1, max_length=512)
    data_class: str = Field(min_length=1, max_length=128)
    business_purpose: str = Field(min_length=1, max_length=128)
    policy_epoch: int = Field(ge=0)


class DecideAccountAccessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=36)
    required_assurance: str = Field(min_length=3, max_length=3)
    control_point: str = Field(min_length=1, max_length=64)
    policy_id: str | None = Field(default=None, max_length=128)
    policy_version: str | None = Field(default=None, max_length=64)


class DecideDeviceDownloadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(min_length=1, max_length=36)
    data_classification: str = Field(min_length=1, max_length=128)
    policy_id: str | None = Field(default=None, max_length=128)
    policy_version: str | None = Field(default=None, max_length=64)


class CreateIntegrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str = Field(min_length=1, max_length=64)
    product: str = Field(min_length=1, max_length=128)
    surfaces: list[str] = Field(min_length=1)


class ValidateIntegrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    surface: str = Field(min_length=1, max_length=64)


class LifecycleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_state: str = Field(min_length=1, max_length=32)


class RevalidateSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy_version: str | None = Field(default=None, max_length=64)


@router.get("/providers")
def provider_manifests(
    _ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return {"providers": _service(db).provider_capability_manifests()}


@router.get("/providers/{provider}/capabilities")
def provider_capabilities(
    provider: str,
    _ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    providers = _service(db).provider_capability_manifests()
    if provider not in providers:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
    return providers[provider]


@router.post("/integrations")
def create_integration(body: CreateIntegrationRequest, ctx: TenantContext = Depends(require_role(min_role="admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    row = _service(db).create_integration(db, tenant_id=ctx.tenant.id, **body.model_dump())
    db.commit()
    return {"integration_id": row.id, "lifecycle_state": row.lifecycle_state}


@router.get("/integrations")
def list_integrations(ctx: TenantContext = Depends(require_role(min_role="viewer")), db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = _service(db).list_integrations(db, tenant_id=ctx.tenant.id)
    return {"integrations": [{"integration_id": row.id, "provider": row.provider, "product": row.product, "lifecycle_state": row.lifecycle_state, "route_health": row.route_health} for row in rows]}


@router.get("/integrations/{integration_id}")
def get_integration(integration_id: str, ctx: TenantContext = Depends(require_role(min_role="viewer")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        row = _service(db).get_integration(db, tenant_id=ctx.tenant.id, integration_id=integration_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"integration_id": row.id, "provider": row.provider, "product": row.product, "lifecycle_state": row.lifecycle_state, "route_health": row.route_health}


@router.post("/integrations/{integration_id}/validate")
def validate_integration(integration_id: str, body: ValidateIntegrationRequest, ctx: TenantContext = Depends(require_role(min_role="admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        row = _service(db).validate_integration(db, tenant_id=ctx.tenant.id, integration_id=integration_id, checked_at=datetime.now(timezone.utc), **body.model_dump())
    except (LookupError, AccountBoundaryAuthorityUnavailable) as exc:
        raise HTTPException(status_code=503 if isinstance(exc, AccountBoundaryAuthorityUnavailable) else 404, detail=str(exc)) from exc
    db.commit()
    return {"validation_id": row.id, "status": row.status, "valid_until": row.valid_until, "route_health": row.route_health}


@router.post("/integrations/{integration_id}/lifecycle")
def advance_lifecycle(integration_id: str, body: LifecycleRequest, ctx: TenantContext = Depends(require_role(min_role="admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        row = _service(db).advance_lifecycle(db, tenant_id=ctx.tenant.id, integration_id=integration_id, enforcement_enabled=settings.account_boundary_enforce, checked_at=datetime.now(timezone.utc), **body.model_dump())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.commit()
    return {"integration_id": row.id, "lifecycle_state": row.lifecycle_state}


@router.post("/auth-transactions/start")
def start_auth_transaction(
    body: StartAuthTransactionRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _service(db).start_auth_transaction(
        db,
        tenant_id=ctx.tenant.id,
        started_at=datetime.now(timezone.utc),
        **body.model_dump(),
    )
    db.commit()
    return {
        "auth_transaction_id": row.auth_transaction_id,
        "state": row.current_state,
        "expires_at": row.expires_at,
        "secrets_persisted": False,
    }


@router.post("/auth-transactions/correlate")
def correlate_auth_event(
    body: CorrelateAuthEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        result = _service(db).correlate_auth_event(
            db,
            tenant_id=ctx.tenant.id,
            occurred_at=datetime.now(timezone.utc),
            **body.model_dump(),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    db.commit()
    return result


@router.post("/identities/verify")
def verify_identity(
    body: VerifyAccountIdentityRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _service(db).record_server_verified_identity(
        db,
        tenant_id=ctx.tenant.id,
        verified_at=datetime.now(timezone.utc),
        **body.model_dump(),
    )
    db.commit()
    return {
        "account_identity_id": row.id,
        "account_class": row.account_class,
        "verification_status": row.verification_status,
        "email_persisted": False,
    }


@router.post("/sessions")
def create_session(
    body: CreateAccountSessionRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        integration = _service(db).get_integration(db, tenant_id=ctx.tenant.id, integration_id=body.integration_id)
        row = _service(db).create_account_session(
            db,
            tenant_id=ctx.tenant.id,
            issued_at=datetime.now(timezone.utc),
            provider=integration.provider,
            product=integration.product,
            **body.model_dump(),
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    db.commit()
    return {
        "account_session_id": row.id,
        "session_ref": row.account_session_id,
        "session_state": row.session_state,
        "assurance_level": row.assurance_level,
    }


@router.post("/control-plan/select")
def select_control_plan(
    body: SelectBoundaryPlanRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    service = _service(db)
    integration = service.get_integration(db, tenant_id=ctx.tenant.id, integration_id=body.integration_id)
    return service.select_boundary_plan(db, tenant_id=ctx.tenant.id, provider=integration.provider, product=integration.product, **body.model_dump())


@router.post("/permits")
def issue_permit(
    body: IssuePermitRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _require_flag("account_session_permits")
    try:
        row = _service(db).issue_session_permit(
            db,
            tenant_id=ctx.tenant.id,
            issued_at=datetime.now(timezone.utc),
            **body.model_dump(),
        )
    except (LookupError, PermissionError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    db.commit()
    return {
        "permit_id": row.id,
        "permit_ref": row.permit_id,
        "expires_at": row.expires_at,
        "reusable_bearer_token": False,
    }


@router.post("/permits/verify")
def verify_permit(
    body: VerifyPermitRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _require_flag("account_session_permits")
    result = _service(db).verify_session_permit(
        db,
        tenant_id=ctx.tenant.id,
        checked_at=datetime.now(timezone.utc),
        **body.model_dump(),
    )
    db.commit()
    return result


@router.post("/permits/{permit_id}/revoke")
def revoke_permit(permit_id: str, ctx: TenantContext = Depends(require_role(min_role="operator")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        row = _service(db).revoke_permit(db, tenant_id=ctx.tenant.id, permit_id=permit_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.commit()
    return {"permit_id": row.id, "revoked": row.revoked}


@router.get("/sessions/{session_id}")
def get_session(session_id: str, ctx: TenantContext = Depends(require_role(min_role="viewer")), db: Session = Depends(get_db)) -> dict[str, Any]:
    from app.db.models.account_boundary import AIAccountSession
    row = db.get(AIAccountSession, session_id)
    if row is None or row.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=404, detail="account_session_not_found")
    return {"account_session_id": row.id, "session_ref": row.account_session_id, "session_state": row.session_state, "policy_version": row.policy_version}


@router.post("/sessions/{session_id}/revalidate")
def revalidate_session(session_id: str, body: RevalidateSessionRequest, ctx: TenantContext = Depends(require_role(min_role="operator")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        row = _service(db).revalidate_session(db, tenant_id=ctx.tenant.id, session_id=session_id, checked_at=datetime.now(timezone.utc), **body.model_dump())
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.commit()
    return {"account_session_id": row.id, "session_state": row.session_state, "drift_state": row.drift_state}


@router.post("/sessions/{session_id}/revoke")
def revoke_session(session_id: str, ctx: TenantContext = Depends(require_role(min_role="operator")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        row = _service(db).revoke_session(db, tenant_id=ctx.tenant.id, session_id=session_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    db.commit()
    return {"account_session_id": row.id, "session_state": row.session_state}


@router.post("/decisions/account-access")
def decide_account_access(
    body: DecideAccountAccessRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _require_flag("account_boundary_enforce")
    try:
        result = _service(db).decide_account_access(
            db,
            tenant_id=ctx.tenant.id,
            decided_at=datetime.now(timezone.utc),
            **body.model_dump(),
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    db.commit()
    return result


@router.post("/decisions/device-download")
def decide_device_download(
    body: DecideDeviceDownloadRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    _require_flag("account_boundary_enforce")
    try:
        result = _service(db).decide_device_download(
            db,
            tenant_id=ctx.tenant.id,
            decided_at=datetime.now(timezone.utc),
            **body.model_dump(),
        )
    except LookupError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)
        ) from exc
    db.commit()
    return result
