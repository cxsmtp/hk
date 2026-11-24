from __future__ import annotations

import time
from datetime import datetime
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import OperationalError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.monitoring import Connector, DriftAlert
from app.db.session import get_db
from app.services.connector_secret_service import encrypt_connector_secrets
from app.services.connector_evaluation_service import connector_evaluation
from app.services.audit_service import write_audit_log
from app.services.monitoring_service import (
    connector_catalog,
    connector_coverage_summary,
    connector_control_coverage,
    ingest_monitoring_signal,
    ingest_shadow_event,
    run_connector_once,
)
from app.services.microsoft_graph_integration_service import (
    microsoft_graph_app_registration_template,
    build_microsoft_admin_consent_url,
    is_microsoft_graph_provider,
    microsoft_graph_security_profile,
    microsoft_permission_modes,
    normalize_permission_mode,
    resolve_microsoft_graph_scopes,
)


router = APIRouter(prefix="/monitoring", tags=["monitoring"])
SQLITE_LOCK_RETRY_ATTEMPTS = 4
SQLITE_LOCK_RETRY_BACKOFF_SECONDS = 0.35


class ConnectorCreate(BaseModel):
    name: str
    provider_key: str | None = None
    connector_type: str | None = None
    auth_type: str = "bearer"
    enabled: bool = True
    polling_interval_minutes: int = 15
    config: dict = {}
    secrets: dict = {}
    kms_key_ref: str | None = None


class SlackConnectorBootstrapRequest(BaseModel):
    name: str = "Slack Connector"
    workspace_domain: str | None = None
    client_id: str
    client_secret: str
    redirect_uri: str
    signing_secret: str | None = None
    state: str | None = None
    create_connector: bool = True
    enabled: bool = True
    polling_interval_minutes: int = 15
    app_token: str | None = None
    bot_token: str | None = None
    scopes: list[str] | None = None


class MicrosoftConnectorBootstrapRequest(BaseModel):
    connector_id: str | None = Field(default=None, max_length=36)
    name: str = "Microsoft 365 Connector"
    provider_key: str = "microsoft_365"
    tenant_id: str
    client_id: str
    redirect_uri: str
    permission_mode: str = "poc_safe"
    include_optional_scopes: bool = True
    create_connector: bool = True
    enabled: bool = True
    polling_interval_minutes: int = 15
    credential_mode: str = "client_secret"  # client_secret | client_assertion
    client_secret: str | None = None
    client_assertion: str | None = None
    client_assertion_type: str | None = None
    state: str | None = None


class MicrosoftScopeResolveRequest(BaseModel):
    provider_key: str
    permission_mode: str = "poc_safe"
    include_optional: bool = True


class MicrosoftConsentUrlRequest(BaseModel):
    tenant_id: str
    client_id: str
    redirect_uri: str
    state: str | None = None


class MicrosoftScopesResponse(BaseModel):
    provider_key: str
    permission_mode: str
    required_scopes: list[str]
    optional_scopes: list[str]
    selected_scopes: list[str]
    security_profile: dict


class MicrosoftConsentUrlResponse(BaseModel):
    consent_url: str
    tenant_id: str
    client_id: str
    redirect_uri: str


class MicrosoftAppRegistrationTemplateResponse(BaseModel):
    app_registration_mode: str
    oauth_supported: list[str]
    required_fields: list[str]
    credential_options: list[str]
    admin_consent_required_for_application_permissions: bool
    graph_resource: str
    security_baseline: dict


class ConnectorBootstrapResponse(BaseModel):
    provider_key: str
    connector_id: str | None = None
    created: bool
    updated: bool = False
    install_url: str | None = None
    consent_url: str | None = None
    required_scopes: list[str] = []
    selected_scopes: list[str] = []
    connector: ConnectorResponse | None = None


class SignalIngestRequest(BaseModel):
    ai_system_id: str | None = None
    signal_type: str
    severity: str = "low"
    payload: dict = {}


class ShadowEventRequest(BaseModel):
    ai_system_id: str | None = None
    event_type: str
    payload: dict = {}


class ConnectorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    connector_type: str
    provider_key: str
    auth_type: str
    enabled: bool
    status: str
    config: dict
    is_stub: bool
    stub_reason: str
    last_pull_status: str
    last_pull_error: str | None = None
    last_signal_count: int
    polling_interval_minutes: int
    metadata_json: dict
    has_secrets: bool
    last_run_at: datetime | None = None


class ConnectorEvaluationConnectorResponse(BaseModel):
    id: str = Field(max_length=36)
    provider_key: str = Field(max_length=64)
    connector_type: str = Field(max_length=64)
    name: str = Field(max_length=255)
    enabled: bool
    status: str = Field(max_length=32)
    is_stub: bool
    stub_reason: str = Field(max_length=256)
    last_pull_status: str = Field(max_length=32)
    last_pull_error: str | None = Field(default=None, max_length=512)
    has_secrets: bool


class ConnectorEvaluationPullResponse(BaseModel):
    status: str = Field(max_length=32)
    normalized_signal_count: int = Field(ge=0)
    correlation_id: str | None = Field(default=None, max_length=64)
    evidence_root_id: str | None = Field(default=None, max_length=36)
    error: str | None = Field(default=None, max_length=512)
    created_at: datetime


class ConnectorEvaluationConnectorPathResponse(BaseModel):
    mode: str = Field(max_length=32)
    discovery: str = Field(max_length=32)
    authorization: str = Field(max_length=32)
    prove: str = Field(max_length=32)


class ConnectorEvaluationBrowserPathResponse(BaseModel):
    canonical_domain: str | None = Field(default=None, max_length=255)
    search_status: str = Field(max_length=32)
    mode: str = Field(max_length=32)
    discovery: str = Field(max_length=32)
    authorization: str = Field(max_length=32)
    prove: str = Field(max_length=32)


class ConnectorEvaluationBrowserActionResponse(BaseModel):
    event_id: str = Field(max_length=36)
    source: str = Field(max_length=32)
    application: str | None = Field(default=None, max_length=255)
    action_type: str | None = Field(default=None, max_length=128)
    reason: str | None = Field(default=None, max_length=128)
    control_mode: str = Field(max_length=32)
    decision_badge: str | None = Field(default=None, max_length=64)
    decision: str | None = Field(default=None, max_length=32)
    domain: str | None = Field(default=None, max_length=255)
    user: str | None = Field(default=None, max_length=64)
    correlation_id: str | None = Field(default=None, max_length=64)
    evidence_node_ids: list[str] = Field(max_length=25)
    evidence_linked: bool
    evidence_link_count: int = Field(ge=0, le=25)
    evidence_integrity_status: str = Field(max_length=32)
    created_at: datetime


class ConnectorEvaluationEvidenceItemResponse(BaseModel):
    id: str = Field(max_length=36)
    node_type: str = Field(max_length=64)
    signal_type: str = Field(max_length=128)
    correlation_id: str | None = Field(default=None, max_length=64)
    created_at: datetime


class ConnectorEvaluationEvidenceResponse(BaseModel):
    root_id: str | None = Field(default=None, max_length=36)
    integrity_status: str = Field(max_length=32)
    count: int = Field(ge=0, le=25)
    items: list[ConnectorEvaluationEvidenceItemResponse] = Field(max_length=25)


class ConnectorEvaluationResponse(BaseModel):
    connector: ConnectorEvaluationConnectorResponse
    latest_pull: ConnectorEvaluationPullResponse | None = None
    connector_path: ConnectorEvaluationConnectorPathResponse
    browser_path: ConnectorEvaluationBrowserPathResponse
    latest_browser_action: ConnectorEvaluationBrowserActionResponse | None = None
    evidence: ConnectorEvaluationEvidenceResponse
    limitations: list[str] = Field(max_length=10)


def _connector_response_payload(row: Connector) -> dict:
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "name": row.name,
        "connector_type": row.connector_type,
        "provider_key": row.provider_key,
        "auth_type": row.auth_type,
        "enabled": row.enabled,
        "status": row.status,
        "config": row.config,
        "is_stub": row.is_stub,
        "stub_reason": row.stub_reason,
        "last_pull_status": row.last_pull_status,
        "last_pull_error": row.last_pull_error,
        "last_signal_count": row.last_signal_count,
        "polling_interval_minutes": row.polling_interval_minutes,
        "metadata_json": row.metadata_json,
        "has_secrets": bool(row.encrypted_secrets),
        "last_run_at": row.last_run_at,
    }


def _create_connector_record(
    *,
    db: Session,
    ctx: TenantContext,
    payload: ConnectorCreate,
) -> Connector:
    provider_key = (payload.provider_key or payload.connector_type or "").strip()
    if not provider_key:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="provider_key or connector_type is required")
    config = dict(payload.config or {})
    metadata_json: dict = {}
    normalized_provider_key = provider_key.lower()

    if is_microsoft_graph_provider(normalized_provider_key):
        permission_mode = normalize_permission_mode(config.get("permission_mode"))
        config.setdefault("permission_mode", permission_mode)
        config.setdefault("metadata_only_ingestion", True)
        config.setdefault("app_registration_mode", "single_tenant")
        config.setdefault("oauth_flow", "client_credentials")
        config.setdefault("base_url", "https://graph.microsoft.com/v1.0")
        scope_resolution = resolve_microsoft_graph_scopes(
            provider_key=normalized_provider_key,
            permission_mode=permission_mode,
            include_optional=True,
        )
        metadata_json.update(
            {
                "microsoft_graph": {
                    "permission_mode": scope_resolution["permission_mode"],
                    "required_scopes": list(scope_resolution["required_scopes"]),
                    "selected_scopes": list(scope_resolution["selected_scopes"]),
                    "metadata_only_ingestion": bool(config.get("metadata_only_ingestion", True)),
                    "security_profile": microsoft_graph_security_profile(),
                }
            }
        )
        tenant_id = str(config.get("tenant_id") or payload.secrets.get("tenant_id") or "").strip()
        client_id = str(config.get("client_id") or payload.secrets.get("client_id") or "").strip()
        redirect_uri = str(config.get("redirect_uri") or "").strip()
        if tenant_id and client_id and redirect_uri:
            try:
                metadata_json["microsoft_graph"]["admin_consent_url"] = build_microsoft_admin_consent_url(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                )
            except ValueError:
                pass

    encrypted_secrets = encrypt_connector_secrets(payload.secrets)
    row = Connector(
        tenant_id=ctx.tenant.id,
        name=payload.name,
        connector_type=provider_key,
        provider_key=provider_key,
        auth_type=payload.auth_type,
        enabled=payload.enabled,
        polling_interval_minutes=payload.polling_interval_minutes,
        config=config,
        encrypted_secrets=encrypted_secrets,
        kms_key_ref=payload.kms_key_ref,
        status="active",
        metadata_json=metadata_json,
    )
    db.add(row)
    db.flush()

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="monitoring.connector.create",
        resource_type="connector",
        resource_id=row.id,
        payload={
            "provider_key": row.provider_key,
            "auth_type": row.auth_type,
            "enabled": row.enabled,
            "polling_interval_minutes": row.polling_interval_minutes,
            "has_secrets": bool(encrypted_secrets),
            "metadata_json": metadata_json,
        },
    )
    return row


def _is_sqlite_lock_error(exc: Exception) -> bool:
    return "database is locked" in str(exc).lower()


class MonitoringSignalResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    ai_system_id: str | None = None
    signal_type: str
    severity: str
    payload: dict
    created_at: datetime


class DriftAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    ai_system_id: str | None = None
    title: str
    status: str
    details: str
    created_at: datetime
    updated_at: datetime


class ConnectorCoverageResponse(BaseModel):
    provider_key: str
    provider_name: str
    provider_category: str
    signal_key: str
    signal_type: str
    control_id: str
    severity: str
    evidence_signal_type: str
    drift_title: str
    modules: list[str]
    observed_count: int
    last_seen_at: datetime | None = None
    connector_count: int
    enabled_connector_count: int
    framework_names: list[str] = []
    live_evidence_count: int = 0
    live_evidence_last_seen_at: datetime | None = None
    has_live_evidence: bool = False


class ConnectorCoverageControlMapRow(BaseModel):
    control_id: str
    framework_names: list[str]
    signal_types: list[str]
    providers: list[str]
    live_evidence_count: int
    last_evidence_at: datetime | None = None


class ConnectorCoverageFrameworkRow(BaseModel):
    framework_name: str
    control_count: int
    signal_count: int
    live_evidence_count: int
    last_evidence_at: datetime | None = None


class ConnectorCoverageSummaryResponse(BaseModel):
    total_signal_rows: int
    controls_covered: int
    frameworks_with_live_evidence: int
    signals_with_live_evidence: int
    control_signal_map: list[ConnectorCoverageControlMapRow]
    framework_live_evidence: list[ConnectorCoverageFrameworkRow]


@router.get("/connectors", response_model=ListEnvelope[ConnectorResponse])
def list_connectors(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(select(Connector).where(Connector.tenant_id == ctx.tenant.id)).all()
    dto_rows = [ConnectorResponse.model_validate(_connector_response_payload(row)) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ConnectorResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/connectors/providers", response_model=ListEnvelope[dict])
def list_connector_providers(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    items = connector_catalog()
    page_items, total, safe_page, safe_page_size = paginate_rows(items, page=page, page_size=page_size)
    return ListEnvelope[dict](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/connectors/microsoft/permission-modes", response_model=ListEnvelope[dict])
def list_microsoft_permission_modes(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
):
    del ctx
    items = microsoft_permission_modes()
    page_items, total, safe_page, safe_page_size = paginate_rows(items, page=page, page_size=page_size)
    return ListEnvelope[dict](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.post("/connectors/microsoft/resolve-scopes", response_model=MicrosoftScopesResponse)
def resolve_microsoft_scopes(
    payload: MicrosoftScopeResolveRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
):
    del ctx
    provider_key = str(payload.provider_key or "").strip().lower()
    if not is_microsoft_graph_provider(provider_key):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="provider_key must be one of entra_id, microsoft_365, outlook, teams, onedrive_sharepoint, office_apps, microsoft_defender, power_platform",
        )
    try:
        resolved = resolve_microsoft_graph_scopes(
            provider_key=provider_key,
            permission_mode=payload.permission_mode,
            include_optional=bool(payload.include_optional),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return MicrosoftScopesResponse(
        provider_key=resolved["provider_key"],
        permission_mode=resolved["permission_mode"],
        required_scopes=list(resolved["required_scopes"]),
        optional_scopes=list(resolved["optional_scopes"]),
        selected_scopes=list(resolved["selected_scopes"]),
        security_profile=microsoft_graph_security_profile(),
    )


@router.post("/connectors/microsoft/admin-consent-url", response_model=MicrosoftConsentUrlResponse)
def microsoft_admin_consent_url(
    payload: MicrosoftConsentUrlRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
):
    del ctx
    try:
        consent_url = build_microsoft_admin_consent_url(
            tenant_id=payload.tenant_id,
            client_id=payload.client_id,
            redirect_uri=payload.redirect_uri,
            state=payload.state,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return MicrosoftConsentUrlResponse(
        consent_url=consent_url,
        tenant_id=payload.tenant_id,
        client_id=payload.client_id,
        redirect_uri=payload.redirect_uri,
    )


@router.get("/connectors/microsoft/app-registration-template", response_model=MicrosoftAppRegistrationTemplateResponse)
def microsoft_app_registration_template(
    ctx: TenantContext = Depends(require_role(min_role="admin")),
):
    del ctx
    return MicrosoftAppRegistrationTemplateResponse.model_validate(microsoft_graph_app_registration_template())


@router.post("/connectors", response_model=ConnectorResponse)
def create_connector(
    payload: ConnectorCreate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    row = _create_connector_record(db=db, ctx=ctx, payload=payload)

    db.commit()
    db.refresh(row)
    return ConnectorResponse.model_validate(_connector_response_payload(row))


@router.post("/connectors/bootstrap/slack", response_model=ConnectorBootstrapResponse)
def bootstrap_slack_connector(
    payload: SlackConnectorBootstrapRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    scopes = [scope.strip() for scope in (payload.scopes or ["channels:history", "groups:history", "search:read", "users:read"]) if scope and scope.strip()]
    oauth_params = {
        "client_id": payload.client_id,
        "scope": ",".join(scopes),
        "redirect_uri": payload.redirect_uri,
    }
    if payload.state:
        oauth_params["state"] = payload.state
    install_url = f"https://slack.com/oauth/v2/authorize?{urlencode(oauth_params, doseq=False)}"

    connector_response: ConnectorResponse | None = None
    connector_id: str | None = None
    if payload.create_connector:
        config = {
            "oauth_flow": "slack_oauth_v2",
            "redirect_uri": payload.redirect_uri,
            "workspace_domain": payload.workspace_domain,
            "required_scopes": scopes,
        }
        secrets = {
            "client_id": payload.client_id,
            "client_secret": payload.client_secret,
        }
        if payload.signing_secret:
            secrets["signing_secret"] = payload.signing_secret
        if payload.app_token:
            secrets["app_token"] = payload.app_token
        if payload.bot_token:
            secrets["bot_token"] = payload.bot_token
        row = _create_connector_record(
            db=db,
            ctx=ctx,
            payload=ConnectorCreate(
                name=payload.name,
                provider_key="slack",
                connector_type="slack",
                auth_type="bearer",
                enabled=payload.enabled,
                polling_interval_minutes=payload.polling_interval_minutes,
                config=config,
                secrets=secrets,
            ),
        )
        db.commit()
        db.refresh(row)
        connector_id = row.id
        connector_response = ConnectorResponse.model_validate(_connector_response_payload(row))
    else:
        db.commit()

    return ConnectorBootstrapResponse(
        provider_key="slack",
        connector_id=connector_id,
        created=bool(payload.create_connector),
        install_url=install_url,
        required_scopes=scopes,
        selected_scopes=scopes,
        connector=connector_response,
    )


@router.post("/connectors/bootstrap/microsoft", response_model=ConnectorBootstrapResponse)
def bootstrap_microsoft_connector(
    payload: MicrosoftConnectorBootstrapRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    provider_key = str(payload.provider_key or "").strip().lower()
    if not is_microsoft_graph_provider(provider_key):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="provider_key must be one of entra_id, microsoft_365, outlook, teams, onedrive_sharepoint, office_apps, microsoft_defender, power_platform",
        )
    try:
        scope_resolution = resolve_microsoft_graph_scopes(
            provider_key=provider_key,
            permission_mode=payload.permission_mode,
            include_optional=bool(payload.include_optional_scopes),
        )
        consent_url = build_microsoft_admin_consent_url(
            tenant_id=payload.tenant_id,
            client_id=payload.client_id,
            redirect_uri=payload.redirect_uri,
            state=payload.state,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    connector_response: ConnectorResponse | None = None
    connector_id: str | None = None
    connector_created = False
    connector_updated = False
    if payload.create_connector:
        secrets: dict[str, str] = {
            "tenant_id": payload.tenant_id,
            "client_id": payload.client_id,
        }
        credential_mode = str(payload.credential_mode or "client_secret").strip().lower()
        if credential_mode == "client_assertion":
            if not str(payload.client_assertion or "").strip():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="client_assertion is required when credential_mode=client_assertion")
            secrets["client_assertion"] = str(payload.client_assertion or "").strip()
            if payload.client_assertion_type:
                secrets["client_assertion_type"] = str(payload.client_assertion_type).strip()
        else:
            if not str(payload.client_secret or "").strip():
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="client_secret is required when credential_mode=client_secret")
            secrets["client_secret"] = str(payload.client_secret or "").strip()

        connector_config = {
            "tenant_id": payload.tenant_id,
            "client_id": payload.client_id,
            "redirect_uri": payload.redirect_uri,
            "permission_mode": scope_resolution["permission_mode"],
            "oauth_flow": "client_credentials",
            "app_registration_mode": "single_tenant",
            "metadata_only_ingestion": True,
            "base_url": "https://graph.microsoft.com/v1.0",
            "required_scopes": list(scope_resolution["required_scopes"]),
            "selected_scopes": list(scope_resolution["selected_scopes"]),
        }
        if payload.connector_id:
            row = db.scalar(
                select(Connector).where(
                    Connector.tenant_id == ctx.tenant.id,
                    Connector.id == payload.connector_id,
                )
            )
            if row is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Connector not found",
                )
            if not is_microsoft_graph_provider(row.provider_key) or row.provider_key != provider_key:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Existing connector provider does not match the Microsoft bootstrap request",
                )
            row.name = payload.name
            row.auth_type = "bearer"
            row.enabled = payload.enabled
            row.polling_interval_minutes = payload.polling_interval_minutes
            row.config = connector_config
            row.encrypted_secrets = encrypt_connector_secrets(secrets)
            row.status = "active"
            row.last_pull_status = "never"
            row.last_pull_error = None
            row.last_signal_count = 0
            row.last_run_at = None
            row.metadata_json = {
                "microsoft_graph": {
                    "permission_mode": scope_resolution["permission_mode"],
                    "required_scopes": list(scope_resolution["required_scopes"]),
                    "selected_scopes": list(scope_resolution["selected_scopes"]),
                    "metadata_only_ingestion": True,
                    "security_profile": microsoft_graph_security_profile(),
                    "admin_consent_url": consent_url,
                }
            }
            db.flush()
            write_audit_log(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=(ctx.user.id if ctx.user is not None else None),
                actor_type="human",
                action="monitoring.connector.credentials_rotated",
                resource_type="connector",
                resource_id=row.id,
                payload={
                    "provider_key": provider_key,
                    "permission_mode": scope_resolution["permission_mode"],
                    "enabled": payload.enabled,
                    "has_secrets": True,
                },
            )
            connector_updated = True
        else:
            row = _create_connector_record(
                db=db,
                ctx=ctx,
                payload=ConnectorCreate(
                    name=payload.name,
                    provider_key=provider_key,
                    connector_type=provider_key,
                    auth_type="bearer",
                    enabled=payload.enabled,
                    polling_interval_minutes=payload.polling_interval_minutes,
                    config=connector_config,
                    secrets=secrets,
                ),
            )
            connector_created = True
        db.commit()
        db.refresh(row)
        connector_id = row.id
        connector_response = ConnectorResponse.model_validate(_connector_response_payload(row))
    else:
        db.commit()

    return ConnectorBootstrapResponse(
        provider_key=provider_key,
        connector_id=connector_id,
        created=connector_created,
        updated=connector_updated,
        consent_url=consent_url,
        required_scopes=list(scope_resolution["required_scopes"]),
        selected_scopes=list(scope_resolution["selected_scopes"]),
        connector=connector_response,
    )


@router.post("/connectors/{connector_id}/pull", response_model=ConnectorResponse)
def pull_connector_now(
    connector_id: str,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    attempt = 0
    while attempt < SQLITE_LOCK_RETRY_ATTEMPTS:
        attempt += 1
        row = db.scalar(select(Connector).where(Connector.id == connector_id, Connector.tenant_id == ctx.tenant.id))
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
        try:
            run_connector_once(db, tenant_id=ctx.tenant.id, connector=row)
            db.commit()
            db.refresh(row)
            return ConnectorResponse.model_validate(_connector_response_payload(row))
        except OperationalError as exc:
            db.rollback()
            if _is_sqlite_lock_error(exc) and attempt < SQLITE_LOCK_RETRY_ATTEMPTS:
                time.sleep(SQLITE_LOCK_RETRY_BACKOFF_SECONDS * attempt)
                continue
            if _is_sqlite_lock_error(exc):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database busy while running connector pull. Retry in a few seconds.",
                ) from exc
            raise

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Connector pull could not acquire database lock after retries.",
    )


@router.get("/connectors/{connector_id}/evaluation", response_model=ConnectorEvaluationResponse)
def evaluate_connector(
    connector_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    evaluation = connector_evaluation(
        db,
        tenant_id=ctx.tenant.id,
        connector_id=connector_id,
    )
    if evaluation is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Connector not found")
    return ConnectorEvaluationResponse.model_validate(evaluation)


@router.post("/signals", response_model=MonitoringSignalResponse)
def ingest_signal(
    payload: SignalIngestRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    try:
        signal = ingest_monitoring_signal(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            signal_type=payload.signal_type,
            severity=payload.severity,
            payload=payload.payload,
            actor_user_id=None,
        )
        db.commit()
        db.refresh(signal)
        return MonitoringSignalResponse.model_validate(signal)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.post("/shadow-events", response_model=MonitoringSignalResponse)
def ingest_shadow(
    payload: ShadowEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    try:
        signal = ingest_shadow_event(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            event_type=payload.event_type,
            payload=payload.payload,
            actor_user_id=None,
        )
        db.commit()
        db.refresh(signal)
        return MonitoringSignalResponse.model_validate(signal)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/drift-alerts", response_model=ListEnvelope[DriftAlertResponse])
def list_drift_alerts(
    status_filter: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    query = select(DriftAlert).where(DriftAlert.tenant_id == ctx.tenant.id)
    if status_filter:
        query = query.where(DriftAlert.status == status_filter)
    rows = db.scalars(query.order_by(DriftAlert.created_at.desc())).all()
    dto_rows = [DriftAlertResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[DriftAlertResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/connectors/coverage", response_model=ListEnvelope[ConnectorCoverageResponse])
def list_connector_coverage(
    provider_key: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    rows = connector_control_coverage(
        db,
        tenant_id=ctx.tenant.id,
        provider_key=provider_key,
    )
    dto_rows = [ConnectorCoverageResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[ConnectorCoverageResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/connectors/coverage/summary", response_model=ConnectorCoverageSummaryResponse)
def connector_coverage_summary_view(
    provider_key: str | None = None,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = connector_coverage_summary(
        db,
        tenant_id=ctx.tenant.id,
        provider_key=provider_key,
    )
    return ConnectorCoverageSummaryResponse.model_validate(payload)
