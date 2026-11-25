"""Endpoint-agent API — server-authoritative controls for the Hawk endpoint agent.

All decisions (notetaker verdicts especially) are made here so device posture
cannot drift from central policy. Additive router; does not alter existing routes.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.endpoint_auth import EndpointPrincipal, require_endpoint_scope
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.user import User
from app.db.models.user import UserTenantRole
from app.db.session import get_db
from app.api.routers.extension import (
    BrowserTelemetryEventRequest,
    BrowserTelemetryIngestResponse,
    DesktopInteractionEvalRequest,
    desktop_interaction_eval,
)
from app.api.routers.gateway import (
    LLMInterceptRequest,
    MCPAuthorizeRequest,
    MCPToolScanRequest,
    gateway_llm_intercept,
    gateway_mcp_authorize,
    gateway_mcp_tool_scan,
)
from app.api.routers.runtime_control import (
    DataTransferCheckRequest,
    data_transfer_check,
)
from app.services.audit_service import write_audit_log
from app.services.browser_extension_service import process_browser_telemetry_event
from app.services.endpoint_identity_service import (
    DEFAULT_ENDPOINT_SCOPES,
    complete_enrollment,
    create_auth_challenge,
    create_enrollment_authorization,
    create_reenrollment_authorization,
    exchange_challenge_for_token,
)
from app.services.endpoint_agent_service import (
    build_endpoint_policy,
    evaluate_notetaker,
    execute_notetaker_platform_action,
    get_endpoint_floor_status,
    get_endpoint_health_status,
    ingest_notetaker_artifact_signal,
    ingest_notetaker_calendar_signal,
    ingest_notetaker_hidden_signal,
    ingest_notetaker_oauth_signal,
    record_evidence,
    record_heartbeat,
)
from app.services.hmair.endpoint_snapshot_service import (
    EndpointMetadataSnapshotInput,
    ingest_endpoint_metadata_snapshot,
)
from app.services.hmair.endpoint_metadata_inventory_service import (
    EndpointMetadataInventoryRunSummary,
    create_endpoint_metadata_inventory_run,
    fail_endpoint_metadata_inventory_assignment,
    get_endpoint_metadata_inventory_run,
    list_endpoint_metadata_inventory_runs,
    next_endpoint_metadata_inventory_assignment,
)

router = APIRouter(prefix="/endpoint-agent", tags=["endpoint-agent"])


@router.get("/floor/status")
def endpoint_enforcement_floor_status(
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    """Latest evidence-backed endpoint floor posture for the active tenant."""
    return get_endpoint_floor_status(db, tenant_id=ctx.tenant.id)


@router.get("/health")
def endpoint_health(
    ctx: TenantContext = Depends(require_permission("deployments.view")),
    db: Session = Depends(get_db),
):
    """Tenant-scoped endpoint identity, signed heartbeat, and policy freshness."""
    return get_endpoint_health_status(db, tenant_id=ctx.tenant.id)


class EnrollmentAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_id: str | None = Field(default=None, max_length=128)
    assigned_user_id: str | None = None
    scopes: list[str] = Field(default_factory=lambda: list(DEFAULT_ENDPOINT_SCOPES))


class EnrollmentAuthorizationResponse(BaseModel):
    authorization_id: str
    enrollment_code: str
    enrollment_nonce: str
    expires_at: datetime
    scopes: list[str]


class EndpointReenrollmentAuthorizationResponse(EnrollmentAuthorizationResponse):
    endpoint_id: str
    assigned_user_id: str | None = None
    revoked_identity_id: str


class EndpointEnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorization_id: str
    enrollment_code: str = Field(min_length=20, max_length=256)
    enrollment_nonce: str = Field(min_length=20, max_length=256)
    tenant_id: str
    endpoint_id: str = Field(min_length=1, max_length=128)
    key_provider: Literal[
        "macos_secure_enclave",
        "windows_tpm_cng",
        "linux_tpm2",
    ]
    public_key_pem: str = Field(min_length=100, max_length=2048)
    timestamp: int
    signature: str = Field(min_length=32, max_length=512)


class EndpointEnrollResponse(BaseModel):
    identity_id: str
    tenant_id: str
    endpoint_id: str
    key_provider: str
    key_thumbprint: str
    status: str
    scopes: list[str]


class EndpointChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    endpoint_id: str = Field(min_length=1, max_length=128)


class EndpointChallengeResponse(BaseModel):
    challenge_id: str
    nonce: str
    expires_at: datetime


class EndpointTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    challenge_id: str
    tenant_id: str
    endpoint_id: str = Field(min_length=1, max_length=128)
    nonce: str = Field(min_length=20, max_length=256)
    signature: str = Field(min_length=32, max_length=512)


class EndpointTokenResponse(BaseModel):
    access_token: str
    token_type: Literal["DPoP"]
    expires_in: int
    scope: list[str]


class EndpointRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(default="operator_revoked", min_length=1, max_length=255)


def _endpoint_tenant_context(principal: EndpointPrincipal) -> TenantContext:
    return TenantContext(tenant=principal.tenant, role="operator", user=principal.user)


@router.post(
    "/enrollment-authorizations", response_model=EnrollmentAuthorizationResponse
)
def issue_endpoint_enrollment_authorization(
    payload: EnrollmentAuthorizationRequest,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.assigned_user_id:
        membership = db.scalar(
            select(UserTenantRole).where(
                UserTenantRole.user_id == payload.assigned_user_id,
                UserTenantRole.tenant_id == ctx.tenant.id,
            )
        )
        if membership is None:
            raise HTTPException(status_code=422, detail="Assigned user is not in tenant")
    issued = create_enrollment_authorization(
        db,
        tenant_id=ctx.tenant.id,
        endpoint_id=payload.endpoint_id,
        assigned_user_id=payload.assigned_user_id or current_user.id,
        issued_by_user_id=current_user.id,
        scopes=payload.scopes,
    )
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="endpoint.identity.enrollment_authorized",
        resource_type="endpoint_enrollment_authorization",
        resource_id=issued["authorization_id"],
        payload={
            "endpoint_id": payload.endpoint_id,
            "assigned_user_id": payload.assigned_user_id or current_user.id,
            "scopes": issued["scopes"],
            "expires_at": issued["expires_at"].isoformat(),
        },
    )
    db.commit()
    return EnrollmentAuthorizationResponse(**issued)


@router.post(
    "/identities/{endpoint_id}/reenroll-authorizations",
    response_model=EndpointReenrollmentAuthorizationResponse,
)
def issue_endpoint_reenrollment_authorization(
    endpoint_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    issued = create_reenrollment_authorization(
        db,
        tenant_id=ctx.tenant.id,
        endpoint_id=endpoint_id,
        issued_by_user_id=current_user.id,
        scopes=DEFAULT_ENDPOINT_SCOPES,
    )
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="endpoint.identity.reenrollment_authorized",
        resource_type="endpoint_device_identity",
        resource_id=issued["revoked_identity_id"],
        payload={
            "endpoint_id": endpoint_id,
            "authorization_id": issued["authorization_id"],
            "assigned_user_id": issued.get("assigned_user_id"),
            "scopes": issued["scopes"],
            "expires_at": issued["expires_at"].isoformat(),
        },
    )
    db.commit()
    return EndpointReenrollmentAuthorizationResponse(**issued)


@router.post("/enroll", response_model=EndpointEnrollResponse)
def enroll_endpoint_identity(
    payload: EndpointEnrollRequest,
    db: Session = Depends(get_db),
):
    identity = complete_enrollment(
        db,
        authorization_id=payload.authorization_id,
        enrollment_code=payload.enrollment_code,
        enrollment_nonce=payload.enrollment_nonce,
        tenant_id=payload.tenant_id,
        endpoint_id=payload.endpoint_id,
        key_provider=payload.key_provider,
        public_key_pem=payload.public_key_pem,
        timestamp=payload.timestamp,
        signature_b64=payload.signature,
    )
    write_audit_log(
        db,
        tenant_id=identity.tenant_id,
        actor_user_id=identity.enrolled_by_user_id,
        actor_type="agent",
        action="endpoint.identity.enrolled",
        resource_type="endpoint_device_identity",
        resource_id=identity.id,
        payload={
            "endpoint_id": identity.endpoint_id,
            "key_provider": identity.key_provider,
            "key_thumbprint": identity.key_thumbprint,
            "scopes": list(identity.scopes),
        },
    )
    db.commit()
    return EndpointEnrollResponse(
        identity_id=identity.id,
        tenant_id=identity.tenant_id,
        endpoint_id=identity.endpoint_id,
        key_provider=identity.key_provider,
        key_thumbprint=identity.key_thumbprint,
        status=identity.status,
        scopes=list(identity.scopes),
    )


@router.post("/auth/challenge", response_model=EndpointChallengeResponse)
def endpoint_auth_challenge(
    payload: EndpointChallengeRequest,
    db: Session = Depends(get_db),
):
    return EndpointChallengeResponse(
        **create_auth_challenge(
            db, tenant_id=payload.tenant_id, endpoint_id=payload.endpoint_id
        )
    )


@router.post("/auth/token", response_model=EndpointTokenResponse)
def endpoint_auth_token(payload: EndpointTokenRequest, db: Session = Depends(get_db)):
    return EndpointTokenResponse(
        **exchange_challenge_for_token(
            db,
            challenge_id=payload.challenge_id,
            tenant_id=payload.tenant_id,
            endpoint_id=payload.endpoint_id,
            nonce=payload.nonce,
            signature_b64=payload.signature,
        )
    )


@router.post("/identities/{endpoint_id}/revoke")
def revoke_endpoint_identity(
    endpoint_id: str,
    payload: EndpointRevokeRequest,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    identity = db.scalar(
        select(EndpointDeviceIdentity).where(
            EndpointDeviceIdentity.tenant_id == ctx.tenant.id,
            EndpointDeviceIdentity.endpoint_id == endpoint_id,
        )
    )
    if identity is None:
        raise HTTPException(status_code=404, detail="Endpoint identity not found")
    identity.status = "revoked"
    identity.revoked_at = datetime.now(timezone.utc)
    identity.revoked_by_user_id = current_user.id
    identity.revocation_reason = payload.reason
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        actor_type="human",
        action="endpoint.identity.revoked",
        resource_type="endpoint_device_identity",
        resource_id=identity.id,
        payload={"endpoint_id": endpoint_id, "reason": payload.reason},
    )
    db.commit()
    return {"status": "revoked", "endpoint_id": endpoint_id}


@router.post("/decision/llm")
def endpoint_llm_decision(
    payload: LLMInterceptRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:decision:execute")
    ),
    db: Session = Depends(get_db),
):
    return gateway_llm_intercept(
        payload=payload,
        ctx=_endpoint_tenant_context(principal),
        db=db,
    )


@router.post("/decision/mcp")
def endpoint_mcp_decision(
    payload: MCPAuthorizeRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:decision:execute")
    ),
    db: Session = Depends(get_db),
):
    return gateway_mcp_authorize(
        payload=payload,
        ctx=_endpoint_tenant_context(principal),
        db=db,
    )


@router.post("/decision/mcp/tools/scan")
def endpoint_mcp_tool_scan(
    payload: MCPToolScanRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:decision:execute")
    ),
    db: Session = Depends(get_db),
):
    return gateway_mcp_tool_scan(
        payload=payload,
        ctx=_endpoint_tenant_context(principal),
        db=db,
    )


@router.post("/decision/data-transfer")
def endpoint_data_transfer_decision(
    request: Request,
    payload: DataTransferCheckRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:decision:execute")
    ),
    db: Session = Depends(get_db),
):
    return data_transfer_check(
        request=request,
        payload=payload,
        ctx=_endpoint_tenant_context(principal),
        current_user=principal.user,
        db=db,
    )


@router.post("/decision/interaction")
def endpoint_interaction_decision(
    request: Request,
    payload: DesktopInteractionEvalRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:decision:execute")
    ),
    db: Session = Depends(get_db),
):
    return desktop_interaction_eval(
        request=request,
        payload=payload,
        ctx=_endpoint_tenant_context(principal),
        current_user=principal.user,
        db=db,
    )


class NotetakerEvalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    endpoint_id: str = ""
    hostname: str = ""
    notetaker: str = ""
    signal: dict[str, Any] = Field(default_factory=dict)


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    endpoint_id: str = ""
    hostname: str = ""


class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    endpoint_id: str = ""
    event_type: str = ""


class EndpointMetadataSnapshotResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    status: str
    observations_count: int
    endpoint_denominator: int
    limitations: list[str]


class EndpointMetadataInventoryRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    endpoint_ids: list[str] | None = Field(default=None, max_length=5_000)
    expires_in_minutes: int = Field(default=60, ge=5, le=1_440)


class EndpointMetadataInventoryFailureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: Literal[
        "scanner_unavailable",
        "scanner_rejected",
        "snapshot_rejected",
        "unsupported_platform",
    ]


class EndpointMetadataInventoryRunResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    status: str
    endpoint_denominator: int
    pending_count: int
    delivered_count: int
    completed_count: int
    failed_count: int
    expired_count: int
    cancelled_count: int
    expires_at: datetime
    limitations: list[str]


class EndpointMetadataInventoryRunListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[EndpointMetadataInventoryRunResponse]


def _inventory_run_response(
    summary: EndpointMetadataInventoryRunSummary,
) -> EndpointMetadataInventoryRunResponse:
    return EndpointMetadataInventoryRunResponse(
        id=summary.id,
        status=summary.status,
        endpoint_denominator=summary.endpoint_denominator,
        pending_count=summary.pending_count,
        delivered_count=summary.delivered_count,
        completed_count=summary.completed_count,
        failed_count=summary.failed_count,
        expired_count=summary.expired_count,
        cancelled_count=summary.cancelled_count,
        expires_at=summary.expires_at,
        limitations=list(summary.limitations),
    )


def _require_hmair_endpoint_snapshot() -> None:
    """Keep the passive lab endpoint route invisible until explicitly enabled."""

    if (
        getattr(settings, "hmair_core", False) is not True
        or getattr(settings, "hmair_endpoint", False) is not True
    ):
        raise HTTPException(status_code=404, detail="Not Found")


class NotetakerPlatformActionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    endpoint_id: str = ""
    hostname: str = ""
    platform: str = ""
    action: str = ""
    meeting_id: str | None = None
    participant_id: str | None = None
    organizer_user_id: str | None = None
    notetaker_email: str | None = None
    notetaker_label: str | None = None
    source_detection_evidence_id: str | None = None


class NotetakerCalendarAttendee(BaseModel):
    model_config = ConfigDict(extra="allow")
    email: str | None = None
    display_name: str | None = None
    participant_id: str | None = None
    role: str | None = None


class NotetakerCalendarSignalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str = "calendar"
    platform: str = ""
    meeting_id: str = ""
    title: str = ""
    organizer_email: str | None = None
    organizer_user_id: str | None = None
    attendees: list[NotetakerCalendarAttendee] = Field(default_factory=list)
    sensitivity_label: str | None = None
    transcription_enabled: bool | None = None
    recording_enabled: bool | None = None


class NotetakerOAuthAppSignalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str = "oauth"
    provider: str = ""
    app_id: str | None = None
    client_id: str | None = None
    tenant_app_id: str | None = None
    name: str = ""
    publisher: str | None = None
    homepage_url: str | None = None
    scopes: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)


class NotetakerHiddenSignalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str = "local_agent"
    endpoint_id: str = ""
    hostname: str = ""
    meeting_platform: str = ""
    meeting_id: str = ""
    active_meeting: bool | None = None
    visible_in_roster: bool | None = None
    local_audio_capture: bool | None = None
    microphone_active: bool | None = None
    processes: list[dict[str, Any]] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    audio_devices: list[str] = Field(default_factory=list)
    transcription_artifact_count: int | None = None


class NotetakerArtifactSignalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    source: str = "meeting_artifact"
    platform: str = ""
    meeting_id: str = ""
    title: str = ""
    organizer_email: str | None = None
    organizer_user_id: str | None = None
    attendance_participants: list[NotetakerCalendarAttendee] = Field(default_factory=list)
    sensitivity_label: str | None = None
    attendance_report_present: bool | None = None
    transcription_enabled: bool | None = None
    recording_enabled: bool | None = None
    transcript_artifact_count: int | None = None
    recording_artifact_count: int | None = None
    external_participant_count: int | None = None
    notetaker_visible_in_roster: bool | None = None


@router.get("/policy")
def endpoint_policy(
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:policy:read")
    ),
    db: Session = Depends(get_db),
):
    hmair_metadata_inventory = None
    if (
        getattr(settings, "hmair_core", False) is True
        and getattr(settings, "hmair_endpoint", False) is True
    ):
        directive = next_endpoint_metadata_inventory_assignment(
            db,
            tenant_id=principal.tenant.id,
            endpoint_identity_id=principal.identity.id,
        )
        if directive is not None:
            hmair_metadata_inventory = {
                "assignment_id": directive.assignment_id,
                "inventory_run_id": directive.inventory_run_id,
                "mode": directive.mode,
                "expires_at": directive.expires_at.isoformat(),
            }
    return build_endpoint_policy(
        db,
        tenant_id=principal.tenant.id,
        hmair_metadata_inventory=hmair_metadata_inventory,
    )


@router.post(
    "/discovery/metadata-inventory-runs",
    response_model=EndpointMetadataInventoryRunResponse,
)
def create_metadata_inventory_run(
    payload: EndpointMetadataInventoryRunRequest,
    ctx: TenantContext = Depends(require_permission("deployments.manage")),
    db: Session = Depends(get_db),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
):
    """Request bounded endpoint metadata inventory for an eligible denominator."""

    _require_hmair_endpoint_snapshot()
    if idempotency_key is None:
        raise HTTPException(status_code=400, detail="Idempotency-Key header is required")
    try:
        summary = create_endpoint_metadata_inventory_run(
            db,
            tenant_id=ctx.tenant.id,
            requested_by_user_id=ctx.user.id if ctx.user is not None else None,
            request_idempotency_key=idempotency_key,
            endpoint_ids=payload.endpoint_ids,
            expires_in_minutes=payload.expires_in_minutes,
        )
        write_audit_log(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id if ctx.user is not None else None,
            actor_type="human",
            action="hmair.endpoint_metadata_inventory.requested",
            resource_type="endpoint_metadata_inventory_run",
            resource_id=summary.id,
            payload={
                "endpoint_denominator": summary.endpoint_denominator,
                "expires_at": summary.expires_at.isoformat(),
                "limitations": list(summary.limitations),
            },
        )
        db.commit()
    except (LookupError, ValueError) as exc:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail="Metadata inventory request is invalid or has no eligible endpoints",
        ) from exc
    return _inventory_run_response(summary)


@router.get(
    "/discovery/metadata-inventory-runs",
    response_model=EndpointMetadataInventoryRunListResponse,
)
def list_metadata_inventory_runs(
    limit: int = Query(default=20, ge=1, le=100),
    ctx: TenantContext = Depends(require_permission("deployments.inspect")),
    db: Session = Depends(get_db),
):
    """List bounded aggregate history for the active tenant only."""

    _require_hmair_endpoint_snapshot()
    summaries = list_endpoint_metadata_inventory_runs(
        db,
        tenant_id=ctx.tenant.id,
        limit=limit,
    )
    db.commit()
    return EndpointMetadataInventoryRunListResponse(
        items=[_inventory_run_response(summary) for summary in summaries]
    )


@router.get(
    "/discovery/metadata-inventory-runs/{run_id}",
    response_model=EndpointMetadataInventoryRunResponse,
)
def get_metadata_inventory_run(
    run_id: str,
    ctx: TenantContext = Depends(require_permission("deployments.inspect")),
    db: Session = Depends(get_db),
):
    """Return tenant-scoped aggregate progress without exposing endpoint names."""

    _require_hmair_endpoint_snapshot()
    try:
        summary = get_endpoint_metadata_inventory_run(
            db,
            tenant_id=ctx.tenant.id,
            run_id=run_id,
        )
        db.commit()
    except LookupError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="Metadata inventory run was not found") from exc
    return _inventory_run_response(summary)


@router.post(
    "/discovery/metadata-inventory-assignments/{assignment_id}/failure",
    response_model=EndpointMetadataInventoryRunResponse,
)
def endpoint_metadata_inventory_failure(
    assignment_id: str,
    payload: EndpointMetadataInventoryFailureRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:discovery:write")
    ),
    db: Session = Depends(get_db),
):
    """Record one bounded failure from the endpoint that received the work."""

    _require_hmair_endpoint_snapshot()
    try:
        summary = fail_endpoint_metadata_inventory_assignment(
            db,
            tenant_id=principal.tenant.id,
            endpoint_identity_id=principal.identity.id,
            assignment_id=assignment_id,
            code=payload.code,
        )
        write_audit_log(
            db,
            tenant_id=principal.tenant.id,
            actor_user_id=principal.user.id,
            actor_type="endpoint_device",
            action="hmair.endpoint_metadata_inventory.failed",
            resource_type="endpoint_metadata_inventory_run",
            resource_id=summary.id,
            payload={"code": payload.code},
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail="Metadata inventory failure is invalid") from exc
    return _inventory_run_response(summary)


@router.post("/notetaker/evaluate")
def notetaker_evaluate(
    payload: NotetakerEvalRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:decision:execute")
    ),
    db: Session = Depends(get_db),
):
    signal = payload.signal or {}
    if not signal and payload.notetaker:
        signal = {"subject": payload.notetaker, "attributes": {}}
    return evaluate_notetaker(
        db,
        tenant_id=principal.tenant.id,
        endpoint_id=principal.identity.endpoint_id,
        hostname=payload.hostname,
        signal=signal,
        actor_user_id=principal.user.id,
    )


@router.post("/notetaker/platform-action")
def notetaker_platform_action(
    payload: NotetakerPlatformActionRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:decision:execute")
    ),
    db: Session = Depends(get_db),
):
    action_payload = payload.model_dump()
    action_payload["endpoint_id"] = principal.identity.endpoint_id
    return execute_notetaker_platform_action(
        db,
        tenant_id=principal.tenant.id,
        endpoint_id=principal.identity.endpoint_id,
        hostname=payload.hostname,
        platform=payload.platform,
        action=payload.action,
        payload=action_payload,
        actor_user_id=principal.user.id,
    )


@router.post("/notetaker/calendar-signal")
def notetaker_calendar_signal(
    payload: NotetakerCalendarSignalRequest,
    ctx: TenantContext = Depends(require_permission("deployments.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return ingest_notetaker_calendar_signal(
        db,
        tenant_id=ctx.tenant.id,
        payload=payload.model_dump(),
        actor_user_id=current_user.id,
    )


@router.post("/notetaker/oauth-signal")
def notetaker_oauth_signal(
    payload: NotetakerOAuthAppSignalRequest,
    ctx: TenantContext = Depends(require_permission("deployments.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return ingest_notetaker_oauth_signal(
        db,
        tenant_id=ctx.tenant.id,
        payload=payload.model_dump(),
        actor_user_id=current_user.id,
    )


@router.post("/notetaker/hidden-signal")
def notetaker_hidden_signal(
    payload: NotetakerHiddenSignalRequest,
    ctx: TenantContext = Depends(require_permission("deployments.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return ingest_notetaker_hidden_signal(
        db,
        tenant_id=ctx.tenant.id,
        payload=payload.model_dump(),
        actor_user_id=current_user.id,
    )


@router.post("/notetaker/artifact-signal")
def notetaker_artifact_signal(
    payload: NotetakerArtifactSignalRequest,
    ctx: TenantContext = Depends(require_permission("deployments.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return ingest_notetaker_artifact_signal(
        db,
        tenant_id=ctx.tenant.id,
        payload=payload.model_dump(),
        actor_user_id=current_user.id,
    )


@router.post("/heartbeat")
def endpoint_heartbeat(
    payload: HeartbeatRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:heartbeat:write")
    ),
    db: Session = Depends(get_db),
):
    heartbeat_payload = payload.model_dump()
    heartbeat_payload["endpoint_id"] = principal.identity.endpoint_id
    return record_heartbeat(
        db,
        tenant_id=principal.tenant.id,
        endpoint_id=principal.identity.endpoint_id,
        payload=heartbeat_payload,
    )


@router.post("/telemetry", response_model=BrowserTelemetryIngestResponse)
def endpoint_telemetry(
    request: Request,
    payload: BrowserTelemetryEventRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:telemetry:write")
    ),
    db: Session = Depends(get_db),
):
    """Ingest endpoint discovery through the existing telemetry pipeline.

    Tenant, endpoint, and human attribution come from the verified device
    identity; caller-supplied values cannot impersonate a different endpoint.
    """
    data = payload.model_dump(mode="json")
    data["tenant_id"] = principal.tenant.id
    data["endpoint_id"] = principal.identity.endpoint_id
    data["source_surface"] = data.get("source_surface") or "endpoint_agent"
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        result = process_browser_telemetry_event(
            db,
            tenant_id=principal.tenant.id,
            actor_user_id=principal.user.id,
            payload=data,
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return BrowserTelemetryIngestResponse.model_validate(result)


@router.post(
    "/discovery/snapshots",
    response_model=EndpointMetadataSnapshotResponse,
)
def endpoint_metadata_snapshot(
    payload: EndpointMetadataSnapshotInput,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:discovery:write")
    ),
    db: Session = Depends(get_db),
) -> EndpointMetadataSnapshotResponse:
    """Ingest one passive, metadata-only HMAIR lab snapshot.

    Tenant, actor, and endpoint are derived from the authenticated device; the
    request carries no authority to select another scope.
    """

    _require_hmair_endpoint_snapshot()
    try:
        receipt = ingest_endpoint_metadata_snapshot(
            db,
            tenant_id=principal.tenant.id,
            actor_user_id=principal.user.id,
            endpoint_id=principal.identity.endpoint_id,
            endpoint_identity_id=principal.identity.id,
            collector_version="endpoint-agent",
            snapshot=payload,
        )
        write_audit_log(
            db,
            tenant_id=principal.tenant.id,
            actor_user_id=principal.user.id,
            actor_type="endpoint_device",
            action="hmair.endpoint_metadata_snapshot.ingested",
            resource_type="discovery_scan",
            resource_id=receipt.scan_id,
            payload={
                "observations_count": receipt.observations_count,
                "endpoint_denominator": receipt.endpoint_denominator,
                "status": receipt.status,
            },
        )
        db.commit()
    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=422,
            detail="Endpoint metadata snapshot is invalid",
        ) from exc
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="Endpoint metadata snapshot could not be processed",
        ) from exc
    return EndpointMetadataSnapshotResponse(
        scan_id=receipt.scan_id,
        status=receipt.status,
        observations_count=receipt.observations_count,
        endpoint_denominator=receipt.endpoint_denominator,
        limitations=list(receipt.limitations),
    )


@router.post("/evidence")
def endpoint_evidence(
    payload: EvidenceRequest,
    principal: EndpointPrincipal = Depends(
        require_endpoint_scope("endpoint:evidence:write")
    ),
    db: Session = Depends(get_db),
):
    evidence_payload = payload.model_dump()
    evidence_payload["endpoint_id"] = principal.identity.endpoint_id
    return record_evidence(
        db,
        tenant_id=principal.tenant.id,
        endpoint_id=principal.identity.endpoint_id,
        payload=evidence_payload,
    )
