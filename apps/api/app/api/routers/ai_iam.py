from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from pydantic_core import PydanticCustomError
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.deps_control_plane import require_control_plane_healthy
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.core.observability import get_correlation_id, log_structured
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.evidence import EvidenceEdge, EvidenceNode
from app.db.models.monitoring import MonitoringSignal
from app.db.models.policy import ApprovalRequest, BusinessPurposeSession
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.session import SessionLocal, get_db
from app.services.ai_iam_service import (
    collect_delegation_descendant_agent_ids,
    create_agent_delegation,
    jit_token_mint_requires_approval,
    mint_capability_token,
    mint_capability_token_with_authority,
    revoke_agent_delegations,
    revoke_capability_token,
    validate_capability_token,
)
from app.services.ai_iam_identity_service import (
    get_agent_identity_profile,
    list_agent_identity_profiles,
)
from app.services.activity_audit_service import (
    get_user_registry_entry,
    list_user_registry,
)
from app.services.agentic_action_integrity_service import agent_blast_radius, agent_touchpoints, evaluate_jit_grant
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.fail_secure_service import enforce_fail_secure_or_raise
from app.services.snapshot_service import create_auditor_snapshot


router = APIRouter(
    prefix="/ai-iam",
    tags=["ai-iam"],
    dependencies=[Depends(require_control_plane_healthy(module="ai_iam"))],
)


def _project_token_revocation_runtime_event(
    *,
    tenant_id: str,
    token_id: str,
    agent_id: str,
    ai_system_id: str | None,
    scopes: list[str],
    correlation_id: str | None,
    bind: Any | None = None,
) -> None:
    """Project an already-committed revocation without participating in its transaction."""
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_ai_iam_event

        with (Session(bind=bind) if bind is not None else SessionLocal()) as projection_db:
            ingest_from_ai_iam_event(
                projection_db,
                tenant_id=tenant_id,
                event_type="aiiam.token_revoked",
                ai_system_id=ai_system_id,
                user_id=None,
                agent_id=agent_id,
                severity="med",
                evidence_node_ids=[],
                correlation_id=correlation_id,
                # This is an authority-control lifecycle record, not observed AI
                # activity.  The normalizer's supported operational-telemetry
                # semantics suppress discovery and anomaly processing.
                metadata={
                    "action": "token_revoke",
                    "capability_token_id": token_id,
                    "scopes": list(scopes),
                    "operational_telemetry": True,
                },
            )
            projection_db.commit()
    except Exception as exc:  # pragma: no cover - defensive post-response guard
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="ai_iam_router",
            tenant_id=tenant_id,
            event_type="aiiam.token_revoked",
            token_id=token_id,
            error=str(exc),
        )


def _project_token_mint_runtime_event(
    *,
    tenant_id: str,
    token_id: str,
    agent_id: str,
    ai_system_id: str,
    scopes: list[str],
    chain_depth: int,
    approval_request_id: str | None,
    correlation_id: str | None,
    bind: Any | None = None,
) -> None:
    """Project an already-committed token mint without participating in its transaction."""
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_ai_iam_event

        with (Session(bind=bind) if bind is not None else SessionLocal()) as projection_db:
            try:
                ingest_from_ai_iam_event(
                    projection_db,
                    tenant_id=tenant_id,
                    event_type="aiiam.token_minted",
                    ai_system_id=ai_system_id,
                    user_id=None,
                    agent_id=agent_id,
                    severity="med",
                    evidence_node_ids=[],
                    correlation_id=correlation_id,
                    # Capability lifecycle is operational telemetry, not an
                    # observed AI-discovery event.
                    metadata={
                        "action": "token_mint",
                        "capability_token_id": token_id,
                        "scopes": list(scopes),
                        "chain_depth": chain_depth,
                        "approval_request_id": approval_request_id,
                        "operational_telemetry": True,
                    },
                )
                projection_db.commit()
            except Exception:
                projection_db.rollback()
                raise
    except Exception as exc:  # pragma: no cover - defensive post-response guard
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="ai_iam_router",
            tenant_id=tenant_id,
            event_type="aiiam.token_minted",
            token_id=token_id,
            error=str(exc),
        )


def _raise_jit_approval_required(
    *,
    tenant_id: str,
    ai_system_id: str,
    agent_id: str,
    scopes: list[str],
    chain_depth: int,
    expires_minutes: int,
    db: Session,
) -> None:
    req = ApprovalRequest(
        tenant_id=tenant_id,
        enforcement_event_id=None,
        ai_system_id=ai_system_id,
        request_payload={
            "type": "jit_token_mint",
            "agent_id": agent_id,
            "scopes": scopes,
            "chain_depth": chain_depth,
            "expires_minutes": expires_minutes,
        },
        required_roles=["owner", "admin"],
        sla_minutes=30,
        default_if_timeout="block",
        status="pending",
    )
    db.add(req)
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="human",
        action="ai_iam.token.mint.approval_requested",
        resource_type="approval_request",
        resource_id=req.id,
        payload={
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "scopes": scopes,
            "chain_depth": chain_depth,
            "expires_minutes": expires_minutes,
        },
    )
    db.commit()
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "code": "jit_approval_required",
            "message": "JIT approval required before minting token for high-risk AI system.",
            "approval_request_id": req.id,
        },
)


class AgentCreate(BaseModel):
    name: str
    description: str = ""
    owner_attested_at: datetime | None = None
    owner_attestation_expiry: datetime | None = None
    max_chain_depth: int = 3
    capability_inheritance: bool = False
    action_scope: list[str] = Field(default_factory=list)
    tool_registry: list[str] = Field(default_factory=list)
    external_system_access: list[str] = Field(default_factory=list)
    agent_type: str = "workflow_agent"
    autonomy_level: str = "medium"

    @model_validator(mode="after")
    def reject_client_owned_attestation_timestamps(self):
        if {"owner_attested_at", "owner_attestation_expiry"} & self.model_fields_set:
            raise PydanticCustomError(
                "owner_attestation_server_issued",
                "Owner attestation timestamps are server-issued; use the refresh endpoint.",
            )
        return self


class AgentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    owner_attested_at: datetime | None = None
    owner_attestation_expiry: datetime | None = None
    max_chain_depth: int | None = None
    capability_inheritance: bool | None = None
    action_scope: list[str] | None = None
    tool_registry: list[str] | None = None
    external_system_access: list[str] | None = None
    agent_type: str | None = None
    autonomy_level: str | None = None

    @model_validator(mode="after")
    def reject_client_owned_attestation_timestamps(self):
        if {"owner_attested_at", "owner_attestation_expiry"} & self.model_fields_set:
            raise PydanticCustomError(
                "owner_attestation_server_issued",
                "Owner attestation timestamps are server-issued; use the refresh endpoint.",
            )
        return self


class OwnerAttestationRefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expires_minutes: int = Field(default=35, ge=1, le=60)


class MintTokenRequest(BaseModel):
    ai_system_id: str
    scopes: list[str]
    expires_minutes: int = 120
    chain_depth: int = 1
    approval_request_id: str | None = None


class DelegateTokenRequest(BaseModel):
    parent_agent_id: str
    child_agent_id: str
    ai_system_id: str
    parent_capability_token: str
    action_scope: list[str]
    expires_minutes: int = 60
    chain_depth: int | None = None
    parent_chain_depth: int = 1
    metadata: dict[str, Any] = Field(default_factory=dict)


class PurposeSessionCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    declared_purpose: str = Field(min_length=1, max_length=512)
    purpose_category: str = Field(default="unknown", max_length=64)
    business_function: str = Field(default="unknown", max_length=64)
    approved_scope: dict[str, Any]
    expires_minutes: int = Field(default=30, ge=1, le=1440)


class PurposeSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    user_id: str
    declared_purpose: str
    purpose_category: str
    business_function: str
    approved_scope: dict[str, Any]
    expires_at: datetime | None
    status: str


class JITGrantEvaluateRequest(BaseModel):
    chain_id: str
    agent_id: str
    requested_scope: list[str] = Field(default_factory=list)
    approved_scope: list[str] = Field(default_factory=list)
    approved_task: str = ""
    actual_action: str = ""
    identity_provider: str | None = None
    grant_type: str = "temporary"
    expires_at: datetime | None = None


class AgentIdentityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: str
    status: str
    owner_attested_at: datetime | None = None
    owner_attestation_expiry: datetime | None = None
    max_chain_depth: int
    capability_inheritance: bool
    action_scope: list[str]
    tool_registry: list[str]
    external_system_access: list[str]
    agent_type: str
    autonomy_level: str


class IdentityPermissionsResponse(BaseModel):
    tools: list[str] = Field(default_factory=list)
    data: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)


class IdentityCRQResponse(BaseModel):
    ALE: float = 0.0
    SLE: float = 0.0
    ARO: float = 0.0
    baseline_ALE: float = 0.0
    loss_reduction: float = 0.0
    remediation_cost: float = 0.0
    decision_impact_score: float = 0.0
    control_effectiveness: float = 0.0


class IdentityRiskComponentsResponse(BaseModel):
    privilege_score: float = 0.0
    behavior_anomaly_score: float = 0.0
    control_failure_score: float = 0.0
    exposure_score: float = 0.0
    simulation_failure_score: float = 0.0


class IdentityTokenControlResponse(BaseModel):
    active_token_count: int = 0
    kill_switch_ready: bool = True
    rotation_recommended: bool = False


class IdentityAnomalySummaryResponse(BaseModel):
    count: int = 0
    recent_high: int = 0


class IdentityControlSummaryResponse(BaseModel):
    triggered_controls: list[str] = Field(default_factory=list)
    missed_controls: list[str] = Field(default_factory=list)
    failed_controls: int = 0
    total_controls_evaluated: int = 0
    effectiveness: float = 0.0


class IdentitySimulationSummaryResponse(BaseModel):
    total_runs: int = 0
    pass_: int = Field(default=0, alias="pass")
    fail: int = 0
    partial: int = 0
    not_executable: int = 0
    pass_rate: float = 0.0


class AgentIdentityProfileResponse(BaseModel):
    identity_id: str
    type: str
    owner: str | None = None
    model: str | None = None
    environment: list[str] = Field(default_factory=list)
    permissions: IdentityPermissionsResponse = Field(default_factory=IdentityPermissionsResponse)
    token_scope: list[str] = Field(default_factory=list)
    expiry: str | None = None
    status: str
    risk_score: float = 0.0
    blast_radius_score: float = 0.0
    tools: list[str] = Field(default_factory=list)
    recent_actions: list[dict[str, Any]] = Field(default_factory=list)
    linked_findings: list[str] = Field(default_factory=list)
    behavior_profile: dict[str, Any] = Field(default_factory=dict)
    crq: IdentityCRQResponse = Field(default_factory=IdentityCRQResponse)
    risk_components: IdentityRiskComponentsResponse = Field(default_factory=IdentityRiskComponentsResponse)
    token_control: IdentityTokenControlResponse = Field(default_factory=IdentityTokenControlResponse)
    anomalies: IdentityAnomalySummaryResponse = Field(default_factory=IdentityAnomalySummaryResponse)
    controls: IdentityControlSummaryResponse = Field(default_factory=IdentityControlSummaryResponse)
    simulation: IdentitySimulationSummaryResponse = Field(default_factory=IdentitySimulationSummaryResponse)
    exposure_context: dict[str, Any] = Field(default_factory=dict)
    graph_summary: dict[str, Any] = Field(default_factory=dict)
    owasp_summary: dict[str, Any] = Field(default_factory=dict)
    blast_radius: dict[str, Any] | None = None
    lookback_hours: int = 0
    updated_at: str | None = None


class AgentActivityActionResponse(BaseModel):
    event_id: str
    event_type: str
    decision: str
    application: str | None = None
    tool_name: str | None = None
    machine_id: str | None = None
    created_at: datetime
    risk_score: float = 0.0


class AgentActivityResponse(BaseModel):
    agent_id: str
    last_actions: list[AgentActivityActionResponse] = Field(default_factory=list)
    tools_used: list[str] = Field(default_factory=list)
    anomaly_flag: bool = False
    anomaly_count: int = 0


class UserRegistryDetailResponse(BaseModel):
    user: dict[str, Any] | None = None
    machine_id: str | None = None
    browser_type: str | None = None
    last_seen: str | None = None
    ai_activity_count: int = 0
    recent_actions: list[dict[str, Any]] = Field(default_factory=list)


class MintTokenResponse(BaseModel):
    token_id: str
    capability_token: str
    scopes: list[str]
    expires_at: datetime
    approval_request_id: str | None = None


class RevokeTokenResponse(BaseModel):
    status: str
    token_id: str


class KillSwitchResponse(BaseModel):
    status: str
    agent_id: str
    revoked_tokens: int
    snapshot_id: str
    evidence_node_ids: list[str]


class DelegateTokenResponse(BaseModel):
    delegation_id: str
    token_id: str
    capability_token: str
    scopes: list[str]
    expires_at: datetime
    parent_agent_id: str
    child_agent_id: str


@router.get("/agents", response_model=ListEnvelope[AgentIdentityResponse])
def list_agents(
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id="ai_iam.list_agents",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    rows = db.scalars(select(AgentIdentity).where(AgentIdentity.tenant_id == ctx.tenant.id)).all()
    dto_rows = [AgentIdentityResponse.model_validate(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[AgentIdentityResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/agents/{agent_id}/activity", response_model=AgentActivityResponse)
def get_agent_activity(
    agent_id: str,
    lookback_hours: int = 24 * 30,
    limit: int = 30,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"ai_iam.agent_activity:{agent_id}",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == ctx.tenant.id,
        )
    )
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    safe_lookback = max(1, min(24 * 180, int(lookback_hours or 24 * 30)))
    safe_limit = max(1, min(200, int(limit or 30)))
    started_at = datetime.now(timezone.utc) - timedelta(hours=safe_lookback)

    rows = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.agent_id == agent_id,
            RuntimeEvent.created_at >= started_at,
        )
        .order_by(desc(RuntimeEvent.created_at))
        .limit(safe_limit)
    ).all()

    tools_used: set[str] = set()
    last_actions: list[AgentActivityActionResponse] = []
    for row in rows:
        metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
        decision = str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower() or "unknown"
        app = (
            str(row.app_id or "").strip()
            or str(metadata.get("domain") or "").strip()
            or str(metadata.get("destination_domain") or "").strip()
            or None
        )
        tool_name = str(metadata.get("tool_name") or "").strip() or None
        if tool_name:
            tools_used.add(tool_name)
        elif app:
            tools_used.add(app)
        last_actions.append(
            AgentActivityActionResponse(
                event_id=row.event_id,
                event_type=row.event_type,
                decision=decision,
                application=app,
                tool_name=tool_name,
                machine_id=(
                    str(metadata.get("machine_id") or "").strip()
                    or str(metadata.get("endpoint_id") or "").strip()
                    or str(metadata.get("host_id") or "").strip()
                    or None
                ),
                created_at=row.created_at,
                risk_score=float(row.risk_score or 0.0),
            )
        )

    anomaly_rows = db.scalars(
        select(MonitoringSignal).where(
            MonitoringSignal.tenant_id == ctx.tenant.id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= started_at,
        )
    ).all()
    anomaly_count = 0
    for row in anomaly_rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        payload_agent = str(payload.get("agent_id") or "").strip()
        if payload_agent and payload_agent == agent_id:
            anomaly_count += 1
            continue
        related_entities = payload.get("related_entities") or []
        for item in related_entities:
            if not isinstance(item, dict):
                continue
            if str(item.get("type") or "").strip().lower() != "agent":
                continue
            if str(item.get("id") or "").strip() == agent_id:
                anomaly_count += 1
                break

    return AgentActivityResponse(
        agent_id=agent_id,
        last_actions=last_actions,
        tools_used=sorted(tools_used),
        anomaly_flag=anomaly_count > 0,
        anomaly_count=anomaly_count,
    )


@router.get("/users", response_model=ListEnvelope[dict[str, Any]])
def list_ai_iam_users_registry(
    q: str | None = None,
    page: int = 1,
    page_size: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id="ai_iam.list_users",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    payload = list_user_registry(
        db,
        tenant_id=ctx.tenant.id,
        q=q,
        page=page,
        page_size=page_size,
    )
    return ListEnvelope[dict[str, Any]](
        items=list(payload.get("items") or []),
        total=int(payload.get("total") or 0),
        page=int(payload.get("page") or page),
        page_size=int(payload.get("page_size") or page_size),
    )


@router.get("/users/{user_id}", response_model=UserRegistryDetailResponse)
def get_ai_iam_user_registry(
    user_id: str,
    action_limit: int = 20,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"ai_iam.get_user:{user_id}",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    payload = get_user_registry_entry(
        db,
        tenant_id=ctx.tenant.id,
        user_id=user_id,
        action_limit=action_limit,
    )
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return UserRegistryDetailResponse.model_validate(payload)


@router.post("/purpose-sessions", response_model=PurposeSessionResponse, status_code=status.HTTP_201_CREATED)
def create_purpose_session(
    payload: PurposeSessionCreateRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
):
    if ctx.user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authenticated user required")
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id="ai_iam.create_purpose_session",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    approved_scope = dict(payload.approved_scope or {})
    identity_type = str(approved_scope.get("identity_type") or "").strip().lower()
    identity_id = str(approved_scope.get("identity_id") or "").strip()
    if identity_type == "agent":
        agent = db.scalar(
            select(AgentIdentity).where(
                AgentIdentity.id == identity_id,
                AgentIdentity.tenant_id == ctx.tenant.id,
            )
        )
        if agent is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
        if agent.status != "active":
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Agent must be active")
    elif identity_type:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Unsupported purpose identity_type")

    expires_at = datetime.now(timezone.utc) + timedelta(minutes=payload.expires_minutes)
    row = BusinessPurposeSession(
        tenant_id=ctx.tenant.id,
        user_id=ctx.user.id,
        declared_purpose=payload.declared_purpose,
        purpose_category=str(payload.purpose_category or "unknown").strip()[:64] or "unknown",
        business_function=str(payload.business_function or "unknown").strip()[:64] or "unknown",
        approved_scope=approved_scope,
        expires_at=expires_at,
        status="active",
    )
    db.add(row)
    db.flush()
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id,
        actor_type="human",
        action="ai_iam.purpose_session.create",
        resource_type="business_purpose_session",
        resource_id=row.id,
        payload={
            "purpose_category": row.purpose_category,
            "business_function": row.business_function,
            "identity_type": identity_type or None,
            "identity_id": identity_id or None,
            "expires_at": expires_at.isoformat(),
        },
    )
    db.commit()
    db.refresh(row)
    return PurposeSessionResponse.model_validate(row)


@router.get("/identities", response_model=ListEnvelope[AgentIdentityProfileResponse])
def list_identities(
    page: int = 1,
    page_size: int = 25,
    q: str | None = None,
    lookback_hours: int = 24 * 30,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id="ai_iam.list_identities",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    safe_fetch_limit = max(50, min(500, max(1, page) * max(1, page_size)))
    profiles = list_agent_identity_profiles(
        db,
        tenant_id=ctx.tenant.id,
        q=q,
        limit=safe_fetch_limit,
        lookback_hours=lookback_hours,
    )
    dto_rows = [AgentIdentityProfileResponse.model_validate(row) for row in profiles]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[AgentIdentityProfileResponse](
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/identities/{identity_id}", response_model=AgentIdentityProfileResponse)
def get_identity(
    identity_id: str,
    lookback_hours: int = 24 * 30,
    include_graph_details: bool = True,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"ai_iam.get_identity:{identity_id}",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    try:
        profile = get_agent_identity_profile(
            db,
            tenant_id=ctx.tenant.id,
            identity_id=identity_id,
            lookback_hours=lookback_hours,
            include_graph_details=include_graph_details,
        )
    except ValueError as exc:
        detail = str(exc)
        if "not found" in detail.lower():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail) from exc
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=detail) from exc
    return AgentIdentityProfileResponse.model_validate(profile)


@router.post("/agents", response_model=AgentIdentityResponse)
def create_agent(
    payload: AgentCreate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id="ai_iam.create_agent",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    row = AgentIdentity(
        tenant_id=ctx.tenant.id,
        name=payload.name,
        description=payload.description,
        max_chain_depth=payload.max_chain_depth,
        capability_inheritance=payload.capability_inheritance,
        action_scope=list(payload.action_scope or []),
        tool_registry=list(payload.tool_registry or []),
        external_system_access=list(payload.external_system_access or []),
        agent_type=str(payload.agent_type or "workflow_agent").strip() or "workflow_agent",
        autonomy_level=str(payload.autonomy_level or "medium").strip() or "medium",
        status="active",
    )
    db.add(row)
    db.flush()

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_iam.agent.create",
        resource_type="agent_identity",
        resource_id=row.id,
        payload={
            "name": row.name,
            "owner_attestation_expiry": row.owner_attestation_expiry.isoformat() if row.owner_attestation_expiry else None,
            "max_chain_depth": row.max_chain_depth,
            "capability_inheritance": row.capability_inheritance,
            "action_scope": row.action_scope,
            "tool_registry": row.tool_registry,
            "external_system_access": row.external_system_access,
            "agent_type": row.agent_type,
            "autonomy_level": row.autonomy_level,
        },
    )

    db.commit()
    db.refresh(row)
    return AgentIdentityResponse.model_validate(row)


@router.patch("/agents/{agent_id}", response_model=AgentIdentityResponse)
def update_agent(
    agent_id: str,
    payload: AgentUpdate,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"ai_iam.update_agent:{agent_id}",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    row = db.scalar(select(AgentIdentity).where(AgentIdentity.id == agent_id, AgentIdentity.tenant_id == ctx.tenant.id))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    for field in [
        "name",
        "description",
        "status",
        "max_chain_depth",
        "capability_inheritance",
        "action_scope",
        "tool_registry",
        "external_system_access",
        "agent_type",
        "autonomy_level",
    ]:
        value = getattr(payload, field)
        if value is not None:
            setattr(row, field, value)

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_iam.agent.update",
        resource_type="agent_identity",
        resource_id=row.id,
        # Audit JSON must remain serializable when an attestation update carries
        # timezone-aware timestamps.
        payload=payload.model_dump(mode="json", exclude_none=True),
    )

    db.commit()
    db.refresh(row)
    return AgentIdentityResponse.model_validate(row)


@router.post("/agents/{agent_id}/owner-attestation/refresh", response_model=AgentIdentityResponse)
def refresh_owner_attestation(
    agent_id: str,
    payload: OwnerAttestationRefreshRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"ai_iam.refresh_owner_attestation:{agent_id}",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="tenant_registry",
    )
    row = db.scalar(select(AgentIdentity).where(AgentIdentity.id == agent_id, AgentIdentity.tenant_id == ctx.tenant.id))
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    attested_at = datetime.now(timezone.utc)
    expires_at = attested_at + timedelta(minutes=payload.expires_minutes)
    row.owner_attested_at = attested_at
    row.owner_attestation_expiry = expires_at
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user is not None else None,
        actor_type="human",
        action="ai_iam.agent.owner_attestation.refresh",
        resource_type="agent_identity",
        resource_id=row.id,
        payload={
            "expires_minutes": payload.expires_minutes,
            "owner_attested_at": attested_at.isoformat(),
            "owner_attestation_expiry": expires_at.isoformat(),
        },
    )
    db.commit()
    db.refresh(row)
    return AgentIdentityResponse.model_validate(row)


@router.post("/agents/{agent_id}/tokens", response_model=MintTokenResponse)
def mint_token(
    agent_id: str,
    payload: MintTokenRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = None,
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        ai_system_id=payload.ai_system_id,
        request_id=f"ai_iam.mint_token:{agent_id}",
    )
    agent = db.scalar(select(AgentIdentity).where(AgentIdentity.id == agent_id, AgentIdentity.tenant_id == ctx.tenant.id))
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == payload.ai_system_id,
            AISystem.tenant_id == ctx.tenant.id,
        )
    )
    if not ai_system:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")

    approved_request_id: str | None = None
    if jit_token_mint_requires_approval(ai_system.risk_tier):
        if not payload.approval_request_id:
            _raise_jit_approval_required(
                tenant_id=ctx.tenant.id,
                ai_system_id=ai_system.id,
                agent_id=agent.id,
                scopes=payload.scopes,
                chain_depth=payload.chain_depth,
                expires_minutes=payload.expires_minutes,
                db=db,
            )
        approved_request_id = payload.approval_request_id

    raw_token = secrets.token_urlsafe(32)
    try:
        row, approved_request_id = mint_capability_token_with_authority(
            db,
            tenant_id=ctx.tenant.id,
            ai_system=ai_system,
            agent_identity_id=agent.id,
            raw_token=raw_token,
            scopes=payload.scopes,
            expires_minutes=payload.expires_minutes,
            chain_depth=payload.chain_depth,
            issued_by_user_id=None,
            approval_request_id=approved_request_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_iam.token.mint",
        resource_type="capability_token",
        resource_id=row.id,
        payload={
            "ai_system_id": ai_system.id,
            "agent_id": agent.id,
            "scopes": payload.scopes,
            "approval_request_id": approved_request_id,
        },
    )

    db.commit()
    if background_tasks is not None:
        background_tasks.add_task(
            _project_token_mint_runtime_event,
            tenant_id=ctx.tenant.id,
            token_id=row.id,
            agent_id=agent.id,
            ai_system_id=ai_system.id,
            scopes=list(row.scopes or []),
            chain_depth=row.chain_depth,
            approval_request_id=approved_request_id,
            correlation_id=get_correlation_id(),
            bind=db.get_bind(),
        )
    return MintTokenResponse(
        token_id=row.id,
        capability_token=raw_token,
        scopes=row.scopes,
        expires_at=row.expires_at,
        approval_request_id=approved_request_id,
    )


@router.post("/delegate", response_model=DelegateTokenResponse)
def delegate_token(
    payload: DelegateTokenRequest,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        ai_system_id=payload.ai_system_id,
        request_id=f"ai_iam.delegate:{payload.parent_agent_id}:{payload.child_agent_id}",
    )

    parent_agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == payload.parent_agent_id,
            AgentIdentity.tenant_id == ctx.tenant.id,
        )
    )
    if not parent_agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent agent not found")

    child_agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == payload.child_agent_id,
            AgentIdentity.tenant_id == ctx.tenant.id,
        )
    )
    if not child_agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Child agent not found")

    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == payload.ai_system_id,
            AISystem.tenant_id == ctx.tenant.id,
        )
    )
    if not ai_system:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="AI system not found")

    requested_scopes = sorted({str(scope).strip() for scope in payload.action_scope if str(scope).strip()})
    if not requested_scopes:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="action_scope must contain at least one scope")

    parent_token_row: CapabilityToken | None = None
    for scope in requested_scopes:
        allowed, reason, token_row, token_agent, _effective_scopes = validate_capability_token(
            db,
            tenant_id=ctx.tenant.id,
            raw_token=payload.parent_capability_token,
            required_scope=scope,
            chain_depth=max(1, int(payload.parent_chain_depth)),
        )
        if not allowed or token_row is None or token_agent is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Delegation denied: {reason}")
        if token_agent.id != parent_agent.id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Parent token does not belong to parent_agent_id")
        if token_row.ai_system_id is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Delegation denied: token_system_unbound")
        if token_row.ai_system_id != payload.ai_system_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Delegation denied: token_system_mismatch")
        parent_token_row = token_row

    base_chain_depth = int(parent_token_row.chain_depth if parent_token_row is not None else max(1, int(payload.parent_chain_depth)))
    delegated_chain_depth = (
        int(payload.chain_depth)
        if payload.chain_depth is not None
        else min(base_chain_depth + 1, int(child_agent.max_chain_depth))
    )
    if delegated_chain_depth < 1:
        delegated_chain_depth = 1
    if delegated_chain_depth > int(child_agent.max_chain_depth):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Delegated chain depth exceeds child agent max_chain_depth",
        )
    if delegated_chain_depth > (base_chain_depth + 1):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Delegated chain depth exceeds parent delegation allowance",
        )

    raw_child_token = secrets.token_urlsafe(32)
    child_token = mint_capability_token(
        db,
        tenant_id=ctx.tenant.id,
        ai_system_id=payload.ai_system_id,
        agent_identity_id=child_agent.id,
        raw_token=raw_child_token,
        scopes=requested_scopes,
        expires_minutes=int(payload.expires_minutes),
        chain_depth=delegated_chain_depth,
        issued_by_user_id=None,
    )
    delegation = create_agent_delegation(
        db,
        tenant_id=ctx.tenant.id,
        parent_agent_identity_id=parent_agent.id,
        child_agent_identity_id=child_agent.id,
        parent_token_id=(parent_token_row.id if parent_token_row is not None else ""),
        child_token_id=child_token.id,
        ai_system_id=payload.ai_system_id,
        action_scope=requested_scopes,
        chain_depth=delegated_chain_depth,
        metadata=payload.metadata,
    )

    delegation_node = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="agent_delegation",
        signal_type="ai_iam.delegate",
        label=f"Delegation {parent_agent.id} -> {child_agent.id}",
        payload={
            "delegation_id": delegation.id,
            "parent_agent_id": parent_agent.id,
            "child_agent_id": child_agent.id,
            "parent_token_id": parent_token_row.id if parent_token_row is not None else None,
            "child_token_id": child_token.id,
            "ai_system_id": payload.ai_system_id,
            "action_scope": requested_scopes,
            "chain_depth": delegated_chain_depth,
        },
        correlation_id=get_correlation_id(),
    )

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_iam.delegate.create",
        resource_type="agent_delegation",
        resource_id=delegation.id,
        payload={
            "parent_agent_id": parent_agent.id,
            "child_agent_id": child_agent.id,
            "ai_system_id": payload.ai_system_id,
            "action_scope": requested_scopes,
            "chain_depth": delegated_chain_depth,
            "evidence_node_id": delegation_node.id,
        },
    )

    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_ai_iam_event

        ingest_from_ai_iam_event(
            db,
            tenant_id=ctx.tenant.id,
            event_type="aiiam.delegate",
            ai_system_id=payload.ai_system_id,
            user_id=None,
            agent_id=child_agent.id,
            severity="med",
            evidence_node_ids=[delegation_node.id],
            correlation_id=get_correlation_id(),
            metadata={
                "action": "delegate",
                "parent_agent_id": parent_agent.id,
                "child_agent_id": child_agent.id,
                "action_scope": requested_scopes,
                "chain_depth": delegated_chain_depth,
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="ai_iam_router",
            tenant_id=ctx.tenant.id,
            event_type="aiiam.delegate",
            error=str(exc),
        )

    db.commit()
    return DelegateTokenResponse(
        delegation_id=delegation.id,
        token_id=child_token.id,
        capability_token=raw_child_token,
        scopes=child_token.scopes,
        expires_at=child_token.expires_at,
        parent_agent_id=parent_agent.id,
        child_agent_id=child_agent.id,
    )


@router.post("/tokens/{token_id}/revoke", response_model=RevokeTokenResponse)
def revoke_token(
    token_id: str,
    background_tasks: BackgroundTasks,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"ai_iam.revoke_token:{token_id}",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="containment",
    )
    row = revoke_capability_token(db, tenant_id=ctx.tenant.id, token_id=token_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_iam.token.revoke",
        resource_type="capability_token",
        resource_id=row.id,
        payload={},
    )
    # Revocation is an availability-critical authority boundary.  Its immutable
    # audit record is committed with the revoked token before any optional
    # Runtime Intelligence projection can run elsewhere.
    db.commit()
    background_tasks.add_task(
        _project_token_revocation_runtime_event,
        tenant_id=ctx.tenant.id,
        token_id=row.id,
        agent_id=row.agent_identity_id,
        ai_system_id=row.ai_system_id,
        scopes=list(row.scopes or []),
        correlation_id=get_correlation_id(),
        bind=db.get_bind(),
    )
    return RevokeTokenResponse(status="revoked", token_id=token_id)


@router.post("/agents/{agent_id}/kill-switch", response_model=KillSwitchResponse)
def kill_switch_agent(
    agent_id: str,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
):
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="ai_iam",
        request_id=f"ai_iam.kill_switch:{agent_id}",
        # Not an action of one AI system (fail_secure_service.NO_AI_SYSTEM_CONTEXT_REASONS).
        no_ai_system_context_reason="containment",
    )
    agent = db.scalar(select(AgentIdentity).where(AgentIdentity.id == agent_id, AgentIdentity.tenant_id == ctx.tenant.id))
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")

    descendant_agent_ids = collect_delegation_descendant_agent_ids(
        db,
        tenant_id=ctx.tenant.id,
        root_agent_identity_id=agent.id,
    )
    impacted_agent_ids = sorted({agent.id, *descendant_agent_ids})
    impacted_agents = db.scalars(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == ctx.tenant.id,
            AgentIdentity.id.in_(impacted_agent_ids),
        )
    ).all()
    for impacted_agent in impacted_agents:
        impacted_agent.status = "isolated"

    now = datetime.now(timezone.utc)
    tokens = db.scalars(
        select(CapabilityToken).where(
            CapabilityToken.tenant_id == ctx.tenant.id,
            CapabilityToken.agent_identity_id.in_(impacted_agent_ids),
        )
    ).all()

    revoked_count = 0
    token_ids: list[str] = []
    for token in tokens:
        token_ids.append(token.id)
        if token.revoked_at is None:
            token.revoked_at = now
            revoked_count += 1

    delegations_revoked = revoke_agent_delegations(
        db,
        tenant_id=ctx.tenant.id,
        impacted_agent_identity_ids=impacted_agent_ids,
        revoked_at=now,
    )

    kill_node = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="kill_switch",
        signal_type="ai_iam.kill_switch",
        label=f"Agent {agent.id} isolated by kill switch",
        payload={
            "agent_id": agent.id,
            "status": "isolated",
            "revoked_tokens_count": revoked_count,
            "total_tokens": len(tokens),
            "impacted_agent_ids": impacted_agent_ids,
            "descendant_agent_ids": descendant_agent_ids,
            "delegations_revoked": delegations_revoked,
        },
    )
    token_node = create_evidence_node(
        db,
        tenant_id=ctx.tenant.id,
        node_type="token_revocation",
        signal_type="ai_iam.tokens.revoked",
        label=f"Tokens revoked for agent {agent.id}",
        payload={
            "agent_id": agent.id,
            "token_ids": token_ids,
            "revoked_count": revoked_count,
            "impacted_agent_ids": impacted_agent_ids,
        },
    )
    edge = link_evidence_nodes(
        db,
        tenant_id=ctx.tenant.id,
        from_node_id=kill_node.id,
        to_node_id=token_node.id,
        edge_type="generated",
        payload={"agent_id": agent.id},
    )
    evidence_node_ids = [kill_node.id, token_node.id]
    evidence_edges = [
        {
            "id": edge.id,
            "from_node_id": edge.from_node_id,
            "to_node_id": edge.to_node_id,
            "edge_type": edge.edge_type,
        }
    ]

    evidence_nodes = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == ctx.tenant.id,
            EvidenceNode.id.in_(evidence_node_ids),
        )
    ).all()
    evidence_node_payloads: list[dict[str, Any]] = [
        {
            "id": node.id,
            "node_type": node.node_type,
            "signal_type": node.signal_type,
            "label": node.label,
        }
        for node in evidence_nodes
    ]

    linked_edges = db.scalars(
        select(EvidenceEdge).where(
            EvidenceEdge.tenant_id == ctx.tenant.id,
            EvidenceEdge.from_node_id.in_(evidence_node_ids),
            EvidenceEdge.to_node_id.in_(evidence_node_ids),
        )
    ).all()
    if linked_edges:
        evidence_edges = [
            {
                "id": linked.id,
                "from_node_id": linked.from_node_id,
                "to_node_id": linked.to_node_id,
                "edge_type": linked.edge_type,
            }
            for linked in linked_edges
        ]

    snap = create_auditor_snapshot(
        db,
        tenant_id=ctx.tenant.id,
        ai_system_id=None,
        trigger_type="kill_switch",
        payload={
            "agent_id": agent.id,
            "status": "isolated",
            "revoked_tokens": revoked_count,
            "token_ids": token_ids,
            "impacted_agent_ids": impacted_agent_ids,
            "descendant_agent_ids": descendant_agent_ids,
            "delegations_revoked": delegations_revoked,
            "evidence_graph": {
                "nodes": evidence_node_payloads,
                "edges": evidence_edges,
            },
        },
        actor_user_id=None,
    )

    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=None,
        actor_type="human",
        action="ai_iam.kill_switch",
        resource_type="agent_identity",
        resource_id=agent.id,
        payload={
            "status": "isolated",
            "revoked_tokens": revoked_count,
            "impacted_agent_ids": impacted_agent_ids,
            "descendant_agent_ids": descendant_agent_ids,
            "delegations_revoked": delegations_revoked,
            "snapshot_id": snap.id,
            "evidence_node_ids": evidence_node_ids,
        },
    )

    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_ai_iam_event

        ingest_from_ai_iam_event(
            db,
            tenant_id=ctx.tenant.id,
            event_type="aiiam.kill_switch",
            ai_system_id=None,
            user_id=None,
            agent_id=agent.id,
            severity="high",
            evidence_node_ids=evidence_node_ids,
            correlation_id=get_correlation_id(),
            metadata={
                "action": "kill_switch",
                "revoked_tokens": revoked_count,
                "impacted_agent_ids": impacted_agent_ids,
                "descendant_agent_ids": descendant_agent_ids,
                "delegations_revoked": delegations_revoked,
                "snapshot_id": snap.id,
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="ai_iam_router",
            tenant_id=ctx.tenant.id,
            event_type="aiiam.kill_switch",
            error=str(exc),
        )

    db.commit()
    return KillSwitchResponse(
        status="isolated",
        agent_id=agent.id,
        revoked_tokens=revoked_count,
        snapshot_id=snap.id,
        evidence_node_ids=evidence_node_ids,
    )


@router.post("/agents/{agent_id}/disable", response_model=KillSwitchResponse)
def disable_agent(
    agent_id: str,
    ctx: TenantContext = Depends(require_role(allow_list=["owner", "admin"])),
    db: Session = Depends(get_db),
):
    return kill_switch_agent(agent_id=agent_id, ctx=ctx, db=db)


@router.post("/identity/jit/evaluate")
def evaluate_agentic_jit_grant(
    payload: JITGrantEvaluateRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    return evaluate_jit_grant(
        db,
        tenant_id=ctx.tenant.id,
        chain_id=payload.chain_id,
        agent_id=payload.agent_id,
        requested_scope=payload.requested_scope,
        approved_scope=payload.approved_scope,
        approved_task=payload.approved_task,
        actual_action=payload.actual_action,
        identity_provider=payload.identity_provider,
        grant_type=payload.grant_type,
        expires_at=payload.expires_at,
    )


@router.get("/agents/{agent_id}/touchpoints")
def get_agent_touchpoints(
    agent_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return agent_touchpoints(db, tenant_id=ctx.tenant.id, agent_id=agent_id)


@router.get("/agents/{agent_id}/blast-radius")
def get_agent_blast_radius(
    agent_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return agent_blast_radius(db, tenant_id=ctx.tenant.id, agent_id=agent_id)
