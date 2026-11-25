from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.user import User
from app.db.session import get_db
from app.services.runtime_control_agent_action_service import evaluate_agent_action_and_record
from app.services.runtime_control_data_transfer_service import (
    evaluate_data_transfer_and_record,
    submit_data_transfer_justification_and_record,
)


router = APIRouter(prefix="/runtime-control", tags=["runtime-control"])


class CopyContextRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_url: str | None = None
    source_domain: str | None = None
    source_app_name: str | None = None
    source_surface_type: str = "unknown"
    source_classification_hint: str = "unknown"
    copied_text_hash: str
    copied_text_preview_redacted: str | None = None
    timestamp: datetime | None = None


class PasteContextRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    destination_url: str | None = None
    destination_domain: str | None = None
    destination_app_name: str | None = None
    destination_surface_type: str = "unknown"
    destination_input_context: str = "unknown"
    timestamp: datetime | None = None


class DataTransferCheckRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    correlation_id: str | None = None
    tenant_id: str | None = None
    copy_context: CopyContextRequest
    paste_context: PasteContextRequest
    policy_version: str | None = None
    platform_mode: Literal["discovery", "enforce"] | None = None
    browser: str | None = None
    browser_version: str | None = None
    browser_profile: str | None = None
    extension_name: str | None = None
    extension_version: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    ip_address: str | None = None
    location: str | None = None
    prompt_storage_mode: str | None = None
    submitter_name: str | None = None
    submitter_email: str | None = None
    submitter_role: str | None = None
    submitter_department: str | None = None
    actor_role: str | None = None
    actor_department: str | None = None
    user_email: str | None = None


class PolicyDecisionPayload(BaseModel):
    model_config = ConfigDict(extra="allow")

    decision: str
    reason_code: str | None = None
    policy_version: str | None = None
    platform_mode: Literal["discovery", "enforce"] | None = None


class DataTransferJustifyRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    correlation_id: str | None = None
    tenant_id: str | None = None
    justification: str
    copy_context: CopyContextRequest
    paste_context: PasteContextRequest
    policy_decision: PolicyDecisionPayload
    policy_version: str | None = None
    platform_mode: Literal["discovery", "enforce"] | None = None
    browser: str | None = None
    browser_version: str | None = None
    browser_profile: str | None = None
    extension_name: str | None = None
    extension_version: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    ip_address: str | None = None
    location: str | None = None
    prompt_storage_mode: str | None = None
    submitter_name: str | None = None
    submitter_email: str | None = None
    submitter_role: str | None = None
    submitter_department: str | None = None
    actor_role: str | None = None
    actor_department: str | None = None
    user_email: str | None = None


class DataTransferDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "warn", "block", "require_justification"]
    reason_code: str
    explanation: str
    recommended_action: str
    justification_required: bool
    audit_log_id: str
    evidence_node_id: str
    finding_id: str | None = None
    runtime_event_id: str | None = None
    policy_version: str
    platform_mode: str
    destination_ai_system_id: str | None = None
    policy_snapshot: dict[str, Any] = Field(default_factory=dict)
    decision_explanation: dict[str, Any] = Field(default_factory=dict)
    evidence_bundle: dict[str, Any] = Field(default_factory=dict)


class DataTransferJustifyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "block"]
    reason_code: str
    explanation: str
    recommended_action: str
    audit_log_id: str
    evidence_node_id: str
    finding_id: str | None = None
    runtime_event_id: str | None = None
    policy_version: str
    platform_mode: str
    destination_ai_system_id: str | None = None
    destination_app_name: str | None = None
    policy_snapshot: dict[str, Any] = Field(default_factory=dict)
    decision_explanation: dict[str, Any] = Field(default_factory=dict)
    evidence_bundle: dict[str, Any] = Field(default_factory=dict)


class AgentActionInterceptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: str | None = None
    tenant_id: str | None = None
    ai_system_id: str | None = None
    agent_id: str
    capability_token: str
    action_type: Literal["api_call", "email_send", "db_query", "tool_execution"]
    tool_name: str | None = None
    target_resource: str | None = None
    input_context: dict[str, Any] = Field(default_factory=dict)
    chain_depth: int = 1
    chain_id: str | None = None
    parent_action_id: str | None = None
    parent_agent_id: str | None = None
    policy_version: str | None = None
    platform_mode: Literal["discovery", "enforce"] | None = None


class AgentActionInterceptResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["allow", "warn", "block", "require_approval"]
    reason_code: str
    explanation: str
    recommended_action: str
    approval_required: bool
    audit_log_id: str
    evidence_node_id: str
    finding_id: str | None = None
    runtime_event_id: str | None = None
    chain_id: str | None = None
    policy_version: str
    platform_mode: str
    ai_system_id: str | None = None
    agent_id: str
    token_id: str | None = None
    identity_risk_score: float | None = None
    identity_risk_level: str | None = None
    identity_risk_reasoning: list[str] = Field(default_factory=list)
    identity_blast_radius_score: float | None = None
    identity_crq: dict[str, Any] = Field(default_factory=dict)
    identity_risk_components: dict[str, Any] = Field(default_factory=dict)
    pre_action_governance_check: dict[str, Any] = Field(default_factory=dict)
    control_mode: str | None = None
    decision_badge: str | None = None
    at: str


@router.post("/data-transfer-check", response_model=DataTransferDecisionResponse)
def data_transfer_check(
    request: Request,
    payload: DataTransferCheckRequest,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        result = evaluate_data_transfer_and_record(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            actor_user_email=current_user.email,
            payload=data,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    return DataTransferDecisionResponse.model_validate(result)


@router.post("/data-transfer-justify", response_model=DataTransferJustifyResponse)
def data_transfer_justify(
    request: Request,
    payload: DataTransferJustifyRequest,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        result = submit_data_transfer_justification_and_record(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            payload=data,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    return DataTransferJustifyResponse.model_validate(result)


@router.post("/agent-action-intercept", response_model=AgentActionInterceptResponse)
def agent_action_intercept(
    request: Request,
    payload: AgentActionInterceptRequest,
    ctx: TenantContext = Depends(require_permission("activity.operate")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        result = evaluate_agent_action_and_record(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            payload=data,
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    db.commit()
    return AgentActionInterceptResponse.model_validate(result)
