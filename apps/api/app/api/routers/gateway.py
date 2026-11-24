from __future__ import annotations

import math
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.deps_control_plane import require_control_plane_healthy
from app.core.deps_governance import governance_payload_dependency
from app.core.observability import log_structured
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import SessionLocal, get_db
from app.services.gateway_service import get_guardian_enforcement_matrix, llm_intercept, mcp_authorize
from app.services.agentic_action_integrity_service import scan_mcp_tool
from app.services.instruction_tool_provenance import InstructionToolProvenanceService
from app.services.rate_limit_service import tenant_rate_limiter
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.fail_secure_service import enforce_fail_secure_or_raise
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError
from app.services.mcp_session_service import (
    MCPSessionAuthorityError,
    get_owned_mcp_session,
    open_mcp_session,
    serialize_mcp_session,
    transition_mcp_session,
)
from app.services.mcp_tool_approval_service import (
    MCPToolFingerprintConflictError,
    MCPToolFingerprintNotFoundError,
    decide_mcp_tool_fingerprint,
    list_mcp_tool_fingerprints,
)


router = APIRouter(
    prefix="/gateway",
    tags=["gateway"],
    dependencies=[Depends(require_control_plane_healthy(module="gateway"))],
)


class LLMInterceptRequest(BaseModel):
    ai_system_id: str
    actor_type: str
    actor_id: str
    request_id: str | None = None
    prompt: str
    context_summary: str = ""
    attachments_meta: list[dict] = Field(default_factory=list)
    tool_output: str | None = None
    response_text: str | None = None
    provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    tool_name: str | None = None
    tool_category: str | None = None
    api_endpoint: str | None = None
    data_source: str | None = None
    tool_usage_meta: dict | list[dict] | None = None
    context_id: str | None = None
    chain_id: str | None = None
    chain_depth: int | None = None
    parent_action_id: str | None = None
    parent_agent_id: str | None = None


class MCPAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_system_id: str
    actor_id: str
    capability_token: str
    action: str
    resource: str
    chain_depth: int = 0
    request_id: str | None = None
    provider: str | None = None
    model: str | None = None
    model_version: str | None = None
    tool_name: str | None = None
    tool_category: str | None = None
    api_endpoint: str | None = None
    data_source: str | None = None
    tool_usage_meta: dict | list[dict] | None = None
    context_id: str | None = None
    chain_id: str | None = None
    parent_action_id: str | None = None
    parent_agent_id: str | None = None
    session_id: str | None = None
    initiating_user_id: str | None = None
    session_context: dict[str, Any] | None = None
    dynamic_permission: dict[str, Any] | None = None


class MCPToolMetadataBundle(BaseModel):
    """Material metadata that must be scanned and signed as one tool bundle."""

    model_config = ConfigDict(extra="forbid")

    instructions: list[str] = Field(default_factory=list, max_length=64)
    capabilities: list[str] = Field(default_factory=list, max_length=64)
    resource_declarations: list[str] = Field(default_factory=list, max_length=64)
    target_declarations: list[str] = Field(default_factory=list, max_length=64)
    destination_declarations: list[str] = Field(default_factory=list, max_length=64)


class MCPToolScanRequest(BaseModel):
    mcp_server_id: str
    tool_name: str
    tool_version: str = "unknown"
    description: str = ""
    tool_schema: dict[str, Any] = Field(default_factory=dict, alias="schema")
    examples: list[Any] = Field(default_factory=list)
    manifest: dict[str, Any] | None = None
    metadata_bundle: MCPToolMetadataBundle = Field(default_factory=MCPToolMetadataBundle)
    chain_id: str | None = None
    request_id: str | None = None
    principal: dict[str, Any] | None = None
    principal_assertion: dict[str, Any] | None = None
    lifecycle_version: str = "unknown"


class MCPToolFingerprintDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "block", "under_review"]
    expected_manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    reason: str = Field(min_length=1, max_length=512)
    tool_binding_id: str | None = None
    expected_binding_version: int | None = Field(default=None, ge=1)


class MCPToolRemovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=512)


class MCPSessionOpenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ai_system_id: str
    agent_id: str
    capability_token: str
    expires_minutes: int = Field(default=30, ge=1, le=1440)
    session_context: dict[str, Any] = Field(default_factory=dict)


def _write_best_effort_audit(
    db: Session,
    *,
    tenant_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    payload: dict,
) -> str | None:
    try:
        audit = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            payload=payload,
        )
        db.commit()
        return audit.id
    except SQLAlchemyError:
        db.rollback()

    try:
        with SessionLocal() as fallback_db:
            audit = write_audit_log(
                fallback_db,
                tenant_id=tenant_id,
                actor_user_id=None,
                actor_type="system",
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                payload=payload,
            )
            fallback_db.commit()
            return audit.id
    except SQLAlchemyError:
        return None


def _enforce_rate_limit_or_raise(
    *,
    db: Session,
    tenant_id: str,
    route_key: str,
    qps_limit: int,
    window_seconds: float,
    request_id: str,
    resource_id: str,
) -> None:
    allowed, retry_after_seconds = tenant_rate_limiter.check_and_consume(
        route_key=route_key,
        tenant_id=tenant_id,
        qps_limit=qps_limit,
        window_seconds=window_seconds,
    )
    if allowed:
        return

    audit_id = _write_best_effort_audit(
        db,
        tenant_id=tenant_id,
        action=f"{route_key}.rate_limited",
        resource_type="ai_system",
        resource_id=resource_id,
        payload={
            "request_id": request_id,
            "retry_after_seconds": retry_after_seconds,
            "qps_limit": qps_limit,
            "window_seconds": window_seconds,
        },
    )
    raise HTTPException(
        status_code=429,
        detail={
            "code": "rate_limited",
            "message": "Per-tenant rate limit exceeded.",
            "request_id": request_id,
            "retry_after_seconds": retry_after_seconds,
            "final_decision": "block",
            "audit_log_id": audit_id,
        },
        headers={"Retry-After": str(max(1, math.ceil(retry_after_seconds)))},
    )


def _write_best_effort_evidence(
    db: Session,
    *,
    tenant_id: str,
    signal_type: str,
    label: str,
    payload: dict,
    correlation_id: str | None,
) -> str | None:
    try:
        node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="gateway_fail_closed",
            signal_type=signal_type,
            label=label,
            payload=payload,
            correlation_id=correlation_id,
        )
        db.commit()
        return node.id
    except SQLAlchemyError:
        db.rollback()

    try:
        with SessionLocal() as fallback_db:
            node = create_evidence_node(
                fallback_db,
                tenant_id=tenant_id,
                node_type="gateway_fail_closed",
                signal_type=signal_type,
                label=label,
                payload=payload,
                correlation_id=correlation_id,
            )
            fallback_db.commit()
            return node.id
    except SQLAlchemyError:
        return None


def _raise_fail_closed(
    *,
    db: Session,
    tenant_id: str,
    request_id: str,
    resource_id: str,
    route_key: str,
    error: Exception,
) -> None:
    failure_payload = {
        "request_id": request_id,
        "reason": "database_unavailable",
        "error": str(error),
        "final_decision": "block",
        "route_key": route_key,
    }
    audit_id = _write_best_effort_audit(
        db,
        tenant_id=tenant_id,
        action=f"{route_key}.fail_closed",
        resource_type="ai_system",
        resource_id=resource_id,
        payload=failure_payload,
    )
    evidence_id = _write_best_effort_evidence(
        db,
        tenant_id=tenant_id,
        signal_type=f"{route_key}.fail_closed",
        label=f"Gateway fail-closed for {route_key}",
        payload=failure_payload,
        correlation_id=request_id,
    )
    log_structured(
        "gateway_fail_closed",
        route_key=route_key,
        tenant_id=tenant_id,
        request_id=request_id,
        resource_id=resource_id,
        audit_log_id=audit_id,
        evidence_node_id=evidence_id,
        error=str(error),
    )
    raise HTTPException(
        status_code=503,
        detail={
            "code": "enforcement_fail_closed",
            "message": "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
            "request_id": request_id,
            "final_decision": "block",
            "audit_log_id": audit_id,
            "evidence_node_id": evidence_id,
        },
    )


@router.get("/llm/guardian-matrix")
def guardian_enforcement_matrix(
    ai_system_id: str,
    actor_type: str = "human",
    ctx: TenantContext = Depends(require_role(min_role="auditor")),
    db: Session = Depends(get_db),
):
    try:
        return get_guardian_enforcement_matrix(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=ai_system_id,
            actor_type=actor_type,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/llm/intercept")
def gateway_llm_intercept(
    payload: LLMInterceptRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    req_id = payload.request_id or str(uuid4())
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="gateway",
        ai_system_id=payload.ai_system_id,
        request_id=req_id,
    )
    _enforce_rate_limit_or_raise(
        db=db,
        tenant_id=ctx.tenant.id,
        route_key="gateway.llm.intercept",
        qps_limit=settings.llm_intercept_qps_per_tenant,
        window_seconds=settings.rate_limit_window_seconds,
        request_id=req_id,
        resource_id=payload.ai_system_id,
    )
    try:
        result = llm_intercept(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            actor_type=payload.actor_type,
            actor_id=payload.actor_id,
            request_id=req_id,
            prompt=payload.prompt,
            context_summary=payload.context_summary,
            attachments_meta=payload.attachments_meta,
            tool_output=payload.tool_output,
            audit_actor_user_id=None,
            response_text=payload.response_text,
            provider=payload.provider,
            model_name=payload.model,
            model_version=payload.model_version,
            tool_name=payload.tool_name,
            tool_category=payload.tool_category,
            api_endpoint=payload.api_endpoint,
            data_source=payload.data_source,
            tool_usage_meta=payload.tool_usage_meta,
            context_id=payload.context_id,
            chain_id=payload.chain_id,
            chain_depth=payload.chain_depth,
            parent_action_id=payload.parent_action_id,
            parent_agent_id=payload.parent_agent_id,
        )
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        _raise_fail_closed(
            db=db,
            tenant_id=ctx.tenant.id,
            request_id=req_id,
            resource_id=payload.ai_system_id,
            route_key="gateway.llm.intercept",
            error=exc,
        )


@router.post("/mcp/sessions/open", status_code=201)
def gateway_open_mcp_session(
    payload: MCPSessionOpenRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    if ctx.user is None:
        raise HTTPException(status_code=401, detail="Authenticated user required")
    try:
        session = open_mcp_session(
            db,
            tenant_id=ctx.tenant.id,
            user_id=ctx.user.id,
            ai_system_id=payload.ai_system_id,
            agent_id=payload.agent_id,
            raw_capability_token=payload.capability_token,
            expires_minutes=payload.expires_minutes,
            session_context=payload.session_context,
        )
        db.commit()
        db.refresh(session)
        return serialize_mcp_session(session)
    except MCPSessionAuthorityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=403,
            detail={"code": "mcp_session_authority_denied", "reason_code": exc.reason},
        ) from exc
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc


def _authenticated_mcp_session_user_id(ctx: TenantContext) -> str:
    if ctx.user is None:
        raise HTTPException(status_code=401, detail="Authenticated user required")
    return ctx.user.id


def _raise_mcp_session_authority_denied(exc: MCPSessionAuthorityError) -> None:
    status_code = 404 if exc.reason == "mcp_session_not_found" else 409
    raise HTTPException(
        status_code=status_code,
        detail={"code": "mcp_session_authority_denied", "reason_code": exc.reason},
    ) from exc


@router.get("/mcp/sessions/{session_id}")
def gateway_get_mcp_session(
    session_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    try:
        session = get_owned_mcp_session(
            db,
            tenant_id=ctx.tenant.id,
            user_id=_authenticated_mcp_session_user_id(ctx),
            session_id=session_id,
        )
        return serialize_mcp_session(session)
    except MCPSessionAuthorityError as exc:
        _raise_mcp_session_authority_denied(exc)


def _transition_authenticated_mcp_session(
    *,
    session_id: str,
    transition: str,
    ctx: TenantContext,
    db: Session,
):
    try:
        session = transition_mcp_session(
            db,
            tenant_id=ctx.tenant.id,
            user_id=_authenticated_mcp_session_user_id(ctx),
            session_id=session_id,
            transition=transition,
        )
        db.commit()
        db.refresh(session)
        return serialize_mcp_session(session)
    except MCPSessionAuthorityError as exc:
        db.rollback()
        _raise_mcp_session_authority_denied(exc)


@router.post("/mcp/sessions/{session_id}/close")
def gateway_close_mcp_session(
    session_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    return _transition_authenticated_mcp_session(
        session_id=session_id,
        transition="close",
        ctx=ctx,
        db=db,
    )


@router.post("/mcp/sessions/{session_id}/revoke")
def gateway_revoke_mcp_session(
    session_id: str,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    return _transition_authenticated_mcp_session(
        session_id=session_id,
        transition="revoke",
        ctx=ctx,
        db=db,
    )


@router.post("/mcp/authorize")
def gateway_mcp_authorize(
    payload: MCPAuthorizeRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    req_id = payload.request_id or str(uuid4())
    enforce_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="gateway",
        ai_system_id=payload.ai_system_id,
        request_id=req_id,
    )
    _enforce_rate_limit_or_raise(
        db=db,
        tenant_id=ctx.tenant.id,
        route_key="gateway.mcp.authorize",
        qps_limit=settings.mcp_authorize_qps_per_tenant,
        window_seconds=settings.rate_limit_window_seconds,
        request_id=req_id,
        resource_id=payload.ai_system_id,
    )
    try:
        result = mcp_authorize(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            actor_id=payload.actor_id,
            capability_token=payload.capability_token,
            action=payload.action,
            resource=payload.resource,
            chain_depth=payload.chain_depth,
            request_id=req_id,
            audit_actor_user_id=(ctx.user.id if ctx.user is not None else None),
            provider=payload.provider,
            model_name=payload.model,
            model_version=payload.model_version,
            tool_name=payload.tool_name,
            tool_category=payload.tool_category,
            api_endpoint=payload.api_endpoint,
            data_source=payload.data_source,
            tool_usage_meta=payload.tool_usage_meta,
            context_id=payload.context_id,
            chain_id=payload.chain_id,
            parent_action_id=payload.parent_action_id,
            parent_agent_id=payload.parent_agent_id,
            session_id=payload.session_id,
            initiating_user_id=payload.initiating_user_id,
            session_context=payload.session_context,
            dynamic_permission=payload.dynamic_permission,
        )
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        _raise_fail_closed(
            db=db,
            tenant_id=ctx.tenant.id,
            request_id=req_id,
            resource_id=payload.ai_system_id,
            route_key="gateway.mcp.authorize",
            error=exc,
        )


@router.post("/mcp/tools/scan")
def gateway_mcp_tool_scan(
    payload: MCPToolScanRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    metadata_bundle = payload.metadata_bundle.model_dump()
    scan_manifest = dict(payload.manifest or {})
    # Retain the legacy manifest verbatim when the material bundle is empty so
    # existing discovery callers do not receive a synthetic drift event.  Once
    # any material declaration is supplied it is part of both the scan and the
    # exact signed principal binding.
    if any(metadata_bundle.values()):
        scan_manifest["hawk_tool_metadata_bundle"] = metadata_bundle
    result = scan_mcp_tool(
        db,
        tenant_id=ctx.tenant.id,
        mcp_server_id=payload.mcp_server_id,
        tool_name=payload.tool_name,
        tool_version=payload.tool_version,
        description=payload.description,
        schema=payload.tool_schema,
        examples=payload.examples,
        manifest=scan_manifest or None,
        chain_id=payload.chain_id,
        request_id=payload.request_id,
    )
    # Legacy scan callers remain accepted but are never promoted to the
    # repository-native execution-capable exposure boundary without proof.
    if payload.principal is not None:
        bundle = {
            "name": payload.tool_name,
            "description": payload.description,
            "schema": payload.tool_schema,
            **metadata_bundle,
            "lifecycle_version": payload.lifecycle_version,
        }
        service = InstructionToolProvenanceService(
            db,
            signing_provider=db.info.get("phase5_signing_provider"),
        )
        binding = service.register_tool(
            tenant_id=ctx.tenant.id,
            principal=payload.principal,
            bundle=bundle,
            evidence_quality="GATEWAY_MCP_SCAN",
            evidence_refs=([result["evidence_bundle_id"]] if result.get("evidence_bundle_id") else ()),
            principal_assertion=payload.principal_assertion,
        )
        db.commit()
        result["tool_binding_id"] = binding.id
        result["tool_binding_state"] = binding.lifecycle_state
        result["tool_binding_version"] = binding.state_version
    return result


@router.get("/mcp/tools/fingerprints")
def gateway_list_mcp_tool_fingerprints(
    trust_status: Literal["unknown", "approved", "changed", "blocked", "under_review"] | None = None,
    limit: int = 100,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    if limit < 1 or limit > 100:
        raise HTTPException(status_code=422, detail="limit must be between 1 and 100")
    return list_mcp_tool_fingerprints(
        db,
        tenant_id=ctx.tenant.id,
        trust_status=trust_status,
        limit=limit,
    )


@router.post("/mcp/tools/fingerprints/{tool_fingerprint_id}/decision")
def gateway_decide_mcp_tool_fingerprint(
    tool_fingerprint_id: str,
    payload: MCPToolFingerprintDecisionRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    try:
        result = decide_mcp_tool_fingerprint(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=ctx.user.id,
            tool_fingerprint_id=tool_fingerprint_id,
            decision=payload.decision,
            expected_manifest_hash=payload.expected_manifest_hash,
            reason=payload.reason.strip(),
            commit=not bool(payload.tool_binding_id),
        )
        if payload.tool_binding_id:
            if payload.expected_binding_version is None:
                raise HTTPException(status_code=422, detail="expected_binding_version is required")
            service = InstructionToolProvenanceService(
                db,
                signing_provider=db.info.get("phase5_signing_provider"),
            )
            actor_ref = f"user:{ctx.user.id}"
            evidence_refs = ([result["evidence_node_id"]] if result.get("evidence_node_id") else ())
            if payload.decision == "approve":
                binding = service.validate_tool(
                    tenant_id=ctx.tenant.id,
                    binding_id=payload.tool_binding_id,
                    expected_version=payload.expected_binding_version,
                    actor_ref=actor_ref,
                    metadata_verdict="SAFE",
                    policy_allowed=result["trust_status"] == "approved",
                    evidence_refs=evidence_refs,
                )
            elif payload.decision == "block":
                binding = service.revoke_tool(
                    tenant_id=ctx.tenant.id,
                    binding_id=payload.tool_binding_id,
                    expected_version=payload.expected_binding_version,
                    actor_ref=actor_ref,
                    reason=payload.reason.strip(),
                )
            else:
                binding = service.quarantine_tool(
                    tenant_id=ctx.tenant.id,
                    binding_id=payload.tool_binding_id,
                    expected_version=payload.expected_binding_version,
                    actor_ref=actor_ref,
                    reason=payload.reason.strip(),
                    evidence_refs=evidence_refs,
                )
            db.commit()
            result["tool_binding_id"] = binding.id
            result["tool_binding_state"] = binding.lifecycle_state
            result["tool_binding_version"] = binding.state_version
        return result
    except MCPToolFingerprintNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=404, detail="MCP tool fingerprint not found") from exc
    except MCPToolFingerprintConflictError as exc:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc
    except (PermissionError, RuntimeError, ValueError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/mcp/tools/exposure")
def gateway_mcp_tool_exposure(
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    db: Session = Depends(get_db),
):
    service = InstructionToolProvenanceService(
        db,
        signing_provider=db.info.get("phase5_signing_provider"),
    )
    return {"items": service.expose_tools(tenant_id=ctx.tenant.id, execution_capable=True)}


@router.post("/mcp/tools/{tool_binding_id}/remove")
def gateway_remove_mcp_tool(
    tool_binding_id: str,
    payload: MCPToolRemovalRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    db: Session = Depends(get_db),
):
    service = InstructionToolProvenanceService(
        db,
        signing_provider=db.info.get("phase5_signing_provider"),
    )
    try:
        binding = service.revoke_tool(
            tenant_id=ctx.tenant.id,
            binding_id=tool_binding_id,
            expected_version=payload.expected_version,
            actor_ref=f"user:{ctx.user.id}",
            reason=payload.reason.strip(),
        )
        db.commit()
        return {"tool_binding_id": binding.id, "lifecycle_state": binding.lifecycle_state, "state_version": binding.state_version}
    except (PermissionError, RuntimeError) as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc)) from exc
