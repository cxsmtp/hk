from __future__ import annotations

import time
from typing import Any, Callable, Literal

from fastapi import APIRouter, Depends, HTTPException, File, Form, UploadFile
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, ValidationError, field_validator
from starlette.responses import JSONResponse
from sqlalchemy import desc, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.deps_control_plane import require_control_plane_healthy
from app.core.deps_governance import governance_payload_dependency
from app.core.provenance import (
    OpaqueProvenanceId,
    validate_authoritative_provenance_id,
)
from app.core.rbac import require_permission
from app.core.response_control import (
    RESPONSE_CONTROL_COVERAGE_ORDER,
    ResponseControlCoverage,
    normalize_response_control_coverage,
)
from app.core.tenant import TenantContext
from app.db.models.enforcement import EnforcementEvent
from app.db.session import get_db
from app.services.fail_secure_service import enforce_gateway_fail_secure_or_raise
from app.services.governance_guard import GovernanceFailSecureError, GovernanceViolationError
from app.services.llm_gateway_service import (
    gateway_chat_complete,
    gateway_document_complete,
    gateway_request_only,
    gateway_response_only,
)
from app.services.llm_gateway_secure import ProviderStageError
from app.services.llm_gateway_secure.data_minimizer import MaskingError
from app.services.llm_gateway_secure.document_codec import DocumentCodecError
from app.services.llm_gateway_streaming import (
    STREAM_MAX_OUTPUT_CHARS,
    STREAM_WINDOW_CHARS,
    GatewayChatStream,
    GatewaySSEResponse,
)


router = APIRouter(
    prefix="/llm-gateway",
    tags=["llm-gateway"],
    dependencies=[Depends(require_control_plane_healthy(module="gateway"))],
)

openai_compatible_router = APIRouter(
    prefix="/openai-compatible",
    tags=["llm-gateway"],
    dependencies=[Depends(require_control_plane_healthy(module="gateway"))],
)

LLM_GATEWAY_ACTOR_CLAIM_MAX_LENGTH = 128


def _invalid_actor_claim() -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={
            "code": "invalid_actor_claim",
            "message": (
                "actor identity claims must be between 1 and "
                f"{LLM_GATEWAY_ACTOR_CLAIM_MAX_LENGTH} characters"
            ),
        },
    )


def _validate_actor_claim(value: Any, *, allow_empty: bool = False) -> Any:
    if allow_empty and (value is None or value == ""):
        return value
    if (
        not isinstance(value, str)
        or not value
        or len(value) > LLM_GATEWAY_ACTOR_CLAIM_MAX_LENGTH
    ):
        raise _invalid_actor_claim()
    return value


class LLMGatewayMessage(BaseModel):
    role: str
    content: str


class _LLMGatewayActorClaimPayload(BaseModel):
    actor_id: str = Field(
        min_length=1,
        max_length=LLM_GATEWAY_ACTOR_CLAIM_MAX_LENGTH,
    )

    @field_validator("actor_id", mode="before")
    @classmethod
    def _bounded_actor_claim(cls, value: Any) -> Any:
        return _validate_actor_claim(value)


class LLMGatewayRequestPayload(_LLMGatewayActorClaimPayload):
    tenant_id: str
    ai_system_id: str
    policy_version_id: str
    provider: Literal[
        "openai",
        "anthropic",
        "claude",
        "gemini",
        "mistral",
        "custom",
        "oss",
        "local",
        "ollama",
        "azure_openai",
        "azure-openai",
    ] = "openai"
    model: str | None = None
    actor_type: Literal["human", "agent", "system"] = "human"
    request_id: str | None = None
    chain_id: OpaqueProvenanceId | None = None
    parent_action_id: OpaqueProvenanceId | None = None
    prompt: str
    context_summary: str = ""
    attachments_meta: list[dict[str, Any]] = Field(default_factory=list)
    tool_context: list[str] = Field(default_factory=list, max_length=64)


class LLMGatewayResponsePayload(_LLMGatewayActorClaimPayload):
    tenant_id: str
    ai_system_id: str
    policy_version_id: str
    provider: Literal[
        "openai",
        "anthropic",
        "claude",
        "gemini",
        "mistral",
        "custom",
        "oss",
        "local",
        "ollama",
        "azure_openai",
        "azure-openai",
    ] = "openai"
    model: str | None = None
    actor_type: Literal["human", "agent", "system"] = "human"
    request_id: str | None = None
    chain_id: OpaqueProvenanceId | None = None
    parent_action_id: OpaqueProvenanceId | None = None
    prompt: str | None = None
    response_text: str
    context_summary: str = ""
    attachments_meta: list[dict[str, Any]] = Field(default_factory=list)


class LLMGatewayChatCompletePayload(_LLMGatewayActorClaimPayload):
    tenant_id: str
    ai_system_id: str
    policy_version_id: str
    provider: Literal[
        "openai",
        "anthropic",
        "claude",
        "gemini",
        "mistral",
        "custom",
        "oss",
        "local",
        "ollama",
        "azure_openai",
        "azure-openai",
    ] = "openai"
    model: str | None = None
    actor_type: Literal["human", "agent", "system"] = "human"
    request_id: str | None = None
    chain_id: OpaqueProvenanceId | None = None
    parent_action_id: OpaqueProvenanceId | None = None
    system_prompt: str | None = None
    messages: list[LLMGatewayMessage]
    stream: bool = False
    context_summary: str = ""
    attachments_meta: list[dict[str, Any]] = Field(default_factory=list)
    tool_context: list[str] = Field(default_factory=list, max_length=64)


class OpenAICompatibleChatCompletionPayload(BaseModel):
    tenant_id: str | None = None
    ai_system_id: str | None = None
    policy_version_id: str | None = None
    provider: Literal[
        "openai",
        "anthropic",
        "claude",
        "gemini",
        "mistral",
        "custom",
        "oss",
        "local",
        "ollama",
        "azure_openai",
        "azure-openai",
    ] = "openai"
    model: str | None = None
    chain_id: OpaqueProvenanceId | None = None
    parent_action_id: OpaqueProvenanceId | None = None
    messages: list[LLMGatewayMessage]
    stream: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata", mode="before")
    @classmethod
    def _bounded_metadata_actor_claims(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        for key in ("actor_id", "user_id"):
            if key in value:
                _validate_actor_claim(value[key], allow_empty=True)
        return value


class LLMGatewayResult(BaseModel):
    event_id: str
    request_id: str
    runtime_event_id: str | None = None
    audit_log_id: str
    evidence_node_ids: list[str]
    finding_id: str | None
    correlation_id: str | None
    final_decision: str
    guardian_results: list[dict[str, Any]]
    prompt_hash: str
    response_hash: str | None
    provider: str
    model: str
    gateway_trace: dict[str, Any]
    response_control_coverage: ResponseControlCoverage
    chain_id: str
    parent_action_id: str | None = None
    control_mode: str | None = None
    decision_badge: str | None = None
    ai_action: dict[str, Any] | None = None
    decision_explanation: dict[str, Any] | None = None
    policy_snapshot: dict[str, Any] | None = None
    evidence_bundle: dict[str, Any] | None = None

    @field_validator("response_control_coverage", mode="before")
    @classmethod
    def _closed_response_control_coverage(cls, value: Any) -> ResponseControlCoverage:
        return normalize_response_control_coverage(value)


class LLMGatewayRequestResult(LLMGatewayResult):
    allowed: bool
    mutated_prompt_preview: str | None = None


class LLMGatewayResponseResult(LLMGatewayResult):
    controlled_response: str


class LLMGatewayChatCompleteResult(LLMGatewayResult):
    completion: str
    provider_invoked: bool


def _assert_payload_tenant(payload_tenant_id: str, ctx: TenantContext) -> None:
    if payload_tenant_id != ctx.tenant.id:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "tenant_mismatch",
                "message": "Payload tenant_id does not match selected tenant context",
            },
        )


def _metadata_str(metadata: dict[str, Any], key: str, default: str = "") -> str:
    value = metadata.get(key, default)
    return str(value) if value is not None else default


def _metadata_actor_claim(metadata: dict[str, Any], key: str) -> str:
    value = metadata.get(key)
    _validate_actor_claim(value, allow_empty=True)
    return value if isinstance(value, str) else ""


def _metadata_list(metadata: dict[str, Any], key: str) -> list[Any]:
    value = metadata.get(key, [])
    return value if isinstance(value, list) else []


def _metadata_provenance_id(metadata: dict[str, Any], key: str) -> str | None:
    if key not in metadata:
        return None
    value = metadata[key]
    try:
        return validate_authoritative_provenance_id(value, field_name=key)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_provenance_id",
                "message": "chain_id and parent_action_id must be safe opaque identifiers",
            },
        ) from exc


def _openai_to_hawk_payload(payload: OpenAICompatibleChatCompletionPayload, ctx: TenantContext) -> LLMGatewayChatCompletePayload:
    metadata = payload.metadata or {}
    metadata_chain_id = _metadata_provenance_id(metadata, "chain_id")
    metadata_parent_action_id = _metadata_provenance_id(metadata, "parent_action_id")
    tenant_id = payload.tenant_id or _metadata_str(metadata, "tenant_id", ctx.tenant.id)
    ai_system_id = payload.ai_system_id or _metadata_str(metadata, "ai_system_id")
    policy_version_id = payload.policy_version_id or _metadata_str(metadata, "policy_version_id")
    actor_id = (
        _metadata_actor_claim(metadata, "actor_id")
        or _metadata_actor_claim(metadata, "user_id")
        or "gateway-api-client"
    )
    actor_type = _metadata_str(metadata, "actor_type", "human")
    if actor_type not in {"human", "agent", "system"}:
        actor_type = "human"
    if not ai_system_id:
        raise HTTPException(status_code=400, detail={"code": "missing_ai_system_id", "message": "ai_system_id is required"})
    if not policy_version_id:
        raise HTTPException(
            status_code=400,
            detail={"code": "missing_policy_version_id", "message": "policy_version_id is required"},
        )
    try:
        return LLMGatewayChatCompletePayload(
            tenant_id=tenant_id,
            ai_system_id=ai_system_id,
            policy_version_id=policy_version_id,
            provider=payload.provider,
            model=payload.model,
            actor_type=actor_type,  # type: ignore[arg-type]
            actor_id=actor_id,
            request_id=_metadata_str(metadata, "request_id") or None,
            chain_id=payload.chain_id or metadata_chain_id,
            parent_action_id=payload.parent_action_id or metadata_parent_action_id,
            system_prompt=_metadata_str(metadata, "system_prompt") or None,
            messages=payload.messages,
            context_summary=_metadata_str(metadata, "context_summary"),
            attachments_meta=_metadata_list(metadata, "attachments_meta"),
            tool_context=[str(item) for item in _metadata_list(metadata, "tool_context")],
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_provenance_id",
                "message": "chain_id and parent_action_id must be safe opaque identifiers",
            },
        ) from exc


def _hawk_envelope(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": result.get("event_id"),
        "request_id": result.get("request_id"),
        "runtime_event_id": result.get("runtime_event_id"),
        "audit_log_id": result.get("audit_log_id"),
        "evidence_node_ids": result.get("evidence_node_ids", []),
        "finding_id": result.get("finding_id"),
        "correlation_id": result.get("correlation_id"),
        "final_decision": result.get("final_decision"),
        "control_mode": result.get("control_mode"),
        "decision_badge": result.get("decision_badge"),
        "provider_invoked": result.get("provider_invoked", False),
        "provider": result.get("provider"),
        "model": result.get("model"),
        "prompt_hash": result.get("prompt_hash"),
        "response_hash": result.get("response_hash"),
        "guardian_results": result.get("guardian_results", []),
        "gateway_trace": result.get("gateway_trace", {}),
        "response_control_coverage": normalize_response_control_coverage(
            result.get("response_control_coverage")
        ),
        "chain_id": result.get("chain_id"),
        "parent_action_id": result.get("parent_action_id"),
        "ai_action": result.get("ai_action"),
        "decision_explanation": result.get("decision_explanation"),
        "policy_snapshot": result.get("policy_snapshot"),
        "evidence_bundle": result.get("evidence_bundle"),
    }


def _openai_response_or_block(result: dict[str, Any]) -> dict[str, Any]:
    hawk = _hawk_envelope(result)
    if result.get("final_decision") == "block" or result.get("control_mode") == "inline_prevented":
        provider_invoked = result.get("provider_invoked") is True
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "code": "hawk_policy_block",
                    "message": (
                        "Hawk restricted this model response before client return."
                        if provider_invoked
                        else "Hawk blocked this model request before provider invocation."
                    ),
                },
                "hawk": hawk,
            },
        )
    return {
        "id": result.get("request_id"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": result.get("model"),
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": result.get("completion", "")},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
        },
        "hawk": hawk,
    }


def _stream_gateway_chat(
    db: Session,
    gateway_kwargs: dict[str, Any],
    *,
    finish_unstreamed: Callable[[dict[str, Any]], Any],
    map_error: Callable[[Exception], Any],
) -> Any:
    """Run the governed call and answer as SSE once upstream text arrives.

    Everything decided before the first upstream chunk (request guards,
    pre-request blocks, provider connect errors) is answered exactly as the
    buffered route answers it.
    """
    stream = GatewayChatStream(
        db=db,
        run=lambda relay: gateway_chat_complete(db, _stream_relay=relay, **gateway_kwargs),
        envelope=lambda result: jsonable_encoder(_hawk_envelope(result)),
        model_hint=gateway_kwargs.get("model"),
    )
    stream.start()
    if stream.wait_until_streaming_or_done():
        return GatewaySSEResponse(stream)
    try:
        result = stream.unstreamed_result()
        db.commit()
        return finish_unstreamed(result)
    except Exception as exc:
        return map_error(exc)


def _map_openai_chat_error(exc: Exception, db: Session) -> JSONResponse:
    """Error contract of the OpenAI-compatible route, shared by both modes."""
    if isinstance(exc, HTTPException):
        db.commit()
        raise exc
    if isinstance(exc, ProviderStageError):
        db.rollback()
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": "Model provider execution failed.",
                    "type": "provider_error",
                    "param": None,
                    "code": "provider_execution_failed",
                }
            },
            headers={"X-Hawk-Response-Control-Coverage": "unknown"},
        )
    return _raise_chat_error(exc, db)


def _raise_chat_error(exc: Exception, db: Session) -> Any:
    """Error contract of the native chat route, shared by both modes."""
    if isinstance(exc, ValueError):
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if isinstance(exc, ProviderStageError):
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail={
                "code": "provider_execution_failed",
                "message": "Model provider execution failed.",
            },
            headers={"X-Hawk-Response-Control-Coverage": "unknown"},
        ) from None
    if isinstance(exc, RuntimeError):
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail=str(exc),
            headers={"X-Hawk-Response-Control-Coverage": "unknown"},
        ) from exc
    if isinstance(exc, GovernanceViolationError):
        db.rollback()
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": "governance_context_blocked", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    if isinstance(exc, GovernanceFailSecureError):
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={"code": "governance_fail_secure", "reason_code": exc.reason_code, "message": exc.message},
        ) from exc
    if isinstance(exc, SQLAlchemyError):
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={
                "code": "enforcement_fail_closed",
                "message": "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
                "error": str(exc),
            },
        ) from exc
    raise exc


def _handle_openai_compatible_chat(
    *,
    payload: OpenAICompatibleChatCompletionPayload,
    ctx: TenantContext,
    db: Session,
) -> Any:
    hawk_payload = _openai_to_hawk_payload(payload, ctx)
    _assert_payload_tenant(hawk_payload.tenant_id, ctx)
    request_id = hawk_payload.request_id or ""
    enforce_gateway_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="gateway",
        ai_system_id=hawk_payload.ai_system_id,
        request_id=request_id,
        governance_route="/llm-gateway/chat/complete",
        governance_action="llm_gateway.chat.complete",
    )
    gateway_kwargs: dict[str, Any] = dict(
        tenant_id=ctx.tenant.id,
        ai_system_id=hawk_payload.ai_system_id,
        policy_version_id=hawk_payload.policy_version_id,
        provider=hawk_payload.provider,
        model=hawk_payload.model,
        actor_type=hawk_payload.actor_type,
        actor_id=hawk_payload.actor_id,
        trusted_actor_user_id=(ctx.user.id if ctx.user is not None else None),
        client_request_id=hawk_payload.request_id,
        chain_id=hawk_payload.chain_id,
        parent_action_id=hawk_payload.parent_action_id,
        system_prompt=hawk_payload.system_prompt,
        messages=[item.model_dump() for item in hawk_payload.messages],
        context_summary=hawk_payload.context_summary,
        attachments_meta=hawk_payload.attachments_meta,
        tool_context=hawk_payload.tool_context,
    )
    if payload.stream:
        return _stream_gateway_chat(
            db,
            gateway_kwargs,
            finish_unstreamed=_openai_response_or_block,
            map_error=lambda exc: _map_openai_chat_error(exc, db),
        )
    try:
        result = gateway_chat_complete(db, **gateway_kwargs)
        db.commit()
        return _openai_response_or_block(result)
    except HTTPException:
        db.commit()
        raise
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ProviderStageError:
        db.rollback()
        return JSONResponse(
            status_code=502,
            content={
                "error": {
                    "message": "Model provider execution failed.",
                    "type": "provider_error",
                    "param": None,
                    "code": "provider_execution_failed",
                }
            },
            headers={"X-Hawk-Response-Control-Coverage": "unknown"},
        )
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail=str(exc),
            headers={"X-Hawk-Response-Control-Coverage": "unknown"},
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
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={
                "code": "enforcement_fail_closed",
                "message": "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
                "error": str(exc),
            },
        ) from exc


@router.get("/config")
def llm_gateway_config_route(ctx: TenantContext = Depends(require_permission("gateway.view"))):
    return {
        "tenant_id": ctx.tenant.id,
        "mode": "action_control",
        "credential_handling": "server_side_redacted",
        "routes": [
            "/llm-gateway/request",
            "/llm-gateway/response",
            "/llm-gateway/chat/complete",
            "/llm-gateway/documents/complete",
            "/llm-gateway/v1/chat/completions",
            "/openai-compatible/v1/chat/completions",
        ],
        "supported_providers": [
            "openai",
            "azure_openai",
            "anthropic",
            "claude",
            "gemini",
            "mistral",
            "custom",
            "oss_local",
        ],
        "control_modes": [
            "inline_allowed",
            "inline_prevented",
            "warned",
            "shadow_would_block",
            "detected_only",
            "telemetry_only",
            "external_required",
            "external_action_triggered",
            "incomplete",
        ],
        "evidence": "policy_snapshot, decision_explanation, gateway_trace, evidence_bundle",
        "response_control_coverage": list(RESPONSE_CONTROL_COVERAGE_ORDER),
        "streaming": {
            "supported": True,
            "routes": [
                "/llm-gateway/chat/complete",
                "/llm-gateway/v1/chat/completions",
                "/openai-compatible/v1/chat/completions",
            ],
            "format": "openai_sse",
            "response_enforcement": "sliding_window_buffer_and_scan",
            "window_chars": STREAM_WINDOW_CHARS,
            "max_output_chars": STREAM_MAX_OUTPUT_CHARS,
        },
        "documents": {"formats": ["pdf", "docx"], "modes": ["draft", "transform"], "max_bytes": 10485760, "max_pages": 100, "max_text_chars": 100000, "streaming": False, "scanned_or_encrypted_supported": False, "layout": "text_reflow"},
    }


@router.get("/events/{event_id}")
def llm_gateway_event_route(
    event_id: str,
    ctx: TenantContext = Depends(require_permission("gateway.view")),
    db: Session = Depends(get_db),
):
    event = db.scalar(
        select(EnforcementEvent).where(
            EnforcementEvent.id == event_id,
            EnforcementEvent.tenant_id == ctx.tenant.id,
        )
    )
    if event is None:
        raise HTTPException(status_code=404, detail={"code": "event_not_found"})
    trace = dict((event.final_actions or {}).get("_trace") or {})
    trace["response_control_coverage"] = normalize_response_control_coverage(
        trace.get("response_control_coverage")
    )
    return {
        "event_id": event.id,
        "request_id": event.request_id,
        "runtime_event_id": trace.get("runtime_event_id"),
        "timestamp": event.timestamp.isoformat() if event.timestamp else None,
        "ai_system_id": event.ai_system_id,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "final_decision": event.final_decision,
        "control_mode": trace.get("control_mode"),
        "provider": trace.get("provider"),
        "model": trace.get("model"),
        "prompt_hash": trace.get("prompt_hash"),
        "response_hash": trace.get("response_hash"),
        "policy_snapshot_id": trace.get("policy_snapshot_id"),
        "response_control_coverage": trace["response_control_coverage"],
        "chain_id": trace.get("chain_id"),
        "parent_action_id": trace.get("parent_action_id"),
        "evidence_node_ids": event.evidence_nodes_created or [],
        "gateway_trace": trace,
    }


@router.get("/logs")
def llm_gateway_logs_route(
    limit: int = 50,
    ctx: TenantContext = Depends(require_permission("gateway.view")),
    db: Session = Depends(get_db),
):
    capped_limit = min(max(limit, 1), 200)
    rows = db.scalars(
        select(EnforcementEvent)
        .where(EnforcementEvent.tenant_id == ctx.tenant.id)
        .order_by(desc(EnforcementEvent.timestamp))
        .limit(capped_limit)
    ).all()
    items = []
    for event in rows:
        trace = dict((event.final_actions or {}).get("_trace") or {})
        if trace.get("application") != "llm_gateway":
            continue
        response_control_coverage = normalize_response_control_coverage(
            trace.get("response_control_coverage")
        )
        items.append(
            {
                "event_id": event.id,
                "request_id": event.request_id,
                "runtime_event_id": trace.get("runtime_event_id"),
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "final_decision": event.final_decision,
                "control_mode": trace.get("control_mode"),
                "provider": trace.get("provider"),
                "model": trace.get("model"),
                "policy_snapshot_id": trace.get("policy_snapshot_id"),
                "response_control_coverage": response_control_coverage,
                "chain_id": trace.get("chain_id"),
                "parent_action_id": trace.get("parent_action_id"),
                "evidence_node_count": len(event.evidence_nodes_created or []),
            }
        )
    return {"tenant_id": ctx.tenant.id, "items": items, "count": len(items)}


@router.post(
    "/v1/chat/completions",
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="llm_gateway.openai_compatible.chat.complete",
                route="/llm-gateway/v1/chat/completions",
                module="gateway",
            )
        )
    ],
)
def llm_gateway_v1_chat_completions_route(
    payload: OpenAICompatibleChatCompletionPayload,
    ctx: TenantContext = Depends(require_permission("gateway.operate")),
    db: Session = Depends(get_db),
):
    return _handle_openai_compatible_chat(payload=payload, ctx=ctx, db=db)


@openai_compatible_router.post(
    "/v1/chat/completions",
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="llm_gateway.openai_compatible.chat.complete",
                route="/openai-compatible/v1/chat/completions",
                module="gateway",
            )
        )
    ],
)
def openai_compatible_chat_completions_route(
    payload: OpenAICompatibleChatCompletionPayload,
    ctx: TenantContext = Depends(require_permission("gateway.operate")),
    db: Session = Depends(get_db),
):
    return _handle_openai_compatible_chat(payload=payload, ctx=ctx, db=db)


@router.post(
    "/request",
    response_model=LLMGatewayRequestResult,
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="llm_gateway.request",
                route="/llm-gateway/request",
                module="gateway",
            )
        )
    ],
)
def llm_gateway_request_route(
    payload: LLMGatewayRequestPayload,
    ctx: TenantContext = Depends(require_permission("gateway.operate")),
    db: Session = Depends(get_db),
):
    _assert_payload_tenant(payload.tenant_id, ctx)
    request_id = payload.request_id or ""
    enforce_gateway_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="gateway",
        ai_system_id=payload.ai_system_id,
        request_id=request_id,
        governance_route="/llm-gateway/request",
        governance_action="llm_gateway.request",
    )
    try:
        result = gateway_request_only(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            policy_version_id=payload.policy_version_id,
            provider=payload.provider,
            model=payload.model,
            actor_type=payload.actor_type,
            actor_id=payload.actor_id,
            trusted_actor_user_id=(ctx.user.id if ctx.user is not None else None),
            client_request_id=payload.request_id,
            chain_id=payload.chain_id,
            parent_action_id=payload.parent_action_id,
            prompt=payload.prompt,
            context_summary=payload.context_summary,
            attachments_meta=payload.attachments_meta,
            tool_context=payload.tool_context,
        )
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
        raise HTTPException(
            status_code=503,
            detail={
                "code": "enforcement_fail_closed",
                "message": "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
                "error": str(exc),
            },
        ) from exc


@router.post(
    "/response",
    response_model=LLMGatewayResponseResult,
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="llm_gateway.response",
                route="/llm-gateway/response",
                module="gateway",
            )
        )
    ],
)
def llm_gateway_response_route(
    payload: LLMGatewayResponsePayload,
    ctx: TenantContext = Depends(require_permission("gateway.operate")),
    db: Session = Depends(get_db),
):
    _assert_payload_tenant(payload.tenant_id, ctx)
    request_id = payload.request_id or ""
    enforce_gateway_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="gateway",
        ai_system_id=payload.ai_system_id,
        request_id=request_id,
        governance_route="/llm-gateway/response",
        governance_action="llm_gateway.response",
    )
    try:
        result = gateway_response_only(
            db,
            tenant_id=ctx.tenant.id,
            ai_system_id=payload.ai_system_id,
            policy_version_id=payload.policy_version_id,
            provider=payload.provider,
            model=payload.model,
            actor_type=payload.actor_type,
            actor_id=payload.actor_id,
            trusted_actor_user_id=(ctx.user.id if ctx.user is not None else None),
            client_request_id=payload.request_id,
            chain_id=payload.chain_id,
            parent_action_id=payload.parent_action_id,
            prompt=payload.prompt,
            response_text=payload.response_text,
            context_summary=payload.context_summary,
            attachments_meta=payload.attachments_meta,
        )
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
        raise HTTPException(
            status_code=503,
            detail={
                "code": "enforcement_fail_closed",
                "message": "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
                "error": str(exc),
            },
        ) from exc


@router.post(
    "/chat/complete",
    response_model=LLMGatewayChatCompleteResult,
    dependencies=[
        Depends(
            governance_payload_dependency(
                action="llm_gateway.chat.complete",
                route="/llm-gateway/chat/complete",
                module="gateway",
            )
        )
    ],
)
def llm_gateway_chat_complete_route(
    payload: LLMGatewayChatCompletePayload,
    ctx: TenantContext = Depends(require_permission("gateway.operate")),
    db: Session = Depends(get_db),
):
    _assert_payload_tenant(payload.tenant_id, ctx)
    request_id = payload.request_id or ""
    enforce_gateway_fail_secure_or_raise(
        db,
        tenant_id=ctx.tenant.id,
        module="gateway",
        ai_system_id=payload.ai_system_id,
        request_id=request_id,
        governance_route="/llm-gateway/chat/complete",
        governance_action="llm_gateway.chat.complete",
    )
    gateway_kwargs: dict[str, Any] = dict(
        tenant_id=ctx.tenant.id,
        ai_system_id=payload.ai_system_id,
        policy_version_id=payload.policy_version_id,
        provider=payload.provider,
        model=payload.model,
        actor_type=payload.actor_type,
        actor_id=payload.actor_id,
        trusted_actor_user_id=(ctx.user.id if ctx.user is not None else None),
        client_request_id=payload.request_id,
        chain_id=payload.chain_id,
        parent_action_id=payload.parent_action_id,
        system_prompt=payload.system_prompt,
        messages=[item.model_dump() for item in payload.messages],
        context_summary=payload.context_summary,
        attachments_meta=payload.attachments_meta,
        tool_context=payload.tool_context,
    )
    if payload.stream:
        return _stream_gateway_chat(
            db,
            gateway_kwargs,
            # A pre-stream outcome is serialized by the route's response model,
            # exactly like the buffered answer.
            finish_unstreamed=lambda result: result,
            map_error=lambda exc: _raise_chat_error(exc, db),
        )
    try:
        result = gateway_chat_complete(db, **gateway_kwargs)
        db.commit()
        return result
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ProviderStageError:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail={
                "code": "provider_execution_failed",
                "message": "Model provider execution failed.",
            },
            headers={"X-Hawk-Response-Control-Coverage": "unknown"},
        ) from None
    except RuntimeError as exc:
        db.rollback()
        raise HTTPException(
            status_code=502,
            detail=str(exc),
            headers={"X-Hawk-Response-Control-Coverage": "unknown"},
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
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=503,
            detail={
                "code": "enforcement_fail_closed",
                "message": "Enforcement dependency unavailable. Request blocked by fail-closed policy.",
                "error": str(exc),
            },
        ) from exc


class LLMGatewayDocumentFacts(BaseModel):
    format: Literal["pdf", "docx"]
    page_count: int | None
    block_count: int


class LLMGatewayMaskingFacts(BaseModel):
    enabled: bool
    applied: bool
    restored: bool
    entity_type_counts: dict[str, int]
    mapping_destroyed: bool


class LLMGatewayDocumentHawk(BaseModel):
    final_decision: Literal["allow", "warn"]
    provider_invoked: bool
    response_control_coverage: ResponseControlCoverage
    reversible_masking: LLMGatewayMaskingFacts


class LLMGatewayDocumentResult(BaseModel):
    file_name: str
    media_type: str
    content_base64: str
    document: LLMGatewayDocumentFacts
    hawk: LLMGatewayDocumentHawk


@router.post("/documents/complete", response_model=LLMGatewayDocumentResult)
def llm_gateway_document_complete_route(
    tenant_id: str = Form(...),
    ai_system_id: str = Form(...),
    policy_version_id: str = Form(...),
    provider: str = Form(...),
    mode: Literal["draft", "transform"] = Form(...),
    output_format: Literal["pdf", "docx"] = Form(...),
    instruction: str = Form(..., max_length=10000),
    model: str | None = Form(None),
    request_id: str | None = Form(None),
    chain_id: str | None = Form(None),
    parent_action_id: str | None = Form(None),
    file: UploadFile | None = File(None),
    ctx: TenantContext = Depends(require_permission("gateway.operate")),
    db: Session = Depends(get_db),
):
    _assert_payload_tenant(tenant_id, ctx)
    enforce_gateway_fail_secure_or_raise(
        db, tenant_id=ctx.tenant.id, module="gateway",
        ai_system_id=ai_system_id, request_id=request_id or "",
        governance_route="/llm-gateway/documents/complete",
        governance_action="llm_gateway.document.complete",
    )
    content: bytes | None = None
    if file is not None:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = file.file.read(min(65536, 10485761 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > 10485760:
                raise HTTPException(status_code=413, detail={"code": "document_size_limit"})
            chunks.append(chunk)
        content = b"".join(chunks)
    try:
        result = gateway_document_complete(
            db, tenant_id=ctx.tenant.id,
            ai_system_id=ai_system_id, policy_version_id=policy_version_id,
            provider=provider, model=model,
            trusted_actor_user_id=(ctx.user.id if ctx.user is not None else ""),
            client_request_id=request_id, chain_id=chain_id,
            parent_action_id=parent_action_id, mode=mode,
            output_format=output_format, instruction=instruction,
            file_bytes=content, file_name=file.filename if file else None,
            mime_type=file.content_type if file else None,
        )
        db.commit()
        return result
    except DocumentCodecError as exc:
        db.rollback()
        status = 403 if exc.code in {"documents_not_enabled", "document_policy_blocked"} else 400
        raise HTTPException(status_code=status, detail={"code": exc.code}) from None
    except MaskingError as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail={"code": exc.code}) from None
    except ProviderStageError:
        db.rollback()
        raise HTTPException(status_code=502, detail={"code": "provider_execution_failed"}) from None
    except GovernanceViolationError as exc:
        db.rollback()
        raise HTTPException(status_code=exc.status_code, detail={"code": "governance_context_blocked", "reason_code": exc.reason_code}) from None
    except GovernanceFailSecureError as exc:
        db.rollback()
        raise HTTPException(status_code=503, detail={"code": "governance_fail_secure", "reason_code": exc.reason_code}) from None
    except (ValueError, RuntimeError):
        db.rollback()
        raise HTTPException(status_code=400, detail={"code": "invalid_document_request"}) from None
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(status_code=503, detail={"code": "enforcement_fail_closed"}) from None
