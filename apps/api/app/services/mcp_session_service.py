from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.security import token_hash
from app.db.models.activity_audit import AISession
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.services.ai_iam_service import (
    narrow_authority_values,
    resolve_persisted_purpose_bound_permission,
)
from app.services.governance_guard import GovernanceViolationError, enforce as enforce_governance


MCP_SESSION_TYPE = "mcp_authenticated"
MCP_SESSION_OPEN_STATUS = "active"
MCP_SESSION_MAX_MINUTES = 24 * 60


class MCPSessionAuthorityError(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalized_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        normalized = str(item or "").strip().lower()
        if normalized and normalized not in result:
            result.append(normalized)
    return result


def _optional_text(value: Any) -> str | None:
    normalized = str(value or "").strip()
    return normalized or None


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return _utc(value)
    normalized = str(value or "").strip()
    if not normalized:
        return None
    try:
        return _utc(datetime.fromisoformat(normalized.replace("Z", "+00:00")))
    except ValueError:
        return None


def _intersect_authority_lists(*authorities: list[str]) -> list[str]:
    normalized = [_normalized_list(items) for items in authorities]
    if not normalized or any(not items for items in normalized):
        return []
    effective = list(normalized[0])
    for items in normalized[1:]:
        if "*" in effective:
            effective = list(items)
        elif "*" not in items:
            item_set = set(items)
            effective = [item for item in effective if item in item_set]
    return effective


def _derive_server_bounds(
    *,
    agent: AgentIdentity,
    token: CapabilityToken,
    permission: dict[str, Any],
) -> dict[str, Any]:
    scope = dict(permission.get("scope") or {})
    purpose_context = dict(permission.get("context") or {})
    purpose_actions = _normalized_list(permission.get("allowed_actions") or scope.get("allowed_actions"))
    purpose_tools = _normalized_list(permission.get("allowed_tools") or scope.get("allowed_tools"))
    purpose_data = _normalized_list(
        permission.get("allowed_data_scope")
        or scope.get("allowed_data_scopes")
        or scope.get("allowed_data_scope")
    )
    purpose_environments = _normalized_list(
        permission.get("allowed_environments")
        or scope.get("allowed_environments")
    )
    destination_authorities = [_normalized_list(agent.external_system_access)]
    for values in (
        purpose_context.get("connected_systems"),
        scope.get("allowed_domains"),
    ):
        normalized_values = _normalized_list(values)
        if normalized_values:
            destination_authorities.append(normalized_values)
    purpose_depth = purpose_context.get("max_chain_depth")
    depth_candidates = [int(agent.max_chain_depth), int(token.chain_depth)]
    if isinstance(purpose_depth, int) and not isinstance(purpose_depth, bool):
        depth_candidates.append(purpose_depth)
    return {
        "max_chain_depth": min(depth_candidates),
        "connected_systems": _intersect_authority_lists(*destination_authorities),
        "allowed_resources": _normalized_list(scope.get("allowed_resources")),
        "allowed_data_scope": purpose_data,
        "allowed_environments": purpose_environments,
        "allowed_actions": _intersect_authority_lists(
            _normalized_list(token.scopes),
            _normalized_list(agent.action_scope),
            purpose_actions,
        ),
        "allowed_tools": _intersect_authority_lists(
            _normalized_list(agent.tool_registry),
            purpose_tools,
        ),
    }


def _bound_context(
    requested: dict[str, Any],
    *,
    server_bounds: dict[str, Any],
) -> dict[str, Any]:
    context = {
        "max_chain_depth": int(server_bounds["max_chain_depth"]),
        "connected_systems": _normalized_list(server_bounds.get("connected_systems")),
        "allowed_resources": _normalized_list(server_bounds.get("allowed_resources")),
        "allowed_data_scope": _normalized_list(server_bounds.get("allowed_data_scope")),
        "allowed_environments": _normalized_list(server_bounds.get("allowed_environments")),
        "allowed_actions": _normalized_list(server_bounds.get("allowed_actions")),
        "allowed_tools": _normalized_list(server_bounds.get("allowed_tools")),
    }
    requested_depth = requested.get("max_chain_depth")
    if requested_depth is not None:
        if isinstance(requested_depth, bool) or not isinstance(requested_depth, int) or requested_depth < 1:
            raise MCPSessionAuthorityError("mcp_session_context_invalid")
        if requested_depth > context["max_chain_depth"]:
            raise MCPSessionAuthorityError("mcp_session_context_outside_authority")
        context["max_chain_depth"] = requested_depth

    for key, aliases in {
        "connected_systems": (),
        "allowed_resources": (),
        "allowed_data_scope": ("allowed_data_scopes",),
        "allowed_environments": (),
        "allowed_actions": (),
        "allowed_tools": (),
    }.items():
        supplied_names = [name for name in (key, *aliases) if name in requested]
        if not supplied_names:
            continue
        raw_value = requested[supplied_names[0]]
        if not isinstance(raw_value, list):
            raise MCPSessionAuthorityError("mcp_session_context_invalid")
        requested_values = _normalized_list(raw_value)
        server_values = _normalized_list(context.get(key))
        narrowed = (
            narrow_authority_values(server_values, requested_values, kind="resource")
            if key == "allowed_resources"
            else [
                item
                for item in requested_values
                if item in server_values or "*" in server_values
            ]
        )
        if requested_values and len(narrowed) != len(requested_values):
            raise MCPSessionAuthorityError("mcp_session_context_outside_authority")
        context[key] = narrowed if key == "allowed_resources" else requested_values

    data_classification = str(requested.get("data_classification") or "").strip().lower()
    if data_classification:
        allowed_data_scope = _normalized_list(context["allowed_data_scope"])
        if not allowed_data_scope or (
            "*" not in allowed_data_scope and data_classification not in allowed_data_scope
        ):
            raise MCPSessionAuthorityError("mcp_session_context_outside_authority")
        context["data_classification"] = data_classification
    environment = str(requested.get("environment") or "").strip().lower()
    if environment:
        allowed_environments = _normalized_list(context.get("allowed_environments"))
        if not allowed_environments or (
            "*" not in allowed_environments and environment not in allowed_environments
        ):
            raise MCPSessionAuthorityError("mcp_session_context_outside_authority")
        context["environment"] = environment
    return context


def open_mcp_session(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    ai_system_id: str,
    agent_id: str,
    raw_capability_token: str,
    expires_minutes: int,
    session_context: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> AISession:
    issued_at = _utc(now or datetime.now(timezone.utc))
    governance = enforce_governance(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        action="gateway.mcp.session.open",
        route="/gateway/mcp/sessions/open",
        module="mcp_session_service",
        emit_logs=False,
    )
    if str(governance.lifecycle_state or "").strip().upper() not in {"ACTIVE", "LIVE"}:
        raise GovernanceViolationError("lifecycle_state_not_active", status_code=403)
    ai_system = db.scalar(
        select(AISystem).where(AISystem.id == ai_system_id, AISystem.tenant_id == tenant_id)
    )
    if ai_system is None:
        raise MCPSessionAuthorityError("mcp_session_ai_system_not_found")
    if str(ai_system.status or "").strip().lower() not in {"active", "live"}:
        raise GovernanceViolationError("lifecycle_state_not_active", status_code=403)

    token = db.scalar(
        select(CapabilityToken).where(
            CapabilityToken.tenant_id == tenant_id,
            CapabilityToken.token_hash == token_hash(raw_capability_token),
        )
    )
    if token is None:
        raise MCPSessionAuthorityError("mcp_session_token_not_found")
    if token.revoked_at is not None:
        raise MCPSessionAuthorityError("mcp_session_token_revoked")
    token_expiry = _utc(token.expires_at)
    if token_expiry <= issued_at:
        raise MCPSessionAuthorityError("mcp_session_token_expired")
    if token.agent_identity_id != agent_id:
        raise MCPSessionAuthorityError("mcp_session_agent_mismatch")

    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == tenant_id,
        )
    )
    if agent is None or agent.status != "active":
        raise MCPSessionAuthorityError("mcp_session_agent_inactive")
    if agent.owner_attested_at is None or agent.owner_attestation_expiry is None:
        raise MCPSessionAuthorityError("mcp_session_owner_attestation_required")
    owner_attested_at = _utc(agent.owner_attested_at)
    owner_attestation_expiry = _utc(agent.owner_attestation_expiry)
    if owner_attested_at > issued_at or owner_attested_at >= owner_attestation_expiry:
        raise MCPSessionAuthorityError("mcp_session_owner_attestation_invalid")
    if owner_attestation_expiry <= issued_at:
        raise MCPSessionAuthorityError("mcp_session_owner_attestation_expired")
    if expires_minutes < 1 or expires_minutes > MCP_SESSION_MAX_MINUTES:
        raise MCPSessionAuthorityError("mcp_session_expiry_invalid")

    purpose_authority = resolve_persisted_purpose_bound_permission(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        agent_id=agent_id,
        caller_permission={},
        now=issued_at,
    )
    purpose_permission = purpose_authority.get("permission")
    purpose_permission_id = _optional_text(purpose_authority.get("session_id"))
    if not purpose_authority.get("valid"):
        raise MCPSessionAuthorityError(
            str(purpose_authority.get("reason") or "mcp_session_persisted_purpose_required")
        )
    if not isinstance(purpose_permission, dict) or not purpose_permission_id:
        raise MCPSessionAuthorityError("mcp_session_persisted_purpose_required")
    server_bounds = _derive_server_bounds(
        agent=agent,
        token=token,
        permission=purpose_permission,
    )
    expiry_candidates = [
        token_expiry,
        owner_attestation_expiry,
        issued_at + timedelta(minutes=expires_minutes),
    ]
    purpose_expiry = _parse_datetime(purpose_permission.get("expiry"))
    if purpose_expiry is not None:
        expiry_candidates.append(purpose_expiry)
    absolute_expiry = min(expiry_candidates)
    if absolute_expiry <= issued_at:
        raise MCPSessionAuthorityError("mcp_session_expired")
    bound_context = _bound_context(
        dict(session_context or {}),
        server_bounds=server_bounds,
    )
    session = AISession(
        session_id=f"mcp_sess_{secrets.token_urlsafe(32)}",
        tenant_id=tenant_id,
        user_id=user_id,
        source_surface="mcp",
        ai_app=ai_system.name,
        start_time=issued_at,
        end_time=None,
        status=MCP_SESSION_OPEN_STATUS,
        metadata_json={
            "session_type": MCP_SESSION_TYPE,
            "lifecycle_status": "open",
            "issued_at": issued_at.isoformat(),
            "absolute_expires_at": absolute_expiry.isoformat(),
            "ai_system_id": ai_system_id,
            "agent_id": agent_id,
            "capability_token_id": token.id,
            "purpose_permission_id": purpose_permission_id,
            "bound_context": bound_context,
        },
    )
    db.add(session)
    db.flush()
    return session


def serialize_mcp_session(session: AISession) -> dict[str, Any]:
    metadata = dict(session.metadata_json or {})
    return {
        "session_id": session.session_id,
        "tenant_id": session.tenant_id,
        "user_id": session.user_id,
        "ai_system_id": metadata.get("ai_system_id"),
        "agent_id": metadata.get("agent_id"),
        "status": metadata.get("lifecycle_status") or session.status,
        "issued_at": metadata.get("issued_at") or _utc(session.start_time).isoformat(),
        "expires_at": metadata.get("absolute_expires_at"),
        "closed_at": metadata.get("closed_at"),
        "revoked_at": metadata.get("revoked_at"),
        "context": dict(metadata.get("bound_context") or {}),
    }


def get_owned_mcp_session(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    session_id: str,
) -> AISession:
    session = db.scalar(
        select(AISession).where(
            AISession.session_id == session_id,
            AISession.tenant_id == tenant_id,
            AISession.user_id == user_id,
        )
    )
    metadata = dict(session.metadata_json or {}) if session is not None else {}
    if session is None or metadata.get("session_type") != MCP_SESSION_TYPE:
        raise MCPSessionAuthorityError("mcp_session_not_found")
    return session


def transition_mcp_session(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    session_id: str,
    transition: str,
    now: datetime | None = None,
) -> AISession:
    session = get_owned_mcp_session(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
        session_id=session_id,
    )
    metadata = dict(session.metadata_json or {})
    target_status = "closed" if transition == "close" else "revoked" if transition == "revoke" else None
    if target_status is None:
        raise MCPSessionAuthorityError("mcp_session_transition_invalid")
    lifecycle = _optional_text(metadata.get("lifecycle_status"))
    if session.status == target_status and lifecycle == target_status:
        return session
    if session.status != MCP_SESSION_OPEN_STATUS or lifecycle != "open":
        raise MCPSessionAuthorityError("mcp_session_transition_conflict")
    transitioned_at = _utc(now or datetime.now(timezone.utc))
    if transition == "close":
        metadata["lifecycle_status"] = "closed"
        metadata["closed_at"] = transitioned_at.isoformat()
    else:
        metadata["lifecycle_status"] = "revoked"
        metadata["revoked_at"] = transitioned_at.isoformat()
    transitioned = db.execute(
        update(AISession)
        .where(
            AISession.session_id == session_id,
            AISession.tenant_id == tenant_id,
            AISession.user_id == user_id,
            AISession.status == MCP_SESSION_OPEN_STATUS,
        )
        .values(
            status=target_status,
            end_time=transitioned_at,
            metadata_json=metadata,
        )
        .execution_options(synchronize_session=False)
    )
    if transitioned.rowcount != 1:
        db.expire_all()
        current = get_owned_mcp_session(
            db,
            tenant_id=tenant_id,
            user_id=user_id,
            session_id=session_id,
        )
        current_metadata = dict(current.metadata_json or {})
        if current.status == target_status and current_metadata.get("lifecycle_status") == target_status:
            return current
        raise MCPSessionAuthorityError("mcp_session_transition_conflict")
    db.expire(session)
    db.refresh(session)
    db.flush()
    return session


def validate_persisted_mcp_session(
    db: Session,
    *,
    tenant_id: str,
    authenticated_user_id: str | None,
    ai_system_id: str,
    agent_id: str | None,
    capability_token_id: str | None,
    session_id: str | None,
    initiating_user_id: str | None,
    caller_context: dict[str, Any] | None,
    purpose_permission_id: str | None = None,
    purpose_permission: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    checked_at = _utc(now or datetime.now(timezone.utc))
    normalized_session_id = _optional_text(session_id)
    result: dict[str, Any] = {
        "session": None,
        "session_id": normalized_session_id,
        "valid": False,
        "reason": "agent_session_required",
        "initiating_user_id": _optional_text(authenticated_user_id),
        "expires_at": None,
        "context": {},
    }
    if normalized_session_id is None:
        return result

    resolved_user_id = _optional_text(authenticated_user_id)
    session = db.scalar(
        select(AISession).where(
            AISession.session_id == normalized_session_id,
            AISession.tenant_id == tenant_id,
            AISession.user_id == resolved_user_id,
        )
    )
    if session is None:
        result["reason"] = "agent_session_not_found"
        return result
    metadata = dict(session.metadata_json or {})
    if metadata.get("session_type") != MCP_SESSION_TYPE:
        result["reason"] = "agent_session_not_found"
        return result

    result["session"] = session
    lifecycle = _optional_text(metadata.get("lifecycle_status"))
    if session.status == "revoked" or lifecycle == "revoked" or metadata.get("revoked_at"):
        result["reason"] = "agent_session_revoked"
        return result
    if session.status != MCP_SESSION_OPEN_STATUS or lifecycle != "open":
        result["reason"] = "agent_session_inactive"
        return result

    persisted_user_id = _optional_text(session.user_id)
    if persisted_user_id is None or resolved_user_id is None or persisted_user_id != resolved_user_id:
        result["reason"] = "agent_session_user_mismatch"
        return result
    if _optional_text(initiating_user_id) not in {None, resolved_user_id}:
        result["reason"] = "agent_session_user_mismatch"
        return result
    result["initiating_user_id"] = resolved_user_id

    if _optional_text(metadata.get("ai_system_id")) != _optional_text(ai_system_id):
        result["reason"] = "agent_session_ai_system_mismatch"
        return result
    bound_agent_id = _optional_text(metadata.get("agent_id"))
    bound_token_id = _optional_text(metadata.get("capability_token_id"))
    if bound_token_id != _optional_text(capability_token_id):
        result["reason"] = "agent_session_token_mismatch"
        return result
    if _optional_text(metadata.get("purpose_permission_id")) != _optional_text(purpose_permission_id):
        result["reason"] = "agent_session_purpose_mismatch"
        return result

    current_token = db.scalar(
        select(CapabilityToken).where(
            CapabilityToken.id == bound_token_id,
            CapabilityToken.tenant_id == tenant_id,
        )
    )
    if current_token is None:
        result["reason"] = "agent_session_token_not_found"
        return result
    if current_token.revoked_at is not None:
        result["reason"] = "agent_session_token_revoked"
        return result
    if _utc(current_token.expires_at) <= checked_at:
        result["reason"] = "agent_session_token_expired"
        return result
    if current_token.agent_identity_id != bound_agent_id:
        result["reason"] = "agent_session_agent_mismatch"
        return result
    current_agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == bound_agent_id,
            AgentIdentity.tenant_id == tenant_id,
        )
    )
    if current_agent is None or current_agent.status != "active":
        result["reason"] = "agent_session_agent_inactive"
        return result
    if current_agent.owner_attested_at is None or current_agent.owner_attestation_expiry is None:
        result["reason"] = "agent_session_owner_attestation_required"
        return result
    attested_at = _utc(current_agent.owner_attested_at)
    attestation_expiry = _utc(current_agent.owner_attestation_expiry)
    if attested_at > checked_at or attested_at >= attestation_expiry:
        result["reason"] = "agent_session_owner_attestation_invalid"
        return result
    if attestation_expiry <= checked_at:
        result["reason"] = "agent_session_owner_attestation_expired"
        return result
    if bound_agent_id != _optional_text(agent_id):
        result["reason"] = "agent_session_agent_mismatch"
        return result
    if not isinstance(purpose_permission, dict):
        result["reason"] = "agent_session_purpose_mismatch"
        return result

    absolute_expiry = _parse_datetime(metadata.get("absolute_expires_at"))
    if absolute_expiry is None:
        result["reason"] = "agent_session_expiry_invalid"
        return result
    if absolute_expiry <= checked_at:
        result["reason"] = "agent_session_expired"
        result["expires_at"] = absolute_expiry
        return result

    bound_context = dict(metadata.get("bound_context") or {})
    current_bounds = _derive_server_bounds(
        agent=current_agent,
        token=current_token,
        permission=purpose_permission,
    )
    bound_depth = bound_context.get("max_chain_depth")
    if not isinstance(bound_depth, int) or bound_depth > int(current_bounds["max_chain_depth"]):
        result["reason"] = "agent_session_authority_changed"
        return result
    for key in (
        "connected_systems",
        "allowed_resources",
        "allowed_data_scope",
        "allowed_environments",
        "allowed_actions",
        "allowed_tools",
    ):
        bound_values = _normalized_list(bound_context.get(key))
        current_values = _normalized_list(current_bounds.get(key))
        if any(item not in current_values and "*" not in current_values for item in bound_values):
            result["reason"] = "agent_session_authority_changed"
            return result
    requested_context = dict(caller_context or {})
    for key, expected in {
        "session_id": normalized_session_id,
        "agent_id": agent_id,
        "ai_system_id": ai_system_id,
        "capability_token_id": capability_token_id,
        "initiating_user_id": resolved_user_id,
        "user_id": resolved_user_id,
    }.items():
        supplied = _optional_text(requested_context.get(key))
        if supplied is not None and supplied != _optional_text(expected):
            result["reason"] = "agent_session_context_mismatch"
            return result

    caller_expiry_raw = requested_context.get("expiry")
    if caller_expiry_raw is not None:
        caller_expiry = _parse_datetime(caller_expiry_raw)
        if caller_expiry is None:
            result["reason"] = "agent_session_context_mismatch"
            return result
        if caller_expiry <= checked_at:
            result["reason"] = "agent_session_expired"
            result["expires_at"] = caller_expiry
            return result
        if caller_expiry > absolute_expiry:
            result["reason"] = "agent_session_context_widening"
            return result
        absolute_expiry = caller_expiry

    effective_context = dict(bound_context)
    caller_depth = requested_context.get("max_chain_depth")
    if caller_depth is not None:
        if isinstance(caller_depth, bool) or not isinstance(caller_depth, int) or caller_depth < 1:
            result["reason"] = "agent_session_context_mismatch"
            return result
        bound_depth = bound_context.get("max_chain_depth")
        if isinstance(bound_depth, int) and caller_depth > bound_depth:
            result["reason"] = "agent_session_context_widening"
            return result
        effective_context["max_chain_depth"] = caller_depth

    for key in (
        "connected_systems",
        "allowed_resources",
        "allowed_data_scope",
        "allowed_environments",
        "allowed_actions",
        "allowed_tools",
    ):
        if key not in requested_context:
            continue
        if not isinstance(requested_context.get(key), list):
            result["reason"] = "agent_session_context_mismatch"
            return result
        requested_values = _normalized_list(requested_context.get(key))
        bound_values = _normalized_list(bound_context.get(key))
        narrowed = (
            narrow_authority_values(bound_values, requested_values, kind="resource")
            if key == "allowed_resources"
            else [
                item
                for item in requested_values
                if item in bound_values or "*" in bound_values
            ]
        )
        if requested_values and len(narrowed) != len(requested_values):
            result["reason"] = "agent_session_context_widening"
            return result
        effective_context[key] = narrowed if key == "allowed_resources" else requested_values

    requested_classification = _optional_text(requested_context.get("data_classification"))
    if requested_classification:
        allowed_data_scope = _normalized_list(effective_context.get("allowed_data_scope"))
        if not allowed_data_scope or (
            "*" not in allowed_data_scope and requested_classification.lower() not in allowed_data_scope
        ):
            result["reason"] = "agent_session_context_widening"
            return result
        effective_context["data_classification"] = requested_classification.lower()
    requested_environment = _optional_text(requested_context.get("environment"))
    if requested_environment:
        allowed_environments = _normalized_list(effective_context.get("allowed_environments"))
        if not allowed_environments or (
            "*" not in allowed_environments and requested_environment.lower() not in allowed_environments
        ):
            result["reason"] = "agent_session_context_widening"
            return result
        effective_context["environment"] = requested_environment.lower()

    effective_context["session_id"] = normalized_session_id
    effective_context["agent_id"] = _optional_text(agent_id)
    effective_context["initiating_user_id"] = resolved_user_id
    effective_context["expiry"] = absolute_expiry.isoformat()
    result.update(
        {
            "valid": True,
            "reason": "allow",
            "expires_at": absolute_expiry,
            "context": effective_context,
        }
    )
    return result
