from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentDelegation, AgentIdentity, CapabilityToken
from app.db.models.runtime_intelligence import RuntimeEvent


MAX_DELEGATION_CHAIN_HOPS = 64
MAX_PARENT_ACTION_HOPS = 256
AUTHORITATIVE_PARENT_ACTION_EVENT_TYPES = frozenset({"agent_action_intercept", "mcp_authorize"})
AUTHORITATIVE_PARENT_ACTION_DECISIONS = frozenset({"allow"})


@dataclass(frozen=True)
class DelegationChainDepthResult:
    allowed: bool
    reason_code: str
    claimed_depth: int | None
    derived_depth: int | None
    parent_agent_id: str | None
    parent_agent_ids: tuple[str, ...] = ()
    delegation_ids: tuple[str, ...] = ()
    stored_depths: tuple[int, ...] = ()


def _utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _scope_allows(scopes: object, required_action: str | None) -> bool:
    if not required_action:
        return True
    required = str(required_action).strip().lower()
    normalized = {
        str(scope).strip().lower()
        for scope in (scopes if isinstance(scopes, list) else [])
        if str(scope).strip()
    }
    return "*" in normalized or required in normalized


def _result(
    *,
    allowed: bool,
    reason_code: str,
    claimed_depth: int | None,
    derived_depth: int | None,
    parent_agent_id: str | None,
    delegation_ids: list[str],
    stored_depths: list[int],
    parent_agent_ids: list[str] | None = None,
) -> DelegationChainDepthResult:
    return DelegationChainDepthResult(
        allowed=allowed,
        reason_code=reason_code,
        claimed_depth=claimed_depth,
        derived_depth=derived_depth,
        parent_agent_id=parent_agent_id,
        parent_agent_ids=tuple(parent_agent_ids or []),
        delegation_ids=tuple(delegation_ids),
        stored_depths=tuple(stored_depths),
    )


def resolve_persisted_delegation_chain_depth(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    capability_token_id: str,
    claimed_chain_depth: int | None,
    claimed_parent_agent_id: str | None = None,
    parent_action_id: str | None = None,
    chain_id: str | None = None,
    ai_system_id: str | None = None,
    required_action: str | None = None,
    now: datetime | None = None,
) -> DelegationChainDepthResult:
    """Resolve delegation depth from tenant-scoped persisted authority edges.

    Request fields are assertions only. They can cause a mismatch denial, but
    they never create a parent relationship or increase effective authority.
    """

    current_time = _utc(now or datetime.now(timezone.utc))
    claimed_depth = int(claimed_chain_depth) if claimed_chain_depth is not None else None
    if claimed_depth is not None and claimed_depth <= 0:
        claimed_depth = None
    parent_hint = str(claimed_parent_agent_id or "").strip() or None
    action_hint = str(parent_action_id or "").strip() or None
    resolved_chain_id = str(chain_id or "").strip() or None

    delegation_ids: list[str] = []
    stored_depths: list[int] = []

    token = db.scalar(
        select(CapabilityToken).where(
            CapabilityToken.id == capability_token_id,
            CapabilityToken.tenant_id == tenant_id,
        )
    )
    if token is None:
        return _result(allowed=False, reason_code="delegation_chain_token_not_found", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
    if str(token.agent_identity_id) != agent_id:
        return _result(allowed=False, reason_code="delegation_chain_token_agent_mismatch", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
    if token.revoked_at is not None:
        return _result(allowed=False, reason_code="delegation_chain_token_revoked", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
    if _utc(token.expires_at) <= current_time:
        return _result(allowed=False, reason_code="delegation_chain_token_expired", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
    token_system_id = str(token.ai_system_id or "").strip() or None
    if token_system_id is None:
        return _result(allowed=False, reason_code="delegation_chain_token_system_unbound", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
    if ai_system_id and token_system_id != ai_system_id:
        return _result(allowed=False, reason_code="delegation_chain_token_system_mismatch", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)

    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == tenant_id,
        )
    )
    if agent is None:
        return _result(allowed=False, reason_code="delegation_chain_agent_not_found", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
    if str(agent.status or "").strip().lower() != "active":
        return _result(allowed=False, reason_code="delegation_chain_agent_inactive", claimed_depth=claimed_depth, derived_depth=None, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)

    current_agent_id = agent_id
    current_token_id = capability_token_id
    visited_agent_ids: set[str] = {current_agent_id}
    visited_token_ids: set[str] = {current_token_id}
    derived_depth = 1
    immediate_parent_agent_id: str | None = None
    parent_agent_ids: list[str] = []
    parent_token_ids: list[str] = []
    parent_agent_depth_limits: list[int] = []
    parent_token_depth_limits: list[int] = []

    if not ai_system_id and (parent_hint or action_hint):
        return _result(
            allowed=False,
            reason_code="delegation_chain_ai_system_required",
            claimed_depth=claimed_depth,
            derived_depth=derived_depth,
            parent_agent_id=None,
            delegation_ids=delegation_ids,
            stored_depths=stored_depths,
        )

    for _hop in range(MAX_DELEGATION_CHAIN_HOPS + 1):
        candidates = list(
            db.scalars(
                select(AgentDelegation).where(
                    AgentDelegation.tenant_id == tenant_id,
                    AgentDelegation.child_agent_identity_id == current_agent_id,
                    AgentDelegation.child_token_id == current_token_id,
                )
            ).all()
        )
        active = [
            row
            for row in candidates
            if str(row.status or "").strip().lower() == "active" and row.revoked_at is None
        ]
        if not active:
            if candidates:
                return _result(allowed=False, reason_code="delegation_chain_revoked", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
            break
        if len(active) != 1:
            return _result(allowed=False, reason_code="delegation_chain_ambiguous_parent", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)

        edge = active[0]
        if not ai_system_id:
            return _result(allowed=False, reason_code="delegation_chain_ai_system_required", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if ai_system_id and str(edge.ai_system_id or "").strip() != ai_system_id:
            return _result(allowed=False, reason_code="delegation_chain_ai_system_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if str(edge.child_agent_identity_id) != current_agent_id or str(edge.child_token_id) != current_token_id:
            return _result(allowed=False, reason_code="delegation_chain_edge_binding_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if not _scope_allows(edge.action_scope, required_action):
            return _result(allowed=False, reason_code="delegation_chain_edge_action_scope_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)

        parent_agent_id = str(edge.parent_agent_identity_id)
        parent_token_id = str(edge.parent_token_id)
        if parent_token_id in visited_token_ids:
            return _result(allowed=False, reason_code="delegation_chain_token_cycle_detected", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if parent_agent_id in visited_agent_ids:
            return _result(allowed=False, reason_code="delegation_chain_agent_cycle_detected", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        parent_agent = db.scalar(
            select(AgentIdentity).where(
                AgentIdentity.id == parent_agent_id,
                AgentIdentity.tenant_id == tenant_id,
            )
        )
        if parent_agent is None:
            return _result(allowed=False, reason_code="delegation_chain_parent_agent_not_found", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if str(parent_agent.status or "").strip().lower() != "active":
            return _result(allowed=False, reason_code="delegation_chain_parent_agent_inactive", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if not _scope_allows(parent_agent.action_scope, required_action):
            return _result(allowed=False, reason_code="delegation_chain_parent_agent_scope_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)

        parent_token = db.scalar(
            select(CapabilityToken).where(
                CapabilityToken.id == parent_token_id,
                CapabilityToken.tenant_id == tenant_id,
                CapabilityToken.agent_identity_id == parent_agent_id,
            )
        )
        if parent_token is None:
            return _result(allowed=False, reason_code="delegation_chain_parent_token_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if parent_token.revoked_at is not None:
            return _result(allowed=False, reason_code="delegation_chain_parent_token_revoked", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if _utc(parent_token.expires_at) <= current_time:
            return _result(allowed=False, reason_code="delegation_chain_parent_token_expired", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        parent_token_system_id = str(parent_token.ai_system_id or "").strip() or None
        if parent_token_system_id is None:
            return _result(allowed=False, reason_code="delegation_chain_parent_token_system_unbound", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if ai_system_id and parent_token_system_id != ai_system_id:
            return _result(allowed=False, reason_code="delegation_chain_parent_token_system_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if not _scope_allows(parent_token.scopes, required_action):
            return _result(allowed=False, reason_code="delegation_chain_parent_token_scope_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)

        if immediate_parent_agent_id is None:
            immediate_parent_agent_id = parent_agent_id
        parent_agent_ids.append(parent_agent_id)
        parent_token_ids.append(parent_token_id)
        parent_agent_depth_limits.append(int(parent_agent.max_chain_depth))
        parent_token_depth_limits.append(int(parent_token.chain_depth))
        delegation_ids.append(str(edge.id))
        stored_depths.append(int(edge.chain_depth))
        derived_depth += 1
        current_agent_id = parent_agent_id
        current_token_id = parent_token_id
        visited_agent_ids.add(parent_agent_id)
        visited_token_ids.add(parent_token_id)
    else:  # pragma: no cover - defensive; loop returns on the extra hop
        return _result(allowed=False, reason_code="delegation_chain_too_deep", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)

    if derived_depth > MAX_DELEGATION_CHAIN_HOPS:
        return _result(allowed=False, reason_code="delegation_chain_too_deep", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)
    for hop_index, stored_edge_depth in enumerate(stored_depths):
        expected_child_position = derived_depth - hop_index
        expected_parent_position = expected_child_position - 1
        if stored_edge_depth < expected_child_position:
            return _result(allowed=False, reason_code="delegation_chain_edge_depth_exceeded", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
        if parent_token_depth_limits[hop_index] < expected_parent_position:
            return _result(allowed=False, reason_code="delegation_chain_parent_token_depth_exceeded", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
        if parent_agent_depth_limits[hop_index] < derived_depth:
            return _result(allowed=False, reason_code="delegation_chain_parent_agent_depth_exceeded", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
    if parent_hint and immediate_parent_agent_id is None:
        return _result(allowed=False, reason_code="delegation_parent_not_found", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
    if parent_hint and parent_hint != immediate_parent_agent_id:
        return _result(allowed=False, reason_code="delegation_parent_agent_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths)

    if claimed_depth is not None and claimed_depth != derived_depth:
        return _result(allowed=False, reason_code="delegation_chain_depth_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)

    if delegation_ids and not action_hint:
        return _result(allowed=False, reason_code="delegation_parent_action_required", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
    if action_hint:
        if immediate_parent_agent_id is None:
            return _result(allowed=False, reason_code="delegation_parent_action_without_edge", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=None, delegation_ids=delegation_ids, stored_depths=stored_depths)
        if not resolved_chain_id:
            return _result(allowed=False, reason_code="delegation_parent_action_chain_required", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
        if len(parent_agent_ids) > MAX_PARENT_ACTION_HOPS:
            return _result(allowed=False, reason_code="delegation_parent_action_too_deep", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)

        current_action_id = action_hint
        visited_actions: set[str] = set()
        for hop_index, expected_agent_id in enumerate(parent_agent_ids):
            if hop_index >= MAX_PARENT_ACTION_HOPS:
                return _result(allowed=False, reason_code="delegation_parent_action_too_deep", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            if current_action_id in visited_actions:
                return _result(allowed=False, reason_code="delegation_parent_action_cycle_detected", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            visited_actions.add(current_action_id)
            current_event = db.scalar(
                select(RuntimeEvent).where(
                    RuntimeEvent.event_id == current_action_id,
                    RuntimeEvent.tenant_id == tenant_id,
                )
            )
            if current_event is None:
                reason = "delegation_parent_action_not_found" if len(visited_actions) == 1 else "delegation_parent_action_disconnected"
                return _result(allowed=False, reason_code=reason, claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            if str(current_event.chain_id or "") != resolved_chain_id:
                return _result(allowed=False, reason_code="delegation_parent_action_chain_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            if str(current_event.agent_id or "") != expected_agent_id:
                return _result(allowed=False, reason_code="delegation_parent_action_agent_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            if str(current_event.event_type or "").strip().lower() not in AUTHORITATIVE_PARENT_ACTION_EVENT_TYPES:
                return _result(allowed=False, reason_code="delegation_parent_action_event_type_invalid", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            event_metadata = dict(current_event.metadata_json or {})
            event_decision = str(current_event.decision or event_metadata.get("decision") or "").strip().lower()
            if event_decision not in AUTHORITATIVE_PARENT_ACTION_DECISIONS:
                return _result(allowed=False, reason_code="delegation_parent_action_decision_not_allowed", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            if "capability_token_id" not in event_metadata or "delegation_edge_id" not in event_metadata:
                return _result(allowed=False, reason_code="delegation_parent_action_authority_binding_missing", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            bound_token_id = str(event_metadata.get("capability_token_id") or "").strip()
            bound_edge_id = str(event_metadata.get("delegation_edge_id") or "").strip() or None
            if not bound_token_id:
                return _result(allowed=False, reason_code="delegation_parent_action_authority_binding_missing", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            if bound_token_id != parent_token_ids[hop_index]:
                return _result(allowed=False, reason_code="delegation_parent_action_token_binding_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            expected_incoming_edge_id = (
                delegation_ids[hop_index + 1]
                if hop_index + 1 < len(delegation_ids)
                else None
            )
            if bound_edge_id != expected_incoming_edge_id:
                return _result(allowed=False, reason_code="delegation_parent_action_edge_binding_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            event_system_id = str(current_event.ai_system_id or "").strip() or None
            if ai_system_id and event_system_id is None:
                return _result(allowed=False, reason_code="delegation_parent_action_system_unbound", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            if ai_system_id and event_system_id != ai_system_id:
                return _result(allowed=False, reason_code="delegation_parent_action_system_mismatch", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            current_action_id = str(current_event.parent_action_id or "").strip()
            if hop_index < len(parent_agent_ids) - 1 and not current_action_id:
                return _result(allowed=False, reason_code="delegation_parent_action_disconnected", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)

        if current_action_id:
            if current_action_id in visited_actions:
                return _result(allowed=False, reason_code="delegation_parent_action_cycle_detected", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)
            return _result(allowed=False, reason_code="delegation_parent_action_over_bound", claimed_depth=claimed_depth, derived_depth=derived_depth, parent_agent_id=immediate_parent_agent_id, delegation_ids=delegation_ids, stored_depths=stored_depths, parent_agent_ids=parent_agent_ids)

    return _result(
        allowed=True,
        reason_code=("delegation_chain_verified" if delegation_ids else "delegation_chain_root"),
        claimed_depth=claimed_depth,
        derived_depth=derived_depth,
        parent_agent_id=immediate_parent_agent_id,
        delegation_ids=delegation_ids,
        stored_depths=stored_depths,
        parent_agent_ids=parent_agent_ids,
    )
