"""Evidence-first, bounded Phase 7 AI activity lineage projections.

The service is intentionally relational and action-centric.  It materializes
only references and safe summaries over Phase 1-6 authorities; it never turns
the projection into a second decision, receipt, policy, or evidence store.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Iterable, Mapping

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.db.models.action_integrity import DelegationContextV2, ExpectedOutcomeV2, OutcomeVerificationV2
from app.db.models.activity_lineage import (
    ActivityLineage,
    Investigation,
    InvestigationFinding,
    LineageEdge,
    LineageNode,
)
from app.db.models.continuous_assurance import (
    ControlAssertion,
    DriftSignal,
    ValidationEvidenceBundle,
    ValidationRun,
)
from app.db.models.evidence import EvidenceNode, ExecutionReceipt
from app.db.models.native_control import NativeControlSelection
from app.db.models.instruction_tool_provenance import ToolActionProvenanceBinding
from app.db.models.runtime_intelligence import RuntimeEvent
from app.services.action_integrity.action_detail import build_action_detail
from app.services.action_integrity.delegation_lifecycle import DELEGATION_CONTEXT_DOMAIN, DELEGATION_SIGNING_PURPOSE
from app.services.action_integrity.lifecycle_persistence import EXPECTED_OUTCOME_DOMAIN
from app.services.action_integrity.signing import verify_signed_object


MAX_LINEAGE_DEPTH = 6
MAX_LINEAGE_RESULTS = 200
DEFAULT_LINEAGE_DEPTH = 3
DEFAULT_LINEAGE_RESULTS = 100
MAX_SEARCH_WINDOW_RESULTS = 200
_INVESTIGATION_QUERY_FIELDS = frozenset({
    "action_id", "actor", "executing_principal", "represented_subject", "agent", "tool",
    "mcp_server", "mcp_tool", "resource", "target", "destination", "provider", "decision",
    "integrity_status", "drift_type", "control_point", "validation_state",
})

_CERTAINTY_RANK = {"UNKNOWN": 0, "INFERRED": 1, "CORRELATED": 2, "CONFIRMED": 3}
_QUESTION_ORDER = (
    "originating_actor", "executing_principal", "represented_subject", "participating_agents",
    "model_or_runtime", "tools_or_services", "resources_targets_destinations", "purpose_and_authority",
    "policy_decision", "approval", "authorised", "executed", "execution_drift",
    "expected_controls", "actual_controls", "control_assurance", "evidence", "persistent_effect",
    "expected_outcome", "observed_outcome",
)


def _utc_iso(value: datetime | str | None) -> str | None:
    if isinstance(value, str):
        return value
    if value is None:
        return None
    aware = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return aware.isoformat()


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _bounded_text(value: Any, *, maximum: int = 255, fallback: str = "Unknown") -> str:
    if isinstance(value, str):
        normalized = " ".join(value.split())
    elif value is None:
        normalized = ""
    else:
        normalized = " ".join(str(value).split())
    return normalized[:maximum] if normalized else fallback


def _observation_value(card: Mapping[str, Any] | None) -> Any | None:
    return card.get("value") if isinstance(card, Mapping) and card.get("state") == "OBSERVED" else None


def _observation_refs(card: Mapping[str, Any] | None) -> list[str]:
    if not isinstance(card, Mapping) or card.get("state") != "OBSERVED":
        return []
    return [str(value) for value in card.get("evidence_refs", []) if isinstance(value, str)][:100]


def _unknown_answer(reason: str) -> dict[str, Any]:
    return {"state": "UNKNOWN", "value": None, "evidence_refs": [], "reason_code": reason}


def _answer(value: Any, *, state: str, evidence_refs: Iterable[str] = (), reason_code: str | None = None) -> dict[str, Any]:
    refs = list(dict.fromkeys(str(item) for item in evidence_refs if item))[:100]
    if state == "UNKNOWN" or value is None or value == []:
        return _unknown_answer(reason_code or "evidence_unavailable")
    return {"state": state, "value": value, "evidence_refs": refs, "reason_code": reason_code}


def _safe_query_map(value: Mapping[str, Any] | None, *, field_name: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, raw in dict(value or {}).items():
        if key not in _INVESTIGATION_QUERY_FIELDS:
            raise ValueError(f"{field_name} contains unsupported key: {key}")
        values = raw if isinstance(raw, list) else [raw]
        if len(values) > 100 or any(not isinstance(item, str) or not item.strip() or len(item) > 255 for item in values):
            raise ValueError(f"{field_name}.{key} must contain bounded reference values")
        normalized = [item.strip() for item in values]
        result[key] = normalized if isinstance(raw, list) else normalized[0]
    return result


def validate_lineage_bounds(*, depth: int, limit: int) -> tuple[int, int]:
    if not isinstance(depth, int) or not 0 <= depth <= MAX_LINEAGE_DEPTH:
        raise ValueError(f"depth must be between 0 and {MAX_LINEAGE_DEPTH}")
    if not isinstance(limit, int) or not 1 <= limit <= MAX_LINEAGE_RESULTS:
        raise ValueError(f"limit must be between 1 and {MAX_LINEAGE_RESULTS}")
    return depth, limit


@dataclass(frozen=True, slots=True)
class LineageQuery:
    action_id: str | None = None
    authority_type: str | None = None
    authority_id: str | None = None
    node_type: str | None = None
    certainty: str | None = None
    actor: str | None = None
    executing_principal: str | None = None
    represented_subject: str | None = None
    agent: str | None = None
    tool: str | None = None
    mcp_server: str | None = None
    mcp_tool: str | None = None
    resource: str | None = None
    target: str | None = None
    destination: str | None = None
    provider: str | None = None
    decision: str | None = None
    integrity_status: str | None = None
    drift_type: str | None = None
    control_point: str | None = None
    validation_state: str | None = None
    time_from: datetime | None = None
    time_to: datetime | None = None
    limit: int = 50

    def validated(self) -> "LineageQuery":
        validate_lineage_bounds(depth=0, limit=self.limit)
        if self.time_from and self.time_to and self.time_from > self.time_to:
            raise ValueError("time_from must not be after time_to")
        for name in (
            "action_id", "authority_type", "authority_id", "node_type", "certainty", "actor",
            "executing_principal", "represented_subject", "agent", "tool", "mcp_server", "mcp_tool",
            "resource", "target", "destination", "provider", "decision", "integrity_status", "drift_type",
            "control_point", "validation_state",
        ):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip() or len(value) > 255):
                raise ValueError(f"{name} must be a bounded non-empty string")
        return self


@dataclass(frozen=True, slots=True)
class _NodeSpec:
    key: str
    node_type: str
    authority_type: str
    authority_id: str
    label: str
    certainty: str
    evidence_quality: str = "UNKNOWN"
    evidence_refs: tuple[str, ...] = ()
    safe_attributes: Mapping[str, Any] | None = None
    occurred_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class _EdgeSpec:
    key: str
    from_key: str
    to_key: str
    edge_type: str
    certainty: str
    evidence_quality: str = "UNKNOWN"
    evidence_refs: tuple[str, ...] = ()
    safe_attributes: Mapping[str, Any] | None = None
    occurred_at: datetime | None = None


class _GraphBuilder:
    def __init__(self) -> None:
        self.nodes: dict[str, _NodeSpec] = {}
        self.edges: dict[str, _EdgeSpec] = {}
        self.blind_spots: list[str] = []

    def add_node(self, spec: _NodeSpec) -> str:
        existing = self.nodes.get(spec.key)
        if existing is None or _CERTAINTY_RANK[spec.certainty] > _CERTAINTY_RANK[existing.certainty]:
            self.nodes[spec.key] = spec
        return spec.key

    def add_edge(self, spec: _EdgeSpec) -> None:
        if spec.from_key in self.nodes and spec.to_key in self.nodes:
            existing = self.edges.get(spec.key)
            if existing is None or _CERTAINTY_RANK[spec.certainty] > _CERTAINTY_RANK[existing.certainty]:
                self.edges[spec.key] = spec

    def blind(self, reason: str) -> None:
        if reason and reason not in self.blind_spots:
            self.blind_spots.append(reason)


def _node_key(authority_type: str, authority_id: str) -> str:
    return _canonical_hash({"authority_type": authority_type, "authority_id": authority_id})


def _add_reference_node(
    graph: _GraphBuilder,
    *,
    node_type: str,
    authority_type: str,
    authority_id: str,
    label: str,
    certainty: str,
    evidence_quality: str = "UNKNOWN",
    evidence_refs: Iterable[str] = (),
    safe_attributes: Mapping[str, Any] | None = None,
    occurred_at: datetime | None = None,
) -> str:
    key = _node_key(authority_type, authority_id)
    return graph.add_node(_NodeSpec(
        key=key,
        node_type=node_type,
        authority_type=authority_type,
        authority_id=_bounded_text(authority_id, maximum=255),
        label=_bounded_text(label),
        certainty=certainty,
        evidence_quality=_bounded_text(evidence_quality, maximum=64, fallback="UNKNOWN"),
        evidence_refs=tuple(dict.fromkeys(str(item) for item in evidence_refs if item))[:100],
        safe_attributes=dict(safe_attributes or {}),
        occurred_at=occurred_at,
    ))


def _edge_key(from_key: str, edge_type: str, to_key: str, discriminator: str = "") -> str:
    return _canonical_hash({"from": from_key, "type": edge_type, "to": to_key, "d": discriminator})


def _event_action_id(event: RuntimeEvent, detail: Mapping[str, Any]) -> str:
    identity = detail.get("identity") if isinstance(detail.get("identity"), Mapping) else {}
    value = identity.get("canonical_action_id") or identity.get("action_id")
    if isinstance(value, str) and value:
        return value
    if event.entity_type in {"action", "canonical_action"} and event.entity_id:
        return str(event.entity_id)
    return f"runtime-event:{event.event_id}"


def _safe_card_attributes(card: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(card, Mapping):
        return {"state": "UNKNOWN"}
    return {
        "state": str(card.get("state") or "UNKNOWN"),
        "reason_code": card.get("reason_code") if isinstance(card.get("reason_code"), str) else None,
        "occurred_at": card.get("occurred_at") if isinstance(card.get("occurred_at"), str) else None,
    }


def _safe_authority_attributes(card: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return only reviewed, non-content authority metadata from Action Detail."""
    result = _safe_card_attributes(card)
    value = _observation_value(card)
    if not isinstance(value, Mapping):
        return result
    allowed = {
        "action_id", "approval_binding_id", "approval_request_id", "authoritative_decision",
        "canonical_action_hash", "control_plan_digest", "decision", "decision_receipt_id",
        "decision_version", "expires_at", "matched_policy", "material_fields_hash",
        "policy_epoch", "policy_version", "policy_version_id", "receipt_id", "status",
    }
    for key in allowed:
        item = value.get(key)
        if isinstance(item, (str, int, float, bool)) or item is None:
            result[key] = item
    return result


def _add_card_node(
    graph: _GraphBuilder,
    *,
    action_key: str,
    action_id: str,
    card: Mapping[str, Any] | None,
    field: str,
    node_type: str,
    edge_type: str,
    direction: str = "to_action",
) -> str | None:
    value = _observation_value(card)
    if value is None:
        graph.blind(f"{field}_unknown")
        return None
    values = value if isinstance(value, list) else [value]
    first_key: str | None = None
    for index, item in enumerate(values[:25]):
        label = _bounded_text(item)
        authority_id = f"{action_id}:{field}:{index}"
        node_key = _add_reference_node(
            graph,
            node_type=node_type,
            authority_type=f"CanonicalAIAction.{field}",
            authority_id=authority_id,
            label=label,
            certainty="CONFIRMED",
            evidence_quality="NATIVE_SEMANTIC",
            evidence_refs=_observation_refs(card),
            safe_attributes={"field": field},
        )
        if first_key is None:
            first_key = node_key
        from_key, to_key = (node_key, action_key) if direction == "to_action" else (action_key, node_key)
        graph.add_edge(_EdgeSpec(
            key=_edge_key(from_key, edge_type, to_key, str(index)), from_key=from_key, to_key=to_key,
            edge_type=edge_type, certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
            evidence_refs=tuple(_observation_refs(card)), safe_attributes={"field": field},
        ))
    return first_key


def _verified_delegation(db: Session, *, tenant_id: str, row: DelegationContextV2) -> bool:
    provider = db.info.get("phase5_signing_provider")
    if provider is None or row.reconstruction_status != "VERIFIED":
        return False
    envelope = dict(row.signed_envelope or {})
    return bool(
        verify_signed_object(
            provider,
            purpose=DELEGATION_SIGNING_PURPOSE,
            domain=DELEGATION_CONTEXT_DOMAIN,
            tenant_id=tenant_id,
            value=envelope,
            current_authority=False,
        )
        and envelope.get("tenant_id") == tenant_id
        and envelope.get("delegation_context_id") == row.delegation_context_id
        and envelope.get("parent_action_id") == row.parent_action_id
        and envelope.get("delegated_action_id") == row.delegated_action_id
        and envelope.get("source_principal_ref") == row.source_principal_ref
        and envelope.get("destination_principal_ref") == row.destination_principal_ref
    )


def _select_connected_events(
    db: Session,
    *,
    tenant_id: str,
    seed: RuntimeEvent,
    depth: int,
    limit: int,
) -> tuple[list[RuntimeEvent], bool]:
    clauses = [RuntimeEvent.event_id == seed.event_id]
    if seed.chain_id:
        clauses.append(RuntimeEvent.chain_id == seed.chain_id)
    if seed.entity_id:
        clauses.extend((RuntimeEvent.entity_id == seed.entity_id, RuntimeEvent.parent_action_id == seed.entity_id))
    if seed.parent_action_id:
        clauses.extend((RuntimeEvent.entity_id == seed.parent_action_id, RuntimeEvent.parent_action_id == seed.parent_action_id))
    candidates = list(db.scalars(
        select(RuntimeEvent)
        .where(RuntimeEvent.tenant_id == tenant_id, or_(*clauses))
        .order_by(RuntimeEvent.created_at.asc(), RuntimeEvent.event_id.asc())
        .limit(limit + 1)
    ).all())
    truncated = len(candidates) > limit
    candidates = candidates[:limit]
    if depth == 0:
        return [seed], truncated
    by_action = {str(row.entity_id): row for row in candidates if row.entity_id}
    selected: dict[str, RuntimeEvent] = {seed.event_id: seed}
    frontier = {str(seed.entity_id or "")}
    if seed.parent_action_id:
        frontier.add(str(seed.parent_action_id))
    for _ in range(depth):
        next_frontier: set[str] = set()
        for row in candidates:
            if row.event_id in selected:
                continue
            same_chain = bool(seed.chain_id and row.chain_id == seed.chain_id)
            related = bool(
                (row.parent_action_id and row.parent_action_id in frontier)
                or (row.entity_id and row.entity_id in frontier)
                or (row.entity_id and any(item.parent_action_id == row.entity_id for item in selected.values()))
            )
            if same_chain or related:
                selected[row.event_id] = row
                if row.entity_id:
                    next_frontier.add(str(row.entity_id))
        if not next_frontier:
            break
        frontier = next_frontier
    # A directly named parent remains eligible even when it has a different
    # chain id; the explicit parent identifier is the correlation authority.
    if seed.parent_action_id and seed.parent_action_id in by_action:
        selected[by_action[seed.parent_action_id].event_id] = by_action[seed.parent_action_id]
    rows = sorted(selected.values(), key=lambda row: (row.created_at, row.event_id))[:limit]
    return rows, truncated or len(selected) > limit


def _build_specs(
    db: Session,
    *,
    tenant_id: str,
    events: list[RuntimeEvent],
) -> tuple[_GraphBuilder, dict[str, dict[str, Any]], dict[str, str]]:
    graph = _GraphBuilder()
    details: dict[str, dict[str, Any]] = {}
    action_keys: dict[str, str] = {}
    for event in events:
        detail = build_action_detail(db, tenant_id=tenant_id, runtime_event_id=event.event_id)
        if detail is None:
            continue
        details[event.event_id] = detail
        action_id = _event_action_id(event, detail)
        action_refs = detail.get("identity", {}).get("evidence_node_ids", [])
        action_observed = any(
            isinstance(card, Mapping) and card.get("state") == "OBSERVED"
            for card in detail.get("action", {}).values()
        )
        integrity_value = _observation_value(detail.get("execution", {}).get("material_integrity"))
        drift_values = _observation_value(detail.get("execution", {}).get("drift_fields")) or []
        action_key = _add_reference_node(
            graph,
            node_type="ACTION",
            authority_type="CanonicalAIAction" if not action_id.startswith("runtime-event:") else "RuntimeEvent",
            authority_id=action_id if not action_id.startswith("runtime-event:") else event.event_id,
            label=_bounded_text(_observation_value(detail.get("action", {}).get("operation")), fallback=event.event_type),
            certainty="CONFIRMED" if action_observed and action_refs else "CORRELATED",
            evidence_quality="NATIVE_SEMANTIC" if action_refs else "UNKNOWN",
            evidence_refs=action_refs,
            safe_attributes={
                "runtime_event_id": event.event_id,
                "source_surface": event.source_surface,
                "decision": event.decision,
                "integrity_status": integrity_value.get("result") if isinstance(integrity_value, Mapping) else "UNVERIFIED",
                "drift_fields": list(drift_values) if isinstance(drift_values, list) else [],
                "chain_id": event.chain_id,
                "parent_action_id": event.parent_action_id,
            },
            occurred_at=event.created_at,
        )
        action_keys[action_id] = action_key
        context = detail.get("context", {})
        action = detail.get("action", {})
        actor_key = _add_card_node(
            graph, action_key=action_key, action_id=action_id, card=context.get("actor_principal"),
            field="actor_principal", node_type="HUMAN", edge_type="INITIATED",
        )
        executing_key = _add_card_node(
            graph, action_key=action_key, action_id=action_id, card=context.get("executing_identity"),
            field="executing_principal", node_type="SERVICE", edge_type="EXECUTED_BY", direction="from_action",
        )
        _add_card_node(
            graph, action_key=action_key, action_id=action_id, card=context.get("represented_subjects"),
            field="represented_subject", node_type="EXTERNAL_USER", edge_type="REPRESENTS",
        )
        tool_key = _add_card_node(
            graph, action_key=action_key, action_id=action_id, card=action.get("tool_or_service"),
            field="tool_or_service", node_type="TOOL", edge_type="USED_TOOL", direction="from_action",
        )
        for field, node_type, edge_type in (
            ("resources", "RESOURCE", "TARGETED"), ("targets", "TARGET", "TARGETED"),
            ("destinations", "DESTINATION", "SENT_TO"),
        ):
            _add_card_node(
                graph, action_key=action_key, action_id=action_id, card=action.get(field),
                field=field, node_type=node_type, edge_type=edge_type, direction="from_action",
            )
        if event.application or event.app_id:
            app_id = str(event.app_id or event.application)
            app_key = _add_reference_node(
                graph, node_type="AI_APPLICATION", authority_type="RuntimeEvent.application",
                authority_id=app_id, label=str(event.application or event.app_id), certainty="CORRELATED",
                evidence_quality="CORRELATED", evidence_refs=event.evidence_node_ids,
                safe_attributes={"source_surface": event.source_surface}, occurred_at=event.created_at,
            )
            if actor_key:
                graph.add_edge(_EdgeSpec(
                    key=_edge_key(actor_key, "CALLED", app_key, action_id), from_key=actor_key, to_key=app_key,
                    edge_type="CALLED", certainty="CORRELATED", evidence_quality="CORRELATED",
                    evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
                ))
            graph.add_edge(_EdgeSpec(
                key=_edge_key(app_key, "CALLED", action_key, action_id), from_key=app_key, to_key=action_key,
                edge_type="CALLED", certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
            ))
        if event.agent_id:
            agent_key = _add_reference_node(
                graph, node_type="AGENT", authority_type="RuntimeEvent.agent_id", authority_id=event.agent_id,
                label=event.agent_id, certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=event.evidence_node_ids, occurred_at=event.created_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "EXECUTED_BY", agent_key, action_id), from_key=action_key, to_key=agent_key,
                edge_type="EXECUTED_BY", certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
            ))
        metadata = event.metadata_json if isinstance(event.metadata_json, Mapping) else {}
        runtime_ref = metadata.get("runtime") or metadata.get("runtime_ref") or metadata.get("provider_runtime")
        if isinstance(runtime_ref, str) and runtime_ref:
            runtime_key = _add_reference_node(
                graph, node_type="RUNTIME", authority_type="RuntimeEvent.runtime", authority_id=runtime_ref,
                label=runtime_ref, certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=event.evidence_node_ids, occurred_at=event.created_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "ROUTED_THROUGH", runtime_key, action_id), from_key=action_key,
                to_key=runtime_key, edge_type="ROUTED_THROUGH", certainty="CORRELATED",
                evidence_quality="CORRELATED", evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
            ))
        model_ref = metadata.get("model") or metadata.get("model_ref")
        if isinstance(model_ref, str) and model_ref:
            model_key = _add_reference_node(
                graph, node_type="MODEL", authority_type="RuntimeEvent.model", authority_id=model_ref,
                label=model_ref, certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=event.evidence_node_ids, occurred_at=event.created_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "USED_MODEL", model_key, action_id), from_key=action_key, to_key=model_key,
                edge_type="USED_MODEL", certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
            ))
        mcp_server_ref = metadata.get("mcp_server_id") or metadata.get("mcp_server_ref")
        mcp_tool_ref = (
            metadata.get("mcp_tool_id") or metadata.get("mcp_tool_name") or metadata.get("mcp_tool_ref")
        )
        mcp_server_key: str | None = None
        if isinstance(mcp_server_ref, str) and mcp_server_ref:
            mcp_server_key = _add_reference_node(
                graph, node_type="MCP_SERVER", authority_type="RuntimeEvent.mcp_server_id",
                authority_id=mcp_server_ref, label=mcp_server_ref, certainty="CORRELATED",
                evidence_quality="CORRELATED", evidence_refs=event.evidence_node_ids,
                occurred_at=event.created_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "ROUTED_THROUGH", mcp_server_key, action_id),
                from_key=action_key, to_key=mcp_server_key, edge_type="ROUTED_THROUGH",
                certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
            ))
        if isinstance(mcp_tool_ref, str) and mcp_tool_ref:
            mcp_tool_key = _add_reference_node(
                graph, node_type="MCP_TOOL", authority_type="RuntimeEvent.mcp_tool",
                authority_id=mcp_tool_ref, label=mcp_tool_ref, certainty="CORRELATED",
                evidence_quality="CORRELATED", evidence_refs=event.evidence_node_ids,
                occurred_at=event.created_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "USED_TOOL", mcp_tool_key, action_id),
                from_key=action_key, to_key=mcp_tool_key, edge_type="USED_TOOL",
                certainty="CORRELATED", evidence_quality="CORRELATED",
                evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
            ))
            if mcp_server_key is not None:
                graph.add_edge(_EdgeSpec(
                    key=_edge_key(mcp_server_key, "USED_TOOL", mcp_tool_key, action_id),
                    from_key=mcp_server_key, to_key=mcp_tool_key, edge_type="USED_TOOL",
                    certainty="CORRELATED", evidence_quality="CORRELATED",
                    evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
                ))
        tool_provenance = db.scalar(
            select(ToolActionProvenanceBinding).where(
                ToolActionProvenanceBinding.tenant_id == tenant_id,
                ToolActionProvenanceBinding.action_id == action_id,
            )
        )
        if tool_provenance is not None:
            binding_key = _add_reference_node(
                graph, node_type="TOOL", authority_type="ToolPrincipalBinding",
                authority_id=tool_provenance.tool_binding_id, label="bound dynamic tool",
                certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                evidence_refs=tuple(), safe_attributes={
                    "tool_identity_hash": tool_provenance.tool_identity_hash,
                    "material_fingerprint": tool_provenance.material_fingerprint,
                    "schema_fingerprint": tool_provenance.schema_fingerprint,
                    "lifecycle_version": tool_provenance.lifecycle_version,
                }, occurred_at=event.created_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "USED_TOOL", binding_key, tool_provenance.id),
                from_key=action_key, to_key=binding_key, edge_type="USED_TOOL",
                certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                evidence_refs=tuple(), occurred_at=event.created_at,
            ))
            provenance_key = _add_reference_node(
                graph, node_type="RESOURCE", authority_type="InstructionProvenanceSet",
                authority_id=tool_provenance.provenance_set_id, label="instruction provenance",
                certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                evidence_refs=tuple(), safe_attributes={
                    "provenance_record_ids": list(tool_provenance.provenance_record_ids or [])[:128],
                    "decision_receipt_id": tool_provenance.decision_receipt_id,
                    "execution_permit_id": tool_provenance.execution_permit_id,
                    "execution_receipt_id": tool_provenance.execution_receipt_id,
                }, occurred_at=event.created_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(binding_key, "CONTROLLED_BY", provenance_key, tool_provenance.id),
                from_key=binding_key, to_key=provenance_key, edge_type="CONTROLLED_BY",
                certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                evidence_refs=tuple(), occurred_at=event.created_at,
            ))
        identity = detail.get("identity", {})
        for field, node_type, edge_type in (
            ("decision_receipt_id", "DECISION_RECEIPT", "AUTHORISED_BY"),
            ("approval_request_id", "APPROVAL", "APPROVED_BY"),
            ("approval_binding_id", "APPROVAL", "APPROVED_BY"),
        ):
            ref = identity.get(field)
            if isinstance(ref, str) and ref:
                card_name = {
                    "decision_receipt_id": "decision_receipt",
                    "approval_request_id": "approval_request",
                    "approval_binding_id": "approval_binding",
                }[field]
                card = detail.get("authorisation", {}).get(card_name)
                certainty = "CONFIRMED" if _observation_value(card) is not None else "UNKNOWN"
                node_key = _add_reference_node(
                    graph, node_type=node_type, authority_type=field, authority_id=ref, label=field.replace("_id", ""),
                    certainty=certainty, evidence_quality="NATIVE_SEMANTIC" if certainty == "CONFIRMED" else "UNKNOWN",
                    evidence_refs=_observation_refs(card), safe_attributes=_safe_authority_attributes(card),
                )
                graph.add_edge(_EdgeSpec(
                    key=_edge_key(action_key, edge_type, node_key, ref), from_key=action_key, to_key=node_key,
                    edge_type=edge_type, certainty=certainty,
                    evidence_quality="NATIVE_SEMANTIC" if certainty == "CONFIRMED" else "UNKNOWN",
                    evidence_refs=tuple(_observation_refs(card)),
                ))
        policy_card = detail.get("authorisation", {}).get("policy")
        policy_value = _observation_value(policy_card)
        if isinstance(policy_value, Mapping):
            policy_ref = _bounded_text(
                policy_value.get("policy_version_id") or policy_value.get("policy_version"),
                maximum=255, fallback=f"action:{action_id}:policy",
            )
            policy_key = _add_reference_node(
                graph, node_type="POLICY", authority_type="ActionDetail.policy", authority_id=policy_ref,
                label=policy_ref, certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                evidence_refs=_observation_refs(policy_card), safe_attributes=_safe_authority_attributes(policy_card),
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "AUTHORISED_BY", policy_key, policy_ref),
                from_key=action_key, to_key=policy_key, edge_type="AUTHORISED_BY",
                certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                evidence_refs=tuple(_observation_refs(policy_card)),
            ))
        for ref in identity.get("execution_permit_ids", []) or []:
            card = detail.get("authorisation", {}).get("execution_permits")
            certainty = "CONFIRMED" if _observation_value(card) else "UNKNOWN"
            node_key = _add_reference_node(
                graph, node_type="EXECUTION_PERMIT", authority_type="ExecutionPermitV2", authority_id=str(ref),
                label="Execution permit", certainty=certainty,
                evidence_quality="NATIVE_SEMANTIC" if certainty == "CONFIRMED" else "UNKNOWN",
                evidence_refs=_observation_refs(card), safe_attributes=_safe_card_attributes(card),
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "PERMITTED_BY", node_key, str(ref)), from_key=action_key, to_key=node_key,
                edge_type="PERMITTED_BY", certainty=certainty,
                evidence_quality="NATIVE_SEMANTIC" if certainty == "CONFIRMED" else "UNKNOWN",
                evidence_refs=tuple(_observation_refs(card)),
            ))
        for ref in identity.get("execution_receipt_ids", []) or []:
            card = detail.get("execution", {}).get("execution_receipts")
            certainty = "CONFIRMED" if _observation_value(card) else "UNKNOWN"
            node_key = _add_reference_node(
                graph, node_type="EXECUTION_RECEIPT", authority_type="ExecutionReceiptV2", authority_id=str(ref),
                label="Execution receipt", certainty=certainty,
                evidence_quality=_bounded_text(_observation_value(detail.get("execution", {}).get("evidence_quality")), maximum=64, fallback="UNKNOWN"),
                evidence_refs=_observation_refs(card), safe_attributes=_safe_card_attributes(card),
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "PRODUCED", node_key, str(ref)), from_key=action_key, to_key=node_key,
                edge_type="PRODUCED", certainty=certainty,
                evidence_quality="NATIVE_SEMANTIC" if certainty == "CONFIRMED" else "UNKNOWN",
                evidence_refs=tuple(_observation_refs(card)),
            ))
        for stage, node_type, edge_type in (
            ("persistent_effect", "PERSISTENT_EFFECT", "CREATED_PERSISTENT_EFFECT"),
            ("outcome", "OUTCOME", "PRODUCED"),
        ):
            timeline_row = next((row for row in detail.get("timeline", []) if row.get("event_type") == stage.upper()), None)
            if isinstance(timeline_row, Mapping) and timeline_row.get("state") == "OBSERVED":
                value = timeline_row.get("value") if isinstance(timeline_row.get("value"), Mapping) else {}
                ref = value.get("effect_id") if stage == "persistent_effect" else value.get("verification_id")
                if isinstance(ref, str) and ref:
                    node_key = _add_reference_node(
                        graph, node_type=node_type, authority_type=stage, authority_id=ref,
                        label=stage.replace("_", " ").title(), certainty="CONFIRMED",
                        evidence_quality="NATIVE_SEMANTIC", evidence_refs=timeline_row.get("evidence_node_ids", []),
                        safe_attributes={"state": value.get("state") or value.get("result")},
                    )
                    graph.add_edge(_EdgeSpec(
                        key=_edge_key(action_key, edge_type, node_key, ref), from_key=action_key, to_key=node_key,
                        edge_type=edge_type, certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                        evidence_refs=tuple(timeline_row.get("evidence_node_ids", [])),
                    ))
        if tool_key is None:
            graph.blind("tool_or_service_unknown")
        if executing_key is None:
            graph.blind("executing_principal_unknown")

    # Exact parent identifiers are authoritative lineage; shared timing is not.
    for event in events:
        detail = details.get(event.event_id)
        if detail is None:
            continue
        child_id = _event_action_id(event, detail)
        if event.parent_action_id and event.parent_action_id in action_keys and child_id in action_keys:
            parent_key, child_key = action_keys[event.parent_action_id], action_keys[child_id]
            graph.add_edge(_EdgeSpec(
                key=_edge_key(parent_key, "PARENT_OF", child_key, event.event_id), from_key=parent_key, to_key=child_key,
                edge_type="PARENT_OF", certainty="CONFIRMED", evidence_quality="NATIVE_SEMANTIC",
                evidence_refs=tuple(event.evidence_node_ids), occurred_at=event.created_at,
            ))

    # Signed Phase 5 delegation is projected only after cryptographic and
    # semantic binding verification.  Otherwise the relationship is unknown.
    action_ids = list(action_keys)
    delegations = list(db.scalars(
        select(DelegationContextV2).where(
            DelegationContextV2.tenant_id == tenant_id,
            or_(DelegationContextV2.parent_action_id.in_(action_ids), DelegationContextV2.delegated_action_id.in_(action_ids)),
        ).limit(MAX_LINEAGE_RESULTS)
    ).all()) if action_ids else []
    for row in delegations:
        verified = _verified_delegation(db, tenant_id=tenant_id, row=row)
        certainty = "CONFIRMED" if verified else "UNKNOWN"
        source_key = _add_reference_node(
            graph, node_type="AGENT", authority_type="DelegationContextV2.source_principal_ref",
            authority_id=f"{row.delegation_context_id}:source", label=row.source_principal_ref,
            certainty=certainty, evidence_quality="NATIVE_SEMANTIC" if verified else "UNKNOWN",
            safe_attributes={"delegation_context_id": row.delegation_context_id, "depth": row.depth},
        )
        destination_key = _add_reference_node(
            graph, node_type="AGENT", authority_type="DelegationContextV2.destination_principal_ref",
            authority_id=f"{row.delegation_context_id}:destination", label=row.destination_principal_ref,
            certainty=certainty, evidence_quality="NATIVE_SEMANTIC" if verified else "UNKNOWN",
            safe_attributes={"delegation_context_id": row.delegation_context_id, "depth": row.depth},
        )
        graph.add_edge(_EdgeSpec(
            key=_edge_key(source_key, "DELEGATED_TO", destination_key, row.delegation_context_id),
            from_key=source_key, to_key=destination_key, edge_type="DELEGATED_TO", certainty=certainty,
            evidence_quality="NATIVE_SEMANTIC" if verified else "UNKNOWN",
            safe_attributes={"authority_scope_hash": row.authority_scope_hash, "depth": row.depth},
        ))
        if not verified:
            graph.blind("delegation_authority_unverified")

    # Expected/actual controls and Phase 6 state are correlated through the
    # exact selection required capability.  Correlation is never rendered as
    # independent proof that a configured control participated.
    for event in events:
        detail = details.get(event.event_id)
        if detail is None:
            continue
        refs = (event.metadata_json or {}).get("action_integrity_refs", {}) if isinstance(event.metadata_json, Mapping) else {}
        selection_id = refs.get("control_selection_id") if isinstance(refs, Mapping) else None
        selection = db.scalar(select(NativeControlSelection).where(
            NativeControlSelection.tenant_id == tenant_id,
            NativeControlSelection.selection_id == selection_id,
        )) if isinstance(selection_id, str) else None
        action_id = _event_action_id(event, detail)
        action_key = action_keys[action_id]
        if selection is None:
            graph.blind("control_plan_unknown")
            continue
        expected = list(dict.fromkeys(str(value) for value in (selection.required_capabilities or []) if value))
        satisfied = list(dict.fromkeys(str(value) for value in (selection.satisfied_capabilities or []) if value))
        control_refs = ([selection.semantic_primary_control_point_id] if selection.semantic_primary_control_point_id else [])
        control_refs += list(selection.selected_mandatory_floors or [])
        if selection.primary_control_point_id:
            control_refs.append(selection.primary_control_point_id)
        for control_ref in dict.fromkeys(str(value) for value in control_refs if value):
            control_key = _add_reference_node(
                graph, node_type="CONTROL_POINT", authority_type="NativeControlSelection.control_point",
                authority_id=f"{selection.selection_id}:{control_ref}", label=control_ref, certainty="CORRELATED",
                evidence_quality="CORRELATED",
                safe_attributes={
                    "selection_id": selection.selection_id,
                    "expected": True,
                    "actual": False,
                    "required_capabilities": expected,
                    "satisfied_capabilities": satisfied,
                },
                occurred_at=selection.selected_at,
            )
            graph.add_edge(_EdgeSpec(
                key=_edge_key(action_key, "CONTROLLED_BY", control_key, control_ref), from_key=action_key,
                to_key=control_key, edge_type="CONTROLLED_BY", certainty="CORRELATED",
                evidence_quality="CORRELATED",
            ))
        if control_refs:
            graph.blind("actual_control_participation_unknown")
        for capability in expected:
            assertions = list(db.scalars(
                select(ControlAssertion).where(
                    ControlAssertion.tenant_id == tenant_id,
                    ControlAssertion.required_capability == capability,
                ).order_by(ControlAssertion.updated_at.desc()).limit(10)
            ).all())
            if not assertions:
                graph.blind(f"control_assurance_unknown:{capability}")
            for assertion in assertions:
                assertion_key = _add_reference_node(
                    graph, node_type="CONTROL_POINT", authority_type="ControlAssertion",
                    authority_id=assertion.id, label=capability, certainty="CORRELATED",
                    evidence_quality=assertion.required_evidence_level,
                    safe_attributes={
                        "assurance_state": assertion.assurance_state,
                        "last_validation_run_id": assertion.last_validation_run_id,
                        "last_validated_at": _utc_iso(assertion.last_validated_at),
                        "fresh_until": _utc_iso(assertion.fresh_until),
                    },
                    occurred_at=assertion.last_validated_at,
                )
                graph.add_edge(_EdgeSpec(
                    key=_edge_key(action_key, "VALIDATED_BY", assertion_key, assertion.id), from_key=action_key,
                    to_key=assertion_key, edge_type="VALIDATED_BY", certainty="CORRELATED",
                    evidence_quality=assertion.required_evidence_level,
                    safe_attributes={"assurance_state": assertion.assurance_state},
                ))
                if assertion.last_validation_run_id:
                    validation = db.scalar(select(ValidationRun).where(
                        ValidationRun.tenant_id == tenant_id,
                        ValidationRun.id == assertion.last_validation_run_id,
                    ))
                    if validation:
                        validation_evidence = db.scalar(select(ValidationEvidenceBundle).where(
                            ValidationEvidenceBundle.tenant_id == tenant_id,
                            ValidationEvidenceBundle.validation_run_id == validation.id,
                        ))
                        evidence_quality = validation_evidence.evidence_quality if validation_evidence else "UNKNOWN"
                        evidence_refs = list(validation_evidence.evidence_refs or []) if validation_evidence else []
                        validation_key = _add_reference_node(
                            graph, node_type="VALIDATION_RUN", authority_type="ValidationRun",
                            authority_id=validation.id, label=validation.outcome or validation.status,
                            certainty="CONFIRMED", evidence_quality=evidence_quality,
                            evidence_refs=evidence_refs,
                            safe_attributes={"outcome": validation.outcome, "status": validation.status},
                            occurred_at=validation.completed_at,
                        )
                        graph.add_edge(_EdgeSpec(
                            key=_edge_key(assertion_key, "VERIFIED_BY", validation_key, validation.id),
                            from_key=assertion_key, to_key=validation_key, edge_type="VERIFIED_BY",
                            certainty="CONFIRMED", evidence_quality=evidence_quality,
                            evidence_refs=tuple(evidence_refs),
                        ))
                drifts = [
                    row for row in db.scalars(select(DriftSignal).where(
                        DriftSignal.tenant_id == tenant_id,
                        DriftSignal.status == "OPEN",
                    ).order_by(DriftSignal.observed_at.desc()).limit(MAX_LINEAGE_RESULTS)).all()
                    if assertion.id in set(row.affected_assertion_ids or [])
                ][:10]
                for drift in drifts:
                    drift_key = _add_reference_node(
                        graph, node_type="DRIFT_SIGNAL", authority_type="DriftSignal", authority_id=drift.id,
                        label=drift.category, certainty="CONFIRMED", evidence_quality="CORRELATED",
                        safe_attributes={"category": drift.category, "dependency_key": drift.dependency_key, "status": drift.status},
                        occurred_at=drift.observed_at,
                    )
                    graph.add_edge(_EdgeSpec(
                        key=_edge_key(assertion_key, "DRIFTED_FROM", drift_key, drift.id), from_key=assertion_key,
                        to_key=drift_key, edge_type="DRIFTED_FROM", certainty="CONFIRMED",
                        evidence_quality="CORRELATED",
                    ))
    return graph, details, action_keys


def _source_watermark(events: list[RuntimeEvent], details: Mapping[str, Mapping[str, Any]], graph: _GraphBuilder) -> str:
    return _canonical_hash({
        "events": [
            {
                "event_id": row.event_id,
                "created_at": _utc_iso(row.created_at),
                "entity_id": row.entity_id,
                "parent_action_id": row.parent_action_id,
                "detail_identity": details.get(row.event_id, {}).get("identity", {}),
                "timeline_sources": [
                    (item.get("event_type"), item.get("state"), item.get("source_authority_ref"))
                    for item in details.get(row.event_id, {}).get("timeline", [])
                ],
            }
            for row in events
        ],
        "nodes": [(item.key, item.certainty, item.evidence_quality, item.safe_attributes) for item in graph.nodes.values()],
        "edges": [(item.key, item.certainty, item.evidence_quality, item.safe_attributes) for item in graph.edges.values()],
    })


def materialize_activity_lineage(
    db: Session,
    *,
    tenant_id: str,
    runtime_event_id: str,
    depth: int = DEFAULT_LINEAGE_DEPTH,
    limit: int = DEFAULT_LINEAGE_RESULTS,
) -> ActivityLineage | None:
    validate_lineage_bounds(depth=depth, limit=limit)
    seed = db.scalar(select(RuntimeEvent).where(
        RuntimeEvent.tenant_id == tenant_id,
        RuntimeEvent.event_id == runtime_event_id,
    ))
    if seed is None:
        return None
    events, truncated = _select_connected_events(
        db, tenant_id=tenant_id, seed=seed, depth=depth, limit=limit,
    )
    graph, details, action_keys = _build_specs(db, tenant_id=tenant_id, events=events)
    if truncated:
        graph.blind("lineage_result_limit_reached")
    seed_detail = details.get(seed.event_id) or {}
    seed_action_id = _event_action_id(seed, seed_detail)
    child_ids = {str(row.entity_id) for row in events if row.parent_action_id and row.entity_id}
    roots = [action_id for action_id in action_keys if action_id not in child_ids]
    root_action_id = roots[0] if roots else seed_action_id
    lineage_key = _canonical_hash({
        "tenant_id": tenant_id,
        "root_action_id": root_action_id,
        "chain_id": seed.chain_id,
    })
    watermark = _source_watermark(events, details, graph)
    existing = db.scalar(select(ActivityLineage).where(
        ActivityLineage.tenant_id == tenant_id,
        ActivityLineage.lineage_key == lineage_key,
        ActivityLineage.source_watermark == watermark,
    ))
    if existing is not None:
        return existing
    lineage = ActivityLineage(
        tenant_id=tenant_id,
        lineage_key=lineage_key,
        source_watermark=watermark,
        seed_action_id=seed_action_id,
        seed_runtime_event_id=seed.event_id,
        root_action_id=root_action_id,
        status="PARTIAL" if graph.blind_spots else "COMPLETE",
        blind_spots=graph.blind_spots,
    )
    db.add(lineage)
    db.flush()
    node_rows: dict[str, LineageNode] = {}
    for ordinal, spec in enumerate(graph.nodes.values()):
        row = LineageNode(
            tenant_id=tenant_id, lineage_id=lineage.id, node_key=spec.key, node_type=spec.node_type,
            authority_type=spec.authority_type, authority_id=spec.authority_id, label=spec.label,
            certainty=spec.certainty, evidence_quality=spec.evidence_quality,
            evidence_refs=list(spec.evidence_refs), safe_attributes=dict(spec.safe_attributes or {}),
            ordinal=ordinal, occurred_at=spec.occurred_at,
        )
        db.add(row)
        node_rows[spec.key] = row
    db.flush()
    for sequence, spec in enumerate(graph.edges.values()):
        db.add(LineageEdge(
            tenant_id=tenant_id, lineage_id=lineage.id, edge_key=spec.key,
            from_node_id=node_rows[spec.from_key].id, to_node_id=node_rows[spec.to_key].id,
            edge_type=spec.edge_type, certainty=spec.certainty,
            evidence_quality=spec.evidence_quality, evidence_refs=list(spec.evidence_refs),
            safe_attributes=dict(spec.safe_attributes or {}), sequence=sequence, occurred_at=spec.occurred_at,
        ))
    db.flush()
    return lineage


def _serialize_node(node: LineageNode) -> dict[str, Any]:
    return {
        "id": node.id, "node_key": node.node_key, "node_type": node.node_type,
        "authority_type": node.authority_type, "authority_id": node.authority_id,
        "label": node.label, "certainty": node.certainty, "evidence_quality": node.evidence_quality,
        "evidence_refs": list(node.evidence_refs or []), "safe_attributes": dict(node.safe_attributes or {}),
        "ordinal": node.ordinal, "occurred_at": _utc_iso(node.occurred_at),
    }


def _serialize_edge(edge: LineageEdge) -> dict[str, Any]:
    return {
        "id": edge.id, "edge_key": edge.edge_key, "from_node_id": edge.from_node_id,
        "to_node_id": edge.to_node_id, "edge_type": edge.edge_type, "certainty": edge.certainty,
        "evidence_quality": edge.evidence_quality, "evidence_refs": list(edge.evidence_refs or []),
        "safe_attributes": dict(edge.safe_attributes or {}), "sequence": edge.sequence,
        "occurred_at": _utc_iso(edge.occurred_at),
    }


def _comparison_projection(db: Session, *, tenant_id: str, lineage: ActivityLineage) -> dict[str, Any]:
    detail = build_action_detail(db, tenant_id=tenant_id, runtime_event_id=lineage.seed_runtime_event_id)
    if detail is None:
        return {"authorised": {}, "executed": {}, "result": "UNVERIFIED", "drift_fields": [], "evidence_refs": []}
    authorised = {
        field: {
            "state": card.get("state"),
            "value": card.get("value") if card.get("state") == "OBSERVED" else None,
            "evidence_refs": list(card.get("evidence_refs", [])) if card.get("state") == "OBSERVED" else [],
            "reason_code": card.get("reason_code"),
        }
        for field, card in detail.get("action", {}).items()
        if isinstance(card, Mapping)
    }
    context = {
        field: {
            "state": card.get("state"),
            "value": card.get("value") if card.get("state") == "OBSERVED" else None,
            "evidence_refs": list(card.get("evidence_refs", [])) if card.get("state") == "OBSERVED" else [],
            "reason_code": card.get("reason_code"),
        }
        for field, card in detail.get("context", {}).items()
        if isinstance(card, Mapping)
    }
    receipt_ids = detail.get("identity", {}).get("execution_receipt_ids", [])
    receipt = db.scalar(select(ExecutionReceipt).where(
        ExecutionReceipt.tenant_id == tenant_id,
        ExecutionReceipt.receipt_id.in_(receipt_ids),
    ).limit(1)) if receipt_ids else None
    execution_card = detail.get("execution", {}).get("observed_semantics", {})
    executed = {
        "state": execution_card.get("state", "UNKNOWN"),
        "terminal": _observation_value(detail.get("execution", {}).get("execution_state")),
        "evidence_quality": _observation_value(detail.get("execution", {}).get("evidence_quality")),
        "actual_actor_hash": receipt.actual_actor_hash if receipt else None,
        "actual_purpose_hash": receipt.actual_purpose_hash if receipt else None,
        "actual_tool_fingerprint": receipt.actual_tool_fingerprint if receipt else None,
        "actual_parameter_hash": receipt.actual_parameter_hash if receipt else None,
        "actual_target_resource_hash": receipt.actual_target_resource_hash if receipt else None,
        "actual_destination_hash": receipt.actual_destination_hash if receipt else None,
        "actual_authority_hash": receipt.actual_authority_hash if receipt else None,
        "actual_side_effect_class": receipt.actual_side_effect_class if receipt else None,
        "evidence_refs": _observation_refs(execution_card),
        "reason_code": execution_card.get("reason_code") if isinstance(execution_card, Mapping) else "execution_unknown",
    }
    integrity_card = detail.get("execution", {}).get("material_integrity", {})
    integrity_value = _observation_value(integrity_card)
    drift_card = detail.get("execution", {}).get("drift_fields", {})
    outcome_timeline = next((
        item for item in detail.get("timeline", [])
        if item.get("event_type") == "OUTCOME" and item.get("state") == "OBSERVED"
    ), None)
    outcome_value = outcome_timeline.get("value") if isinstance(outcome_timeline, Mapping) and isinstance(outcome_timeline.get("value"), Mapping) else {}
    verification_id = outcome_value.get("verification_id")
    verification = db.scalar(select(OutcomeVerificationV2).where(
        OutcomeVerificationV2.tenant_id == tenant_id,
        OutcomeVerificationV2.verification_id == verification_id,
    )) if isinstance(verification_id, str) else None
    expected = db.scalar(select(ExpectedOutcomeV2).where(
        ExpectedOutcomeV2.tenant_id == tenant_id,
        ExpectedOutcomeV2.outcome_contract_id == verification.outcome_contract_id,
        ExpectedOutcomeV2.action_id == verification.action_id,
    )) if verification is not None else None
    provider = db.info.get("phase5_signing_provider")
    expected_verified = bool(
        expected is not None and provider is not None
        and verify_signed_object(
            provider, purpose="outcome_verification_signing", domain=EXPECTED_OUTCOME_DOMAIN,
            tenant_id=tenant_id, value=dict(expected.signed_envelope or {}), current_authority=False,
        )
        and (expected.signed_envelope or {}).get("outcome_contract_id") == expected.outcome_contract_id
        and (expected.signed_envelope or {}).get("action_id") == expected.action_id
        and (expected.signed_envelope or {}).get("expected_state_hash") == expected.expected_state_hash
    )
    return {
        "context": context,
        "authorised": authorised,
        "executed": executed,
        "result": integrity_value.get("result") if isinstance(integrity_value, Mapping) else "UNVERIFIED",
        "drift_fields": _observation_value(drift_card) or [],
        "evidence_refs": list(dict.fromkeys(_observation_refs(integrity_card) + _observation_refs(execution_card))),
        "expected_outcome": {
            "state": "CONFIRMED" if expected_verified else "UNKNOWN",
            "value": {"outcome_contract_id": expected.outcome_contract_id, "expected_state_hash": expected.expected_state_hash} if expected_verified and expected is not None else None,
            "evidence_refs": list(outcome_timeline.get("evidence_node_ids", [])) if expected_verified and isinstance(outcome_timeline, Mapping) else [],
            "reason_code": None if expected_verified else "expected_outcome_contract_unverified",
        },
        "observed_outcome": {
            "state": "CONFIRMED" if verification is not None and outcome_timeline else "UNKNOWN",
            "value": {"verification_id": verification.verification_id, "result": verification.result, "evidence_quality": verification.evidence_quality} if verification is not None and outcome_timeline else None,
            "evidence_refs": list(outcome_timeline.get("evidence_node_ids", [])) if isinstance(outcome_timeline, Mapping) else [],
            "reason_code": None if verification is not None and outcome_timeline else "observed_outcome_unknown",
        },
    }


def _questions(
    *,
    nodes: list[LineageNode],
    comparison: Mapping[str, Any],
    blind_spots: list[str],
) -> dict[str, dict[str, Any]]:
    by_type: dict[str, list[LineageNode]] = {}
    for node in nodes:
        by_type.setdefault(node.node_type, []).append(node)

    def nodes_answer(types: tuple[str, ...], reason: str) -> dict[str, Any]:
        selected = [node for node_type in types for node in by_type.get(node_type, [])]
        if not selected:
            return _unknown_answer(reason)
        state = "CONFIRMED" if any(node.certainty == "CONFIRMED" for node in selected) else selected[0].certainty
        return _answer(
            [{
                "label": node.label,
                "authority_type": node.authority_type,
                "authority_id": node.authority_id,
                "certainty": node.certainty,
                "safe_attributes": dict(node.safe_attributes or {}),
            } for node in selected],
            state=state,
            evidence_refs=(ref for node in selected for ref in node.evidence_refs),
        )

    assurance_nodes = [
        node for node in nodes
        if node.node_type in {"VALIDATION_RUN", "DRIFT_SIGNAL"}
        or (node.node_type == "CONTROL_POINT" and node.authority_type == "ControlAssertion")
    ]
    control_assurance = _answer(
        [{
            "label": node.label,
            "authority_type": node.authority_type,
            "authority_id": node.authority_id,
            "certainty": node.certainty,
            "safe_attributes": dict(node.safe_attributes or {}),
        } for node in assurance_nodes],
        state=(
            "CONFIRMED" if any(node.certainty == "CONFIRMED" for node in assurance_nodes)
            else assurance_nodes[0].certainty if assurance_nodes else "UNKNOWN"
        ),
        evidence_refs=(ref for node in assurance_nodes for ref in node.evidence_refs),
        reason_code="control_assurance_unknown",
    )

    result = {
        "originating_actor": nodes_answer(("HUMAN",), "originating_actor_unknown"),
        "executing_principal": nodes_answer(("SERVICE", "WORKLOAD"), "executing_principal_unknown"),
        "represented_subject": nodes_answer(("EXTERNAL_USER",), "represented_subject_unknown"),
        "participating_agents": nodes_answer(("AGENT",), "participating_agents_unknown"),
        "model_or_runtime": nodes_answer(("MODEL", "RUNTIME"), "model_runtime_unknown"),
        "tools_or_services": nodes_answer(("TOOL", "MCP_SERVER", "MCP_TOOL", "API"), "tool_service_unknown"),
        "resources_targets_destinations": nodes_answer(("RESOURCE", "TARGET", "DESTINATION"), "resource_target_destination_unknown"),
        "purpose_and_authority": _answer(
            {
                "business_purpose": comparison.get("context", {}).get("business_purpose", {}).get("value"),
                "authority": comparison.get("context", {}).get("authority", {}).get("value"),
            },
            state="CONFIRMED" if all(
                comparison.get("context", {}).get(field, {}).get("state") == "OBSERVED"
                for field in ("business_purpose", "authority")
            ) else "UNKNOWN",
            evidence_refs=(
                ref for field in ("business_purpose", "authority")
                for ref in comparison.get("context", {}).get(field, {}).get("evidence_refs", [])
            ),
            reason_code="purpose_or_authority_unknown",
        ),
        "policy_decision": nodes_answer(("DECISION_RECEIPT", "POLICY"), "policy_decision_unknown"),
        "approval": nodes_answer(("APPROVAL",), "approval_not_required_or_unknown"),
        "authorised": _answer(dict(comparison.get("authorised", {})), state="CONFIRMED" if comparison.get("authorised") else "UNKNOWN"),
        "executed": _answer(dict(comparison.get("executed", {})), state="CONFIRMED" if comparison.get("executed", {}).get("state") == "OBSERVED" else "UNKNOWN", evidence_refs=comparison.get("executed", {}).get("evidence_refs", [])),
        "execution_drift": _answer({"result": comparison.get("result"), "drift_fields": comparison.get("drift_fields", [])}, state="CONFIRMED" if comparison.get("result") != "UNVERIFIED" else "UNKNOWN", evidence_refs=comparison.get("evidence_refs", [])),
        "expected_controls": _answer(
            [{"label": node.label, "certainty": node.certainty} for node in by_type.get("CONTROL_POINT", []) if node.safe_attributes.get("expected") is True],
            state="CORRELATED", reason_code="expected_controls_unknown",
        ),
        "actual_controls": _answer(
            [{"label": node.label, "certainty": node.certainty} for node in by_type.get("CONTROL_POINT", []) if node.safe_attributes.get("actual") is True],
            state="CONFIRMED", reason_code="actual_controls_unknown",
        ),
        "control_assurance": control_assurance,
        "evidence": _answer(sorted({ref for node in nodes for ref in node.evidence_refs}), state="CONFIRMED" if any(node.evidence_refs for node in nodes) else "UNKNOWN"),
        "persistent_effect": nodes_answer(("PERSISTENT_EFFECT",), "persistent_effect_not_observed"),
        "expected_outcome": dict(comparison.get("expected_outcome", _unknown_answer("expected_outcome_contract_not_referenced"))),
        "observed_outcome": dict(comparison.get("observed_outcome", _unknown_answer("observed_outcome_unknown"))),
    }
    assert tuple(result) == _QUESTION_ORDER
    return result


def get_activity_lineage_projection(
    db: Session,
    *,
    tenant_id: str,
    lineage_id: str,
    limit: int = DEFAULT_LINEAGE_RESULTS,
) -> dict[str, Any] | None:
    validate_lineage_bounds(depth=0, limit=limit)
    lineage = db.scalar(select(ActivityLineage).where(
        ActivityLineage.tenant_id == tenant_id,
        ActivityLineage.id == lineage_id,
    ))
    if lineage is None:
        return None
    nodes = list(db.scalars(select(LineageNode).where(
        LineageNode.tenant_id == tenant_id,
        LineageNode.lineage_id == lineage.id,
    ).order_by(LineageNode.ordinal.asc()).limit(limit + 1)).all())
    truncated = len(nodes) > limit
    nodes = nodes[:limit]
    node_ids = {node.id for node in nodes}
    edges = list(db.scalars(select(LineageEdge).where(
        LineageEdge.tenant_id == tenant_id,
        LineageEdge.lineage_id == lineage.id,
        LineageEdge.from_node_id.in_(node_ids),
        LineageEdge.to_node_id.in_(node_ids),
    ).order_by(LineageEdge.sequence.asc()).limit(limit)).all()) if node_ids else []
    comparison = _comparison_projection(db, tenant_id=tenant_id, lineage=lineage)
    blind_spots = list(lineage.blind_spots or [])
    if truncated and "lineage_projection_limit_reached" not in blind_spots:
        blind_spots.append("lineage_projection_limit_reached")
    assurance = [
        {
            "assertion_id": node.authority_id,
            "capability": node.label,
            "certainty": node.certainty,
            **dict(node.safe_attributes or {}),
        }
        for node in nodes
        if node.authority_type == "ControlAssertion"
    ]
    investigation_ids = list(db.scalars(select(Investigation.id).where(
        Investigation.tenant_id == tenant_id,
        Investigation.lineage_id == lineage.id,
    ).limit(MAX_LINEAGE_RESULTS)).all())
    finding_rows = list(db.scalars(select(InvestigationFinding).where(
        InvestigationFinding.tenant_id == tenant_id,
        InvestigationFinding.investigation_id.in_(investigation_ids),
    ).order_by(InvestigationFinding.created_at.desc()).limit(MAX_LINEAGE_RESULTS)).all()) if investigation_ids else []
    return {
        "schema_version": "1.0",
        "lineage": {
            "id": lineage.id, "lineage_key": lineage.lineage_key,
            "source_watermark": lineage.source_watermark, "status": lineage.status,
            "seed_action_id": lineage.seed_action_id, "seed_runtime_event_id": lineage.seed_runtime_event_id,
            "root_action_id": lineage.root_action_id, "created_at": _utc_iso(lineage.created_at),
        },
        "nodes": [_serialize_node(node) for node in nodes],
        "edges": [_serialize_edge(edge) for edge in edges],
        "authorised_vs_executed": comparison,
        "control_assurance": assurance,
        "findings": [
            {
                "id": row.id, "investigation_id": row.investigation_id,
                "finding_type": row.finding_type, "severity": row.severity,
                "title": row.title, "reason_code": row.reason_code, "status": row.status,
                "lineage_node_ids": list(row.lineage_node_ids or []),
                "lineage_edge_ids": list(row.lineage_edge_ids or []),
                "evidence_refs": list(row.evidence_refs or []),
            }
            for row in finding_rows
        ],
        "questions": _questions(nodes=nodes, comparison=comparison, blind_spots=blind_spots),
        "blind_spots": blind_spots,
        "bounds": {"limit": limit, "returned_nodes": len(nodes), "returned_edges": len(edges), "truncated": truncated},
    }


def materialize_lineage_projection(
    db: Session,
    *,
    tenant_id: str,
    runtime_event_id: str,
    depth: int = DEFAULT_LINEAGE_DEPTH,
    limit: int = DEFAULT_LINEAGE_RESULTS,
) -> dict[str, Any] | None:
    lineage = materialize_activity_lineage(
        db, tenant_id=tenant_id, runtime_event_id=runtime_event_id, depth=depth, limit=limit,
    )
    return get_activity_lineage_projection(db, tenant_id=tenant_id, lineage_id=lineage.id, limit=limit) if lineage else None


def traverse_lineage(
    db: Session,
    *,
    tenant_id: str,
    lineage_id: str,
    seed_node_id: str,
    direction: str = "both",
    depth: int = DEFAULT_LINEAGE_DEPTH,
    limit: int = DEFAULT_LINEAGE_RESULTS,
) -> dict[str, Any] | None:
    validate_lineage_bounds(depth=depth, limit=limit)
    if direction not in {"upstream", "downstream", "both"}:
        raise ValueError("direction must be upstream, downstream, or both")
    lineage = db.scalar(select(ActivityLineage).where(
        ActivityLineage.tenant_id == tenant_id, ActivityLineage.id == lineage_id,
    ))
    seed = db.scalar(select(LineageNode).where(
        LineageNode.tenant_id == tenant_id, LineageNode.lineage_id == lineage_id, LineageNode.id == seed_node_id,
    ))
    if lineage is None or seed is None:
        return None
    selected_ids = {seed.id}
    frontier = {seed.id}
    selected_edges: list[LineageEdge] = []
    truncated = False
    for _ in range(depth):
        if not frontier or len(selected_ids) >= limit:
            break
        clauses = []
        if direction in {"downstream", "both"}:
            clauses.append(LineageEdge.from_node_id.in_(frontier))
        if direction in {"upstream", "both"}:
            clauses.append(LineageEdge.to_node_id.in_(frontier))
        rows = list(db.scalars(select(LineageEdge).where(
            LineageEdge.tenant_id == tenant_id,
            LineageEdge.lineage_id == lineage_id,
            or_(*clauses),
        ).order_by(LineageEdge.sequence.asc()).limit(limit + 1)).all())
        if len(rows) > limit:
            truncated = True
        next_frontier: set[str] = set()
        for edge in rows[:limit]:
            candidate_ids: list[str] = []
            if direction in {"downstream", "both"} and edge.from_node_id in frontier:
                candidate_ids.append(edge.to_node_id)
            if direction in {"upstream", "both"} and edge.to_node_id in frontier:
                candidate_ids.append(edge.from_node_id)
            for candidate in candidate_ids:
                if candidate not in selected_ids:
                    if len(selected_ids) >= limit:
                        truncated = True
                        break
                    selected_ids.add(candidate)
                    next_frontier.add(candidate)
            if edge.from_node_id in selected_ids and edge.to_node_id in selected_ids and edge not in selected_edges:
                selected_edges.append(edge)
        frontier = next_frontier
    nodes = list(db.scalars(select(LineageNode).where(
        LineageNode.tenant_id == tenant_id,
        LineageNode.lineage_id == lineage_id,
        LineageNode.id.in_(selected_ids),
    ).order_by(LineageNode.ordinal.asc()).limit(limit)).all())
    return {
        "lineage_id": lineage.id, "seed_node_id": seed.id, "direction": direction,
        "nodes": [_serialize_node(node) for node in nodes],
        "edges": [_serialize_edge(edge) for edge in selected_edges[:limit]],
        "bounds": {"depth": depth, "limit": limit, "truncated": truncated},
    }


def search_lineages(db: Session, *, tenant_id: str, query: LineageQuery) -> list[dict[str, Any]]:
    query = query.validated()
    stmt = select(ActivityLineage).join(
        RuntimeEvent,
        and_(
            RuntimeEvent.tenant_id == ActivityLineage.tenant_id,
            RuntimeEvent.event_id == ActivityLineage.seed_runtime_event_id,
        ),
    ).where(ActivityLineage.tenant_id == tenant_id)
    if query.time_from:
        stmt = stmt.where(RuntimeEvent.created_at >= query.time_from)
    if query.time_to:
        stmt = stmt.where(RuntimeEvent.created_at <= query.time_to)
    lineages = list(db.scalars(stmt.order_by(ActivityLineage.created_at.desc()).limit(MAX_SEARCH_WINDOW_RESULTS)).all())
    results: list[dict[str, Any]] = []
    node_filters = {
        "actor": (("HUMAN",), query.actor),
        "executing_principal": (("SERVICE", "WORKLOAD"), query.executing_principal),
        "represented_subject": (("EXTERNAL_USER",), query.represented_subject),
        "agent": (("AGENT",), query.agent),
        "tool": (("TOOL",), query.tool),
        "mcp_server": (("MCP_SERVER",), query.mcp_server),
        "mcp_tool": (("MCP_TOOL",), query.mcp_tool),
        "resource": (("RESOURCE",), query.resource),
        "target": (("TARGET",), query.target),
        "destination": (("DESTINATION",), query.destination),
        "control_point": (("CONTROL_POINT",), query.control_point),
    }
    for lineage in lineages:
        all_nodes = list(db.scalars(select(LineageNode).where(
            LineageNode.tenant_id == tenant_id,
            LineageNode.lineage_id == lineage.id,
        ).order_by(LineageNode.ordinal.asc()).limit(MAX_LINEAGE_RESULTS)).all())
        node_stmt = select(LineageNode).where(
            LineageNode.tenant_id == tenant_id, LineageNode.lineage_id == lineage.id,
        )
        if query.authority_type:
            node_stmt = node_stmt.where(LineageNode.authority_type == query.authority_type)
        if query.authority_id:
            node_stmt = node_stmt.where(LineageNode.authority_id == query.authority_id)
        if query.node_type:
            node_stmt = node_stmt.where(LineageNode.node_type == query.node_type)
        if query.certainty:
            node_stmt = node_stmt.where(LineageNode.certainty == query.certainty)
        matches = list(db.scalars(node_stmt.limit(10)).all())
        if any((query.authority_type, query.authority_id, query.node_type, query.certainty)) and not matches:
            continue
        if any(
            not any(
                node.node_type in node_types and (node.label == value or node.authority_id == value)
                for node in all_nodes
            )
            for node_types, value in node_filters.values()
            if value is not None
        ):
            continue
        if query.action_id and not any(
            node.node_type == "ACTION" and node.authority_id == query.action_id
            for node in all_nodes
        ):
            continue
        action_nodes = [node for node in all_nodes if node.node_type == "ACTION"]
        if query.decision and not any(str(node.safe_attributes.get("decision") or "").lower() == query.decision.lower() for node in action_nodes):
            continue
        if query.integrity_status and not any(node.safe_attributes.get("integrity_status") == query.integrity_status for node in action_nodes):
            continue
        if query.drift_type and not any(query.drift_type in set(node.safe_attributes.get("drift_fields") or []) for node in action_nodes):
            continue
        if query.validation_state and not any(
            node.node_type == "CONTROL_POINT" and node.safe_attributes.get("assurance_state") == query.validation_state
            for node in all_nodes
        ):
            continue
        if query.provider and not any(
            node.node_type in {"MODEL", "RUNTIME"} and (node.label == query.provider or node.authority_id == query.provider)
            for node in all_nodes
        ):
            continue
        results.append({
            "lineage_id": lineage.id, "seed_action_id": lineage.seed_action_id,
            "seed_runtime_event_id": lineage.seed_runtime_event_id, "root_action_id": lineage.root_action_id,
            "status": lineage.status, "created_at": _utc_iso(lineage.created_at),
            "matched_nodes": [_serialize_node(node) for node in (matches or all_nodes[:10])],
        })
        if len(results) >= query.limit:
            break
    return results


def create_investigation(
    db: Session,
    *,
    tenant_id: str,
    lineage_id: str,
    title: str,
    owner_ref: str,
    scope: Mapping[str, Any] | None = None,
    saved_query: Mapping[str, Any] | None = None,
    time_from: datetime | None = None,
    time_to: datetime | None = None,
) -> Investigation | None:
    if not title.strip() or len(title.strip()) > 255 or not owner_ref.strip() or len(owner_ref.strip()) > 255:
        raise ValueError("title and owner_ref must be bounded non-empty values")
    if time_from and time_to and time_from > time_to:
        raise ValueError("time_from must not be after time_to")
    lineage = db.scalar(select(ActivityLineage).where(
        ActivityLineage.tenant_id == tenant_id, ActivityLineage.id == lineage_id,
    ))
    if lineage is None:
        return None
    row = Investigation(
        tenant_id=tenant_id, lineage_id=lineage.id, title=title.strip(), owner_ref=owner_ref.strip(),
        status="OPEN", seed_action_id=lineage.seed_action_id, seed_runtime_event_id=lineage.seed_runtime_event_id,
        scope=_safe_query_map(scope, field_name="scope"),
        saved_query=_safe_query_map(saved_query, field_name="saved_query"),
        time_from=time_from, time_to=time_to,
    )
    db.add(row)
    db.flush()
    return row


def get_investigation(db: Session, *, tenant_id: str, investigation_id: str) -> dict[str, Any] | None:
    row = db.scalar(select(Investigation).where(
        Investigation.tenant_id == tenant_id, Investigation.id == investigation_id,
    ))
    if row is None:
        return None
    findings = list(db.scalars(select(InvestigationFinding).where(
        InvestigationFinding.tenant_id == tenant_id,
        InvestigationFinding.investigation_id == row.id,
    ).order_by(InvestigationFinding.created_at.asc()).limit(MAX_LINEAGE_RESULTS)).all())
    return {
        "id": row.id, "lineage_id": row.lineage_id, "title": row.title,
        "owner_ref": row.owner_ref, "status": row.status, "seed_action_id": row.seed_action_id,
        "seed_runtime_event_id": row.seed_runtime_event_id, "scope": dict(row.scope or {}),
        "saved_query": dict(row.saved_query or {}), "time_from": _utc_iso(row.time_from),
        "time_to": _utc_iso(row.time_to), "created_at": _utc_iso(row.created_at),
        "updated_at": _utc_iso(row.updated_at),
        "findings": [
            {
                "id": finding.id, "finding_type": finding.finding_type, "severity": finding.severity,
                "title": finding.title, "reason_code": finding.reason_code, "status": finding.status,
                "lineage_node_ids": list(finding.lineage_node_ids or []),
                "lineage_edge_ids": list(finding.lineage_edge_ids or []),
                "evidence_refs": list(finding.evidence_refs or []),
            }
            for finding in findings
        ],
    }


def add_investigation_finding(
    db: Session,
    *,
    tenant_id: str,
    investigation_id: str,
    finding_type: str,
    severity: str,
    title: str,
    reason_code: str,
    lineage_node_ids: Iterable[str] = (),
    lineage_edge_ids: Iterable[str] = (),
    evidence_refs: Iterable[str] = (),
) -> InvestigationFinding | None:
    investigation = db.scalar(select(Investigation).where(
        Investigation.tenant_id == tenant_id, Investigation.id == investigation_id,
    ))
    if investigation is None:
        return None
    node_ids = list(dict.fromkeys(str(value) for value in lineage_node_ids if value))[:100]
    edge_ids = list(dict.fromkeys(str(value) for value in lineage_edge_ids if value))[:100]
    if node_ids:
        count = len(db.scalars(select(LineageNode.id).where(
            LineageNode.tenant_id == tenant_id, LineageNode.lineage_id == investigation.lineage_id,
            LineageNode.id.in_(node_ids),
        )).all())
        if count != len(node_ids):
            raise ValueError("finding contains a foreign or unknown lineage node")
    if edge_ids:
        count = len(db.scalars(select(LineageEdge.id).where(
            LineageEdge.tenant_id == tenant_id, LineageEdge.lineage_id == investigation.lineage_id,
            LineageEdge.id.in_(edge_ids),
        )).all())
        if count != len(edge_ids):
            raise ValueError("finding contains a foreign or unknown lineage edge")
    normalized_evidence_refs = list(dict.fromkeys(str(value) for value in evidence_refs if value))[:100]
    if normalized_evidence_refs:
        resolved_evidence = set(db.scalars(select(EvidenceNode.id).where(
            EvidenceNode.tenant_id == tenant_id,
            EvidenceNode.id.in_(normalized_evidence_refs),
        )).all())
        if resolved_evidence != set(normalized_evidence_refs):
            raise ValueError("finding contains a foreign or unknown evidence reference")
    row = InvestigationFinding(
        tenant_id=tenant_id, investigation_id=investigation.id,
        finding_type=_bounded_text(finding_type, maximum=64), severity=severity,
        title=_bounded_text(title), reason_code=_bounded_text(reason_code, maximum=128), status="OPEN",
        lineage_node_ids=node_ids, lineage_edge_ids=edge_ids,
        evidence_refs=normalized_evidence_refs,
    )
    db.add(row)
    db.flush()
    return row
