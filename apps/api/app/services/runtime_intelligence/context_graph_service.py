from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.runtime_intelligence import ContextEdge, ContextNode, RuntimeEvent


EVENT_ENTITY_TYPES = {"user", "agent", "tool", "ai_system"}
DECISION_RISK = {
    "allow": 0.05,
    "warn": 0.35,
    "redact": 0.45,
    "require_justification": 0.55,
    "hold_for_approval": 0.7,
    "require_approval": 0.7,
    "block": 0.9,
}
SEVERITY_RISK = {
    "low": 0.2,
    "med": 0.55,
    "medium": 0.55,
    "high": 0.8,
    "critical": 1.0,
}
SENSITIVITY_RISK = {
    "public": 0.1,
    "internal": 0.3,
    "unknown": 0.45,
    "sensitive": 0.72,
    "protected": 0.85,
    "restricted": 0.92,
    "secret": 1.0,
}
VIOLATION_HINTS = (
    "violation",
    "denied",
    "blocked",
    "prompt_injection",
    "prompt_decomposition",
    "sensitive_data",
    "unregistered_ai_system",
)
CONTEXT_NODE_ENTITY_ID_MAX_LENGTH = 128


def _safe_text(value: Any) -> str:
    text = str(value or "").strip()
    return text


def _compact_context_entity_id(node_type: str, entity_id: str, metadata: dict[str, Any] | None) -> tuple[str, dict[str, Any]]:
    safe_entity_id = _safe_text(entity_id)
    safe_metadata = dict(metadata or {})
    if len(safe_entity_id) <= CONTEXT_NODE_ENTITY_ID_MAX_LENGTH:
        return safe_entity_id, safe_metadata

    digest = hashlib.sha256(safe_entity_id.encode("utf-8")).hexdigest()[:32]
    prefix = _safe_text(node_type).lower() or "entity"
    compacted = f"{prefix}:{digest}"
    safe_metadata.setdefault("raw_entity_id", safe_entity_id)
    safe_metadata["entity_id_compacted"] = True
    safe_metadata["entity_id_hash"] = digest
    safe_metadata["entity_id_original_length"] = len(safe_entity_id)
    return compacted[:CONTEXT_NODE_ENTITY_ID_MAX_LENGTH], safe_metadata


def _clamp_score(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return round(float(value), 4)


def _extract_data_classification(metadata: dict[str, Any]) -> str:
    return (
        _safe_text(
            metadata.get("data_classification")
            or metadata.get("source_classification_hint")
            or metadata.get("classification")
            or "unknown"
        ).lower()
        or "unknown"
    )


def _contains_violation_signal(metadata: dict[str, Any]) -> bool:
    candidates: list[str] = []
    decision = _safe_text(metadata.get("decision") or metadata.get("final_decision")).lower()
    if decision:
        candidates.append(decision)
    reason_code = _safe_text(metadata.get("reason_code") or metadata.get("reason")).lower()
    if reason_code:
        candidates.append(reason_code)
    for key in ("input_signal_types", "reason_codes", "risk_labels"):
        values = metadata.get(key)
        if isinstance(values, list):
            for item in values:
                text = _safe_text(item).lower()
                if text:
                    candidates.append(text)
    text_blob = " ".join(candidates)
    return any(hint in text_blob for hint in VIOLATION_HINTS)


def compute_event_risk_score(
    *,
    event: RuntimeEvent,
    metadata: dict[str, Any],
    provided_score: float | None = None,
) -> float:
    if provided_score is not None and float(provided_score) > 0.0:
        try:
            return _clamp_score(float(provided_score))
        except (TypeError, ValueError):
            pass

    components = compute_event_risk_components(event=event, metadata=metadata)
    score = components["total"]
    return _clamp_score(score)


def compute_event_risk_components(
    *,
    event: RuntimeEvent,
    metadata: dict[str, Any],
) -> dict[str, float]:
    decision = _safe_text(metadata.get("decision") or metadata.get("final_decision")).lower()
    severity = _safe_text(event.severity or metadata.get("severity")).lower() or "med"
    data_classification = _extract_data_classification(metadata)
    semantic_drift = dict(metadata.get("semantic_drift") or {}) if isinstance(metadata.get("semantic_drift"), dict) else {}
    context_mismatch = float(semantic_drift.get("drift_score") or 0.0)
    context_mismatch = _clamp_score(context_mismatch)

    decision_risk = DECISION_RISK.get(decision, 0.25)
    severity_risk = SEVERITY_RISK.get(severity, 0.55)
    anomaly_score = _clamp_score((decision_risk * 0.6) + (severity_risk * 0.4))
    sensitivity_score = _clamp_score(SENSITIVITY_RISK.get(data_classification, 0.45))
    violation_boost = 0.15 if _contains_violation_signal(metadata) else 0.0
    total = _clamp_score(
        (sensitivity_score * 0.35) + (anomaly_score * 0.45) + (context_mismatch * 0.2) + violation_boost
    )
    return {
        "sensitivity_score": sensitivity_score,
        "anomaly_score": anomaly_score,
        "context_mismatch": context_mismatch,
        "total": total,
    }


def _resolve_context_fields(event: RuntimeEvent, metadata: dict[str, Any]) -> tuple[str, str, str | None]:
    context_id = _safe_text(event.context_id) or _safe_text(metadata.get("context_id")) or _safe_text(event.correlation_id) or event.event_id
    chain_id = _safe_text(event.chain_id) or _safe_text(metadata.get("chain_id")) or context_id
    parent_action_id = _safe_text(event.parent_action_id) or _safe_text(metadata.get("parent_action_id")) or None
    return context_id, chain_id, parent_action_id


def _resolve_event_entity(event: RuntimeEvent, metadata: dict[str, Any]) -> tuple[str | None, str | None]:
    entity_type = _safe_text(event.entity_type).lower()
    entity_id = _safe_text(event.entity_id)
    if entity_type in EVENT_ENTITY_TYPES and entity_id:
        return entity_type, entity_id

    if _safe_text(event.agent_id):
        return "agent", _safe_text(event.agent_id)
    if _safe_text(event.user_id):
        return "user", _safe_text(event.user_id)
    tool_name = _safe_text(metadata.get("tool_name"))
    if tool_name:
        return "tool", tool_name
    if _safe_text(event.ai_system_id):
        return "ai_system", _safe_text(event.ai_system_id)
    return None, None


def _upsert_context_node(
    db: Session,
    *,
    tenant_id: str,
    context_id: str,
    node_type: str,
    entity_id: str,
    metadata: dict[str, Any] | None = None,
) -> ContextNode:
    entity_id, metadata = _compact_context_entity_id(node_type, entity_id, metadata)
    existing = db.scalar(
        select(ContextNode).where(
            ContextNode.tenant_id == tenant_id,
            ContextNode.context_id == context_id,
            ContextNode.type == node_type,
            ContextNode.entity_id == entity_id,
        )
    )
    if existing is not None:
        merged = dict(existing.metadata_json or {})
        merged.update(dict(metadata or {}))
        existing.metadata_json = merged
        db.flush()
        return existing

    row = ContextNode(
        tenant_id=tenant_id,
        context_id=context_id,
        type=node_type,
        entity_id=entity_id,
        metadata_json=dict(metadata or {}),
    )
    db.add(row)
    db.flush()
    return row


def _create_context_edge_if_missing(
    db: Session,
    *,
    tenant_id: str,
    context_id: str,
    from_node: str,
    to_node: str,
    relation_type: str,
    chain_id: str | None = None,
    parent_action_id: str | None = None,
) -> ContextEdge:
    existing = db.scalar(
        select(ContextEdge).where(
            ContextEdge.tenant_id == tenant_id,
            ContextEdge.context_id == context_id,
            ContextEdge.from_node == from_node,
            ContextEdge.to_node == to_node,
            ContextEdge.relation_type == relation_type,
            ContextEdge.chain_id == chain_id,
            ContextEdge.parent_action_id == parent_action_id,
        )
    )
    if existing is not None:
        return existing

    row = ContextEdge(
        tenant_id=tenant_id,
        context_id=context_id,
        from_node=from_node,
        to_node=to_node,
        relation_type=relation_type,
        chain_id=chain_id,
        parent_action_id=parent_action_id,
    )
    db.add(row)
    db.flush()
    return row


def build_context_graph_for_event(db: Session, *, event: RuntimeEvent) -> RuntimeEvent:
    metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}
    context_id, chain_id, parent_action_id = _resolve_context_fields(event, metadata)
    entity_type, entity_id = _resolve_event_entity(event, metadata)
    risk_components = compute_event_risk_components(event=event, metadata=metadata)
    if event.risk_score is not None and float(event.risk_score or 0.0) > 0.0:
        risk_score = compute_event_risk_score(event=event, metadata=metadata, provided_score=event.risk_score)
        risk_components["total"] = float(risk_score)
    else:
        risk_score = float(risk_components["total"])

    event.context_id = context_id
    event.chain_id = chain_id
    event.parent_action_id = parent_action_id
    event.entity_type = entity_type
    event.entity_id = entity_id
    event.risk_score = risk_score

    action_node = _upsert_context_node(
        db,
        tenant_id=event.tenant_id,
        context_id=context_id,
        node_type="action",
        entity_id=event.event_id,
        metadata={
            "event_type": event.event_type,
            "source_surface": event.source_surface,
            "severity": event.severity,
            "decision": _safe_text(metadata.get("decision") or metadata.get("final_decision")) or None,
            "risk_score": risk_score,
        },
    )

    if entity_type and entity_id:
        entity_node = _upsert_context_node(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            node_type=entity_type,
            entity_id=entity_id,
            metadata={},
        )
        _create_context_edge_if_missing(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            from_node=entity_node.id,
            to_node=action_node.id,
            relation_type="context.entity_to_action",
            chain_id=chain_id,
            parent_action_id=parent_action_id,
        )

    # Connector identities are retained as explicitly unresolved source refs
    # when they do not map to a tenant User FK.  They still establish an
    # observed user-to-agent relationship; they must not disappear from the
    # context graph merely because directory resolution is pending.
    user_id = _safe_text(event.user_id) or _safe_text(metadata.get("source_user_ref"))
    agent_id = _safe_text(event.agent_id)
    tool_name = _safe_text(metadata.get("tool_name"))
    resource_id = (
        _safe_text(metadata.get("target_resource"))
        or _safe_text(metadata.get("resource"))
        or _safe_text(metadata.get("api_endpoint"))
        or _safe_text(metadata.get("domain"))
        or None
    )

    user_node: ContextNode | None = None
    agent_node: ContextNode | None = None
    tool_node: ContextNode | None = None
    if user_id:
        user_node = _upsert_context_node(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            node_type="user",
            entity_id=user_id,
            metadata={
                "identity_resolution": (
                    "resolved"
                    if event.user_id
                    else _safe_text(metadata.get("source_user_ref_status"))
                    or "unresolved_external"
                )
            },
        )
    if agent_id:
        agent_node = _upsert_context_node(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            node_type="agent",
            entity_id=agent_id,
            metadata={},
        )
    if tool_name:
        tool_node = _upsert_context_node(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            node_type="tool",
            entity_id=tool_name,
            metadata={"tool_category": _safe_text(metadata.get("tool_category")) or None},
        )

    if user_node is not None and agent_node is not None:
        _create_context_edge_if_missing(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            from_node=user_node.id,
            to_node=agent_node.id,
            relation_type="context.user_to_agent",
            chain_id=chain_id,
            parent_action_id=parent_action_id,
        )
    if agent_node is not None and tool_node is not None:
        _create_context_edge_if_missing(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            from_node=agent_node.id,
            to_node=tool_node.id,
            relation_type="context.agent_to_tool",
            chain_id=chain_id,
            parent_action_id=parent_action_id,
        )
    if tool_node is not None and resource_id:
        resource_node = _upsert_context_node(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            node_type="resource",
            entity_id=resource_id,
            metadata={},
        )
        _create_context_edge_if_missing(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            from_node=tool_node.id,
            to_node=resource_node.id,
            relation_type="context.tool_to_resource",
            chain_id=chain_id,
            parent_action_id=parent_action_id,
        )

    if event.ai_system_id:
        ai_system_node = _upsert_context_node(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            node_type="ai_system",
            entity_id=_safe_text(event.ai_system_id),
            metadata={},
        )
        _create_context_edge_if_missing(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            from_node=ai_system_node.id,
            to_node=action_node.id,
            relation_type="context.ai_system_to_action",
            chain_id=chain_id,
            parent_action_id=parent_action_id,
        )

    if parent_action_id:
        parent_node = _upsert_context_node(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            node_type="action",
            entity_id=parent_action_id,
            metadata={"placeholder": parent_action_id != event.event_id},
        )
        _create_context_edge_if_missing(
            db,
            tenant_id=event.tenant_id,
            context_id=context_id,
            from_node=parent_node.id,
            to_node=action_node.id,
            relation_type="context.parent_action",
            chain_id=chain_id,
            parent_action_id=parent_action_id,
        )

    metadata["context_id"] = context_id
    metadata["chain_id"] = chain_id
    metadata["parent_action_id"] = parent_action_id
    metadata["entity_type"] = entity_type
    metadata["entity_id"] = entity_id
    metadata["risk_score"] = risk_score
    metadata["risk_components"] = {
        "phase": "phase_1",
        "sensitivity_score": round(float(risk_components.get("sensitivity_score") or 0.0), 4),
        "anomaly_score": round(float(risk_components.get("anomaly_score") or 0.0), 4),
        "context_mismatch": round(float(risk_components.get("context_mismatch") or 0.0), 4),
        "total": round(float(risk_score or 0.0), 4),
    }
    metadata["risk_phase_hints"] = {
        "phase_2_signal_inputs": [
            "repeat_frequency",
            "cross_session_behavior",
            "multi_step_anomaly",
        ],
        "phase_3_signal_inputs": [
            "crq_financial_impact",
            "loss_reduction_modeling",
        ],
    }
    event.metadata_json = metadata
    db.flush()
    return event


def _edge_to_dict(edge: ContextEdge) -> dict[str, Any]:
    return {
        "id": edge.id,
        "from_node": edge.from_node,
        "to_node": edge.to_node,
        "relation_type": edge.relation_type,
        "chain_id": edge.chain_id,
        "parent_action_id": edge.parent_action_id,
        "created_at": edge.created_at.isoformat() if isinstance(edge.created_at, datetime) else None,
    }


def _node_to_dict(node: ContextNode) -> dict[str, Any]:
    return {
        "id": node.id,
        "type": node.type,
        "entity_id": node.entity_id,
        "metadata": dict(node.metadata_json or {}),
        "created_at": node.created_at.isoformat() if isinstance(node.created_at, datetime) else None,
    }


def _aggregate_risk(events: list[RuntimeEvent]) -> float:
    if not events:
        return 0.0
    scores = [_clamp_score(float(getattr(event, "risk_score", 0.0) or 0.0)) for event in events]
    max_score = max(scores)
    avg_score = sum(scores) / float(len(scores))
    return _clamp_score((max_score * 0.6) + (avg_score * 0.4))


def _event_metadata(event: RuntimeEvent) -> dict[str, Any]:
    return dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}


def _build_session_context_summary(
    *,
    events: list[RuntimeEvent],
    session_id: str,
) -> dict[str, Any]:
    ordered = sorted(events, key=lambda row: row.created_at)
    original_intent = None
    actions: list[dict[str, Any]] = []
    tools_used: set[str] = set()
    data_accessed: set[str] = set()
    identities: dict[str, dict[str, Any]] = {}
    risk_signals: set[str] = set()
    drift_scores: list[float] = []
    drift_thresholds: list[float] = []
    drift_breaches = 0

    for event in ordered:
        metadata = _event_metadata(event)
        semantic_drift = dict(metadata.get("semantic_drift") or {}) if isinstance(metadata.get("semantic_drift"), dict) else {}
        if semantic_drift:
            score = float(semantic_drift.get("drift_score") or 0.0)
            threshold = float(semantic_drift.get("threshold") or 0.0)
            drift_scores.append(score)
            drift_thresholds.append(threshold)
            if bool(semantic_drift.get("threshold_breach")):
                drift_breaches += 1

        intent = _safe_text(metadata.get("original_intent"))
        if intent and not original_intent:
            original_intent = intent

        action = dict(metadata.get("canonical_action") or {})
        if not action:
            action = {
                "action_id": event.event_id,
                "source_surface": event.source_surface,
                "user_id": event.user_id,
                "agent_id": event.agent_id,
                "model": _safe_text(metadata.get("model_name") or metadata.get("provider")) or None,
                "tool": _safe_text(metadata.get("tool_name") or event.app_id) or None,
                "operation": _safe_text(metadata.get("action_type") or event.event_type) or event.event_type,
                "data_entities": [],
                "timestamp": event.created_at.isoformat(),
            }
        actions.append(action)

        tool_name = _safe_text(metadata.get("tool_name"))
        if tool_name:
            tools_used.add(tool_name)

        for value in (
            metadata.get("data_source"),
            metadata.get("api_endpoint"),
            metadata.get("target_resource"),
            metadata.get("domain"),
            metadata.get("destination_domain"),
            metadata.get("source_domain"),
            event.app_id,
        ):
            text = _safe_text(value)
            if text:
                data_accessed.add(text)

        identity_pairs = [
            ("user", _safe_text(event.user_id)),
            ("agent", _safe_text(event.agent_id)),
            (_safe_text(event.entity_type).lower(), _safe_text(event.entity_id)),
        ]
        for identity_type, identity_id in identity_pairs:
            if identity_type and identity_id:
                identities[f"{identity_type}:{identity_id}"] = {
                    "entity_type": identity_type,
                    "entity_id": identity_id,
                }

        for signal in (
            metadata.get("reason_code"),
            metadata.get("reason"),
            *list(metadata.get("input_signal_types") or []),
            *list(metadata.get("reason_codes") or []),
            *list(metadata.get("risk_labels") or []),
        ):
            text = _safe_text(signal)
            if text:
                risk_signals.add(text)

    avg_drift = (sum(drift_scores) / len(drift_scores)) if drift_scores else 0.0
    max_drift = max(drift_scores) if drift_scores else 0.0
    threshold = max(drift_thresholds) if drift_thresholds else 0.0
    return {
        "session_id": session_id,
        "original_intent": original_intent or "unknown",
        "actions": actions,
        "tools_used": sorted(tools_used),
        "data_accessed": sorted(data_accessed),
        "identities": list(identities.values()),
        "semantic_drift": {
            "average_drift": round(float(avg_drift), 4),
            "max_drift": round(float(max_drift), 4),
            "threshold": round(float(threshold), 4),
            "threshold_breach": bool(drift_breaches > 0),
            "breach_count": int(drift_breaches),
        },
        "risk_signals": sorted(risk_signals),
    }


def get_context_graph(db: Session, *, tenant_id: str, context_id: str) -> dict[str, Any]:
    nodes = db.scalars(
        select(ContextNode)
        .where(
            ContextNode.tenant_id == tenant_id,
            ContextNode.context_id == context_id,
        )
        .order_by(ContextNode.created_at.asc())
    ).all()
    edges = db.scalars(
        select(ContextEdge)
        .where(
            ContextEdge.tenant_id == tenant_id,
            ContextEdge.context_id == context_id,
        )
        .order_by(ContextEdge.created_at.asc())
    ).all()
    events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.context_id == context_id,
        )
    ).all()
    return {
        "nodes": [_node_to_dict(node) for node in nodes],
        "edges": [_edge_to_dict(edge) for edge in edges],
        "risk_score": _aggregate_risk(events),
        "context": _build_session_context_summary(events=events, session_id=context_id),
    }


def build_chain_tree(db: Session, *, tenant_id: str, chain_id: str) -> dict[str, Any]:
    events = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.chain_id == chain_id,
        )
        .order_by(RuntimeEvent.created_at.asc())
    ).all()
    if not events:
        return {
            "nodes": [],
            "edges": [],
            "risk_score": 0.0,
            "context": _build_session_context_summary(events=[], session_id=chain_id),
        }

    context_ids = sorted({_safe_text(event.context_id) for event in events if _safe_text(event.context_id)})
    context_nodes = db.scalars(
        select(ContextNode).where(
            ContextNode.tenant_id == tenant_id,
            ContextNode.context_id.in_(context_ids),
        )
    ).all()
    context_edges = db.scalars(
        select(ContextEdge).where(
            ContextEdge.tenant_id == tenant_id,
            ContextEdge.chain_id == chain_id,
        )
    ).all()

    nodes_by_id: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for node in context_nodes:
        nodes_by_id[node.id] = _node_to_dict(node)
    for edge in context_edges:
        edges.append(_edge_to_dict(edge))

    # Add explicit action lineage edges from runtime events for deterministic chain reconstruction.
    for event in events:
        action_node_id = f"action:{event.event_id}"
        if action_node_id not in nodes_by_id:
            nodes_by_id[action_node_id] = {
                "id": action_node_id,
                "type": "action",
                "entity_id": event.event_id,
                "metadata": {
                    "event_type": event.event_type,
                    "source_surface": event.source_surface,
                    "entity_type": event.entity_type,
                    "entity_id": event.entity_id,
                    "risk_score": event.risk_score,
                    "context_id": event.context_id,
                    "created_at": event.created_at.isoformat(),
                },
                "created_at": event.created_at.isoformat(),
            }
        if event.parent_action_id:
            parent_action_node_id = f"action:{event.parent_action_id}"
            if parent_action_node_id not in nodes_by_id:
                nodes_by_id[parent_action_node_id] = {
                    "id": parent_action_node_id,
                    "type": "action",
                    "entity_id": event.parent_action_id,
                    "metadata": {
                        "placeholder": True,
                        "chain_id": chain_id,
                    },
                    "created_at": event.created_at.isoformat()
                    if isinstance(event.created_at, datetime)
                    else datetime.now(timezone.utc).isoformat(),
                }
            edges.append(
                {
                    "id": f"chain:{event.parent_action_id}:{event.event_id}",
                    "from_node": parent_action_node_id,
                    "to_node": action_node_id,
                    "relation_type": "context.parent_action",
                    "chain_id": chain_id,
                    "parent_action_id": event.parent_action_id,
                    "created_at": event.created_at.isoformat()
                    if isinstance(event.created_at, datetime)
                    else datetime.now(timezone.utc).isoformat(),
                }
            )

    return {
        "nodes": list(nodes_by_id.values()),
        "edges": edges,
        "risk_score": _aggregate_risk(events),
        "context": _build_session_context_summary(events=events, session_id=chain_id),
    }
