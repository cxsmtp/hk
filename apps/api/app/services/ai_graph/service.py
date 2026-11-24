from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models.runtime_intelligence import ContextEdge, ContextNode, RuntimeBehaviorEdge, RuntimeEvent


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _node_type(value: str) -> str:
    normalized = _safe_str(value).lower() or "unknown"
    if normalized in {"host", "endpoint"}:
        return "device"
    if normalized == "app":
        return "ai_app"
    return normalized


def _label_for_node(*, node_type: str, node_id: str, fallback: str | None = None) -> str:
    if _safe_str(fallback):
        return _safe_str(fallback)
    if node_type == "user":
        return f"user:{node_id}"
    if node_type == "agent":
        return f"agent:{node_id}"
    if node_type == "device":
        return f"device:{node_id}"
    if node_type == "ai_app":
        return f"app:{node_id}"
    if node_type == "model":
        return f"model:{node_id}"
    if node_type == "tool":
        return f"tool:{node_id}"
    if node_type == "browser":
        return f"browser:{node_id}"
    return node_id


def build_unified_ai_graph(
    db: Session,
    *,
    tenant_id: str,
    lookback_hours: int = 24 * 7,
    user_id: str | None = None,
    agent_id: str | None = None,
    ai_app: str | None = None,
    max_edges: int = 1200,
) -> dict[str, Any]:
    safe_hours = max(1, min(24 * 90, int(lookback_hours or 24 * 7)))
    safe_max_edges = max(10, min(5000, int(max_edges or 1200)))
    started_at = _utcnow() - timedelta(hours=safe_hours)

    event_stmt = select(RuntimeEvent).where(
        RuntimeEvent.tenant_id == tenant_id,
        RuntimeEvent.created_at >= started_at,
    )
    if user_id:
        event_stmt = event_stmt.where(RuntimeEvent.user_id == user_id)
    if agent_id:
        event_stmt = event_stmt.where(RuntimeEvent.agent_id == agent_id)
    if ai_app:
        event_stmt = event_stmt.where(RuntimeEvent.app_id == ai_app)
    events = db.scalars(event_stmt.order_by(desc(RuntimeEvent.created_at)).limit(safe_max_edges)).all()
    event_ids = [_safe_str(row.event_id) for row in events if _safe_str(row.event_id)]
    context_ids = {_safe_str(row.context_id) for row in events if _safe_str(row.context_id)}

    edge_stmt = select(RuntimeBehaviorEdge).where(RuntimeBehaviorEdge.tenant_id == tenant_id)
    if event_ids:
        edge_stmt = edge_stmt.where(RuntimeBehaviorEdge.event_id.in_(event_ids))
    else:
        edge_stmt = edge_stmt.where(RuntimeBehaviorEdge.event_id.is_(None))
    behavior_edges = db.scalars(edge_stmt.order_by(desc(RuntimeBehaviorEdge.created_at)).limit(safe_max_edges)).all()

    context_nodes: list[ContextNode] = []
    context_edges: list[ContextEdge] = []
    if context_ids:
        context_nodes = db.scalars(
            select(ContextNode).where(
                ContextNode.tenant_id == tenant_id,
                ContextNode.context_id.in_(list(context_ids)),
            )
        ).all()
        node_ids = [_safe_str(node.id) for node in context_nodes if _safe_str(node.id)]
        if node_ids:
            context_edges = db.scalars(
                select(ContextEdge).where(
                    ContextEdge.tenant_id == tenant_id,
                    ContextEdge.from_node.in_(node_ids),
                    ContextEdge.to_node.in_(node_ids),
                )
            ).all()

    nodes: dict[tuple[str, str], dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    relationship_counts: Counter[str] = Counter()

    def register_node(*, raw_type: str, raw_id: str, label: str | None = None) -> None:
        node_type = _node_type(raw_type)
        node_id = _safe_str(raw_id)
        if not node_type or not node_id:
            return
        key = (node_type, node_id)
        if key not in nodes:
            nodes[key] = {
                "node_type": node_type,
                "node_id": node_id,
                "label": _label_for_node(node_type=node_type, node_id=node_id, fallback=label),
            }

    for row in behavior_edges:
        source_type = _node_type(row.source_node_type)
        target_type = _node_type(row.target_node_type)
        source_id = _safe_str(row.source_node_id)
        target_id = _safe_str(row.target_node_id)
        if not source_id or not target_id:
            continue
        register_node(raw_type=source_type, raw_id=source_id, label=row.source_node_label)
        register_node(raw_type=target_type, raw_id=target_id, label=row.target_node_label)
        relation = _safe_str(row.relationship_type) or "related_to"
        relationship_counts[relation] += 1
        edges.append(
            {
                "edge_id": _safe_str(row.id),
                "source_node_type": source_type,
                "source_node_id": source_id,
                "target_node_type": target_type,
                "target_node_id": target_id,
                "relationship_type": relation,
                "event_id": _safe_str(row.event_id) or None,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "payload": dict(row.payload or {}),
            }
        )

    context_node_lookup = {_safe_str(node.id): node for node in context_nodes}
    for edge in context_edges:
        from_node = context_node_lookup.get(_safe_str(edge.from_node))
        to_node = context_node_lookup.get(_safe_str(edge.to_node))
        if from_node is None or to_node is None:
            continue
        register_node(
            raw_type=_safe_str(from_node.type),
            raw_id=_safe_str(from_node.entity_id),
            label=_safe_str(dict(from_node.metadata_json or {}).get("label")) or None,
        )
        register_node(
            raw_type=_safe_str(to_node.type),
            raw_id=_safe_str(to_node.entity_id),
            label=_safe_str(dict(to_node.metadata_json or {}).get("label")) or None,
        )
        relation = _safe_str(edge.relation_type) or "context_link"
        relationship_counts[relation] += 1
        edges.append(
            {
                "edge_id": _safe_str(edge.id),
                "source_node_type": _node_type(_safe_str(from_node.type)),
                "source_node_id": _safe_str(from_node.entity_id),
                "target_node_type": _node_type(_safe_str(to_node.type)),
                "target_node_id": _safe_str(to_node.entity_id),
                "relationship_type": relation,
                "event_id": None,
                "created_at": edge.created_at.isoformat() if edge.created_at else None,
                "payload": {
                    "context_id": _safe_str(edge.context_id),
                    "chain_id": _safe_str(edge.chain_id) or None,
                    "parent_action_id": _safe_str(edge.parent_action_id) or None,
                },
            }
        )

    node_counts = Counter(node["node_type"] for node in nodes.values())
    return {
        "window_hours": safe_hours,
        "filters": {
            "user_id": user_id,
            "agent_id": agent_id,
            "ai_app": ai_app,
        },
        "nodes": sorted(nodes.values(), key=lambda item: (item["node_type"], item["node_id"])),
        "edges": edges[:safe_max_edges],
        "stats": {
            "node_count": len(nodes),
            "edge_count": min(len(edges), safe_max_edges),
            "event_count": len(events),
            "node_counts": dict(node_counts),
            "relationship_counts": dict(relationship_counts),
        },
    }
