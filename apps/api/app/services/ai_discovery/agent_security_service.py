from __future__ import annotations

from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from sqlalchemy import desc, false, select
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentActionBaseline, AgentIdentity, CapabilityToken
from app.db.models.monitoring import MonitoringSignal
from app.db.models.runtime_intelligence import RuntimeBehaviorEdge, RuntimeEvent
from app.services.ai_iam_service import collect_delegation_descendant_agent_ids, revoke_agent_delegations
from app.services.ai_discovery.owasp_mapping_service import (
    build_agent_owasp_coverage,
    map_controls_to_owasp,
)
from app.services.audit_service import write_audit_log
from app.services.crq_service import compute_control_crq_profile
from app.services.evidence_service import create_evidence_node
from app.services.runtime_intelligence.streaming import publish_runtime_update
from app.services.simulation_pack_service import execute_pack, get_pack_definition


AgentEnforcementAction = Literal["block_agent", "restrict_tools", "require_approval", "isolate_execution"]

ATTACK_TYPE_TO_PACK: dict[str, str] = {
    "prompt_injection": "prompt_attack_pack",
    "tool_abuse": "tool_abuse_pack",
    "data_exfiltration": "data_leakage_pack",
    "privilege_escalation": "ai_identity_abuse_pack",
    "rag_poisoning": "rag_poisoning_pack",
}

DEFAULT_AGENT_CONTROL_IDS = [
    "AGENT_ACTION_AUTHORIZATION",
    "TOOL_CALL_VALIDATION",
    "CHAIN_OF_ACTION_VALIDATION",
    "PRIVILEGE_DRIFT_DETECTION",
]

SEVERITY_ORDER = {"low": 0, "med": 1, "high": 2, "critical": 3}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _to_utc(value: datetime | None) -> datetime:
    if value is None:
        return _utcnow()
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed != parsed:
        return default
    return parsed


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value or {}) if isinstance(value, dict) else {}


def _event_metadata(row: RuntimeEvent) -> dict[str, Any]:
    return _safe_dict(row.metadata_json)


def _event_decision(row: RuntimeEvent) -> str:
    metadata = _event_metadata(row)
    return _safe_str(metadata.get("final_decision") or metadata.get("decision")).lower() or "unknown"


def _event_action_type(row: RuntimeEvent) -> str:
    metadata = _event_metadata(row)
    return _safe_str(metadata.get("action_type") or row.event_type) or "unknown_action"


def _event_tool_name(row: RuntimeEvent) -> str:
    metadata = _event_metadata(row)
    return _safe_str(metadata.get("tool_name") or metadata.get("ai_tool"))


def _event_model_name(row: RuntimeEvent) -> str:
    metadata = _event_metadata(row)
    return _safe_str(
        metadata.get("model_name")
        or metadata.get("model")
        or metadata.get("model_provider")
        or metadata.get("provider")
    )


def _event_data_classification(row: RuntimeEvent) -> str:
    metadata = _event_metadata(row)
    return _safe_str(metadata.get("data_classification")).lower() or "unknown"


def _event_response_bytes(row: RuntimeEvent) -> int:
    metadata = _event_metadata(row)
    return max(
        0,
        _safe_int(
            metadata.get("response_size")
            or metadata.get("bytes_sent")
            or metadata.get("bytes_received")
            or 0
        ),
    )


def _severity_for_risk_score(risk_score: float) -> str:
    score = _safe_float(risk_score, 0.0)
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.35:
        return "med"
    return "low"


def _severity_rank(value: str | None) -> int:
    return SEVERITY_ORDER.get(_safe_str(value).lower(), 0)


def _dominant_severity(values: list[str]) -> str:
    best = "low"
    for value in values:
        if _severity_rank(value) > _severity_rank(best):
            best = value
    return best


def _extract_agent_id_from_signal(payload: dict[str, Any]) -> str | None:
    direct = _safe_str(payload.get("agent_id"))
    if direct:
        return direct
    entities = list(payload.get("related_entities") or [])
    for item in entities:
        if not isinstance(item, dict):
            continue
        entity_type = _safe_str(item.get("type")).lower()
        if entity_type == "agent":
            value = _safe_str(item.get("id"))
            if value:
                return value
    return None


def _read_only_scopes(scopes: list[str] | None) -> list[str]:
    out: list[str] = []
    for item in scopes or []:
        token = _safe_str(item)
        lower = token.lower()
        if lower.endswith(".read") or lower.startswith("read.") or lower in {"tool.read", "read"}:
            out.append(token)
    if not out:
        out = ["tool.read"]
    return sorted(set(out))


def _started_at(lookback_hours: int) -> datetime:
    safe_hours = max(1, min(24 * 180, int(lookback_hours or 24 * 7)))
    return _utcnow() - timedelta(hours=safe_hours)


def list_agent_entities(
    db: Session,
    *,
    tenant_id: str,
    lookback_hours: int = 24 * 7,
) -> dict[str, Any]:
    started_at = _started_at(lookback_hours)
    agents = db.scalars(
        select(AgentIdentity).where(AgentIdentity.tenant_id == tenant_id)
    ).all()
    events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.created_at >= started_at,
            RuntimeEvent.agent_id.is_not(None),
        )
    ).all()
    anomaly_rows = db.scalars(
        select(MonitoringSignal).where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= started_at,
        )
    ).all()

    by_agent_events: dict[str, list[RuntimeEvent]] = defaultdict(list)
    for event in events:
        key = _safe_str(event.agent_id)
        if key:
            by_agent_events[key].append(event)

    by_agent_anomalies: dict[str, list[MonitoringSignal]] = defaultdict(list)
    for row in anomaly_rows:
        payload = _safe_dict(row.payload)
        key = _extract_agent_id_from_signal(payload)
        if key:
            by_agent_anomalies[key].append(row)

    registry_by_id = {row.id: row for row in agents}
    discovered_agent_ids = set(registry_by_id.keys()) | set(by_agent_events.keys()) | set(by_agent_anomalies.keys())
    token_scope_by_agent: dict[str, set[str]] = defaultdict(set)
    if discovered_agent_ids:
        token_rows = db.scalars(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == tenant_id,
                CapabilityToken.agent_identity_id.in_(sorted(discovered_agent_ids)),
                CapabilityToken.revoked_at.is_(None),
            )
        ).all()
        for token_row in token_rows:
            agent_key = _safe_str(getattr(token_row, "agent_identity_id", None))
            if not agent_key:
                continue
            for scope in list(getattr(token_row, "scopes", []) or []):
                normalized_scope = _safe_str(scope)
                if normalized_scope:
                    token_scope_by_agent[agent_key].add(normalized_scope)

    entities: list[dict[str, Any]] = []
    for agent_id in sorted(discovered_agent_ids):
        row = registry_by_id.get(agent_id)
        rows = by_agent_events.get(agent_id, [])
        anomaly_items = by_agent_anomalies.get(agent_id, [])

        model_counter: Counter[str] = Counter()
        tool_counter: Counter[str] = Counter()
        action_counter: Counter[str] = Counter()
        source_counter: Counter[str] = Counter()
        data_access: set[str] = set()
        owner_counter: Counter[str] = Counter()
        avg_risk = 0.0
        last_seen_at: datetime | None = row.updated_at if row else None

        for event in rows:
            model = _event_model_name(event)
            tool = _event_tool_name(event)
            action = _event_action_type(event)
            source_surface = _safe_str(event.source_surface).lower() or "unknown"
            classification = _event_data_classification(event)
            owner_id = _safe_str(event.user_id)

            if model:
                model_counter[model] += 1
            if tool:
                tool_counter[tool] += 1
            action_counter[action] += 1
            source_counter[source_surface] += 1
            if classification:
                data_access.add(classification)
            if owner_id:
                owner_counter[owner_id] += 1
            avg_risk += _safe_float(event.risk_score, 0.0)
            event_ts = _to_utc(event.created_at)
            if last_seen_at is None or event_ts > _to_utc(last_seen_at):
                last_seen_at = event_ts

        avg_risk = round(avg_risk / max(1, len(rows)), 4)
        anomaly_score = round(
            sum(_severity_rank(_safe_str(item.severity)) for item in anomaly_items) / max(1, len(anomaly_items)),
            3,
        )
        risk_score = round(
            min(
                1.0,
                avg_risk + (0.06 * len([item for item in anomaly_items if _severity_rank(_safe_str(item.severity)) >= 2])),
            ),
            4,
        )

        capabilities = sorted(
            set(
                [*_read_only_scopes(list(getattr(row, "action_scope", []) or [])), *list((getattr(row, "action_scope", []) if row else []) or [])]
            )
        )
        capabilities = sorted(set(capabilities + list(token_scope_by_agent.get(agent_id, set()))))
        if not capabilities:
            capabilities = sorted(action_counter.keys())[:20]
        tools = sorted(set(list((getattr(row, "tool_registry", []) if row else []) or []) + list(tool_counter.keys())))[:40]
        environments = sorted(
            set(
                list(source_counter.keys())
                + [_safe_str(item) for item in list((getattr(row, "external_system_access", []) if row else []) or []) if _safe_str(item)]
            )
        )[:40]
        connected_systems: set[str] = {
            _safe_str(item).lower()
            for item in list((getattr(row, "external_system_access", []) if row else []) or [])
            if _safe_str(item)
        }
        runtime_over_scoped_flag = False
        for event in rows:
            metadata = _event_metadata(event)
            runtime_over_scoped_flag = runtime_over_scoped_flag or bool(metadata.get("over_scoped_flag"))
            for raw in (
                metadata.get("api_endpoint"),
                metadata.get("target_resource"),
                metadata.get("resource"),
                metadata.get("data_source"),
                event.app_id,
            ):
                token = _safe_str(raw).lower()
                if not token:
                    continue
                if "://" in token:
                    token = token.split("://", 1)[1]
                token = token.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split(":", 1)[0].strip()
                if token and token not in {"http", "https", "mcp"}:
                    connected_systems.add(token)

        over_scoped_flag = bool(
            runtime_over_scoped_flag
            or any(_safe_str(item) == "*" for item in capabilities)
            or any(_safe_str(item) == "*" for item in tools)
            or len(connected_systems) >= 8
        )
        if over_scoped_flag:
            risk_score = round(min(1.0, risk_score + 0.15), 4)

        entities.append(
            {
                "agent_id": agent_id,
                "owner": owner_counter.most_common(1)[0][0] if owner_counter else None,
                "model": model_counter.most_common(1)[0][0] if model_counter else None,
                "tools": tools,
                "capabilities": capabilities,
                "permissions": capabilities,
                "data_access": sorted(data_access)[:20],
                "environment": environments,
                "connected_systems": sorted(connected_systems)[:40],
                "status": _safe_str(getattr(row, "status", "")) or "discovered_unregistered",
                "risk_score": risk_score,
                "anomaly_score": anomaly_score,
                "event_count": len(rows),
                "anomaly_count": len(anomaly_items),
                "source_surfaces": sorted(source_counter.keys()),
                "over_scoped_flag": over_scoped_flag,
                "last_seen_at": _to_utc(last_seen_at).isoformat() if last_seen_at else None,
            }
        )

    high_risk_agents = sum(1 for item in entities if _safe_float(item.get("risk_score"), 0.0) >= 0.65)
    return {
        "window_hours": max(1, min(24 * 180, int(lookback_hours or 24 * 7))),
        "discovered_agents": len(entities),
        "registered_agents": len(agents),
        "unregistered_agents": max(0, len(entities) - len(agents)),
        "high_risk_agents": high_risk_agents,
        "agents": sorted(
            entities,
            key=lambda item: (
                -_safe_float(item.get("risk_score"), 0.0),
                -_safe_int(item.get("anomaly_count"), 0),
                str(item.get("agent_id") or ""),
            ),
        ),
    }


def build_agent_attack_surface_map(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    lookback_hours: int = 24 * 7,
    max_edges: int = 1200,
) -> dict[str, Any]:
    started_at = _started_at(lookback_hours)
    safe_max_edges = max(50, min(5000, int(max_edges or 1200)))
    normalized_agent_id = _safe_str(agent_id)
    if not normalized_agent_id:
        raise ValueError("agent_id is required")

    event_rows = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.agent_id == normalized_agent_id,
            RuntimeEvent.created_at >= started_at,
        )
    ).all()
    event_ids = [_safe_str(item.event_id) for item in event_rows if _safe_str(item.event_id)]
    event_by_id = {row.event_id: row for row in event_rows if _safe_str(row.event_id)}

    edge_rows = db.scalars(
        select(RuntimeBehaviorEdge)
        .where(
            RuntimeBehaviorEdge.tenant_id == tenant_id,
            RuntimeBehaviorEdge.created_at >= started_at,
            (
                ((RuntimeBehaviorEdge.source_node_type == "agent") & (RuntimeBehaviorEdge.source_node_id == normalized_agent_id))
                | ((RuntimeBehaviorEdge.target_node_type == "agent") & (RuntimeBehaviorEdge.target_node_id == normalized_agent_id))
                | (RuntimeBehaviorEdge.event_id.in_(event_ids) if event_ids else false())
            ),
        )
        .order_by(desc(RuntimeBehaviorEdge.created_at))
        .limit(safe_max_edges)
    ).all()

    nodes: dict[tuple[str, str], dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    relationship_counts: Counter[str] = Counter()
    connected_counts: Counter[str] = Counter()

    def register_node(node_type: str, node_id: str, label: str | None = None) -> None:
        key = (_safe_str(node_type).lower() or "unknown", _safe_str(node_id))
        if not key[1]:
            return
        if key not in nodes:
            nodes[key] = {
                "node_type": key[0],
                "node_id": key[1],
                "label": _safe_str(label) or f"{key[0]}:{key[1]}",
            }

    for edge in edge_rows:
        source_type = _safe_str(edge.source_node_type).lower() or "unknown"
        source_id = _safe_str(edge.source_node_id)
        target_type = _safe_str(edge.target_node_type).lower() or "unknown"
        target_id = _safe_str(edge.target_node_id)
        if not source_id or not target_id:
            continue
        register_node(source_type, source_id, edge.source_node_label)
        register_node(target_type, target_id, edge.target_node_label)

        relation = _safe_str(edge.relationship_type).lower() or "related_to"
        relationship_counts[relation] += 1
        if source_type == "agent" and source_id == normalized_agent_id:
            connected_counts[f"{target_type}:{target_id}"] += 1
        if target_type == "agent" and target_id == normalized_agent_id:
            connected_counts[f"{source_type}:{source_id}"] += 1

        event = event_by_id.get(_safe_str(edge.event_id))
        event_risk = _safe_float(getattr(event, "risk_score", 0.0), 0.0)
        payload = _safe_dict(edge.payload)
        risk_weight = _safe_float(payload.get("risk_score"), event_risk)
        edges.append(
            {
                "edge_id": _safe_str(edge.id),
                "source_node_type": source_type,
                "source_node_id": source_id,
                "target_node_type": target_type,
                "target_node_id": target_id,
                "relationship_type": relation,
                "created_at": _to_utc(edge.created_at).isoformat() if edge.created_at else None,
                "event_id": _safe_str(edge.event_id) or None,
                "risk_weight": round(risk_weight, 4),
                "payload": payload,
            }
        )

    if ("agent", normalized_agent_id) not in nodes:
        register_node("agent", normalized_agent_id, normalized_agent_id)

    node_counts = Counter(item["node_type"] for item in nodes.values())
    decision_counter: Counter[str] = Counter()
    for row in event_rows:
        decision_counter[_event_decision(row)] += 1

    observed_control_ids = _collect_control_ids_from_agent_events(events=event_rows, anomaly_rows=[])
    owasp_risk_overlays = map_controls_to_owasp(observed_control_ids)

    return {
        "agent_id": normalized_agent_id,
        "window_hours": max(1, min(24 * 180, int(lookback_hours or 24 * 7))),
        "live_updated_at": _utcnow().isoformat(),
        "nodes": sorted(nodes.values(), key=lambda item: (item["node_type"], item["node_id"])),
        "edges": edges,
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "event_count": len(event_rows),
            "node_counts": dict(node_counts),
            "relationship_counts": dict(relationship_counts),
            "decision_counts": dict(decision_counter),
        },
        "owasp_risk_overlays": owasp_risk_overlays,
        "top_connections": [
            {
                "entity": key,
                "relationship_count": count,
            }
            for key, count in connected_counts.most_common(20)
        ],
    }


def _collect_control_ids_from_agent_events(
    *,
    events: list[RuntimeEvent],
    anomaly_rows: list[MonitoringSignal],
) -> list[str]:
    values: set[str] = set(DEFAULT_AGENT_CONTROL_IDS)
    for row in events:
        metadata = _event_metadata(row)
        for key in ("triggered_controls", "related_control_ids", "mapped_controls", "control_ids"):
            for item in list(metadata.get(key) or []):
                token = _safe_str(item)
                if token:
                    values.add(token)
    for row in anomaly_rows:
        payload = _safe_dict(row.payload)
        for item in list(payload.get("control_ids") or []):
            token = _safe_str(item)
            if token:
                values.add(token)
    return sorted(values)


def compute_agent_blast_radius(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    lookback_hours: int = 24 * 7,
) -> dict[str, Any]:
    attack_surface = build_agent_attack_surface_map(
        db,
        tenant_id=tenant_id,
        agent_id=agent_id,
        lookback_hours=lookback_hours,
        max_edges=2000,
    )

    started_at = _started_at(lookback_hours)
    normalized_agent_id = _safe_str(agent_id)
    events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.agent_id == normalized_agent_id,
            RuntimeEvent.created_at >= started_at,
        )
    ).all()
    anomalies = db.scalars(
        select(MonitoringSignal).where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= started_at,
        )
    ).all()
    anomaly_rows: list[MonitoringSignal] = []
    for row in anomalies:
        payload = _safe_dict(row.payload)
        if _extract_agent_id_from_signal(payload) == normalized_agent_id:
            anomaly_rows.append(row)

    adjacency: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for edge in attack_surface["edges"]:
        src = (_safe_str(edge.get("source_node_type")).lower(), _safe_str(edge.get("source_node_id")))
        dst = (_safe_str(edge.get("target_node_type")).lower(), _safe_str(edge.get("target_node_id")))
        relation = _safe_str(edge.get("relationship_type")).lower() or "related_to"
        if src[1] and dst[1]:
            adjacency[src].append((dst[0], dst[1], relation))

    start = ("agent", normalized_agent_id)
    queue: deque[tuple[tuple[str, str], int]] = deque([(start, 0)])
    visited: set[tuple[str, str]] = {start}
    reachable: set[tuple[str, str]] = set()
    propagation_paths: list[dict[str, Any]] = []

    while queue:
        node, depth = queue.popleft()
        if depth >= 6:
            continue
        for next_type, next_id, relation in adjacency.get(node, []):
            candidate = (next_type, next_id)
            if candidate not in visited:
                visited.add(candidate)
                queue.append((candidate, depth + 1))
                reachable.add(candidate)
            propagation_paths.append(
                {
                    "from": f"{node[0]}:{node[1]}",
                    "to": f"{next_type}:{next_id}",
                    "relation": relation,
                    "depth": depth + 1,
                }
            )

    reachable_by_type: dict[str, list[str]] = defaultdict(list)
    for node_type, node_id in sorted(reachable):
        reachable_by_type[node_type].append(node_id)

    severity_values = []
    allow_high_risk = 0
    protective_outcomes = 0
    for row in events:
        severity_values.append(_severity_for_risk_score(_safe_float(row.risk_score, 0.0)))
        decision = _event_decision(row)
        if decision in {"block", "deny", "redact", "modify", "require_approval", "hold_for_approval", "step_up"}:
            protective_outcomes += 1
        if decision in {"allow", "defer"} and _safe_float(row.risk_score, 0.0) >= 0.65:
            allow_high_risk += 1

    anomaly_severity_values = [_safe_str(row.severity).lower() or "low" for row in anomaly_rows]
    dominant_severity = _dominant_severity(severity_values + anomaly_severity_values)
    base_score = (
        (len(reachable) * 1.8)
        + (len([value for value in severity_values if value == "high"]) * 7.0)
        + (len([value for value in severity_values if value == "critical"]) * 10.0)
        + (len([value for value in anomaly_severity_values if value in {"high", "critical"}]) * 8.0)
        + (allow_high_risk * 9.0)
    )
    risk_score = round(max(0.0, min(100.0, base_score)), 2)

    control_ids = _collect_control_ids_from_agent_events(events=events, anomaly_rows=anomaly_rows)[:12]
    pass_rate = (protective_outcomes / max(1, len(events))) * 100.0
    trigger_count = len([value for value in severity_values if value in {"high", "critical"}]) + len(anomaly_rows)
    miss_count = allow_high_risk

    profiles = [
        compute_control_crq_profile(
            control_id=control_id,
            category="agent",
            severity=dominant_severity,
            risk_tags=["agent_abuse", "chain_abuse", "policy_violation"],
            trigger_count=max(1, trigger_count),
            miss_count=max(0, miss_count),
            observed_event_count=max(1, len(events)),
            lookback_hours=max(1, min(24 * 180, int(lookback_hours or 24 * 7))),
            simulation_pass_rate_percent=max(0.0, min(100.0, pass_rate)),
            threat_type="agent_compromise",
            asset="agent_runtime",
            event_id=f"agent-blast:{normalized_agent_id}:{control_id}",
        )
        for control_id in control_ids
    ]

    if profiles:
        baseline_ale = sum(
            _safe_float(_safe_dict(item.get("control_risk_profile")).get("baseline_risk"), 0.0)
            for item in profiles
        ) / len(profiles)
        current_ale = sum(
            _safe_float(_safe_dict(item.get("control_risk_profile")).get("current_risk"), 0.0)
            for item in profiles
        ) / len(profiles)
        risk_reduction = max(0.0, baseline_ale - current_ale)
        likelihood = sum(_safe_float(item.get("likelihood"), 0.0) for item in profiles) / len(profiles)
        confidence = sum(_safe_float(_safe_dict(item.get("control_risk_profile")).get("confidence"), 0.0) for item in profiles) / len(profiles)
    else:
        baseline_ale = current_ale = risk_reduction = likelihood = confidence = 0.0

    return {
        "agent_id": normalized_agent_id,
        "window_hours": max(1, min(24 * 180, int(lookback_hours or 24 * 7))),
        "reachable_assets": {
            "total": len(reachable),
            "by_type": {key: len(value) for key, value in reachable_by_type.items()},
            "nodes": dict(reachable_by_type),
        },
        "risk_score": risk_score,
        "financial_impact": {
            "loss_if_compromised_usd": round(baseline_ale, 2),
            "loss_prevented_usd": round(risk_reduction, 2),
            "annualized_loss_expectancy_usd": round(current_ale, 2),
            "baseline_ale_usd": round(baseline_ale, 2),
            "residual_risk_usd": round(current_ale, 2),
            "likelihood": round(likelihood, 4),
            "confidence": round(confidence, 4),
        },
        "control_ids": control_ids,
        "owasp_risk_overlays": map_controls_to_owasp(control_ids),
        "propagation_paths": propagation_paths[:120],
        "attack_surface_stats": dict(attack_surface.get("stats") or {}),
        "updated_at": _utcnow().isoformat(),
    }


def get_agent_behavior_profile(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    lookback_hours: int = 24 * 7,
) -> dict[str, Any]:
    started_at = _started_at(lookback_hours)
    normalized_agent_id = _safe_str(agent_id)
    events = db.scalars(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == tenant_id,
            RuntimeEvent.agent_id == normalized_agent_id,
            RuntimeEvent.created_at >= started_at,
        )
    ).all()
    baselines = db.scalars(
        select(AgentActionBaseline).where(
            AgentActionBaseline.tenant_id == tenant_id,
            AgentActionBaseline.agent_identity_id == normalized_agent_id,
        )
    ).all()
    anomaly_rows = db.scalars(
        select(MonitoringSignal).where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= started_at,
        )
    ).all()

    relevant_anomalies = []
    for row in anomaly_rows:
        payload = _safe_dict(row.payload)
        if _extract_agent_id_from_signal(payload) == normalized_agent_id:
            relevant_anomalies.append(row)

    usage_time_distribution: Counter[int] = Counter()
    frequency_per_day: Counter[str] = Counter()
    action_type_distribution: Counter[str] = Counter()
    tool_usage_patterns: Counter[str] = Counter()
    data_access_patterns: Counter[str] = Counter()
    source_surface_distribution: Counter[str] = Counter()
    chain_depth_values: list[int] = []
    response_sizes: list[int] = []

    for row in events:
        ts = _to_utc(row.created_at)
        usage_time_distribution[int(ts.hour)] += 1
        frequency_per_day[ts.strftime("%Y-%m-%d")] += 1
        action_type_distribution[_event_action_type(row)] += 1
        source_surface_distribution[_safe_str(row.source_surface).lower() or "unknown"] += 1

        tool_name = _event_tool_name(row)
        if tool_name:
            tool_usage_patterns[tool_name] += 1

        classification = _event_data_classification(row)
        if classification:
            data_access_patterns[classification] += 1

        metadata = _event_metadata(row)
        chain_depth = _safe_int(metadata.get("chain_depth"), -1)
        if chain_depth >= 0:
            chain_depth_values.append(chain_depth)
        response_size = _event_response_bytes(row)
        if response_size > 0:
            response_sizes.append(response_size)

    anomaly_score = round(
        sum(_severity_rank(_safe_str(row.severity)) for row in relevant_anomalies) / max(1, len(relevant_anomalies)),
        3,
    )

    return {
        "agent_id": normalized_agent_id,
        "window_hours": max(1, min(24 * 180, int(lookback_hours or 24 * 7))),
        "usage_patterns": {
            "usage_time_distribution": {str(k): v for k, v in sorted(usage_time_distribution.items())},
            "frequency_per_day": dict(sorted(frequency_per_day.items())),
            "action_type_distribution": dict(action_type_distribution),
            "tool_usage_patterns": dict(tool_usage_patterns),
            "data_access_patterns": dict(data_access_patterns),
            "source_surface_distribution": dict(source_surface_distribution),
            "event_count": len(events),
        },
        "chain_depth": {
            "max": max(chain_depth_values) if chain_depth_values else 0,
            "average": round(sum(chain_depth_values) / len(chain_depth_values), 3) if chain_depth_values else 0.0,
            "samples": len(chain_depth_values),
        },
        "data_volume": {
            "total_bytes": int(sum(response_sizes)) if response_sizes else 0,
            "average_bytes": round(sum(response_sizes) / len(response_sizes), 2) if response_sizes else 0.0,
            "samples": len(response_sizes),
        },
        "baseline": [
            {
                "action": _safe_str(row.action),
                "baseline_rate_per_hour": round(_safe_float(row.baseline_rate_per_hour, 0.0), 4),
                "current_window_count": _safe_int(row.current_window_count, 0),
                "window_started_at": _to_utc(row.window_started_at).isoformat() if row.window_started_at else None,
                "last_seen_at": _to_utc(row.last_seen_at).isoformat() if row.last_seen_at else None,
                "last_anomaly_at": _to_utc(row.last_anomaly_at).isoformat() if row.last_anomaly_at else None,
            }
            for row in baselines
        ],
        "anomaly_score": anomaly_score,
        "anomaly_count_7d": len(relevant_anomalies),
        "updated_at": _utcnow().isoformat(),
    }


def list_agent_anomaly_events(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    lookback_hours: int = 24 * 7,
    limit: int = 50,
) -> list[dict[str, Any]]:
    started_at = _started_at(lookback_hours)
    safe_limit = max(1, min(500, int(limit or 50)))
    normalized_agent_id = _safe_str(agent_id)
    rows = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type.like("ai_anomaly.%"),
            MonitoringSignal.created_at >= started_at,
        )
        .order_by(desc(MonitoringSignal.created_at))
        .limit(safe_limit * 3)
    ).all()

    out: list[dict[str, Any]] = []
    for row in rows:
        payload = _safe_dict(row.payload)
        if _extract_agent_id_from_signal(payload) != normalized_agent_id:
            continue
        out.append(
            {
                "id": row.id,
                "signal_type": _safe_str(row.signal_type),
                "anomaly_type": _safe_str(row.signal_type).replace("ai_anomaly.", "", 1),
                "severity": _safe_str(row.severity).lower() or "low",
                "reason": _safe_str(payload.get("reason")) or "Anomaly detected",
                "confidence": round(_safe_float(payload.get("confidence"), 0.0), 4),
                "created_at": _to_utc(row.created_at).isoformat() if row.created_at else None,
                "related_entities": list(payload.get("related_entities") or []),
                "control_ids": [str(item) for item in list(payload.get("control_ids") or []) if _safe_str(item)],
                "runtime_event_id": _safe_str(payload.get("runtime_event_id")) or None,
                "monitoring_signal_id": row.id,
                "risk_context": {
                    "potential_loss_usd": round(_safe_float(payload.get("potential_loss_usd"), 0.0), 2),
                    "risk_increase_usd": round(_safe_float(payload.get("risk_increase_usd"), 0.0), 2),
                },
                "owasp_mappings": map_controls_to_owasp([str(item) for item in list(payload.get("control_ids") or [])]),
                "payload": payload,
            }
        )
        if len(out) >= safe_limit:
            break
    return out


def enforce_agent_security_action(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    action: AgentEnforcementAction,
    reason: str,
    actor_user_id: str | None,
    tool_allowlist: list[str] | None = None,
    required_approval: bool = False,
    ai_system_id: str | None = None,
    control_ids: list[str] | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    normalized_agent_id = _safe_str(agent_id)
    row = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.id == normalized_agent_id,
        )
    )
    if row is None:
        raise ValueError("Agent not found")

    if action not in {"block_agent", "restrict_tools", "require_approval", "isolate_execution"}:
        raise ValueError("Unsupported enforcement action")

    previous_state = {
        "status": _safe_str(row.status) or "active",
        "action_scope": list(row.action_scope or []),
        "tool_registry": list(row.tool_registry or []),
        "external_system_access": list(row.external_system_access or []),
    }
    enforced_controls = [str(item).strip() for item in (control_ids or DEFAULT_AGENT_CONTROL_IDS) if str(item).strip()]
    enforced_at = _utcnow()

    revoked_tokens = 0
    revoked_delegations = 0
    impacted_agent_ids: list[str] = [normalized_agent_id]

    if action == "block_agent":
        row.status = "blocked"
        row.action_scope = _read_only_scopes(list(row.action_scope or []))
    elif action == "restrict_tools":
        allowlist = [str(item).strip() for item in list(tool_allowlist or []) if str(item).strip()]
        row.status = "restricted"
        row.tool_registry = sorted(set(allowlist))
        row.action_scope = _read_only_scopes(list(row.action_scope or []))
    elif action == "require_approval":
        row.status = "restricted"
        row.action_scope = _read_only_scopes(list(row.action_scope or []))
    elif action == "isolate_execution":
        row.status = "isolated"
        row.action_scope = _read_only_scopes(list(row.action_scope or []))
        row.tool_registry = []
        row.external_system_access = []

    if action in {"block_agent", "isolate_execution"}:
        descendants = collect_delegation_descendant_agent_ids(
            db,
            tenant_id=tenant_id,
            root_agent_identity_id=normalized_agent_id,
        )
        impacted_agent_ids = [normalized_agent_id, *descendants]
        token_rows = db.scalars(
            select(CapabilityToken).where(
                CapabilityToken.tenant_id == tenant_id,
                CapabilityToken.agent_identity_id.in_(impacted_agent_ids),
                CapabilityToken.revoked_at.is_(None),
            )
        ).all()
        for token in token_rows:
            token.revoked_at = enforced_at
            revoked_tokens += 1
        revoked_delegations = revoke_agent_delegations(
            db,
            tenant_id=tenant_id,
            impacted_agent_identity_ids=impacted_agent_ids,
            revoked_at=enforced_at,
        )

    updated_state = {
        "status": _safe_str(row.status),
        "action_scope": list(row.action_scope or []),
        "tool_registry": list(row.tool_registry or []),
        "external_system_access": list(row.external_system_access or []),
    }
    owasp_mappings = map_controls_to_owasp(enforced_controls)

    evidence_row = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="agent_security_enforcement",
        signal_type="ai_discovery.agent_security.enforced",
        label=f"Agent enforcement {normalized_agent_id} -> {action}",
        payload={
            "agent_id": normalized_agent_id,
            "action": action,
            "reason": reason,
            "required_approval": bool(required_approval),
            "control_ids": enforced_controls,
            "previous_state": previous_state,
            "updated_state": updated_state,
            "revoked_tokens": revoked_tokens,
            "revoked_delegations": revoked_delegations,
            "impacted_agent_ids": impacted_agent_ids,
            "owasp_mappings": owasp_mappings,
            "enforced_at": enforced_at.isoformat(),
        },
        correlation_id=correlation_id,
    )

    audit_row = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="ai_discovery.agent_security.enforce",
        resource_type="agent_identity",
        resource_id=normalized_agent_id,
        payload={
            "action": action,
            "reason": reason,
            "required_approval": bool(required_approval),
            "control_ids": enforced_controls,
            "evidence_node_id": evidence_row.id,
            "previous_state": previous_state,
            "updated_state": updated_state,
            "revoked_tokens": revoked_tokens,
            "revoked_delegations": revoked_delegations,
            "impacted_agent_ids": impacted_agent_ids,
            "owasp_mappings": owasp_mappings,
        },
        correlation_id=correlation_id,
    )

    runtime_event_id: str | None = None
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_ai_iam_event

        runtime_row = ingest_from_ai_iam_event(
            db,
            tenant_id=tenant_id,
            event_type="aiiam.agent_security_enforcement",
            ai_system_id=ai_system_id,
            user_id=actor_user_id,
            agent_id=normalized_agent_id,
            severity=("critical" if action in {"block_agent", "isolate_execution"} else "high"),
            evidence_node_ids=[evidence_row.id],
            correlation_id=correlation_id,
            metadata={
                "action": action,
                "reason": reason,
                "required_approval": bool(required_approval),
                "control_ids": enforced_controls,
                "previous_state": previous_state,
                "updated_state": updated_state,
                "revoked_tokens": revoked_tokens,
                "revoked_delegations": revoked_delegations,
                "impacted_agent_ids": impacted_agent_ids,
                "owasp_mappings": owasp_mappings,
                "audit_log_id": audit_row.id,
                "evidence_node_id": evidence_row.id,
            },
            risk_score=(0.95 if action in {"block_agent", "isolate_execution"} else 0.72),
        )
        runtime_event_id = _safe_str(getattr(runtime_row, "event_id", "")) or None
    except Exception:
        runtime_event_id = None

    try:
        publish_runtime_update(
            tenant_id=tenant_id,
            event_type="runtime.agent_security.enforced",
            payload={
                "agent_id": normalized_agent_id,
                "action": action,
                "reason": reason,
                "required_approval": bool(required_approval),
                "control_ids": enforced_controls,
                "updated_state": updated_state,
                "runtime_event_id": runtime_event_id,
                "evidence_node_id": evidence_row.id,
                "audit_log_id": audit_row.id,
                "owasp_mappings": owasp_mappings,
            },
        )
    except Exception:
        # Runtime streaming failures are non-blocking.
        pass

    return {
        "agent_id": normalized_agent_id,
        "action": action,
        "status": "enforced",
        "reason": reason,
        "required_approval": bool(required_approval),
        "control_ids": enforced_controls,
        "previous_state": previous_state,
        "updated_state": updated_state,
        "revoked_tokens": revoked_tokens,
        "revoked_delegations": revoked_delegations,
        "impacted_agent_ids": impacted_agent_ids,
        "owasp_mappings": owasp_mappings,
        "evidence_node_id": evidence_row.id,
        "audit_log_id": audit_row.id,
        "runtime_event_id": runtime_event_id,
        "enforced_at": enforced_at.isoformat(),
    }


def run_agent_security_simulation(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    actor_user_id: str | None,
    ai_system_id: str | None = None,
    pack_id: str | None = None,
    attack_type: str | None = None,
    mode: str = "deterministic",
    max_definitions: int = 8,
    target_control_ids: list[str] | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    normalized_agent_id = _safe_str(agent_id)
    if not normalized_agent_id:
        raise ValueError("agent_id is required")

    resolved_attack_type = _safe_str(attack_type).lower() or "tool_abuse"
    resolved_pack_id = _safe_str(pack_id) or ATTACK_TYPE_TO_PACK.get(resolved_attack_type) or "tool_abuse_pack"
    if get_pack_definition(resolved_pack_id) is None:
        raise ValueError("Unsupported simulation pack for agent security")

    resolved_ai_system_id = _safe_str(ai_system_id)
    if not resolved_ai_system_id:
        latest = db.scalar(
            select(RuntimeEvent)
            .where(
                RuntimeEvent.tenant_id == tenant_id,
                RuntimeEvent.agent_id == normalized_agent_id,
                RuntimeEvent.ai_system_id.is_not(None),
            )
            .order_by(desc(RuntimeEvent.created_at))
        )
        resolved_ai_system_id = _safe_str(getattr(latest, "ai_system_id", None))
    if not resolved_ai_system_id:
        raise ValueError("No ai_system_id available for the selected agent. Pass ai_system_id explicitly.")

    summary = execute_pack(
        db,
        tenant_id=tenant_id,
        pack_id=resolved_pack_id,
        ai_system_id=resolved_ai_system_id,
        mode=("stochastic" if _safe_str(mode).lower() == "stochastic" else "deterministic"),
        stochastic_runs=(5 if _safe_str(mode).lower() == "stochastic" else 1),
        inputs_used={
            "agent_id": normalized_agent_id,
            "attack_type": resolved_attack_type,
            "trigger_source": "ai_discovery_agent_security",
            "correlation_id": correlation_id,
        },
        actor_user_id=actor_user_id,
        max_definitions=max(1, min(50, int(max_definitions or 8))),
        target_control_ids=[str(item).strip() for item in list(target_control_ids or []) if str(item).strip()] or None,
        execution_environment="sandbox",
        approval_granted=False,
    )
    summary["agent_id"] = normalized_agent_id
    summary["attack_type"] = resolved_attack_type
    summary["resolved_pack_id"] = resolved_pack_id
    summary["execution_status"] = "not_executable" if int(summary.get("total_runs") or 0) <= 0 else "executed"
    summary["owasp_mappings"] = map_controls_to_owasp([str(item) for item in list(summary.get("related_control_ids") or [])])
    return summary


def get_agent_owasp_coverage(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    lookback_hours: int = 24 * 7,
) -> dict[str, Any]:
    return build_agent_owasp_coverage(
        db,
        tenant_id=tenant_id,
        agent_id=agent_id,
        lookback_hours=lookback_hours,
    )
