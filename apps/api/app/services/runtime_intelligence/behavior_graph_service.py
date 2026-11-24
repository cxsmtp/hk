from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.runtime_intelligence import RuntimeBehaviorEdge, RuntimeEvent


NODE_ID_MAX_LENGTH = 128
# Some pilot databases were created before the 255-char model landed. Keep
# display labels inside the stricter 128-char shape and preserve full values in
# edge payload metadata when IDs are compacted.
NODE_LABEL_MAX_LENGTH = 128


def _safe_text(value: Any) -> str:
    return str(value or "").strip()


def _is_url_like(value: str) -> bool:
    lowered = value.lower()
    return lowered.startswith(("http://", "https://"))


def _compact_node_value(node_type: str, value: Any) -> tuple[str, dict[str, Any]]:
    raw = _safe_text(value)
    if not raw:
        return "", {}
    if len(raw) <= NODE_ID_MAX_LENGTH:
        return raw, {}

    parsed = urlparse(raw)
    host = (parsed.netloc or "").lower()
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    prefix = _safe_text(node_type).lower() or "node"
    compact = f"{prefix}:{host}:{digest}" if host else f"{prefix}:{digest}"
    return compact[:NODE_ID_MAX_LENGTH], {
        "raw_node_id": raw,
        "node_id_compacted": True,
        "node_id_hash": digest,
        "node_id_original_length": len(raw),
    }


def _display_label(value: Any) -> str | None:
    raw = _safe_text(value)
    if not raw:
        return None
    if _is_url_like(raw):
        parsed = urlparse(raw)
        candidate = parsed.netloc or raw
        if parsed.path and parsed.path != "/":
            candidate = f"{candidate}{parsed.path}"
    else:
        candidate = raw
    if len(candidate) <= NODE_LABEL_MAX_LENGTH:
        return candidate
    return f"{candidate[: NODE_LABEL_MAX_LENGTH - 1]}…"


def _create_edge_if_missing(
    db: Session,
    *,
    tenant_id: str,
    event_id: str | None,
    ai_system_id: str | None,
    source_node_type: str,
    source_node_id: str,
    source_node_label: str | None,
    target_node_type: str,
    target_node_id: str,
    target_node_label: str | None,
    relationship_type: str,
    evidence_node_id: str | None,
    payload: dict[str, Any] | None = None,
) -> RuntimeBehaviorEdge:
    source_compact, source_meta = _compact_node_value(source_node_type, source_node_id)
    target_compact, target_meta = _compact_node_value(target_node_type, target_node_id)
    edge_payload = dict(payload or {})
    if source_meta:
        edge_payload["raw_source_node_id"] = source_meta["raw_node_id"]
        edge_payload["source_node_id_compacted"] = True
        edge_payload["source_node_id_hash"] = source_meta["node_id_hash"]
        edge_payload["source_node_id_original_length"] = source_meta["node_id_original_length"]
    if target_meta:
        edge_payload["raw_target_node_id"] = target_meta["raw_node_id"]
        edge_payload["target_node_id_compacted"] = True
        edge_payload["target_node_id_hash"] = target_meta["node_id_hash"]
        edge_payload["target_node_id_original_length"] = target_meta["node_id_original_length"]
    source_label = _display_label(source_node_label or source_node_id)
    target_label = _display_label(target_node_label or target_node_id)

    existing = db.scalar(
        select(RuntimeBehaviorEdge).where(
            RuntimeBehaviorEdge.tenant_id == tenant_id,
            RuntimeBehaviorEdge.event_id == event_id,
            RuntimeBehaviorEdge.source_node_type == source_node_type,
            RuntimeBehaviorEdge.source_node_id == source_compact,
            RuntimeBehaviorEdge.target_node_type == target_node_type,
            RuntimeBehaviorEdge.target_node_id == target_compact,
            RuntimeBehaviorEdge.relationship_type == relationship_type,
        )
    )
    if existing:
        return existing

    row = RuntimeBehaviorEdge(
        tenant_id=tenant_id,
        event_id=event_id,
        ai_system_id=ai_system_id,
        source_node_type=source_node_type,
        source_node_id=source_compact,
        source_node_label=source_label,
        target_node_type=target_node_type,
        target_node_id=target_compact,
        target_node_label=target_label,
        relationship_type=relationship_type,
        evidence_node_id=evidence_node_id,
        payload=edge_payload,
    )
    db.add(row)
    db.flush()
    return row


def build_behavior_graph_for_event(
    db: Session,
    *,
    event: RuntimeEvent,
    finding_ids: list[str] | None = None,
    related_control_ids: list[str] | None = None,
) -> list[RuntimeBehaviorEdge]:
    metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}
    model_provider = str(metadata.get("model_provider") or metadata.get("provider") or "").strip()
    model_name = str(metadata.get("model_name") or "").strip()
    tool_name = str(metadata.get("tool_name") or "").strip()
    tool_category = str(metadata.get("tool_category") or "").strip()
    api_endpoint = str(metadata.get("api_endpoint") or "").strip()
    data_source = str(metadata.get("data_source") or "").strip()
    parent_agent_id = str(metadata.get("parent_agent_id") or "").strip()
    endpoint_id = str(
        metadata.get("endpoint_id")
        or metadata.get("device_id")
        or metadata.get("machine_id")
        or event.machine_id
        or ""
    ).strip()
    browser_type = str(metadata.get("browser_type") or metadata.get("browser") or event.browser_type or "").strip()
    app_node_id = str(event.app_id or metadata.get("domain") or metadata.get("application") or event.application or "").strip()
    user_node_id = str(event.user_id or metadata.get("source_user_ref") or "").strip()

    created: list[RuntimeBehaviorEdge] = []
    event_node_id = event.event_id
    ai_action = dict(metadata.get("ai_action") or {}) if isinstance(metadata.get("ai_action"), dict) else {}
    ai_action_node_id = str(ai_action.get("action_id") or event.event_id).strip()
    evidence_bundle = (
        dict(ai_action.get("evidence_bundle") or {})
        if isinstance(ai_action.get("evidence_bundle"), dict)
        else {}
    )

    if ai_action_node_id:
        actor = dict(ai_action.get("actor") or {}) if isinstance(ai_action.get("actor"), dict) else {}
        actor_identity_type = _safe_text(actor.get("identity_type")).lower()
        actor_user_id = _safe_text(actor.get("user_id") or event.user_id)
        actor_email = _safe_text(actor.get("email") or metadata.get("user_email"))
        actor_agent_id = _safe_text(actor.get("agent_id") or event.agent_id)
        if actor_user_id or actor_email or actor_agent_id:
            if actor_identity_type == "agent" and actor_agent_id:
                actor_node_type = "agent_identity"
                actor_node_id = actor_agent_id
            elif actor_identity_type in {"service", "service_account", "oauth_app"}:
                actor_node_type = "service_identity"
                actor_node_id = actor_user_id or actor_email or actor_agent_id
            else:
                actor_node_type = "human_user"
                actor_node_id = actor_user_id or actor_email or actor_agent_id
            created.append(
                _create_edge_if_missing(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    ai_system_id=event.ai_system_id,
                    source_node_type=actor_node_type,
                    source_node_id=actor_node_id,
                    source_node_label=actor_email or actor_node_id,
                    target_node_type="ai_action",
                    target_node_id=ai_action_node_id,
                    target_node_label=event.event_type,
                    relationship_type="acted_as",
                    evidence_node_id=None,
                    payload={
                        "identity_type": actor_identity_type or "unknown",
                        "email": actor_email or None,
                        "machine_id": actor.get("machine_id") or event.machine_id,
                        "session_id": actor.get("session_id"),
                    },
                )
            )

        authority = dict(ai_action.get("authority") or {}) if isinstance(ai_action.get("authority"), dict) else {}
        authority_type = str(authority.get("authority_type") or "unknown").strip() or "unknown"
        authority_owner = str(authority.get("authority_owner") or event.user_id or event.agent_id or "unknown").strip() or "unknown"
        authority_node_id = f"{authority_type}:{authority_owner}"
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="ai_action",
                source_node_id=ai_action_node_id,
                source_node_label=event.event_type,
                target_node_type="authority",
                target_node_id=authority_node_id,
                target_node_label=authority_node_id,
                relationship_type="used_authority",
                evidence_node_id=None,
                payload={
                    "authority_type": authority_type,
                    "authority_owner": authority_owner,
                    "standing_privilege": authority.get("standing_privilege"),
                    "control_mode": dict(ai_action.get("policy") or {}).get("control_mode"),
                },
            )
        )

        surface = dict(ai_action.get("surface") or {}) if isinstance(ai_action.get("surface"), dict) else {}
        surface_type = _safe_text(surface.get("surface_type") or event.source_surface or "unknown").lower() or "unknown"
        surface_application = _safe_text(
            surface.get("application")
            or metadata.get("application")
            or event.application
            or app_node_id
        )
        surface_domain = _safe_text(surface.get("domain") or metadata.get("domain") or event.app_id)
        surface_url = _safe_text(surface.get("url") or metadata.get("url"))
        surface_node_id = ":".join(
            part
            for part in [
                surface_type,
                surface_application or surface_domain or surface_url,
            ]
            if part
        )
        if surface_node_id:
            created.append(
                _create_edge_if_missing(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    ai_system_id=event.ai_system_id,
                    source_node_type="ai_action",
                    source_node_id=ai_action_node_id,
                    source_node_label=event.event_type,
                    target_node_type="surface",
                    target_node_id=surface_node_id,
                    target_node_label=surface_application or surface_domain or surface_node_id,
                    relationship_type="observed_on_surface",
                    evidence_node_id=None,
                    payload={
                        "surface_type": surface_type,
                        "source_surface": surface.get("source_surface") or event.source_surface,
                        "application": surface_application or None,
                        "domain": surface_domain or None,
                        "url": surface_url or None,
                        "browser_type": surface.get("browser_type") or browser_type or None,
                        "control_mode": dict(ai_action.get("policy") or {}).get("control_mode"),
                    },
                )
            )

        policy_snapshot = (
            dict(ai_action.get("policy_snapshot") or {})
            if isinstance(ai_action.get("policy_snapshot"), dict)
            else {}
        )
        policy_snapshot_id = str(
            policy_snapshot.get("policy_snapshot_id")
            or dict(ai_action.get("policy") or {}).get("policy_snapshot_id")
            or ""
        ).strip()
        if policy_snapshot_id:
            created.append(
                _create_edge_if_missing(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    ai_system_id=event.ai_system_id,
                    source_node_type="ai_action",
                    source_node_id=ai_action_node_id,
                    source_node_label=event.event_type,
                    target_node_type="policy",
                    target_node_id=policy_snapshot_id,
                    target_node_label=str(policy_snapshot.get("policy_name") or policy_snapshot_id),
                    relationship_type="triggered_policy",
                    evidence_node_id=None,
                    payload={
                        "policy_snapshot_id": policy_snapshot_id,
                        "policy_id": policy_snapshot.get("policy_id"),
                        "policy_version": policy_snapshot.get("policy_version"),
                        "decision": dict(ai_action.get("policy") or {}).get("decision"),
                        "control_mode": dict(ai_action.get("policy") or {}).get("control_mode"),
                    },
                )
            )

        evidence_bundle_id = str(evidence_bundle.get("evidence_bundle_id") or "").strip()
        if evidence_bundle_id:
            created.append(
                _create_edge_if_missing(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    ai_system_id=event.ai_system_id,
                    source_node_type="ai_action",
                    source_node_id=ai_action_node_id,
                    source_node_label=event.event_type,
                    target_node_type="evidence_bundle",
                    target_node_id=evidence_bundle_id,
                    target_node_label=evidence_bundle_id,
                    relationship_type="has_evidence",
                    evidence_node_id=None,
                    payload={
                        "integrity_status": evidence_bundle.get("integrity_status"),
                        "bundle_hash": evidence_bundle.get("bundle_hash"),
                        "evidence_refs": list(evidence_bundle.get("evidence_refs") or []),
                    },
                )
            )

    if event.user_id and endpoint_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="user",
                source_node_id=str(event.user_id),
                source_node_label=str(event.user_id),
                target_node_type="device",
                target_node_id=endpoint_id,
                target_node_label=str(metadata.get("hostname") or endpoint_id),
                relationship_type="uses",
                evidence_node_id=None,
                payload={
                    "os_type": metadata.get("os_type") or metadata.get("os"),
                    "os_version": metadata.get("os_version"),
                    "source_surface": event.source_surface,
                },
            )
        )

    if endpoint_id and browser_type:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="device",
                source_node_id=endpoint_id,
                source_node_label=str(metadata.get("hostname") or endpoint_id),
                target_node_type="browser",
                target_node_id=browser_type,
                target_node_label=browser_type,
                relationship_type="uses",
                evidence_node_id=None,
                payload={
                    "browser_version": metadata.get("browser_version"),
                    "extension_version": metadata.get("extension_version"),
                    "source_surface": event.source_surface,
                },
            )
        )

    if user_node_id and app_node_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="user",
                source_node_id=user_node_id,
                source_node_label=user_node_id,
                target_node_type="app",
                target_node_id=app_node_id,
                target_node_label=app_node_id,
                relationship_type="uses",
                evidence_node_id=None,
                payload={"source_surface": event.source_surface},
            )
        )

    if user_node_id and app_node_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="user",
                source_node_id=user_node_id,
                source_node_label=user_node_id,
                target_node_type="app",
                target_node_id=app_node_id,
                target_node_label=app_node_id,
                relationship_type="runtime.user_to_app",
                evidence_node_id=None,
            )
        )

    if event.app_id and event.ai_system_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="app",
                source_node_id=str(event.app_id),
                source_node_label=str(event.app_id),
                target_node_type="ai_system",
                target_node_id=str(event.ai_system_id),
                target_node_label=str(event.ai_system_id),
                relationship_type="runtime.app_to_ai_system",
                evidence_node_id=None,
            )
        )

    model_node_id = ":".join(part for part in [model_provider, model_name] if part) or (model_name or model_provider)
    if event.agent_id and model_node_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="agent",
                source_node_id=str(event.agent_id),
                source_node_label=str(event.agent_id),
                target_node_type="model",
                target_node_id=model_node_id,
                target_node_label=model_node_id,
                relationship_type="uses",
                evidence_node_id=None,
                payload={"model_provider": model_provider or None, "model_name": model_name or None},
            )
        )

    if app_node_id and model_node_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="app",
                source_node_id=app_node_id,
                source_node_label=app_node_id,
                target_node_type="model",
                target_node_id=model_node_id,
                target_node_label=model_node_id,
                relationship_type="uses",
                evidence_node_id=None,
                payload={"model_provider": model_provider or None, "model_name": model_name or None},
            )
        )

    if event.ai_system_id and model_node_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="ai_system",
                source_node_id=str(event.ai_system_id),
                source_node_label=str(event.ai_system_id),
                target_node_type="model",
                target_node_id=model_node_id,
                target_node_label=model_node_id,
                relationship_type="runtime.ai_system_to_model",
                evidence_node_id=None,
                payload={"model_provider": model_provider or None, "model_name": model_name or None},
            )
        )

    if event.ai_system_id and tool_name:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="ai_system",
                source_node_id=str(event.ai_system_id),
                source_node_label=str(event.ai_system_id),
                target_node_type="tool",
                target_node_id=tool_name,
                target_node_label=(f"{tool_name} ({tool_category})" if tool_category else tool_name),
                relationship_type="runtime.ai_system_to_tool",
                evidence_node_id=None,
                payload={"tool_category": tool_category or None},
            )
        )

    if model_node_id and tool_name:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="model",
                source_node_id=model_node_id,
                source_node_label=model_node_id,
                target_node_type="tool",
                target_node_id=tool_name,
                target_node_label=(f"{tool_name} ({tool_category})" if tool_category else tool_name),
                relationship_type="runtime.model_to_tool",
                evidence_node_id=None,
                payload={"tool_category": tool_category or None},
            )
        )

    if event.agent_id and tool_name:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="agent",
                source_node_id=str(event.agent_id),
                source_node_label=str(event.agent_id),
                target_node_type="tool",
                target_node_id=tool_name,
                target_node_label=(f"{tool_name} ({tool_category})" if tool_category else tool_name),
                relationship_type="invokes",
                evidence_node_id=None,
                payload={"tool_category": tool_category or None},
            )
        )

    if tool_name and api_endpoint:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="tool",
                source_node_id=tool_name,
                source_node_label=(f"{tool_name} ({tool_category})" if tool_category else tool_name),
                target_node_type="api",
                target_node_id=api_endpoint,
                target_node_label=api_endpoint,
                relationship_type="runtime.tool_to_api",
                evidence_node_id=None,
                payload={"tool_category": tool_category or None},
            )
        )

    if event.agent_id and api_endpoint:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="agent",
                source_node_id=str(event.agent_id),
                source_node_label=str(event.agent_id),
                target_node_type="api",
                target_node_id=api_endpoint,
                target_node_label=api_endpoint,
                relationship_type="connects_to",
                evidence_node_id=None,
                payload={"tool_name": tool_name or None, "tool_category": tool_category or None},
            )
        )

    if api_endpoint and data_source:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="api",
                source_node_id=api_endpoint,
                source_node_label=api_endpoint,
                target_node_type="data_source",
                target_node_id=data_source,
                target_node_label=data_source,
                relationship_type="runtime.api_to_data_source",
                evidence_node_id=None,
            )
        )

    action_data_entities: list[str] = []
    canonical_action = dict(metadata.get("canonical_action") or {}) if isinstance(metadata.get("canonical_action"), dict) else {}
    for value in [
        data_source,
        api_endpoint,
        str(metadata.get("target_resource") or "").strip(),
        str(metadata.get("resource") or "").strip(),
        *[str(item).strip() for item in list(canonical_action.get("data_entities") or []) if str(item).strip()],
    ]:
        if value and value not in action_data_entities:
            action_data_entities.append(value)
    for data_object_id in action_data_entities:
        if event.agent_id:
            created.append(
                _create_edge_if_missing(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    ai_system_id=event.ai_system_id,
                    source_node_type="agent",
                    source_node_id=str(event.agent_id),
                    source_node_label=str(event.agent_id),
                    target_node_type="data_object",
                    target_node_id=data_object_id,
                    target_node_label=data_object_id,
                    relationship_type="accesses",
                    evidence_node_id=None,
                    payload={
                        "data_classification": metadata.get("data_classification")
                        or metadata.get("source_classification_hint")
                        or metadata.get("classification"),
                        "source_surface": event.source_surface,
                    },
                )
            )

        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="action",
                source_node_id=event_node_id,
                source_node_label=event.event_type,
                target_node_type="data_object",
                target_node_id=data_object_id,
                target_node_label=data_object_id,
                relationship_type="accesses",
                evidence_node_id=None,
                payload={
                    "data_classification": metadata.get("data_classification")
                    or metadata.get("source_classification_hint")
                    or metadata.get("classification"),
                    "source_surface": event.source_surface,
                },
            )
        )

    if parent_agent_id and event.agent_id:
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="agent",
                source_node_id=parent_agent_id,
                source_node_label=parent_agent_id,
                target_node_type="agent",
                target_node_id=str(event.agent_id),
                target_node_label=str(event.agent_id),
                relationship_type="runtime.parent_agent_to_agent",
                evidence_node_id=None,
            )
        )

    graph_finding_ids = {
        str(item).strip()
        for item in (finding_ids or [])
        if str(item).strip()
    }
    graph_finding_ids.update(
        str(item).strip()
        for item in list(evidence_bundle.get("related_finding_ids") or [])
        if str(item).strip()
    )
    for value in [
        ai_action.get("finding_id"),
        metadata.get("finding_id"),
    ]:
        if str(value or "").strip():
            graph_finding_ids.add(str(value).strip())

    for finding_id in sorted(graph_finding_ids):
        if ai_action_node_id:
            created.append(
                _create_edge_if_missing(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    ai_system_id=event.ai_system_id,
                    source_node_type="ai_action",
                    source_node_id=ai_action_node_id,
                    source_node_label=event.event_type,
                    target_node_type="finding",
                    target_node_id=finding_id,
                    target_node_label=finding_id,
                    relationship_type="created_finding",
                    evidence_node_id=None,
                )
            )
        created.append(
            _create_edge_if_missing(
                db,
                tenant_id=event.tenant_id,
                event_id=event.event_id,
                ai_system_id=event.ai_system_id,
                source_node_type="event",
                source_node_id=event_node_id,
                source_node_label=event.event_type,
                target_node_type="finding",
                target_node_id=finding_id,
                target_node_label=finding_id,
                relationship_type="runtime.event_to_finding",
                evidence_node_id=None,
            )
        )

    controls = sorted({str(item) for item in (related_control_ids or []) if str(item).strip()})
    for finding_id in sorted(graph_finding_ids):
        for control_id in controls:
            created.append(
                _create_edge_if_missing(
                    db,
                    tenant_id=event.tenant_id,
                    event_id=event.event_id,
                    ai_system_id=event.ai_system_id,
                    source_node_type="finding",
                    source_node_id=finding_id,
                    source_node_label=finding_id,
                    target_node_type="control",
                    target_node_id=control_id,
                    target_node_label=control_id,
                    relationship_type="runtime.finding_to_control",
                    evidence_node_id=None,
                )
            )

    return created
