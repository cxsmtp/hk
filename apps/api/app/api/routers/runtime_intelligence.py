from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import math
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session

from app.api.envelopes import ListEnvelope, paginate_rows
from app.core.config import settings
from app.core.control_engine.canonical_action import (
    MAX_DELEGATION_DEPTH,
    MAX_LIST_ITEMS,
    canonical_field_material,
)
from app.core.rbac import holds, require_permission
from app.core.tenant import TenantContext, require_stream_tenant
from app.db.models.evidence import DecisionReceipt, EvidenceNode, ExecutionIntegrityResult, ExecutionReceipt
from app.db.models.finding import Finding
from app.db.models.policy import ApprovalBinding
from app.db.models.runtime_intelligence import RuntimeBehaviorEdge, RuntimeEvent, RuntimeGovernanceRecommendation, RuntimeSimulationTrigger
from app.db.session import get_db
from app.services.control_graph_service import infer_runtime_control_mapping, normalize_control_ids
from app.services.agentic_action_integrity_service import chain_evidence, chain_graph, record_deferred_side_effect
from app.services.receipt_service import (
    verify_decision_receipt,
    verify_execution_receipt,
    verify_integrity_evidence,
)
from app.services.privacy_sanitizer import (
    BINARY_OMITTED,
    HASHED_ONLY,
    REDACTED,
    sanitize_privacy_scalar,
)
from app.services.runtime_intelligence.runtime_correlation_service import RUNTIME_FINDING_TYPES
from app.services.runtime_intelligence.streaming import stream_runtime_updates


router = APIRouter(prefix="/runtime-intelligence", tags=["runtime-intelligence"])


def _require_stream_viewer(ctx: TenantContext = Depends(require_stream_tenant)) -> TenantContext:
    if not holds(ctx, "activity.view"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
    return ctx


def _runtime_stream_response(*, tenant_id: str, channel: str) -> StreamingResponse:
    return StreamingResponse(
        stream_runtime_updates(tenant_id=tenant_id, channel=channel),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


class RuntimeEventResponse(BaseModel):
    event_id: str
    tenant_id: str
    source_surface: str
    event_type: str
    ai_system_id: str | None = None
    app_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    risk_tier: str | None = None
    policy_version_id: str | None = None
    governance_version: str | None = None
    severity: str | None = None
    confidence_tier: str | None = None
    evidence_node_ids: list[str]
    correlation_id: str | None = None
    context_id: str | None = None
    chain_id: str | None = None
    parent_action_id: str | None = None
    entity_type: str | None = None
    entity_id: str | None = None
    risk_score: float = 0.0
    created_at: datetime
    model_provider: str | None = None
    provider: str | None = None
    model_name: str | None = None
    model_version: str | None = None
    tool_name: str | None = None
    tool_category: str | None = None
    api_endpoint: str | None = None
    data_source: str | None = None
    response_size: int | None = None
    chain_depth: int | None = None
    parent_agent_id: str | None = None
    metadata: dict[str, Any]


class RuntimeFindingResponse(BaseModel):
    finding_id: str
    tenant_id: str
    source_surface: str
    ai_tool: str
    ai_system_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    machine_id: str | None = None
    severity: str
    finding_type: str
    risk_category: str
    status: str
    recommended_action: str
    policy_version_id: str | None = None
    evidence_node_ids: list[str]
    related_event_ids: list[str] = Field(default_factory=list)
    related_control_ids: list[str]
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class RuntimeGraphNode(BaseModel):
    node_type: str
    node_id: str
    label: str | None = None


class RuntimeGraphEdgeResponse(BaseModel):
    edge_id: str
    relationship_type: str
    source_node_type: str
    source_node_id: str
    target_node_type: str
    target_node_id: str
    evidence_node_id: str | None = None
    event_id: str | None = None
    created_at: datetime
    payload: dict[str, Any]


class RuntimeGraphResponse(BaseModel):
    ai_system_id: str
    nodes: list[RuntimeGraphNode]
    edges: list[RuntimeGraphEdgeResponse]
    total_edges: int


class RuntimeActionGraphResponse(BaseModel):
    action_id: str
    runtime_event_id: str
    ai_system_id: str | None = None
    nodes: list[RuntimeGraphNode]
    edges: list[RuntimeGraphEdgeResponse]
    total_edges: int


class RuntimeActionTraceResponse(BaseModel):
    action_id: str
    runtime_event: dict[str, Any]
    ai_action: dict[str, Any] = Field(default_factory=dict)
    canonical_ai_action: dict[str, Any] = Field(default_factory=dict)
    canonical_ai_action_status: str = "unavailable"
    policy_snapshot: dict[str, Any] = Field(default_factory=dict)
    decision_explanation: dict[str, Any] = Field(default_factory=dict)
    evidence_bundle: dict[str, Any] = Field(default_factory=dict)
    decision_receipt: dict[str, Any] = Field(default_factory=dict)
    execution_receipt: dict[str, Any] = Field(default_factory=dict)
    execution_integrity: dict[str, Any] = Field(default_factory=dict)
    related_findings: list[dict[str, Any]] = Field(default_factory=list)
    graph: dict[str, Any] = Field(default_factory=dict)
    investigation_links: dict[str, str] = Field(default_factory=dict)


class RuntimeAgentGraphResponse(BaseModel):
    agent_id: str
    nodes: list[RuntimeGraphNode]
    edges: list[RuntimeGraphEdgeResponse]
    total_edges: int
    event_count: int
    decision_counts: dict[str, int]
    linked_ai_system_ids: list[str]
    max_observed_chain_depth: int


class RuntimeTriggerResponse(BaseModel):
    trigger_id: str
    tenant_id: str
    ai_system_id: str | None = None
    event_id: str | None = None
    reason_code: str
    target_pack: str
    related_control_ids: list[str]
    evidence_node_ids: list[str]
    correlation_id: str | None = None
    recommended_action: str
    status: str
    schedule_decision_id: str | None = None
    created_at: datetime
    updated_at: datetime


class RuntimeRecommendationResponse(BaseModel):
    recommendation_id: str
    tenant_id: str
    event_id: str
    ai_system_id: str | None = None
    recommendation_type: str
    reason_code: str
    priority: str
    payload: dict[str, Any]
    status: str
    created_at: datetime
    applied_at: datetime | None = None


class DeferredSideEffectRequest(BaseModel):
    chain_id: str
    action_id: str | None = None
    agent_id: str | None = None
    side_effect_type: str
    target_system: str | None = None
    target_resource: str | None = None
    external_destination: str | None = None
    persistence_duration: str | None = None


class RuntimeFindingsEnvelope(BaseModel):
    items: list[RuntimeFindingResponse]
    total: int
    page: int
    page_size: int
    recommendation_count: int = 0


_SAFE_SIGNATURE_FIELDS = {
    "signature_present",
    "signature_verified",
}
_CANONICAL_DISPLAY_TOP_LEVEL_FIELDS = {
    "schema_name",
    "schema_version",
    "action_id",
    "tenant_id",
    "chain_id",
    "actor",
    "authority",
    "purpose",
    "surface",
    "action",
    "approval",
    "policy",
    "transformations",
}
_CANONICAL_DISPLAY_OPTIONAL_TOP_LEVEL_FIELDS = {"provenance"}
_CANONICAL_DISPLAY_ACTION_FIELDS = {
    "action_type",
    "action_category",
    "tool_name",
    "tool_version",
    "tool_fingerprint_id",
    "parameter_hash",
    "target_resource_hash",
    "destination_hash",
    "side_effect_class",
}
_CANONICAL_DISPLAY_OPTIONAL_ACTION_FIELDS = {
    "redacted_arguments",
    "target_resource",
    "data_destination",
    "persistent_side_effect",
}
_CANONICAL_DISPLAY_POLICY_FIELDS = {
    "policy_snapshot_id",
    "decision",
    "control_mode",
}
_CANONICAL_DISPLAY_ACTOR_FIELDS = {
    "identity_id",
    "identity_type",
    "user_id",
    "agent_id",
    "session_id",
    "runtime_instance_id",
    "machine_id",
    "acting_on_behalf_of",
    "acting_on_behalf_of_user_id",
    "delegation_chain",
}
_CANONICAL_DISPLAY_AUTHORITY_FIELDS = {
    "authority_type",
    "authority_source",
    "authority_owner",
    "standing_privilege",
    "jit_grant_id",
    "permission_scope",
    "verified",
}
_CANONICAL_DISPLAY_PURPOSE_FIELDS = {
    "tenant_sector",
    "business_function",
    "declared_purpose",
    "inferred_purpose",
    "purpose_confidence",
    "business_relevance",
    "purpose_status",
}
_CANONICAL_DISPLAY_SURFACE_FIELDS = {
    "surface_type",
    "collector_type",
    "application",
    "provider",
    "model",
    "environment",
    "domain",
    "endpoint",
    "repo_id",
    "workspace_id",
    "mcp_server_id",
    "asset_status",
}
_AUTHORIZATION_PROJECTED_NULLABLE_SURFACE_FIELDS = {
    "application",
    "provider",
    "model",
    "mcp_server_id",
    "asset_status",
}
_RECEIPT_PROJECTED_NULLABLE_ACTOR_FIELDS = {
    "identity_id",
    "user_id",
    "agent_id",
    "session_id",
    "machine_id",
    "acting_on_behalf_of_user_id",
}
_RECEIPT_PROJECTED_NULLABLE_AUTHORITY_FIELDS = {
    "authority_owner",
    "jit_grant_id",
}
_LEGACY_COMPATIBILITY_TEXT_FIELDS = {
    "actor": {
        "identity_id",
        "identity_type",
        "user_id",
        "agent_id",
        "session_id",
        "machine_id",
        "acting_on_behalf_of",
        "acting_on_behalf_of_user_id",
    },
    "surface": {
        "surface_type",
        "collector_type",
        "source_surface",
        "application",
        "provider",
        "model",
        "environment",
        "domain",
        "browser_type",
        "repo_id",
        "workspace_id",
        "mcp_server_id",
        "asset_status",
    },
    "action": {
        "action_type",
        "action_category",
        "operation",
        "risk_level",
        "action_risk",
        "tool_name",
        "tool_version",
        "tool_fingerprint_id",
        "parameter_hash",
        "target_resource_hash",
        "destination_hash",
        "input_ref",
        "output_ref",
        "side_effect_class",
    },
    "authority": {
        "authority_type",
        "authority_source",
        "authority_owner",
        "standing_privilege",
        "jit_grant_id",
    },
    "approval": {
        "approval_id",
        "approval_binding_id",
        "approval_status",
    },
    "policy": {
        "policy_snapshot_id",
        "decision",
        "control_mode",
        "decision_badge",
        "reason_code",
    },
    "evidence": {
        "decision_receipt_id",
        "execution_receipt_id",
        "evidence_bundle_id",
        "trace_id",
        "integrity_status",
        "event_hash",
        "finding_id",
    },
    "context": {
        "chain_id",
        "parent_action_id",
        "correlation_id",
        "trace_id",
    },
}
_LEGACY_COMPATIBILITY_BOOL_FIELDS = {
    "action": {"persistent_side_effect"},
    "authority": {"verified"},
    "approval": {"approval_required"},
}
_LEGACY_COMPATIBILITY_LIST_FIELDS = {
    "authority": {"permission_scope"},
    "policy": {"control_ids", "policy_ids", "matched_rules"},
    "evidence": {"evidence_refs"},
}
_LEGACY_POLICY_SNAPSHOT_TEXT_FIELDS = {
    "policy_snapshot_id",
    "snapshot_id",
    "version",
    "decision",
    "control_mode",
    "decision_badge",
    "reason_code",
    "evaluated_at",
    "created_at",
}
_LEGACY_DECISION_EXPLANATION_TEXT_FIELDS = {
    "explanation_id",
    "decision_id",
    "action_id",
    "tenant_id",
    "timestamp",
    "reason_code",
    "decision",
    "control_mode",
    "decision_badge",
}
_LEGACY_EVIDENCE_BUNDLE_TEXT_FIELDS = {
    "bundle_id",
    "evidence_bundle_id",
    "decision_receipt_id",
    "execution_receipt_id",
    "trace_id",
    "integrity_status",
    "event_hash",
}
_GRAPH_EDGE_PAYLOAD_TEXT_FIELDS = {
    "action_id",
    "tenant_id",
    "chain_id",
    "context_id",
    "correlation_id",
    "trace_id",
    "event_id",
    "finding_id",
    "policy_snapshot_id",
    "control_id",
    "reason_code",
    "decision",
    "control_mode",
    "status",
    "integrity_status",
    "evidence_node_id",
    "evidence_bundle_id",
    "decision_receipt_id",
    "execution_receipt_id",
    "execution_attempt_id",
    "canonical_action_hash",
    "event_hash",
    "parameter_hash",
    "target_resource_hash",
    "destination_hash",
    "tool_fingerprint_id",
    "side_effect_class",
    "collector_id",
    "signing_key_id",
}


def _signature_field_name(key: Any) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    compact = normalized.replace("_", "")
    return "signature" in compact or compact == "signedreceipt"


def _without_raw_signature_values(value: Any) -> Any:
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _SAFE_SIGNATURE_FIELDS:
                if type(item) is bool:
                    output[str(key)] = item
                continue
            if _signature_field_name(key):
                continue
            output[str(key)] = _without_raw_signature_values(item)
        return output
    if isinstance(value, (list, tuple)):
        return [_without_raw_signature_values(item) for item in value]
    return value


def _is_finite_json(value: Any) -> bool:
    if value is None or type(value) in {bool, int, str}:
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_finite_json(item) for item in value)
    if isinstance(value, Mapping):
        return all(
            type(key) is str and _is_finite_json(item)
            for key, item in value.items()
        )
    return False


def _contains_signature_field(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            _signature_field_name(key) or _contains_signature_field(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_signature_field(item) for item in value)
    return False


def _exact_nonempty_strings(mapping: Mapping[str, Any], fields: set[str]) -> bool:
    return all(
        type(mapping.get(field)) is str and bool(mapping[field].strip())
        for field in fields
    )


def _exact_nonempty_string_list(value: Any, *, max_items: int) -> bool:
    return (
        type(value) is list
        and len(value) <= max_items
        and all(type(item) is str and bool(item.strip()) for item in value)
    )


def _bounded_legacy_text(value: Any, *, key: str) -> str | None:
    if type(value) is not str or not value.strip():
        return None
    if len(value.encode("utf-8")) > 512:
        return None
    sanitized = sanitize_privacy_scalar(value, key=key)
    if type(sanitized) is not str or not sanitized.strip():
        return None
    return sanitized if len(sanitized.encode("utf-8")) <= 512 else None


def _closed_legacy_mapping_projection(
    source: Any,
    *,
    text_fields: set[str],
    bool_fields: set[str] | None = None,
    list_fields: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(source, Mapping):
        return {}
    projected: dict[str, Any] = {}
    for field in text_fields:
        value = _bounded_legacy_text(source.get(field), key=field)
        if value is not None:
            projected[field] = value
    for field in bool_fields or set():
        value = source.get(field)
        if type(value) is bool:
            projected[field] = value
    for field in list_fields or set():
        value = source.get(field)
        if type(value) is not list or len(value) > MAX_LIST_ITEMS:
            continue
        items: list[str] = []
        valid = True
        for item in value:
            safe_item = _bounded_legacy_text(item, key=field)
            if safe_item is None:
                valid = False
                break
            items.append(safe_item)
        if valid:
            projected[field] = items
    return projected


def _legacy_policy_snapshot_projection(source: Any) -> dict[str, Any]:
    return _closed_legacy_mapping_projection(
        source,
        text_fields=_LEGACY_POLICY_SNAPSHOT_TEXT_FIELDS,
        list_fields={"control_ids", "policy_ids", "matched_rules"},
    )


def _legacy_decision_explanation_projection(source: Any) -> dict[str, Any]:
    projected = _closed_legacy_mapping_projection(
        source,
        text_fields=_LEGACY_DECISION_EXPLANATION_TEXT_FIELDS,
    )
    if isinstance(source, Mapping):
        summary = _closed_legacy_mapping_projection(
            source.get("decision_summary"),
            text_fields={
                "final_decision",
                "control_mode",
                "decision_badge",
                "reason_code",
            },
        )
        if summary:
            projected["decision_summary"] = summary
    return projected


def _legacy_evidence_bundle_projection(source: Any) -> dict[str, Any]:
    return _closed_legacy_mapping_projection(
        source,
        text_fields=_LEGACY_EVIDENCE_BUNDLE_TEXT_FIELDS,
        list_fields={"evidence_refs"},
    )


def _legacy_ai_action_projection(source: Any) -> dict[str, Any]:
    if not isinstance(source, Mapping):
        return {}
    projected = _closed_legacy_mapping_projection(
        source,
        text_fields={
            "schema_name",
            "schema_version",
            "action_id",
            "tenant_id",
            "chain_id",
            "timestamp",
            "signing_key_id",
        },
        bool_fields={"signature_present"},
    )
    for section, text_fields in _LEGACY_COMPATIBILITY_TEXT_FIELDS.items():
        section_value = _closed_legacy_mapping_projection(
            source.get(section),
            text_fields=text_fields,
            bool_fields=_LEGACY_COMPATIBILITY_BOOL_FIELDS.get(section),
            list_fields=_LEGACY_COMPATIBILITY_LIST_FIELDS.get(section),
        )
        if section_value:
            projected[section] = section_value
    nested_projections = (
        ("policy_snapshot", _legacy_policy_snapshot_projection),
        ("decision_explanation", _legacy_decision_explanation_projection),
        ("evidence_bundle", _legacy_evidence_bundle_projection),
    )
    for field, projector in nested_projections:
        nested = projector(source.get(field))
        if nested:
            projected[field] = nested
    return projected


def _graph_edge_payload_projection(source: Any) -> dict[str, Any]:
    return _closed_legacy_mapping_projection(
        source,
        text_fields=_GRAPH_EDGE_PAYLOAD_TEXT_FIELDS,
        bool_fields={
            "signature_present",
            "signature_verified",
            "verified",
            "collector_inline_capable",
            "inline_pre_execution",
        },
        list_fields={
            "evidence_node_ids",
            "evidence_refs",
            "control_ids",
            "policy_ids",
            "matched_rules",
            "drift_fields",
        },
    )


def _action_trace_graph_edge_projection(
    edge: RuntimeGraphEdgeResponse,
) -> dict[str, Any]:
    projected = edge.model_dump()
    projected["payload"] = _graph_edge_payload_projection(edge.payload)
    return projected


def _explicitly_redacted_json(value: Any) -> bool:
    if value is None:
        return True
    if type(value) is str:
        return value in {
            REDACTED,
            HASHED_ONLY,
            BINARY_OMITTED,
            "[omitted:max_depth]",
        }
    if type(value) is list:
        return all(_explicitly_redacted_json(item) for item in value)
    if isinstance(value, Mapping):
        for key, item in value.items():
            if type(key) is not str:
                return False
            compact_key = "".join(character for character in key.lower() if character.isalnum())
            if any(
                token in compact_key
                for token in (
                    "signature",
                    "signedreceipt",
                    "arguments",
                    "toolargs",
                    "parameters",
                    "rawprompt",
                    "prompt",
                    "content",
                    "secret",
                    "password",
                    "apikey",
                    "accesstoken",
                    "refreshtoken",
                    "request",
                    "response",
                )
            ):
                return False
            if not _explicitly_redacted_json(item):
                return False
        return True
    return False


def _safe_optional_canonical_text(value: Any, *, key: str) -> bool:
    if value is None:
        return True
    if type(value) is not str or not value.strip():
        return False
    if len(value.encode("utf-8")) > 1024:
        return False
    return sanitize_privacy_scalar(value, key=key) == value


def _canonical_display_schema_is_valid(canonical: Mapping[str, Any]) -> bool:
    if (
        not _CANONICAL_DISPLAY_TOP_LEVEL_FIELDS.issubset(canonical)
        or not set(canonical).issubset(
            _CANONICAL_DISPLAY_TOP_LEVEL_FIELDS
            | _CANONICAL_DISPLAY_OPTIONAL_TOP_LEVEL_FIELDS
        )
    ):
        return False
    if canonical.get("schema_name") != "hawk.ai_action" or canonical.get("schema_version") != "1.0":
        return False
    if not _exact_nonempty_strings(
        canonical,
        {"action_id", "tenant_id", "chain_id"},
    ):
        return False
    if not _is_finite_json(canonical) or _contains_signature_field(canonical):
        return False
    try:
        canonical_field_material(canonical)
    except (TypeError, ValueError):
        return False

    actor = canonical.get("actor")
    authority = canonical.get("authority")
    purpose = canonical.get("purpose")
    surface = canonical.get("surface")
    action = canonical.get("action")
    approval = canonical.get("approval")
    policy = canonical.get("policy")
    if not all(
        isinstance(item, Mapping)
        for item in (actor, authority, purpose, surface, action, approval, policy)
    ):
        return False
    if not set(actor).issubset(_CANONICAL_DISPLAY_ACTOR_FIELDS):
        return False
    for field, value in actor.items():
        if field == "delegation_chain":
            if not _exact_nonempty_string_list(
                value,
                max_items=MAX_DELEGATION_DEPTH,
            ):
                return False
        elif value is None and field in _RECEIPT_PROJECTED_NULLABLE_ACTOR_FIELDS:
            continue
        elif type(value) is not str or not value.strip():
            return False
    if not set(authority).issubset(_CANONICAL_DISPLAY_AUTHORITY_FIELDS):
        return False
    for field, value in authority.items():
        if field == "permission_scope":
            if not _exact_nonempty_string_list(value, max_items=MAX_LIST_ITEMS):
                return False
        elif field == "verified":
            if type(value) is not bool and value != "unknown":
                return False
        elif value is None and field in _RECEIPT_PROJECTED_NULLABLE_AUTHORITY_FIELDS:
            continue
        elif type(value) is not str or not value.strip():
            return False
    if not set(purpose).issubset(_CANONICAL_DISPLAY_PURPOSE_FIELDS):
        return False
    for field, value in purpose.items():
        if field == "purpose_confidence":
            if value != "unknown" and (
                type(value) not in {int, float}
                or not math.isfinite(float(value))
            ):
                return False
        elif type(value) is not str or not value.strip():
            return False
    if not set(surface).issubset(_CANONICAL_DISPLAY_SURFACE_FIELDS):
        return False
    for field, value in surface.items():
        if value is None and field in _AUTHORIZATION_PROJECTED_NULLABLE_SURFACE_FIELDS:
            continue
        if type(value) is not str or not value.strip():
            return False
    if "surface_type" not in surface:
        return False
    action_fields = set(action)
    if (
        not _CANONICAL_DISPLAY_ACTION_FIELDS.issubset(action_fields)
        or not action_fields.issubset(
            _CANONICAL_DISPLAY_ACTION_FIELDS
            | _CANONICAL_DISPLAY_OPTIONAL_ACTION_FIELDS
        )
        or not _exact_nonempty_strings(action, _CANONICAL_DISPLAY_ACTION_FIELDS)
    ):
        return False
    if "redacted_arguments" in action and not _explicitly_redacted_json(
        action.get("redacted_arguments")
    ):
        return False
    for field in ("target_resource", "data_destination"):
        if field in action and not _safe_optional_canonical_text(
            action.get(field),
            key=field,
        ):
            return False
    if "persistent_side_effect" in action and (
        action.get("persistent_side_effect") is not None
        and type(action.get("persistent_side_effect")) is not bool
    ):
        return False
    if set(approval) != {"approval_binding_id"}:
        return False
    approval_binding_id = approval.get("approval_binding_id")
    if approval_binding_id is not None and (
        type(approval_binding_id) is not str or not approval_binding_id.strip()
    ):
        return False
    if set(policy) != _CANONICAL_DISPLAY_POLICY_FIELDS or not _exact_nonempty_strings(
        policy,
        _CANONICAL_DISPLAY_POLICY_FIELDS,
    ):
        return False

    provenance = canonical.get("provenance")
    if provenance is not None:
        if not isinstance(provenance, Mapping) or set(provenance) != {
            "tool_binding_id",
            "tool_identity",
            "instruction_provenance",
        }:
            return False
        tool_identity = provenance.get("tool_identity")
        instruction_provenance = provenance.get("instruction_provenance")
        if not isinstance(tool_identity, Mapping) or set(tool_identity) != {
            "tool_identity_hash",
            "material_fingerprint",
            "schema_fingerprint",
            "lifecycle_version",
        }:
            return False
        if not isinstance(instruction_provenance, Mapping) or set(
            instruction_provenance
        ) != {"provenance_set_id", "record_ids"}:
            return False
        bounded_refs = [
            provenance.get("tool_binding_id"),
            *tool_identity.values(),
            instruction_provenance.get("provenance_set_id"),
        ]
        if any(
            value is not None
            and (
                type(value) is not str
                or not value.strip()
                or len(value.encode("utf-8")) > 128
            )
            for value in bounded_refs
        ):
            return False
        if not _exact_nonempty_string_list(
            instruction_provenance.get("record_ids"),
            max_items=MAX_LIST_ITEMS,
        ) and instruction_provenance.get("record_ids") != []:
            return False

    transformations = canonical.get("transformations")
    return type(transformations) is list and all(
        type(item) is str for item in transformations
    )


def _trusted_canonical_sentinels_are_valid(canonical: Mapping[str, Any]) -> bool:
    sentinel_fields = (
        ("authority", "verified"),
        ("action", "persistent_side_effect"),
        ("approval", "approval_required"),
    )
    for section, field in sentinel_fields:
        section_value = canonical.get(section)
        if isinstance(section_value, Mapping) and field in section_value:
            value = section_value.get(field)
            if type(value) is not bool and value != "unknown":
                return False

    purpose = canonical.get("purpose")
    if isinstance(purpose, Mapping) and "purpose_confidence" in purpose:
        confidence = purpose.get("purpose_confidence")
        if confidence != "unknown" and (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not math.isfinite(float(confidence))
        ):
            return False
    return True


def _verified_canonical_action_projection(
    *,
    event: RuntimeEvent,
    decision_receipt: DecisionReceipt | None,
    db: Session,
) -> tuple[dict[str, Any], str, bool]:
    if decision_receipt is None:
        return {}, "unavailable", False

    try:
        receipt_verified = bool(
            verify_decision_receipt(
                decision_receipt,
                tenant_id=event.tenant_id,
                settings_obj=settings,
                db=db,
            )
        )
    except Exception:
        receipt_verified = False
    if not receipt_verified:
        return {}, "invalid", False

    if (
        not event.chain_id
        or decision_receipt.tenant_id != event.tenant_id
        or decision_receipt.action_id != event.event_id
        or decision_receipt.chain_id != event.chain_id
    ):
        return {}, "invalid", True

    canonical_node = db.scalar(
        select(EvidenceNode).where(
            EvidenceNode.id == decision_receipt.canonical_action_evidence_node_id,
            EvidenceNode.tenant_id == event.tenant_id,
        )
    )
    canonical_payload = (
        dict(canonical_node.payload or {}).get("canonical_action")
        if canonical_node is not None
        else None
    )
    if not isinstance(canonical_payload, Mapping):
        return {}, "invalid", True

    if not _canonical_display_schema_is_valid(canonical_payload):
        return {}, "invalid", True
    canonical = _without_raw_signature_values(dict(canonical_payload))
    if not isinstance(canonical, dict) or not _trusted_canonical_sentinels_are_valid(canonical):
        return {}, "invalid", True
    return canonical, "verified", True


def _graph_from_behavior_edges(rows: list[RuntimeBehaviorEdge]) -> tuple[list[RuntimeGraphNode], list[RuntimeGraphEdgeResponse]]:
    nodes: dict[str, RuntimeGraphNode] = {}
    edges: list[RuntimeGraphEdgeResponse] = []
    for row in rows:
        source_key = f"{row.source_node_type}:{row.source_node_id}"
        target_key = f"{row.target_node_type}:{row.target_node_id}"
        nodes[source_key] = RuntimeGraphNode(
            node_type=row.source_node_type,
            node_id=row.source_node_id,
            label=row.source_node_label,
        )
        nodes[target_key] = RuntimeGraphNode(
            node_type=row.target_node_type,
            node_id=row.target_node_id,
            label=row.target_node_label,
        )
        edges.append(
            RuntimeGraphEdgeResponse(
                edge_id=row.id,
                relationship_type=row.relationship_type,
                source_node_type=row.source_node_type,
                source_node_id=row.source_node_id,
                target_node_type=row.target_node_type,
                target_node_id=row.target_node_id,
                evidence_node_id=row.evidence_node_id,
                event_id=row.event_id,
                created_at=row.created_at,
                payload=dict(row.payload or {}),
            )
        )
    return list(nodes.values()), edges


def _runtime_event_trace_payload(event: RuntimeEvent) -> dict[str, Any]:
    metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}
    return {
        "event_id": event.event_id,
        "tenant_id": event.tenant_id,
        "source_surface": event.source_surface,
        "event_type": event.event_type,
        "ai_system_id": event.ai_system_id,
        "app_id": event.app_id,
        "user_id": event.user_id,
        "agent_id": event.agent_id,
        "machine_id": event.machine_id,
        "browser_type": event.browser_type,
        "application": event.application,
        "decision": event.decision,
        "risk_tier": event.risk_tier,
        "severity": event.severity,
        "policy_version_id": event.policy_version_id,
        "evidence_node_ids": list(event.evidence_node_ids or []),
        "correlation_id": event.correlation_id,
        "context_id": event.context_id,
        "chain_id": event.chain_id,
        "risk_score": float(event.risk_score or 0.0),
        "created_at": event.created_at.isoformat() if event.created_at else None,
        "control_mode": metadata.get("control_mode")
        or dict((metadata.get("ai_action") or {}).get("policy") or {}).get("control_mode"),
        "decision_badge": metadata.get("decision_badge"),
    }


def _recommendation_impact_score(payload: dict[str, Any] | None) -> float:
    body = dict(payload or {})
    direct = body.get("decision_impact_score")
    if direct is not None:
        try:
            return float(direct)
        except (TypeError, ValueError):
            pass
    nested = body.get("decision_impact")
    if isinstance(nested, dict):
        nested_score = nested.get("decision_impact_score")
        try:
            return float(nested_score) if nested_score is not None else 0.0
        except (TypeError, ValueError):
            return 0.0
    return 0.0


@router.get("/stream/overview")
def stream_runtime_overview(
    ctx: TenantContext = Depends(_require_stream_viewer),
):
    return _runtime_stream_response(tenant_id=ctx.tenant.id, channel="overview")


@router.get("/stream/activity")
def stream_runtime_activity(
    ctx: TenantContext = Depends(_require_stream_viewer),
):
    return _runtime_stream_response(tenant_id=ctx.tenant.id, channel="activity")


@router.get("/stream/chains")
def stream_runtime_chains(
    ctx: TenantContext = Depends(_require_stream_viewer),
):
    return _runtime_stream_response(tenant_id=ctx.tenant.id, channel="chains")


@router.get("/stream/patterns")
def stream_runtime_patterns(
    ctx: TenantContext = Depends(_require_stream_viewer),
):
    return _runtime_stream_response(tenant_id=ctx.tenant.id, channel="patterns")


@router.get("/stream/recommendations")
def stream_runtime_recommendations(
    ctx: TenantContext = Depends(_require_stream_viewer),
):
    return _runtime_stream_response(tenant_id=ctx.tenant.id, channel="recommendations")


@router.get("/chains/{chain_id}")
def runtime_chain_detail(
    chain_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    return chain_graph(db, tenant_id=ctx.tenant.id, chain_id=chain_id)


@router.get("/chains/{chain_id}/graph")
def runtime_chain_graph(
    chain_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    return chain_graph(db, tenant_id=ctx.tenant.id, chain_id=chain_id)


@router.get("/chains/{chain_id}/evidence")
def runtime_chain_evidence(
    chain_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    return chain_evidence(db, tenant_id=ctx.tenant.id, chain_id=chain_id)


@router.post("/deferred-side-effects")
def runtime_record_deferred_side_effect(
    payload: DeferredSideEffectRequest,
    ctx: TenantContext = Depends(require_permission("activity.operate")),
    db: Session = Depends(get_db),
):
    return record_deferred_side_effect(
        db,
        tenant_id=ctx.tenant.id,
        chain_id=payload.chain_id,
        action_id=payload.action_id,
        agent_id=payload.agent_id,
        side_effect_type=payload.side_effect_type,
        target_system=payload.target_system,
        target_resource=payload.target_resource,
        external_destination=payload.external_destination,
        persistence_duration=payload.persistence_duration,
    )


def _event_response(row: RuntimeEvent) -> RuntimeEventResponse:
    metadata = dict(row.metadata_json or {}) if isinstance(row.metadata_json, dict) else {}
    normalized_event = metadata.get("normalized_enforcement_event")
    if not isinstance(normalized_event, dict):
        normalized_event = {
            "event_id": row.event_id,
            "tenant_id": row.tenant_id,
            "source_surface": row.source_surface,
            "action_type": str(metadata.get("action_type") or row.event_type or "unknown_action"),
            "ai_system_id": row.ai_system_id,
            "app_id": row.app_id,
            "user_id": row.user_id,
            "agent_id": row.agent_id,
            "provider_id": str(metadata.get("provider_id") or "").strip() or None,
            "provider_name": str(metadata.get("provider") or metadata.get("model_provider") or "").strip() or None,
            "provider_type": str(metadata.get("provider_type") or "").strip() or None,
            "shadow_ai_entity_id": str(metadata.get("shadow_ai_entity_id") or "").strip() or None,
            "model_name": str(metadata.get("model_name") or "").strip() or None,
            "tool_name": str(metadata.get("tool_name") or "").strip() or None,
            "host_id": str(metadata.get("host_id") or "").strip() or None,
            "domain": str(
                metadata.get("domain")
                or metadata.get("destination_domain")
                or metadata.get("request_domain")
                or row.app_id
                or ""
            ).strip()
            or None,
            "api_endpoint": str(metadata.get("api_endpoint") or "").strip() or None,
            "process_name": str(metadata.get("process_name") or "").strip() or None,
            "data_classification": str(
                metadata.get("data_classification")
                or metadata.get("source_classification_hint")
                or metadata.get("classification")
                or "unknown"
            ),
            "correlation_id": row.correlation_id or row.event_id,
            "created_at": row.created_at.isoformat(),
        }
        metadata["normalized_enforcement_event"] = normalized_event
    canonical_action = dict(metadata.get("canonical_action") or {})
    if not canonical_action:
        canonical_action = {
            "action_id": row.event_id,
            "source_surface": (
                "api"
                if row.source_surface == "gateway"
                else ("agent" if row.source_surface == "aiiam" else row.source_surface)
            ),
            "user_id": row.user_id,
            "agent_id": row.agent_id,
            "model": str(metadata.get("model_name") or metadata.get("provider") or metadata.get("model_provider") or "").strip() or None,
            "tool": str(metadata.get("tool_name") or row.app_id or "").strip() or None,
            "operation": str(metadata.get("action_type") or row.event_type or "unknown_action").strip() or "unknown_action",
            "data_entities": [
                value
                for value in (
                    str(metadata.get("data_source") or "").strip(),
                    str(metadata.get("api_endpoint") or "").strip(),
                    str(metadata.get("domain") or row.app_id or "").strip(),
                )
                if value
            ],
            "timestamp": row.created_at.isoformat(),
        }
        metadata["canonical_action"] = canonical_action
        metadata["action"] = canonical_action
    if "enforcement_status" not in metadata:
        metadata["enforcement_status"] = (
            "enforced" if row.source_surface in {"browser", "gateway", "aiiam"} else "simulated"
        )
    if "policy_evaluation" not in metadata:
        decision = str(metadata.get("decision") or metadata.get("final_decision") or "").strip().lower()
        mapped = "allow" if decision == "allow" else ("deny" if decision in {"block", "deny", "denied"} else "defer")
        metadata["policy_evaluation"] = {
            "classification": "context_allow" if mapped == "allow" else ("forbidden" if mapped == "deny" else "defer"),
            "decision": mapped,
            "simulated": bool(metadata["enforcement_status"] == "simulated"),
        }
    if "triggered_controls" not in metadata or "risk_tags" not in metadata:
        inferred_mapping = infer_runtime_control_mapping(
            event_type=row.event_type,
            metadata=metadata,
            source_surface=row.source_surface,
        )
        metadata["triggered_controls"] = normalize_control_ids(list(inferred_mapping.get("triggered_controls") or []))
        metadata["missed_controls"] = normalize_control_ids(list(inferred_mapping.get("missed_controls") or []))
        metadata["risk_tags"] = [str(item) for item in list(inferred_mapping.get("risk_tags") or []) if str(item).strip()]
    if "runtime_receipt" not in metadata:
        metadata["runtime_receipt"] = {
            "action": canonical_action,
            "context": {
                "session_id": row.context_id,
                "context_id": row.context_id,
                "chain_id": row.chain_id,
                "parent_action_id": row.parent_action_id,
            },
            "identity": {
                "human_id": row.user_id,
                "agent_id": row.agent_id,
            },
            "decision": dict(metadata.get("policy_evaluation") or {}),
            "enforcement_status": metadata.get("enforcement_status"),
            "timestamp": row.created_at.isoformat(),
        }
    return RuntimeEventResponse(
        event_id=row.event_id,
        tenant_id=row.tenant_id,
        source_surface=row.source_surface,
        event_type=row.event_type,
        ai_system_id=row.ai_system_id,
        app_id=row.app_id,
        user_id=row.user_id,
        agent_id=row.agent_id,
        risk_tier=row.risk_tier,
        policy_version_id=row.policy_version_id,
        governance_version=row.governance_version,
        severity=row.severity,
        confidence_tier=row.confidence_tier,
        evidence_node_ids=[str(node_id) for node_id in (row.evidence_node_ids or []) if str(node_id).strip()],
        correlation_id=row.correlation_id,
        context_id=(row.context_id or str(metadata.get("context_id") or "").strip() or None),
        chain_id=(row.chain_id or str(metadata.get("chain_id") or "").strip() or None),
        parent_action_id=(row.parent_action_id or str(metadata.get("parent_action_id") or "").strip() or None),
        entity_type=(row.entity_type or str(metadata.get("entity_type") or "").strip() or None),
        entity_id=(row.entity_id or str(metadata.get("entity_id") or "").strip() or None),
        risk_score=float(row.risk_score or metadata.get("risk_score") or 0.0),
        created_at=row.created_at,
        model_provider=(str(metadata.get("model_provider") or metadata.get("provider") or "").strip() or None),
        provider=(str(metadata.get("provider") or metadata.get("model_provider") or "").strip() or None),
        model_name=(str(metadata.get("model_name") or "").strip() or None),
        model_version=(str(metadata.get("model_version") or "").strip() or None),
        tool_name=(str(metadata.get("tool_name") or "").strip() or None),
        tool_category=(str(metadata.get("tool_category") or "").strip() or None),
        api_endpoint=(str(metadata.get("api_endpoint") or "").strip() or None),
        data_source=(str(metadata.get("data_source") or "").strip() or None),
        response_size=(int(metadata.get("response_size")) if isinstance(metadata.get("response_size"), int) else None),
        chain_depth=(int(metadata.get("chain_depth")) if isinstance(metadata.get("chain_depth"), int) else None),
        parent_agent_id=(str(metadata.get("parent_agent_id") or "").strip() or None),
        metadata=metadata,
    )


@router.get("/events", response_model=ListEnvelope[RuntimeEventResponse])
def list_runtime_events(
    page: int = 1,
    page_size: int = 50,
    source_surface: str | None = None,
    event_type: str | None = None,
    ai_system_id: str | None = None,
    agent_id: str | None = None,
    correlation_id: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    stmt = select(RuntimeEvent).where(RuntimeEvent.tenant_id == ctx.tenant.id)
    if source_surface:
        stmt = stmt.where(RuntimeEvent.source_surface == source_surface)
    if event_type:
        stmt = stmt.where(RuntimeEvent.event_type == event_type)
    if ai_system_id:
        stmt = stmt.where(RuntimeEvent.ai_system_id == ai_system_id)
    if agent_id:
        stmt = stmt.where(RuntimeEvent.agent_id == agent_id)
    if correlation_id:
        stmt = stmt.where(RuntimeEvent.correlation_id == correlation_id)

    rows = db.scalars(stmt.order_by(desc(RuntimeEvent.created_at))).all()
    dto_rows = [_event_response(row) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeEventResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/findings", response_model=RuntimeFindingsEnvelope)
def list_runtime_findings(
    page: int = 1,
    page_size: int = 50,
    ai_system_id: str | None = None,
    severity: str | None = None,
    finding_type: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    finding_types = sorted(RUNTIME_FINDING_TYPES)
    stmt = select(Finding).where(
        Finding.tenant_id == ctx.tenant.id,
        Finding.finding_type.in_(finding_types),
    )
    if ai_system_id:
        stmt = stmt.where(Finding.ai_system_id == ai_system_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if finding_type:
        stmt = stmt.where(Finding.finding_type == finding_type)

    rows = db.scalars(stmt.order_by(desc(Finding.updated_at))).all()
    dto_rows = [RuntimeFindingResponse.model_validate(row, from_attributes=True) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)

    recommendation_count = int(
        db.scalar(
            select(func.count())
            .select_from(RuntimeGovernanceRecommendation)
            .where(RuntimeGovernanceRecommendation.tenant_id == ctx.tenant.id)
        )
        or 0
    )

    return RuntimeFindingsEnvelope(
        items=page_items,
        total=total,
        page=safe_page,
        page_size=safe_page_size,
        recommendation_count=recommendation_count,
    )


@router.get("/graph/{ai_system_id}", response_model=RuntimeGraphResponse)
def runtime_graph(
    ai_system_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    rows = db.scalars(
        select(RuntimeBehaviorEdge)
        .where(
            RuntimeBehaviorEdge.tenant_id == ctx.tenant.id,
            RuntimeBehaviorEdge.ai_system_id == ai_system_id,
        )
        .order_by(desc(RuntimeBehaviorEdge.created_at))
    ).all()

    nodes: dict[str, RuntimeGraphNode] = {}
    edges: list[RuntimeGraphEdgeResponse] = []
    for row in rows:
        source_key = f"{row.source_node_type}:{row.source_node_id}"
        target_key = f"{row.target_node_type}:{row.target_node_id}"
        nodes[source_key] = RuntimeGraphNode(
            node_type=row.source_node_type,
            node_id=row.source_node_id,
            label=row.source_node_label,
        )
        nodes[target_key] = RuntimeGraphNode(
            node_type=row.target_node_type,
            node_id=row.target_node_id,
            label=row.target_node_label,
        )
        edges.append(
            RuntimeGraphEdgeResponse(
                edge_id=row.id,
                relationship_type=row.relationship_type,
                source_node_type=row.source_node_type,
                source_node_id=row.source_node_id,
                target_node_type=row.target_node_type,
                target_node_id=row.target_node_id,
                evidence_node_id=row.evidence_node_id,
                event_id=row.event_id,
                created_at=row.created_at,
                payload=dict(row.payload or {}),
            )
        )

    return RuntimeGraphResponse(
        ai_system_id=ai_system_id,
        nodes=list(nodes.values()),
        edges=edges,
        total_edges=len(edges),
    )


@router.get("/action-graph/{action_id}", response_model=RuntimeActionGraphResponse)
def runtime_action_graph(
    action_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    normalized_action_id = str(action_id or "").strip()
    event = db.scalar(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.event_id == normalized_action_id,
        )
    )
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Runtime action not found",
        )

    rows = db.scalars(
        select(RuntimeBehaviorEdge)
        .where(
            RuntimeBehaviorEdge.tenant_id == ctx.tenant.id,
            or_(
                RuntimeBehaviorEdge.event_id == event.event_id,
                (RuntimeBehaviorEdge.source_node_type == "ai_action")
                & (RuntimeBehaviorEdge.source_node_id == normalized_action_id),
                (RuntimeBehaviorEdge.target_node_type == "ai_action")
                & (RuntimeBehaviorEdge.target_node_id == normalized_action_id),
            ),
        )
        .order_by(desc(RuntimeBehaviorEdge.created_at))
    ).all()
    nodes, edges = _graph_from_behavior_edges(rows)
    if not any(node.node_type == "ai_action" and node.node_id == normalized_action_id for node in nodes):
        nodes.append(
            RuntimeGraphNode(
                node_type="ai_action",
                node_id=normalized_action_id,
                label=event.event_type,
            )
        )

    return RuntimeActionGraphResponse(
        action_id=normalized_action_id,
        runtime_event_id=event.event_id,
        ai_system_id=event.ai_system_id,
        nodes=nodes,
        edges=edges,
        total_edges=len(edges),
    )


@router.get("/action-trace/{action_id}", response_model=RuntimeActionTraceResponse)
def runtime_action_trace(
    action_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    normalized_action_id = str(action_id or "").strip()
    event = db.scalar(
        select(RuntimeEvent).where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.event_id == normalized_action_id,
        )
    )
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Runtime action not found",
        )

    metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}
    legacy_ai_action = metadata.get("ai_action")
    ai_action = _legacy_ai_action_projection(legacy_ai_action)
    policy_snapshot = (
        _legacy_policy_snapshot_projection(ai_action.get("policy_snapshot"))
        if isinstance(ai_action.get("policy_snapshot"), dict)
        else _legacy_policy_snapshot_projection(metadata.get("policy_snapshot"))
        if isinstance(metadata.get("policy_snapshot"), dict)
        else {}
    )
    decision_explanation = (
        _legacy_decision_explanation_projection(ai_action.get("decision_explanation"))
        if isinstance(ai_action.get("decision_explanation"), dict)
        else _legacy_decision_explanation_projection(metadata.get("decision_explanation"))
        if isinstance(metadata.get("decision_explanation"), dict)
        else {}
    )
    control_mode = _bounded_legacy_text(
        dict(ai_action.get("policy") or {}).get("control_mode")
        or metadata.get("control_mode"),
        key="control_mode",
    )
    decision_badge = _bounded_legacy_text(
        metadata.get("decision_badge"),
        key="decision_badge",
    )
    if decision_explanation and control_mode and not decision_explanation.get("control_mode"):
        decision_explanation["control_mode"] = control_mode
    if decision_explanation and decision_badge and not decision_explanation.get("decision_badge"):
        decision_explanation["decision_badge"] = decision_badge
    evidence_bundle = (
        _legacy_evidence_bundle_projection(ai_action.get("evidence_bundle"))
        if isinstance(ai_action.get("evidence_bundle"), dict)
        else _legacy_evidence_bundle_projection(metadata.get("evidence_bundle"))
        if isinstance(metadata.get("evidence_bundle"), dict)
        else {}
    )

    decision_receipt = db.scalar(
        select(DecisionReceipt)
        .where(
            DecisionReceipt.tenant_id == ctx.tenant.id,
            DecisionReceipt.action_id == normalized_action_id,
        )
        .order_by(desc(DecisionReceipt.issued_at))
    )
    approval_binding = None
    execution_receipt = None
    execution_integrity = None
    if decision_receipt is not None:
        if decision_receipt.approval_binding_id:
            approval_binding = db.scalar(
                select(ApprovalBinding).where(
                    ApprovalBinding.tenant_id == ctx.tenant.id,
                    ApprovalBinding.id == decision_receipt.approval_binding_id,
                    ApprovalBinding.action_id == decision_receipt.action_id,
                    ApprovalBinding.chain_id == decision_receipt.chain_id,
                )
            )
        execution_receipt = db.scalar(
            select(ExecutionReceipt)
            .where(
                ExecutionReceipt.tenant_id == ctx.tenant.id,
                ExecutionReceipt.decision_receipt_id == decision_receipt.receipt_id,
            )
            .order_by(desc(ExecutionReceipt.executed_at))
        )
        if execution_receipt is not None:
            execution_integrity = db.scalar(
                select(ExecutionIntegrityResult)
                .where(
                    ExecutionIntegrityResult.tenant_id == ctx.tenant.id,
                    ExecutionIntegrityResult.decision_receipt_id == decision_receipt.receipt_id,
                    ExecutionIntegrityResult.execution_receipt_id
                    == execution_receipt.receipt_id,
                    ExecutionIntegrityResult.execution_attempt_id
                    == execution_receipt.execution_attempt_id,
                )
                .order_by(desc(ExecutionIntegrityResult.evaluated_at))
            )

    (
        canonical_ai_action,
        canonical_ai_action_status,
        decision_receipt_verified,
    ) = _verified_canonical_action_projection(
        event=event,
        decision_receipt=decision_receipt,
        db=db,
    )
    execution_receipt_verified = False
    if execution_receipt is not None:
        try:
            execution_receipt_verified = bool(
                verify_execution_receipt(
                    execution_receipt,
                    tenant_id=event.tenant_id,
                    settings_obj=settings,
                )
            )
        except Exception:
            execution_receipt_verified = False
    execution_integrity_verified = False
    if execution_integrity is not None:
        try:
            execution_integrity_verified = bool(
                verify_integrity_evidence(
                    db,
                    tenant_id=event.tenant_id,
                    integrity=execution_integrity,
                    settings_obj=settings,
                )
            )
        except Exception:
            execution_integrity_verified = False

    decision_receipt_payload: dict[str, Any] = {}
    if decision_receipt is not None:
        decision_receipt_payload = {
            "receipt_id": decision_receipt.receipt_id,
            "chain_id": decision_receipt.chain_id,
            "canonical_action_hash": decision_receipt.canonical_action_hash,
            "actor_hash": decision_receipt.actor_hash,
            "authority_hash": decision_receipt.authority_hash,
            "purpose_hash": decision_receipt.purpose_hash,
            "tool_fingerprint": decision_receipt.tool_fingerprint,
            "parameter_hash": decision_receipt.parameter_hash,
            "target_resource_hash": decision_receipt.target_resource_hash,
            "destination_hash": decision_receipt.destination_hash,
            "side_effect_class": decision_receipt.side_effect_class,
            "approval_binding_id": decision_receipt.approval_binding_id,
            "approval_binding_status": (
                approval_binding.status
                if approval_binding is not None
                else "not_required"
                if not decision_receipt.approval_binding_id
                else "missing"
            ),
            "approved_by": approval_binding.approver_user_id if approval_binding is not None else None,
            "approval_expires_at": approval_binding.expires_at if approval_binding is not None else None,
            "policy_snapshot_id": decision_receipt.policy_snapshot_id,
            "decision": decision_receipt.decision,
            "control_mode": decision_receipt.control_mode,
            "transformations": list(decision_receipt.transformations or []),
            "expires_at": decision_receipt.expires_at,
            "issued_at": decision_receipt.issued_at,
            "collector_id": decision_receipt.collector_id,
            "evidence_bundle_id": decision_receipt.evidence_bundle_id,
            "evidence_node_id": decision_receipt.evidence_node_id,
            "signature_present": bool(decision_receipt.signature),
            "signature_verified": decision_receipt_verified,
            "signing_key_id": decision_receipt.signing_key_id,
        }

    execution_receipt_payload: dict[str, Any] = {}
    if execution_receipt is not None:
        execution_receipt_payload = {
            "receipt_id": execution_receipt.receipt_id,
            "decision_receipt_id": execution_receipt.decision_receipt_id,
            "execution_attempt_id": execution_receipt.execution_attempt_id,
            "actual_tool_fingerprint": execution_receipt.actual_tool_fingerprint,
            "actual_parameter_hash": execution_receipt.actual_parameter_hash,
            "actual_target_resource_hash": execution_receipt.actual_target_resource_hash,
            "actual_destination_hash": execution_receipt.actual_destination_hash,
            "actual_authority_hash": execution_receipt.actual_authority_hash,
            "actual_side_effect_class": execution_receipt.actual_side_effect_class,
            "downstream_objects": list(execution_receipt.downstream_objects or []),
            "execution_status": execution_receipt.execution_status,
            "executed_at": execution_receipt.executed_at,
            "collector_id": execution_receipt.collector_id,
            "evidence_node_id": execution_receipt.evidence_node_id,
            "signature_present": bool(execution_receipt.signature),
            "signature_verified": execution_receipt_verified,
            "signing_key_id": execution_receipt.signing_key_id,
        }

    execution_integrity_payload: dict[str, Any] = {}
    if execution_integrity is not None:
        execution_integrity_payload = {
            "result_id": execution_integrity.result_id,
            "decision_receipt_id": execution_integrity.decision_receipt_id,
            "execution_receipt_id": execution_integrity.execution_receipt_id,
            "execution_attempt_id": execution_integrity.execution_attempt_id,
            "result": execution_integrity.result,
            "drift_fields": list(execution_integrity.drift_fields or []),
            "severity": execution_integrity.severity,
            "response_action": execution_integrity.response_action,
            "evidence_bundle_id": execution_integrity.evidence_bundle_id,
            "evaluated_at": execution_integrity.evaluated_at,
            "signature_present": bool(execution_integrity.signature),
            "signature_verified": execution_integrity_verified,
            "signing_key_id": execution_integrity.signing_key_id,
        }

    finding_rows = db.scalars(
        select(Finding)
        .where(
            Finding.tenant_id == ctx.tenant.id,
            or_(
                Finding.related_runtime_event_id == event.event_id,
                Finding.related_event_ids.contains([event.event_id]),
            ),
        )
        .order_by(desc(Finding.last_seen_at))
    ).all()
    related_findings = [
        {
            "finding_id": row.finding_id,
            "finding_type": row.finding_type,
            "severity": row.severity,
            "risk_category": row.risk_category,
            "status": row.status,
            "decision": row.decision,
            "evidence_status": row.evidence_status,
            "related_runtime_event_id": row.related_runtime_event_id,
            "evidence_node_ids": list(row.evidence_node_ids or []),
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }
        for row in finding_rows
    ]

    rows = db.scalars(
        select(RuntimeBehaviorEdge)
        .where(
            RuntimeBehaviorEdge.tenant_id == ctx.tenant.id,
            or_(
                RuntimeBehaviorEdge.event_id == event.event_id,
                (RuntimeBehaviorEdge.source_node_type == "ai_action")
                & (RuntimeBehaviorEdge.source_node_id == normalized_action_id),
                (RuntimeBehaviorEdge.target_node_type == "ai_action")
                & (RuntimeBehaviorEdge.target_node_id == normalized_action_id),
            ),
        )
        .order_by(desc(RuntimeBehaviorEdge.created_at))
    ).all()
    nodes, edges = _graph_from_behavior_edges(rows)
    if not any(node.node_type == "ai_action" and node.node_id == normalized_action_id for node in nodes):
        nodes.append(
            RuntimeGraphNode(
                node_type="ai_action",
                node_id=normalized_action_id,
                label=event.event_type,
            )
        )

    first_finding_id = related_findings[0]["finding_id"] if related_findings else ""
    investigation_links = {
        "action_graph": f"/runtime-intelligence/action-graph/{normalized_action_id}",
        "runtime_event": f"/runtime-intelligence/events?event_id={event.event_id}",
    }
    if first_finding_id:
        investigation_links["finding"] = f"/findings/{first_finding_id}"
        investigation_links["finding_traceability"] = f"/findings/{first_finding_id}/traceability"

    return RuntimeActionTraceResponse(
        action_id=normalized_action_id,
        runtime_event=_runtime_event_trace_payload(event),
        ai_action=ai_action,
        canonical_ai_action=canonical_ai_action,
        canonical_ai_action_status=canonical_ai_action_status,
        policy_snapshot=policy_snapshot,
        decision_explanation=decision_explanation,
        evidence_bundle=evidence_bundle,
        decision_receipt=decision_receipt_payload,
        execution_receipt=execution_receipt_payload,
        execution_integrity=execution_integrity_payload,
        related_findings=related_findings,
        graph={
            "nodes": [node.model_dump() for node in nodes],
            "edges": [_action_trace_graph_edge_projection(edge) for edge in edges],
            "total_edges": len(edges),
        },
        investigation_links=investigation_links,
    )


@router.get("/agent-graph/{agent_id}", response_model=RuntimeAgentGraphResponse)
def runtime_agent_graph(
    agent_id: str,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    agent_events = db.scalars(
        select(RuntimeEvent)
        .where(
            RuntimeEvent.tenant_id == ctx.tenant.id,
            RuntimeEvent.agent_id == agent_id,
        )
        .order_by(desc(RuntimeEvent.created_at))
    ).all()
    event_ids = [row.event_id for row in agent_events if str(row.event_id).strip()]

    if event_ids:
        rows = db.scalars(
            select(RuntimeBehaviorEdge)
            .where(
                RuntimeBehaviorEdge.tenant_id == ctx.tenant.id,
                or_(
                    RuntimeBehaviorEdge.event_id.in_(event_ids),
                    (RuntimeBehaviorEdge.source_node_type == "agent") & (RuntimeBehaviorEdge.source_node_id == agent_id),
                    (RuntimeBehaviorEdge.target_node_type == "agent") & (RuntimeBehaviorEdge.target_node_id == agent_id),
                ),
            )
            .order_by(desc(RuntimeBehaviorEdge.created_at))
        ).all()
    else:
        rows = db.scalars(
            select(RuntimeBehaviorEdge)
            .where(
                RuntimeBehaviorEdge.tenant_id == ctx.tenant.id,
                or_(
                    (RuntimeBehaviorEdge.source_node_type == "agent") & (RuntimeBehaviorEdge.source_node_id == agent_id),
                    (RuntimeBehaviorEdge.target_node_type == "agent") & (RuntimeBehaviorEdge.target_node_id == agent_id),
                ),
            )
            .order_by(desc(RuntimeBehaviorEdge.created_at))
        ).all()

    nodes: dict[str, RuntimeGraphNode] = {}
    edges: list[RuntimeGraphEdgeResponse] = []
    for row in rows:
        source_key = f"{row.source_node_type}:{row.source_node_id}"
        target_key = f"{row.target_node_type}:{row.target_node_id}"
        nodes[source_key] = RuntimeGraphNode(
            node_type=row.source_node_type,
            node_id=row.source_node_id,
            label=row.source_node_label,
        )
        nodes[target_key] = RuntimeGraphNode(
            node_type=row.target_node_type,
            node_id=row.target_node_id,
            label=row.target_node_label,
        )
        edges.append(
            RuntimeGraphEdgeResponse(
                edge_id=row.id,
                relationship_type=row.relationship_type,
                source_node_type=row.source_node_type,
                source_node_id=row.source_node_id,
                target_node_type=row.target_node_type,
                target_node_id=row.target_node_id,
                evidence_node_id=row.evidence_node_id,
                event_id=row.event_id,
                created_at=row.created_at,
                payload=dict(row.payload or {}),
            )
        )

    # Ensure the selected agent is visible even when there are no graph edges yet.
    agent_key = f"agent:{agent_id}"
    if agent_key not in nodes:
        nodes[agent_key] = RuntimeGraphNode(
            node_type="agent",
            node_id=agent_id,
            label=agent_id,
        )

    decision_counts: dict[str, int] = {}
    linked_ai_system_ids: set[str] = set()
    max_observed_chain_depth = 0
    for event in agent_events:
        if event.ai_system_id:
            linked_ai_system_ids.add(event.ai_system_id)
        metadata = dict(event.metadata_json or {}) if isinstance(event.metadata_json, dict) else {}
        decision = str(metadata.get("final_decision") or metadata.get("decision") or "").strip().lower()
        if decision:
            decision_counts[decision] = int(decision_counts.get(decision, 0)) + 1
        chain_depth = metadata.get("chain_depth")
        if isinstance(chain_depth, int):
            max_observed_chain_depth = max(max_observed_chain_depth, chain_depth)

    return RuntimeAgentGraphResponse(
        agent_id=agent_id,
        nodes=list(nodes.values()),
        edges=edges,
        total_edges=len(edges),
        event_count=len(agent_events),
        decision_counts=decision_counts,
        linked_ai_system_ids=sorted(linked_ai_system_ids),
        max_observed_chain_depth=max_observed_chain_depth,
    )


@router.get("/triggers", response_model=ListEnvelope[RuntimeTriggerResponse])
def list_runtime_triggers(
    page: int = 1,
    page_size: int = 50,
    status_filter: str | None = None,
    ai_system_id: str | None = None,
    reason_code: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    stmt = select(RuntimeSimulationTrigger).where(RuntimeSimulationTrigger.tenant_id == ctx.tenant.id)
    if status_filter:
        stmt = stmt.where(RuntimeSimulationTrigger.status == status_filter)
    if ai_system_id:
        stmt = stmt.where(RuntimeSimulationTrigger.ai_system_id == ai_system_id)
    if reason_code:
        stmt = stmt.where(RuntimeSimulationTrigger.reason_code == reason_code)

    rows = db.scalars(stmt.order_by(desc(RuntimeSimulationTrigger.created_at))).all()
    dto_rows = [RuntimeTriggerResponse.model_validate(row, from_attributes=True) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeTriggerResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)


@router.get("/recommendations", response_model=ListEnvelope[RuntimeRecommendationResponse])
def list_runtime_recommendations(
    page: int = 1,
    page_size: int = 50,
    status_filter: str | None = None,
    ai_system_id: str | None = None,
    recommendation_type: str | None = None,
    ctx: TenantContext = Depends(require_permission("activity.view")),
    db: Session = Depends(get_db),
):
    stmt = select(RuntimeGovernanceRecommendation).where(RuntimeGovernanceRecommendation.tenant_id == ctx.tenant.id)
    if status_filter:
        stmt = stmt.where(RuntimeGovernanceRecommendation.status == status_filter)
    if ai_system_id:
        stmt = stmt.where(RuntimeGovernanceRecommendation.ai_system_id == ai_system_id)
    if recommendation_type:
        stmt = stmt.where(RuntimeGovernanceRecommendation.recommendation_type == recommendation_type)

    rows = db.scalars(stmt).all()
    rows = sorted(
        rows,
        key=lambda row: (
            _recommendation_impact_score(row.payload),
            row.created_at,
        ),
        reverse=True,
    )
    dto_rows = [RuntimeRecommendationResponse.model_validate(row, from_attributes=True) for row in rows]
    page_items, total, safe_page, safe_page_size = paginate_rows(dto_rows, page=page, page_size=page_size)
    return ListEnvelope[RuntimeRecommendationResponse](items=page_items, total=total, page=safe_page, page_size=safe_page_size)
