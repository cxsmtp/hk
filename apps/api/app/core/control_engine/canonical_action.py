"""Versioned, redaction-safe canonical AI Action contract.

This module adapts existing Hawk event projections.  It intentionally does not
authorize actions; Phase 5 owns the shared authorization kernel.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
from typing import Any, Callable, Iterable, Mapping

from app.services.privacy_sanitizer import redact_sensitive_text, sanitize_privacy_scalar, strip_url_query


SCHEMA_VERSION = "1.0"
UNKNOWN = "unknown"
MAX_TEXT_LENGTH = 512
MAX_LIST_ITEMS = 64
MAX_DELEGATION_DEPTH = 32
MAX_BINDING_ENCODED_BYTES = 65_536
MAX_BINDING_NODES = 4_096
MAX_BINDING_DEPTH = 16
MAX_BINDING_CONTAINER_ITEMS = 1_024
MAX_BINDING_STRING_BYTES = 16_384

ALLOWED_CONTROL_MODES = frozenset(
    {
        "inline_prevented",
        "inline_allowed",
        "warned",
        "review_required",
        "shadow_would_block",
        "detected_only",
        "telemetry_only",
        "external_required",
        "external_action_triggered",
        "incomplete",
    }
)

_BLOCK_DECISIONS = {"block", "blocked", "deny", "denied"}
_ALLOW_DECISIONS = {"allow", "allowed"}
_WARN_DECISIONS = {"warn", "warned", "alert"}
_REVIEW_DECISIONS = {
    "review",
    "review_required",
    "require_approval",
    "hold",
    "held",
    "hold_for_approval",
    "step_up",
    "require_justification",
}
_DEPLOYMENT_FAMILIES = frozenset(
    {"browser", "endpoint", "runtime", "saas_api", "unknown"}
)
_DEPLOYMENT_AUTHORIZATION_PATHS = frozenset(
    {
        "inline_pre_execution",
        "telemetry_observation",
        "external_control",
        "post_execution",
        "unknown",
    }
)
_DEPLOYMENT_EVIDENCE_CAPABILITIES = frozenset(
    {"complete", "partial", "metadata_only", "none", "unknown"}
)
_DEPLOYMENT_TOKEN_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_.:-"
)


@dataclass(frozen=True, slots=True)
class ControlPathEvidence:
    """Server-owned facts about where a decision was made.

    These values must be supplied by the adapter call site, not copied from an
    inbound event label.  In particular, a caller-provided ``control_mode`` is
    never considered proof of prevention.
    """

    collector_inline_capable: bool = False
    inline_pre_execution: bool = False
    execution_prevented: bool = False
    shadow_evaluation: bool = False
    shadow_would_block: bool = False
    telemetry_observation: bool = False
    external_control_required: bool = False
    external_action_triggered: bool = False


class CanonicalMaterialLimitError(ValueError):
    """Exact action material exceeded the deterministic binding contract."""


class CanonicalProjectionError(RuntimeError):
    """Flag-on canonical persistence failed and the transaction owner must roll back."""


@dataclass(slots=True)
class _BindingTraversalState:
    nodes: int = 0
    raw_bytes: int = 0

    def add_node(self) -> None:
        self.nodes += 1
        if self.nodes > MAX_BINDING_NODES:
            raise CanonicalMaterialLimitError("canonical binding material exceeds max nodes")

    def add_bytes(self, value: str) -> None:
        size = len(value.encode("utf-8"))
        if size > MAX_BINDING_STRING_BYTES:
            raise CanonicalMaterialLimitError("canonical binding string exceeds max bytes")
        self.raw_bytes += size
        if self.raw_bytes > MAX_BINDING_ENCODED_BYTES:
            raise CanonicalMaterialLimitError("canonical binding material exceeds max encoded bytes")


def _dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    if len(value) > MAX_BINDING_CONTAINER_ITEMS:
        raise CanonicalMaterialLimitError("canonical mapping exceeds max items")
    return dict(value)


def _raw_text(value: Any) -> str:
    if isinstance(value, str) and len(value.encode("utf-8")) > MAX_BINDING_STRING_BYTES:
        raise CanonicalMaterialLimitError("canonical text exceeds max bytes")
    return str(value if value is not None else "").strip()


def _safe_text(value: Any, *, url: bool = False, max_len: int = MAX_TEXT_LENGTH) -> str:
    text = _raw_text(value)
    if not text:
        return UNKNOWN
    if len(text.encode("utf-8")) > MAX_BINDING_STRING_BYTES:
        raise CanonicalMaterialLimitError("canonical display string exceeds max bytes")
    safe = strip_url_query(text) if url else redact_sensitive_text(text, max_len=max_len)
    if not safe:
        return UNKNOWN
    if len(safe) > max_len:
        return f"{safe[:max_len]}...[truncated]"
    return safe


def _safe_bool(value: Any) -> bool | str:
    return value if isinstance(value, bool) else UNKNOWN


def _safe_list(value: Any, *, max_items: int = MAX_LIST_ITEMS) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return [UNKNOWN]
    if len(value) > max_items:
        raise CanonicalMaterialLimitError("canonical display list exceeds max items")
    if isinstance(value, (set, frozenset)):
        ordered = sorted(
            value,
            key=lambda item: _canonical_json(canonical_field_material(item)),
        )
    else:
        ordered = value
    result: list[str] = []
    for item in ordered:
        token = _safe_text(item)
        if token not in result:
            result.append(token)
    return result or [UNKNOWN]


def _unknown_deployment() -> dict[str, Any]:
    return {
        "deployment_instance_id": None,
        "technical_surface_type": UNKNOWN,
        "deployment_family": UNKNOWN,
        "collector_id": None,
        "authorization_path": UNKNOWN,
        "control_mode": "incomplete",
        "evidence_capability_at_decision_time": UNKNOWN,
    }


def _valid_deployment_token(value: Any, *, maximum: int) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value) <= maximum
        and all(character in _DEPLOYMENT_TOKEN_CHARACTERS for character in value)
    )


def _validated_deployment(value: Any) -> dict[str, Any]:
    deployment = _dict(value)
    if (
        not _valid_deployment_token(
            deployment.get("deployment_instance_id"),
            maximum=36,
        )
        or not _valid_deployment_token(
            deployment.get("technical_surface_type"),
            maximum=64,
        )
        or not _valid_deployment_token(
            deployment.get("collector_id"),
            maximum=128,
        )
        or deployment.get("deployment_family") not in _DEPLOYMENT_FAMILIES
        or deployment.get("authorization_path")
        not in _DEPLOYMENT_AUTHORIZATION_PATHS
        or deployment.get("control_mode") not in ALLOWED_CONTROL_MODES
        or deployment.get("evidence_capability_at_decision_time")
        not in _DEPLOYMENT_EVIDENCE_CAPABILITIES
    ):
        return _unknown_deployment()
    return {
        key: deployment[key]
        for key in _unknown_deployment()
    }


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _redacted_canonical_material(
    value: Any,
    *,
    state: _BindingTraversalState,
    key: str = "",
    depth: int = 0,
) -> Any:
    if depth > MAX_BINDING_DEPTH:
        raise CanonicalMaterialLimitError("canonical redacted material exceeds max depth")
    state.add_node()
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else UNKNOWN
    if isinstance(value, str):
        state.add_bytes(value)
        return sanitize_privacy_scalar(value, key=key)
    if isinstance(value, Mapping):
        if len(value) > MAX_BINDING_CONTAINER_ITEMS:
            raise CanonicalMaterialLimitError("canonical redacted mapping exceeds max items")
        keys: list[str] = []
        for item_key in value.keys():
            if not isinstance(item_key, str):
                raise TypeError("unsupported canonical hash material mapping key")
            state.add_node()
            state.add_bytes(item_key)
            keys.append(item_key)
        keys.sort()
        return {
            item_key: _redacted_canonical_material(
                value[item_key],
                state=state,
                key=item_key,
                depth=depth + 1,
            )
            for item_key in keys
        }
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_BINDING_CONTAINER_ITEMS:
            raise CanonicalMaterialLimitError("canonical redacted sequence exceeds max items")
        return [
            _redacted_canonical_material(item, state=state, key=key, depth=depth + 1)
            for item in value
        ]
    if isinstance(value, (set, frozenset)):
        if len(value) > MAX_BINDING_CONTAINER_ITEMS:
            raise CanonicalMaterialLimitError("canonical redacted set exceeds max items")
        normalized_items = [
            _redacted_canonical_material(item, state=state, key=key, depth=depth + 1)
            for item in value
        ]
        normalized_items.sort(key=_canonical_json)
        return normalized_items
    raise TypeError(f"unsupported canonical hash material type: {type(value).__name__}")


def canonical_field_material(value: Any) -> Any:
    """Return bounded, normalized, redacted material safe for deterministic hashing."""

    state = _BindingTraversalState()
    material = _redacted_canonical_material(value, state=state)
    if len(_canonical_json(material).encode("utf-8")) > MAX_BINDING_ENCODED_BYTES:
        raise CanonicalMaterialLimitError("canonical redacted material exceeds max encoded bytes")
    return material


def _exact_binding_material(
    value: Any,
    *,
    state: _BindingTraversalState,
    depth: int = 0,
) -> Any:
    if depth > MAX_BINDING_DEPTH:
        raise CanonicalMaterialLimitError("canonical binding material exceeds max depth")
    state.add_node()
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["bool", value]
    if isinstance(value, int):
        return ["int", str(value)]
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalMaterialLimitError("canonical binding float must be finite")
        return ["float", repr(value)]
    if isinstance(value, str):
        state.add_bytes(value)
        return ["str", value]
    if isinstance(value, Mapping):
        if len(value) > MAX_BINDING_CONTAINER_ITEMS:
            raise CanonicalMaterialLimitError("canonical binding mapping exceeds max items")
        for key in value:
            if not isinstance(key, str):
                raise TypeError("unsupported canonical binding mapping key")
            state.add_node()
            state.add_bytes(key)
        return [
            "map",
            [
                [key, _exact_binding_material(value[key], state=state, depth=depth + 1)]
                for key in sorted(value)
            ],
        ]
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_BINDING_CONTAINER_ITEMS:
            raise CanonicalMaterialLimitError("canonical binding sequence exceeds max items")
        tag = "tuple" if isinstance(value, tuple) else "list"
        return [tag, [_exact_binding_material(item, state=state, depth=depth + 1) for item in value]]
    if isinstance(value, (set, frozenset)):
        if len(value) > MAX_BINDING_CONTAINER_ITEMS:
            raise CanonicalMaterialLimitError("canonical binding set exceeds max items")
        tag = "frozenset" if isinstance(value, frozenset) else "set"
        encoded_items = [_exact_binding_material(item, state=state, depth=depth + 1) for item in value]
        encoded_items.sort(key=_canonical_json)
        return [tag, encoded_items]
    raise TypeError(f"unsupported canonical binding material type: {type(value).__name__}")


def _resolve_binding_key(binding_key: str | bytes | None) -> bytes:
    if binding_key is None:
        from app.core.config import settings

        binding_key = settings.canonical_action_binding_key
    if isinstance(binding_key, bytes):
        resolved = binding_key
    else:
        resolved = str(binding_key or "").encode("utf-8")
    if not resolved:
        raise ValueError("CANONICAL_ACTION_BINDING_KEY is required for exact action binding")
    return resolved


def canonical_field_hash(
    tenant_id: str,
    field_domain: str,
    value: Any,
    *,
    binding_key: str | bytes | None = None,
) -> str:
    tenant = _raw_text(tenant_id)
    domain = _raw_text(field_domain).lower()
    if not tenant:
        raise ValueError("tenant_id is required")
    if not domain:
        raise ValueError("field_domain is required")
    state = _BindingTraversalState()
    exact_material = _exact_binding_material(value, state=state)
    encoded_material = _canonical_json(exact_material).encode("utf-8")
    if len(encoded_material) > MAX_BINDING_ENCODED_BYTES:
        raise CanonicalMaterialLimitError("canonical binding material exceeds max encoded bytes")
    master_key = _resolve_binding_key(binding_key)
    separation_context = _canonical_json(
        {
            "schema_version": SCHEMA_VERSION,
            "tenant_id": tenant,
            "field_domain": domain,
            "purpose": "hawk.canonical_action.exact_binding",
        }
    ).encode("utf-8")
    separated_key = hmac.new(master_key, separation_context, hashlib.sha256).digest()
    return hmac.new(separated_key, encoded_material, hashlib.sha256).hexdigest()


def _field_hash_or_unknown(*, tenant_id: str, field_domain: str, value: Any) -> str:
    if value is None or value == "" or value == [] or value == {}:
        return UNKNOWN
    return canonical_field_hash(tenant_id, field_domain, value)


def trusted_parameter_hash_binding(
    *,
    tenant_id: str,
    action_id: str,
    parameter_hash: str,
    binding_key: str | bytes | None = None,
) -> str:
    """Bind a server-resolved parameter hash to one tenant/action boundary."""

    tenant = _raw_text(tenant_id)
    action = _raw_text(action_id)
    resolved_hash = _raw_text(parameter_hash).lower()
    if not tenant:
        raise ValueError("tenant_id is required")
    if not action:
        raise ValueError("action_id is required")
    if len(resolved_hash) != 64 or any(character not in "0123456789abcdef" for character in resolved_hash):
        raise ValueError("parameter_hash must be a SHA-256 hex digest")
    material = _canonical_json(
        {
            "schema_version": SCHEMA_VERSION,
            "tenant_id": tenant,
            "action_id": action,
            "parameter_hash": resolved_hash,
            "purpose": "hawk.canonical_action.trusted_parameter_hash",
        }
    ).encode("utf-8")
    return hmac.new(_resolve_binding_key(binding_key), material, hashlib.sha256).hexdigest()


def verify_trusted_parameter_hash_binding(
    *,
    tenant_id: str,
    action_id: str,
    parameter_hash: Any,
    binding: Any,
) -> bool:
    resolved_hash = _raw_text(parameter_hash).lower()
    supplied_binding = _raw_text(binding).lower()
    if len(resolved_hash) != 64 or len(supplied_binding) != 64:
        return False
    try:
        expected = trusted_parameter_hash_binding(
            tenant_id=tenant_id,
            action_id=action_id,
            parameter_hash=resolved_hash,
        )
    except ValueError:
        return False
    return hmac.compare_digest(expected, supplied_binding)


def stable_action_id(*, tenant_id: str, source_surface: str, source_action_id: str) -> str:
    """Map a source record to a stable 64-character-safe action identifier."""

    tenant = _raw_text(tenant_id)
    surface = _raw_text(source_surface).lower()
    source = _raw_text(source_action_id)
    if not tenant:
        raise ValueError("tenant_id is required")
    if not source:
        raise ValueError("action_id is required")
    if len(source) <= 64:
        return source
    return f"ca_{_sha256({'tenant_id': tenant, 'surface': surface or UNKNOWN, 'source_action_id': source})[:61]}"


def _normalize_decision(value: Any) -> str:
    decision = _raw_text(value).lower()
    if decision in {"blocked", "denied"}:
        return "block"
    if decision == "allowed":
        return "allow"
    if decision == "warned":
        return "warn"
    if decision in {"held", "hold_for_approval", "require_approval", "step_up"}:
        return "review"
    return decision or UNKNOWN


def derive_control_mode(*, decision: str, path_evidence: ControlPathEvidence | None) -> str:
    """Derive an honest mode only from server-owned path facts."""

    evidence = path_evidence or ControlPathEvidence()
    normalized = _normalize_decision(decision)
    inline_proof = evidence.collector_inline_capable and evidence.inline_pre_execution
    if evidence.execution_prevented and not inline_proof:
        return "incomplete"
    if evidence.shadow_would_block and not evidence.shadow_evaluation:
        return "incomplete"
    if evidence.external_action_triggered:
        return "external_action_triggered"
    if evidence.shadow_evaluation and evidence.shadow_would_block:
        return "shadow_would_block"
    if evidence.shadow_evaluation:
        return "incomplete"
    if inline_proof:
        if normalized in _BLOCK_DECISIONS:
            return "inline_prevented" if evidence.execution_prevented else "incomplete"
        if normalized in _ALLOW_DECISIONS:
            return "inline_allowed"
        if normalized in _WARN_DECISIONS:
            return "warned"
        if normalized in _REVIEW_DECISIONS:
            return "review_required"
        return "incomplete"
    if evidence.telemetry_observation:
        if normalized in _ALLOW_DECISIONS:
            return "telemetry_only"
        if normalized in _BLOCK_DECISIONS | _WARN_DECISIONS | _REVIEW_DECISIONS:
            return "detected_only"
        return "telemetry_only"
    if evidence.external_control_required:
        return "external_required"
    return "incomplete"


def gateway_control_path_evidence(
    *,
    request_stage: str | None,
    event_type: str,
    decision: str,
    enforcement_outcome: str | None = None,
) -> ControlPathEvidence:
    """Return server-owned gateway capability facts for a persisted stage."""

    stage = _raw_text(request_stage).lower()
    event = _raw_text(event_type).lower()
    post_execution_stages = {"response", "post", "post_response", "output", "chat.complete"}
    authorization_only_stages = {"authorize", "authorization", "auth"}
    authorization_only = stage in authorization_only_stages or "authorize" in event
    if stage in post_execution_stages:
        return ControlPathEvidence(telemetry_observation=True)
    if authorization_only:
        return ControlPathEvidence(
            collector_inline_capable=True,
            inline_pre_execution=True,
        )
    pre_execution = stage in {"request", "pre_request", "input"} or not stage
    if not pre_execution:
        return ControlPathEvidence(telemetry_observation=True)
    return ControlPathEvidence(
        collector_inline_capable=True,
        inline_pre_execution=True,
        execution_prevented=_raw_text(enforcement_outcome).lower() == "pre_execution_stopped",
    )


def _required_text(source: Mapping[str, Any], key: str, *, fallback: Any = None) -> str:
    value = _raw_text(source.get(key) if source.get(key) is not None else fallback)
    if not value:
        raise ValueError(f"{key} is required")
    return value


def build_canonical_ai_action_v1(
    source: Mapping[str, Any],
    *,
    adapter: str = UNKNOWN,
    path_evidence: ControlPathEvidence | None = None,
    parameters: Any = None,
) -> dict[str, Any]:
    """Build the canonical v1 payload from an existing Hawk action projection."""

    canonical_field_material(source)
    if parameters is not None:
        canonical_field_material(parameters)
    source_map = _dict(source)
    context = _dict(source_map.get("context"))
    tenant_id = _required_text(source_map, "tenant_id")
    action_id = _required_text(source_map, "action_id")
    chain_id = _required_text(source_map, "chain_id", fallback=context.get("chain_id"))

    actor = _dict(source_map.get("actor"))
    authority = _dict(source_map.get("authority"))
    purpose = _dict(source_map.get("purpose")) or _dict(source_map.get("business_purpose"))
    surface = _dict(source_map.get("surface"))
    deployment = _validated_deployment(source_map.get("deployment"))
    action = _dict(source_map.get("action"))
    content = _dict(source_map.get("content"))
    input_context = _dict(context.get("input"))
    output_context = _dict(context.get("output"))
    approval = _dict(source_map.get("approval"))
    policy = _dict(source_map.get("policy"))
    evidence = _dict(source_map.get("evidence"))

    decision = _normalize_decision(policy.get("decision") or source_map.get("decision"))
    control_mode = derive_control_mode(decision=decision, path_evidence=path_evidence)
    raw_target = action.get("target_resource")
    raw_parameters = parameters if parameters is not None else action.get("parameters")
    raw_destination = action.get("data_destination")
    supplied_parameter_hash = _raw_text(action.get("parameter_hash")).lower()
    parameter_hash = (
        supplied_parameter_hash
        if parameters is None
        and verify_trusted_parameter_hash_binding(
            tenant_id=tenant_id,
            action_id=action_id,
            parameter_hash=supplied_parameter_hash,
            binding=action.get("parameter_hash_binding"),
        )
        else _field_hash_or_unknown(
            tenant_id=tenant_id,
            field_domain="parameters",
            value=raw_parameters,
        )
    )

    payload: dict[str, Any] = {
        "schema_name": "hawk.ai_action",
        "schema_version": SCHEMA_VERSION,
        "adapter": _safe_text(adapter, max_len=64),
        "action_id": stable_action_id(
            tenant_id=tenant_id,
            source_surface=adapter,
            source_action_id=action_id,
        ),
        "tenant_id": _safe_text(tenant_id, max_len=128),
        "chain_id": _safe_text(chain_id, max_len=128),
        "timestamp": _safe_text(source_map.get("timestamp")),
        "actor": {
            "identity_id": _safe_text(actor.get("identity_id")),
            "identity_type": _safe_text(actor.get("identity_type"), max_len=64),
            "user_id": _safe_text(actor.get("user_id")),
            "agent_id": _safe_text(actor.get("agent_id")),
            "session_id": _safe_text(actor.get("session_id")),
            "runtime_instance_id": _safe_text(actor.get("runtime_instance_id") or actor.get("machine_id")),
            "acting_on_behalf_of": _safe_text(
                actor.get("acting_on_behalf_of") or actor.get("acting_on_behalf_of_user_id")
            ),
            "delegation_chain": _safe_list(actor.get("delegation_chain"), max_items=MAX_DELEGATION_DEPTH),
        },
        "authority": {
            "authority_type": _safe_text(authority.get("authority_type"), max_len=64),
            "authority_source": _safe_text(authority.get("authority_source")),
            "authority_owner": _safe_text(authority.get("authority_owner")),
            "standing_privilege": _safe_text(authority.get("standing_privilege"), max_len=64),
            "jit_grant_id": _safe_text(authority.get("jit_grant_id")),
            "permission_scope": _safe_list(authority.get("permission_scope")),
            "verified": _safe_bool(authority.get("verified")),
        },
        "purpose": {
            "tenant_sector": _safe_text(purpose.get("tenant_sector")),
            "business_function": _safe_text(purpose.get("business_function")),
            "declared_purpose": _safe_text(
                purpose.get("declared_purpose") or purpose.get("declared_intent")
            ),
            "inferred_purpose": _safe_text(purpose.get("inferred_purpose")),
            "purpose_confidence": (
                purpose.get("purpose_confidence")
                if (
                    type(purpose.get("purpose_confidence")) in {int, float}
                    and math.isfinite(
                        float(purpose.get("purpose_confidence"))
                    )
                )
                else UNKNOWN
            ),
            "business_relevance": _safe_text(purpose.get("business_relevance")),
            "purpose_status": _safe_text(purpose.get("purpose_status")),
        },
        "surface": {
            "surface_type": _safe_text(surface.get("surface_type"), max_len=64),
            "collector_type": _safe_text(surface.get("collector_type"), max_len=64),
            "application": _safe_text(surface.get("application")),
            "provider": _safe_text(surface.get("provider")),
            "model": _safe_text(surface.get("model")),
            "environment": _safe_text(surface.get("environment"), max_len=64),
            "domain": _safe_text(surface.get("domain")),
            "endpoint": _safe_text(surface.get("endpoint") or surface.get("url"), url=True),
            "repo_id": _safe_text(surface.get("repo_id")),
            "workspace_id": _safe_text(surface.get("workspace_id")),
            "mcp_server_id": _safe_text(surface.get("mcp_server_id") or surface.get("mcp_server")),
            "asset_status": _safe_text(surface.get("asset_status"), max_len=64),
        },
        "deployment": {
            "deployment_instance_id": _safe_text(
                deployment.get("deployment_instance_id"),
                max_len=36,
            ),
            "technical_surface_type": _safe_text(
                deployment.get("technical_surface_type"),
                max_len=64,
            ),
            "deployment_family": _safe_text(
                deployment.get("deployment_family"),
                max_len=32,
            ),
            "collector_id": _safe_text(
                deployment.get("collector_id"),
                max_len=128,
            ),
            "authorization_path": _safe_text(
                deployment.get("authorization_path"),
                max_len=32,
            ),
            "control_mode": _safe_text(
                deployment.get("control_mode"),
                max_len=32,
            ),
            "evidence_capability_at_decision_time": _safe_text(
                deployment.get(
                    "evidence_capability_at_decision_time"
                ),
                max_len=32,
            ),
        },
        "action": {
            "action_type": _safe_text(action.get("action_type"), max_len=128),
            "action_category": _safe_text(action.get("action_category"), max_len=64),
            "operation": _safe_text(action.get("operation"), max_len=128),
            "risk_level": _safe_text(action.get("risk_level") or action.get("action_risk"), max_len=32),
            "tool_name": _safe_text(action.get("tool_name")),
            "tool_version": _safe_text(action.get("tool_version")),
            "tool_fingerprint_id": _safe_text(
                action.get("tool_fingerprint_id") or action.get("tool_fingerprint")
            ),
            "parameter_hash": parameter_hash,
            "target_resource": _safe_text(raw_target),
            "target_resource_hash": _field_hash_or_unknown(
                tenant_id=tenant_id,
                field_domain="target_resource",
                value=raw_target,
            ),
            "data_destination": _safe_text(raw_destination),
            "destination_hash": _field_hash_or_unknown(
                tenant_id=tenant_id,
                field_domain="data_destination",
                value=raw_destination,
            ),
            "side_effect_class": _safe_text(action.get("side_effect_class"), max_len=64),
            "persistent_side_effect": _safe_bool(action.get("persistent_side_effect")),
        },
        "content": {
            "input_sensitivity": _safe_text(
                content.get("input_sensitivity") or input_context.get("sensitivity_level"), max_len=64
            ),
            "output_sensitivity": _safe_text(
                content.get("output_sensitivity") or output_context.get("output_sensitivity"), max_len=64
            ),
            "code_sensitivity": _safe_text(content.get("code_sensitivity"), max_len=64),
            "sql_type": _safe_text(content.get("sql_type"), max_len=64),
            "secret_indicators": _safe_list(content.get("secret_indicators")),
            "customer_data_indicators": _safe_list(content.get("customer_data_indicators")),
            "taint_labels": _safe_list(content.get("taint_labels")),
        },
        "approval": {
            "approval_required": _safe_bool(approval.get("approval_required")),
            "approval_id": _safe_text(approval.get("approval_id")),
            "approval_binding_id": _safe_text(approval.get("approval_binding_id")),
            "approval_status": _safe_text(approval.get("approval_status"), max_len=64),
        },
        "policy": {
            "policy_snapshot_id": _safe_text(policy.get("policy_snapshot_id")),
            "matched_rules": _safe_list(
                policy.get("matched_rules") or policy.get("control_ids") or policy.get("policy_ids")
            ),
            "decision": _safe_text(decision, max_len=64),
            "reason": _safe_text(policy.get("reason")),
            "control_mode": control_mode,
            "evaluated_at": _safe_text(policy.get("evaluated_at")),
        },
        "evidence": {
            "decision_receipt_id": _safe_text(evidence.get("decision_receipt_id")),
            "execution_receipt_id": _safe_text(evidence.get("execution_receipt_id")),
            "evidence_bundle_id": _safe_text(evidence.get("evidence_bundle_id")),
            "trace_id": _safe_text(evidence.get("trace_id")),
            "integrity_status": _safe_text(evidence.get("integrity_status"), max_len=64),
        },
    }
    payload["canonical_action_hash"] = canonical_action_hash(payload)
    return payload


def canonical_action_hash(payload: Mapping[str, Any]) -> str:
    if len(payload) > MAX_BINDING_CONTAINER_ITEMS:
        raise CanonicalMaterialLimitError("canonical action exceeds max items")
    tenant_id = _required_text(payload, "tenant_id")
    schema_version = _required_text(payload, "schema_version")
    core = {
        key: value
        for key, value in payload.items()
        if key != "canonical_action_hash"
    }
    material = canonical_field_material(core)
    return _sha256(
        {
            "schema_version": schema_version,
            "tenant_id": tenant_id,
            "field_domain": "canonical_action",
            "material": material,
        }
    )


def _prepare_adapter_source(source: Mapping[str, Any], *, adapter: str) -> dict[str, Any]:
    canonical_field_material(source)
    prepared = deepcopy(dict(source))
    source_action_id = (
        _raw_text(prepared.get("action_id"))
        or _raw_text(prepared.get("event_id"))
        or _raw_text(prepared.get("source_event_id"))
    )
    if source_action_id:
        prepared["action_id"] = source_action_id
    context = _dict(prepared.get("context"))
    chain_id = (
        _raw_text(prepared.get("chain_id"))
        or _raw_text(context.get("chain_id"))
    )
    if chain_id:
        context["chain_id"] = chain_id
    prepared["context"] = context
    surface = _dict(prepared.get("surface"))
    surface.setdefault("collector_type", adapter)
    prepared["surface"] = surface
    return prepared


def _adapt(
    source: Mapping[str, Any],
    *,
    adapter: str,
    path_evidence: ControlPathEvidence | None,
    parameters: Any = None,
) -> dict[str, Any]:
    return build_canonical_ai_action_v1(
        _prepare_adapter_source(source, adapter=adapter),
        adapter=adapter,
        path_evidence=path_evidence,
        parameters=parameters,
    )


def _adapter(adapter: str, default_evidence: ControlPathEvidence | None = None) -> Callable[..., dict[str, Any]]:
    def adapt(
        source: Mapping[str, Any],
        *,
        path_evidence: ControlPathEvidence | None = None,
        parameters: Any = None,
    ) -> dict[str, Any]:
        return _adapt(
            source,
            adapter=adapter,
            path_evidence=path_evidence if path_evidence is not None else default_evidence,
            parameters=parameters,
        )

    adapt.__name__ = f"adapt_{adapter}_action"
    return adapt


adapt_llm_gateway_action = _adapter("llm_gateway")
adapt_mcp_gateway_action = _adapter("mcp_gateway")
adapt_runtime_control_action = _adapter("runtime_control")
adapt_browser_action = _adapter("browser", ControlPathEvidence(telemetry_observation=True))
adapt_sdk_action = _adapter("sdk")
adapt_internal_mcp_action = _adapter("internal_mcp")


def adapt_existing_hawk_action(
    source: Mapping[str, Any],
    *,
    source_surface: str,
    event_type: str = "",
    path_evidence: ControlPathEvidence | None = None,
    parameters: Any = None,
) -> dict[str, Any]:
    """Select a compatibility adapter for an existing persisted action."""

    surface = _raw_text(source_surface).lower()
    event = _raw_text(event_type).lower()
    if surface == "gateway":
        adapter = adapt_mcp_gateway_action if "mcp" in event else adapt_llm_gateway_action
    elif surface == "aiiam":
        adapter = adapt_runtime_control_action
    elif surface == "browser":
        adapter = adapt_browser_action
    elif surface in {"sdk", "api"}:
        adapter = adapt_sdk_action
    elif surface == "internal_mcp":
        adapter = adapt_internal_mcp_action
    else:
        return _adapt(
            source,
            adapter=f"{surface or 'unknown'}_telemetry",
            path_evidence=path_evidence or ControlPathEvidence(telemetry_observation=True),
            parameters=parameters,
        )
    return adapter(source, path_evidence=path_evidence, parameters=parameters)


def maybe_dual_write_canonical_action(
    metadata: dict[str, Any],
    *,
    canonical_action: Mapping[str, Any] | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    """Attach v1 to an existing metadata JSON document when the flag is on."""

    if enabled is None:
        from app.core.config import settings

        enabled = bool(settings.canonical_ai_action_dual_write_enabled)
    if not enabled:
        return metadata
    if canonical_action is None:
        raise ValueError("canonical_action is required when canonical dual-write is enabled")
    canonical_hash = canonical_action_hash(canonical_action)
    canonical = deepcopy(dict(canonical_action))
    canonical["canonical_action_hash"] = canonical_hash
    output = dict(metadata)
    output["canonical_ai_action_v1"] = canonical
    output["canonical_ai_action_hash"] = canonical_hash
    return output


def canonical_reconciliation_counts(metadata_rows: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {
        "legacy_total": 0,
        "canonical_total": 0,
        "matched": 0,
        "missing": 0,
        "hash_mismatch": 0,
    }
    for row in metadata_rows:
        metadata = _dict(row)
        legacy = _dict(metadata.get("ai_action"))
        canonical = _dict(metadata.get("canonical_ai_action_v1"))
        if legacy:
            counts["legacy_total"] += 1
        if canonical:
            counts["canonical_total"] += 1
        if legacy and not canonical:
            counts["missing"] += 1
            continue
        if not canonical:
            continue
        stored_hash = _raw_text(metadata.get("canonical_ai_action_hash"))
        embedded_hash = _raw_text(canonical.get("canonical_action_hash"))
        computed_hash = canonical_action_hash(canonical)
        legacy_action_id = _raw_text(legacy.get("action_id"))
        canonical_action_id = _raw_text(canonical.get("action_id"))
        if (
            stored_hash == computed_hash
            and embedded_hash == computed_hash
            and (not legacy or legacy_action_id == canonical_action_id)
        ):
            counts["matched"] += 1
        else:
            counts["hash_mismatch"] += 1
    return counts


def _projection_key(metadata: Mapping[str, Any]) -> tuple[str, str] | None:
    canonical = _dict(metadata.get("canonical_ai_action_v1"))
    legacy = _dict(metadata.get("ai_action"))
    tenant_id = _raw_text(canonical.get("tenant_id") or legacy.get("tenant_id"))
    action_id = _raw_text(canonical.get("action_id") or legacy.get("action_id"))
    return (tenant_id, action_id) if tenant_id and action_id else None


def _projection_index(
    rows: Iterable[Mapping[str, Any]],
) -> tuple[dict[tuple[str, str], dict[str, Any]], set[tuple[str, str]], int]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        metadata = _dict(row)
        key = _projection_key(metadata)
        if key is not None:
            grouped.setdefault(key, []).append(metadata)
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    duplicate_keys: set[tuple[str, str]] = set()
    duplicate_count = 0
    for key, candidates in grouped.items():
        ordered = sorted(candidates, key=_canonical_json)
        indexed[key] = ordered[0]
        if len(ordered) > 1:
            duplicate_keys.add(key)
            duplicate_count += len(ordered) - 1
    return indexed, duplicate_keys, duplicate_count


def canonical_projection_reconciliation_counts(
    runtime_metadata_rows: Iterable[Mapping[str, Any]],
    activity_metadata_rows: Iterable[Mapping[str, Any]],
) -> dict[str, int]:
    """Compare correlated RuntimeEvent and AIAction canonical projections."""

    runtime, duplicate_runtime_keys, duplicate_runtime = _projection_index(runtime_metadata_rows)
    activity, duplicate_activity_keys, duplicate_activity = _projection_index(activity_metadata_rows)
    counts = {
        "runtime_total": len(runtime),
        "activity_total": len(activity),
        "correlated_total": 0,
        "matched": 0,
        "missing_runtime": 0,
        "missing_activity": 0,
        "hash_mismatch": 0,
        "schema_mismatch": 0,
        "control_mode_mismatch": 0,
        "duplicate_runtime": duplicate_runtime,
        "duplicate_activity": duplicate_activity,
    }
    for key in sorted(set(runtime) | set(activity)):
        runtime_metadata = runtime.get(key)
        activity_metadata = activity.get(key)
        if runtime_metadata is None:
            counts["missing_runtime"] += 1
            continue
        if activity_metadata is None:
            counts["missing_activity"] += 1
            continue
        runtime_action = _dict(runtime_metadata.get("canonical_ai_action_v1"))
        activity_action = _dict(activity_metadata.get("canonical_ai_action_v1"))
        if not runtime_action:
            counts["missing_runtime"] += 1
            continue
        if not activity_action:
            counts["missing_activity"] += 1
            continue
        counts["correlated_total"] += 1
        runtime_hash = canonical_action_hash(runtime_action)
        activity_hash = canonical_action_hash(activity_action)
        hash_mismatch = any(
            (
                runtime_hash != activity_hash,
                _raw_text(runtime_metadata.get("canonical_ai_action_hash")) != runtime_hash,
                _raw_text(activity_metadata.get("canonical_ai_action_hash")) != activity_hash,
                _raw_text(runtime_action.get("canonical_action_hash")) != runtime_hash,
                _raw_text(activity_action.get("canonical_action_hash")) != activity_hash,
            )
        )
        schema_mismatch = (
            _raw_text(runtime_action.get("schema_version")) != _raw_text(activity_action.get("schema_version"))
            or _raw_text(runtime_action.get("schema_version")) != SCHEMA_VERSION
        )
        runtime_mode = _raw_text(_dict(runtime_action.get("policy")).get("control_mode"))
        activity_mode = _raw_text(_dict(activity_action.get("policy")).get("control_mode"))
        control_mode_mismatch = runtime_mode != activity_mode
        counts["hash_mismatch"] += int(hash_mismatch)
        counts["schema_mismatch"] += int(schema_mismatch)
        counts["control_mode_mismatch"] += int(control_mode_mismatch)
        duplicate = key in duplicate_runtime_keys or key in duplicate_activity_keys
        if not (hash_mismatch or schema_mismatch or control_mode_mismatch or duplicate):
            counts["matched"] += 1
    return counts


__all__ = [
    "ALLOWED_CONTROL_MODES",
    "CanonicalMaterialLimitError",
    "CanonicalProjectionError",
    "ControlPathEvidence",
    "adapt_browser_action",
    "adapt_existing_hawk_action",
    "adapt_internal_mcp_action",
    "adapt_llm_gateway_action",
    "adapt_mcp_gateway_action",
    "adapt_runtime_control_action",
    "adapt_sdk_action",
    "build_canonical_ai_action_v1",
    "canonical_action_hash",
    "canonical_field_hash",
    "canonical_field_material",
    "canonical_projection_reconciliation_counts",
    "canonical_reconciliation_counts",
    "derive_control_mode",
    "gateway_control_path_evidence",
    "maybe_dual_write_canonical_action",
    "stable_action_id",
]
