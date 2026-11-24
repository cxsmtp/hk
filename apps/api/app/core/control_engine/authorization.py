"""Deterministic Hawk authorization kernel v2.

The kernel consumes only a normalized, server-assembled request and deterministic
policy profile. It never delegates authority to an LLM. Rollout selection is
read exclusively from server settings; inbound metadata cannot self-enroll.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import math
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.control_engine.canonical_action import ControlPathEvidence, derive_control_mode
from app.core.control_engine.engine import evaluate_control_engine
from app.core.control_engine.schemas import AIAction


SCHEMA_VERSION = "2.0"
MAX_SHADOW_COMPARISON_BYTES = 4_096
MAX_AUTHORIZATION_NODES = 4_096
MAX_AUTHORIZATION_BYTES = 65_536
MAX_AUTHORIZATION_DEPTH = 16
MAX_AUTHORIZATION_CONTAINER_ITEMS = 1_024
MAX_AUTHORIZATION_STRING_BYTES = 16_384
ALLOWED_DECISIONS = frozenset(
    {"allow", "warn", "review", "require_approval", "require_second_approval", "redact", "block"}
)
ALLOWED_SURFACES = frozenset(
    {"llm_gateway", "mcp_gateway", "runtime_control", "browser", "sdk", "internal_mcp"}
)
PRE_SIDE_EFFECT_ENFORCEABLE_SURFACES = frozenset(
    {"llm_gateway", "mcp_gateway", "runtime_control", "internal_mcp"}
)
_HIGH_RISK = frozenset({"high", "restricted", "critical", "prohibited", "unknown", ""})
_MEDIUM_RISK = frozenset({"medium", "moderate"})
_FAIL_CLOSED_DEGRADED = frozenset({"review", "require_approval", "require_second_approval", "block"})
_VERIFIED_ASSET_STATUSES = frozenset({"approved", "active", "registered", "verified", "sanctioned", "managed"})

AuthorizationSurface = Literal[
    "llm_gateway", "mcp_gateway", "runtime_control", "browser", "sdk", "internal_mcp"
]
AuthorizationDecision = Literal[
    "allow", "warn", "review", "require_approval", "require_second_approval", "redact", "block"
]
AuthorizationControlMode = Literal[
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
]
DegradedBehavior = Literal["review", "require_approval", "require_second_approval", "block"]


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _mapping(value: Any) -> dict[str, Any]:
    return deepcopy(dict(value)) if isinstance(value, Mapping) else {}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _norm(value: Any) -> str:
    return _text(value).lower()


def _bounded_tuple(value: Any, *, maximum: int = 64) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return ()
    if len(value) > maximum:
        raise ValueError(f"authorization list exceeds {maximum} items")
    normalized: set[str] = set()
    for item in value:
        token = _text(item)
        if not token:
            continue
        if len(token.encode("utf-8")) > 256:
            raise ValueError("authorization list value exceeds 256 bytes")
        normalized.add(token)
    return tuple(sorted(normalized))


def _validate_structural_bounds(value: Any) -> None:
    nodes = 0
    total_bytes = 0

    def visit(item: Any, *, depth: int) -> None:
        nonlocal nodes, total_bytes
        if depth > MAX_AUTHORIZATION_DEPTH:
            raise ValueError("authorization material exceeds max depth")
        nodes += 1
        if nodes > MAX_AUTHORIZATION_NODES:
            raise ValueError("authorization material exceeds max nodes")
        if item is None or isinstance(item, (bool, int)):
            return
        if isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("authorization numeric material must be finite")
            return
        if isinstance(item, str):
            item_bytes = len(item.encode("utf-8"))
            if item_bytes > MAX_AUTHORIZATION_STRING_BYTES:
                raise ValueError("authorization string exceeds max bytes")
            total_bytes += item_bytes
        elif isinstance(item, Mapping):
            if len(item) > MAX_AUTHORIZATION_CONTAINER_ITEMS:
                raise ValueError("authorization mapping exceeds max items")
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValueError("authorization mapping keys must be strings")
                visit(key, depth=depth + 1)
                visit(child, depth=depth + 1)
        elif isinstance(item, list):
            if len(item) > MAX_AUTHORIZATION_CONTAINER_ITEMS:
                raise ValueError("authorization sequence exceeds max items")
            for child in item:
                visit(child, depth=depth + 1)
        else:
            raise ValueError("authorization material must be JSON-compatible")
        if total_bytes > MAX_AUTHORIZATION_BYTES:
            raise ValueError("authorization material exceeds max bytes")

    visit(value, depth=0)


class AuthorizationRequest(BaseModel):
    """Versioned normalization of the Phase 5 authorization request."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_version: Literal["2.0"] = SCHEMA_VERSION
    tenant_id: str
    environment: str
    collector_id: str
    action_id: str
    chain_id: str
    surface: AuthorizationSurface
    actor: dict[str, Any] = Field(default_factory=dict)
    authority: dict[str, Any] = Field(default_factory=dict)
    runtime: dict[str, Any] = Field(default_factory=dict)
    purpose: dict[str, Any] = Field(default_factory=dict)
    action: dict[str, Any] = Field(default_factory=dict)
    tool: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    target: dict[str, Any] = Field(default_factory=dict)
    data_context: dict[str, Any] = Field(default_factory=dict)
    approval_context: dict[str, Any] = Field(default_factory=dict)
    jit_context: dict[str, Any] = Field(default_factory=dict)
    taint_context: dict[str, Any] = Field(default_factory=dict)
    side_effect_context: dict[str, Any] = Field(default_factory=dict)
    discovery_context: dict[str, Any] = Field(default_factory=dict)
    policy_snapshot_id: str
    policy_profile: dict[str, Any] = Field(default_factory=dict)
    path_evidence: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "tenant_id", "environment", "collector_id", "action_id", "chain_id", "surface", "policy_snapshot_id"
    )
    @classmethod
    def _required_text(cls, value: str) -> str:
        token = _text(value)
        if not token:
            raise ValueError("authorization identity fields cannot be empty")
        if len(token.encode("utf-8")) > 512:
            raise ValueError("authorization identity field exceeds 512 bytes")
        return token

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    @model_validator(mode="after")
    def _bounded_nested_material(self) -> "AuthorizationRequest":
        _validate_structural_bounds(self.model_dump())
        return self


class AuthorizationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["2.0"] = SCHEMA_VERSION
    decision: AuthorizationDecision
    control_mode: AuthorizationControlMode
    reason: str
    matched_rules: tuple[str, ...] = ()
    policy_snapshot_id: str
    decision_receipt: None = None
    transformations: tuple[str, ...] = ()
    safe_path: tuple[str, ...] = ()
    evidence_required: tuple[str, ...] = ()
    cache_ttl: int = 0
    degraded_behavior: DegradedBehavior = "block"
    policy_profile_hash: str
    response_hash: str

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def to_canonical_json(self) -> str:
        return _canonical_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class AuthorizationRolloutOutcome:
    authoritative_decision: str
    metadata: dict[str, Any]
    v2_response: AuthorizationResponse | None
    enforced: bool
    request: AuthorizationRequest | None = None


def _validated_request(request: AuthorizationRequest | Mapping[str, Any]) -> AuthorizationRequest:
    if isinstance(request, AuthorizationRequest):
        return AuthorizationRequest.model_validate(request.model_dump())
    return AuthorizationRequest.model_validate(dict(request))


def adapt_authorization_request(
    canonical_action: Mapping[str, Any],
    *,
    collector_id: str,
    policy_snapshot_id: str,
    policy_profile: Mapping[str, Any],
    path_evidence: Mapping[str, Any] | ControlPathEvidence | None = None,
    expected_surface: str | None = None,
) -> AuthorizationRequest:
    """Map canonical AI Action v1 to the one Phase 5 request contract."""

    source = _mapping(canonical_action)
    surface_context = _mapping(source.get("surface"))
    source_surface = _norm(source.get("adapter") or surface_context.get("collector_type"))
    surface = _norm(expected_surface or source_surface)
    if surface not in ALLOWED_SURFACES:
        raise ValueError("unsupported authorization surface")
    if expected_surface and source_surface in ALLOWED_SURFACES and source_surface != surface:
        raise ValueError("canonical authorization surface mismatch")
    action = _mapping(source.get("action"))
    authority = _mapping(source.get("authority"))
    actor = _mapping(source.get("actor"))
    content = _mapping(source.get("content"))
    if isinstance(path_evidence, ControlPathEvidence):
        evidence = {
            name: bool(getattr(path_evidence, name))
            for name in ControlPathEvidence.__dataclass_fields__
        }
    else:
        evidence = _mapping(path_evidence)
    return AuthorizationRequest(
        tenant_id=_text(source.get("tenant_id")),
        environment=_text(surface_context.get("environment") or "unknown"),
        collector_id=_text(collector_id),
        action_id=_text(source.get("action_id")),
        chain_id=_text(source.get("chain_id")),
        surface=surface,
        actor=actor,
        authority=authority,
        runtime={
            "runtime_instance_id": actor.get("runtime_instance_id"),
            "session_id": actor.get("session_id"),
            "trace_id": _mapping(source.get("evidence")).get("trace_id"),
        },
        purpose=_mapping(source.get("purpose")),
        action=action,
        tool={
            "name": action.get("tool_name"),
            "version": action.get("tool_version"),
            "fingerprint_id": action.get("tool_fingerprint_id"),
        },
        parameters={"parameter_hash": action.get("parameter_hash")},
        target={
            "resource": action.get("target_resource"),
            "resource_hash": action.get("target_resource_hash"),
            "destination": action.get("data_destination"),
            "destination_hash": action.get("destination_hash"),
        },
        data_context=content,
        approval_context=_mapping(source.get("approval")),
        jit_context={"jit_grant_id": authority.get("jit_grant_id")},
        taint_context={"taint_labels": content.get("taint_labels")},
        side_effect_context={
            "side_effect_class": action.get("side_effect_class"),
            "persistent_side_effect": action.get("persistent_side_effect"),
        },
        discovery_context={
            "application": surface_context.get("application"),
            "provider": surface_context.get("provider"),
            "model": surface_context.get("model"),
            "mcp_server_id": surface_context.get("mcp_server_id"),
            "asset_status": surface_context.get("asset_status"),
        },
        policy_snapshot_id=_text(policy_snapshot_id),
        policy_profile=_mapping(policy_profile),
        path_evidence=evidence,
    )


def _surface_adapter(surface: str):
    def adapt(canonical_action: Mapping[str, Any], **kwargs: Any) -> AuthorizationRequest:
        return adapt_authorization_request(canonical_action, expected_surface=surface, **kwargs)

    adapt.__name__ = f"adapt_{surface}_authorization_request"
    return adapt


adapt_llm_gateway_authorization_request = _surface_adapter("llm_gateway")
adapt_mcp_gateway_authorization_request = _surface_adapter("mcp_gateway")
adapt_runtime_control_authorization_request = _surface_adapter("runtime_control")
adapt_browser_authorization_request = _surface_adapter("browser")
adapt_sdk_authorization_request = _surface_adapter("sdk")
adapt_internal_mcp_authorization_request = _surface_adapter("internal_mcp")


def _unknown_authority_decision(risk: str) -> str:
    if risk in _HIGH_RISK:
        return "block"
    if risk in _MEDIUM_RISK:
        return "require_approval"
    return "review"


def _response_control_mode(decision: str, evidence: Mapping[str, Any]) -> str:
    semantic_decision = decision
    if decision in {"require_approval", "require_second_approval"}:
        semantic_decision = "review"
    elif decision == "redact":
        semantic_decision = "warn"
    return derive_control_mode(
        decision=semantic_decision,
        path_evidence=ControlPathEvidence(
            collector_inline_capable=bool(evidence.get("collector_inline_capable")),
            inline_pre_execution=bool(evidence.get("inline_pre_execution")),
            execution_prevented=bool(evidence.get("execution_prevented")),
            shadow_evaluation=bool(evidence.get("shadow_evaluation")),
            shadow_would_block=bool(evidence.get("shadow_would_block")),
            telemetry_observation=bool(evidence.get("telemetry_observation")),
            external_control_required=bool(evidence.get("external_control_required")),
            external_action_triggered=bool(evidence.get("external_action_triggered")),
        ),
    )


def _base_decision(profile: Mapping[str, Any]) -> str:
    decision = _norm(profile.get("base_decision") or "allow")
    decision = {"alert": "warn", "modify": "redact", "step_up": "require_approval", "deny": "block"}.get(
        decision, decision
    )
    return decision if decision in ALLOWED_DECISIONS else "block"


def _decision_rank(decision: str) -> int:
    return {
        "allow": 0,
        "warn": 1,
        "redact": 2,
        "review": 3,
        "require_approval": 4,
        "require_second_approval": 5,
        "block": 6,
    }.get(decision, 6)


def _max_decision(left: str, right: str) -> str:
    return right if _decision_rank(right) > _decision_rank(left) else left


def authorize_ai_action(request: AuthorizationRequest | Mapping[str, Any]) -> AuthorizationResponse:
    """Return the deterministic authorization result for a normalized action."""

    normalized = _validated_request(request)
    profile = _mapping(normalized.policy_profile)
    profile_hash = _hash(profile)
    degraded = _norm(profile.get("degraded_behavior") or "block")
    if degraded not in _FAIL_CLOSED_DEGRADED:
        degraded = "block"
    risk = _norm(normalized.action.get("risk_level"))
    risk_invalid = risk not in {
        "low", "medium", "moderate", "high", "restricted", "critical", "prohibited", "unknown"
    }
    if risk_invalid:
        risk = "unknown"
    authority_verified = (
        normalized.authority.get("verified") is True
        and _norm(normalized.authority.get("authority_type")) not in {"", "unknown"}
        and _norm(normalized.authority.get("authority_source")) not in {"", "unknown"}
    )
    target_hash = _norm(normalized.target.get("resource_hash"))
    destination = _norm(normalized.target.get("destination"))
    destination_hash = _norm(normalized.target.get("destination_hash"))
    fingerprint = _norm(normalized.tool.get("fingerprint_id"))
    explicit_asset_status = _norm(normalized.discovery_context.get("asset_status"))
    action_type = _norm(normalized.action.get("action_type"))
    parameter_hash = _norm(normalized.parameters.get("parameter_hash"))
    expected_parameter_hash = _norm(profile.get("expected_parameter_hash"))
    executable_action = action_type in {"tool_execution", "api_call", "agent_action"}
    parameter_binding_unknown = executable_action and parameter_hash in {"", "unknown"}
    parameter_binding_mismatch = bool(
        executable_action
        and expected_parameter_hash not in {"", "unknown"}
        and parameter_hash != expected_parameter_hash
    )
    target_unknown = explicit_asset_status not in _VERIFIED_ASSET_STATUSES
    if not target_hash or target_hash == "unknown":
        target_unknown = True
    if action_type in {"tool_execution", "api_call", "agent_action"} and (
        not fingerprint or fingerprint == "unknown"
    ):
        target_unknown = True
    external_send_action = _norm(normalized.action.get("action_type")) in {
        "email_send",
        "external_send",
        "paste_output_to_external_site",
        "share_output",
    }
    if (
        destination not in {"", "unknown", "internal", "none"}
        and destination_hash in {"", "unknown"}
    ) or (external_send_action and destination_hash in {"", "unknown"}):
        target_unknown = True

    reason = "policy_evaluated"
    if profile.get("dependencies_healthy") is not True:
        decision = degraded
        reason = "authorization_dependency_unavailable"
        triggered_controls: tuple[str, ...] = ("AUTHORIZATION_DEPENDENCY_CONTROL",)
    elif risk_invalid:
        decision = "block"
        reason = "risk_classification_invalid:risk=unknown"
        triggered_controls = ("RISK_CLASSIFICATION_CONTROL",)
    elif not authority_verified:
        decision = _unknown_authority_decision(risk)
        reason = f"authority_unverified:risk={risk or 'unknown'}"
        triggered_controls = ("AI_IDENTITY_BINDING", "TOKEN_SCOPE_ENFORCEMENT")
    elif target_unknown:
        decision = _unknown_authority_decision(risk)
        reason = f"target_authority_unknown:risk={risk or 'unknown'}"
        triggered_controls = ("TOOL_CALL_VALIDATION",)
    elif parameter_binding_mismatch:
        decision = _unknown_authority_decision(risk)
        reason = f"parameter_binding_mismatch:risk={risk or 'unknown'}"
        triggered_controls = ("TOOL_CALL_VALIDATION", "PARAMETER_BINDING_CONTROL")
    elif parameter_binding_unknown:
        decision = _unknown_authority_decision(risk)
        reason = f"parameter_binding_unknown:risk={risk or 'unknown'}"
        triggered_controls = ("TOOL_CALL_VALIDATION", "PARAMETER_BINDING_CONTROL")
    else:
        base = _base_decision(profile)
        engine_base = {
            "warn": "alert",
            "redact": "modify",
            "review": "step_up",
            "require_approval": "step_up",
            "require_second_approval": "step_up",
            "block": "block",
        }.get(base, "allow")
        surface = {
            "llm_gateway": "gateway",
            "mcp_gateway": "gateway",
            "runtime_control": "agent",
            "browser": "browser",
            "sdk": "api",
            "internal_mcp": "agent",
        }[normalized.surface]
        engine = evaluate_control_engine(
            AIAction(
                action_id=normalized.action_id,
                user_id=_text(normalized.actor.get("user_id")) or None,
                ai_app=_text(normalized.discovery_context.get("application")) or None,
                model=_text(normalized.discovery_context.get("model")) or None,
                metadata={
                    "source_surface": surface,
                    "action_type": normalized.action.get("action_type"),
                    "data_classification": normalized.data_context.get("input_sensitivity"),
                    "contains_sensitive": _norm(normalized.data_context.get("input_sensitivity"))
                    in {"sensitive", "restricted"},
                    "destination_is_external": _norm(normalized.target.get("destination"))
                    not in {"", "unknown", "internal", "none"},
                    "governance_status": "approved",
                    "triggered_controls": list(profile.get("triggered_controls") or []),
                    "risk_tags": list(normalized.taint_context.get("taint_labels") or []),
                },
                source_surface=surface,
            ),
            base_decision=engine_base,
            hinted_control_ids=list(profile.get("triggered_controls") or []),
        )
        engine_decision = {
            "allow": "allow",
            "alert": "warn",
            "modify": "redact",
            "step_up": "require_approval",
            "block": "block",
        }.get(engine.decision, "block")
        decision = _max_decision(base, engine_decision)
        reason = engine.reasoning
        triggered_controls = tuple(engine.triggered_controls)

    matched_rules = tuple(sorted({*_bounded_tuple(profile.get("matched_rules")), *triggered_controls}))
    transformations = _bounded_tuple(profile.get("transformations"))
    if decision == "redact" and not transformations:
        transformations = ("redact_sensitive_data",)
    safe_path = _bounded_tuple(profile.get("safe_path"))
    evidence_required = _bounded_tuple(profile.get("evidence_required"))
    if decision != "allow" and not evidence_required:
        evidence_required = ("authorization_decision",)
    try:
        cache_ttl = max(0, min(300, int(profile.get("cache_ttl") or 0)))
    except (TypeError, ValueError):
        cache_ttl = 0
    if decision not in {"allow", "warn"} or bool(normalized.side_effect_context.get("persistent_side_effect")):
        cache_ttl = 0
    payload = {
        "schema_version": SCHEMA_VERSION,
        "decision": decision,
        "control_mode": _response_control_mode(decision, normalized.path_evidence),
        "reason": reason,
        "matched_rules": matched_rules,
        "policy_snapshot_id": normalized.policy_snapshot_id,
        "decision_receipt": None,
        "transformations": transformations,
        "safe_path": safe_path,
        "evidence_required": evidence_required,
        "cache_ttl": cache_ttl,
        "degraded_behavior": degraded,
        "policy_profile_hash": profile_hash,
    }
    return AuthorizationResponse(**payload, response_hash=_hash(payload))


def _shadow_request(request: AuthorizationRequest, *, would_block: bool) -> AuthorizationRequest:
    payload = request.model_dump()
    payload["path_evidence"] = {
        **_mapping(payload.get("path_evidence")),
        "shadow_evaluation": True,
        "shadow_would_block": bool(would_block),
        "execution_prevented": False,
    }
    return AuthorizationRequest.model_validate(payload)


def _comparison_side(*, decision: str, reason: str, control_mode: str, policy_snapshot_id: str) -> dict[str, str]:
    return {
        "decision": _norm(decision) or "unknown",
        "reason_hash": _hash(_text(reason)),
        "control_mode": _norm(control_mode) or "unknown",
        "policy_snapshot_hash": _hash(_text(policy_snapshot_id)),
    }


def persist_shadow_comparison_metadata(
    metadata: Mapping[str, Any],
    *,
    request: AuthorizationRequest | Mapping[str, Any],
    response: AuthorizationResponse,
    legacy_decision: str,
    legacy_reason: str,
    legacy_control_mode: str,
    legacy_policy_snapshot_id: str,
) -> dict[str, Any]:
    """Attach one bounded, redacted, idempotent comparison to JSON metadata."""

    normalized = _validated_request(request)
    legacy = _comparison_side(
        decision=legacy_decision,
        reason=legacy_reason,
        control_mode=legacy_control_mode,
        policy_snapshot_id=legacy_policy_snapshot_id,
    )
    v2 = _comparison_side(
        decision=response.decision,
        reason=response.reason,
        control_mode=response.control_mode,
        policy_snapshot_id=response.policy_snapshot_id,
    )
    comparison = {
        "schema_version": SCHEMA_VERSION,
        "action_id": normalized.action_id,
        "legacy": legacy,
        "v2": v2,
        "parity": legacy == v2,
    }
    comparison["comparison_hash"] = _hash(comparison)
    if len(_canonical_json(comparison).encode("utf-8")) > MAX_SHADOW_COMPARISON_BYTES:
        raise ValueError("authorization shadow comparison exceeds bounded payload")
    output = deepcopy(dict(metadata))
    output["authorization_kernel_v2_shadow"] = comparison
    return output


def validate_precomputed_authorization_metadata(
    metadata: Mapping[str, Any],
    *,
    expected_action_id: str,
    expected_policy_snapshot_id: str,
) -> dict[str, Any]:
    """Validate server-precomputed rollout telemetry before event persistence."""

    material = deepcopy(dict(metadata))
    _validate_structural_bounds(material)
    if set(material) != {
        "authorization_kernel_v2_shadow",
        "authorization_kernel_v2_shadow_health",
    }:
        raise ValueError("precomputed authorization metadata has unexpected fields")
    comparison = _mapping(material.get("authorization_kernel_v2_shadow"))
    health = _mapping(material.get("authorization_kernel_v2_shadow_health"))
    if set(comparison) != {
        "schema_version",
        "action_id",
        "legacy",
        "v2",
        "parity",
        "comparison_hash",
    }:
        raise ValueError("precomputed authorization comparison schema is invalid")
    if comparison.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("precomputed authorization comparison version is invalid")
    if _text(comparison.get("action_id")) != _text(expected_action_id):
        raise ValueError("precomputed authorization action binding mismatch")
    if not isinstance(comparison.get("parity"), bool):
        raise ValueError("precomputed authorization parity must be boolean")
    for side_name in ("legacy", "v2"):
        side = _mapping(comparison.get(side_name))
        if set(side) != {"decision", "reason_hash", "control_mode", "policy_snapshot_hash"}:
            raise ValueError("precomputed authorization comparison side is invalid")
        if any(not isinstance(side.get(field), str) or not side.get(field) for field in side):
            raise ValueError("precomputed authorization comparison side is incomplete")
        if side["policy_snapshot_hash"] != _hash(_text(expected_policy_snapshot_id)):
            raise ValueError("precomputed authorization policy binding mismatch")
    comparison_without_hash = dict(comparison)
    comparison_hash = _text(comparison_without_hash.pop("comparison_hash", None))
    if comparison_hash != _hash(comparison_without_hash):
        raise ValueError("precomputed authorization comparison hash mismatch")
    if comparison.get("parity") is not (comparison.get("legacy") == comparison.get("v2")):
        raise ValueError("precomputed authorization parity is invalid")
    if len(_canonical_json(comparison).encode("utf-8")) > MAX_SHADOW_COMPARISON_BYTES:
        raise ValueError("precomputed authorization comparison exceeds bounded payload")
    if set(health) != {"schema_version", "status", "error_code"}:
        raise ValueError("precomputed authorization health schema is invalid")
    if health != {"schema_version": SCHEMA_VERSION, "status": "ok", "error_code": None}:
        raise ValueError("precomputed authorization health is not successful")
    return material


def authorization_rollout_persistence_metadata(
    outcome: AuthorizationRolloutOutcome,
) -> dict[str, Any]:
    """Build bounded trusted event metadata from one selected pre-action evaluation."""

    if not outcome.enforced or outcome.v2_response is None:
        return {}
    comparison = _mapping(outcome.metadata.get("authorization_kernel_v2_shadow"))
    material = {
        "authorization_kernel_v2_shadow": comparison,
        "authorization_kernel_v2_shadow_health": {
            "schema_version": SCHEMA_VERSION,
            "status": "ok",
            "error_code": None,
        },
    }
    return validate_precomputed_authorization_metadata(
        material,
        expected_action_id=_text(comparison.get("action_id")),
        expected_policy_snapshot_id=outcome.v2_response.policy_snapshot_id,
    )


def parse_enforcement_rollout(raw: str) -> dict[str, frozenset[str]]:
    try:
        decoded = json.loads(str(raw or "{}"))
    except json.JSONDecodeError as exc:
        raise ValueError("AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise ValueError("AUTHORIZATION_KERNEL_V2_ENFORCE_ROLLOUT must be an object")
    rollout: dict[str, frozenset[str]] = {}
    for tenant_id, surfaces in decoded.items():
        tenant = _text(tenant_id)
        if not tenant or not isinstance(surfaces, list) or not surfaces:
            raise ValueError("authorization enforcement rollout requires explicit tenant and surfaces")
        normalized_surfaces = frozenset(_norm(item) for item in surfaces)
        if "" in normalized_surfaces or not normalized_surfaces.issubset(ALLOWED_SURFACES):
            raise ValueError("authorization enforcement rollout contains unsupported surface")
        rollout[tenant] = normalized_surfaces
    return rollout


def is_enforcement_selected(*, tenant_id: str, surface: str, settings_obj: Any) -> bool:
    if not bool(settings_obj.authorization_kernel_v2_enforce):
        return False
    rollout = parse_enforcement_rollout(settings_obj.authorization_kernel_v2_enforce_rollout)
    return _norm(surface) in rollout.get(_text(tenant_id), frozenset())


def apply_authorization_rollout(
    *,
    metadata: Mapping[str, Any],
    request: AuthorizationRequest | Mapping[str, Any],
    legacy_decision: str,
    legacy_reason: str,
    legacy_control_mode: str,
    settings_obj: Any,
    legacy_policy_snapshot_id: str = "unknown",
) -> AuthorizationRolloutOutcome:
    """Shadow or enforce v2 without consulting caller-controlled rollout claims."""

    original_metadata = deepcopy(dict(metadata))
    if not bool(settings_obj.authorization_kernel_v2_enabled):
        return AuthorizationRolloutOutcome(_text(legacy_decision), original_metadata, None, False)
    normalized = _validated_request(request)
    enforce = is_enforcement_selected(
        tenant_id=normalized.tenant_id, surface=normalized.surface, settings_obj=settings_obj
    )
    if enforce:
        response = authorize_ai_action(normalized)
    else:
        preliminary = authorize_ai_action(normalized)
        response = authorize_ai_action(_shadow_request(normalized, would_block=preliminary.decision == "block"))
    output_metadata = original_metadata
    if bool(settings_obj.authorization_kernel_shadow_compare_enabled):
        output_metadata = persist_shadow_comparison_metadata(
            output_metadata,
            request=normalized,
            response=response,
            legacy_decision=legacy_decision,
            legacy_reason=legacy_reason,
            legacy_control_mode=legacy_control_mode,
            legacy_policy_snapshot_id=legacy_policy_snapshot_id,
        )
    return AuthorizationRolloutOutcome(
        response.decision if enforce else _text(legacy_decision),
        output_metadata,
        response,
        enforce,
        normalized,
    )


def apply_trusted_pre_action_rollout(
    *,
    tenant_id: str,
    surface: str,
    action_id: str,
    chain_id: str,
    collector_id: str,
    trusted_pre_action_governance_check: Mapping[str, Any],
    legacy_decision: str,
    legacy_reason: str,
    legacy_control_mode: str,
    policy_snapshot_id: str,
    settings_obj: Any,
) -> AuthorizationRolloutOutcome:
    """Evaluate server-resolved pre-action facts without accepting rollout or hash claims from callers."""

    if not bool(settings_obj.authorization_kernel_v2_enabled) or not is_enforcement_selected(
        tenant_id=tenant_id,
        surface=surface,
        settings_obj=settings_obj,
    ):
        return AuthorizationRolloutOutcome(legacy_decision, {}, None, False)

    trusted = _mapping(trusted_pre_action_governance_check)
    actor = _mapping(trusted.get("actor"))
    authority = _mapping(trusted.get("authority"))
    surface_context = _mapping(trusted.get("surface"))
    action = _mapping(trusted.get("action"))
    policy = _mapping(trusted.get("policy"))
    target_resource = action.get("target_resource")
    destination = action.get("data_destination")
    request = AuthorizationRequest(
        tenant_id=tenant_id,
        environment=_text(surface_context.get("environment") or "unknown"),
        collector_id=collector_id,
        action_id=action_id,
        chain_id=chain_id,
        surface=_norm(surface),
        actor=actor,
        authority=authority,
        runtime={"session_id": actor.get("session_id"), "trace_id": _mapping(trusted.get("evidence")).get("trace_id")},
        purpose=_mapping(trusted.get("purpose")),
        action={
            "action_type": action.get("action_type"),
            "risk_level": action.get("action_risk"),
        },
        tool={
            "name": action.get("tool_name"),
            "version": action.get("tool_version"),
            "fingerprint_id": action.get("tool_fingerprint_id"),
        },
        parameters={"parameter_hash": action.get("parameter_hash")},
        target={
            "resource": target_resource,
            "resource_hash": _hash(target_resource) if _text(target_resource) else "unknown",
            "destination": destination,
            "destination_hash": _hash(destination) if _text(destination) else "unknown",
        },
        data_context=_mapping(trusted.get("content")),
        approval_context=_mapping(trusted.get("approval")),
        side_effect_context={
            "side_effect_class": action.get("side_effect_class"),
            "persistent_side_effect": action.get("persistent_side_effect"),
        },
        discovery_context={
            "application": surface_context.get("application"),
            "provider": surface_context.get("provider"),
            "model": surface_context.get("model"),
            "mcp_server_id": surface_context.get("mcp_server_id"),
            "asset_status": surface_context.get("asset_status"),
        },
        policy_snapshot_id=policy_snapshot_id,
        policy_profile={
            "base_decision": legacy_decision,
            "triggered_controls": list(policy.get("control_ids") or []),
            "dependencies_healthy": True,
            "degraded_behavior": "block",
            "expected_parameter_hash": action.get("expected_parameter_hash"),
        },
        path_evidence={
            "collector_inline_capable": True,
            "inline_pre_execution": True,
            **_mapping(trusted.get("path_evidence")),
        },
    )
    return apply_authorization_rollout(
        metadata={},
        request=request,
        legacy_decision=legacy_decision,
        legacy_reason=legacy_reason,
        legacy_control_mode=legacy_control_mode,
        legacy_policy_snapshot_id=policy_snapshot_id,
        settings_obj=settings_obj,
    )


__all__ = [
    "ALLOWED_DECISIONS",
    "AuthorizationRequest",
    "AuthorizationResponse",
    "AuthorizationRolloutOutcome",
    "MAX_SHADOW_COMPARISON_BYTES",
    "adapt_authorization_request",
    "adapt_browser_authorization_request",
    "adapt_internal_mcp_authorization_request",
    "adapt_llm_gateway_authorization_request",
    "adapt_mcp_gateway_authorization_request",
    "adapt_runtime_control_authorization_request",
    "adapt_sdk_authorization_request",
    "apply_authorization_rollout",
    "apply_trusted_pre_action_rollout",
    "authorization_rollout_persistence_metadata",
    "authorize_ai_action",
    "is_enforcement_selected",
    "parse_enforcement_rollout",
    "persist_shadow_comparison_metadata",
    "validate_precomputed_authorization_metadata",
]
