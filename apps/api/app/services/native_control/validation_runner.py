from __future__ import annotations

from typing import Callable

from app.core.control_engine.authorization import AuthorizationRequest, authorize_ai_action


def _probe_request(*, tenant_id: str, integration_id: str, decision: str) -> AuthorizationRequest:
    return AuthorizationRequest(
        tenant_id=tenant_id,
        environment="validation",
        collector_id=f"native-control-validation:{integration_id}",
        action_id=f"safe-synthetic-{decision}",
        chain_id=f"safe-synthetic-{integration_id}",
        surface="sdk",
        actor={"identity_id": "hawk-validation", "identity_type": "service"},
        authority={
            "verified": True,
            "authority_type": "workload_identity",
            "authority_source": "native_control_validation",
        },
        action={"action_type": "prompt", "risk_level": "low"},
        target={
            "resource": "hawk-safe-synthetic-target",
            "resource_hash": "hawk-safe-synthetic-target-v1",
            "destination": "internal",
            "destination_hash": "validation-internal",
        },
        side_effect_context={"persistent_side_effect": False},
        discovery_context={"asset_status": "approved"},
        policy_snapshot_id="native-control-safe-validation/1.0",
        policy_profile={
            "dependencies_healthy": True,
            "base_decision": decision,
            "degraded_behavior": "block",
            "triggered_controls": [],
        },
        path_evidence={
            "collector_inline_capable": True,
            "inline_pre_execution": True,
            "execution_prevented": decision == "block",
        },
    )


def _endpoint_probe_request(*, tenant_id: str, integration_id: str, decision: str) -> AuthorizationRequest:
    request = _probe_request(tenant_id=tenant_id, integration_id=integration_id, decision=decision)
    return request.model_copy(
        deep=True,
        update={
            "collector_id": f"native-endpoint-validation:{integration_id}",
            # Endpoint runtime control is represented by the authorization
            # kernel's runtime_control surface.  "endpoint" is deliberately
            # not an accepted authorization surface because it would bypass
            # the kernel's pre-side-effect enforcement classification.
            "surface": "runtime_control",
            "path_evidence": {
                **request.path_evidence,
                "native_control_route_binding": {
                    "verified": True,
                    "source": "hawk_endpoint_route",
                    "integration_instance_ids": [integration_id],
                    "allowed_methods": ["endpoint_runtime"],
                },
            },
        },
    )


def _server_endpoint_probe(*, tenant_id: str, integration_id: str, decision: str) -> dict[str, object]:
    response = authorize_ai_action(
        _endpoint_probe_request(
            tenant_id=tenant_id,
            integration_id=integration_id,
            decision=decision,
        )
    )
    return {
        "decision": response.decision,
        "control_mode": response.control_mode,
        "route_verified": True,
        # The server runner deliberately has no protected callback to invoke.
        "protected_callback_executed": False,
    }


def run_safe_synthetic_validation(
    *,
    tenant_id: str,
    integration_id: str,
    integration_method: str,
    profile_verified: bool,
    pre_execution_capable: bool,
    route_binding_configured: bool,
    live_route_observed: bool,
    endpoint_probe: Callable[[str], dict[str, object]] | None = None,
) -> dict[str, bool]:
    """Exercise Hawk-owned inline policy behavior without any external side effect."""

    gateway_supported = (
        integration_method == "gateway_inline"
        and profile_verified
        and pre_execution_capable
        and route_binding_configured
    )
    endpoint_supported = (
        integration_method in {"endpoint_runtime", "native_hook"}
        and profile_verified
        and pre_execution_capable
        and route_binding_configured
        and live_route_observed
    )
    if endpoint_supported:
        probe = endpoint_probe or (
            lambda decision: _server_endpoint_probe(
                tenant_id=tenant_id,
                integration_id=integration_id,
                decision=decision,
            )
        )
        allowed = probe("allow")
        blocked = probe("block")
        return {
            "route_binding_configured": True,
            "server_probe_supported": True,
            "live_route_observed": True,
            "allow_behavior": (
                allowed.get("decision") == "allow"
                and allowed.get("control_mode") == "inline_allowed"
                and allowed.get("route_verified") is True
            ),
            "block_behavior": (
                blocked.get("decision") == "block"
                and blocked.get("control_mode") == "inline_prevented"
                and blocked.get("route_verified") is True
            ),
            "protected_callback_not_executed": blocked.get("protected_callback_executed") is False,
        }
    if not gateway_supported:
        return {
            "route_binding_configured": route_binding_configured,
            "server_probe_supported": False,
            "live_route_observed": live_route_observed,
            "allow_behavior": False,
            "block_behavior": False,
            "protected_callback_not_executed": False,
        }
    allowed = authorize_ai_action(
        _probe_request(tenant_id=tenant_id, integration_id=integration_id, decision="allow")
    )
    blocked = authorize_ai_action(
        _probe_request(tenant_id=tenant_id, integration_id=integration_id, decision="block")
    )
    return {
        "route_binding_configured": True,
        "server_probe_supported": True,
        "live_route_observed": live_route_observed,
        "allow_behavior": allowed.decision == "allow" and allowed.control_mode == "inline_allowed",
        "block_behavior": blocked.decision == "block" and blocked.control_mode == "inline_prevented",
        "protected_callback_not_executed": True,
    }
