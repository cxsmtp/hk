"""The real proxy HTTP body must satisfy the API's strict MCP authorization model."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api.routers.gateway import MCPAuthorizeRequest
from app.services.ai_iam_service import evaluate_purpose_bound_permission


ROOT = Path(__file__).resolve().parents[3]
RUNNER = ROOT / "infra" / "scripts" / "run_isolated_mcp_client_acceptance.py"


def test_real_js_gateway_wire_body_matches_strict_api_contract():
    spec = importlib.util.spec_from_file_location("run_isolated_mcp_client_acceptance", RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    payload = module.capture_gateway_authorize_wire({
        "aiSystemId": "synthetic-system", "actorId": "synthetic-agent",
        "capabilityToken": "synthetic-capability", "mcpServerId": "manual-terminal-lab",
        "toolName": "write_demo_marker", "toolVersion": "1.0.0",
        "toolFingerprintId": "synthetic-fingerprint",
        "argumentsObject": {"note": "synthetic-marker"},
        "sessionId": "synthetic-session", "clientApp": "official-sdk",
    })
    parsed = MCPAuthorizeRequest.model_validate(payload)
    assert parsed.ai_system_id == "synthetic-system"
    assert parsed.actor_id == "synthetic-agent"
    assert parsed.capability_token == "synthetic-capability"
    assert parsed.tool_name == "write_demo_marker"
    assert parsed.session_id == "synthetic-session"
    assert "client_app" not in payload
    with pytest.raises(ValidationError):
        MCPAuthorizeRequest.model_validate({**payload, "client_app": "official-sdk"})


def test_read_fixture_environment_must_match_persisted_purpose_scope():
    permission = {
        "status": "active", "mode": "block", "purpose": {"name": "synthetic_read"},
        "scope": {"allowed_actions": ["file_read"], "allowed_tools": ["read_demo_marker"],
                  "allowed_domains": ["unknown"], "allowed_resources": ["unknown"],
                  "allowed_environments": ["production"], "allowed_data_scopes": ["internal"]},
        "constraints": {"max_risk_level": "high"},
    }
    common = {"permission": permission, "action_type": "file_read", "action_category": "read",
              "action_risk": "low", "tool_name": "read_demo_marker", "target_resource": "unknown", "domain": "unknown"}
    before = evaluate_purpose_bound_permission(**common, environment="prod")
    after = evaluate_purpose_bound_permission(**common, environment="production")
    assert before["decision"] == "block"
    assert before["reason"] == "action_outside_purpose_scope"
    assert before["violations"] == ["environment:prod"]
    assert after["decision"] == "allow"
