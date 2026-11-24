from __future__ import annotations

import pytest
from pydantic import ValidationError


def _binding(transport: str) -> dict:
    common = {
        "transport": transport,
        "route_id": f"route:{transport}",
        "authentication_mode": "managed_identity",
        "direct_bypass": False,
    }
    variants = {
        "function": {
            "function_manifest_id": "function:get_account_summary:1.0.0",
        },
        "mcp": {
            "mcp_server_id": "mcp-bank-core",
            "mcp_tool_name": "get_account_summary",
            "mcp_tool_version": "1.0.0",
            "mcp_tool_fingerprint_id": "tool-fingerprint-001",
        },
        "toolbox": {
            "toolbox_id": "foundry-toolbox-bank",
            "toolbox_version": "7",
            "project_connection_id": "foundry-connection-bank",
            "mcp_server_id": "mcp-bank-core",
            "mcp_tool_name": "get_account_summary",
            "mcp_tool_version": "1.0.0",
            "mcp_tool_fingerprint_id": "tool-fingerprint-001",
        },
        "rest": {
            "http_method": "POST",
            "route_template": "/customers/{customer}/accounts/{account}/summary",
        },
        "openapi": {
            "http_method": "POST",
            "route_template": "/customers/{customer}/accounts/{account}/summary",
            "openapi_operation_id": "getAccountSummary",
            "openapi_document_fingerprint": "d" * 64,
        },
        "apim": {
            "http_method": "POST",
            "route_template": "/customers/{customer}/accounts/{account}/summary",
            "openapi_operation_id": "getAccountSummary",
            "openapi_document_fingerprint": "d" * 64,
            "apim_api_id": "banking-api",
            "apim_revision": "3",
            "apim_backend_id": "bank-core-backend",
        },
    }
    return {**common, **variants[transport]}


def _action(transport: str = "function") -> dict:
    return {
        "tenant_id": "tenant-a",
        "ai_transaction_id": "transaction-001",
        "action_id": f"action:{transport}",
        "chain_id": "chain-001",
        "business_purpose_id": "own-account-summary",
        "operation_type": "read_summary",
        "tool_name": "get_account_summary",
        "tool_version": "1.0.0",
        "tool_schema_fingerprint": "a" * 64,
        "arguments": {"account_id": "acct-001", "view": "summary"},
        "target_resource_type": "account",
        "target_resource_reference": "acct-001",
        "target_resolver_version": "bank-account-v1",
        "destination": "bank-core.internal",
        "identity_type": "project_managed_identity",
        "side_effect_class": "read_only",
        "persistent_side_effect": False,
        "idempotency_key_hash": "e" * 64,
        "transport_binding": _binding(transport),
    }


def _mcp_inventory() -> dict:
    return {
        "id": "tool-fingerprint-001",
        "mcp_server_id": "mcp-bank-core",
        "tool_name": "get_account_summary",
        "tool_version": "1.0.0",
        "schema_hash": "a" * 64,
        "approved_hash": "a" * 64,
        "trust_status": "approved",
    }


def test_same_business_action_has_transport_independent_semantic_hash() -> None:
    from app.services.banking_transport_control_service import (
        BankingTransportAction,
        canonicalize_banking_transport_action,
    )

    projections = [
        canonicalize_banking_transport_action(
            BankingTransportAction.model_validate(_action(transport)),
            mcp_inventory_record=(
                _mcp_inventory() if transport in {"mcp", "toolbox"} else None
            ),
        )
        for transport in ("function", "mcp", "toolbox", "rest", "openapi", "apim")
    ]

    assert len({item.semantic_action_hash for item in projections}) == 1
    assert len({item.execution_binding_hash for item in projections}) == 6
    assert all(item.control_requirement_satisfied for item in projections)
    assert all(item.semantic_action["operation_type"] == "read_summary" for item in projections)
    assert all("acct-001" not in item.model_dump_json() for item in projections)


@pytest.mark.parametrize(
    ("auth_mode", "quality", "shared"),
    (
        ("oauth_passthrough", "verified_end_user", False),
        ("agent_identity", "dedicated_agent_identity", False),
        ("project_managed_identity", "project_shared_identity", True),
        ("shared_key", "shared_credential", True),
    ),
)
def test_mcp_authentication_mode_is_honest(
    auth_mode: str,
    quality: str,
    shared: bool,
) -> None:
    from app.services.banking_transport_control_service import (
        BankingTransportAction,
        canonicalize_banking_transport_action,
    )

    payload = _action("mcp")
    payload["transport_binding"]["authentication_mode"] = auth_mode
    projection = canonicalize_banking_transport_action(
        BankingTransportAction.model_validate(payload),
        mcp_inventory_record=_mcp_inventory(),
    )

    assert projection.identity_quality == quality
    assert projection.shared_authority is shared


@pytest.mark.parametrize(
    ("mutation", "reason"),
    (
        ({"direct_bypass": True}, "DIRECT_TRANSPORT_BYPASS"),
        ({"route_id": ""}, "validation_error"),
    ),
)
def test_direct_bypass_and_missing_route_never_claim_inline_control(
    mutation: dict,
    reason: str,
) -> None:
    from app.services.banking_transport_control_service import (
        BankingTransportAction,
        canonicalize_banking_transport_action,
    )

    payload = _action("rest")
    payload["transport_binding"].update(mutation)
    if reason == "validation_error":
        with pytest.raises(ValidationError):
            BankingTransportAction.model_validate(payload)
        return

    projection = canonicalize_banking_transport_action(
        BankingTransportAction.model_validate(payload)
    )
    assert projection.control_requirement_satisfied is False
    assert projection.reason_code == reason


def test_mcp_must_reference_existing_approved_inventory() -> None:
    from app.services.banking_transport_control_service import (
        BankingTransportAction,
        canonicalize_banking_transport_action,
    )

    action = BankingTransportAction.model_validate(_action("mcp"))
    missing = canonicalize_banking_transport_action(action)
    changed_inventory = _mcp_inventory()
    changed_inventory["schema_hash"] = "f" * 64
    drift = canonicalize_banking_transport_action(
        action,
        mcp_inventory_record=changed_inventory,
    )

    assert (missing.control_requirement_satisfied, missing.reason_code) == (
        False,
        "MCP_INVENTORY_UNVERIFIED",
    )
    assert (drift.control_requirement_satisfied, drift.reason_code) == (
        False,
        "MCP_TOOL_FINGERPRINT_DRIFT",
    )


def test_toolbox_version_and_project_connection_are_execution_bound() -> None:
    from app.services.banking_transport_control_service import (
        BankingTransportAction,
        canonicalize_banking_transport_action,
    )

    original = canonicalize_banking_transport_action(
        BankingTransportAction.model_validate(_action("toolbox")),
        mcp_inventory_record=_mcp_inventory(),
    )
    changed = _action("toolbox")
    changed["transport_binding"]["toolbox_version"] = "8"
    drift = canonicalize_banking_transport_action(
        BankingTransportAction.model_validate(changed),
        mcp_inventory_record=_mcp_inventory(),
    )

    assert original.semantic_action_hash == drift.semantic_action_hash
    assert original.execution_binding_hash != drift.execution_binding_hash


def test_unresolved_target_and_persistence_are_explicit() -> None:
    from app.services.banking_transport_control_service import (
        BankingTransportAction,
        canonicalize_banking_transport_action,
    )

    unresolved = _action("function")
    unresolved["target_resource_reference"] = "unknown"
    unresolved_projection = canonicalize_banking_transport_action(
        BankingTransportAction.model_validate(unresolved)
    )
    persistent = _action("function")
    persistent["side_effect_class"] = "persistent"
    persistent["persistent_side_effect"] = True
    persistent_projection = canonicalize_banking_transport_action(
        BankingTransportAction.model_validate(persistent)
    )

    assert unresolved_projection.control_requirement_satisfied is False
    assert unresolved_projection.reason_code == "TARGET_UNRESOLVED"
    assert persistent_projection.semantic_action["persistent_side_effect"] is True
