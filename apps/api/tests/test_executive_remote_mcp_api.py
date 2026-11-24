from __future__ import annotations

from apps.api.app.services.executive_remote_mcp_service import (
    EXECUTIVE_REMOTE_MCP_TOOLS,
    build_oauth_authorization_server_metadata,
    build_oauth_protected_resource_metadata,
    build_executive_remote_mcp_metadata,
    build_jsonrpc_error,
    build_jsonrpc_result,
)


def test_remote_mcp_metadata_is_connector_friendly_and_truthful() -> None:
    metadata = build_executive_remote_mcp_metadata()

    assert metadata["name"] == "hawk-executive-remote-mcp"
    assert metadata["transport"] == "streamable-http"
    assert metadata["auth"]["type"] == "bearer"
    assert metadata["auth"]["tenant_header"] == "X-Tenant-ID"
    assert metadata["auth"]["oauth"]["protected_resource_metadata"] == "/mcp/executive/.well-known/oauth-protected-resource"
    assert metadata["privacy"]["raw_prompt_content_included"] is False
    assert {tool["name"] for tool in metadata["tools"]} == {
        "get_executive_summary",
        "query_executive_metrics",
        "create_executive_presentation",
    }


def test_remote_mcp_tools_are_bounded_and_match_expected_executive_scope() -> None:
    query_tool = next(tool for tool in EXECUTIVE_REMOTE_MCP_TOOLS if tool["name"] == "query_executive_metrics")
    metric_enum = query_tool["inputSchema"]["properties"]["metric"]["enum"]

    assert "tokens" in metric_enum
    assert "spend" in metric_enum
    assert "github_repositories" in metric_enum
    assert "raw_prompts" not in metric_enum
    assert query_tool["inputSchema"]["properties"]["limit"]["maximum"] == 100


def test_remote_mcp_jsonrpc_helpers_preserve_ids_and_error_codes() -> None:
    result = build_jsonrpc_result("req-1", {"ok": True})
    error = build_jsonrpc_error("req-2", -32601, "Method not found")

    assert result == {"jsonrpc": "2.0", "id": "req-1", "result": {"ok": True}}
    assert error == {
        "jsonrpc": "2.0",
        "id": "req-2",
        "error": {"code": -32601, "message": "Method not found"},
    }


def test_remote_mcp_oauth_metadata_is_claude_connector_ready() -> None:
    protected = build_oauth_protected_resource_metadata("https://api.example.test")
    server = build_oauth_authorization_server_metadata("https://api.example.test")

    assert protected["resource"] == "https://api.example.test/mcp/executive"
    assert protected["authorization_servers"] == ["https://api.example.test/mcp/executive"]
    assert "executive_mcp:read" in protected["scopes_supported"]
    assert server["authorization_endpoint"] == "https://api.example.test/mcp/executive/authorize"
    assert server["token_endpoint"] == "https://api.example.test/mcp/executive/token"
    assert server["device_authorization_endpoint"] == "https://api.example.test/mcp/executive/device_authorization"
    assert server["registration_endpoint"] == "https://api.example.test/mcp/executive/register"
    assert "authorization_code" in server["grant_types_supported"]
    assert "urn:ietf:params:oauth:grant-type:device_code" in server["grant_types_supported"]
