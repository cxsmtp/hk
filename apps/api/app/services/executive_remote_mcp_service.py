from __future__ import annotations

from copy import deepcopy
import json
from typing import Any


EXECUTIVE_REMOTE_MCP_PROTOCOL_VERSION = "2024-11-05"
EXECUTIVE_REMOTE_MCP_SERVER_NAME = "hawk-executive-remote-mcp"
EXECUTIVE_REMOTE_MCP_SERVER_VERSION = "0.1.0"
EXECUTIVE_REMOTE_MCP_RESOURCE_PATH = "/mcp/executive"
EXECUTIVE_REMOTE_MCP_SCOPE_READ = "executive_mcp:read"
EXECUTIVE_REMOTE_MCP_SCOPE_PRESENTATION = "executive_mcp:presentation"


EXECUTIVE_REMOTE_MCP_TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_executive_summary",
        "description": "Return a tenant-scoped executive AI governance summary. Raw prompt content is never included.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "window_days": {"type": "integer", "minimum": 1, "maximum": 366, "default": 30},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "query_executive_metrics",
        "description": (
            "Query tenant-scoped executive metrics such as actions, blocks, top violations, providers, MCP tools, "
            "GitHub repositories, control coverage, spend, or tokens."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["metric"],
            "properties": {
                "metric": {
                    "type": "string",
                    "enum": [
                        "actions",
                        "blocked",
                        "top_violations",
                        "violations_by_framework",
                        "providers",
                        "mcp_tools",
                        "github_repositories",
                        "control_coverage",
                        "spend",
                        "tokens",
                    ],
                },
                "group_by": {"type": ["string", "null"], "default": None},
                "window_days": {"type": "integer", "minimum": 1, "maximum": 366, "default": 30},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 10},
                "include_named_users": {"type": "boolean", "default": False},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "create_executive_presentation",
        "description": "Create an audited tenant-scoped PPTX executive brief from current evidence. Raw prompt content is excluded.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 120,
                    "default": "Executive AI Governance Brief",
                },
                "window_days": {"type": "integer", "minimum": 1, "maximum": 366, "default": 30},
            },
            "additionalProperties": False,
        },
    },
]


def build_jsonrpc_result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def build_jsonrpc_error(
    request_id: Any,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def build_initialize_result() -> dict[str, Any]:
    return {
        "protocolVersion": EXECUTIVE_REMOTE_MCP_PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {
            "name": EXECUTIVE_REMOTE_MCP_SERVER_NAME,
            "version": EXECUTIVE_REMOTE_MCP_SERVER_VERSION,
        },
    }


def build_tools_list_result() -> dict[str, Any]:
    return {"tools": deepcopy(EXECUTIVE_REMOTE_MCP_TOOLS)}


def build_tool_call_result(tool_result: dict[str, Any]) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(tool_result, default=str, ensure_ascii=False),
            }
        ],
        "isError": False,
    }


def build_executive_remote_mcp_metadata() -> dict[str, Any]:
    return {
        "name": EXECUTIVE_REMOTE_MCP_SERVER_NAME,
        "version": EXECUTIVE_REMOTE_MCP_SERVER_VERSION,
        "transport": "streamable-http",
        "endpoint": EXECUTIVE_REMOTE_MCP_RESOURCE_PATH,
        "auth": {
            "type": "bearer",
            "header": "Authorization",
            "scheme": "Bearer",
            "tenant_header": "X-Tenant-ID",
            "oauth": {
                "protected_resource_metadata": f"{EXECUTIVE_REMOTE_MCP_RESOURCE_PATH}/.well-known/oauth-protected-resource",
                "authorization_server_metadata": f"{EXECUTIVE_REMOTE_MCP_RESOURCE_PATH}/.well-known/oauth-authorization-server",
                "scopes": [
                    EXECUTIVE_REMOTE_MCP_SCOPE_READ,
                    EXECUTIVE_REMOTE_MCP_SCOPE_PRESENTATION,
                ],
            },
        },
        "tools": deepcopy(EXECUTIVE_REMOTE_MCP_TOOLS),
        "privacy": {
            "raw_prompt_content_included": False,
            "named_user_detail": "role-based",
        },
        "notes": [
            "Use an HTTPS URL reachable from the MCP client.",
            "Pass a short-lived platform access token as the bearer token.",
            "Pass X-Tenant-ID as a header or connector header variable.",
            "Hosted OAuth connector flow is available for MCP clients that cannot set custom headers.",
        ],
    }


def build_oauth_protected_resource_metadata(base_url: str) -> dict[str, Any]:
    resource = f"{base_url}{EXECUTIVE_REMOTE_MCP_RESOURCE_PATH}"
    return {
        "resource": resource,
        "authorization_servers": [resource],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [
            EXECUTIVE_REMOTE_MCP_SCOPE_READ,
            EXECUTIVE_REMOTE_MCP_SCOPE_PRESENTATION,
        ],
    }


def build_oauth_authorization_server_metadata(base_url: str) -> dict[str, Any]:
    issuer = f"{base_url}{EXECUTIVE_REMOTE_MCP_RESOURCE_PATH}"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "device_authorization_endpoint": f"{issuer}/device_authorization",
        "registration_endpoint": f"{issuer}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "urn:ietf:params:oauth:grant-type:device_code"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "scopes_supported": [
            EXECUTIVE_REMOTE_MCP_SCOPE_READ,
            EXECUTIVE_REMOTE_MCP_SCOPE_PRESENTATION,
        ],
    }
