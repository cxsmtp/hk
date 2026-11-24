from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from time import sleep
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services.agentic_action_integrity_service import record_surface_agent_touchpoints
from app.services.surface_control_plane_service import (
    get_identity_unified_view,
    get_unified_alert_trace,
    ingest_surface_event,
    list_unified_alerts,
)


router = APIRouter(prefix="/surface-coverage", tags=["surface-coverage"])
SQLITE_LOCK_RETRY_ATTEMPTS = 8
SQLITE_LOCK_RETRY_BACKOFF_SECONDS = 0.1


class UnifiedSurfaceEventRequest(BaseModel):
    surface: str = "saas"
    app: str | None = None
    action_type: str = "prompt_input"
    event_type: str | None = None
    user_id: str | None = None
    agent_id: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    session_id: str | None = None
    correlation_id: str | None = None
    ai_system_id: str | None = None
    app_domain: str | None = None
    url: str | None = None
    model: str | None = None
    model_version: str | None = None
    provider: str | None = None
    tool: str | None = None
    tool_category: str | None = None
    api_endpoint: str | None = None
    data_source: str | None = None
    prompt_or_content: str | None = None
    prompt: str | None = None
    content: str | None = None
    prompt_preview_redacted: str | None = None
    file_meta: list[dict[str, Any]] = Field(default_factory=list)
    input_signal_types: list[str] = Field(default_factory=list)
    decision_hint: str | None = None
    reason_code: str | None = None
    policy_version: str | None = None
    governance_version: str | None = None
    risk_tier: str | None = None
    risk_score: float | None = None
    confidence_tier: str | None = None
    timestamp: datetime | None = None
    gateway_routed: bool = False
    prompt_storage_mode: str | None = None
    platform_mode: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    browser: str | None = None
    browser_version: str | None = None
    extension_version: str | None = None
    location: str | None = None
    chain_id: str | None = None
    chain_depth: int | None = None
    parent_action_id: str | None = None
    parent_agent_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    transport: dict[str, Any] = Field(default_factory=dict)
    evidence_node_ids: list[str] = Field(default_factory=list)
    response_size: int | None = None
    data_classification: str | None = None
    source_classification_hint: str | None = None
    ai_usage_detected: bool | None = None


class UnifiedSurfaceBatchRequest(BaseModel):
    events: list[UnifiedSurfaceEventRequest]


class EndpointHeartbeatRequest(BaseModel):
    user_id: str | None = None
    device_id: str
    hostname: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    browser_type: str | None = None
    browser_version: str | None = None
    extension_version: str | None = None
    location: str | None = None
    running_apps: list[str] = Field(default_factory=list)
    gateway_routed: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SlackEventApiRequest(BaseModel):
    type: str | None = None
    challenge: str | None = None
    team_id: str | None = None
    event_id: str | None = None
    event_time: int | None = None
    event: dict[str, Any] = Field(default_factory=dict)


class O365GraphEventRequest(BaseModel):
    value: list[dict[str, Any]] = Field(default_factory=list)


class GoogleWorkspaceRawEventRequest(BaseModel):
    payload: dict[str, Any] = Field(default_factory=dict)
    user_id: str | None = None
    app: str = "google_workspace"


class MicrosoftOutlookEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    event_type: str = "outlook.email"
    subject: str | None = None
    body_preview: str | None = None
    recipients: list[str] = Field(default_factory=list)
    file_meta: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = True


class MicrosoftTeamsEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    event_type: str = "teams.message"
    message: str | None = None
    channel_id: str | None = None
    team_id: str | None = None
    meeting_id: str | None = None
    file_meta: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = True


class MicrosoftDriveSharepointEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    source: str = "sharepoint"  # onedrive | sharepoint
    event_type: str = "file.activity"
    action: str | None = None
    file_name: str | None = None
    file_path: str | None = None
    sharing_scope: str | None = None
    content_preview: str | None = None
    sensitivity_label: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = True


class MicrosoftOfficeCopilotEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    app_name: str = "word"  # word | excel | powerpoint
    event_type: str = "office.copilot.prompt"
    prompt_or_content: str | None = None
    document_title: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = True


class MicrosoftEntraEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    event_type: str = "entra.identity_activity"
    activity: str | None = None
    app_display_name: str | None = None
    risk_level: str | None = None
    risk_state: str | None = None
    risk_detail: str | None = None
    ip_address: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = True


class MicrosoftAzureOpenAIEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    event_type: str = "azure_openai.request"
    prompt_or_content: str | None = None
    prompt_preview_redacted: str | None = None
    model: str | None = None
    model_version: str | None = None
    api_endpoint: str | None = None
    provider: str = "azure_openai"
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = True
    transport: dict[str, Any] = Field(default_factory=dict)


class MicrosoftFoundryEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    agent_id: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    event_type: str = "foundry.agent_action"
    action_type: str = "agent_action"
    prompt_or_content: str | None = None
    project_id: str | None = None
    project_name: str | None = None
    workspace_id: str | None = None
    subscription_id: str | None = None
    resource_group: str | None = None
    agent_name: str | None = None
    model: str | None = None
    model_version: str | None = None
    model_deployment: str | None = None
    model_deployment_id: str | None = None
    tool: str | None = None
    tool_names: list[str] = Field(default_factory=list)
    data_source: str | None = None
    data_source_ids: list[str] = Field(default_factory=list)
    api_endpoint: str | None = None
    service_principal_id: str | None = None
    managed_identity_id: str | None = None
    entra_app_id: str | None = None
    authority: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = False
    transport: dict[str, Any] = Field(default_factory=dict)


class MicrosoftFoundrySyncRequest(BaseModel):
    subscription_id: str | None = None
    resource_group: str | None = None
    workspace_id: str | None = None
    project_endpoint: str | None = None
    api_version: str = "2025-05-01-preview"
    endpoints: dict[str, str] = Field(default_factory=dict)
    access_token: str | None = Field(default=None, repr=False)
    inventory: dict[str, Any] = Field(default_factory=dict)
    gateway_routed_agent_ids: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    max_pages_per_endpoint: int = Field(default=10, ge=1, le=100)
    max_retries: int = Field(default=2, ge=0, le=5)
    allow_insecure_local_http: bool = False


class MicrosoftCopilotSyncRequest(BaseModel):
    tenant_graph_endpoint: str | None = None
    copilot_studio_endpoint: str | None = None
    endpoints: dict[str, str] = Field(default_factory=dict)
    access_token: str | None = Field(default=None, repr=False)
    inventory: dict[str, Any] = Field(default_factory=dict)
    gateway_routed_agent_ids: list[str] = Field(default_factory=list)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    max_pages_per_endpoint: int = Field(default=10, ge=1, le=100)
    max_retries: int = Field(default=2, ge=0, le=5)
    allow_insecure_local_http: bool = False


class MicrosoftCopilotEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    app: str = "m365_copilot"
    copilot_type: str = "m365_copilot"
    event_type: str = "copilot.prompt"
    action_type: str = "prompt_input"
    prompt_or_content: str | None = None
    document_title: str | None = None
    workload: str | None = None
    source_app: str | None = None
    sensitivity_label: str | None = None
    knowledge_asset_ids: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    permission_scopes: list[str] = Field(default_factory=list)
    oauth_app_id: str | None = None
    oauth_app_name: str | None = None
    remediation_actions: list[str] = Field(default_factory=list)
    external_action_status: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = False


class MicrosoftCopilotStudioEventRequest(BaseModel):
    user_id: str | None = None
    entra_user_id: str | None = None
    user_principal_name: str | None = None
    agent_id: str | None = None
    device_id: str | None = None
    endpoint_id: str | None = None
    correlation_id: str | None = None
    timestamp: datetime | None = None
    event_type: str = "copilot_studio.agent_action"
    action_type: str = "connector_action"
    prompt_or_content: str | None = None
    environment_id: str | None = None
    agent_name: str | None = None
    connector_name: str | None = None
    connector_names: list[str] = Field(default_factory=list)
    oauth_scopes: list[str] = Field(default_factory=list)
    agent_owner: str | None = None
    publisher: str | None = None
    oauth_app_id: str | None = None
    oauth_app_name: str | None = None
    permission_scopes: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    sensitivity_label: str | None = None
    remediation_actions: list[str] = Field(default_factory=list)
    external_action_status: str | None = None
    api_endpoint: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    gateway_routed: bool = False


class UnifiedSurfaceEventResponse(BaseModel):
    user_id: str | None = None
    app: str
    application_key: str | None = None
    device_id: str | None = None
    prompt_or_content: str | None = None
    content_preview: str | None = None
    sensitivity_score: float
    ai_usage_detected: bool
    policy_triggered: str | None = None
    decision: str
    timestamp: str
    surface: str
    runtime_event_id: str | None = None
    audit_action_id: str | None = None
    alert_id: str | None = None
    control_ids: list[str] = Field(default_factory=list)
    enforcement_path: str
    gateway_routed: bool = False
    gateway_bypass_detected: bool = False
    trace_url: str | None = None
    remediation_suggestion: str | None = None
    session_id: str | None = None
    endpoint_id: str | None = None


class UnifiedSurfaceBatchResponse(BaseModel):
    total: int
    processed: int
    blocked: int
    warned: int
    allowed: int
    items: list[UnifiedSurfaceEventResponse]


class MicrosoftFoundrySyncResponse(BaseModel):
    status: str
    source: str
    sync_id: str
    control_capability: str
    control_mode: str
    pulled: dict[str, int]
    ingested_events: int
    runtime_event_ids: list[str]
    errors: list[str] = Field(default_factory=list)
    connector_diagnostics: dict[str, Any] = Field(default_factory=dict)


class MicrosoftCopilotSyncResponse(BaseModel):
    status: str
    source: str
    sync_id: str
    control_capability: str
    control_mode: str
    pulled: dict[str, int]
    ingested_events: int
    runtime_event_ids: list[str]
    errors: list[str] = Field(default_factory=list)
    connector_diagnostics: dict[str, Any] = Field(default_factory=dict)


class EndpointHeartbeatResponse(BaseModel):
    processed: int
    device_id: str
    items: list[UnifiedSurfaceEventResponse]


class UnifiedIdentityViewResponse(BaseModel):
    identity: dict[str, Any]
    timeline: dict[str, Any]
    graph: dict[str, Any]


class UnifiedAlertResponse(BaseModel):
    alert_id: str
    action_id: str
    user_id: str | None = None
    device_id: str | None = None
    app: str | None = None
    surface: str | None = None
    severity: str
    alert_type: str
    policy_reason: str | None = None
    source: str | None = None
    decision: str
    timestamp: str | None = None
    prompt_preview_redacted: str | None = None


class UnifiedAlertListResponse(BaseModel):
    items: list[UnifiedAlertResponse]
    total: int
    page: int
    page_size: int


class UnifiedAlertTraceResponse(BaseModel):
    alert: dict[str, Any]
    trace: dict[str, Any]


def _paginate(items: list[dict[str, Any]], *, page: int, page_size: int) -> tuple[list[dict[str, Any]], int, int, int]:
    safe_page = max(1, int(page or 1))
    safe_page_size = max(1, min(200, int(page_size or 50)))
    total = len(items)
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    return items[start:end], total, safe_page, safe_page_size


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _foundry_items(inventory: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = inventory.get(key)
    if isinstance(value, dict):
        for nested_key in ("value", "items", "data", "records"):
            nested = value.get(nested_key)
            if isinstance(nested, list):
                value = nested
                break
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _foundry_first(*values: Any) -> str:
    for value in values:
        token = _safe_str(value)
        if token:
            return token
    return ""


def _foundry_record_id(record: dict[str, Any]) -> str:
    return _foundry_first(record.get("id"), record.get("name"), record.get("displayName"), record.get("appId"))


def _foundry_record_name(record: dict[str, Any]) -> str:
    return _foundry_first(record.get("name"), record.get("displayName"), record.get("id"), record.get("appId"))


def _foundry_record_hash(record: dict[str, Any]) -> str:
    safe_record = {
        key: value
        for key, value in record.items()
        if key.lower()
        not in {
            "access_token",
            "authorization",
            "bearer",
            "key",
            "api_key",
            "apikey",
            "secret",
            "password",
            "credential",
            "connectionstring",
            "connection_string",
        }
    }
    encoded = json.dumps(safe_record, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _foundry_record_summary(record: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "id",
        "name",
        "displayName",
        "type",
        "kind",
        "model",
        "version",
        "project_id",
        "projectId",
        "workspace_id",
        "workspaceId",
        "subscription_id",
        "subscriptionId",
        "resource_group",
        "resourceGroup",
        "appId",
    }
    return {key: record.get(key) for key in allowed_keys if record.get(key) is not None}


def _foundry_tool_names(agent: dict[str, Any], inventory: dict[str, Any]) -> list[str]:
    names: list[str] = []
    raw_tools = agent.get("tools") if isinstance(agent.get("tools"), list) else []
    for item in raw_tools:
        if isinstance(item, dict):
            name = _foundry_record_name(item)
        else:
            name = _safe_str(item)
        if name:
            names.append(name)
    for item in _foundry_items(inventory, "tools"):
        agent_id = _safe_str(item.get("agent_id") or item.get("agentId"))
        if agent_id and agent_id != _foundry_record_id(agent):
            continue
        name = _foundry_record_name(item)
        if name:
            names.append(name)
    return list(dict.fromkeys(names))


def _foundry_data_source_ids(agent: dict[str, Any], inventory: dict[str, Any]) -> list[str]:
    ids: list[str] = []
    raw_sources = agent.get("data_sources") if isinstance(agent.get("data_sources"), list) else []
    for item in raw_sources:
        if isinstance(item, dict):
            value = _foundry_record_id(item)
        else:
            value = _safe_str(item)
        if value:
            ids.append(value)
    for item in _foundry_items(inventory, "data_sources"):
        agent_id = _safe_str(item.get("agent_id") or item.get("agentId"))
        if agent_id and agent_id != _foundry_record_id(agent):
            continue
        value = _foundry_record_id(item)
        if value:
            ids.append(value)
    return list(dict.fromkeys(ids))


_MICROSOFT_TRANSIENT_STATUS_CODES = {429, 500, 502, 503, 504}
_CONNECTOR_DIAGNOSTICS_KEY = "_connector_diagnostics"
_MICROSOFT_CONNECTOR_HOSTS = {
    "ai.azure.com",
    "api.powerplatform.com",
    "graph.microsoft.com",
    "management.azure.com",
}
_MICROSOFT_CONNECTOR_HOST_SUFFIXES = (
    ".api.azureml.ms",
    ".api.powerplatform.com",
    ".openai.azure.com",
    ".services.ai.azure.com",
)


def _is_loopback_host(hostname: str | None) -> bool:
    host = _safe_str(hostname).lower().strip("[]")
    return host in {"localhost", "127.0.0.1", "::1"}


def _validate_microsoft_connector_endpoint(endpoint: str, *, allow_insecure_local_http: bool) -> None:
    parsed = urlparse(endpoint)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid Microsoft connector endpoint: {endpoint}",
        )
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Microsoft live connector endpoints cannot contain embedded credentials",
        )
    host = _safe_str(parsed.hostname).lower().rstrip(".")
    if parsed.scheme == "https" and (
        host in _MICROSOFT_CONNECTOR_HOSTS
        or any(host.endswith(suffix) for suffix in _MICROSOFT_CONNECTOR_HOST_SUFFIXES)
    ):
        return
    if parsed.scheme == "http" and allow_insecure_local_http and _is_loopback_host(parsed.hostname):
        return
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail=(
            "Microsoft live connector endpoints must use HTTPS on an approved Microsoft or Azure origin; "
            "localhost HTTP is allowed only when allow_insecure_local_http is set for testing"
        ),
    )


def _connector_items_from_body(body: Any, *, key: str) -> list[Any]:
    if isinstance(body, list):
        return body
    if not isinstance(body, dict):
        return []
    raw = body.get("value")
    if raw is None:
        raw = body.get("items")
    if raw is None:
        raw = body.get(key)
    if raw is None:
        return []
    return raw if isinstance(raw, list) else [raw]


def _connector_next_link(body: Any) -> str | None:
    if not isinstance(body, dict):
        return None
    for key in ("@odata.nextLink", "nextLink", "next", "continuationLink"):
        value = _safe_str(body.get(key))
        if value:
            return value
    return None


def _connector_retry_delay_seconds(response: Any) -> float:
    headers = getattr(response, "headers", {}) or {}
    retry_after = _safe_str(headers.get("Retry-After") if hasattr(headers, "get") else None)
    try:
        return min(max(float(retry_after), 0.0), 0.2)
    except ValueError:
        return 0.05


def _microsoft_connector_pull_collection(
    client: httpx.Client,
    *,
    endpoint: str,
    headers: dict[str, str],
    key: str,
    max_pages: int,
    max_retries: int,
    allow_insecure_local_http: bool,
    diagnostics: dict[str, Any],
) -> list[Any]:
    _validate_microsoft_connector_endpoint(endpoint, allow_insecure_local_http=allow_insecure_local_http)
    page_url: str | None = endpoint
    pages_fetched = 0
    collected: list[Any] = []
    endpoint_stats = diagnostics.setdefault("endpoints", {})
    endpoint_stats[key] = {
        "requested": True,
        "pages_fetched": 0,
        "items_pulled": 0,
        "retries": 0,
        "rate_limited": False,
        "truncated": False,
    }

    while page_url and pages_fetched < max_pages:
        _validate_microsoft_connector_endpoint(
            page_url,
            allow_insecure_local_http=allow_insecure_local_http,
        )
        response = None
        for attempt in range(max_retries + 1):
            response = client.get(page_url, headers=headers)
            status_code = int(getattr(response, "status_code", 200) or 200)
            if status_code not in _MICROSOFT_TRANSIENT_STATUS_CODES or attempt >= max_retries:
                break
            endpoint_stats[key]["retries"] += 1
            diagnostics["retry_count"] = int(diagnostics.get("retry_count") or 0) + 1
            if status_code == 429:
                endpoint_stats[key]["rate_limited"] = True
                diagnostics["rate_limited"] = True
            sleep(_connector_retry_delay_seconds(response))
        if response is None:
            break
        response.raise_for_status()
        body = response.json()
        pages_fetched += 1
        endpoint_stats[key]["pages_fetched"] = pages_fetched
        collected.extend(_connector_items_from_body(body, key=key))
        page_url = _connector_next_link(body)

    if page_url:
        endpoint_stats[key]["truncated"] = True
        diagnostics["pagination_truncated"] = True
    endpoint_stats[key]["items_pulled"] = len(collected)
    diagnostics["pages_fetched"] = int(diagnostics.get("pages_fetched") or 0) + pages_fetched
    return collected


def _connector_diagnostics(inventory: dict[str, Any]) -> dict[str, Any]:
    raw = inventory.get(_CONNECTOR_DIAGNOSTICS_KEY)
    return raw if isinstance(raw, dict) else {}


def _foundry_endpoint(payload: MicrosoftFoundrySyncRequest, key: str) -> str | None:
    explicit = _safe_str((payload.endpoints or {}).get(key))
    if explicit:
        return explicit
    base = _safe_str(payload.project_endpoint).rstrip("/")
    if not base:
        return None
    suffix_by_key = {
        "projects": "/projects",
        "agents": "/agents",
        "deployments": "/deployments",
        "models": "/models",
        "service_principals": "/servicePrincipals",
        "tools": "/tools",
        "data_sources": "/dataSources",
    }
    suffix = suffix_by_key.get(key)
    if not suffix:
        return None
    separator = "&" if "?" in base else "?"
    return f"{base}{suffix}{separator}api-version={payload.api_version}"


def _pull_foundry_inventory(payload: MicrosoftFoundrySyncRequest) -> dict[str, Any]:
    if payload.inventory:
        inventory = dict(payload.inventory)
        inventory[_CONNECTOR_DIAGNOSTICS_KEY] = {
            "mode": "provided_inventory",
            "endpoint_validation": "not_applicable",
            "pages_fetched": 0,
            "retry_count": 0,
            "rate_limited": False,
        }
        return inventory
    if not _safe_str(payload.access_token):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="access_token or inventory is required for Foundry sync",
        )
    inventory: dict[str, Any] = {}
    diagnostics: dict[str, Any] = {
        "mode": "live_pull",
        "endpoint_validation": "https_required",
        "pages_fetched": 0,
        "retry_count": 0,
        "rate_limited": False,
        "pagination_truncated": False,
    }
    headers = {"Authorization": f"Bearer {_safe_str(payload.access_token)}"}
    keys = ("projects", "agents", "deployments", "models", "service_principals", "tools", "data_sources")
    try:
        with httpx.Client(timeout=float(payload.timeout_seconds or 10.0)) as client:
            for key in keys:
                endpoint = _foundry_endpoint(payload, key)
                if not endpoint:
                    inventory[key] = []
                    continue
                inventory[key] = _microsoft_connector_pull_collection(
                    client,
                    endpoint=endpoint,
                    headers=headers,
                    key=key,
                    max_pages=int(payload.max_pages_per_endpoint or 10),
                    max_retries=int(payload.max_retries or 0),
                    allow_insecure_local_http=bool(payload.allow_insecure_local_http),
                    diagnostics=diagnostics,
                )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Azure Foundry inventory pull failed: {exc}",
        ) from exc
    inventory[_CONNECTOR_DIAGNOSTICS_KEY] = diagnostics
    return inventory


def _foundry_inventory_counts(inventory: dict[str, Any]) -> dict[str, int]:
    projects = _foundry_items(inventory, "projects")
    agents = _foundry_items(inventory, "agents")
    deployments = _foundry_items(inventory, "deployments")
    models = _foundry_items(inventory, "models")
    service_principals = _foundry_items(inventory, "service_principals")
    tools = set()
    data_sources = set()
    for item in _foundry_items(inventory, "tools"):
        name = _foundry_record_name(item)
        if name:
            tools.add(name)
    for item in _foundry_items(inventory, "data_sources"):
        value = _foundry_record_id(item)
        if value:
            data_sources.add(value)
    for agent in agents:
        tools.update(_foundry_tool_names(agent, inventory))
        data_sources.update(_foundry_data_source_ids(agent, inventory))
    return {
        "projects": len(projects),
        "agents": len(agents),
        "deployments": len(deployments),
        "models": len(models),
        "service_principals": len(service_principals),
        "tools": len(tools),
        "data_sources": len(data_sources),
    }


def _foundry_inventory_to_events(
    payload: MicrosoftFoundrySyncRequest,
    inventory: dict[str, Any],
    *,
    sync_id: str,
) -> list[MicrosoftFoundryEventRequest]:
    routed_agent_ids = {_safe_str(item) for item in list(payload.gateway_routed_agent_ids or []) if _safe_str(item)}
    projects_by_id = {_foundry_record_id(project): project for project in _foundry_items(inventory, "projects")}
    deployments = _foundry_items(inventory, "deployments")
    deployments_by_project: dict[str, dict[str, Any]] = {}
    for deployment in deployments:
        project_id = _foundry_first(deployment.get("project_id"), deployment.get("projectId"))
        if project_id and project_id not in deployments_by_project:
            deployments_by_project[project_id] = deployment
    events: list[MicrosoftFoundryEventRequest] = []

    def inventory_metadata(record: dict[str, Any], object_type: str, *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        return {
            "source": "microsoft_foundry",
            "inventory_source": "azure_foundry_live_connector",
            "inventory_object_type": object_type,
            "sync_id": sync_id,
            "inventory_record_id": _foundry_record_id(record) or None,
            "inventory_record_name": _foundry_record_name(record) or None,
            "inventory_record_hash": _foundry_record_hash(record),
            "inventory_record_summary": _foundry_record_summary(record),
            "control_mode_hint": "telemetry_only",
            **(extra or {}),
        }

    for project in _foundry_items(inventory, "projects"):
        project_id = _foundry_record_id(project)
        events.append(
            MicrosoftFoundryEventRequest(
                event_type="foundry.inventory.project",
                action_type="foundry_project_inventory",
                prompt_or_content="Azure Foundry project inventory sync",
                project_id=project_id or None,
                project_name=_foundry_record_name(project) or None,
                workspace_id=_foundry_first(project.get("workspace_id"), project.get("workspaceId"), payload.workspace_id) or None,
                subscription_id=_foundry_first(
                    project.get("subscription_id"),
                    project.get("subscriptionId"),
                    payload.subscription_id,
                )
                or None,
                resource_group=_foundry_first(project.get("resource_group"), project.get("resourceGroup"), payload.resource_group)
                or None,
                api_endpoint=_safe_str(payload.project_endpoint) or None,
                metadata=inventory_metadata(project, "project"),
                gateway_routed=False,
            )
        )
    for agent in _foundry_items(inventory, "agents"):
        agent_id = _foundry_record_id(agent)
        project_id = _foundry_first(agent.get("project_id"), agent.get("projectId"))
        project = projects_by_id.get(project_id, {})
        deployment = deployments_by_project.get(project_id, {})
        gateway_routed = agent_id in routed_agent_ids
        service_principal_id = _foundry_first(
            agent.get("service_principal_id"),
            agent.get("servicePrincipalId"),
            agent.get("servicePrincipal"),
        )
        managed_identity_id = _foundry_first(agent.get("managed_identity_id"), agent.get("managedIdentityId"))
        entra_app_id = _foundry_first(agent.get("entra_app_id"), agent.get("entraAppId"), agent.get("appId"))
        tool_names = _foundry_tool_names(agent, inventory)
        data_source_ids = _foundry_data_source_ids(agent, inventory)
        events.append(
            MicrosoftFoundryEventRequest(
                event_type="foundry.inventory.agent",
                action_type="foundry_agent_inventory",
                prompt_or_content="Azure Foundry agent inventory sync",
                agent_id=agent_id or None,
                agent_name=_foundry_record_name(agent) or None,
                project_id=project_id or _foundry_record_id(project) or None,
                project_name=_foundry_record_name(project) or None,
                workspace_id=_foundry_first(
                    agent.get("workspace_id"),
                    agent.get("workspaceId"),
                    project.get("workspace_id"),
                    project.get("workspaceId"),
                    payload.workspace_id,
                )
                or None,
                subscription_id=_foundry_first(
                    agent.get("subscription_id"),
                    agent.get("subscriptionId"),
                    project.get("subscription_id"),
                    project.get("subscriptionId"),
                    payload.subscription_id,
                )
                or None,
                resource_group=_foundry_first(
                    agent.get("resource_group"),
                    agent.get("resourceGroup"),
                    project.get("resource_group"),
                    project.get("resourceGroup"),
                    payload.resource_group,
                )
                or None,
                model=_foundry_first(agent.get("model"), deployment.get("model")) or None,
                model_version=_foundry_first(agent.get("model_version"), agent.get("modelVersion"), deployment.get("version"))
                or None,
                model_deployment=_foundry_first(
                    agent.get("model_deployment"),
                    agent.get("modelDeployment"),
                    deployment.get("name"),
                )
                or None,
                model_deployment_id=_foundry_first(
                    agent.get("model_deployment_id"),
                    agent.get("modelDeploymentId"),
                    deployment.get("id"),
                )
                or None,
                tool=tool_names[0] if tool_names else None,
                tool_names=tool_names,
                data_source=data_source_ids[0] if data_source_ids else None,
                data_source_ids=data_source_ids,
                api_endpoint=_safe_str(payload.project_endpoint) or None,
                service_principal_id=service_principal_id or None,
                managed_identity_id=managed_identity_id or None,
                entra_app_id=entra_app_id or None,
                metadata={
                    **inventory_metadata(agent, "agent"),
                    "deployment_record_hash": _foundry_record_hash(deployment) if deployment else None,
                    "control_mode_hint": "inline_candidate" if gateway_routed else "telemetry_only",
                },
                gateway_routed=gateway_routed,
            )
        )
    for deployment in deployments:
        project_id = _foundry_first(deployment.get("project_id"), deployment.get("projectId"))
        project = projects_by_id.get(project_id, {})
        deployment_id = _foundry_record_id(deployment)
        events.append(
            MicrosoftFoundryEventRequest(
                event_type="foundry.inventory.deployment",
                action_type="foundry_model_deployment_inventory",
                prompt_or_content="Azure Foundry model deployment inventory sync",
                project_id=project_id or _foundry_record_id(project) or None,
                project_name=_foundry_record_name(project) or None,
                workspace_id=_foundry_first(
                    deployment.get("workspace_id"),
                    deployment.get("workspaceId"),
                    project.get("workspace_id"),
                    project.get("workspaceId"),
                    payload.workspace_id,
                )
                or None,
                subscription_id=_foundry_first(
                    deployment.get("subscription_id"),
                    deployment.get("subscriptionId"),
                    project.get("subscription_id"),
                    project.get("subscriptionId"),
                    payload.subscription_id,
                )
                or None,
                resource_group=_foundry_first(
                    deployment.get("resource_group"),
                    deployment.get("resourceGroup"),
                    project.get("resource_group"),
                    project.get("resourceGroup"),
                    payload.resource_group,
                )
                or None,
                model=_foundry_first(deployment.get("model"), deployment.get("modelName")) or None,
                model_version=_foundry_first(deployment.get("version"), deployment.get("model_version"), deployment.get("modelVersion"))
                or None,
                model_deployment=_foundry_record_name(deployment) or None,
                model_deployment_id=deployment_id or None,
                agent_id=_foundry_first(deployment.get("agent_id"), deployment.get("agentId")) or None,
                api_endpoint=_safe_str(payload.project_endpoint) or None,
                metadata=inventory_metadata(
                    deployment,
                    "deployment",
                    extra={
                        "foundry_project_id": project_id or None,
                        "model_deployment_id": deployment_id or None,
                    },
                ),
                gateway_routed=False,
            )
        )
    for model in _foundry_items(inventory, "models"):
        model_id = _foundry_record_id(model)
        events.append(
            MicrosoftFoundryEventRequest(
                event_type="foundry.inventory.model",
                action_type="foundry_model_inventory",
                prompt_or_content="Azure Foundry model inventory sync",
                model=_foundry_record_name(model) or None,
                model_version=_foundry_first(model.get("version"), model.get("model_version"), model.get("modelVersion")) or None,
                api_endpoint=_safe_str(payload.project_endpoint) or None,
                metadata=inventory_metadata(
                    model,
                    "model",
                    extra={
                        "model_id": model_id or None,
                        "model_provider": _foundry_first(model.get("provider"), model.get("publisher")) or None,
                    },
                ),
                gateway_routed=False,
            )
        )
    for service_principal in _foundry_items(inventory, "service_principals"):
        service_principal_id = _foundry_record_id(service_principal)
        entra_app_id = _foundry_first(
            service_principal.get("appId"),
            service_principal.get("app_id"),
            service_principal.get("entra_app_id"),
            service_principal.get("entraAppId"),
        )
        events.append(
            MicrosoftFoundryEventRequest(
                event_type="foundry.inventory.service_principal",
                action_type="foundry_service_principal_inventory",
                prompt_or_content="Azure Foundry service principal inventory sync",
                service_principal_id=service_principal_id or None,
                entra_app_id=entra_app_id or None,
                agent_id=_foundry_first(service_principal.get("agent_id"), service_principal.get("agentId")) or None,
                api_endpoint=_safe_str(payload.project_endpoint) or None,
                metadata=inventory_metadata(
                    service_principal,
                    "service_principal",
                    extra={
                        "service_principal_id": service_principal_id or None,
                        "entra_app_id": entra_app_id or None,
                        "service_principal_name": _foundry_record_name(service_principal) or None,
                    },
                ),
                gateway_routed=False,
            )
        )
    for tool in _foundry_items(inventory, "tools"):
        tool_name = _foundry_record_name(tool)
        events.append(
            MicrosoftFoundryEventRequest(
                event_type="foundry.inventory.tool",
                action_type="foundry_tool_inventory",
                prompt_or_content="Azure Foundry tool inventory sync",
                agent_id=_foundry_first(tool.get("agent_id"), tool.get("agentId")) or None,
                tool=tool_name or None,
                tool_names=[tool_name] if tool_name else [],
                api_endpoint=_safe_str(payload.project_endpoint) or None,
                metadata=inventory_metadata(
                    tool,
                    "tool",
                    extra={
                        "tool_id": _foundry_record_id(tool) or None,
                        "tool_name": tool_name or None,
                        "tool_type": _foundry_first(tool.get("type"), tool.get("kind")) or None,
                    },
                ),
                gateway_routed=False,
            )
        )
    for data_source in _foundry_items(inventory, "data_sources"):
        data_source_id = _foundry_record_id(data_source)
        events.append(
            MicrosoftFoundryEventRequest(
                event_type="foundry.inventory.data_source",
                action_type="foundry_data_source_inventory",
                prompt_or_content="Azure Foundry data source inventory sync",
                agent_id=_foundry_first(data_source.get("agent_id"), data_source.get("agentId")) or None,
                data_source=data_source_id or None,
                data_source_ids=[data_source_id] if data_source_id else [],
                api_endpoint=_safe_str(payload.project_endpoint) or None,
                metadata=inventory_metadata(
                    data_source,
                    "data_source",
                    extra={
                        "data_source_id": data_source_id or None,
                        "data_source_name": _foundry_record_name(data_source) or None,
                        "data_source_type": _foundry_first(data_source.get("type"), data_source.get("kind")) or None,
                    },
                ),
                gateway_routed=False,
            )
        )
    return events


_COPILOT_INVENTORY_KEYS = (
    "m365_activity",
    "copilot_studio_agents",
    "connectors",
    "oauth_apps",
    "purview_signals",
    "graph_permissions",
    "remediation_hooks",
)


def _copilot_endpoint(payload: MicrosoftCopilotSyncRequest, key: str) -> str | None:
    explicit = _safe_str((payload.endpoints or {}).get(key))
    if explicit:
        return explicit
    graph_base = _safe_str(payload.tenant_graph_endpoint).rstrip("/")
    studio_base = _safe_str(payload.copilot_studio_endpoint).rstrip("/")
    endpoint_map = {
        "m365_activity": (graph_base, "/copilot/activity"),
        "purview_signals": (graph_base, "/security/informationProtection/sensitivityLabels"),
        "graph_permissions": (graph_base, "/servicePrincipals"),
        "oauth_apps": (graph_base, "/servicePrincipals"),
        "remediation_hooks": (graph_base, "/security/copilot/remediationHooks"),
        "copilot_studio_agents": (studio_base, "/agents"),
        "connectors": (studio_base, "/connectors"),
    }
    base, suffix = endpoint_map.get(key, ("", ""))
    if not base:
        return None
    return f"{base}{suffix}"


def _pull_copilot_inventory(payload: MicrosoftCopilotSyncRequest) -> dict[str, Any]:
    if payload.inventory:
        inventory = dict(payload.inventory)
        inventory[_CONNECTOR_DIAGNOSTICS_KEY] = {
            "mode": "provided_inventory",
            "endpoint_validation": "not_applicable",
            "pages_fetched": 0,
            "retry_count": 0,
            "rate_limited": False,
        }
        return inventory
    if not _safe_str(payload.access_token):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="access_token or inventory is required for Copilot sync",
        )
    inventory: dict[str, Any] = {}
    diagnostics: dict[str, Any] = {
        "mode": "live_pull",
        "endpoint_validation": "https_required",
        "pages_fetched": 0,
        "retry_count": 0,
        "rate_limited": False,
        "pagination_truncated": False,
    }
    headers = {"Authorization": f"Bearer {_safe_str(payload.access_token)}"}
    try:
        with httpx.Client(timeout=float(payload.timeout_seconds or 10.0)) as client:
            for key in _COPILOT_INVENTORY_KEYS:
                endpoint = _copilot_endpoint(payload, key)
                if not endpoint:
                    inventory[key] = []
                    continue
                inventory[key] = _microsoft_connector_pull_collection(
                    client,
                    endpoint=endpoint,
                    headers=headers,
                    key=key,
                    max_pages=int(payload.max_pages_per_endpoint or 10),
                    max_retries=int(payload.max_retries or 0),
                    allow_insecure_local_http=bool(payload.allow_insecure_local_http),
                    diagnostics=diagnostics,
                )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Microsoft Copilot inventory pull failed: {exc}",
        ) from exc
    inventory[_CONNECTOR_DIAGNOSTICS_KEY] = diagnostics
    return inventory


def _copilot_inventory_counts(inventory: dict[str, Any]) -> dict[str, int]:
    return {key: len(_foundry_items(inventory, key)) for key in _COPILOT_INVENTORY_KEYS}


def _copilot_values(*values: Any) -> list[str]:
    collected: list[str] = []
    for value in values:
        if isinstance(value, list):
            raw_values = value
        elif value is None:
            raw_values = []
        else:
            raw_values = [value]
        for item in raw_values:
            token = _foundry_record_name(item) if isinstance(item, dict) else _safe_str(item)
            if token and token not in collected:
                collected.append(token)
        if collected:
            return collected
    return collected


def _copilot_external_status(*values: Any) -> str:
    for value in values:
        status_token = _safe_str(value).lower()
        if not status_token:
            continue
        if status_token in {"external_action_triggered", "triggered", "completed", "complete", "success", "succeeded"}:
            return "external_action_triggered"
        if status_token in {"external_required", "required", "pending", "review", "approval_required"}:
            return "external_required"
        return status_token
    return "external_required"


def _copilot_truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return _safe_str(value).lower() in {"1", "true", "yes", "y", "required"}


def _copilot_inventory_to_events(
    payload: MicrosoftCopilotSyncRequest,
    inventory: dict[str, Any],
    *,
    sync_id: str,
) -> list[MicrosoftCopilotEventRequest | MicrosoftCopilotStudioEventRequest]:
    routed_agent_ids = {_safe_str(item) for item in list(payload.gateway_routed_agent_ids or []) if _safe_str(item)}
    events: list[MicrosoftCopilotEventRequest | MicrosoftCopilotStudioEventRequest] = []

    def inventory_metadata(
        record: dict[str, Any],
        object_type: str,
        *,
        control_mode_hint: str = "telemetry_only",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "source": "microsoft_copilot_live",
            "inventory_source": "microsoft_copilot_live_connector",
            "inventory_object_type": object_type,
            "sync_id": sync_id,
            "inventory_record_id": _foundry_record_id(record) or None,
            "inventory_record_name": _foundry_record_name(record) or None,
            "inventory_record_hash": _foundry_record_hash(record),
            "inventory_record_summary": _foundry_record_summary(record),
            "control_mode_hint": control_mode_hint,
            **(extra or {}),
        }

    for activity in _foundry_items(inventory, "m365_activity"):
        events.append(
            MicrosoftCopilotEventRequest(
                user_id=_foundry_first(activity.get("user_id"), activity.get("userId")) or None,
                entra_user_id=_foundry_first(activity.get("entra_user_id"), activity.get("entraUserId")) or None,
                user_principal_name=_foundry_first(
                    activity.get("user_principal_name"),
                    activity.get("userPrincipalName"),
                    activity.get("user"),
                )
                or None,
                correlation_id=_foundry_record_id(activity) or None,
                event_type="copilot.inventory.activity",
                action_type=_foundry_first(activity.get("action_type"), activity.get("activityType"), "copilot_activity_inventory"),
                prompt_or_content=_foundry_first(
                    activity.get("prompt"),
                    activity.get("content"),
                    activity.get("summary"),
                    "Microsoft 365 Copilot activity inventory sync",
                )
                or None,
                workload=_foundry_first(activity.get("workload"), activity.get("source_app"), activity.get("sourceApp")) or None,
                source_app=_foundry_first(activity.get("source_app"), activity.get("sourceApp"), activity.get("workload")) or None,
                sensitivity_label=_foundry_first(activity.get("sensitivity_label"), activity.get("sensitivityLabel")) or None,
                knowledge_asset_ids=_copilot_values(activity.get("knowledge_asset_ids"), activity.get("knowledgeAssetIds")),
                data_sources=_copilot_values(activity.get("data_sources"), activity.get("dataSources")),
                permission_scopes=_copilot_values(activity.get("permission_scopes"), activity.get("permissionScopes")),
                oauth_app_id=_foundry_first(activity.get("oauth_app_id"), activity.get("oauthAppId"), activity.get("appId")) or None,
                oauth_app_name=_foundry_first(activity.get("oauth_app_name"), activity.get("oauthAppName"), activity.get("appDisplayName"))
                or None,
                remediation_actions=_copilot_values(activity.get("remediation_actions"), activity.get("remediationActions")),
                external_action_status=_foundry_first(activity.get("external_action_status"), activity.get("externalActionStatus"))
                or None,
                metadata=inventory_metadata(activity, "m365_activity"),
                gateway_routed=False,
            )
        )

    for agent in _foundry_items(inventory, "copilot_studio_agents"):
        agent_id = _foundry_record_id(agent)
        control_mode_hint = "inline_candidate" if agent_id in routed_agent_ids else "telemetry_only"
        connector_names = _copilot_values(agent.get("connector_names"), agent.get("connectorNames"), agent.get("connectors"))
        data_sources = _copilot_values(agent.get("data_sources"), agent.get("dataSources"))
        oauth_scopes = _copilot_values(agent.get("oauth_scopes"), agent.get("oauthScopes"), agent.get("permission_scopes"))
        oauth_app_id = _foundry_first(agent.get("oauth_app_id"), agent.get("oauthAppId"), agent.get("appId"))
        events.append(
            MicrosoftCopilotStudioEventRequest(
                agent_id=agent_id or None,
                event_type="copilot.inventory.studio_agent",
                action_type="copilot_studio_agent_inventory",
                prompt_or_content="Copilot Studio agent inventory sync",
                environment_id=_foundry_first(agent.get("environment_id"), agent.get("environmentId")) or None,
                agent_name=_foundry_record_name(agent) or None,
                connector_name=connector_names[0] if connector_names else None,
                connector_names=connector_names,
                oauth_scopes=oauth_scopes,
                agent_owner=_foundry_first(agent.get("owner"), agent.get("agent_owner"), agent.get("agentOwner")) or None,
                publisher=_foundry_first(agent.get("publisher"), agent.get("publisherName")) or None,
                oauth_app_id=oauth_app_id or None,
                oauth_app_name=_foundry_first(agent.get("oauth_app_name"), agent.get("oauthAppName"), agent.get("appDisplayName"))
                or None,
                permission_scopes=_copilot_values(agent.get("permission_scopes"), agent.get("permissionScopes"), oauth_scopes),
                data_sources=data_sources,
                sensitivity_label=_foundry_first(agent.get("sensitivity_label"), agent.get("sensitivityLabel")) or None,
                remediation_actions=_copilot_values(agent.get("remediation_actions"), agent.get("remediationActions")),
                external_action_status=_foundry_first(agent.get("external_action_status"), agent.get("externalActionStatus"))
                or None,
                api_endpoint=_safe_str(payload.copilot_studio_endpoint) or None,
                metadata=inventory_metadata(
                    agent,
                    "copilot_studio_agent",
                    control_mode_hint=control_mode_hint,
                    extra={
                        "tool_names": connector_names,
                        "data_source_ids": data_sources,
                        "service_principal_id": oauth_app_id or None,
                        "entra_app_id": oauth_app_id or None,
                    },
                ),
                gateway_routed=agent_id in routed_agent_ids,
            )
        )

    for connector in _foundry_items(inventory, "connectors"):
        connector_name = _foundry_record_name(connector)
        agent_id = _foundry_first(connector.get("agent_id"), connector.get("agentId"))
        control_mode_hint = "inline_candidate" if agent_id in routed_agent_ids else "telemetry_only"
        data_sources = _copilot_values(connector.get("data_sources"), connector.get("dataSources"))
        oauth_scopes = _copilot_values(connector.get("oauth_scopes"), connector.get("oauthScopes"), connector.get("permission_scopes"))
        events.append(
            MicrosoftCopilotStudioEventRequest(
                agent_id=agent_id or None,
                event_type="copilot.inventory.connector",
                action_type="copilot_connector_inventory",
                prompt_or_content="Copilot Studio connector inventory sync",
                connector_name=connector_name or None,
                connector_names=[connector_name] if connector_name else [],
                oauth_scopes=oauth_scopes,
                permission_scopes=oauth_scopes,
                data_sources=data_sources,
                metadata=inventory_metadata(
                    connector,
                    "connector",
                    control_mode_hint=control_mode_hint,
                    extra={"tool_names": [connector_name] if connector_name else [], "data_source_ids": data_sources},
                ),
                gateway_routed=agent_id in routed_agent_ids,
            )
        )

    for app in _foundry_items(inventory, "oauth_apps"):
        app_id = _foundry_record_id(app)
        agent_id = _foundry_first(app.get("agent_id"), app.get("agentId"))
        scopes = _copilot_values(app.get("permission_scopes"), app.get("permissionScopes"), app.get("oauth_scopes"))
        metadata = inventory_metadata(
            app,
            "oauth_app",
            control_mode_hint="inline_candidate" if agent_id in routed_agent_ids else "telemetry_only",
            extra={"service_principal_id": app_id or None, "entra_app_id": app_id or None, "oauth_app_id": app_id or None},
        )
        if agent_id:
            events.append(
                MicrosoftCopilotStudioEventRequest(
                    agent_id=agent_id,
                    event_type="copilot.inventory.oauth_app",
                    action_type="copilot_oauth_app_inventory",
                    prompt_or_content="Copilot Studio OAuth app inventory sync",
                    oauth_app_id=app_id or None,
                    oauth_app_name=_foundry_record_name(app) or None,
                    permission_scopes=scopes,
                    remediation_actions=_copilot_values(app.get("remediation_actions"), app.get("remediationActions")),
                    external_action_status=_foundry_first(app.get("external_action_status"), app.get("externalActionStatus"))
                    or None,
                    metadata=metadata,
                    gateway_routed=agent_id in routed_agent_ids,
                )
            )
        else:
            events.append(
                MicrosoftCopilotEventRequest(
                    event_type="copilot.inventory.oauth_app",
                    action_type="copilot_oauth_app_inventory",
                    prompt_or_content="Microsoft Copilot OAuth app inventory sync",
                    oauth_app_id=app_id or None,
                    oauth_app_name=_foundry_record_name(app) or None,
                    permission_scopes=scopes,
                    remediation_actions=_copilot_values(app.get("remediation_actions"), app.get("remediationActions")),
                    external_action_status=_foundry_first(app.get("external_action_status"), app.get("externalActionStatus"))
                    or None,
                    metadata=metadata,
                    gateway_routed=False,
                )
            )

    for signal in _foundry_items(inventory, "purview_signals"):
        events.append(
            MicrosoftCopilotEventRequest(
                user_id=_foundry_first(signal.get("user_id"), signal.get("userId")) or None,
                user_principal_name=_foundry_first(signal.get("user_principal_name"), signal.get("userPrincipalName")) or None,
                correlation_id=_foundry_record_id(signal) or None,
                event_type="copilot.inventory.purview_signal",
                action_type="purview_signal_inventory",
                prompt_or_content="Microsoft Purview signal inventory sync",
                workload=_foundry_first(signal.get("workload"), signal.get("source_app"), signal.get("sourceApp")) or None,
                source_app=_foundry_first(signal.get("source_app"), signal.get("sourceApp"), signal.get("workload")) or None,
                sensitivity_label=_foundry_first(signal.get("sensitivity_label"), signal.get("sensitivityLabel")) or None,
                data_sources=_copilot_values(signal.get("data_sources"), signal.get("dataSources")),
                remediation_actions=_copilot_values(signal.get("remediation_actions"), signal.get("remediationActions")),
                external_action_status=_foundry_first(
                    signal.get("external_action_status"),
                    signal.get("externalActionStatus"),
                    "external_required" if signal.get("remediation_actions") or signal.get("remediationActions") else None,
                )
                or None,
                metadata=inventory_metadata(signal, "purview_signal"),
                gateway_routed=False,
            )
        )

    for permission in _foundry_items(inventory, "graph_permissions"):
        agent_id = _foundry_first(permission.get("agent_id"), permission.get("agentId"))
        app_id = _foundry_first(permission.get("oauth_app_id"), permission.get("oauthAppId"), permission.get("appId"))
        control_mode_hint = "inline_candidate" if agent_id in routed_agent_ids else "telemetry_only"
        scopes = _copilot_values(permission.get("permission_scopes"), permission.get("permissionScopes"), permission.get("oauth_scopes"))
        events.append(
            MicrosoftCopilotStudioEventRequest(
                agent_id=agent_id or None,
                event_type="copilot.inventory.graph_permission",
                action_type="graph_permission_inventory",
                prompt_or_content="Microsoft Graph permission inventory sync",
                oauth_app_id=app_id or None,
                oauth_app_name=_foundry_first(
                    permission.get("oauth_app_name"),
                    permission.get("oauthAppName"),
                    permission.get("displayName"),
                )
                or None,
                permission_scopes=scopes,
                remediation_actions=_copilot_values(permission.get("remediation_actions"), permission.get("remediationActions")),
                external_action_status=_foundry_first(
                    permission.get("external_action_status"),
                    permission.get("externalActionStatus"),
                    "external_required" if permission.get("remediation_actions") or permission.get("remediationActions") else None,
                )
                or None,
                metadata=inventory_metadata(
                    permission,
                    "graph_permission",
                    control_mode_hint=control_mode_hint,
                    extra={"service_principal_id": app_id or None, "entra_app_id": app_id or None, "oauth_app_id": app_id or None},
                ),
                gateway_routed=agent_id in routed_agent_ids,
            )
        )

    for hook in _foundry_items(inventory, "remediation_hooks"):
        agent_id = _foundry_first(hook.get("agent_id"), hook.get("agentId"))
        app_id = _foundry_first(hook.get("oauth_app_id"), hook.get("oauthAppId"), hook.get("appId"))
        action_name = _foundry_first(
            hook.get("action"),
            hook.get("actionType"),
            hook.get("remediation_action"),
            hook.get("remediationAction"),
            _foundry_record_name(hook),
            "copilot_remediation",
        )
        external_status = _copilot_external_status(
            hook.get("external_action_status"),
            hook.get("externalActionStatus"),
            hook.get("status"),
        )
        target_type = _foundry_first(hook.get("target_type"), hook.get("targetType"))
        target_resource = _foundry_first(
            hook.get("target_resource"),
            hook.get("targetResource"),
            hook.get("resourceId"),
            hook.get("objectId"),
        )
        remediation_actions = _copilot_values(hook.get("remediation_actions"), hook.get("remediationActions"), action_name)
        scopes = _copilot_values(hook.get("permission_scopes"), hook.get("permissionScopes"), hook.get("oauth_scopes"))
        metadata = inventory_metadata(
            hook,
            "remediation_hook",
            control_mode_hint=external_status,
            extra={
                "remediation_action": action_name or None,
                "remediation_target_type": target_type or None,
                "remediation_target_resource": target_resource or None,
                "related_activity_id": _foundry_first(hook.get("related_activity_id"), hook.get("relatedActivityId")) or None,
                "requires_approval": _copilot_truthy(hook.get("requires_approval") or hook.get("requiresApproval")),
                "external_action_status": external_status,
                "oauth_app_id": app_id or None,
                "oauth_app_name": _foundry_first(hook.get("oauth_app_name"), hook.get("oauthAppName"), hook.get("appDisplayName"))
                or None,
            },
        )
        if agent_id:
            events.append(
                MicrosoftCopilotStudioEventRequest(
                    agent_id=agent_id,
                    event_type="copilot.inventory.remediation_hook",
                    action_type="copilot_remediation_hook",
                    prompt_or_content="Copilot Studio remediation hook inventory sync",
                    user_principal_name=_foundry_first(hook.get("user_principal_name"), hook.get("userPrincipalName")) or None,
                    connector_name=target_resource or action_name or None,
                    connector_names=[target_resource] if target_resource else [],
                    oauth_app_id=app_id or None,
                    oauth_app_name=_foundry_first(hook.get("oauth_app_name"), hook.get("oauthAppName"), hook.get("appDisplayName"))
                    or None,
                    permission_scopes=scopes,
                    data_sources=_copilot_values(hook.get("data_sources"), hook.get("dataSources")),
                    sensitivity_label=_foundry_first(hook.get("sensitivity_label"), hook.get("sensitivityLabel")) or None,
                    remediation_actions=remediation_actions,
                    external_action_status=external_status,
                    metadata=metadata,
                    gateway_routed=False,
                )
            )
        else:
            events.append(
                MicrosoftCopilotEventRequest(
                    user_principal_name=_foundry_first(hook.get("user_principal_name"), hook.get("userPrincipalName")) or None,
                    correlation_id=_foundry_record_id(hook) or None,
                    event_type="copilot.inventory.remediation_hook",
                    action_type="copilot_remediation_hook",
                    prompt_or_content="Microsoft Copilot remediation hook inventory sync",
                    workload=_foundry_first(hook.get("workload"), hook.get("source_app"), hook.get("sourceApp")) or None,
                    source_app=_foundry_first(hook.get("source_app"), hook.get("sourceApp"), hook.get("workload")) or None,
                    sensitivity_label=_foundry_first(hook.get("sensitivity_label"), hook.get("sensitivityLabel")) or None,
                    data_sources=_copilot_values(hook.get("data_sources"), hook.get("dataSources")),
                    permission_scopes=scopes,
                    oauth_app_id=app_id or None,
                    oauth_app_name=_foundry_first(hook.get("oauth_app_name"), hook.get("oauthAppName"), hook.get("appDisplayName"))
                    or None,
                    remediation_actions=remediation_actions,
                    external_action_status=external_status,
                    metadata=metadata,
                    gateway_routed=False,
                )
            )

    return events


def _is_sqlite_lock_error(exc: Exception) -> bool:
    return "database is locked" in str(exc).lower()


def _iso_from_epoch(value: Any) -> datetime | None:
    try:
        token = float(value)
        if token <= 0:
            return None
        return datetime.fromtimestamp(token, tz=timezone.utc)
    except (TypeError, ValueError):
        return None


def _slack_request_to_unified(payload: SlackEventApiRequest) -> UnifiedSurfaceEventRequest:
    event = payload.event if isinstance(payload.event, dict) else {}
    files = event.get("files") if isinstance(event.get("files"), list) else []
    file_meta = []
    for item in files:
        if not isinstance(item, dict):
            continue
        file_meta.append(
            {
                "name": _safe_str(item.get("name") or item.get("title")),
                "mime_type": _safe_str(item.get("mimetype")),
                "size_bytes": item.get("size"),
            }
        )
    event_ts = _iso_from_epoch(event.get("event_ts") or payload.event_time)
    return UnifiedSurfaceEventRequest(
        surface="saas",
        app="slack",
        action_type="prompt_input" if _safe_str(event.get("text")) else "message",
        event_type=_safe_str(payload.type) or "slack.event",
        user_id=_safe_str(event.get("user")) or None,
        correlation_id=_safe_str(payload.event_id) or None,
        timestamp=event_ts,
        prompt_or_content=_safe_str(event.get("text")) or None,
        url=f"https://slack.com/app_redirect?team={_safe_str(payload.team_id)}" if _safe_str(payload.team_id) else "https://slack.com",
        app_domain="slack.com",
        file_meta=file_meta,
        gateway_routed=True,
        metadata={
            "source": "slack_events_api",
            "channel": _safe_str(event.get("channel")) or None,
            "event_subtype": _safe_str(event.get("subtype")) or None,
            "team_id": _safe_str(payload.team_id) or None,
        },
    )


def _o365_request_to_unified(payload: O365GraphEventRequest) -> UnifiedSurfaceBatchRequest:
    events: list[UnifiedSurfaceEventRequest] = []
    for item in payload.value:
        if not isinstance(item, dict):
            continue
        resource = _safe_str(item.get("resource")).lower()
        resource_data = item.get("resourceData") if isinstance(item.get("resourceData"), dict) else {}
        app = "microsoft_365"
        if "teams" in resource:
            app = "teams"
        elif "messages" in resource or "mail" in resource:
            app = "outlook"
        prompt_or_content = _safe_str(
            resource_data.get("subject")
            or resource_data.get("bodyPreview")
            or resource_data.get("chatMessage")
            or resource_data.get("content")
        )
        user_id = _safe_str(
            resource_data.get("userId")
            or resource_data.get("userPrincipalName")
            or resource_data.get("from")
            or item.get("subscriptionId")
        )
        device_id = _safe_str(
            resource_data.get("deviceId")
            or resource_data.get("device_id")
            or resource_data.get("endpointId")
            or resource_data.get("endpoint_id")
        )
        events.append(
            UnifiedSurfaceEventRequest(
                surface="saas",
                app=app,
                action_type="prompt_input" if prompt_or_content else "activity",
                event_type=_safe_str(item.get("changeType")) or "graph.notification",
                user_id=user_id or None,
                device_id=device_id or None,
                endpoint_id=device_id or None,
                prompt_or_content=prompt_or_content or None,
                app_domain="outlook.office.com" if app == "outlook" else ("teams.microsoft.com" if app == "teams" else "office.com"),
                url=f"https://graph.microsoft.com/v1.0/{resource}" if resource else "https://graph.microsoft.com/v1.0",
                correlation_id=_safe_str(item.get("subscriptionId")) or _safe_str(resource_data.get("id")) or None,
                gateway_routed=True,
                metadata={
                    "source": "microsoft_graph",
                    "resource": resource or None,
                    "tenant_id": _safe_str(item.get("tenantId")) or None,
                    "client_state": _safe_str(item.get("clientState")) or None,
                },
            )
        )
    return UnifiedSurfaceBatchRequest(events=events)


def _google_workspace_request_to_unified(payload: GoogleWorkspaceRawEventRequest) -> UnifiedSurfaceEventRequest:
    body = payload.payload if isinstance(payload.payload, dict) else {}
    event = body.get("event") if isinstance(body.get("event"), dict) else body
    prompt_or_content = _safe_str(event.get("snippet") or event.get("subject") or event.get("content"))
    user_id = _safe_str(payload.user_id or event.get("user") or event.get("email"))
    app = _safe_str(payload.app or "google_workspace").lower()
    app_domain = "workspace.google.com"
    if app == "gmail":
        app_domain = "mail.google.com"
    elif app in {"gdrive", "google_drive", "drive"}:
        app = "google_workspace"
        app_domain = "drive.google.com"
    return UnifiedSurfaceEventRequest(
        surface="saas",
        app=app,
        action_type="prompt_input" if prompt_or_content else "activity",
        event_type=_safe_str(body.get("event_type")) or "google_workspace.event",
        user_id=user_id or None,
        prompt_or_content=prompt_or_content or None,
        app_domain=app_domain,
        url=f"https://{app_domain}",
        gateway_routed=True,
        metadata={
            "source": "google_workspace",
            "raw_event": event if isinstance(event, dict) else {},
        },
    )


def _microsoft_outlook_request_to_unified(payload: MicrosoftOutlookEventRequest) -> UnifiedSurfaceEventRequest:
    content = _safe_str(payload.subject) or _safe_str(payload.body_preview)
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    return UnifiedSurfaceEventRequest(
        surface="saas",
        app="outlook",
        action_type="prompt_input" if content else "activity",
        event_type=_safe_str(payload.event_type) or "outlook.email",
        user_id=user_ref or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=content or None,
        app_domain="outlook.office.com",
        url="https://outlook.office.com",
        file_meta=list(payload.file_meta or []),
        gateway_routed=payload.gateway_routed,
        metadata={
            "source": "microsoft_outlook",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "recipients": list(payload.recipients or []),
            **(payload.metadata or {}),
        },
    )


def _microsoft_teams_request_to_unified(payload: MicrosoftTeamsEventRequest) -> UnifiedSurfaceEventRequest:
    content = _safe_str(payload.message)
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    return UnifiedSurfaceEventRequest(
        surface="saas",
        app="teams",
        action_type="prompt_input" if content else "activity",
        event_type=_safe_str(payload.event_type) or "teams.message",
        user_id=user_ref or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=content or None,
        app_domain="teams.microsoft.com",
        url="https://teams.microsoft.com",
        file_meta=list(payload.file_meta or []),
        gateway_routed=payload.gateway_routed,
        metadata={
            "source": "microsoft_teams",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "channel_id": _safe_str(payload.channel_id) or None,
            "team_id": _safe_str(payload.team_id) or None,
            "meeting_id": _safe_str(payload.meeting_id) or None,
            **(payload.metadata or {}),
        },
    )


def _microsoft_drive_request_to_unified(payload: MicrosoftDriveSharepointEventRequest) -> UnifiedSurfaceEventRequest:
    source = _safe_str(payload.source).lower()
    app = "onedrive" if source == "onedrive" else "sharepoint"
    domain = "onedrive.live.com" if app == "onedrive" else "sharepoint.com"
    content = _safe_str(payload.content_preview) or _safe_str(payload.file_name)
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    return UnifiedSurfaceEventRequest(
        surface="saas",
        app=app,
        action_type="upload" if _safe_str(payload.action).lower() in {"upload", "share"} else "activity",
        event_type=_safe_str(payload.event_type) or "file.activity",
        user_id=user_ref or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=content or None,
        app_domain=domain,
        url=f"https://{domain}",
        file_meta=[
            {
                "name": _safe_str(payload.file_name) or None,
                "path": _safe_str(payload.file_path) or None,
                "sharing_scope": _safe_str(payload.sharing_scope) or None,
                "sensitivity_label": _safe_str(payload.sensitivity_label) or None,
            }
        ],
        gateway_routed=payload.gateway_routed,
        metadata={
            "source": "microsoft_storage",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "storage_source": app,
            "action": _safe_str(payload.action) or None,
            "sharing_scope": _safe_str(payload.sharing_scope) or None,
            **(payload.metadata or {}),
        },
    )


def _microsoft_office_copilot_request_to_unified(payload: MicrosoftOfficeCopilotEventRequest) -> UnifiedSurfaceEventRequest:
    app_name = _safe_str(payload.app_name).lower() or "word"
    if app_name not in {"word", "excel", "powerpoint"}:
        app_name = "word"
    content = _safe_str(payload.prompt_or_content) or _safe_str(payload.document_title)
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    return UnifiedSurfaceEventRequest(
        surface="saas",
        app=app_name,
        action_type="prompt_input" if content else "activity",
        event_type=_safe_str(payload.event_type) or "office.copilot.prompt",
        user_id=user_ref or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=content or None,
        app_domain="office.com",
        url="https://office.com",
        gateway_routed=payload.gateway_routed,
        metadata={
            "source": "office_copilot",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "office_app": app_name,
            "document_title": _safe_str(payload.document_title) or None,
            **(payload.metadata or {}),
        },
    )


def _microsoft_entra_request_to_unified(payload: MicrosoftEntraEventRequest) -> UnifiedSurfaceEventRequest:
    risk_level = _safe_str(payload.risk_level).lower()
    risk_state = _safe_str(payload.risk_state).lower()
    activity = _safe_str(payload.activity) or "identity_activity"
    app_display_name = _safe_str(payload.app_display_name)
    risky = risk_level in {"medium", "high", "critical"} or risk_state in {"at_risk", "confirmed_compromised"}
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    content = " ".join(
        token
        for token in [
            "Microsoft Entra identity activity",
            activity,
            app_display_name,
            f"risk:{risk_level}" if risk_level else "",
            f"state:{risk_state}" if risk_state else "",
        ]
        if token
    )
    return UnifiedSurfaceEventRequest(
        surface="saas",
        app="entra_id",
        action_type="identity_activity",
        event_type=_safe_str(payload.event_type) or "entra.identity_activity",
        user_id=user_ref or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=content or None,
        app_domain="login.microsoftonline.com",
        url="https://login.microsoftonline.com",
        gateway_routed=payload.gateway_routed,
        decision_hint="warn" if risky else None,
        reason_code="microsoft_entra_risky_signin" if risky else None,
        risk_score=0.82 if risky else None,
        metadata={
            "source": "microsoft_entra",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "activity": activity,
            "app_display_name": app_display_name or None,
            "risk_level": risk_level or None,
            "risk_state": risk_state or None,
            "risk_detail": _safe_str(payload.risk_detail) or None,
            "ip_address": _safe_str(payload.ip_address) or None,
            "metadata_first": True,
            **(payload.metadata or {}),
        },
    )


def _microsoft_azure_openai_request_to_unified(payload: MicrosoftAzureOpenAIEventRequest) -> UnifiedSurfaceEventRequest:
    transport = dict(payload.transport or {})
    if not transport:
        transport = {"require_tls": True, "tls_version": "1.3", "scheme": "https"}
    upstream_api_endpoint = _safe_str(payload.api_endpoint)
    if payload.gateway_routed:
        gateway_endpoint = _safe_str((payload.metadata or {}).get("gateway_endpoint")) or _safe_str(transport.get("gateway_endpoint"))
        api_endpoint = gateway_endpoint or "https://hawk-gateway.company.com/azure-openai"
    else:
        api_endpoint = upstream_api_endpoint or "https://api.openai.azure.com"
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    return UnifiedSurfaceEventRequest(
        surface="developer_tool",
        app="azure_openai",
        action_type="api_call",
        event_type=_safe_str(payload.event_type) or "azure_openai.request",
        user_id=user_ref or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=_safe_str(payload.prompt_or_content) or None,
        prompt_preview_redacted=_safe_str(payload.prompt_preview_redacted) or None,
        model=_safe_str(payload.model) or None,
        model_version=_safe_str(payload.model_version) or None,
        provider=_safe_str(payload.provider) or "azure_openai",
        api_endpoint=api_endpoint,
        app_domain="api.openai.azure.com",
        url=api_endpoint,
        gateway_routed=payload.gateway_routed,
        transport=transport,
        metadata={
            "source": "azure_openai",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "gateway_enforced": bool(payload.gateway_routed),
            "upstream_api_endpoint": upstream_api_endpoint or None,
            **(payload.metadata or {}),
        },
    )


def _microsoft_foundry_request_to_unified(payload: MicrosoftFoundryEventRequest) -> UnifiedSurfaceEventRequest:
    transport = dict(payload.transport or {})
    if not transport and payload.gateway_routed:
        transport = {"require_tls": True, "tls_version": "1.3", "scheme": "https"}
    api_endpoint = _safe_str(payload.api_endpoint) or "https://ai.azure.com"
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    metadata = dict(payload.metadata or {})
    tool_names = [_safe_str(item) for item in list(payload.tool_names or []) if _safe_str(item)] or (
        [_safe_str(payload.tool)] if _safe_str(payload.tool) else []
    )
    data_source_ids = [_safe_str(item) for item in list(payload.data_source_ids or []) if _safe_str(item)] or (
        [_safe_str(payload.data_source)] if _safe_str(payload.data_source) else []
    )
    authority = dict(payload.authority or {})
    if _safe_str(payload.service_principal_id):
        authority["service_principal_id"] = _safe_str(payload.service_principal_id)
    if _safe_str(payload.managed_identity_id):
        authority["managed_identity_id"] = _safe_str(payload.managed_identity_id)
    if _safe_str(payload.entra_app_id):
        authority["entra_app_id"] = _safe_str(payload.entra_app_id)
    metadata.update(
        {
            "source": "microsoft_foundry",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "foundry_project_id": _safe_str(payload.project_id) or None,
            "foundry_project_name": _safe_str(payload.project_name) or None,
            "workspace_id": _safe_str(payload.workspace_id) or None,
            "subscription_id": _safe_str(payload.subscription_id) or None,
            "resource_group": _safe_str(payload.resource_group) or None,
            "agent_name": _safe_str(payload.agent_name) or None,
            "model_deployment": _safe_str(payload.model_deployment) or None,
            "model_deployment_id": _safe_str(payload.model_deployment_id) or None,
            "tool_names": tool_names,
            "data_source_ids": data_source_ids,
            "service_principal_id": _safe_str(payload.service_principal_id) or None,
            "managed_identity_id": _safe_str(payload.managed_identity_id) or None,
            "entra_app_id": _safe_str(payload.entra_app_id) or None,
            "authority": authority,
            "gateway_enforced": bool(payload.gateway_routed),
            "control_mode_hint": "inline_candidate" if payload.gateway_routed else "telemetry_only",
        }
    )
    return UnifiedSurfaceEventRequest(
        surface="foundry",
        app="microsoft_foundry",
        action_type=_safe_str(payload.action_type) or "agent_action",
        event_type=_safe_str(payload.event_type) or "foundry.agent_action",
        user_id=user_ref or None,
        agent_id=_safe_str(payload.agent_id) or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=_safe_str(payload.prompt_or_content) or None,
        model=_safe_str(payload.model or payload.model_deployment) or None,
        model_version=_safe_str(payload.model_version) or None,
        provider="Microsoft Foundry",
        tool=_safe_str(payload.tool) or (tool_names[0] if tool_names else "azure ai foundry"),
        api_endpoint=api_endpoint,
        data_source=_safe_str(payload.data_source) or (data_source_ids[0] if data_source_ids else "microsoft_foundry"),
        app_domain="ai.azure.com",
        url=api_endpoint,
        gateway_routed=payload.gateway_routed,
        transport=transport,
        metadata=metadata,
    )


def _microsoft_copilot_request_to_unified(payload: MicrosoftCopilotEventRequest) -> UnifiedSurfaceEventRequest:
    app = _safe_str(payload.app).lower() or "m365_copilot"
    if app not in {"m365_copilot", "office_copilot", "microsoft_copilot"}:
        app = "m365_copilot"
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    metadata = dict(payload.metadata or {})
    knowledge_asset_ids = [_safe_str(item) for item in list(payload.knowledge_asset_ids or []) if _safe_str(item)]
    data_sources = [_safe_str(item) for item in list(payload.data_sources or []) if _safe_str(item)]
    permission_scopes = [_safe_str(item) for item in list(payload.permission_scopes or []) if _safe_str(item)]
    remediation_actions = [_safe_str(item) for item in list(payload.remediation_actions or []) if _safe_str(item)]
    control_mode_hint = _safe_str(metadata.get("control_mode_hint")) or "telemetry_only"
    metadata.update(
        {
            "source": "microsoft_copilot",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "copilot_type": _safe_str(payload.copilot_type) or "m365_copilot",
            "document_title": _safe_str(payload.document_title) or None,
            "workload": _safe_str(payload.workload) or None,
            "source_app": _safe_str(payload.source_app) or None,
            "sensitivity_label": _safe_str(payload.sensitivity_label) or None,
            "knowledge_asset_ids": knowledge_asset_ids,
            "data_sources": data_sources,
            "permission_scopes": permission_scopes,
            "oauth_app_id": _safe_str(payload.oauth_app_id) or None,
            "oauth_app_name": _safe_str(payload.oauth_app_name) or None,
            "remediation_actions": remediation_actions,
            "external_action_status": _safe_str(payload.external_action_status) or None,
            "control_mode_hint": control_mode_hint,
        }
    )
    return UnifiedSurfaceEventRequest(
        surface="copilot",
        app=app,
        action_type=_safe_str(payload.action_type) or "prompt_input",
        event_type=_safe_str(payload.event_type) or "copilot.prompt",
        user_id=user_ref or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=_safe_str(payload.prompt_or_content) or _safe_str(payload.document_title) or None,
        provider="Microsoft Copilot",
        tool="microsoft 365 copilot",
        app_domain="copilot.microsoft.com",
        url="https://copilot.microsoft.com",
        gateway_routed=payload.gateway_routed,
        metadata=metadata,
    )


def _microsoft_copilot_studio_request_to_unified(payload: MicrosoftCopilotStudioEventRequest) -> UnifiedSurfaceEventRequest:
    api_endpoint = _safe_str(payload.api_endpoint) or "https://copilotstudio.microsoft.com"
    user_ref = _safe_str(payload.user_id) or _safe_str(payload.user_principal_name)
    metadata = dict(payload.metadata or {})
    control_mode_hint = _safe_str(metadata.get("control_mode_hint")) or (
        "inline_candidate" if payload.gateway_routed else "telemetry_only"
    )
    connector_names = [_safe_str(item) for item in list(payload.connector_names or []) if _safe_str(item)] or (
        [_safe_str(payload.connector_name)] if _safe_str(payload.connector_name) else []
    )
    oauth_scopes = [_safe_str(item) for item in list(payload.oauth_scopes or []) if _safe_str(item)]
    permission_scopes = [_safe_str(item) for item in list(payload.permission_scopes or []) if _safe_str(item)]
    data_sources = [_safe_str(item) for item in list(payload.data_sources or []) if _safe_str(item)]
    remediation_actions = [_safe_str(item) for item in list(payload.remediation_actions or []) if _safe_str(item)]
    metadata.update(
        {
            "source": "microsoft_copilot_studio",
            "entra_user_id": _safe_str(payload.entra_user_id) or None,
            "user_principal_name": _safe_str(payload.user_principal_name) or None,
            "environment_id": _safe_str(payload.environment_id) or None,
            "agent_name": _safe_str(payload.agent_name) or None,
            "agent_owner": _safe_str(payload.agent_owner) or None,
            "publisher": _safe_str(payload.publisher) or None,
            "tool_names": connector_names,
            "connector_name": _safe_str(payload.connector_name) or None,
            "connector_names": connector_names,
            "oauth_scopes": oauth_scopes,
            "oauth_app_id": _safe_str(payload.oauth_app_id) or None,
            "oauth_app_name": _safe_str(payload.oauth_app_name) or None,
            "permission_scopes": permission_scopes,
            "data_sources": data_sources,
            "sensitivity_label": _safe_str(payload.sensitivity_label) or None,
            "remediation_actions": remediation_actions,
            "external_action_status": _safe_str(payload.external_action_status) or None,
            "control_mode_hint": control_mode_hint,
        }
    )
    return UnifiedSurfaceEventRequest(
        surface="copilot",
        app="copilot_studio",
        action_type=_safe_str(payload.action_type) or "connector_action",
        event_type=_safe_str(payload.event_type) or "copilot_studio.agent_action",
        user_id=user_ref or None,
        agent_id=_safe_str(payload.agent_id) or None,
        device_id=_safe_str(payload.device_id or payload.endpoint_id) or None,
        endpoint_id=_safe_str(payload.endpoint_id or payload.device_id) or None,
        correlation_id=_safe_str(payload.correlation_id) or None,
        timestamp=payload.timestamp,
        prompt_or_content=_safe_str(payload.prompt_or_content) or None,
        provider="Microsoft Copilot Studio",
        tool=_safe_str(payload.connector_name) or (connector_names[0] if connector_names else "copilot studio agent"),
        api_endpoint=api_endpoint,
        data_source=_safe_str(payload.connector_name) or (connector_names[0] if connector_names else "copilot_studio"),
        app_domain="copilotstudio.microsoft.com",
        url=api_endpoint,
        gateway_routed=payload.gateway_routed,
        metadata=metadata,
    )


def _ingest(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    payload: UnifiedSurfaceEventRequest,
    force_surface: str | None = None,
    force_app: str | None = None,
) -> dict[str, Any]:
    body = payload.model_dump()
    if force_surface:
        body["surface"] = force_surface
    if force_app:
        body["app"] = force_app
    if not str(body.get("app") or "").strip():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="app is required")
    for attempt in range(1, SQLITE_LOCK_RETRY_ATTEMPTS + 1):
        try:
            return ingest_surface_event(
                db,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                event=body,
            )
        except SQLAlchemyError as exc:
            db.rollback()
            if _is_sqlite_lock_error(exc) and attempt < SQLITE_LOCK_RETRY_ATTEMPTS:
                backoff_seconds = min(0.8, SQLITE_LOCK_RETRY_BACKOFF_SECONDS * attempt)
                sleep(backoff_seconds)
                continue
            if _is_sqlite_lock_error(exc):
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Database busy while ingesting surface event. Retry in a few seconds.",
                    headers={"Retry-After": "2"},
                ) from exc
            raise
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Database busy while ingesting surface event. Retry in a few seconds.",
        headers={"Retry-After": "2"},
    )


def _resolve_endpoint_heartbeat_user_id(
    db: Session,
    *,
    tenant_id: str,
    current_user: User,
    reported_user_ref: str | None,
) -> tuple[str, dict[str, Any]]:
    ref = str(reported_user_ref or "").strip()
    if not ref:
        return current_user.id, {"identity_binding_state": "current_user"}

    if ref == current_user.id:
        return current_user.id, {"identity_binding_state": "reported_user_id"}

    if ref.lower() == str(current_user.email or "").lower():
        return current_user.id, {
            "identity_binding_state": "resolved_current_user_email",
            "reported_user_ref": ref,
        }

    row = db.scalar(
        select(User)
        .join(UserTenantRole, UserTenantRole.user_id == User.id)
        .where(
            UserTenantRole.tenant_id == tenant_id,
            or_(User.id == ref, func.lower(User.email) == ref.lower()),
        )
        .limit(1)
    )
    if row:
        return row.id, {
            "identity_binding_state": "resolved_tenant_user_ref",
            "reported_user_ref": ref,
        }

    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={
            "code": "endpoint_heartbeat_user_not_in_tenant",
            "message": "Endpoint heartbeat user reference must resolve to a user in the selected tenant.",
        },
    )


@router.post("/events", response_model=UnifiedSurfaceEventResponse)
def ingest_unified_surface_event(
    payload: UnifiedSurfaceEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=payload,
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/events/batch", response_model=UnifiedSurfaceBatchResponse)
def ingest_unified_surface_batch(
    payload: UnifiedSurfaceBatchRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    items: list[dict[str, Any]] = []
    for item in payload.events:
        items.append(
            _ingest(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=item,
            )
        )
    db.commit()
    blocked = len([row for row in items if row.get("decision") == "block"])
    warned = len([row for row in items if row.get("decision") == "warn"])
    allowed = len([row for row in items if row.get("decision") == "allow"])
    return UnifiedSurfaceBatchResponse(
        total=len(payload.events),
        processed=len(items),
        blocked=blocked,
        warned=warned,
        allowed=allowed,
        items=[UnifiedSurfaceEventResponse.model_validate(row) for row in items],
    )


@router.post("/saas/slack/events", response_model=UnifiedSurfaceEventResponse)
def ingest_slack_event(
    payload: UnifiedSurfaceEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=payload,
        force_surface="saas",
        force_app="slack",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/saas/slack/events/raw")
def ingest_slack_event_raw(
    payload: SlackEventApiRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if _safe_str(payload.type) == "url_verification" and _safe_str(payload.challenge):
        return {"accepted": True, "challenge": payload.challenge}
    mapped = _slack_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="saas",
        force_app="slack",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/saas/o365/events", response_model=UnifiedSurfaceEventResponse)
def ingest_o365_event(
    payload: UnifiedSurfaceEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=payload,
        force_surface="saas",
        force_app="microsoft_365",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/saas/o365/events/raw", response_model=UnifiedSurfaceBatchResponse)
def ingest_o365_event_raw(
    payload: O365GraphEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _o365_request_to_unified(payload)
    items: list[dict[str, Any]] = []
    for item in mapped.events:
        items.append(
            _ingest(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=item,
                force_surface="saas",
            )
        )
    db.commit()
    blocked = len([row for row in items if row.get("decision") == "block"])
    warned = len([row for row in items if row.get("decision") == "warn"])
    allowed = len([row for row in items if row.get("decision") == "allow"])
    return UnifiedSurfaceBatchResponse(
        total=len(mapped.events),
        processed=len(items),
        blocked=blocked,
        warned=warned,
        allowed=allowed,
        items=[UnifiedSurfaceEventResponse.model_validate(row) for row in items],
    )


@router.post("/microsoft/outlook/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_outlook_event(
    payload: MicrosoftOutlookEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_outlook_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="saas",
        force_app="outlook",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/teams/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_teams_event(
    payload: MicrosoftTeamsEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_teams_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="saas",
        force_app="teams",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/onedrive-sharepoint/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_drive_sharepoint_event(
    payload: MicrosoftDriveSharepointEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_drive_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="saas",
        force_app=_safe_str(mapped.app) or "sharepoint",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/office-copilot/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_office_copilot_event(
    payload: MicrosoftOfficeCopilotEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_office_copilot_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="saas",
        force_app=_safe_str(mapped.app) or "word",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/entra/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_entra_event(
    payload: MicrosoftEntraEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_entra_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="saas",
        force_app="entra_id",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/azure-openai/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_azure_openai_event(
    payload: MicrosoftAzureOpenAIEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_azure_openai_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="developer_tool",
        force_app="azure_openai",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/foundry/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_foundry_event(
    payload: MicrosoftFoundryEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_foundry_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="foundry",
        force_app="microsoft_foundry",
    )
    if _safe_str(out.get("runtime_event_id")):
        record_surface_agent_touchpoints(
            db,
            tenant_id=ctx.tenant.id,
            runtime_event_id=_safe_str(out.get("runtime_event_id")),
        )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/foundry/sync", response_model=MicrosoftFoundrySyncResponse)
def sync_microsoft_foundry_inventory(
    payload: MicrosoftFoundrySyncRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sync_id = str(uuid4())
    inventory = _pull_foundry_inventory(payload)
    events = _foundry_inventory_to_events(payload, inventory, sync_id=sync_id)
    runtime_event_ids: list[str] = []
    for event_payload in events:
        mapped = _microsoft_foundry_request_to_unified(event_payload)
        out = _ingest(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            payload=mapped,
            force_surface="foundry",
            force_app="microsoft_foundry",
        )
        runtime_event_id = _safe_str(out.get("runtime_event_id"))
        if runtime_event_id:
            runtime_event_ids.append(runtime_event_id)
            record_surface_agent_touchpoints(
                db,
                tenant_id=ctx.tenant.id,
                runtime_event_id=runtime_event_id,
            )
    db.commit()
    gateway_routed_count = len({_safe_str(item) for item in list(payload.gateway_routed_agent_ids or []) if _safe_str(item)})
    return MicrosoftFoundrySyncResponse(
        status="ok",
        source="azure_foundry_live_connector",
        sync_id=sync_id,
        control_capability="inventory_and_trace",
        control_mode="inline_candidate" if gateway_routed_count else "telemetry_only",
        pulled=_foundry_inventory_counts(inventory),
        ingested_events=len(runtime_event_ids),
        runtime_event_ids=runtime_event_ids,
        errors=[],
        connector_diagnostics=_connector_diagnostics(inventory),
    )


@router.post("/microsoft/copilot/sync", response_model=MicrosoftCopilotSyncResponse)
def sync_microsoft_copilot_inventory(
    payload: MicrosoftCopilotSyncRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sync_id = str(uuid4())
    inventory = _pull_copilot_inventory(payload)
    events = _copilot_inventory_to_events(payload, inventory, sync_id=sync_id)
    runtime_event_ids: list[str] = []
    for event_payload in events:
        if isinstance(event_payload, MicrosoftCopilotStudioEventRequest):
            mapped = _microsoft_copilot_studio_request_to_unified(event_payload)
            force_app = "copilot_studio"
        else:
            mapped = _microsoft_copilot_request_to_unified(event_payload)
            force_app = _safe_str(mapped.app) or "m365_copilot"
        out = _ingest(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            payload=mapped,
            force_surface="copilot",
            force_app=force_app,
        )
        runtime_event_id = _safe_str(out.get("runtime_event_id"))
        if runtime_event_id:
            runtime_event_ids.append(runtime_event_id)
            if isinstance(event_payload, MicrosoftCopilotStudioEventRequest):
                record_surface_agent_touchpoints(
                    db,
                    tenant_id=ctx.tenant.id,
                    runtime_event_id=runtime_event_id,
                )
    db.commit()
    gateway_routed_count = len({_safe_str(item) for item in list(payload.gateway_routed_agent_ids or []) if _safe_str(item)})
    return MicrosoftCopilotSyncResponse(
        status="ok",
        source="microsoft_copilot_live_connector",
        sync_id=sync_id,
        control_capability="inventory_and_trace",
        control_mode="inline_candidate" if gateway_routed_count else "telemetry_only",
        pulled=_copilot_inventory_counts(inventory),
        ingested_events=len(runtime_event_ids),
        runtime_event_ids=runtime_event_ids,
        errors=[],
        connector_diagnostics=_connector_diagnostics(inventory),
    )


@router.post("/microsoft/copilot/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_copilot_event(
    payload: MicrosoftCopilotEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_copilot_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="copilot",
        force_app=_safe_str(mapped.app) or "m365_copilot",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/microsoft/copilot-studio/events", response_model=UnifiedSurfaceEventResponse)
def ingest_microsoft_copilot_studio_event(
    payload: MicrosoftCopilotStudioEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _microsoft_copilot_studio_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="copilot",
        force_app="copilot_studio",
    )
    if _safe_str(out.get("runtime_event_id")):
        record_surface_agent_touchpoints(
            db,
            tenant_id=ctx.tenant.id,
            runtime_event_id=_safe_str(out.get("runtime_event_id")),
        )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/saas/google-workspace/events", response_model=UnifiedSurfaceEventResponse)
def ingest_google_workspace_event(
    payload: UnifiedSurfaceEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=payload,
        force_surface="saas",
        force_app="google_workspace",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/saas/google-workspace/events/raw", response_model=UnifiedSurfaceEventResponse)
def ingest_google_workspace_event_raw(
    payload: GoogleWorkspaceRawEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    mapped = _google_workspace_request_to_unified(payload)
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=mapped,
        force_surface="saas",
        force_app=_safe_str(mapped.app) or "google_workspace",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/endpoint/events", response_model=UnifiedSurfaceEventResponse)
def ingest_endpoint_event(
    payload: UnifiedSurfaceEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=payload,
        force_surface="endpoint",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.post("/endpoint/heartbeat", response_model=EndpointHeartbeatResponse)
def ingest_endpoint_heartbeat(
    payload: EndpointHeartbeatRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    resolved_user_id, identity_metadata = _resolve_endpoint_heartbeat_user_id(
        db,
        tenant_id=ctx.tenant.id,
        current_user=current_user,
        reported_user_ref=payload.user_id,
    )
    apps = [name.strip() for name in payload.running_apps if name and name.strip()]
    if not apps:
        apps = ["endpoint_agent"]
    metadata = {
        "source": "endpoint_agent_heartbeat",
        **identity_metadata,
        **(payload.metadata or {}),
    }
    items: list[dict[str, Any]] = []
    for app_name in apps:
        request = UnifiedSurfaceEventRequest(
            surface="endpoint",
            app=app_name,
            action_type="activity",
            event_type="endpoint.heartbeat",
            user_id=resolved_user_id,
            device_id=payload.device_id,
            endpoint_id=payload.device_id,
            hostname=payload.hostname,
            os_type=payload.os_type,
            os_version=payload.os_version,
            browser=payload.browser_type,
            browser_version=payload.browser_version,
            extension_version=payload.extension_version,
            location=payload.location,
            gateway_routed=payload.gateway_routed,
            metadata=metadata,
        )
        items.append(
            _ingest(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=request,
                force_surface="endpoint",
                force_app=app_name,
            )
        )
    db.commit()
    return EndpointHeartbeatResponse(
        processed=len(items),
        device_id=payload.device_id,
        items=[UnifiedSurfaceEventResponse.model_validate(item) for item in items],
    )


@router.post("/dev-tools/events", response_model=UnifiedSurfaceEventResponse)
def ingest_dev_tool_event(
    payload: UnifiedSurfaceEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="operator")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    out = _ingest(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=current_user.id,
        payload=payload,
        force_surface="developer_tool",
    )
    db.commit()
    return UnifiedSurfaceEventResponse.model_validate(out)


@router.get("/identity/{user_id}", response_model=UnifiedIdentityViewResponse)
def unified_identity_view(
    user_id: str,
    lookback_hours: int = 24 * 7,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return UnifiedIdentityViewResponse.model_validate(
        get_identity_unified_view(
            db,
            tenant_id=ctx.tenant.id,
            user_id=user_id,
            lookback_hours=lookback_hours,
        )
    )


@router.get("/alerts", response_model=UnifiedAlertListResponse)
def unified_alerts(
    user_id: str | None = None,
    app: str | None = None,
    severity: str | None = None,
    surface: str | None = None,
    page: int = 1,
    page_size: int = 50,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    items = list_unified_alerts(
        db,
        tenant_id=ctx.tenant.id,
        user_id=user_id,
        app=app,
        severity=severity,
        surface=surface,
    )
    page_items, total, safe_page, safe_page_size = _paginate(items, page=page, page_size=page_size)
    return UnifiedAlertListResponse(
        items=[UnifiedAlertResponse.model_validate(item) for item in page_items],
        total=total,
        page=safe_page,
        page_size=safe_page_size,
    )


@router.get("/alerts/{alert_id}", response_model=UnifiedAlertTraceResponse)
def unified_alert_trace(
    alert_id: str,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    payload = get_unified_alert_trace(
        db,
        tenant_id=ctx.tenant.id,
        alert_id=alert_id,
    )
    if payload is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return UnifiedAlertTraceResponse.model_validate(payload)
