from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import quote
from urllib.parse import urlencode
from urllib.request import Request
from urllib.request import urlopen


MICROSOFT_GRAPH_PROVIDER_KEYS = {
    "entra_id",
    "microsoft_365",
    "outlook",
    "teams",
    "onedrive_sharepoint",
    "office_apps",
    "microsoft_defender",
    "power_platform",
}
DEFAULT_MICROSOFT_PERMISSION_MODE = "poc_safe"

MICROSOFT_PERMISSION_MODES: dict[str, dict[str, Any]] = {
    "poc_safe": {
        "label": "POC Safe",
        "description": "Metadata-first coverage with minimum viable application scopes for enterprise pilots.",
        "application_scopes": (
            "AuditLog.Read.All",
            "User.Read.All",
            "Mail.ReadBasic.All",
            "Files.Read.All",
            "ChatMessage.Read.All",
            "ChannelMessage.Read.All",
        ),
        "optional_scopes": (
            "Directory.Read.All",
            "Reports.Read.All",
            "Mail.Read",
        ),
    },
    "standard": {
        "label": "Standard",
        "description": "Balanced production mode with richer messaging visibility and collaboration telemetry.",
        "application_scopes": (
            "AuditLog.Read.All",
            "User.Read.All",
            "Directory.Read.All",
            "Mail.Read",
            "Files.Read.All",
            "ChatMessage.Read.All",
            "ChannelMessage.Read.All",
        ),
        "optional_scopes": (
            "Reports.Read.All",
        ),
    },
    "full_enterprise": {
        "label": "Full Enterprise",
        "description": "Expanded enterprise governance with directory and security telemetry for high-control deployments.",
        "application_scopes": (
            "AuditLog.Read.All",
            "User.Read.All",
            "Directory.Read.All",
            "Mail.Read",
            "Files.Read.All",
            "ChatMessage.Read.All",
            "ChannelMessage.Read.All",
            "Reports.Read.All",
        ),
        "optional_scopes": (
            "SecurityEvents.Read.All",
            "CallRecords.Read.All",
            "AiEnterpriseInteraction.Read.User",
        ),
    },
}

_PROVIDER_REQUIRED_SCOPE_HINTS: dict[str, tuple[str, ...]] = {
    "entra_id": ("AuditLog.Read.All", "User.Read.All"),
    "microsoft_365": ("AuditLog.Read.All", "Files.Read.All", "ChatMessage.Read.All", "ChannelMessage.Read.All"),
    "outlook": ("AuditLog.Read.All", "Mail.ReadBasic.All"),
    "teams": ("AuditLog.Read.All", "ChatMessage.Read.All", "ChannelMessage.Read.All"),
    "onedrive_sharepoint": ("AuditLog.Read.All", "Files.Read.All", "Sites.Read.All"),
    "office_apps": ("AuditLog.Read.All", "Files.Read.All"),
    "microsoft_defender": ("SecurityEvents.Read.All", "AuditLog.Read.All"),
    "power_platform": ("AuditLog.Read.All", "User.Read.All", "Files.Read.All"),
}

_METADATA_ALLOWED_KEYS = {
    "id",
    "createdDateTime",
    "lastModifiedDateTime",
    "receivedDateTime",
    "sentDateTime",
    "userPrincipalName",
    "userId",
    "appDisplayName",
    "clientAppUsed",
    "resourceDisplayName",
    "activityDisplayName",
    "ipAddress",
    "status",
    "riskLevelDuringSignIn",
    "riskState",
    "riskDetail",
    "correlationId",
    "operationType",
    "targetResources",
}

_CONTENT_KEYS = {
    "body",
    "bodyPreview",
    "uniqueBody",
    "content",
    "message",
    "chatMessage",
    "raw",
    "prompt",
}

_TEAMS_NOTETAKER_ACTIONS = {
    "remove_meeting_participant": {
        "label": "Remove AI notetaker from Teams meeting",
        "side_effect": "meeting_participant_removal",
        "requires": ("meeting_id",),
    },
    "disable_meeting_transcription": {
        "label": "Disable Teams meeting transcription",
        "side_effect": "meeting_transcription_disable",
        "requires": ("meeting_id",),
    },
    "disable_meeting_recording": {
        "label": "Disable Teams meeting recording",
        "side_effect": "meeting_recording_disable",
        "requires": ("meeting_id",),
    },
    "harden_meeting_admission": {
        "label": "Harden Teams meeting admission controls",
        "side_effect": "meeting_admission_hardening",
        "requires": ("meeting_id",),
    },
}


def is_microsoft_graph_provider(provider_key: str | None) -> bool:
    return str(provider_key or "").strip().lower() in MICROSOFT_GRAPH_PROVIDER_KEYS


def normalize_permission_mode(permission_mode: str | None) -> str:
    token = str(permission_mode or "").strip().lower()
    return token if token in MICROSOFT_PERMISSION_MODES else DEFAULT_MICROSOFT_PERMISSION_MODE


def microsoft_permission_modes() -> list[dict[str, Any]]:
    return [
        {
            "mode": mode,
            "label": str(payload.get("label") or mode),
            "description": str(payload.get("description") or ""),
            "application_scopes": list(payload.get("application_scopes") or []),
            "optional_scopes": list(payload.get("optional_scopes") or []),
        }
        for mode, payload in MICROSOFT_PERMISSION_MODES.items()
    ]


def resolve_microsoft_graph_scopes(
    *,
    provider_key: str,
    permission_mode: str | None,
    include_optional: bool = True,
) -> dict[str, Any]:
    provider = str(provider_key or "").strip().lower()
    if provider not in MICROSOFT_GRAPH_PROVIDER_KEYS:
        raise ValueError("provider_key is not a Microsoft Graph provider")

    resolved_mode = normalize_permission_mode(permission_mode)
    mode_payload = MICROSOFT_PERMISSION_MODES[resolved_mode]
    mode_scopes = [str(scope).strip() for scope in (mode_payload.get("application_scopes") or []) if str(scope).strip()]
    optional_scopes = [str(scope).strip() for scope in (mode_payload.get("optional_scopes") or []) if str(scope).strip()]

    required_scope_hints = [str(scope).strip() for scope in _PROVIDER_REQUIRED_SCOPE_HINTS.get(provider, ()) if str(scope).strip()]
    required_scopes: list[str] = []
    for scope in [*required_scope_hints, *mode_scopes]:
        if scope and scope not in required_scopes:
            required_scopes.append(scope)

    selected_optional = optional_scopes if include_optional else []
    selected_scopes: list[str] = []
    for scope in [*required_scopes, *selected_optional]:
        if scope and scope not in selected_scopes:
            selected_scopes.append(scope)

    return {
        "provider_key": provider,
        "permission_mode": resolved_mode,
        "required_scopes": required_scopes,
        "optional_scopes": optional_scopes,
        "selected_scopes": selected_scopes,
    }


def build_microsoft_admin_consent_url(
    *,
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    state: str | None = None,
) -> str:
    tenant = str(tenant_id or "").strip()
    client = str(client_id or "").strip()
    redirect = str(redirect_uri or "").strip()
    if not tenant:
        raise ValueError("tenant_id is required")
    if not client:
        raise ValueError("client_id is required")
    if not redirect:
        raise ValueError("redirect_uri is required")

    params: dict[str, str] = {
        "client_id": client,
        "redirect_uri": redirect,
    }
    state_token = str(state or "").strip()
    if state_token:
        params["state"] = state_token

    query = urlencode(params, doseq=False)
    return f"https://login.microsoftonline.com/{tenant}/adminconsent?{query}"


def microsoft_graph_security_profile() -> dict[str, Any]:
    return {
        "tls_minimum": "1.3",
        "certificate_validation": "strict",
        "mtls_supported": True,
        "certificate_pinning_supported": True,
        "header_minimization": True,
        "query_secret_forbidden": True,
        "metadata_minimization": True,
    }


def microsoft_graph_app_registration_template() -> dict[str, Any]:
    return {
        "app_registration_mode": "single_tenant",
        "oauth_supported": ["client_credentials", "delegated_optional"],
        "required_fields": ["tenant_id", "client_id"],
        "credential_options": ["client_secret", "client_certificate_or_assertion"],
        "admin_consent_required_for_application_permissions": True,
        "graph_resource": "https://graph.microsoft.com/.default",
        "security_baseline": microsoft_graph_security_profile(),
    }


def metadata_only_graph_record(
    *,
    record: dict[str, Any],
    provider_key: str,
    signal_type: str,
    include_content: bool = False,
) -> dict[str, Any]:
    payload = dict(record or {})
    output: dict[str, Any] = {}

    for key in _METADATA_ALLOWED_KEYS:
        if key in payload:
            output[key] = payload[key]

    if "initiatedBy" in payload and isinstance(payload["initiatedBy"], dict):
        actor = payload["initiatedBy"]
        output["initiatedBy"] = {
            "user": {
                "id": ((actor.get("user") or {}).get("id") if isinstance(actor.get("user"), dict) else None),
                "userPrincipalName": ((actor.get("user") or {}).get("userPrincipalName") if isinstance(actor.get("user"), dict) else None),
            },
            "app": {
                "appId": ((actor.get("app") or {}).get("appId") if isinstance(actor.get("app"), dict) else None),
                "displayName": ((actor.get("app") or {}).get("displayName") if isinstance(actor.get("app"), dict) else None),
            },
        }

    if "deviceDetail" in payload and isinstance(payload["deviceDetail"], dict):
        detail = payload["deviceDetail"]
        output["deviceDetail"] = {
            "displayName": detail.get("displayName"),
            "operatingSystem": detail.get("operatingSystem"),
            "browser": detail.get("browser"),
            "trustType": detail.get("trustType"),
        }

    if include_content:
        # Content support stays explicit and bounded by policy; keep only short preview fields.
        for key in ("subject", "bodyPreview"):
            if key in payload:
                output[key] = payload[key]
    else:
        for key in _CONTENT_KEYS:
            if key in payload:
                output.setdefault("content_redacted", True)

    output["record_mode"] = "metadata_only" if not include_content else "policy_content_scan"
    output["source_provider"] = str(provider_key or "").strip().lower()
    output["signal_type"] = str(signal_type or "").strip()
    return output


def microsoft_teams_notetaker_action_catalog() -> list[dict[str, Any]]:
    return [
        {
            "action": action,
            "provider_control_path": "microsoft_graph",
            "label": str(payload["label"]),
            "side_effect": str(payload["side_effect"]),
            "required_fields": list(payload["requires"]),
        }
        for action, payload in _TEAMS_NOTETAKER_ACTIONS.items()
    ]


def _env_flag(name: str) -> bool:
    return str(os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _env_action_key(action: str, suffix: str) -> str:
    token = str(action or "").strip().upper().replace("-", "_")
    return f"HAWK_TEAMS_GRAPH_{token}_{suffix}"


def _format_graph_path(template: str, payload: dict[str, Any]) -> str:
    values = {
        "meeting_id": quote(str(payload.get("meeting_id") or ""), safe=""),
        "participant_id": quote(str(payload.get("participant_id") or ""), safe=""),
        "notetaker_email": quote(str(payload.get("notetaker_email") or ""), safe=""),
        "organizer_user_id": quote(str(payload.get("organizer_user_id") or ""), safe=""),
    }
    return template.format(**values)


def build_microsoft_teams_notetaker_graph_operation(
    *,
    action: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Build a server-configured Microsoft Graph operation for Teams controls.

    Graph write/remove capabilities vary by tenant licensing, Teams policy, and
    permissions. Hawk therefore does not hardcode one universal endpoint. The API
    machine must opt in and provide action-specific method/path templates.
    """
    action_token = str(action or "").strip().lower()
    catalog_entry = _TEAMS_NOTETAKER_ACTIONS.get(action_token)
    if catalog_entry is None:
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "configured": False,
            "reason": "unsupported_microsoft_graph_action",
        }

    missing = [
        field for field in catalog_entry["requires"]
        if not str(payload.get(field) or "").strip()
    ]
    if missing:
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "configured": False,
            "reason": "missing_required_graph_fields",
            "missing_fields": missing,
        }

    method = str(os.getenv(_env_action_key(action_token, "METHOD")) or "").strip().upper()
    path_template = str(os.getenv(_env_action_key(action_token, "PATH_TEMPLATE")) or "").strip()
    if not method or not path_template:
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "configured": False,
            "reason": "microsoft_graph_action_not_configured",
            "required_env": [
                _env_action_key(action_token, "METHOD"),
                _env_action_key(action_token, "PATH_TEMPLATE"),
            ],
        }

    body_template = str(os.getenv(_env_action_key(action_token, "BODY_JSON")) or "").strip()
    body: dict[str, Any] | None = None
    if body_template:
        try:
            loaded_body = json.loads(body_template)
        except Exception:
            try:
                loaded_body = json.loads(body_template.format(**{k: str(v or "") for k, v in payload.items()}))
            except Exception:
                return {
                    "provider_control_path": "microsoft_graph",
                    "action": action_token,
                    "configured": False,
                    "reason": "microsoft_graph_body_template_invalid",
                }
        if not isinstance(loaded_body, dict):
            return {
                "provider_control_path": "microsoft_graph",
                "action": action_token,
                "configured": False,
                "reason": "microsoft_graph_body_template_invalid",
            }
        body = loaded_body

    try:
        path = _format_graph_path(path_template, payload)
    except Exception:
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "configured": False,
            "reason": "microsoft_graph_path_template_invalid",
        }

    return {
        "provider_control_path": "microsoft_graph",
        "action": action_token,
        "configured": True,
        "method": method,
        "path": path,
        "body": body,
        "side_effect": catalog_entry["side_effect"],
    }


def execute_microsoft_teams_notetaker_graph_action(
    *,
    action: str,
    payload: dict[str, Any],
    access_token: str | None = None,
    http_client: Any | None = None,
) -> dict[str, Any]:
    """Execute a Teams notetaker control through Microsoft Graph when configured.

    Returns honest control modes:
    - external_required when the tenant/API machine is not configured for Graph write action.
    - external_action_triggered only when Graph returns a 2xx response.
    - incomplete when the Graph call fails after being attempted.
    """
    action_token = str(action or "").strip().lower()
    if not _env_flag("HAWK_TEAMS_GRAPH_EXECUTION_ENABLED"):
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "microsoft_graph_execution_not_configured",
        }

    token = str(
        access_token
        or os.getenv("HAWK_TEAMS_GRAPH_ACCESS_TOKEN")
        or os.getenv("MICROSOFT_GRAPH_ACCESS_TOKEN")
        or ""
    ).strip()
    if not token:
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "microsoft_graph_credentials_not_configured",
        }

    operation = build_microsoft_teams_notetaker_graph_operation(action=action_token, payload=payload)
    if not operation.get("configured"):
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": operation.get("reason") or "microsoft_graph_action_not_configured",
            "graph_operation": {k: v for k, v in operation.items() if k not in {"body"}},
        }

    base_url = str(os.getenv("MICROSOFT_GRAPH_BASE_URL") or "https://graph.microsoft.com/v1.0").rstrip("/")
    url = f"{base_url}/{str(operation['path']).lstrip('/')}"
    body = operation.get("body")
    body_bytes = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    try:
        if http_client is not None:
            response = http_client.request(
                operation["method"],
                url,
                headers=headers,
                json=body,
                timeout=10,
            )
            status_code = int(getattr(response, "status_code", 0))
        else:
            req = Request(url, data=body_bytes, headers=headers, method=operation["method"])
            with urlopen(req, timeout=10) as response:  # nosec B310 - URL is server-configured Microsoft Graph base.
                status_code = int(getattr(response, "status", 0))
    except Exception as exc:
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "control_mode": "incomplete",
            "performed": False,
            "reason": "microsoft_graph_action_failed",
            "error": type(exc).__name__,
            "graph_operation": {
                "method": operation["method"],
                "path": operation["path"],
                "side_effect": operation.get("side_effect"),
            },
        }

    graph_operation = {
        "method": operation["method"],
        "path": operation["path"],
        "side_effect": operation.get("side_effect"),
    }
    if 200 <= status_code < 300:
        return {
            "provider_control_path": "microsoft_graph",
            "action": action_token,
            "control_mode": "external_action_triggered",
            "performed": True,
            "reason": "microsoft_graph_action_succeeded",
            "status_code": status_code,
            "graph_operation": graph_operation,
        }
    return {
        "provider_control_path": "microsoft_graph",
        "action": action_token,
        "control_mode": "incomplete",
        "performed": False,
        "reason": "microsoft_graph_action_rejected",
        "status_code": status_code,
        "graph_operation": graph_operation,
    }
