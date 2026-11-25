from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import quote
from urllib.request import Request
from urllib.request import urlopen

from app.services import connector_activity


_ZOOM_NOTETAKER_ACTIONS: dict[str, dict[str, Any]] = {
    "remove_meeting_participant": {
        "label": "Remove AI notetaker from Zoom meeting",
        "side_effect": "meeting_participant_removal",
        "requires": ("meeting_id", "participant_id"),
    },
    "disable_meeting_transcription": {
        "label": "Disable Zoom meeting transcription",
        "side_effect": "meeting_transcription_disable",
        "requires": ("meeting_id",),
    },
    "disable_meeting_recording": {
        "label": "Disable Zoom meeting recording",
        "side_effect": "meeting_recording_disable",
        "requires": ("meeting_id",),
    },
    "harden_meeting_admission": {
        "label": "Harden Zoom meeting admission controls",
        "side_effect": "meeting_admission_hardening",
        "requires": ("meeting_id",),
    },
    "lock_meeting": {
        "label": "Lock Zoom meeting",
        "side_effect": "meeting_lock",
        "requires": ("meeting_id",),
    },
}


def zoom_notetaker_action_catalog() -> list[dict[str, Any]]:
    return [
        {
            "action": action,
            "provider_control_path": "zoom",
            "label": str(payload["label"]),
            "side_effect": str(payload["side_effect"]),
            "required_fields": list(payload["requires"]),
        }
        for action, payload in _ZOOM_NOTETAKER_ACTIONS.items()
    ]


def _env_flag(name: str) -> bool:
    return str(os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _env_action_key(action: str, suffix: str) -> str:
    token = str(action or "").strip().upper().replace("-", "_")
    return f"HAWK_ZOOM_{token}_{suffix}"


def _format_zoom_path(template: str, payload: dict[str, Any]) -> str:
    values = {
        "account_id": quote(str(payload.get("account_id") or ""), safe=""),
        "meeting_id": quote(str(payload.get("meeting_id") or ""), safe=""),
        "participant_id": quote(str(payload.get("participant_id") or ""), safe=""),
        "notetaker_email": quote(str(payload.get("notetaker_email") or ""), safe=""),
        "organizer_user_id": quote(str(payload.get("organizer_user_id") or ""), safe=""),
    }
    return template.format(**values)


def build_zoom_notetaker_operation(
    *,
    action: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Build a tenant-configured Zoom operation for meeting notetaker controls.

    Zoom enforcement varies by account plan, scopes, and API availability. Hawk
    therefore requires tenant-specific action templates and stays honest when no
    inline/external control path is configured.
    """
    action_token = str(action or "").strip().lower()
    catalog_entry = _ZOOM_NOTETAKER_ACTIONS.get(action_token)
    if catalog_entry is None:
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "configured": False,
            "reason": "unsupported_zoom_action",
        }

    missing = [
        field
        for field in catalog_entry["requires"]
        if not str(payload.get(field) or "").strip()
    ]
    if missing:
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "configured": False,
            "reason": "missing_required_zoom_fields",
            "missing_fields": missing,
        }

    method = str(os.getenv(_env_action_key(action_token, "METHOD")) or "").strip().upper()
    path_template = str(os.getenv(_env_action_key(action_token, "PATH_TEMPLATE")) or "").strip()
    if not method or not path_template:
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "configured": False,
            "reason": "zoom_action_not_configured",
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
                    "provider_control_path": "zoom",
                    "action": action_token,
                    "configured": False,
                    "reason": "zoom_body_template_invalid",
                }
        if not isinstance(loaded_body, dict):
            return {
                "provider_control_path": "zoom",
                "action": action_token,
                "configured": False,
                "reason": "zoom_body_template_invalid",
            }
        body = loaded_body

    try:
        path = _format_zoom_path(path_template, payload)
    except Exception:
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "configured": False,
            "reason": "zoom_path_template_invalid",
        }

    return {
        "provider_control_path": "zoom",
        "action": action_token,
        "configured": True,
        "method": method,
        "path": path,
        "body": body,
        "side_effect": catalog_entry["side_effect"],
    }


def execute_zoom_notetaker_action(
    *,
    action: str,
    payload: dict[str, Any],
    access_token: str | None = None,
    http_client: Any | None = None,
) -> dict[str, Any]:
    """Execute a Zoom notetaker control only when tenant configuration exists."""
    action_token = str(action or "").strip().lower()
    if not _env_flag("HAWK_ZOOM_EXECUTION_ENABLED"):
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "zoom_execution_not_configured",
        }

    token = str(
        access_token
        or os.getenv("HAWK_ZOOM_ACCESS_TOKEN")
        or os.getenv("ZOOM_ACCESS_TOKEN")
        or ""
    ).strip()
    if not token:
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "zoom_credentials_not_configured",
        }

    operation = build_zoom_notetaker_operation(action=action_token, payload=payload)
    if not operation.get("configured"):
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": operation.get("reason") or "zoom_action_not_configured",
            "zoom_operation": {k: v for k, v in operation.items() if k not in {"body"}},
        }

    base_url = str(os.getenv("ZOOM_API_BASE_URL") or "https://api.zoom.us").rstrip("/")
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
            with connector_activity.timed(operation["method"], url, source="zoom") as recorded:
                with urlopen(req, timeout=10) as response:  # nosec B310 - URL is server-configured Zoom API base.
                    status_code = int(getattr(response, "status", 0))
                recorded["status"] = status_code
    except Exception as exc:
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "control_mode": "incomplete",
            "performed": False,
            "reason": "zoom_action_failed",
            "error": type(exc).__name__,
            "zoom_operation": {
                "method": operation["method"],
                "path": operation["path"],
                "side_effect": operation.get("side_effect"),
            },
        }

    zoom_operation = {
        "method": operation["method"],
        "path": operation["path"],
        "side_effect": operation.get("side_effect"),
    }
    if 200 <= status_code < 300:
        return {
            "provider_control_path": "zoom",
            "action": action_token,
            "control_mode": "external_action_triggered",
            "performed": True,
            "reason": "zoom_action_succeeded",
            "status_code": status_code,
            "zoom_operation": zoom_operation,
        }
    return {
        "provider_control_path": "zoom",
        "action": action_token,
        "control_mode": "incomplete",
        "performed": False,
        "reason": "zoom_action_rejected",
        "status_code": status_code,
        "zoom_operation": zoom_operation,
    }
