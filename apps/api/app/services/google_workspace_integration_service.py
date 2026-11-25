from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import quote
from urllib.request import Request
from urllib.request import urlopen

from app.services import connector_activity


_GOOGLE_MEET_NOTETAKER_ACTIONS: dict[str, dict[str, Any]] = {
    "remove_calendar_notetaker_invitee": {
        "label": "Remove AI notetaker from Google Calendar invite",
        "side_effect": "meeting_calendar_invitee_removal",
        "requires": ("meeting_id", "notetaker_email"),
    },
    "remove_meeting_participant": {
        "label": "Remove AI notetaker from Google Meet",
        "side_effect": "meeting_participant_removal",
        "requires": ("meeting_id",),
    },
    "disable_meeting_transcription": {
        "label": "Disable Google Meet transcription",
        "side_effect": "meeting_transcription_disable",
        "requires": ("meeting_id",),
    },
    "disable_meeting_recording": {
        "label": "Disable Google Meet recording",
        "side_effect": "meeting_recording_disable",
        "requires": ("meeting_id",),
    },
    "harden_meeting_admission": {
        "label": "Harden Google Meet admission controls",
        "side_effect": "meeting_admission_hardening",
        "requires": ("meeting_id",),
    },
}


def google_meet_notetaker_action_catalog() -> list[dict[str, Any]]:
    return [
        {
            "action": action,
            "provider_control_path": "google_workspace",
            "label": str(payload["label"]),
            "side_effect": str(payload["side_effect"]),
            "required_fields": list(payload["requires"]),
        }
        for action, payload in _GOOGLE_MEET_NOTETAKER_ACTIONS.items()
    ]


def _env_flag(name: str) -> bool:
    return str(os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _env_action_key(action: str, suffix: str) -> str:
    token = str(action or "").strip().upper().replace("-", "_")
    return f"HAWK_GOOGLE_MEET_{token}_{suffix}"


def _format_google_path(template: str, payload: dict[str, Any]) -> str:
    values = {
        "calendar_id": quote(str(payload.get("calendar_id") or "primary"), safe=""),
        "meeting_id": quote(str(payload.get("meeting_id") or ""), safe=""),
        "participant_id": quote(str(payload.get("participant_id") or ""), safe=""),
        "notetaker_email": quote(str(payload.get("notetaker_email") or ""), safe=""),
        "organizer_user_id": quote(str(payload.get("organizer_user_id") or ""), safe=""),
    }
    return template.format(**values)


def build_google_meet_notetaker_operation(
    *,
    action: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Build a server-configured Google Workspace operation for meeting controls.

    Google Meet and Calendar enforcement depends on Workspace edition, admin
    permissions, and API availability. Hawk therefore requires explicit
    action-specific templates instead of pretending one universal endpoint works
    for every tenant.
    """
    action_token = str(action or "").strip().lower()
    catalog_entry = _GOOGLE_MEET_NOTETAKER_ACTIONS.get(action_token)
    if catalog_entry is None:
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "configured": False,
            "reason": "unsupported_google_workspace_action",
        }

    missing = [
        field
        for field in catalog_entry["requires"]
        if not str(payload.get(field) or "").strip()
    ]
    if missing:
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "configured": False,
            "reason": "missing_required_google_workspace_fields",
            "missing_fields": missing,
        }

    method = str(os.getenv(_env_action_key(action_token, "METHOD")) or "").strip().upper()
    path_template = str(os.getenv(_env_action_key(action_token, "PATH_TEMPLATE")) or "").strip()
    if not method or not path_template:
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "configured": False,
            "reason": "google_workspace_action_not_configured",
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
                    "provider_control_path": "google_workspace",
                    "action": action_token,
                    "configured": False,
                    "reason": "google_workspace_body_template_invalid",
                }
        if not isinstance(loaded_body, dict):
            return {
                "provider_control_path": "google_workspace",
                "action": action_token,
                "configured": False,
                "reason": "google_workspace_body_template_invalid",
            }
        body = loaded_body

    try:
        path = _format_google_path(path_template, payload)
    except Exception:
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "configured": False,
            "reason": "google_workspace_path_template_invalid",
        }

    return {
        "provider_control_path": "google_workspace",
        "action": action_token,
        "configured": True,
        "method": method,
        "path": path,
        "body": body,
        "side_effect": catalog_entry["side_effect"],
    }


def execute_google_meet_notetaker_action(
    *,
    action: str,
    payload: dict[str, Any],
    access_token: str | None = None,
    http_client: Any | None = None,
) -> dict[str, Any]:
    """Execute a Google Meet/Calendar notetaker control when configured."""
    action_token = str(action or "").strip().lower()
    if not _env_flag("HAWK_GOOGLE_MEET_EXECUTION_ENABLED"):
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "google_workspace_execution_not_configured",
        }

    token = str(
        access_token
        or os.getenv("HAWK_GOOGLE_MEET_ACCESS_TOKEN")
        or os.getenv("GOOGLE_WORKSPACE_ACCESS_TOKEN")
        or ""
    ).strip()
    if not token:
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": "google_workspace_credentials_not_configured",
        }

    operation = build_google_meet_notetaker_operation(action=action_token, payload=payload)
    if not operation.get("configured"):
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "control_mode": "external_required",
            "performed": False,
            "reason": operation.get("reason") or "google_workspace_action_not_configured",
            "google_operation": {k: v for k, v in operation.items() if k not in {"body"}},
        }

    base_url = str(os.getenv("GOOGLE_WORKSPACE_API_BASE_URL") or "https://www.googleapis.com").rstrip("/")
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
            with connector_activity.timed(operation["method"], url, source="google_workspace") as recorded:
                with urlopen(req, timeout=10) as response:  # nosec B310 - URL is server-configured Google API base.
                    status_code = int(getattr(response, "status", 0))
                recorded["status"] = status_code
    except Exception as exc:
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "control_mode": "incomplete",
            "performed": False,
            "reason": "google_workspace_action_failed",
            "error": type(exc).__name__,
            "google_operation": {
                "method": operation["method"],
                "path": operation["path"],
                "side_effect": operation.get("side_effect"),
            },
        }

    google_operation = {
        "method": operation["method"],
        "path": operation["path"],
        "side_effect": operation.get("side_effect"),
    }
    if 200 <= status_code < 300:
        return {
            "provider_control_path": "google_workspace",
            "action": action_token,
            "control_mode": "external_action_triggered",
            "performed": True,
            "reason": "google_workspace_action_succeeded",
            "status_code": status_code,
            "google_operation": google_operation,
        }
    return {
        "provider_control_path": "google_workspace",
        "action": action_token,
        "control_mode": "incomplete",
        "performed": False,
        "reason": "google_workspace_action_rejected",
        "status_code": status_code,
        "google_operation": google_operation,
    }
