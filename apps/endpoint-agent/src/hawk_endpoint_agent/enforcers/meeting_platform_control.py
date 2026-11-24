"""Meeting-platform control planning for AI notetakers.

The endpoint agent can see a visible notetaker in the user's meeting context,
but it cannot honestly eject a participant unless a Teams/Meet/Zoom API or host
control path is configured. This helper returns explicit operator/platform
actions so telemetry and evidence can say exactly what Hawk can and cannot do.
"""

from __future__ import annotations

from typing import Any

from ..decision import ControlMode


_PLATFORM_ALIASES: dict[str, str] = {
    "google meet": "google_meet",
    "google_meet": "google_meet",
    "meet": "google_meet",
    "meet.google": "google_meet",
    "meet.google.com": "google_meet",
    "microsoft teams": "teams",
    "teams": "teams",
    "ms teams": "teams",
    "zoom": "zoom",
    "zoom.us": "zoom",
    "webex": "webex",
}


_OPERATOR_STEPS: dict[str, list[str]] = {
    "teams": [
        "Open the Teams participants panel.",
        "Find the AI notetaker participant and choose Remove from meeting.",
        "Disable transcription/recording if this meeting is sensitive.",
        "Use Meeting options to force lobby or restrict anonymous join for future meetings.",
    ],
    "google_meet": [
        "Open the Google Meet people panel.",
        "Find the AI notetaker participant and choose Remove from call.",
        "Turn off recording/transcription if this meeting is sensitive.",
        "Use host controls to restrict entry or disable quick access for future meetings.",
    ],
    "zoom": [
        "Open the Zoom participants panel.",
        "Find the AI notetaker participant and choose Remove.",
        "Disable recording/transcription if this meeting is sensitive.",
        "Use Security controls to lock the meeting or enable waiting room.",
    ],
    "webex": [
        "Open the Webex participants panel.",
        "Find the AI notetaker participant and choose Expel or Remove.",
        "Disable recording/transcription if this meeting is sensitive.",
        "Use meeting options to restrict guest access for future meetings.",
    ],
}

_PROVIDER_CONTROL_PATHS: dict[str, str] = {
    "teams": "microsoft_graph",
    "google_meet": "google_workspace_meet",
    "zoom": "zoom_api",
    "webex": "webex_api",
}

_PLATFORM_CONTROL_ACTIONS: dict[str, list[dict[str, Any]]] = {
    "teams": [
        {
            "type": "remove_meeting_participant",
            "mode": "microsoft_graph_remove_participant",
            "graph_operation": "remove_meeting_participant",
            "operator_steps": [
                "Open the Teams participants panel.",
                "Find the AI notetaker participant and choose Remove from meeting.",
            ],
        },
        {
            "type": "disable_meeting_transcription",
            "mode": "microsoft_graph_disable_transcription",
            "graph_operation": "disable_meeting_transcription",
            "operator_steps": [
                "Disable Teams transcription for this meeting if policy requires it.",
            ],
        },
        {
            "type": "disable_meeting_recording",
            "mode": "microsoft_graph_disable_recording",
            "graph_operation": "disable_meeting_recording",
            "operator_steps": [
                "Disable Teams recording for this meeting if policy requires it.",
            ],
        },
        {
            "type": "harden_meeting_admission",
            "mode": "microsoft_graph_update_meeting_options",
            "graph_operation": "harden_meeting_admission",
            "operator_steps": [
                "Use Teams meeting options to force lobby or restrict anonymous join for future meetings.",
            ],
        },
    ]
}


def normalize_meeting_platforms(signals: list[str]) -> list[str]:
    """Return normalized meeting platforms inferred from endpoint signals."""
    platforms: set[str] = set()
    for raw in signals:
        normalized = (raw or "").strip().lower().replace("-", "_")
        for alias, platform in _PLATFORM_ALIASES.items():
            if alias in normalized:
                platforms.add(platform)
    return sorted(platforms)


def plan_notetaker_removal(platforms: list[str], notetaker_label: str) -> list[dict[str, Any]]:
    """Build honest meeting-platform removal actions.

    These are operator/external-platform actions by default. Future Graph/Meet/
    Zoom adapters can mark an action as performed=True when they actually call
    a platform API and the platform accepts the removal.
    """
    actions: list[dict[str, Any]] = []
    for platform in sorted(set(platforms)):
        provider_control_path = _PROVIDER_CONTROL_PATHS.get(platform, "meeting_platform_admin_api")
        platform_actions = _PLATFORM_CONTROL_ACTIONS.get(platform)
        if platform_actions:
            for action in platform_actions:
                actions.append(
                    {
                        **action,
                        "platform": platform,
                        "participant_label": notetaker_label,
                        "performed": False,
                        "provider_control_path": provider_control_path,
                        "control_mode": ControlMode.EXTERNAL_REQUIRED,
                        "reason": "meeting_platform_credentials_not_configured",
                        "control_authority": "meeting_host_or_platform_admin",
                    }
                )
            continue

        steps = _OPERATOR_STEPS.get(
            platform,
            [
                "Open the meeting participants panel.",
                "Find the AI notetaker participant and remove it from the meeting.",
                "Disable recording/transcription if this meeting is sensitive.",
            ],
        )
        actions.append(
            {
                "type": "remove_meeting_participant",
                "platform": platform,
                "participant_label": notetaker_label,
                "performed": False,
                "provider_control_path": provider_control_path,
                "mode": "operator_action_required",
                "control_mode": ControlMode.EXTERNAL_REQUIRED,
                "reason": "meeting_platform_credentials_not_configured",
                "control_authority": "meeting_host_or_platform_admin",
                "operator_steps": steps,
            }
        )
    return actions
