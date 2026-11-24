from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ClaudeSurfaceControl:
    surface: str
    control_method: str
    native_hook_capable: bool
    enrollment_scope: str
    verification_requirement: str
    residual_gap: str


_CONTROLS = (
    ClaudeSurfaceControl(
        "code_cli",
        "native_hook",
        True,
        "user_or_managed",
        "reviewed_exact_version_callback",
        "--bare bypasses hooks",
    ),
    ClaudeSurfaceControl(
        "code_desktop_local",
        "native_hook",
        True,
        "user_or_managed",
        "reviewed_exact_version_callback",
        "Desktop chat is separate",
    ),
    ClaudeSurfaceControl(
        "code_ide",
        "native_hook",
        True,
        "user_or_managed",
        "reviewed_exact_version_callback",
        "IDE host integrity remains external",
    ),
    ClaudeSurfaceControl(
        "code_remote_control",
        "native_hook",
        True,
        "underlying_local_session",
        "local_runtime_callback",
        "Covered only while the local callback is healthy",
    ),
    ClaudeSurfaceControl(
        "code_web_or_desktop_remote",
        "native_hook",
        True,
        "server_managed_or_repository",
        "fresh_server_managed_callback",
        "Local user settings are not loaded in the remote environment",
    ),
    ClaudeSurfaceControl(
        "desktop_chat",
        "mcp_gateway_and_endpoint",
        False,
        "desktop_extension_and_endpoint",
        "signed_mcp_route_or_explicit_endpoint_binding",
        "No Claude Code lifecycle hook exists for ordinary chat prompts",
    ),
    ClaudeSurfaceControl(
        "web_chat",
        "browser_companion_and_mcp_gateway",
        False,
        "managed_browser_and_remote_connector",
        "browser_companion_or_signed_remote_mcp_route",
        "Unmanaged browsers and direct connectors remain bypasses",
    ),
    ClaudeSurfaceControl(
        "mobile_chat",
        "mcp_gateway",
        False,
        "remote_connector",
        "signed_remote_mcp_route",
        "Ordinary mobile prompts are outside endpoint and browser hooks",
    ),
    ClaudeSurfaceControl(
        "direct_api",
        "llm_gateway_or_bound_sdk",
        False,
        "application_or_network_route",
        "signed_llm_gateway_or_sdk_binding",
        "Direct provider routes that bypass Hawk remain Not Covered",
    ),
)


def claude_surface_controls() -> tuple[ClaudeSurfaceControl, ...]:
    return _CONTROLS


def claude_surface_control(surface: str) -> ClaudeSurfaceControl:
    value = str(surface or "").strip().lower()
    for row in _CONTROLS:
        if row.surface == value:
            return row
    raise KeyError("claude_surface_unknown")
