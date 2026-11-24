"""Native-messaging host manifests + install locations."""

from __future__ import annotations

from typing import Any

HOST_NAME = "com.hawk.endpoint_agent"
_DESCRIPTION = "Hawk Endpoint Agent browser bridge"


def chrome_manifest(host_path: str, extension_ids: list[str]) -> dict[str, Any]:
    return {
        "name": HOST_NAME,
        "description": _DESCRIPTION,
        "path": host_path,
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{eid}/" for eid in extension_ids],
    }


def firefox_manifest(host_path: str, extension_ids: list[str]) -> dict[str, Any]:
    return {
        "name": HOST_NAME,
        "description": _DESCRIPTION,
        "path": host_path,
        "type": "stdio",
        "allowed_extensions": list(extension_ids),
    }


# Where each browser looks for native-messaging host manifests (per-user).
INSTALL_LOCATIONS: dict[str, dict[str, str]] = {
    "darwin": {
        "chrome": "~/Library/Application Support/Google/Chrome/NativeMessagingHosts/",
        "edge": "~/Library/Application Support/Microsoft Edge/NativeMessagingHosts/",
        "firefox": "~/Library/Application Support/Mozilla/NativeMessagingHosts/",
    },
    "linux": {
        "chrome": "~/.config/google-chrome/NativeMessagingHosts/",
        "edge": "~/.config/microsoft-edge/NativeMessagingHosts/",
        "firefox": "~/.mozilla/native-messaging-hosts/",
    },
}


def install_location(os_type: str, browser: str) -> str | None:
    return INSTALL_LOCATIONS.get(os_type.lower(), {}).get(browser.lower())
