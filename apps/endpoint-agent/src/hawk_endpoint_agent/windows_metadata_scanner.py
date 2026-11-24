"""Bounded Windows product metadata inventory.

This adapter deliberately reads only the fixed Windows uninstall registry views.
It never reports registry locations or raw values, and it does not inspect
browser profiles, configuration files, prompts, account data, or local paths.
"""

from __future__ import annotations

import sys
from typing import Protocol

from .metadata_scanner import SCHEMA_VERSION, _PRODUCTS, _safe_text


_UNINSTALL_PATH = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
_MAX_UNINSTALL_ENTRIES = 512
_WINDOWS_LIMITATIONS = (
    {"source": "windows_configuration_inventory", "code": "not_supported"},
    {"source": "windows_browser_extension_inventory", "code": "not_supported"},
)
_PRODUCT_MATCHERS: dict[str, tuple[str, ...]] = {
    "claude_code": ("claude code",),
    "codex_cli": ("codex cli", "openai codex", "codex"),
    "cursor": ("cursor",),
    "windsurf": ("windsurf",),
}


class WindowsRegistryUnavailable(RuntimeError):
    """The local uninstall registry cannot be queried safely."""


class WindowsRegistryLimitReached(RuntimeError):
    """The fixed registry enumeration reached its hard limit."""


class WindowsUninstallRegistry(Protocol):
    def uninstall_entries(self) -> tuple[dict[str, str], ...]:
        """Return only DisplayName/DisplayVersion values from fixed uninstall views."""


class LocalWindowsUninstallRegistry:
    """Read fixed uninstall registry views without exposing their locations."""

    def uninstall_entries(self) -> tuple[dict[str, str], ...]:
        if sys.platform != "win32":
            raise WindowsRegistryUnavailable("windows registry unavailable")
        try:
            import winreg
        except ImportError as exc:  # pragma: no cover - winreg is Windows-only
            raise WindowsRegistryUnavailable("windows registry unavailable") from exc

        roots = (
            (winreg.HKEY_CURRENT_USER, winreg.KEY_READ),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
        )
        entries: list[dict[str, str]] = []
        for hive, view in roots:
            try:
                parent = winreg.OpenKey(hive, _UNINSTALL_PATH, 0, view)
            except OSError:
                continue
            with parent:
                index = 0
                while True:
                    if len(entries) >= _MAX_UNINSTALL_ENTRIES:
                        raise WindowsRegistryLimitReached("windows registry limit")
                    try:
                        key_name = winreg.EnumKey(parent, index)
                    except OSError:
                        break
                    index += 1
                    try:
                        child = winreg.OpenKey(parent, key_name, 0, view)
                    except OSError:
                        continue
                    with child:
                        try:
                            display_name = winreg.QueryValueEx(child, "DisplayName")[0]
                        except OSError:
                            continue
                        try:
                            display_version = winreg.QueryValueEx(child, "DisplayVersion")[0]
                        except OSError:
                            display_version = ""
                    if (
                        isinstance(display_name, str)
                        and len(display_name) <= 256
                        and "\x00" not in display_name
                        and isinstance(display_version, str)
                        and len(display_version) <= 128
                        and "\x00" not in display_version
                    ):
                        entries.append(
                            {
                                "display_name": display_name,
                                "display_version": display_version,
                            }
                        )
        return tuple(entries)


def _matched_product_ids(display_name: object) -> tuple[str, ...]:
    if not isinstance(display_name, str) or not display_name or len(display_name) > 256:
        return ()
    normalized = display_name.strip().casefold()
    if not normalized or "\x00" in normalized:
        return ()
    return tuple(
        product_id
        for product_id, matchers in _PRODUCT_MATCHERS.items()
        if any(marker in normalized for marker in matchers)
    )


def _privacy() -> dict[str, bool]:
    return {
        "raw_file_contents_collected": False,
        "prompts_collected": False,
        "browser_history_collected": False,
        "cookies_collected": False,
        "secrets_or_tokens_collected": False,
        "account_identifiers_collected": False,
        "persistent_state_written": False,
    }


def _product_record(
    *, product_id: str, evidence: set[str], versions: set[str]
) -> dict[str, object]:
    product = next(item for item in _PRODUCTS if item.id == product_id)
    return {
        "id": product.id,
        "name": product.name,
        "provider": product.provider,
        "category": product.category,
        "presence": "present" if evidence else "unknown",
        "version": next(iter(versions)) if len(versions) == 1 else "unknown",
        "evidence_types": sorted(evidence),
        "approval_status": "unknown",
        "account": {"status": "unknown", "identifiers_collected": False},
    }


def collect_windows_endpoint_metadata(
    *, registry: WindowsUninstallRegistry | None = None
) -> dict[str, object]:
    """Return schema-compatible installed-product facts from fixed registry views."""

    source = registry or LocalWindowsUninstallRegistry()
    evidence = {product.id: set() for product in _PRODUCTS}
    versions = {product.id: set() for product in _PRODUCTS}
    errors = list(_WINDOWS_LIMITATIONS)
    try:
        entries = source.uninstall_entries()
    except WindowsRegistryLimitReached:
        entries = ()
        errors.append({"source": "windows_registry", "code": "limit_reached"})
    except WindowsRegistryUnavailable:
        entries = ()
        errors.append({"source": "windows_registry", "code": "unavailable"})

    for entry in entries:
        for product_id in _matched_product_ids(entry.get("display_name")):
            evidence[product_id].add("windows_uninstall_registry")
            version = _safe_text(entry.get("display_version"))
            if version != "unknown":
                versions[product_id].add(version)

    products = [
        _product_record(
            product_id=product.id,
            evidence=evidence[product.id],
            versions=versions[product.id],
        )
        for product in _PRODUCTS
    ]
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "completed",
        "collection_mode": "one_shot_read_only",
        "network_used": False,
        "products": products,
        "extensions": [],
        "configurations": [],
        "errors": sorted(errors, key=lambda item: (item["source"], item["code"])),
        "limits": {"max_registry_entries": _MAX_UNINSTALL_ENTRIES},
        "summary": {
            "products_present": sum(
                item["presence"] == "present" for item in products
            ),
            "extensions": 0,
            "configurations": 0,
            "errors": len(errors),
        },
        "privacy": _privacy(),
    }


__all__ = [
    "LocalWindowsUninstallRegistry",
    "WindowsRegistryLimitReached",
    "WindowsRegistryUnavailable",
    "WindowsUninstallRegistry",
    "collect_windows_endpoint_metadata",
]
