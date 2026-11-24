from __future__ import annotations

from typing import Any


def build_diagnostics(collector: Any) -> dict[str, Any]:
    snapshot = collector.collect()
    clipboard = _call_text(collector, "_clipboard_text")
    return {
        "application": getattr(collector, "application", None),
        "desktop_app": getattr(collector, "desktop_app", None),
        "active_app": _call_text(collector, "_active_window_title") or None,
        "accessibility_status": _accessibility_status(collector),
        "focused_text_length": _focused_text_length(collector),
        "clipboard_length": len(clipboard),
        "snapshot": snapshot.to_api_payload() if snapshot is not None else None,
    }


def _call_text(target: Any, method_name: str) -> str:
    method = getattr(target, method_name, None)
    if not callable(method):
        return ""
    try:
        return str(method() or "")
    except Exception:
        return ""


def _accessibility_status(collector: Any) -> str | None:
    controller = getattr(collector, "accessibility_controller", None)
    status = getattr(controller, "accessibility_status", None)
    if callable(status):
        try:
            return str(status() or "") or None
        except Exception:
            return "error"
    return None


def _focused_text_length(collector: Any) -> int | None:
    controller = getattr(collector, "accessibility_controller", None)
    reader = getattr(controller, "read_focused_text", None)
    if callable(reader):
        try:
            return len(str(reader() or ""))
        except Exception:
            return None
    return None
