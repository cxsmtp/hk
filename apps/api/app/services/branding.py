"""Branding (Settings → Branding), ported from FTR Command Center's server/branding.js and the branding part of its
server/routes/branding.js: the product's name and the line under it, the organisation's name, its logo and browser
icon, the accent colour and the look (light, dark or the device's own). Hawk AI shows them in the console's menu, the
browser tab and the emails it sends (app/services/mailer.py).

Kept in ``branding.json`` in the data folder (HAWK_DATA_DIR, in every backup), for the whole installation, as FTR keeps
them in settings.json. A logo or icon is kept as bytes (base64), never as a link the browser follows: it is uploaded
(PNG, JPEG, SVG or WebP), its kind told by its first bytes (not by what the sender says), at most 200 KB for the logo
and 100 KB for the icon. It is served from /branding/logo and /branding/icon; an SVG is served with a policy that runs
nothing in it.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import re
from pathlib import Path
from typing import Any

from app.services.state_file import read_state, write_state

FILE_NAME = "branding.json"
MAX_LOGO = 200 * 1024
MAX_ICON = 100 * 1024
TYPES = {"png": "image/png", "jpeg": "image/jpeg", "svg": "image/svg+xml", "webp": "image/webp"}
MODES = ("light", "dark", "system")
DEFAULT_BRANDING: dict[str, Any] = {
    "appName": "Hawk AI",
    "tagline": "AI control plane",
    "organisationName": "",
    "accent": "",
    "mode": "dark",
    "logo": None,
    "icon": None,
}
#: Headers for a kept image: an SVG runs nothing, whatever it holds (FTR's imageHeaders).
IMAGE_HEADERS = {
    "Cache-Control": "public, max-age=86400",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
    "Cross-Origin-Resource-Policy": "cross-origin",
}


class BrandingError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def data_dir() -> Path:
    from app.core.config import settings

    return Path(str(settings.hawk_data_dir or ".runtime/data"))


def load(directory: Path | None = None) -> dict[str, Any]:
    """The branding in force (the defaults for anything not set). A file that cannot be read gives the defaults: the
    console and the emails never stop for a name or a logo."""

    try:
        saved = read_state((directory or data_dir()) / FILE_NAME, fallback={}, holds="the branding")
    except Exception:  # noqa: BLE001
        saved = {}
    out = {**DEFAULT_BRANDING, **(saved if isinstance(saved, dict) else {})}
    if out.get("mode") not in MODES:
        out["mode"] = DEFAULT_BRANDING["mode"]
    return out


def save(value: dict[str, Any], directory: Path | None = None) -> None:
    folder = directory or data_dir()
    folder.mkdir(parents=True, exist_ok=True)
    write_state(folder / FILE_NAME, value)


def app_name(directory: Path | None = None) -> str:
    return str(load(directory).get("appName") or DEFAULT_BRANDING["appName"])


def sniff(data: bytes) -> str | None:
    """What kind of image these bytes are, by their first bytes."""

    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    head = data[:512].decode("utf-8", errors="ignore").lstrip("﻿").lstrip()
    if re.match(r"^(<\?xml[^>]*>\s*)?(<!--[\s\S]*?-->\s*)*(<!DOCTYPE svg[^>]*>\s*)?<svg[\s>]", head, re.IGNORECASE):
        return "svg"
    return None


def image_from_upload(value: Any, what: str, limit: int) -> dict[str, Any]:
    """An uploaded image, sent as a data: URL or bare base64: bytes of a known kind, within the size."""

    text = str(value or "")
    found = re.match(r"^data:[^;,]*;base64,(.*)$", text, re.DOTALL)
    try:
        data = base64.b64decode(found.group(1) if found else text, validate=False)
    except (binascii.Error, ValueError) as error:
        raise BrandingError(f"{what} could not be read.") from error
    if not data:
        raise BrandingError(f"{what} is empty.")
    if len(data) > limit:
        raise BrandingError(f"{what} is {round(len(data) / 1024)} KB: at most {limit // 1024} KB.", 413)
    kind = sniff(data)
    if not kind:
        raise BrandingError(f"{what} is not a PNG, JPEG, SVG or WebP image.", 415)
    return {"type": TYPES[kind], "data": base64.b64encode(data).decode("ascii"), "bytes": len(data), "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")}


def clean_colour(value: Any) -> str:
    """#rrggbb, or '' for the look's own."""

    text = str(value or "").strip().lower()
    if not text:
        return ""
    if not re.fullmatch(r"#[0-9a-f]{6}", text):
        raise BrandingError("Choose the accent colour as #rrggbb.")
    return text


def _clean(value: Any, limit: int) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "", str(value or "")).strip()[:limit]


def merge(current: dict[str, Any], body: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """What an administrator sent, checked first (a refused change leaves everything as it was). Returns the new
    branding and what changed."""

    out = dict(current)
    changed: list[str] = []
    if "appName" in body:
        out["appName"] = _clean(body.get("appName"), 40) or DEFAULT_BRANDING["appName"]
        changed.append("app name")
    if "tagline" in body:
        out["tagline"] = _clean(body.get("tagline"), 40)
        changed.append("tagline")
    if "organisationName" in body:
        name = _clean(body.get("organisationName"), 120)
        if not name:
            raise BrandingError("Give the company name: it is on every report.")
        out["organisationName"] = name
        changed.append("company name")
    if "accent" in body:
        out["accent"] = clean_colour(body.get("accent"))
        changed.append("accent colour")
    if "mode" in body:
        if body.get("mode") not in MODES:
            raise BrandingError("Choose light, dark or system.")
        out["mode"] = body["mode"]
        changed.append("mode")
    for key, what, limit in (("logo", "The logo", MAX_LOGO), ("icon", "The browser icon", MAX_ICON)):
        if key not in body:
            continue
        value = body.get(key)
        if value is None:
            out[key] = None
        elif isinstance(value, dict) and isinstance(value.get("upload"), str):
            out[key] = image_from_upload(value["upload"], what, limit)
        else:
            raise BrandingError(f"{what}: upload one.")
        changed.append(key)
    return out, changed


def public_view(value: dict[str, Any], organisation: str = "") -> dict[str, Any]:
    """What every page may know (no image bytes: those are at /branding/logo and /branding/icon)."""

    logo, icon = value.get("logo"), value.get("icon")
    return {
        "appName": value.get("appName") or DEFAULT_BRANDING["appName"],
        "tagline": value.get("tagline") or "",
        "organisationName": value.get("organisationName") or organisation,
        "accent": value.get("accent") or "",
        "mode": value.get("mode") or DEFAULT_BRANDING["mode"],
        "logo": f"/branding/logo?v={logo['at']}" if isinstance(logo, dict) else None,
        "icon": f"/branding/icon?v={icon['at']}" if isinstance(icon, dict) else None,
        "logoBytes": int(logo.get("bytes") or 0) if isinstance(logo, dict) else 0,
        "iconBytes": int(icon.get("bytes") or 0) if isinstance(icon, dict) else 0,
        "limits": {"logo": MAX_LOGO, "icon": MAX_ICON},
    }


def image(key: str, directory: Path | None = None) -> tuple[bytes, str] | None:
    kept = load(directory).get(key)
    if not isinstance(kept, dict) or not kept.get("data"):
        return None
    return base64.b64decode(kept["data"]), str(kept.get("type") or "application/octet-stream")
