from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit


BINARY_OMITTED = "[omitted:binary]"
HASHED_ONLY = "[hashed_only]"
REDACTED = "[redacted]"

SENSITIVE_KEYWORDS = {
    "arguments",
    "raw_prompt",
    "prompt",
    "prompt_raw",
    "prompt_text",
    "prompt_or_content",
    "original_intent",
    "intent",
    "extracted_text",
    "ocr_text",
    "text_preview",
    "copied_text",
    "copied_text_preview",
    "file_text",
    "file_content",
    "response_text",
    "output_text",
    "tool_arguments",
}

RAW_MATERIAL_KEYS = {
    "args",
    "arguments",
    "kwargs",
    "prompt",
    "prompt_or_content",
    "prompt_raw",
    "prompt_text",
    "raw_prompt",
    "request_body",
    "response_body",
    "tool_args",
    "tool_arguments",
}

BINARY_KEYS = {
    "content_b64",
    "content_base64",
    "image_b64",
    "image_base64",
    "screenshot_b64",
    "screenshot_base64",
    "file_b64",
    "file_base64",
    "bytes",
    "binary",
}

TOKEN_KEYS = {
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "set_cookie",
    "api_key",
    "secret",
    "token",
    "password",
}

URL_KEYS = {"url", "current_url", "active_url", "tab_url", "source_url", "target_url"}


def _is_identifier_key(normalized: str) -> bool:
    # Server-generated identifiers and digests are already opaque. Running
    # phone/card regexes over hex digests corrupts integrity evidence.
    return (
        normalized == "id"
        or normalized.endswith("_id")
        or normalized.endswith("_ids")
        or normalized.endswith("_hash")
        or normalized.endswith("_fingerprint")
    )

def _is_chatgpt_desktop_version_path(path: tuple[str, ...]) -> bool:
    """Preserve signed application-version metadata, never arbitrary text."""

    return len(path) >= 2 and path[-2:] == ("chatgpt_desktop", "version")


EMAIL_RE = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d\-\s().]{7,}\d)(?!\d)")
# Record ids (UUIDs) and hex digests: a digit run inside one is not a phone or card number, and masking it would make
# the id stop matching its record.
IDENTIFIER_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32,})(?![0-9A-Fa-f])"
)
CC_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
# A date, or a date and time, as the system writes them (ISO 8601, also inside a file name such as
# backup-2026-11-25T10-00-00Z): kept as they are, never taken for a phone number. Only real calendar dates (years
# 1900-2099, months 01-12, days 01-31), so a phone number written with dashes is still redacted.
ISO_DATETIME_RE = re.compile(
    r"(?<![\d.+])(?<!\+\d )(?<!\+\d\d )(?<!\+\d\d\d )(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])"
    r"(?:[T ][0-2]\d([:-])[0-5]\d(?:\1[0-5]\d(?:\.\d{1,9})?)?(?:Z|[+-][0-2]\d:?[0-5]\d)?)?(?![\d])"
)
# An IPv4 address (four numbers of 0-255, no leading zeros), such as the address a sign-in came from: kept as it is,
# never taken for a phone number. Not when part of a longer run of dotted numbers.
IPV4_RE = re.compile(
    r"(?<![\d.+])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?!\d|\.\d)"
)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?:sk-[a-z0-9_-]{8,}|(?:api[_ -]?key|secret|token|password|private[_ -]?key)\b\s*[:=]\s*[a-z0-9_./+=:-]{6,})"
)
BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}")


def _preserve_iso_datetimes(text: str) -> tuple[str, dict[str, str]]:
    """Dates, times and IPv4 addresses put aside (as tokens with no numbers in them) while phone and card numbers are
    looked for."""

    preserved: dict[str, str] = {}

    def replace(match: re.Match[str]) -> str:
        token = f"__HAWK_PRESERVED_{_letters(len(preserved))}__"
        preserved[token] = match.group(0)
        return token

    text = IDENTIFIER_RE.sub(replace, text)
    text = ISO_DATETIME_RE.sub(replace, text)
    return IPV4_RE.sub(replace, text), preserved


def _letters(n: int) -> str:
    """0 -> A, 25 -> Z, 26 -> BA: a token's number in letters, so it never looks like part of a phone number."""

    out = ""
    while True:
        out = chr(ord("A") + n % 26) + out
        n //= 26
        if n == 0:
            return out


def _restore_preserved_text(text: str, preserved: dict[str, str]) -> str:
    for token, original in preserved.items():
        text = text.replace(token, original)
    return text


def redact_sensitive_text(value: Any, *, max_len: int = 512) -> str:
    text = str(value or "")
    if not text:
        return ""
    text = BEARER_RE.sub("Bearer [token]", text)
    text = SECRET_ASSIGNMENT_RE.sub("[secret]", text)
    text = EMAIL_RE.sub("[email]", text)
    text, preserved_iso_datetimes = _preserve_iso_datetimes(text)
    text = PHONE_RE.sub("[phone]", text)
    text = CC_RE.sub("[credit_card]", text)
    text = _restore_preserved_text(text, preserved_iso_datetimes)
    if len(text) > max_len:
        return f"{text[:max_len]}...[truncated]"
    return text


def strip_url_query(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return REDACTED
    if not parsed.scheme or not hostname:
        return redact_sensitive_text(raw)
    safe_hostname = f"[{hostname}]" if ":" in hostname else hostname
    safe_netloc = f"{safe_hostname}:{port}" if port is not None else safe_hostname
    return urlunsplit((parsed.scheme, safe_netloc, parsed.path or "/", "", ""))


def _normalized_key(key: Any) -> str:
    text = str(key or "").strip()
    text = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", text)
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", text)
    return re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_").lower()


def _is_raw_material_key(normalized: str) -> bool:
    return (
        normalized in RAW_MATERIAL_KEYS
        or normalized.endswith(
            (
                "_arguments",
                "_args",
                "_kwargs",
                "_prompt",
                "_prompt_or_content",
                "_prompt_raw",
                "_prompt_text",
            )
        )
    )


def sanitize_privacy_payload(value: Any, *, max_depth: int = 6) -> Any:
    return _sanitize_value(value, key="", path=(), depth=0, max_depth=max_depth)


def sanitize_privacy_scalar(value: Any, *, key: str = "") -> Any:
    """Sanitize one pre-bounded scalar while preserving field-key semantics."""

    if isinstance(value, (dict, list, tuple, set, frozenset)):
        raise TypeError("sanitize_privacy_scalar only accepts scalar values")
    return _sanitize_value(
        value,
        key=key,
        path=(_normalized_key(key),) if key else (),
        depth=0,
        max_depth=0,
    )


def _sanitize_value(
    value: Any,
    *,
    key: str,
    path: tuple[str, ...],
    depth: int,
    max_depth: int,
) -> Any:
    normalized = _normalized_key(key)
    if depth > max_depth:
        return "[omitted:max_depth]"
    if _is_raw_material_key(normalized):
        return HASHED_ONLY
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize_value(
                item_value,
                key=str(item_key),
                path=(*path, _normalized_key(item_key)),
                depth=depth + 1,
                max_depth=max_depth,
            )
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [
            _sanitize_value(
                item,
                key=key,
                path=path,
                depth=depth + 1,
                max_depth=max_depth,
            )
            for item in value
        ]

    if normalized in BINARY_KEYS or normalized.endswith("_b64") or normalized.endswith("_base64"):
        return BINARY_OMITTED
    if normalized in TOKEN_KEYS or any(token in normalized for token in ("secret", "password", "api_key", "access_token", "refresh_token")):
        return REDACTED
    if _is_identifier_key(normalized):
        text = str(value)
        if len(text) > 1024:
            return f"{text[:1024]}...[truncated]"
        return value
    if _is_chatgpt_desktop_version_path(path):
        text = str(value)
        if len(text) > 128:
            return f"{text[:128]}...[truncated]"
        return value
    if normalized in URL_KEYS:
        return strip_url_query(value)
    if normalized in SENSITIVE_KEYWORDS:
        return redact_sensitive_text(value)

    text = str(value)
    if text.startswith(("http://", "https://")):
        return strip_url_query(text)

    redacted = redact_sensitive_text(text)
    if redacted != text:
        return redacted
    if len(text) > 1024:
        return f"{text[:1024]}...[truncated]"
    return value
