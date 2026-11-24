"""Privacy boundary for endpoint-local persistence."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Iterable

_LABEL_RE = re.compile(r"[^a-zA-Z0-9._:/@-]+")
_RAW_KEYS = {
    "prompt",
    "response",
    "response_text",
    "tool_output",
    "tool_arguments",
    "arguments",
    "copied_text",
    "clipboard",
    "document",
    "body",
    "content",
    "api_key",
    "authorization",
    "password",
    "token",
    "capability_token",
    "cookie",
}
_SECRET_VALUE_RE = re.compile(
    r"(?:\bsk-[a-zA-Z0-9_-]{4,}|\bbearer\s+[a-zA-Z0-9._-]+|\bapi[_ -]?key\b)",
    re.IGNORECASE,
)


def bounded_label(value: Any, *, default: str = "unknown", limit: int = 120) -> str:
    text = str(value or "").strip()
    if not text:
        return default
    return _LABEL_RE.sub("_", text)[:limit]


def stable_fingerprint(value: Any, *, key: str = "local") -> str:
    material = str(value or "unknown").encode("utf-8", errors="ignore")
    digest = hmac.new(key.encode("utf-8"), material, hashlib.sha256).hexdigest()
    return f"sha256:{digest}"


def safe_categories(values: Iterable[Any], *, limit: int = 24) -> list[str]:
    return sorted({bounded_label(value, limit=80) for value in values if value})[:limit]


def contains_raw_key(payload: Any) -> bool:
    if isinstance(payload, dict):
        return any(str(key).lower() in _RAW_KEYS or contains_raw_key(value) for key, value in payload.items())
    if isinstance(payload, (list, tuple)):
        return any(contains_raw_key(item) for item in payload)
    return False


def redact_mapping(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Remove prohibited content fields recursively and report their key names."""
    removed: set[str] = set()

    def visit(value: Any) -> Any:
        if isinstance(value, dict):
            clean: dict[str, Any] = {}
            for key, item in value.items():
                normalized = str(key).lower()
                if normalized in _RAW_KEYS:
                    removed.add(normalized)
                    continue
                clean[str(key)] = visit(item)
            return clean
        if isinstance(value, (list, tuple)):
            return [visit(item) for item in value[:100]]
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return bounded_label(type(value).__name__, limit=80)

    return visit(payload), sorted(removed)


def safe_failure(value: Any, *, limit: int = 160) -> str:
    """Return a bounded error class, never caller-controlled request content."""
    if isinstance(value, BaseException):
        return bounded_label(type(value).__name__, limit=limit)
    return safe_reason_code(value, limit=limit)


def safe_reason_code(value: Any, *, limit: int = 120) -> str:
    text = str(value or "policy_evaluation").strip()
    if _SECRET_VALUE_RE.search(text):
        return "redacted_reason"
    return bounded_label(text, default="policy_evaluation", limit=limit)
