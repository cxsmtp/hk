from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from app.services.sensitive_data_detection_service import (
    API_KEY_PATTERN,
    CC_PATTERN,
    EMAIL_PATTERN,
    EMIRATES_ID_CONTEXT_PATTERN,
    EMIRATES_ID_STRICT_PATTERN,
    PHONE_PATTERN,
    detect_sensitive_data,
    private_sensitive_spans,
)

_TOKEN_PATTERN = re.compile(r"\[\[HAWK_[A-Z_]+_[a-z]{24}_[0-9]{4}\]\]")


class MaskingError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ReversibleMaskingPolicy:
    enabled: bool = False
    restore_to_authenticated_caller: bool = True
    mapping_ttl_seconds: int = 120
    max_text_chars: int = 60000
    documents_enabled: bool = False
    max_document_bytes: int = 10485760
    max_document_pages: int = 100

    @classmethod
    def from_scope(cls, raw: Any) -> "ReversibleMaskingPolicy":
        if raw is None:
            return cls()
        if not isinstance(raw, dict):
            raise MaskingError("invalid_reversible_masking_policy")
        enabled = raw.get("enabled", False)
        if not isinstance(enabled, bool):
            raise MaskingError("invalid_reversible_masking_policy")
        if not enabled:
            return cls()
        values = {}
        for key, low, high, default in (
            ("mapping_ttl_seconds", 30, 300, 120),
            ("max_text_chars", 1000, 100000, 60000),
            ("max_document_bytes", 1048576, 10485760, 10485760),
            ("max_document_pages", 1, 100, 100),
        ):
            value = raw.get(key, default)
            if isinstance(value, bool) or not isinstance(value, int):
                raise MaskingError("invalid_reversible_masking_policy")
            values[key] = max(low, min(high, value))
        for key in ("restore_to_authenticated_caller", "documents_enabled"):
            value = raw.get(key, key == "restore_to_authenticated_caller")
            if not isinstance(value, bool):
                raise MaskingError("invalid_reversible_masking_policy")
            values[key] = value
        return cls(enabled=True, **values)


@dataclass(slots=True, repr=False)
class MaskingSession:
    policy: ReversibleMaskingPolicy
    _nonce: str = field(default_factory=lambda: "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(24)), repr=False)
    _deadline: float = field(init=False, repr=False)
    _values: dict[str, str] = field(default_factory=dict, repr=False)
    _tokens: dict[str, str] = field(default_factory=dict, repr=False)
    _kinds: dict[str, str] = field(default_factory=dict, repr=False)
    _counts: dict[str, int] = field(default_factory=dict, repr=False)
    _occurrences: dict[str, int] = field(default_factory=dict, repr=False)
    _destroyed: bool = False

    def __post_init__(self) -> None:
        self._deadline = time.monotonic() + self.policy.mapping_ttl_seconds

    def _check_live(self) -> None:
        if self._destroyed or time.monotonic() >= self._deadline:
            self.destroy()
            raise MaskingError("masking_session_expired")

    def discover(self, text: str) -> None:
        self._check_live()
        if "[[HAWK_" in text:
            raise MaskingError("reserved_masking_token")
        for start, end, kind in private_sensitive_spans(text):
            self._kinds.setdefault(text[start:end], kind)

    def mask(self, text: str) -> str:
        self.discover(text)
        candidates: list[tuple[int, int, str]] = []
        for value, kind in self._kinds.items():
            start = text.find(value)
            while start >= 0:
                candidates.append((start, start + len(value), kind))
                start = text.find(value, start + 1)
        candidates.sort(key=lambda row: (row[0], -(row[1] - row[0])))
        spans: list[tuple[int, int, str]] = []
        for start, end, kind in candidates:
            if spans and start < spans[-1][1]:
                continue
            spans.append((start, end, kind))
        parts: list[str] = []
        cursor = 0
        for start, end, kind in spans:
            value = text[start:end]
            token = self._values.get(value)
            if token is None:
                index = self._counts.get(kind, 0) + 1
                self._counts[kind] = index
                token = f"[[HAWK_{kind.upper()}_{self._nonce}_{index:04d}]]"
                self._values[value] = token
                self._tokens[token] = value
            self._occurrences[token] = self._occurrences.get(token, 0) + 1
            parts.extend((text[cursor:start], token))
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts)

    def restore(self, text: str) -> str:
        self._check_live()
        if "[[HAWK_" not in text:
            return text
        matches = list(_TOKEN_PATTERN.finditer(text))
        residue = _TOKEN_PATTERN.sub("", text)
        if "[[HAWK_" in residue:
            raise MaskingError("invalid_masking_token")
        output_counts: dict[str, int] = {}
        for match in matches:
            token = match.group()
            if token not in self._tokens:
                raise MaskingError("foreign_masking_token")
            output_counts[token] = output_counts.get(token, 0) + 1
            if output_counts[token] > max(8, self._occurrences[token] * 4):
                raise MaskingError("masking_expansion_limit")
        return _TOKEN_PATTERN.sub(lambda match: self._tokens[match.group()], text)

    def metadata(self) -> dict[str, Any]:
        return {"enabled": True, "applied": bool(self._tokens), "entity_type_counts": dict(self._counts), "mapping_destroyed": self._destroyed}

    def destroy(self) -> None:
        self._values.clear()
        self._tokens.clear()
        self._kinds.clear()
        self._counts.clear()
        self._occurrences.clear()
        self._destroyed = True

SENSITIVE_PATTERNS = [
    EMAIL_PATTERN,
    PHONE_PATTERN,
    CC_PATTERN,
    API_KEY_PATTERN,
    EMIRATES_ID_STRICT_PATTERN,
    EMIRATES_ID_CONTEXT_PATTERN,
]

HIDDEN_INSTRUCTION_PATTERNS = [
    re.compile(r"ignore\s+all\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+hidden\s+system", re.IGNORECASE),
    re.compile(r"override\s+policy", re.IGNORECASE),
]

MAX_PROMPT_CHARS_STRICT = 2500
MAX_PROMPT_CHARS_BALANCED = 5000


def _redact_text(value: str) -> tuple[str, bool]:
    redacted = str(value or "")
    changed = False
    for pattern in SENSITIVE_PATTERNS:
        next_value = pattern.sub("[REDACTED]", redacted)
        if next_value != redacted:
            changed = True
        redacted = next_value
    return redacted, changed


def minimization_mode(*, data_sensitivity: str, policy_profile: dict[str, Any]) -> str:
    policy_mode = str(policy_profile.get("minimization_mode") or "").strip().lower()
    if policy_mode in {"strict", "balanced", "permissive"}:
        return policy_mode
    normalized = str(data_sensitivity or "internal").strip().lower()
    if normalized == "restricted":
        return "strict"
    if normalized == "sensitive":
        return "balanced"
    return "permissive"


def minimize_prompts(
    *,
    system_prompt: str,
    user_prompt: str,
    mode: str,
    masking_session: MaskingSession | None = None,
) -> tuple[str, str, dict[str, Any]]:
    applied = str(mode or "permissive").strip().lower()
    redacted_fields: list[str] = []

    next_system = str(system_prompt or "")
    next_user = str(user_prompt or "")
    if masking_session is not None and len(next_system) + len(next_user) + 1 > masking_session.policy.max_text_chars:
        raise MaskingError("masking_text_limit")

    # Always strip clear hidden-instruction markers from retrieval/user context before outbound.
    for pattern in HIDDEN_INSTRUCTION_PATTERNS:
        next_system = pattern.sub("[REMOVED_INSTRUCTION]", next_system)
        next_user = pattern.sub("[REMOVED_INSTRUCTION]", next_user)

    if masking_session is not None:
        masking_session.discover(next_system)
        masking_session.discover(next_user)
        next_system = masking_session.mask(next_system)
        next_user = masking_session.mask(next_user)
        if len(next_system) + len(next_user) + 1 > masking_session.policy.max_text_chars:
            raise MaskingError("masking_text_limit")
    elif applied in {"strict", "balanced"}:
        redacted_system, changed_system = _redact_text(next_system)
        redacted_user, changed_user = _redact_text(next_user)
        if changed_system:
            redacted_fields.append("system_prompt")
        if changed_user:
            redacted_fields.append("user_prompt")
        next_system = redacted_system
        next_user = redacted_user

    if masking_session is None and applied == "strict":
        if len(next_system) > MAX_PROMPT_CHARS_STRICT:
            next_system = f"{next_system[:MAX_PROMPT_CHARS_STRICT]}\\n[TRUNCATED_STRICT_MODE]"
            redacted_fields.append("system_prompt_truncated")
        if len(next_user) > MAX_PROMPT_CHARS_STRICT:
            next_user = f"{next_user[:MAX_PROMPT_CHARS_STRICT]}\\n[TRUNCATED_STRICT_MODE]"
            redacted_fields.append("user_prompt_truncated")
    elif masking_session is None and applied == "balanced":
        if len(next_system) > MAX_PROMPT_CHARS_BALANCED:
            next_system = f"{next_system[:MAX_PROMPT_CHARS_BALANCED]}\\n[TRUNCATED_BALANCED_MODE]"
            redacted_fields.append("system_prompt_truncated")
        if len(next_user) > MAX_PROMPT_CHARS_BALANCED:
            next_user = f"{next_user[:MAX_PROMPT_CHARS_BALANCED]}\\n[TRUNCATED_BALANCED_MODE]"
            redacted_fields.append("user_prompt_truncated")

    detection = detect_sensitive_data(text_inputs=[system_prompt, user_prompt], correlation_id="secure-gateway-minimizer")

    entities = list(detection.get("entities") or [])
    if masking_session is not None:
        entities = [
            {"entity_type": kind, "count": count}
            for kind, count in sorted(masking_session.metadata()["entity_type_counts"].items())
        ]
    return next_system, next_user, {
        "mode": applied,
        "redacted_fields": sorted(set(redacted_fields)),
        "sensitive_detected": bool(detection.get("contains_sensitive")),
        "sensitive_confidence": float(detection.get("confidence_score") or 0.0),
        "entities": entities,
    }


def sanitize_retrieval_refs(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    for row in refs:
        if not isinstance(row, dict):
            continue
        next_row = dict(row)
        # Never forward full raw content to model in prompt context by default.
        for key in ["body", "text", "content", "raw", "raw_content", "document"]:
            if key in next_row:
                value = str(next_row.get(key) or "")
                redacted, _changed = _redact_text(value)
                next_row[key] = f"{redacted[:350]}[TRUNCATED_RETRIEVAL]" if redacted else "[REMOVED]"

        for key, value in list(next_row.items()):
            if isinstance(value, str):
                updated = value
                for pattern in HIDDEN_INSTRUCTION_PATTERNS:
                    updated = pattern.sub("[REMOVED_INSTRUCTION]", updated)
                next_row[key] = updated
        sanitized.append(next_row)
    return sanitized
