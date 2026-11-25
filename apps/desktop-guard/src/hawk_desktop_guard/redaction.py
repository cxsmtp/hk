"""Local redaction of a prompt before anything about it leaves the machine.

The patterns mirror the API's sensitive-data detection (apps/api/app/services/sensitive_data_detection_service.py)
and the guard's own secret checks (local_policy.py). Each finding is replaced by a typed placeholder such as
``[REDACTED:EMAIL]``, and the entity types found are reported so the API can still apply its sensitive-data policy
without seeing the values. The preview is redacted first and only then shortened, so a value cut in half by the
limit is never partly kept.
"""

from __future__ import annotations

from dataclasses import dataclass
import re


#: The longest redacted preview sent to the API (characters, before the truncation marker).
PREVIEW_MAX_CHARS = 512
TRUNCATION_MARKER = " …[truncated]"

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_BEARER = re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)[A-Za-z0-9_\-./+=]{8,}")
_PREFIXED_SECRET = re.compile(
    r"\b(?:sk|pk|rk)[-_][A-Za-z0-9_\-]{10,}\b"
    r"|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{10,}\b"
    r"|\bgithub_pat_[A-Za-z0-9_]{10,}\b"
    r"|\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"
    r"|\bAIza[A-Za-z0-9_\-]{10,}\b"
    r"|\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    r"|\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
)
# "api_key = value", "token: value", "password=value": the label stays, the value goes.
_LABELLED_SECRET = re.compile(
    r"(?i)(\b[A-Z0-9_]*(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|secret|private[_ -]?key|token|password|"
    r"passwd|pwd|credential)s?\b\s*[:=]\s*['\"]?)([^\s'\",;]{6,})"
)
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ -]?[A-Z0-9]){11,30}\b")
_EMIRATES_ID = re.compile(r"(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)")
_CARD = re.compile(r"(?<!\d)\d(?:[ -]?\d){12,18}(?!\d)")
_PHONE = re.compile(r"(?<!\d)\+?\d[\d\s().-]{7,}\d(?!\d)")
_ISO_DATETIME = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d{1,6})?)?)?\b")


@dataclass(frozen=True)
class RedactedPrompt:
    preview: str
    entity_types: tuple[str, ...]
    truncated: bool
    length: int


def _luhn_valid(number: str) -> bool:
    digits = [int(char) for char in number if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def redact_text(text: str) -> tuple[str, tuple[str, ...]]:
    """The text with every finding replaced by a typed placeholder, and the entity types found (API names)."""

    found: list[str] = []

    def placeholder(entity_type: str, label: str):
        def replace(match: re.Match[str]) -> str:
            found.append(entity_type)
            return f"[REDACTED:{label}]"

        return replace

    def keep_label(entity_type: str, label: str):
        def replace(match: re.Match[str]) -> str:
            found.append(entity_type)
            return f"{match.group(1)}[REDACTED:{label}]"

        return replace

    value = str(text or "")
    value = _PRIVATE_KEY_BLOCK.sub(placeholder("api_key", "PRIVATE_KEY"), value)
    value = _BEARER.sub(keep_label("api_key", "TOKEN"), value)
    value = _PREFIXED_SECRET.sub(placeholder("api_key", "SECRET"), value)
    value = _LABELLED_SECRET.sub(keep_label("api_key", "SECRET"), value)
    value = _EMAIL.sub(placeholder("email", "EMAIL"), value)
    value = _IBAN.sub(placeholder("bank_account", "IBAN"), value)
    value = _EMIRATES_ID.sub(placeholder("emirates_id", "EMIRATES_ID"), value)

    def card(match: re.Match[str]) -> str:
        if not _luhn_valid(match.group(0)):
            return match.group(0)
        found.append("credit_card")
        return "[REDACTED:CARD]"

    value = _CARD.sub(card, value)

    def phone(match: re.Match[str]) -> str:
        candidate = match.group(0)
        if _ISO_DATETIME.search(candidate):
            return candidate
        if sum(char.isdigit() for char in candidate) < 8:
            return candidate
        found.append("phone")
        return "[REDACTED:PHONE]"

    value = _PHONE.sub(phone, value)
    return value, tuple(sorted(set(found)))


def redact_prompt(text: str, *, max_chars: int = PREVIEW_MAX_CHARS) -> RedactedPrompt:
    """The preview the API may keep: redacted, then cut to ``max_chars``."""

    original = str(text or "")
    redacted, entity_types = redact_text(original)
    truncated = len(redacted) > max_chars
    preview = redacted[:max_chars] + TRUNCATION_MARKER if truncated else redacted
    return RedactedPrompt(preview=preview, entity_types=entity_types, truncated=truncated, length=len(original))
