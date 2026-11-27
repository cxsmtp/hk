from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
from typing import Any
import unicodedata
from urllib.parse import unquote_to_bytes, urlsplit, urlunsplit

from app.core.config import (
    settings,
    siem_pseudonymization_key_is_obviously_predictable,
)
from app.services.pci_controls import scrub_pan_value
from app.services.outbound_destination_policy import (
    OutboundDestinationPolicy,
    OutboundDestinationPolicyError,
    PinnedHTTPTransport,
    request_with_redirect_validation,
)
from app.services.privacy_sanitizer import (
    redact_sensitive_text,
    sanitize_privacy_scalar,
)


OCSF_ALIGNED_SCHEMA = "ocsf-1.1.0-aligned"
SENTINEL_SCHEMA = f"microsoft-sentinel-custom-log-v1+{OCSF_ALIGNED_SCHEMA}"
MAX_EXPORT_EVENTS = 500
MAX_EXPORT_INPUT_BYTES = 1_048_576
MAX_EXPORT_JSON_DEPTH = 16
MAX_EXPORT_JSON_ITEMS = 20_000
MAX_EXPORT_JSON_NODES = 20_000
MAX_EXPORT_JSON_STRING_CHARS = 1_048_576
MAX_NORMALIZED_TEXT_CHARS = 8_192
MAX_PERCENT_DECODE_ROUNDS = 4


@dataclass(frozen=True)
class SIEMExportBatch:
    ndjson: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class SIEMWebhookResponse:
    status_code: int


class SIEMExportError(ValueError):
    """Base error for fail-closed SIEM export operations."""


class SIEMExportDisabledError(SIEMExportError):
    """The SIEM exporter is disabled by configuration."""


class SIEMTenantScopeError(SIEMExportError):
    """An export batch contains data outside its declared tenant."""


class SIEMUnsupportedAdapterError(SIEMExportError):
    """The requested schema adapter is not implemented."""


class SIEMExportSizeError(SIEMExportError):
    """The export input or serialized payload exceeds a hard safety bound."""


class SIEMInvalidDestinationError(SIEMExportError):
    """The webhook destination failed the outbound safety policy."""


class SIEMDeliveryError(RuntimeError):
    """A validated SIEM webhook delivery did not complete successfully."""

    def __init__(self, message: str, *, metadata: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.metadata = dict(metadata or {})


_SAFE_TRANSPORT_FAILURES = {
    "TimeoutError": ("TimeoutError", "timeout"),
    "ConnectTimeout": ("ConnectTimeout", "timeout"),
    "ReadTimeout": ("ReadTimeout", "timeout"),
    "WriteTimeout": ("WriteTimeout", "timeout"),
    "PoolTimeout": ("PoolTimeout", "timeout"),
    "ConnectionError": ("ConnectionError", "connection_error"),
    "ConnectError": ("ConnectError", "connection_error"),
    "NetworkError": ("NetworkError", "connection_error"),
    "RemoteProtocolError": ("RemoteProtocolError", "connection_error"),
}
_SAFE_DESTINATION_POLICY_FAILURE = ("DestinationPolicyError", "policy_rejected")
_TENANT_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
_EMAIL_DOMAIN_LABEL_RE = re.compile(
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z",
    re.IGNORECASE,
)
_EMAIL_ASCII_ATEXT = frozenset("!#$%&'*+-/=?^_`{|}~")
_EMAIL_TOKEN_DELIMITERS = frozenset("()<>[]{}:,;\"'\\/|!?&#=")
_EMAIL_DOT_EQUIVALENTS = frozenset({".", "\u3002", "\uff0e", "\uff61"})
_EMAIL_DOT_TRANSLATION = str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."})
_MAX_EMAIL_CANDIDATES = 128
_ACTOR_IDENTIFIER_ALIASES = (
    "user_id",
    "actor_user_id",
    "actor_id",
    "user_email",
    "actor_email",
    "account_id",
    "account_user_id",
    "account_actor_id",
    "account_email",
)


def _safe_transport_failure_metadata(error: Exception) -> dict[str, str]:
    error_class, reason = _SAFE_TRANSPORT_FAILURES.get(
        type(error).__name__,
        ("TransportError", "request_failed"),
    )
    return {
        "delivery_error_class": error_class,
        "delivery_error_reason": reason,
    }


def _validated_pseudonymization_key() -> str:
    key = str(settings.siem_pseudonymization_key or "").strip()
    if len(key) < 32:
        raise SIEMExportError("SIEM_PSEUDONYMIZATION_KEY is not safely configured")
    if siem_pseudonymization_key_is_obviously_predictable(key):
        raise SIEMExportError(
            "SIEM_PSEUDONYMIZATION_KEY uses obvious predictable material"
        )
    return key


def _normalize_tenant_id(value: Any) -> str:
    if type(value) is not str:
        raise SIEMTenantScopeError("SIEM export tenant_id must be a string")
    if _TENANT_ID_RE.fullmatch(value) is None:
        raise SIEMTenantScopeError(
            "SIEM export tenant_id must match the ASCII grammar [A-Za-z0-9._:-] "
            "and be at most 128 characters"
        )
    tenant_id = _normalize_untrusted_text(value)
    return tenant_id


def _normalize_untrusted_text(value: str) -> str:
    text = unicodedata.normalize("NFKC", value)
    if len(text) > MAX_NORMALIZED_TEXT_CHARS:
        raise SIEMExportSizeError(
            f"SIEM export normalized text limit is {MAX_NORMALIZED_TEXT_CHARS}"
        )
    for _ in range(MAX_PERCENT_DECODE_ROUNDS):
        decoded = unicodedata.normalize("NFKC", _strict_percent_decode(text))
        if len(decoded) > MAX_NORMALIZED_TEXT_CHARS:
            raise SIEMExportSizeError(
                f"SIEM export normalized text limit is {MAX_NORMALIZED_TEXT_CHARS}"
            )
        if decoded == text:
            return text
        text = decoded
    if unicodedata.normalize("NFKC", _strict_percent_decode(text)) != text:
        raise SIEMExportError("SIEM export percent decode limit exceeded")
    return text


def _strict_percent_decode(value: str) -> str:
    decoding_failed = False
    decoded = ""
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except UnicodeError:
        decoding_failed = True
    if decoding_failed:
        raise SIEMExportError("invalid SIEM export text encoding") from None
    return decoded


def _is_email_token_boundary(value: str) -> bool:
    category = unicodedata.category(value)
    return (
        value.isspace()
        or value in _EMAIL_TOKEN_DELIMITERS
        or category.startswith("C")
        or category[0] in {"P", "S"}
    )


def _is_email_domain_character(value: str) -> bool:
    category = unicodedata.category(value)
    return (
        value in _EMAIL_DOT_EQUIVALENTS | {"-"}
        or category[0] in {"L", "N"}
        or category in {"Mc", "Mn"}
    )


def _is_email_local_character(value: str) -> bool:
    category = unicodedata.category(value)
    if ord(value) < 128:
        return value == "." or value in _EMAIL_ASCII_ATEXT or value.isalnum()
    return (
        not value.isspace()
        and category not in {"Cc", "Cf", "Cs", "Co", "Cn"}
    )


def _is_plausible_email_local_part(value: str) -> bool:
    if not value or len(value) > 64 or len(value.encode("utf-8")) > 64:
        return False
    if value.startswith(".") or value.endswith(".") or ".." in value:
        return False
    return all(_is_email_local_character(character) for character in value)


def _is_idna_valid_email_domain(value: str) -> bool:
    domain = value.translate(_EMAIL_DOT_TRANSLATION)
    if not domain or len(domain) > 253:
        return False
    labels = domain.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return False
    encoded_labels: list[str] = []
    for label in labels:
        if (
            label.startswith("-")
            or label.endswith("-")
            or any(unicodedata.category(character).startswith("C") for character in label)
        ):
            return False
        try:
            encoded_label = label.encode("idna").decode("ascii")
        except UnicodeError:
            return False
        if _EMAIL_DOMAIN_LABEL_RE.fullmatch(encoded_label) is None:
            return False
        encoded_labels.append(encoded_label)
    encoded_domain = ".".join(encoded_labels)
    return len(encoded_domain.encode("ascii")) <= 253 and not encoded_labels[-1].isdigit()


def _plausible_email_spans(value: str) -> list[tuple[int, int]]:
    at_positions = [index for index, character in enumerate(value) if character == "@"]
    if len(at_positions) > _MAX_EMAIL_CANDIDATES:
        raise SIEMExportSizeError(
            f"SIEM export email candidate limit is {_MAX_EMAIL_CANDIDATES}"
        )
    spans: list[tuple[int, int]] = []
    for at_index in at_positions:
        left = at_index
        while left > 0 and _is_email_local_character(value[left - 1]):
            left -= 1
        if left > 0:
            preceding_character = value[left - 1]
            if (
                unicodedata.category(preceding_character).startswith("C")
                and not preceding_character.isspace()
            ):
                continue
            if not _is_email_token_boundary(preceding_character):
                continue
        right = at_index + 1
        while right < len(value) and _is_email_domain_character(value[right]):
            right += 1
        if right < len(value) and not _is_email_token_boundary(value[right]):
            continue
        local_part = value[left:at_index]
        if not _is_plausible_email_local_part(local_part):
            continue
        domain_end = right
        while domain_end > at_index + 1:
            domain = value[at_index + 1 : domain_end]
            if _is_idna_valid_email_domain(domain):
                spans.append((left, domain_end))
                break
            if unicodedata.category(value[domain_end - 1])[0] not in {"P", "S"}:
                break
            domain_end -= 1
    return spans


def _replace_plausible_emails(value: str) -> str:
    spans = _plausible_email_spans(value)
    if not spans:
        return value
    parts: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        parts.extend((value[cursor:start], "[email]"))
        cursor = end
    parts.append(value[cursor:])
    return "".join(parts)


def _redact_export_text(value: str, *, max_len: int) -> str:
    plausible_email_redacted = _replace_plausible_emails(value)
    return redact_sensitive_text(plausible_email_redacted, max_len=max_len)


def _json_scalar_text(value: Any) -> str:
    if value is None:
        return ""
    if type(value) is str:
        return _normalize_untrusted_text(value)
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise SIEMExportError("SIEM export values must be JSON-compatible")
        return json.dumps(value, allow_nan=False, separators=(",", ":"))
    raise SIEMExportError("SIEM export projected fields must be JSON-compatible scalars")


def _value(event: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        value = event.get(name)
        if value is None:
            continue
        text = _json_scalar_text(value)
        if text.strip():
            return _normalize_untrusted_text(value) if type(value) is str else value
    return None


def _bounded_scalar(
    event: Mapping[str, Any],
    *names: str,
    key: str = "",
    max_len: int = 256,
) -> str:
    raw = _value(event, *names)
    if raw is None:
        return "unknown"
    value_for_sanitizer = raw
    if type(raw) is str:
        value_for_sanitizer = _replace_plausible_emails(raw)
    sanitized = sanitize_privacy_scalar(value_for_sanitizer, key=key or names[0])
    sanitized_text = _json_scalar_text(sanitized)
    text = _redact_export_text(
        sanitized_text,
        max_len=max_len,
    ).strip()
    if not text:
        return "unknown"
    if len(text) > max_len:
        return f"{text[:max_len]}...[truncated]"
    return text


def _bounded_identifier(
    event: Mapping[str, Any],
    *names: str,
    tenant_id: str,
    pseudonym_domain: str,
    force_pseudonym_names: frozenset[str] = frozenset(),
    max_len: int = 256,
) -> str:
    for name in names:
        raw = event.get(name)
        text = _json_scalar_text(raw).strip()
        if not text:
            continue
        redacted = _redact_export_text(text, max_len=max_len)
        if name in force_pseudonym_names or redacted != text:
            key = _validated_pseudonymization_key()
            message = (
                "hawk-siem-pseudonym:v1"
                f"\x00tenant:{tenant_id}"
                f"\x00domain:{pseudonym_domain}"
                f"\x00value:{text}"
            ).encode("utf-8")
            digest = hmac.new(
                key.encode("utf-8"),
                message,
                hashlib.sha256,
            ).hexdigest()[:32]
            return f"hawk-pseudo:{digest}"
        return text
    return "unknown"


def _bounded_string_list(
    event: Mapping[str, Any],
    name: str,
    *,
    max_items: int = 32,
    max_len: int = 128,
) -> list[str]:
    raw = event.get(name)
    if raw is None:
        return []
    if type(raw) is not list:
        raise SIEMExportError(f"SIEM export field {name} must be an array")
    values: list[str] = []
    for item in raw[:max_items]:
        if type(item) is not str:
            raise SIEMExportError(f"SIEM export field {name} must contain strings")
        safe = _bounded_scalar({name: item}, name, key=name, max_len=max_len)
        if safe != "unknown":
            values.append(safe)
    return values


_SENSITIVE_PATH_ASSIGNMENT_RE = re.compile(
    r"(?i)(?:^|[/;])"
    r"(?:signature|credential|account(?:_id|_number)?|card(?:_id|_number)?)"
    r"\s*[:=]\s*[^/]+"
)
_SENSITIVE_PATH_LABEL_RE = re.compile(
    r"(?i)/(?:authorization|credentials?|signatures?|accounts?|cards?|tokens?|secrets?)/[^/]+"
)


def _url_path_is_unsafe(path: str) -> bool:
    decoded = "/".join(
        _normalize_untrusted_text(segment)
        for segment in path.split("/")
    )
    redacted = _redact_export_text(decoded, max_len=max(512, len(decoded)))
    return (
        redacted != decoded
        or _SENSITIVE_PATH_ASSIGNMENT_RE.search(decoded) is not None
        or _SENSITIVE_PATH_LABEL_RE.search(decoded) is not None
    )


def _safe_resource_url(event: Mapping[str, Any]) -> str:
    raw = None
    for name in ("url", "source_url", "target_url"):
        candidate = event.get(name)
        if candidate is None:
            continue
        if type(candidate) is not str:
            _json_scalar_text(candidate)
            continue
        if len(candidate) > MAX_NORMALIZED_TEXT_CHARS:
            raise SIEMExportSizeError(
                f"SIEM export normalized text limit is {MAX_NORMALIZED_TEXT_CHARS}"
            )
        if candidate.strip():
            raw = candidate
            break
    if raw is None:
        return "unknown"
    try:
        parsed = urlsplit(raw)
        hostname = str(parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return "unknown"
    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return "unknown"
    host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = f"{host}:{port}" if port is not None else host
    path = parsed.path or "/"
    if _url_path_is_unsafe(path):
        path = "/"
    return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    else:
        text = _json_scalar_text(value).strip()
        if not text:
            return None
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso_z(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _severity(value: Any) -> tuple[int, str]:
    normalized = _json_scalar_text(value).strip().lower() or "unknown"
    aliases = {"medium": "med", "informational": "low", "info": "low"}
    normalized = aliases.get(normalized, normalized)
    return {
        "low": (2, "Low"),
        "med": (3, "Medium"),
        "high": (4, "High"),
        "critical": (5, "Critical"),
    }.get(normalized, (0, "Unknown"))


def _enforcement_truth(control_mode: str) -> str:
    if control_mode == "inline_prevented":
        return "inline_prevention"
    if control_mode == "inline_allowed":
        return "inline_allow"
    if control_mode in {"detected_only", "telemetry_only", "shadow_would_block"}:
        return "monitor_only"
    return "unknown"


def _authoritative_control_mode(*, source_surface: str, claimed_mode: str) -> str:
    if claimed_mode.startswith("inline"):
        if source_surface in {"browser", "browser_extension", "sdk"}:
            return "detected_only"
        return "unknown"
    return claimed_mode


def _generic_event(event: Mapping[str, Any], *, tenant_id: str) -> dict[str, Any]:
    severity_id, severity = _severity(_value(event, "severity", "risk_tier"))
    created_at = _parse_datetime(_value(event, "created_at", "timestamp", "time"))
    source_surface = _bounded_scalar(event, "source_surface", "source", max_len=64).lower()
    control_mode = _authoritative_control_mode(
        source_surface=source_surface,
        claimed_mode=_bounded_scalar(event, "control_mode", max_len=32).lower(),
    )
    projected = {
        "activity_id": 0,
        "activity_name": _bounded_scalar(event, "event_type", "finding_type", "signal_type"),
        "actor_uid": _bounded_identifier(
            event,
            *_ACTOR_IDENTIFIER_ALIASES,
            tenant_id=tenant_id,
            pseudonym_domain="actor",
            force_pseudonym_names=frozenset(_ACTOR_IDENTIFIER_ALIASES),
        ),
        "ai_system_uid": _bounded_identifier(
            event,
            "ai_system_id",
            tenant_id=tenant_id,
            pseudonym_domain="ai_system",
        ),
        "category_name": "Findings",
        "category_uid": 2,
        "class_name": "Security Finding",
        "class_uid": 2001,
        "control_mode": control_mode,
        "correlation_uid": _bounded_identifier(
            event,
            "correlation_id",
            tenant_id=tenant_id,
            pseudonym_domain="correlation",
        ),
        "decision": _bounded_scalar(event, "decision", max_len=32).lower(),
        "enforcement": _enforcement_truth(control_mode),
        "event_uid": _bounded_identifier(
            event,
            "event_id",
            "finding_id",
            "id",
            tenant_id=tenant_id,
            pseudonym_domain="event",
        ),
        "metadata": {
            "product": {"name": "Hawk", "vendor_name": "Hawk"},
            "profiles": ["security_control"],
            "version": "1.1.0",
        },
        "recommended_action": _bounded_scalar(
            event,
            "recommended_action",
            key="recommended_action",
            max_len=512,
        ),
        "resource_url": _safe_resource_url(event),
        "severity": severity,
        "severity_id": severity_id,
        "source_surface": source_surface,
        "status": _bounded_scalar(event, "status", max_len=32).lower(),
        "tenant_uid": tenant_id,
        "time": _iso_z(created_at) if created_at else "unknown",
        "type_uid": 200100,
    }
    if projected["activity_name"] == "banking_ai_transaction":
        projected["banking_transaction"] = {
            "ai_transaction_id": _bounded_identifier(
                event,
                "ai_transaction_id",
                tenant_id=tenant_id,
                pseudonym_domain="ai_transaction",
                max_len=64,
            ),
            "subject_reference": _bounded_identifier(
                event,
                "subject_reference",
                tenant_id=tenant_id,
                pseudonym_domain="banking_subject",
                force_pseudonym_names=frozenset({"subject_reference"}),
                max_len=96,
            ),
            "subject_type": _bounded_scalar(event, "subject_type", max_len=32),
            "agent_chain": _bounded_string_list(
                event, "agent_chain", max_items=32, max_len=128
            ),
            "model": _bounded_scalar(event, "model", max_len=128),
            "business_purpose": _bounded_scalar(
                event, "business_purpose", max_len=128
            ),
            "action_class": _bounded_scalar(event, "action_class", max_len=64),
            "transport": _bounded_scalar(event, "transport", max_len=32),
            "target_class": _bounded_scalar(event, "target_class", max_len=64),
            "destination_class": _bounded_scalar(
                event, "destination_class", max_len=64
            ),
            "selected_controls": _bounded_string_list(
                event, "selected_controls", max_items=64, max_len=128
            ),
            "decision_receipt_id": _bounded_identifier(
                event,
                "decision_receipt_id",
                tenant_id=tenant_id,
                pseudonym_domain="decision_receipt",
                max_len=64,
            ),
            "execution_receipt_id": _bounded_identifier(
                event,
                "execution_receipt_id",
                tenant_id=tenant_id,
                pseudonym_domain="execution_receipt",
                max_len=64,
            ),
            "integrity_status": _bounded_scalar(
                event, "integrity_status", max_len=32
            ),
            "drift_flags": _bounded_string_list(
                event, "drift_flags", max_items=64, max_len=128
            ),
            "finding_id": _bounded_identifier(
                event,
                "finding_id",
                tenant_id=tenant_id,
                pseudonym_domain="finding",
                max_len=64,
            ),
            "coverage_status": _bounded_scalar(
                event, "coverage_status", max_len=32
            ),
        }
    return projected


def _sentinel_event(event: Mapping[str, Any]) -> dict[str, Any]:
    projected = {
        "ActorId": event["actor_uid"],
        "AiSystemId": event["ai_system_uid"],
        "ControlMode": event["control_mode"],
        "CorrelationId": event["correlation_uid"],
        "Decision": event["decision"],
        "Enforcement": event["enforcement"],
        "EventId": event["event_uid"],
        "EventType": event["activity_name"],
        "OcsfCategoryUid": event["category_uid"],
        "OcsfClassUid": event["class_uid"],
        "OcsfTypeUid": event["type_uid"],
        "RecommendedAction": event["recommended_action"],
        "ResourceUrl": event["resource_url"],
        "Severity": event["severity"],
        "SeverityId": event["severity_id"],
        "SourceSurface": event["source_surface"],
        "Status": event["status"],
        "TenantId": event["tenant_uid"],
        "TimeGenerated": event["time"],
        "Vendor": "Hawk",
    }
    banking = event.get("banking_transaction")
    if isinstance(banking, Mapping):
        projected.update(
            {
                "AiTransactionId": banking["ai_transaction_id"],
                "SubjectReference": banking["subject_reference"],
                "SubjectType": banking["subject_type"],
                "AgentChain": banking["agent_chain"],
                "Model": banking["model"],
                "BusinessPurpose": banking["business_purpose"],
                "ActionClass": banking["action_class"],
                "Transport": banking["transport"],
                "TargetClass": banking["target_class"],
                "DestinationClass": banking["destination_class"],
                "SelectedControls": banking["selected_controls"],
                "DecisionReceiptId": banking["decision_receipt_id"],
                "ExecutionReceiptId": banking["execution_receipt_id"],
                "IntegrityStatus": banking["integrity_status"],
                "DriftFlags": banking["drift_flags"],
                "FindingId": banking["finding_id"],
                "CoverageStatus": banking["coverage_status"],
            }
        )
    return projected


def _validate_json_tree(
    value: Any,
    *,
    depth: int,
    counters: dict[str, int],
) -> None:
    if depth > MAX_EXPORT_JSON_DEPTH:
        raise SIEMExportSizeError(
            f"SIEM export JSON depth limit is {MAX_EXPORT_JSON_DEPTH}"
        )
    counters["nodes"] += 1
    if counters["nodes"] > MAX_EXPORT_JSON_NODES:
        raise SIEMExportSizeError(
            f"SIEM export JSON node limit is {MAX_EXPORT_JSON_NODES}"
        )

    value_type = type(value)
    if value is None or value_type in {bool, int}:
        return
    if value_type is float:
        if value != value or value in {float("inf"), float("-inf")}:
            raise SIEMExportError("SIEM export values must be JSON-compatible")
        return
    if value_type is str:
        if len(value) > MAX_EXPORT_JSON_STRING_CHARS:
            raise SIEMExportSizeError(
                "SIEM export input byte limit is "
                f"{MAX_EXPORT_INPUT_BYTES} (JSON string limit exceeded)"
            )
        return
    if value_type is dict:
        for key, item in value.items():
            counters["items"] += 1
            if counters["items"] > MAX_EXPORT_JSON_ITEMS:
                raise SIEMExportSizeError(
                    f"SIEM export JSON item limit is {MAX_EXPORT_JSON_ITEMS}"
                )
            if type(key) is not str:
                raise SIEMExportError(
                    "SIEM export mappings must use JSON-compatible string keys"
                )
            if len(key) > MAX_EXPORT_JSON_STRING_CHARS:
                raise SIEMExportSizeError(
                    "SIEM export input byte limit is "
                    f"{MAX_EXPORT_INPUT_BYTES} (JSON string limit exceeded)"
                )
            _validate_json_tree(item, depth=depth + 1, counters=counters)
        return
    if value_type is list:
        for item in value:
            counters["items"] += 1
            if counters["items"] > MAX_EXPORT_JSON_ITEMS:
                raise SIEMExportSizeError(
                    f"SIEM export JSON item limit is {MAX_EXPORT_JSON_ITEMS}"
                )
            _validate_json_tree(item, depth=depth + 1, counters=counters)
        return
    raise SIEMExportError(
        "SIEM export accepts only strict JSON-compatible mappings, lists, and scalars"
    )


def _validate_and_measure_input(events: Any) -> list[dict[str, Any]]:
    if type(events) is not list:
        raise SIEMExportError("SIEM export events must be a JSON-compatible list")
    if len(events) > MAX_EXPORT_EVENTS:
        raise SIEMExportSizeError(f"SIEM export event limit is {MAX_EXPORT_EVENTS}")
    counters = {"items": 0, "nodes": 0}
    _validate_json_tree(events, depth=0, counters=counters)
    if any(type(event) is not dict for event in events):
        raise SIEMExportError("SIEM export events must be JSON-compatible mappings")

    encoded_bytes = 0
    encoder = json.JSONEncoder(
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    try:
        for chunk in encoder.iterencode(events):
            encoded_bytes += len(chunk.encode("utf-8"))
            if encoded_bytes > MAX_EXPORT_INPUT_BYTES:
                raise SIEMExportSizeError(
                    f"SIEM export input byte limit is {MAX_EXPORT_INPUT_BYTES}"
                )
    except SIEMExportError:
        raise
    except (TypeError, ValueError, UnicodeError):
        raise SIEMExportError("SIEM export values must be JSON-compatible") from None
    return events


def _encode_ndjson(rows: Sequence[Mapping[str, Any]]) -> str:
    encoder = json.JSONEncoder(
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    encoded_bytes = 0
    parts: list[str] = []
    for row in rows:
        for chunk in encoder.iterencode(row):
            encoded_bytes += len(chunk.encode("utf-8"))
            if encoded_bytes > MAX_EXPORT_INPUT_BYTES:
                raise SIEMExportSizeError(
                    f"SIEM export NDJSON byte limit is {MAX_EXPORT_INPUT_BYTES}"
                )
            parts.append(chunk)
        encoded_bytes += 1
        if encoded_bytes > MAX_EXPORT_INPUT_BYTES:
            raise SIEMExportSizeError(
                f"SIEM export NDJSON byte limit is {MAX_EXPORT_INPUT_BYTES}"
            )
        parts.append("\n")
    return "".join(parts)


def build_siem_export(
    *,
    tenant_id: str,
    events: list[dict[str, Any]],
    adapter: str = "generic",
    enabled: bool | None = None,
    generated_at: datetime | None = None,
) -> SIEMExportBatch:
    if not settings.siem_export_enabled or enabled is False:
        raise SIEMExportDisabledError("SIEM export is disabled")
    _validated_pseudonymization_key()
    tenant_key = _normalize_tenant_id(tenant_id)
    if type(adapter) is not str:
        raise SIEMUnsupportedAdapterError("unsupported SIEM adapter: unknown")
    adapter_key = _normalize_untrusted_text(adapter).strip().lower()
    if adapter_key not in {"generic", "sentinel"}:
        raise SIEMUnsupportedAdapterError("unsupported SIEM adapter")
    validated_events = _validate_and_measure_input(events)
    if not validated_events:
        raise SIEMExportError("SIEM export event batch must not be empty")
    for event in validated_events:
        event_tenant = _normalize_tenant_id(event.get("tenant_id"))
        if event_tenant != tenant_key:
            raise SIEMTenantScopeError(
                "SIEM export contains a missing or foreign-tenant event"
            )
    generated = generated_at or datetime.now(timezone.utc)
    projected_generic = [
        _generic_event(event, tenant_id=tenant_key)
        for event in validated_events
    ]
    projected_generic.sort(key=lambda row: (row["time"], row["event_uid"]))
    projected = (
        projected_generic
        if adapter_key == "generic"
        else [_sentinel_event(event) for event in projected_generic]
    )
    # Never a full card number in an export (PCI DSS 3.4): masked as [card ending 1111], whatever the caller passed.
    projected = [scrub_pan_value(row, boundary="export:siem") for row in projected]
    ndjson = _encode_ndjson(projected)
    timestamps = [
        parsed
        for parsed in (
            _parse_datetime(_value(event, "created_at", "timestamp", "time"))
            for event in validated_events
        )
        if parsed is not None
    ]
    latest = max(timestamps) if timestamps else None
    metadata = {
        "adapter": adapter_key,
        "content_type": "application/x-ndjson",
        "delivery_attempted": False,
        "delivery_status": "not_attempted",
        "event_count": len(projected),
        "generated_at": _iso_z(generated),
        "health_status": "ready",
        "lag_seconds": max(0.0, (generated - latest).total_seconds()) if latest else None,
        "latest_event_at": _iso_z(latest) if latest else "unknown",
        "schema": SENTINEL_SCHEMA if adapter_key == "sentinel" else OCSF_ALIGNED_SCHEMA,
    }
    return SIEMExportBatch(ndjson=ndjson, metadata=metadata)


def deliver_siem_webhook(
    *,
    tenant_id: str,
    events: list[dict[str, Any]],
    destination_url: str,
    destination_policy: OutboundDestinationPolicy,
    client_factory: Any = None,
    transport_factory: Any = PinnedHTTPTransport,
    adapter: str = "generic",
    enabled: bool | None = None,
    generated_at: datetime | None = None,
    delivered_at: datetime | None = None,
) -> SIEMExportBatch:
    tenant_key = _normalize_tenant_id(tenant_id)
    batch = build_siem_export(
        tenant_id=tenant_key,
        events=events,
        adapter=adapter,
        enabled=enabled,
        generated_at=generated_at,
    )
    destination_policy_failure: tuple[str, str] | None = None
    try:
        destination = destination_policy.validate(destination_url, source="siem_export")
    except OutboundDestinationPolicyError:
        destination_policy_failure = _SAFE_DESTINATION_POLICY_FAILURE
    if destination_policy_failure is not None:
        raise SIEMInvalidDestinationError("invalid SIEM webhook destination") from None
    attempted = delivered_at or datetime.now(timezone.utc)
    failure_metadata = {
        **batch.metadata,
        "attempted_at": _iso_z(attempted),
        "delivery_attempted": True,
        "delivery_http_status": None,
        "delivery_status": "failed",
        "destination_origin": destination.origin,
        "health_status": "failed",
    }
    transport_failure: dict[str, str] | None = None
    destination_policy_failure = None
    status_code = 0
    from app.services.connector_activity import connector_scope

    try:
        with connector_scope(tenant_id=tenant_id, connector="SIEM export"):
            response = request_with_redirect_validation(
                "POST",
                destination_url,
                source="siem_export",
                policy=destination_policy,
                client_factory=client_factory,
                transport_factory=transport_factory,
                allowed_redirect_statuses=frozenset({307, 308}),
                content=batch.ndjson.encode("utf-8"),
                headers={
                    "Content-Type": "application/x-ndjson",
                    "X-Hawk-Schema": str(batch.metadata["schema"]),
                    "X-Hawk-Tenant": tenant_key,
                },
            )
        raw_status_code = getattr(response, "status_code", None)
        status_code = raw_status_code if type(raw_status_code) is int else 0
    except OutboundDestinationPolicyError:
        destination_policy_failure = _SAFE_DESTINATION_POLICY_FAILURE
    except Exception as exc:
        transport_failure = _safe_transport_failure_metadata(exc)
    if destination_policy_failure is not None:
        raise SIEMInvalidDestinationError("invalid SIEM webhook destination") from None
    if transport_failure is not None:
        raise SIEMDeliveryError(
            "SIEM webhook transport failed",
            metadata={**failure_metadata, **transport_failure},
        ) from None
    if status_code == 202:
        metadata = {
            **batch.metadata,
            "accepted_at": _iso_z(attempted),
            "delivery_attempted": True,
            "delivery_http_status": status_code,
            "delivery_status": "accepted_pending",
            "destination_origin": destination.origin,
            "health_status": "pending",
        }
        return SIEMExportBatch(ndjson=batch.ndjson, metadata=metadata)
    if status_code not in {200, 201, 204}:
        raise SIEMDeliveryError(
            f"SIEM webhook rejected delivery with status {status_code or 'unknown'}",
            metadata={**failure_metadata, "delivery_http_status": status_code or None},
        )
    metadata = {
        **batch.metadata,
        "delivered_at": _iso_z(attempted),
        "delivery_attempted": True,
        "delivery_http_status": status_code,
        "delivery_status": "delivered",
        "destination_origin": destination.origin,
        "health_status": "healthy",
    }
    return SIEMExportBatch(ndjson=batch.ndjson, metadata=metadata)
