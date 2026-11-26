from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import logging
import os
import re
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.control_engine import AIAction, evaluate_control_engine, map_generic_decision
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.core.observability import log_structured
from app.db.models.discovery import DiscoveryApplication
from app.db.models.discovery_resolution import DiscoveryAssetHypothesis
from app.db.models.monitoring import MonitoringSignal
from app.db.models.policy import PolicyPack, PolicyVersion
from app.db.models.user import User
from app.services.ai_iam_service import (
    action_category_for,
    action_risk_for,
    auto_quarantine_agent_identity,
    build_intent_aware_evidence_summary,
    build_pre_action_governance_check,
    classify_input_content_context,
    classify_intent_context,
    classify_output_context,
    evaluate_action_alignment,
    evaluate_intent_aware_action_control,
    evaluate_purpose_bound_permission,
)
from app.services.activity_audit_service import record_activity_event
from app.services.audit_service import write_audit_log
from app.services.discovery_service import tool_key_for_name
from app.services.evidence_service import create_evidence_node
from app.services.provider_catalog import list_catalog
from app.services.findings_service import (
    enrich_pilot_finding_context,
    generate_from_browser_event,
    generate_from_shadow_event,
    generate_unregistered_ai_system_finding,
)
from app.services.enforcement_routing_service import (
    fallback_decision_for_gateway_failure,
    record_routing_failure,
    route_enforcement,
)
from app.services.guardians.threat_detectors import evaluate_threat_detectors
from app.services.guardian_policy_engine import (
    canonical_guardian_policy,
    evaluate_browser_interaction_policy,
    evaluate_guardian_policies,
)
from app.services.governance_resolution import resolve_ai_system_status
from app.services.hmair.hypothesis_service import HypothesisConflict, create_hypothesis
from app.services.platform_mode_service import PLATFORM_MODE_DISCOVERY, get_tenant_platform_mode
from app.services.policy_scope_service import resolve_scoped_policy_decision
from app.services.policy_service import build_intent_aware_action_control_policy, evaluate_business_purpose_boundary
from app.services.sensitive_data_detection_service import (
    classify_data,
    detect_sensitive_data,
    detection_signal_types,
)
from app.services.detection.injection_engine import assess as assess_prompt_injection
from app.services.detection.profile import with_tenant_profile


DEFAULT_SENSITIVE_PATTERNS = [
    r"(?i)\bssn\b",
    r"(?i)\bcredit\s*card\b",
    r"(?i)\bapi[_\s-]?key\b",
    r"(?i)\bsecret\b",
    r"(?i)\bprivate\s*key\b",
    r"(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)",
    r"(?i)\b(?:emirates\s*id|uae\s*(?:id|national\s*id)|eid)\b[^\n\r]{0,24}\b\d{12,18}\b",
    r"(?i)\bAE\d{2}(?:[ -]?\d){19}\b",
]

error_logger = logging.getLogger("uvicorn.error")

UAE_EMIRATES_ID_STRICT_PATTERN = re.compile(r"(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)")
UAE_EMIRATES_ID_CONTEXT_PATTERN = re.compile(
    r"(?i)\b(?:emirates\s*id|uae\s*(?:id|national\s*id)|eid)\b[^\n\r]{0,40}\b\d{10,18}\b"
)
UAE_IDENTIFIER_CONTEXT_PATTERN = re.compile(r"(?i)\b(?:emirates\s*id|uae\s*(?:id|national\s*id)|eid)\b")
LONG_IDENTIFIER_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){10,18}(?!\d)")
UAE_IBAN_STRICT_PATTERN = re.compile(r"(?i)\bAE\d{2}(?:[ -]?\d){19}\b")
UAE_BANK_CONTEXT_PATTERN = re.compile(
    r"(?i)(?:\b(?:uae|emirates)\b[^\n\r]{0,32}\b(?:iban|bank(?:\s*account)?)\b)|"
    r"(?:\b(?:iban|bank(?:\s*account)?)\b[^\n\r]{0,32}\b(?:uae|emirates)\b)"
)

DEFAULT_BLOCKED_KEYWORDS = [
    "project aurora",
    "internal only",
    "do not disclose",
]

DEFAULT_HIGH_RISK_TERMS = [
    "ignore previous instructions",
    "jailbreak",
    "bypass policy",
    "override safeguards",
    "exfiltrate",
]

KNOWN_AI_DOMAINS = [
    "chat.openai.com",
    "chatgpt.com",
    "platform.openai.com",
    "claude.ai",
    "console.anthropic.com",
    "gemini.google.com",
    "aistudio.google.com",
    "notebooklm.google.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "www.perplexity.ai",
    "poe.com",
    "grok.com",
    "x.ai",
    "you.com",
    "www.you.com",
]

DEFAULT_CONTROL_PLANE_ALLOWLIST_DOMAINS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "ngrok.io",
    "ngrok-free.app",
}

MANAGED_DOMAIN_ALIAS_GROUPS: tuple[tuple[str, ...], ...] = (
    ("hotmail.com", "outlook.live.com", "outlook.com", "live.com", "mail.live.com"),
)

BROWSER_EVENT_SEVERITY = {
    "ai_domain_visit": "low",
    "prompt_submitted": "low",
    "prompt_warned": "med",
    "prompt_blocked": "critical",
    "prompt_held": "high",
    "unknown_ai_detected": "high",
    "agent_runtime_discovered": "high",
    "browser_automation_detected": "high",
    "browser_automation_blocked": "critical",
    "file_upload_detected": "med",
    "output_flagged": "high",
    "clipboard_copy_detected": "low",
    "clipboard_paste_detected": "med",
    "clipboard_cut_detected": "med",
    "extension_health_status": "med",
    "meeting_ai_notetaker_detected": "high",
    "meeting_ai_notetaker_block_requested": "high",
    "meeting_ai_notetaker_hidden_suspected": "high",
    "meeting_ai_notetaker_calendar_invitee_detected": "med",
    "meeting_ai_notetaker_oauth_detected": "high",
    "device_audio_notetaker_detected": "high",
    "device_audio_notetaker_control_applied": "critical",
    "meeting_transcription_policy_violation": "high",
}

SEVERITY_RISK_SCORE = {
    "low": 0.2,
    "med": 0.5,
    "high": 0.8,
    "critical": 0.95,
}

_KNOWN_BROWSER_CONTEXT_REASONS = frozenset({
    "input_node_replaced",
    "spa_route_change",
    "spa_route_replace",
    "tab_restore_or_popstate",
    "extension_context_invalidated",
})
_BROWSER_CONTEXT_REAL_DECISIONS = frozenset({
    "block",
    "blocked",
    "warn",
    "warned",
    "warning",
    "deny",
    "denied",
    "tamper",
    "tampered",
    "fail",
    "failed",
    "error",
    "errored",
    "degraded",
    "unhealthy",
    "prevent",
    "prevented",
    "redact",
    "modify",
    "step_up",
    "require_approval",
    "hold_for_approval",
    "approval_required",
})


@dataclass
class PolicySyncPayload:
    tenant_id: str
    platform_mode: str
    policy_version: str
    approved_domains: list[str]
    blocked_domains: list[str]
    warn_domains: list[str]
    critical_domains: list[str]
    unknown_domain_behavior: str
    provider_enforcement_hints: list[dict[str, Any]]
    interaction_rules: dict[str, Any]
    browser_automation_control: dict[str, Any]
    intent_aware_action_control: dict[str, Any]


EXTENSION_REMOVAL_AUTH_SIGNAL_TYPE = "browser.extension_removal_authorization"
EXTENSION_REMOVAL_ACTIONS = {"disable", "remove"}
EXTENSION_REMOVAL_STATUS_VALUES = {"disabled", "removed", "uninstalled", "missing"}
EXTENSION_REMOVAL_TRIGGER_VALUES = {
    "extension_disabled",
    "extension_removed",
    "extension_uninstalled",
    "extension_missing",
    "admin_disable",
    "admin_removal",
    "disable_requested",
    "removal_requested",
}


DEFAULT_BROWSER_AUTOMATION_ALLOWED_ACTIONS = [
    "page_view",
    "search",
    "scroll",
    "navigate",
    "read_content",
]

DEFAULT_BROWSER_AUTOMATION_BLOCKED_ACTIONS = [
    "add_to_cart",
    "checkout",
    "purchase_now",
    "payment_submit",
    "submit_form",
    "upload_file",
    "send_message",
    "send_email",
    "delete_item",
    "change_settings",
    "invite_user",
    "create_api_key",
    "access_admin_console",
    "access_payment_page",
    "access_credentials_page",
    "credential_submit",
]

DEFAULT_BROWSER_AUTOMATION_SOURCES = [
    "browser_visible",
    "extension_marker",
    "agentic_browser_marker",
    "scripted_input",
    "rapid_navigation",
    "automated_click_cadence",
    "suspected_local_agent",
    "unknown",
]


def _normalize_string_list(values: Any) -> list[str]:
    if not isinstance(values, (list, tuple, set)):
        return []
    normalized: list[str] = []
    for item in values:
        token = str(item or "").strip()
        if token and token not in normalized:
            normalized.append(token)
    return normalized


def _coerce_browser_automation_policy(
    *,
    policy: dict[str, Any] | None,
    tenant_id: str,
    approved_domains: set[str],
    blocked_domains: set[str],
    platform_mode: str,
) -> dict[str, Any]:
    control_plane_allowlist = _control_plane_allowlist_domains()
    base_policy: dict[str, Any] = {
        "policy_id": "browser_automation_control_default",
        "name": "Browser Automation Control",
        "category": "BROWSER_AUTOMATION_CONTROL",
        "mode": ("warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block"),
        "enabled": True,
        "scope": {
            "users": [],
            "groups": [],
            "tenant_id": tenant_id,
            "surfaces": ["browser_extension"],
            "source_vendors": [],
            "agentic_browser_assets": [],
            "domains_allowlist": sorted(set(approved_domains) | control_plane_allowlist),
            "domains_blocklist": sorted(blocked_domains),
            "url_patterns_allowlist": [],
            "url_patterns_blocklist": [],
        },
        "automation": {
            "detection_required": True,
            "confidence_threshold": 0.6,
            "sources": list(DEFAULT_BROWSER_AUTOMATION_SOURCES),
        },
        "allowed_actions": list(DEFAULT_BROWSER_AUTOMATION_ALLOWED_ACTIONS),
        "blocked_actions": list(DEFAULT_BROWSER_AUTOMATION_BLOCKED_ACTIONS),
        "action_overrides": [
            {
                "name": "Amazon Browsing Only",
                "domains": ["amazon.com", "www.amazon.com"],
                "allowed_actions": ["page_view", "search", "navigate", "read_content"],
                "blocked_actions": ["add_to_cart", "checkout", "purchase_now", "payment_submit"],
            }
        ],
        "decisions": {
            "on_allowed_browsing": "allow",
            "on_automation_detected": "warn",
            "on_blocked_domain": "block",
            "on_disallowed_domain": "warn",
            "on_blocked_action": "block",
            "on_scope_violation": "block",
            "on_unknown_automation_source": "warn",
            "on_sensitive_data_or_secret": "block",
        },
    }
    incoming = dict(policy or {}) if isinstance(policy, dict) else {}
    merged = {**base_policy, **incoming}
    scope_in = dict(incoming.get("scope") or {}) if isinstance(incoming.get("scope"), dict) else {}
    base_scope = dict(base_policy["scope"])
    merged_scope = {
        **base_scope,
        **scope_in,
        "tenant_id": tenant_id,
    }
    merged_scope["users"] = _normalize_string_list(merged_scope.get("users"))
    merged_scope["groups"] = _normalize_string_list(merged_scope.get("groups"))
    merged_scope["surfaces"] = _normalize_string_list(merged_scope.get("surfaces")) or ["browser_extension"]
    merged_scope["source_vendors"] = _normalize_string_list(merged_scope.get("source_vendors"))
    merged_scope["agentic_browser_assets"] = _normalize_string_list(merged_scope.get("agentic_browser_assets"))
    merged_scope["domains_allowlist"] = _normalize_string_list(merged_scope.get("domains_allowlist"))
    merged_scope["domains_blocklist"] = _normalize_string_list(merged_scope.get("domains_blocklist"))
    merged_scope["url_patterns_allowlist"] = _normalize_string_list(merged_scope.get("url_patterns_allowlist"))
    merged_scope["url_patterns_blocklist"] = _normalize_string_list(merged_scope.get("url_patterns_blocklist"))
    merged_scope["domains_allowlist"] = sorted(
        {
            normalize_domain(item)
            for item in merged_scope["domains_allowlist"] + list(control_plane_allowlist)
            if normalize_domain(item)
        }
    )
    merged_scope["domains_blocklist"] = sorted(
        {
            normalize_domain(item)
            for item in merged_scope["domains_blocklist"]
            if normalize_domain(item) and normalize_domain(item) not in set(merged_scope["domains_allowlist"])
        }
    )
    merged["scope"] = merged_scope

    automation_candidate = incoming.get("automation")
    if not isinstance(automation_candidate, dict):
        automation_candidate = incoming.get("automation_detection")
    automation_in = dict(automation_candidate or {}) if isinstance(automation_candidate, dict) else {}
    base_automation = dict(base_policy["automation"])
    merged_automation = {**base_automation, **automation_in}
    try:
        threshold = float(merged_automation.get("confidence_threshold"))
    except (TypeError, ValueError):
        threshold = float(base_automation["confidence_threshold"])
    merged_automation["confidence_threshold"] = max(0.0, min(1.0, threshold))
    merged_automation["detection_required"] = bool(merged_automation.get("detection_required", True))
    merged_automation["sources"] = _normalize_string_list(merged_automation.get("sources")) or list(DEFAULT_BROWSER_AUTOMATION_SOURCES)
    merged["automation"] = merged_automation
    # Backward/forward compatibility for clients that use `automation_detection`.
    merged["automation_detection"] = dict(merged_automation)

    merged["allowed_actions"] = _normalize_string_list(merged.get("allowed_actions")) or list(DEFAULT_BROWSER_AUTOMATION_ALLOWED_ACTIONS)
    merged["blocked_actions"] = _normalize_string_list(merged.get("blocked_actions")) or list(DEFAULT_BROWSER_AUTOMATION_BLOCKED_ACTIONS)

    overrides: list[dict[str, Any]] = []
    for item in incoming.get("action_overrides") or []:
        if not isinstance(item, dict):
            continue
        override_domains = _normalize_string_list(item.get("domains"))
        domain = normalize_domain(item.get("domain"))
        if domain:
            override_domains = [*override_domains, domain]
        normalized_domains = sorted(
            {
                normalize_domain(candidate)
                for candidate in override_domains
                if normalize_domain(candidate)
            }
        )
        if not normalized_domains:
            continue
        normalized_name = str(item.get("name") or "").strip() or None
        overrides.append(
            {
                "name": normalized_name,
                "domain": normalized_domains[0],
                "domains": normalized_domains,
                "allowed_actions": _normalize_string_list(item.get("allowed_actions")),
                "blocked_actions": _normalize_string_list(item.get("blocked_actions")),
            }
        )
    merged["action_overrides"] = overrides or list(base_policy["action_overrides"])

    decisions_in = dict(incoming.get("decisions") or {}) if isinstance(incoming.get("decisions"), dict) else {}
    decisions = {
        **dict(base_policy["decisions"]),
        **decisions_in,
    }
    merged["decisions"] = {
        key: str(value or dict(base_policy["decisions"]).get(key) or "").strip().lower() or dict(base_policy["decisions"]).get(key)
        for key, value in decisions.items()
    }
    merged["category"] = "BROWSER_AUTOMATION_CONTROL"
    merged["policy_id"] = str(merged.get("policy_id") or "browser_automation_control_default").strip()
    merged["name"] = str(merged.get("name") or "Browser Automation Control").strip()
    merged["mode"] = str(merged.get("mode") or ("warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block")).strip().lower()
    if merged["mode"] not in {"monitor", "warn", "block"}:
        merged["mode"] = "warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block"
    merged["enabled"] = bool(merged.get("enabled", True))
    return merged


def _coerce_intent_aware_action_control_policy(
    *,
    policy: dict[str, Any] | None,
    tenant_id: str,
    platform_mode: str,
) -> dict[str, Any]:
    base_policy = build_intent_aware_action_control_policy(
        tenant_id=tenant_id,
        mode=("warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block"),
    )
    incoming = dict(policy or {}) if isinstance(policy, dict) else {}
    merged = {**base_policy, **incoming}
    scope_in = dict(incoming.get("scope") or {}) if isinstance(incoming.get("scope"), dict) else {}
    base_scope = dict(base_policy["scope"])
    merged_scope = {
        **base_scope,
        **scope_in,
        "tenant_id": tenant_id,
    }
    for key in ("users", "groups", "surfaces", "applications", "domains", "destination_trust_levels"):
        merged_scope[key] = _normalize_string_list(merged_scope.get(key))
    if not merged_scope["surfaces"]:
        merged_scope["surfaces"] = ["browser_extension"]
    merged["scope"] = merged_scope
    merged["allowed_intents"] = _normalize_string_list(merged.get("allowed_intents")) or list(base_policy["allowed_intents"])
    merged["blocked_intents"] = _normalize_string_list(merged.get("blocked_intents")) or list(base_policy["blocked_intents"])
    for key in ("intent_action_rules", "copy_export_rules", "alignment_rules"):
        merged[key] = [dict(item) for item in (merged.get(key) or []) if isinstance(item, dict)] or list(base_policy[key])
    merged["category"] = "INTENT_AWARE_AI_ACTION_CONTROL"
    merged["policy_id"] = str(merged.get("policy_id") or "pilot_intent_aware_ai_action_control").strip()
    merged["schema_version"] = str(merged.get("schema_version") or "intent-aware-ai-action-control/v1").strip()
    merged["name"] = str(merged.get("name") or "Pilot Intent-Aware AI Action Control").strip()
    merged["mode"] = str(merged.get("mode") or ("warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block")).strip().lower()
    if merged["mode"] not in {"monitor", "shadow", "warn", "block"}:
        merged["mode"] = "warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block"
    merged["enabled"] = bool(merged.get("enabled", True))
    return merged


def normalize_domain(raw: str | None) -> str:
    value = str(raw or "").strip().lower()
    if not value:
        return ""

    try:
        parsed = urlparse(value if "://" in value else f"https://{value}")
    except ValueError:
        return ""
    host = parsed.netloc or parsed.path
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host.strip(".")


def _control_plane_allowlist_domains() -> set[str]:
    domains: set[str] = set(DEFAULT_CONTROL_PLANE_ALLOWLIST_DOMAINS)
    web_domain = normalize_domain(str(settings.web_origin or ""))
    if web_domain:
        domains.add(web_domain)
    for key in ("API_BASE_URL", "WEB_ORIGIN", "FRONTEND_URL"):
        configured = normalize_domain(os.getenv(key))
        if configured:
            domains.add(configured)
    for origin in str(os.getenv("CORS_ORIGINS") or "").split(","):
        configured = normalize_domain(origin)
        if configured:
            domains.add(configured)
    return {domain for domain in domains if domain}


def _domain_from_url(raw_url: str | None) -> str:
    return normalize_domain(raw_url)


def _resolve_actor_user_email(db: Session, user_id: str | None) -> str | None:
    candidate = str(user_id or "").strip()
    if not candidate:
        return None
    return db.scalar(select(User.email).where(User.id == candidate))


def _payload_text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = str(payload.get(key) or "").strip()
        if value:
            return value
    return None


def _payload_bool(payload: dict[str, Any], key: str) -> bool | None:
    value = payload.get(key)
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off"}:
            return False
        return None
    return bool(value)


def _decision_badge_from_signal_types(payload: dict[str, Any]) -> str | None:
    for item in payload.get("input_signal_types") or []:
        text = str(item or "").strip()
        if not text.lower().startswith("decision_badge:"):
            continue
        value = text.split(":", 1)[1].strip().replace("_", " ")
        if value:
            return value.title()
    return None


def _decision_for_browser_event(event_type: str, action_taken: str | None) -> str:
    normalized_event = str(event_type or "").strip().lower()
    normalized_action = str(action_taken or "").strip().lower()
    if "block" in normalized_event or "block" in normalized_action:
        return "block"
    if "warn" in normalized_event or "warn" in normalized_action:
        return "warn"
    if normalized_event in {
        "unknown_ai_detected",
        "agent_runtime_discovered",
        "extension_health_status",
        "browser_automation_detected",
    }:
        return "warn"
    return "allow"


def _browser_context_lifecycle_reason(payload: dict[str, Any]) -> str | None:
    source_surface = str(payload.get("source_surface") or "browser").strip().lower().replace("-", "_")
    if source_surface not in {"browser", "browser_extension"}:
        return None
    event_type = str(payload.get("event_type") or "").strip().lower().replace("-", "_")
    if event_type != "context_invalidated":
        return None
    for key in ("reason", "reason_code", "action_taken", "event_type", "decision_reason"):
        raw_value = str(payload.get(key) or "").strip().lower().replace("-", "_")
        if not raw_value:
            continue
        candidates = {raw_value}
        candidates.update(part.strip() for part in raw_value.split(":") if part.strip())
        for candidate in candidates:
            if candidate in _KNOWN_BROWSER_CONTEXT_REASONS:
                return candidate
    return None


def _browser_context_has_real_decision(payload: dict[str, Any]) -> bool:
    def _is_real(value: Any) -> bool:
        normalized = str(value or "").strip().lower().replace("-", "_")
        return normalized in _BROWSER_CONTEXT_REAL_DECISIONS

    action_taken = str(payload.get("action_taken") or "").strip().lower().replace("-", "_")
    if _is_real(action_taken.split(":", 1)[0]):
        return True
    for key in ("decision", "policy_decision", "final_decision"):
        if _is_real(payload.get(key)):
            return True
    for key in ("policy_evaluation", "pre_action_governance_check", "intent_aware_decision"):
        nested = payload.get(key)
        if isinstance(nested, dict) and any(
            _is_real(nested.get(decision_key))
            for decision_key in ("decision", "policy_decision", "final_decision")
        ):
            return True
    status = str(payload.get("status") or "").strip().lower().replace("-", "_")
    return _is_real(status)


HAWK_CONTROL_PLANE_PATH_PREFIXES = (
    "/ai-iam",
    "/auditor",
    "/dashboard",
    "/discovery",
    "/policies",
    "/runtime-intelligence",
)
HAWK_CONTROL_PLANE_MARKERS = (
    "ai control plane",
    "ai iam",
    "control plane",
    "discovery findings",
    "governance review",
    "notification hub",
    "policy version",
    "runtime intelligence",
    "shadow ai",
)


def _is_loopback_domain(domain: str) -> bool:
    normalized = normalize_domain(domain)
    return normalized in {"localhost", "127.0.0.1", "::1"} or normalized.endswith(".localhost")


def _is_private_or_loopback_domain(domain: str) -> bool:
    normalized = normalize_domain(domain)
    if _is_loopback_domain(normalized):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return bool(address.is_private or address.is_loopback)


def _is_control_plane_path(path: str) -> bool:
    normalized = str(path or "").strip().lower() or "/"
    return any(normalized == prefix or normalized.startswith(f"{prefix}/") for prefix in HAWK_CONTROL_PLANE_PATH_PREFIXES)


def _control_plane_marker_count(text: str) -> int:
    normalized = str(text or "").strip().lower()
    return sum(1 for marker in HAWK_CONTROL_PLANE_MARKERS if marker in normalized)


def _is_hawk_control_plane_browser_surface(domain: str, payload: dict[str, Any]) -> bool:
    raw_url = str(payload.get("url") or "").strip()
    parsed = urlparse(raw_url) if raw_url else None
    host = normalize_domain(parsed.hostname if parsed and parsed.hostname else domain)
    allowlisted = host in _control_plane_allowlist_domains()
    if not _is_private_or_loopback_domain(host):
        return allowlisted

    path = parsed.path if parsed else ""
    if allowlisted and _is_control_plane_path(path):
        return True

    title = str(payload.get("page_title") or "").strip().lower()
    if "ai control plane" in title:
        return True

    port = str(parsed.port if parsed and parsed.port else "").strip()
    if port not in {"", "3000"} or not _is_control_plane_path(path):
        return False

    marker_text = "\n".join(
        str(payload.get(key) or "")
        for key in ("page_title", "prompt_preview_redacted", "raw_prompt", "prompt_text")
    )
    return _control_plane_marker_count(marker_text) >= 2


def _domain_matches(candidate: str, expected: str) -> bool:
    candidate_norm = normalize_domain(candidate)
    expected_norm = normalize_domain(expected)
    if not candidate_norm or not expected_norm:
        return False
    return candidate_norm == expected_norm or candidate_norm.endswith(f".{expected_norm}")


def _browser_destination_trust_level(
    *,
    domain: str,
    policy_sync: "PolicySyncPayload",
    ai_system_id: str | None,
) -> str:
    if any(_domain_matches(domain, item) for item in (policy_sync.blocked_domains or [])):
        return "blocked"
    if ai_system_id and any(_domain_matches(domain, item) for item in (policy_sync.approved_domains or [])):
        return "approved_enterprise"
    if any(_domain_matches(domain, item) for item in KNOWN_AI_DOMAINS):
        return "public_ai"
    if any(_domain_matches(domain, item) for item in (policy_sync.approved_domains or [])):
        return "approved_public"
    return "unknown"


def _contains_keyword(text: str, keywords: list[str]) -> bool:
    text_lower = text.lower()
    return any(keyword.lower() in text_lower for keyword in keywords if keyword.strip())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _extract_guardian_keywords(guardian_contracts: list[dict[str, Any]]) -> tuple[list[str], list[str], list[str]]:
    blocked_keywords: set[str] = set(DEFAULT_BLOCKED_KEYWORDS)
    high_risk_terms: set[str] = set(DEFAULT_HIGH_RISK_TERMS)
    sensitive_patterns: set[str] = set(DEFAULT_SENSITIVE_PATTERNS)

    for guardian in guardian_contracts or []:
        guardian_id = str(guardian.get("guardian_id") or "").strip().lower()
        trigger = guardian.get("trigger") if isinstance(guardian.get("trigger"), dict) else {}
        conditions = trigger.get("conditions") if isinstance(trigger.get("conditions"), list) else []
        for condition in conditions:
            if not isinstance(condition, dict):
                continue
            operator = str(condition.get("operator") or "").strip().lower()
            value = condition.get("value")
            if isinstance(value, str) and value.strip():
                if operator == "regex":
                    sensitive_patterns.add(value.strip())
                elif operator == "contains":
                    if guardian_id in {"prompt_injection", "jailbreak", "tool_output_injection"}:
                        blocked_keywords.add(value.strip())
                    else:
                        high_risk_terms.add(value.strip())

        if guardian_id in {"prompt_injection", "jailbreak"}:
            high_risk_terms.add("ignore previous instructions")
            high_risk_terms.add("jailbreak")
        if guardian_id in {"sensitive_data_leakage", "cross_context_leakage_stub"}:
            sensitive_patterns.add(r"(?i)\bconfidential\b")

    return sorted(blocked_keywords), sorted(high_risk_terms), sorted(sensitive_patterns)


def _domains_for_status(apps: list[DiscoveryApplication], statuses: set[str]) -> list[str]:
    out: set[str] = set()
    for app in apps:
        if app.status not in statuses:
            continue
        metadata = app.metadata_json if isinstance(app.metadata_json, dict) else {}
        candidates = [
            normalize_domain(app.tool_name),
            normalize_domain(metadata.get("domain")),
        ]
        for candidate in candidates:
            if candidate and "." in candidate:
                out.add(candidate)
    return sorted(out)


def _expand_managed_domain_aliases(domains: set[str]) -> set[str]:
    expanded = {normalize_domain(value) for value in domains if normalize_domain(value)}
    if not expanded:
        return set()

    for domain in list(expanded):
        for alias_group in MANAGED_DOMAIN_ALIAS_GROUPS:
            aliases = {normalize_domain(alias) for alias in alias_group if normalize_domain(alias)}
            if not aliases:
                continue
            if any(_domain_matches(domain, alias) or _domain_matches(alias, domain) for alias in aliases):
                expanded.update(aliases)
    return {value for value in expanded if value}


def _reconcile_domain_policy_sets(
    *,
    approved_domains: set[str],
    blocked_domains: set[str],
    warn_domains: set[str],
    critical_domains: set[str] | None = None,
) -> tuple[set[str], set[str], set[str], set[str] | None]:
    approved = _expand_managed_domain_aliases(set(approved_domains))
    blocked = _expand_managed_domain_aliases(set(blocked_domains))
    warn = _expand_managed_domain_aliases(set(warn_domains))
    critical = _expand_managed_domain_aliases(set(critical_domains or set())) if critical_domains is not None else None

    # Explicit approval should immediately clear stale block/warn rules for the same domain family.
    blocked.difference_update(approved)
    warn.difference_update(approved)
    # Block takes precedence over warn when both are present.
    warn.difference_update(blocked)

    if critical is not None:
        # Do not keep an approved domain family in critical-only browser handling.
        critical.difference_update(approved)
        critical.update(blocked)

    return approved, blocked, warn, critical


def _provider_enforcement_hints_for_browser(
    *,
    platform_mode: str,
    approved_domains: set[str],
    blocked_domains: set[str],
) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    catalog_rows = list_catalog()
    for row in catalog_rows:
        surfaces = {str(item).strip().lower() for item in (row.get("deployment_surfaces") or [])}
        if "browser" not in surfaces:
            continue

        provider_name = str(row.get("canonical_name") or row.get("provider_id") or "unknown").strip()
        trust_level = str(row.get("trust_level") or "unknown").strip().lower()
        risk_hint = str(row.get("default_risk_hint") or "MEDIUM").strip().upper()
        domains = sorted(
            {
                normalize_domain(domain)
                for domain in (row.get("known_domains") or [])
                if normalize_domain(domain)
            }
        )
        sanctioned_domains = [domain for domain in domains if domain in approved_domains]
        blocked_provider_domains = [domain for domain in domains if domain in blocked_domains]

        suggested_decision = "warn"
        if blocked_provider_domains:
            suggested_decision = "block"
        elif sanctioned_domains:
            suggested_decision = "allow"
        elif risk_hint in {"CRITICAL", "RESTRICTED", "HIGH"} and platform_mode != PLATFORM_MODE_DISCOVERY:
            suggested_decision = "block"

        browser_message = (
            "Domain is explicitly blocked by tenant governance."
            if blocked_provider_domains
            else (
                "Domain is sanctioned for browser usage."
                if sanctioned_domains
                else (
                    "Treat as unknown AI usage in discovery mode and route findings for governance review."
                    if platform_mode == PLATFORM_MODE_DISCOVERY
                    else "Treat as unsanctioned until governance approval is recorded."
                )
            )
        )

        hints.append(
            {
                "provider_id": str(row.get("provider_id") or ""),
                "provider_name": provider_name,
                "provider_type": str(row.get("provider_type") or "unknown"),
                "trust_level": trust_level,
                "default_risk_hint": risk_hint,
                "known_domains": domains,
                "sanctioned_domains": sanctioned_domains,
                "blocked_domains": blocked_provider_domains,
                "suggested_decision": suggested_decision,
                "browser_message": browser_message,
                "surface_policy_mode": "enforceable",
            }
        )

    return sorted(
        hints,
        key=lambda item: (
            0 if item.get("suggested_decision") == "block" else 1,
            0 if item.get("suggested_decision") == "warn" else 1,
            str(item.get("provider_name") or ""),
        ),
    )


def _resolve_policy_version(db: Session, *, tenant_id: str) -> PolicyVersion | None:
    rows = db.scalars(
        select(PolicyVersion)
        .join(PolicyPack, PolicyVersion.pack_id == PolicyPack.id)
        .where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyPack.tenant_id == tenant_id,
            PolicyPack.status == "active",
        )
        .order_by(PolicyVersion.created_at.desc())
        .limit(20)
    ).all()
    if not rows:
        return None

    def _version_sort_key(row: PolicyVersion) -> tuple[float, str, str]:
        created_at = row.created_at
        if isinstance(created_at, datetime):
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
            created_at_epoch = created_at.timestamp()
        else:
            created_at_epoch = 0.0
        return (created_at_epoch, str(row.version or ""), str(row.id or ""))

    rows = sorted(rows, key=_version_sort_key, reverse=True)
    return rows[0]


def build_extension_policy_sync(db: Session, *, tenant_id: str) -> PolicySyncPayload:
    platform_mode = get_tenant_platform_mode(db, tenant_id=tenant_id)
    active_version = _resolve_policy_version(db, tenant_id=tenant_id)
    apps = db.scalars(select(DiscoveryApplication).where(DiscoveryApplication.tenant_id == tenant_id)).all()

    approved_domains = _expand_managed_domain_aliases(set(_domains_for_status(apps, {"approved"})))
    blocked_domains = _expand_managed_domain_aliases(set(_domains_for_status(apps, {"blocked"})))
    warn_domains = _expand_managed_domain_aliases(set(_domains_for_status(apps, {"discovered", "monitoring"})))
    control_plane_allowlist = _control_plane_allowlist_domains()

    if settings.pilot_mode:
        # Pilot mode should not start from broad deny semantics on mainstream AI apps;
        # keep baseline usage functional and let content-aware controls do the blocking.
        approved_domains.update(KNOWN_AI_DOMAINS)
    elif not approved_domains and platform_mode == PLATFORM_MODE_DISCOVERY:
        approved_domains.update(KNOWN_AI_DOMAINS)
    approved_domains.update(control_plane_allowlist)
    blocked_domains.difference_update(control_plane_allowlist)
    warn_domains.difference_update(control_plane_allowlist)
    approved_domains, blocked_domains, warn_domains, _ = _reconcile_domain_policy_sets(
        approved_domains=approved_domains,
        blocked_domains=blocked_domains,
        warn_domains=warn_domains,
        critical_domains=None,
    )

    critical_domains = {
        normalize_domain(app.tool_name)
        for app in apps
        if str(app.provisional_risk_tier or "").upper() in {"CRITICAL", "RESTRICTED", "PROHIBITED"}
        and normalize_domain(app.tool_name)
    }
    critical_domains.update({domain for domain in blocked_domains if domain})
    critical_domains.difference_update(control_plane_allowlist)
    approved_domains, blocked_domains, warn_domains, reconciled_critical = _reconcile_domain_policy_sets(
        approved_domains=approved_domains,
        blocked_domains=blocked_domains,
        warn_domains=warn_domains,
        critical_domains=critical_domains,
    )
    critical_domains = reconciled_critical or set()

    guardian_contracts: list[dict[str, Any]]
    if active_version and isinstance(active_version.guardian_contracts, list):
        guardian_contracts = [item for item in active_version.guardian_contracts if isinstance(item, dict)]
    else:
        guardian_contracts = []
    blocked_keywords, high_risk_terms, sensitive_patterns = _extract_guardian_keywords(guardian_contracts)
    unknown_behavior = "warn" if settings.pilot_mode else ("discover" if platform_mode == PLATFORM_MODE_DISCOVERY else "warn")

    try:
        provider_hints = _provider_enforcement_hints_for_browser(
            platform_mode=platform_mode,
            approved_domains=approved_domains,
            blocked_domains=blocked_domains,
        )
    except Exception as exc:  # pragma: no cover - defensive fallback
        log_structured(
            "extension_policy_sync_provider_hint_fallback",
            level="warning",
            tenant_id=tenant_id,
            error=str(exc),
        )
        provider_hints = []

    browser_automation_override: dict[str, Any] | None = None
    intent_aware_override: dict[str, Any] | None = None
    if active_version is not None:
        scope = active_version.scope if isinstance(active_version.scope, dict) else {}
        contract_json = active_version.contract_json if isinstance(active_version.contract_json, dict) else {}
        contract_scope = contract_json.get("scope") if isinstance(contract_json.get("scope"), dict) else {}
        candidates = [
            scope.get("browser_automation_control"),
            contract_scope.get("browser_automation_control"),
            contract_json.get("browser_automation_control"),
        ]
        for candidate in candidates:
            if isinstance(candidate, dict):
                browser_automation_override = dict(candidate)
                break
        intent_candidates = [
            scope.get("intent_aware_action_control"),
            contract_scope.get("intent_aware_action_control"),
            contract_json.get("intent_aware_action_control"),
        ]
        for candidate in intent_candidates:
            if isinstance(candidate, dict):
                intent_aware_override = dict(candidate)
                break
    browser_automation_control = _coerce_browser_automation_policy(
        policy=browser_automation_override,
        tenant_id=tenant_id,
        approved_domains=approved_domains,
        blocked_domains=blocked_domains,
        platform_mode=platform_mode,
    )
    intent_aware_action_control = _coerce_intent_aware_action_control_policy(
        policy=intent_aware_override,
        tenant_id=tenant_id,
        platform_mode=platform_mode,
    )

    return PolicySyncPayload(
        tenant_id=tenant_id,
        platform_mode=platform_mode,
        policy_version=str(active_version.id) if active_version else "none",
        approved_domains=sorted(approved_domains),
        blocked_domains=sorted(blocked_domains),
        warn_domains=sorted(warn_domains),
        critical_domains=sorted(critical_domains),
        unknown_domain_behavior=unknown_behavior,
        provider_enforcement_hints=provider_hints,
        interaction_rules={
            "input_checks_enabled": True,
            "output_checks_enabled": bool(intent_aware_action_control.get("enabled", True)),
            "sensitive_patterns": sensitive_patterns,
            "blocked_keywords": blocked_keywords,
            "high_risk_terms": high_risk_terms,
            "hold_for_backend_on_ambiguous": True,
            "backend_allow_confirmation_enabled": bool(settings.extension_backend_allow_confirmation_enabled),
        },
        browser_automation_control=browser_automation_control,
        intent_aware_action_control=intent_aware_action_control,
    )


def log_extension_policy_sync_access(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    policy_sync: PolicySyncPayload,
) -> str:
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="extension.policy_sync",
        resource_type="tenant",
        resource_id=tenant_id,
        payload={
            "platform_mode": policy_sync.platform_mode,
            "policy_version": policy_sync.policy_version,
            "approved_domains": len(policy_sync.approved_domains),
            "blocked_domains": len(policy_sync.blocked_domains),
            "warn_domains": len(policy_sync.warn_domains),
            "provider_hints": len(policy_sync.provider_enforcement_hints),
        },
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="extension_policy_sync",
        signal_type="extension.policy.sync",
        label=f"Extension policy sync for tenant {tenant_id}",
        payload={
            "policy_version": policy_sync.policy_version,
            "platform_mode": policy_sync.platform_mode,
            "unknown_domain_behavior": policy_sync.unknown_domain_behavior,
        },
    )
    db.flush()
    return audit.id


def _resolve_ai_system_for_domain(db: Session, *, tenant_id: str, domain: str) -> str | None:
    domain_norm = normalize_domain(domain)
    if not domain_norm:
        return None
    row = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == tenant_id,
            DiscoveryApplication.tool_key == tool_key_for_name(domain_norm),
            DiscoveryApplication.ai_system_id.is_not(None),
        )
    )
    if row and row.ai_system_id:
        return row.ai_system_id

    row = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == tenant_id,
            DiscoveryApplication.tool_name == domain_norm,
            DiscoveryApplication.ai_system_id.is_not(None),
        )
    )
    return row.ai_system_id if row else None


def _project_unknown_browser_domain_hypothesis(
    db: Session,
    *,
    tenant_id: str,
    domain: str,
    evidence_node_id: str,
    observed_at: datetime,
) -> DiscoveryAssetHypothesis:
    """Project one source-backed browser-domain hypothesis without retaining URL content."""
    candidate_key_hash = hashlib.sha256(
        f"hawk:browser-unknown-ai:v1\0{tenant_id}\0{domain}".encode("utf-8")
    ).hexdigest()
    statement = select(DiscoveryAssetHypothesis).where(
        DiscoveryAssetHypothesis.tenant_id == tenant_id,
        DiscoveryAssetHypothesis.candidate_key_hash == candidate_key_hash,
    )
    existing = db.scalar(statement)
    if existing is not None:
        return existing

    try:
        with db.begin_nested():
            return create_hypothesis(
                db,
                tenant_id=tenant_id,
                hypothesis_type="ai_application",
                label=domain,
                candidate_key_hash=candidate_key_hash,
                confidence=0.55,
                verification_state="inferred",
                freshness="fresh",
                contradiction_state="none",
                evidence_node_id=evidence_node_id,
                observed_at=observed_at,
                idempotency_key=f"browser-unknown-hypothesis:{candidate_key_hash}",
            )
    except (HypothesisConflict, IntegrityError):
        existing = db.scalar(statement)
        if existing is not None:
            return existing
        raise


def _activity_action_type_for_browser_event(event_type: str) -> str:
    normalized = str(event_type or "").strip().lower()
    if "automation" in normalized:
        return "tool_call"
    if "clipboard" in normalized or "copy" in normalized or "paste" in normalized:
        return "copy_paste"
    if "upload" in normalized:
        return "upload"
    if "agent_runtime" in normalized:
        return "agent_discovery"
    if "output" in normalized or "response" in normalized:
        return "response"
    if "tool" in normalized:
        return "tool_call"
    return "prompt_input"


def _agent_discovery_fingerprint(payload: dict[str, Any], domain: str) -> str:
    fields = (
        domain,
        str(payload.get("agent_id") or "").strip().lower(),
        str(payload.get("agent_name") or "").strip().lower(),
        str(payload.get("model_name") or "").strip().lower(),
        str(payload.get("runtime_provider") or "").strip().lower(),
        str(payload.get("agent_environment") or "").strip().lower(),
        *(",".join(sorted(_normalize_string_list(payload.get(key)))) for key in ("detected_tools", "detected_actions", "detected_privileges")),
    )
    return hashlib.sha256(json.dumps(fields, separators=(",", ":")).encode("utf-8")).hexdigest()


def _unchanged_agent_discovery(db: Session, *, tenant_id: str, domain: str, payload: dict[str, Any]) -> bool:
    fingerprint = _agent_discovery_fingerprint(payload, domain)
    identity = str(payload.get("agent_id") or payload.get("agent_name") or "").strip().lower()
    for row in db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type == "shadow_ai.browser_agent_runtime_discovered",
        )
        .order_by(MonitoringSignal.created_at.desc())
        .limit(200)
    ).all():
        previous = row.payload if isinstance(row.payload, dict) else {}
        if normalize_domain(previous.get("domain")) != domain:
            continue
        previous_identity = str(previous.get("agent_id") or previous.get("agent_name") or "").strip().lower()
        if previous_identity != identity:
            continue
        return _agent_discovery_fingerprint(previous, domain) == fingerprint
    return False


def _record_lightweight_browser_observation(
    db: Session, *, tenant_id: str, actor_user_id: str | None, payload: dict[str, Any],
    event_type: str, domain: str, policy_sync: PolicySyncPayload, companion: bool = False,
) -> dict[str, Any]:
    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=payload.get("ai_system_id") or _resolve_ai_system_for_domain(db, tenant_id=tenant_id, domain=domain),
        signal_type=f"browser.{event_type}",
        severity=str(payload.get("severity") or BROWSER_EVENT_SEVERITY.get(event_type, "low")).strip().lower(),
        payload={
            "event_type": event_type,
            "domain": domain,
            "action_taken": payload.get("action_taken"),
            "decision": payload.get("decision"),
            "policy_decision": payload.get("policy_decision"),
            "reason": payload.get("reason"),
            "reason_code": payload.get("reason_code"),
            "lifecycle_context_reason": payload.get("lifecycle_context_reason"),
            "status": payload.get("status"),
            "user_id": actor_user_id or payload.get("user_id"),
            "endpoint_id": payload.get("endpoint_id"),
            "correlation_id": correlation_id,
            "source_surface": "browser",
            "operational_telemetry": not companion,
            "policy_companion": companion,
            "policy_version": payload.get("policy_version") or policy_sync.policy_version,
            "platform_mode": payload.get("platform_mode") or policy_sync.platform_mode,
        },
    )
    db.add(signal)
    db.flush()
    audit = write_audit_log(
        db, tenant_id=tenant_id, actor_user_id=actor_user_id, actor_type="human",
        action="telemetry.browser.ingest", resource_type="monitoring_signal", resource_id=signal.id,
        payload={"event_type": event_type, "domain": domain, "policy_companion": companion},
        correlation_id=correlation_id,
    )
    evidence_id = ""
    if companion:
        evidence = create_evidence_node(
            db, tenant_id=tenant_id, node_type="browser_telemetry",
            signal_type=f"browser.{event_type}", label=f"Browser telemetry {event_type} on {domain}",
            payload={"monitoring_signal_id": signal.id, "event_type": event_type, "domain": domain,
                     "action_taken": payload.get("action_taken"), "policy_companion": True},
            correlation_id=correlation_id,
        )
        evidence_id = evidence.id
    return {
        "status": "ok", "monitoring_signal_id": signal.id, "audit_log_id": audit.id,
        "evidence_node_id": evidence_id, "finding_id": None,
        "policy_version": str(payload.get("policy_version") or policy_sync.policy_version),
        "platform_mode": str(payload.get("platform_mode") or policy_sync.platform_mode),
        "governance_recommendation": None, "runtime_event_id": None,
    }

def _safe_trimmed_text(value: Any, *, max_len: int = 255) -> str | None:
    token = str(value or "").strip()
    if not token:
        return None
    return token[:max_len]


def _bounded_runtime_strings(value: Any, *, max_items: int = 32, max_len: int = 255) -> list[str]:
    if not isinstance(value, list):
        return []
    output: list[str] = []
    for item in value[:max_items]:
        normalized = _safe_trimmed_text(item, max_len=max_len)
        if normalized and normalized not in output:
            output.append(normalized)
    return output


def _sanitize_agent_runtime_profile(value: Any) -> dict[str, Any]:
    """Retain only bounded, non-content runtime discovery evidence."""
    if not isinstance(value, dict):
        return {}
    integrations: list[dict[str, Any]] = []
    for raw in list(value.get("integration_transports") or [])[:16]:
        if not isinstance(raw, dict):
            continue
        capability = _safe_trimmed_text(raw.get("capability"), max_len=128)
        transport = _safe_trimmed_text(raw.get("transport"), max_len=128)
        destination = normalize_domain(raw.get("destination_domain"))
        evidence_basis = _safe_trimmed_text(raw.get("evidence_basis"), max_len=128)
        if not capability or not transport or not destination or not evidence_basis:
            continue
        integrations.append({
            "capability": capability,
            "transport": transport,
            "destination_domain": destination,
            "active": raw.get("active") is True,
            "evidence_basis": evidence_basis,
        })
    control_raw = value.get("control_binding")
    control = dict(control_raw) if isinstance(control_raw, dict) else {}
    process_raw = value.get("process")
    process = dict(process_raw) if isinstance(process_raw, dict) else {}
    client_raw = value.get("client")
    client = dict(client_raw) if isinstance(client_raw, dict) else {}
    ports = [
        int(port)
        for port in list(value.get("listening_ports") or [])[:16]
        if type(port) is int and 1 <= int(port) <= 65535
    ]
    return {
        "schema_version": _safe_trimmed_text(value.get("schema_version"), max_len=16) or "1.0",
        "agent_id": _safe_trimmed_text(value.get("agent_id"), max_len=128),
        "agent_name": _safe_trimmed_text(value.get("agent_name"), max_len=255),
        "agent_version": _safe_trimmed_text(value.get("agent_version"), max_len=128),
        "runtime_provider": _safe_trimmed_text(value.get("runtime_provider"), max_len=128),
        "model_provider": _safe_trimmed_text(value.get("model_provider"), max_len=128),
        "model_name": _safe_trimmed_text(value.get("model_name"), max_len=128),
        "models": _bounded_runtime_strings(value.get("models"), max_items=16, max_len=128),
        "tools": _bounded_runtime_strings(value.get("tools")),
        "actions": _bounded_runtime_strings(value.get("actions")),
        "privileges": _bounded_runtime_strings(value.get("privileges")),
        "listening_ports": ports,
        "integration_transports": integrations,
        "active_integration_transport": _safe_trimmed_text(
            value.get("active_integration_transport"), max_len=128
        ) or "unknown",
        "control_binding": {
            "mode": _safe_trimmed_text(control.get("mode"), max_len=32) or "monitor",
            "pre_action_surfaces": _bounded_runtime_strings(
                control.get("pre_action_surfaces"), max_items=8, max_len=64
            ),
        },
        "evidence_basis": _safe_trimmed_text(value.get("evidence_basis"), max_len=128)
        or "unknown",
        "process": {
            "pid": int(process.get("pid")) if type(process.get("pid")) is int and int(process["pid"]) > 0 else None,
            "platform": _safe_trimmed_text(process.get("platform"), max_len=64),
            "architecture": _safe_trimmed_text(process.get("architecture"), max_len=64),
        },
        "client": {
            "name": _safe_trimmed_text(client.get("name"), max_len=128),
            "version": _safe_trimmed_text(client.get("version"), max_len=128),
            "runtime": _safe_trimmed_text(client.get("runtime"), max_len=64),
        },
    }


def process_browser_telemetry_event(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    event_type = str(payload.get("event_type") or "").strip().lower()
    if not event_type:
        raise ValueError("event_type is required")

    domain = normalize_domain(payload.get("domain") or _domain_from_url(payload.get("url")))
    if not domain:
        raise ValueError("domain or url is required")

    policy_sync = build_extension_policy_sync(db, tenant_id=tenant_id)
    lifecycle_context_reason = _browser_context_lifecycle_reason(payload)
    if lifecycle_context_reason and not _browser_context_has_real_decision(payload):
        lifecycle_payload = dict(payload)
        lifecycle_payload["lifecycle_context_reason"] = lifecycle_context_reason
        return _record_lightweight_browser_observation(
            db, tenant_id=tenant_id, actor_user_id=actor_user_id, payload=lifecycle_payload,
            event_type=event_type, domain=domain, policy_sync=policy_sync,
        )
    if event_type == "prompt_drafted":
        return {
            "status": "ignored", "monitoring_signal_id": "", "audit_log_id": "",
            "evidence_node_id": "", "finding_id": None,
            "policy_version": str(payload.get("policy_version") or policy_sync.policy_version),
            "platform_mode": str(payload.get("platform_mode") or policy_sync.platform_mode),
            "governance_recommendation": None, "runtime_event_id": None,
        }
    if event_type in {"unknown_ai_detected", "agent_runtime_discovered"} and _is_hawk_control_plane_browser_surface(domain, payload):
        log_structured(
            "browser_agent_runtime_discovery_ignored_control_plane",
            module="browser_extension_service",
            tenant_id=tenant_id,
            domain=domain,
            url=payload.get("url"),
            page_title=payload.get("page_title"),
            correlation_id=str(payload.get("correlation_id") or "").strip() or None,
        )
        return {
            "status": "ignored",
            "monitoring_signal_id": "",
            "audit_log_id": "",
            "evidence_node_id": "",
            "finding_id": None,
            "policy_version": str(payload.get("policy_version") or policy_sync.policy_version),
            "platform_mode": str(payload.get("platform_mode") or policy_sync.platform_mode),
            "governance_recommendation": None,
            "runtime_event_id": None,
        }

    if event_type == "agent_runtime_discovered" and _unchanged_agent_discovery(
        db, tenant_id=tenant_id, domain=domain, payload=payload,
    ):
        return {
            "status": "unchanged", "monitoring_signal_id": "", "audit_log_id": "",
            "evidence_node_id": "", "finding_id": None,
            "policy_version": str(payload.get("policy_version") or policy_sync.policy_version),
            "platform_mode": str(payload.get("platform_mode") or policy_sync.platform_mode),
            "governance_recommendation": None, "runtime_event_id": None,
        }

    action_taken = str(payload.get("action_taken") or "").strip().lower()
    status_value = str(payload.get("status") or "").strip().lower()
    failed = any(marker in action_taken or marker in status_value for marker in ("fail", "error", "degrad", "block", "warn", "tamper", "invalid", "unhealthy"))
    routine_status = event_type in {
        "extension_installed", "extension_connected", "policy_sync_success", "context_recovered",
    } or (event_type == "extension_health_status" and status_value in {"healthy", "ok", "connected"})
    known_app = bool(payload.get("ai_system_id") or _resolve_ai_system_for_domain(db, tenant_id=tenant_id, domain=domain))
    passive_known_app = event_type in {"ai_domain_visit", "ai_app_opened"} and (
        known_app or any(_domain_matches(domain, item) for item in policy_sync.approved_domains or [])
    )
    if (routine_status or passive_known_app) and not failed:
        return _record_lightweight_browser_observation(
            db, tenant_id=tenant_id, actor_user_id=actor_user_id, payload=payload,
            event_type=event_type, domain=domain, policy_sync=policy_sync,
        )
    if event_type in {"policy_blocked", "policy_warned"} and payload.get("correlation_id"):
        primary_types = {"browser.prompt_blocked", "browser.prompt_warned", "browser.prompt_held", "browser.browser_automation_blocked"}
        previous = db.scalars(
            select(MonitoringSignal)
            .where(MonitoringSignal.tenant_id == tenant_id, MonitoringSignal.signal_type.in_(primary_types))
            .order_by(MonitoringSignal.created_at.desc()).limit(200)
        ).all()
        if any(
            isinstance(row.payload, dict)
            and str(row.payload.get("correlation_id") or "").strip() == str(payload["correlation_id"]).strip()
            and normalize_domain(row.payload.get("domain")) == domain
            for row in previous
        ):
            return _record_lightweight_browser_observation(
                db, tenant_id=tenant_id, actor_user_id=actor_user_id, payload=payload,
                event_type=event_type, domain=domain, policy_sync=policy_sync, companion=True,
            )

    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    ai_system_id = payload.get("ai_system_id") or _resolve_ai_system_for_domain(db, tenant_id=tenant_id, domain=domain)
    agent_id = _safe_trimmed_text(payload.get("agent_id"), max_len=36)
    agent_name = _safe_trimmed_text(payload.get("agent_name"), max_len=255)
    runtime_provider = _safe_trimmed_text(payload.get("runtime_provider"), max_len=128)
    model_name = _safe_trimmed_text(payload.get("model_name"), max_len=128)
    agent_environment = _safe_trimmed_text(payload.get("agent_environment"), max_len=128)
    detected_tools = _normalize_string_list(payload.get("detected_tools"))
    detected_actions = _normalize_string_list(payload.get("detected_actions"))
    detected_privileges = _normalize_string_list(payload.get("detected_privileges"))
    agent_runtime_profile = _sanitize_agent_runtime_profile(payload.get("agent_runtime_profile"))
    integration_transports = list(agent_runtime_profile.get("integration_transports") or [])
    active_integration_transport = str(
        agent_runtime_profile.get("active_integration_transport")
        or payload.get("active_integration_transport")
        or "unknown"
    ).strip()
    control_binding = dict(agent_runtime_profile.get("control_binding") or {})
    evidence_basis = str(
        agent_runtime_profile.get("evidence_basis")
        or payload.get("evidence_basis")
        or "unknown"
    ).strip()
    control_binding_state = "monitor_only" if event_type == "agent_runtime_discovered" else "unknown"
    automation_suspected = bool(payload.get("automation_suspected"))
    automation_confidence_raw = payload.get("automation_confidence")
    try:
        automation_confidence = float(automation_confidence_raw) if automation_confidence_raw is not None else None
    except (TypeError, ValueError):
        automation_confidence = None
    suspected_tool = _safe_trimmed_text(payload.get("suspected_tool"), max_len=128)
    automation_indicators = _normalize_string_list(payload.get("automation_indicators"))
    actor_user_email = _payload_text(payload, "user_email", "email") or _resolve_actor_user_email(db, actor_user_id)
    payload_user_id = _payload_text(payload, "user_id")
    event_user_id = actor_user_id or payload_user_id
    source_user_ref = payload_user_id if payload_user_id and payload_user_id != event_user_id else None
    machine_id = _payload_text(payload, "machine_id", "endpoint_id", "device_id")
    endpoint_id = _payload_text(payload, "endpoint_id", "device_id")
    browser_type = _payload_text(payload, "browser_type", "browser") or "chrome"
    application = _payload_text(payload, "application", "ai_app", "app") or domain
    source_surface = str(payload.get("source_surface") or "browser").strip().lower() or "browser"
    if source_surface == "endpoint_agent":
        source_surface = "endpoint-agent"
    if source_surface not in {"browser", "desktop_app", "endpoint-agent"}:
        source_surface = "browser"
    policy_version = str(payload.get("policy_version") or policy_sync.policy_version)
    platform_mode = str(payload.get("platform_mode") or policy_sync.platform_mode)
    action_type = _payload_text(payload, "action_type")
    action_risk = _payload_text(payload, "action_risk")
    decision_badge = _payload_text(payload, "decision_badge") or _decision_badge_from_signal_types(payload)
    reason = _payload_text(payload, "reason")
    automation_source = _payload_text(payload, "automation_source")
    scope_domain = _payload_text(payload, "scope_domain")
    current_domain = normalize_domain(payload.get("current_domain") or domain)
    current_url = _payload_text(payload, "current_url", "url")
    semantic_action_types = {
        "clipboard_copy_detected": "copy_output",
        "clipboard_cut_detected": "copy_output",
        "clipboard_paste_detected": "paste_output_to_external_site",
        "file_upload_detected": "upload",
        "file_upload_attempted": "upload",
        "agent_runtime_discovered": "agent_discovery",
        "unknown_ai_detected": "unknown_ai_discovery",
        "ai_domain_visit": "domain_visit",
        "ai_app_opened": "app_opened",
        "extension_health_status": "extension_status",
        "browser_automation_action": "browser_automation",
        "browser_automation_detected": "browser_automation",
        "browser_automation_blocked": "browser_automation",
    }
    resolved_action_type = action_type or semantic_action_types.get(event_type) or (
        "meeting_observation" if event_type.startswith(("meeting_", "device_audio_"))
        else ("prompt_submit" if event_type.startswith("prompt_") else event_type)
    )
    is_browser_automation_event = event_type in {
        "browser_automation_action",
        "browser_automation_detected",
        "browser_automation_blocked",
    }
    input_text_for_intent = (
        ""
        if is_browser_automation_event
        else str(
            payload.get("raw_prompt")
            or payload.get("prompt_text")
            or payload.get("prompt_preview_redacted")
            or payload.get("page_title")
            or ""
        )
    )
    output_text_for_intent = str(
        payload.get("output_text_preview_redacted")
        or payload.get("copied_text_preview_redacted")
        or payload.get("selected_text_preview_redacted")
        or (payload.get("prompt_preview_redacted") if resolved_action_type in {"copy_output", "download_output", "export_output", "share_output"} else "")
        or ""
    )
    intent_context = classify_intent_context(
        declared_intent=_payload_text(payload, "declared_intent", "intent"),
        text=input_text_for_intent or output_text_for_intent,
        action_type=resolved_action_type,
        business_context=_payload_text(payload, "business_context"),
    )
    input_content_context = classify_input_content_context(
        input_text_for_intent,
        file_meta=[item for item in (payload.get("file_meta") or []) if isinstance(item, dict)],
    )
    output_context = (
        classify_output_context(
            output_text=output_text_for_intent,
            output_ref=_payload_text(payload, "output_ref") or correlation_id,
        )
        if output_text_for_intent
        else {}
    )
    action_alignment_result = evaluate_action_alignment(
        intent_context=intent_context,
        action_type=resolved_action_type,
        input_content_context=input_content_context,
        output_context=output_context,
    )
    intent_policy = dict(payload.get("intent_policy") or {}) if isinstance(payload.get("intent_policy"), dict) else {}
    if not intent_policy:
        intent_policy = dict(policy_sync.intent_aware_action_control or {})
        if platform_mode == PLATFORM_MODE_DISCOVERY and str(intent_policy.get("mode") or "").strip().lower() == "block":
            intent_policy["mode"] = "warn"
    if not intent_policy:
        intent_policy = {
            "policy_id": "INTENT_AWARE_AI_ACTION_CONTROL",
            "mode": "warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block",
        }
    intent_aware_decision = evaluate_intent_aware_action_control(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        action_type=resolved_action_type,
        policy=intent_policy,
    )
    has_intent_or_content_evidence = bool(
        _payload_text(payload, "declared_intent", "intent")
        or ("" if is_browser_automation_event else str(payload.get("raw_prompt") or payload.get("prompt_text") or payload.get("prompt_preview_redacted") or "").strip())
        or output_text_for_intent.strip()
        or input_content_context.get("contains_secrets")
        or input_content_context.get("contains_business_emails")
        or input_content_context.get("contains_customer_data")
        or output_context.get("contains_business_email")
        or output_context.get("contains_customer_contact")
        or output_context.get("contains_secret_like_value")
    )
    if is_browser_automation_event and not has_intent_or_content_evidence:
        intent_aware_decision = {
            "policy_category": "INTENT_AWARE_AI_ACTION_CONTROL",
            "decision": "allow",
            "would_decision": "allow",
            "mode": str(intent_policy.get("mode") or "block"),
            "decision_reason": "browser_automation_control_primary",
            "finding_type": None,
            "intent_category": intent_context.get("intent_category"),
            "action_alignment": action_alignment_result.get("alignment") or "unknown",
            "matched_indicators": [],
            "copy_export_control_applied": False,
        }
    governance_status = resolve_ai_system_status(
        ai_system_id,
        {
            "db": db,
            "tenant_id": tenant_id,
            "source_hint": "shadow_discovery",
            "route": "/telemetry/browser",
            "module": "browser_extension",
        },
    )
    detection_result = detect_sensitive_data(
        text_inputs=[str(payload.get("prompt_preview_redacted") or "")],
        file_meta=[item for item in (payload.get("file_meta") or []) if isinstance(item, dict)],
        source="browser",
        destination=domain,
        ai_system_id=ai_system_id,
        user_id=actor_user_id,
        correlation_id=str(payload.get("correlation_id") or "").strip() or None,
    )
    severity = str(payload.get("severity") or BROWSER_EVENT_SEVERITY.get(event_type, "low")).strip().lower()
    signal_type = (
        "shadow_ai.browser_unknown_domain"
        if event_type == "unknown_ai_detected"
        else (
            "shadow_ai.browser_agent_runtime_discovered"
            if event_type == "agent_runtime_discovered"
            else f"browser.{event_type}"
        )
    )
    timestamp = payload.get("timestamp") or datetime.now(timezone.utc).isoformat()
    routing = route_enforcement(
        {
            "policy_id": str(payload.get("policy_id") or "extension_policy"),
            "policy_version": str(payload.get("policy_version") or policy_sync.policy_version or "none"),
        },
        {
            "event_id": str(payload.get("event_id") or ""),
            "tenant_id": tenant_id,
            "source_surface": source_surface,
            "action_type": event_type,
            "ai_system_id": ai_system_id,
            "agent_id": None,
            "data_classification": payload.get("source_classification_hint"),
            "correlation_id": payload.get("correlation_id"),
        },
    )

    destination_context = {
        "domain": domain,
        "application": application,
        "trust_level": _browser_destination_trust_level(
            domain=domain,
            policy_sync=policy_sync,
            ai_system_id=ai_system_id,
        ),
        "control_mode": "browser_extension",
    }
    intent_aware_evidence_summary = build_intent_aware_evidence_summary(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        intent_aware_decision=intent_aware_decision,
        action_type=resolved_action_type,
        action_risk=action_risk,
        destination_context=destination_context,
        policy_snapshot={
            "policy_id": str(intent_policy.get("policy_id") or "INTENT_AWARE_AI_ACTION_CONTROL"),
            "policy_version": str(payload.get("policy_version") or policy_sync.policy_version or "none"),
            "mode": str(intent_policy.get("mode") or "block"),
        },
        control_mode="browser_extension",
    )

    meeting_surface = _payload_text(payload, "meeting_surface")
    notetaker_provider = _payload_text(payload, "notetaker_provider")
    notetaker_label = _payload_text(payload, "notetaker_label")
    meeting_id = _payload_text(payload, "meeting_id")
    meeting_title = _payload_text(payload, "meeting_title")
    meeting_organizer_email = _payload_text(payload, "meeting_organizer_email")
    meeting_signal_source = _payload_text(payload, "meeting_signal_source")
    calendar_invitee_domain = _payload_text(payload, "calendar_invitee_domain")
    oauth_app_id = _payload_text(payload, "oauth_app_id")
    meeting_control_mode = _payload_text(payload, "control_mode")
    endpoint_audio_signal_basis = _payload_text(payload, "endpoint_audio_signal_basis")
    microphone_permission_state = _payload_text(payload, "microphone_permission_state")
    microphone_control_authority = _payload_text(payload, "microphone_control_authority")
    microphone_control_mode = _payload_text(payload, "microphone_control_mode")
    raw_audio_captured = _payload_bool(payload, "raw_audio_captured")
    audio_content_captured = _payload_bool(payload, "audio_content_captured")
    microphone_revocation_available = _payload_bool(payload, "microphone_revocation_available")
    local_process_control_available = _payload_bool(payload, "local_process_control_available")
    microphone_control_requirements = [
        str(item).strip()
        for item in (payload.get("microphone_control_requirements") or [])
        if str(item or "").strip()
    ]
    endpoint_audio_posture = {
        "raw_audio_captured": raw_audio_captured,
        "audio_content_captured": audio_content_captured,
        "endpoint_audio_signal_basis": endpoint_audio_signal_basis,
        "microphone_permission_state": microphone_permission_state,
        "microphone_revocation_available": microphone_revocation_available,
        "microphone_control_authority": microphone_control_authority,
        "microphone_control_mode": microphone_control_mode,
        "microphone_control_requirements": microphone_control_requirements,
        "local_process_control_available": local_process_control_available,
    }
    participant_visible_raw = payload.get("participant_visible")
    participant_visible = (
        bool(participant_visible_raw)
        if participant_visible_raw is not None
        else None
    )

    signal_payload = {
        "domain": domain,
        "ai_tool": domain,
        "url": payload.get("url"),
        "page_title": payload.get("page_title"),
        "policy_version": payload.get("policy_version") or policy_sync.policy_version,
        "platform_mode": payload.get("platform_mode") or policy_sync.platform_mode,
        "action_taken": payload.get("action_taken"),
        "prompt_preview_redacted": payload.get("prompt_preview_redacted"),
        "input_signal_types": payload.get("input_signal_types") or [],
        "file_meta": payload.get("file_meta") or [],
        "browser": payload.get("browser") or "chrome",
        "browser_type": browser_type,
        "browser_profile": payload.get("browser_profile") or "default",
        "browser_version": payload.get("browser_version"),
        "extension_version": payload.get("extension_version"),
        "user_id": event_user_id,
        "user_email": actor_user_email,
        "source_user_ref": source_user_ref,
        "source_user_ref_status": "browser_payload_external" if source_user_ref else None,
        "machine_id": machine_id,
        "endpoint_id": endpoint_id,
        "session_id": payload.get("session_id"),
        "hostname": payload.get("hostname"),
        "device_type": payload.get("device_type"),
        "os_type": payload.get("os_type"),
        "os_version": payload.get("os_version"),
        "ip_address": payload.get("ip_address"),
        "location": payload.get("location"),
        "source_surface": source_surface,
        "timestamp": timestamp,
        "correlation_id": payload.get("correlation_id"),
        "governance_state": governance_status.get("status"),
        "governance_reason": governance_status.get("reason"),
        "governance_enforcement_mode": governance_status.get("enforcement_mode"),
        "enforcement_routing": routing,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "runtime_provider": runtime_provider,
        "model_name": model_name,
        "agent_environment": agent_environment,
        "detected_tools": detected_tools,
        "detected_actions": detected_actions,
        "detected_privileges": detected_privileges,
        "agent_runtime_profile": agent_runtime_profile,
        "integration_transports": integration_transports,
        "active_integration_transport": active_integration_transport,
        "control_binding": control_binding,
        "control_binding_state": control_binding_state,
        "evidence_basis": evidence_basis,
        "automation_suspected": automation_suspected,
        "automation_confidence": automation_confidence,
        "automation_source": automation_source,
        "suspected_tool": suspected_tool,
        "automation_indicators": automation_indicators,
        "application": application,
        "action_type": resolved_action_type,
        "action_risk": action_risk,
        "decision_badge": decision_badge,
        "reason": reason,
        "intent_context": intent_context,
        "input_content_context": input_content_context,
        "output_context": output_context,
        "action_alignment_result": action_alignment_result,
        "intent_aware_decision": intent_aware_decision,
        "intent_category": intent_context.get("intent_category"),
        "intent_confidence": intent_context.get("intent_confidence"),
        "business_context": intent_context.get("business_context"),
        "input_sensitivity": input_content_context.get("sensitivity_level"),
        "output_sensitivity": output_context.get("output_sensitivity"),
        "action_alignment": action_alignment_result.get("alignment"),
        "destination_context": destination_context,
        "intent_aware_evidence_summary": intent_aware_evidence_summary,
        "matched_indicators": list(intent_aware_decision.get("matched_indicators") or []),
        "copy_export_control_applied": bool(intent_aware_decision.get("copy_export_control_applied")),
        "decision_reason": intent_aware_decision.get("decision_reason"),
        "scope_domain": scope_domain,
        "current_domain": current_domain or domain,
        "current_url": current_url,
        "meeting_surface": meeting_surface,
        "notetaker_provider": notetaker_provider,
        "notetaker_label": notetaker_label,
        "participant_visible": participant_visible,
        "meeting_id": meeting_id,
        "meeting_title": meeting_title,
        "meeting_organizer_email": meeting_organizer_email,
        "meeting_signal_source": meeting_signal_source,
        "calendar_invitee_domain": calendar_invitee_domain,
        "oauth_app_id": oauth_app_id,
        "control_mode": meeting_control_mode,
        "raw_audio_captured": raw_audio_captured,
        "audio_content_captured": audio_content_captured,
        "endpoint_audio_signal_basis": endpoint_audio_signal_basis,
        "microphone_permission_state": microphone_permission_state,
        "microphone_revocation_available": microphone_revocation_available,
        "microphone_control_authority": microphone_control_authority,
        "microphone_control_mode": microphone_control_mode,
        "microphone_control_requirements": microphone_control_requirements,
        "local_process_control_available": local_process_control_available,
        "endpoint_audio_posture": endpoint_audio_posture,
        "contains_sensitive": bool(detection_result.get("contains_sensitive")),
        "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
        "sensitive_entities": list(detection_result.get("entities") or []),
        "sensitive_detection": detection_result,
    }
    browser_automation_signal_types = [
        f"action_type:{resolved_action_type}" if resolved_action_type else None,
        f"action_risk:{action_risk}" if action_risk else None,
        f"decision_badge:{decision_badge.replace(' ', '_').lower()}" if decision_badge else None,
        f"automation_source:{automation_source}" if automation_source else None,
        f"reason:{reason}" if reason else None,
        f"intent_category:{intent_context.get('intent_category')}" if intent_context.get("intent_category") else None,
        f"input_sensitivity:{input_content_context.get('sensitivity_level')}" if input_content_context.get("sensitivity_level") else None,
        f"output_sensitivity:{output_context.get('output_sensitivity')}" if output_context.get("output_sensitivity") else None,
        f"action_alignment:{action_alignment_result.get('alignment')}" if action_alignment_result.get("alignment") else None,
        f"finding_type:{intent_aware_decision.get('finding_type')}" if intent_aware_decision.get("finding_type") else None,
        f"meeting_surface:{meeting_surface}" if meeting_surface else None,
        f"notetaker_provider:{notetaker_provider}" if notetaker_provider else None,
        f"participant_visible:{str(participant_visible).lower()}" if participant_visible is not None else None,
        f"meeting_signal_source:{meeting_signal_source}" if meeting_signal_source else None,
        f"calendar_invitee_domain:{calendar_invitee_domain}" if calendar_invitee_domain else None,
        f"oauth_app_id:{oauth_app_id}" if oauth_app_id else None,
        f"control_mode:{meeting_control_mode}" if meeting_control_mode else None,
        f"endpoint_audio_signal_basis:{endpoint_audio_signal_basis}" if endpoint_audio_signal_basis else None,
        f"microphone_control_mode:{microphone_control_mode}" if microphone_control_mode else None,
        f"microphone_control_authority:{microphone_control_authority}" if microphone_control_authority else None,
        "intent_aware_ai_action_control",
    ]
    signal_payload["input_signal_types"] = sorted(
        {
            *[str(item) for item in (signal_payload.get("input_signal_types") or []) if str(item).strip()],
            *[str(item) for item in browser_automation_signal_types if str(item or "").strip()],
            *detection_signal_types(detection_result),
        }
    )
    current_signal_decision = str(signal_payload.get("action_taken") or "").strip().lower().split(":", 1)[0]
    if current_signal_decision not in {"allow", "warn", "block"}:
        if event_type in {"prompt_blocked", "browser_automation_blocked"}:
            current_signal_decision = "block"
        elif event_type in {"prompt_warned", "prompt_held", "browser_automation_detected", "browser_automation_action"}:
            current_signal_decision = "warn"
        else:
            current_signal_decision = "allow"
    meeting_event_types = {
        "meeting_ai_notetaker_detected",
        "meeting_ai_notetaker_block_requested",
        "meeting_ai_notetaker_hidden_suspected",
        "meeting_ai_notetaker_calendar_invitee_detected",
        "meeting_ai_notetaker_oauth_detected",
        "device_audio_notetaker_detected",
        "device_audio_notetaker_control_applied",
        "meeting_transcription_policy_violation",
    }
    intent_signal_decision = str(intent_aware_decision.get("decision") or "").strip().lower()
    apply_intent_decision_overlay = (
        event_type not in meeting_event_types
        and
        intent_signal_decision in {"block", "warn"}
        and _decision_rank(intent_signal_decision) > _decision_rank(current_signal_decision)
    )
    if apply_intent_decision_overlay:
        signal_payload["action_taken"] = f"{intent_aware_decision['decision']}:{intent_aware_decision.get('decision_reason') or 'intent_aware_policy'}"
        signal_payload["decision_badge"] = (
            "Blocked Sensitive Input"
            if intent_aware_decision["decision"] == "block" and resolved_action_type not in {"copy_output", "download_output", "export_output", "share_output"}
            else (
                "Blocked Output Copy"
                if intent_aware_decision["decision"] == "block"
                else "Intent Review"
            )
        )
        if intent_aware_decision["decision"] == "block":
            severity = "high" if severity in {"low", "med", "medium"} else severity
    if event_type in {"browser_automation_action", "browser_automation_detected", "browser_automation_blocked"}:
        browser_policy = dict(policy_sync.browser_automation_control or {})
        policy_scope = dict(browser_policy.get("scope") or {}) if isinstance(browser_policy.get("scope"), dict) else {}
        matched_override: dict[str, Any] | None = None
        for override in browser_policy.get("action_overrides") or []:
            if not isinstance(override, dict):
                continue
            override_domains = _normalize_string_list(override.get("domains"))
            if override.get("domain"):
                override_domains.append(str(override.get("domain")))
            if any(_domain_matches(domain, candidate) for candidate in override_domains):
                matched_override = override
                break
        policy_mode = str(browser_policy.get("mode") or "block").strip().lower()
        purpose_permission = {
            "permission_id": str(browser_policy.get("policy_id") or "browser_automation_control_default"),
            "identity_id": agent_id or event_user_id or "browser-user",
            "identity_type": "agent" if automation_suspected else "human",
            "purpose": {
                "name": "browser_visible_action_governance",
                "description": str(browser_policy.get("name") or "Browser Automation Control"),
                "declared_intent": reason,
            },
            "scope": {
                "allowed_actions": list((matched_override or {}).get("allowed_actions") or browser_policy.get("allowed_actions") or []),
                "blocked_actions": list((matched_override or {}).get("blocked_actions") or browser_policy.get("blocked_actions") or []),
                "allowed_tools": [],
                "blocked_tools": [],
                "allowed_domains": list(policy_scope.get("domains_allowlist") or []),
                "blocked_domains": list(policy_scope.get("domains_blocklist") or []),
                "allowed_resources": [],
                "blocked_resources": [],
                "allowed_data_scopes": [],
                "allowed_environments": ["prod", "staging", "dev", "unknown"],
            },
            "constraints": {
                "expiry": None,
                "max_action_count": None,
                "max_risk_level": "low" if resolved_action_type in DEFAULT_BROWSER_AUTOMATION_ALLOWED_ACTIONS else "medium",
                "approval_required_for": ["high", "critical", "admin", "financial", "credential"],
                "require_human_confirmation": False,
            },
            "status": "active",
            "mode": "shadow" if policy_mode == "monitor" else policy_mode,
        }
        resolved_decision = _decision_for_browser_event(event_type, signal_payload.get("action_taken"))
        resolved_action_category = action_category_for(action_type)
        resolved_action_risk = (action_risk or action_risk_for(action_type, environment="prod")).lower()
        purpose_result = evaluate_purpose_bound_permission(
            permission=purpose_permission,
            action_type=resolved_action_type or event_type,
            action_category=resolved_action_category,
            action_risk=resolved_action_risk,
            tool_name=application or domain,
            target_resource=current_url or domain,
            domain=current_domain or domain,
            environment="prod",
            current_action_count=1,
        )
        if resolved_decision in {"block", "warn"}:
            purpose_result = {
                **purpose_result,
                "decision": resolved_decision,
                "reason": reason or purpose_result.get("reason") or "browser_action_policy",
                "violations": list(purpose_result.get("violations") or [resolved_action_type or event_type]),
            }
        elif resolved_decision == "allow":
            purpose_result = {
                **purpose_result,
                "decision": "allow",
                "reason": "browser_action_allowed",
                "violations": [],
            }
        pre_action_governance_check = build_pre_action_governance_check(
            tenant_id=tenant_id,
            action_id=str(payload.get("event_id") or correlation_id or f"browser:{event_type}:{domain}"),
            source_event_id=str(payload.get("event_id") or "").strip() or None,
            actor={
                "identity_id": agent_id or event_user_id,
                "identity_type": "agent" if automation_suspected else "human",
                "user_id": event_user_id,
                "email": actor_user_email,
                "agent_id": agent_id,
                "agent_name": agent_name,
                "session_id": payload.get("session_id"),
                "machine_id": machine_id,
                "acting_on_behalf_of_user_id": event_user_id,
            },
            authority={
                "authority_type": "user_session",
                "authority_owner": actor_user_id,
                "authority_source": "browser_extension",
                "auth_strength": "browser_session",
                "standing_privilege": "unknown" if automation_suspected else False,
                "verified": bool(actor_user_id),
            },
            purpose_permission=purpose_permission,
            purpose_result=purpose_result,
            surface={
                "surface_type": "browser",
                "application": application,
                "provider": runtime_provider,
                "model": model_name,
                "domain": current_domain or domain,
                "url": current_url,
                "asset_id": ai_system_id,
                "environment": "prod",
                "asset_status": str(governance_status.get("status") or "UNKNOWN").lower(),
            },
            action={
                "action_type": resolved_action_type or event_type,
                "action_category": resolved_action_category,
                "action_risk": resolved_action_risk,
                "target_resource": current_url or domain,
                "tool_name": application or domain,
                "parameter_hash": hashlib.sha256(
                    json.dumps(
                        payload.get("parameters")
                        or payload.get("tool_arguments")
                        or payload.get("request_body")
                        or {},
                        sort_keys=True,
                        separators=(",", ":"),
                        default=str,
                    ).encode("utf-8")
                ).hexdigest(),
            },
            workflow_risk_context={
                "workflow_id": correlation_id or str(payload.get("session_id") or ""),
                "previous_action_count": 0,
                "cumulative_risk_score": SEVERITY_RISK_SCORE.get(severity, 0.5),
                "scope_drift_score": 0.7 if str(reason or "").lower() in {"scope_violation", "domain_outside_allowlist"} else 0.0,
                "privilege_escalation_score": 0.0,
                "recent_violations_count": 1 if resolved_decision == "block" else 0,
                "risk_drivers": list(purpose_result.get("violations") or []),
            },
            policy_snapshot_id=str(signal_payload.get("policy_version") or ""),
            policy_ids=[str(browser_policy.get("policy_id") or "browser_automation_control_default")],
            control_ids=["CTRL-BROWSER-AUTOMATION-001"],
            evidence_refs=[],
            trace_id=correlation_id,
            inline=True,
        )
        signal_payload["pre_action_governance_check"] = pre_action_governance_check
        signal_payload["control_mode"] = pre_action_governance_check["control_mode"]
        signal_payload["decision_badge"] = pre_action_governance_check["decision_badge"] if not decision_badge else decision_badge
    governance_recommendation: str | None = None
    if event_type in {"unknown_ai_detected", "agent_runtime_discovered"}:
        signal_payload["risk_category"] = "shadow_ai"
        governance_recommendation = "route_to_governance_review"
        signal_payload["governance_recommendation"] = governance_recommendation
    elif event_type in {"browser_automation_detected", "browser_automation_blocked"}:
        signal_payload["risk_category"] = "browser_automation"
        governance_recommendation = (
            "contain_browser_automation_session"
            if event_type == "browser_automation_blocked"
            else "review_browser_automation_controls"
        )
        signal_payload["governance_recommendation"] = governance_recommendation

    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        signal_type=signal_type,
        severity=severity,
        payload=signal_payload,
    )
    db.add(signal)
    db.flush()


    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="telemetry.browser.ingest",
        resource_type="monitoring_signal",
        resource_id=signal.id,
        payload={
            "event_type": event_type,
            "domain": domain,
            "severity": severity,
            "policy_version": signal_payload["policy_version"],
            "platform_mode": signal_payload["platform_mode"],
            "browser": signal_payload["browser"],
            "browser_profile": signal_payload["browser_profile"],
            "extension_version": signal_payload["extension_version"],
        },
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="browser_telemetry",
        signal_type=signal_type,
        label=f"Browser telemetry {event_type} on {domain}",
        payload={
            "monitoring_signal_id": signal.id,
            "event_type": event_type,
            "domain": domain,
            "policy_version": signal_payload["policy_version"],
            "platform_mode": signal_payload["platform_mode"],
            "action_taken": signal_payload["action_taken"],
            "input_signal_types": signal_payload["input_signal_types"],
            "browser_profile": signal_payload["browser_profile"],
            "extension_version": signal_payload["extension_version"],
            "governance_recommendation": governance_recommendation,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
            "pre_action_governance_check": signal_payload.get("pre_action_governance_check"),
            "control_mode": signal_payload.get("control_mode"),
            "decision_badge": signal_payload.get("decision_badge"),
            "intent_context": intent_context,
            "input_content_context": input_content_context,
            "output_context": output_context,
            "action_alignment_result": action_alignment_result,
            "intent_aware_decision": intent_aware_decision,
            "destination_context": destination_context,
            "intent_aware_evidence_summary": intent_aware_evidence_summary,
            "meeting_notetaker": {
                "meeting_surface": signal_payload.get("meeting_surface"),
                "notetaker_provider": signal_payload.get("notetaker_provider"),
                "notetaker_label": signal_payload.get("notetaker_label"),
                "participant_visible": signal_payload.get("participant_visible"),
                "meeting_signal_source": signal_payload.get("meeting_signal_source"),
                "calendar_invitee_domain": signal_payload.get("calendar_invitee_domain"),
                "oauth_app_id": signal_payload.get("oauth_app_id"),
                "control_mode": signal_payload.get("control_mode"),
                "endpoint_audio_posture": signal_payload.get("endpoint_audio_posture"),
            }
            if event_type.startswith("meeting_") or event_type.startswith("device_audio_")
            else None,
            "agent_runtime_profile": agent_runtime_profile or None,
            "active_integration_transport": active_integration_transport,
            "control_binding_state": control_binding_state,
            "evidence_basis": evidence_basis,
        },
        correlation_id=correlation_id,
    )
    if isinstance(signal_payload.get("pre_action_governance_check"), dict):
        pre_action_copy = dict(signal_payload["pre_action_governance_check"])
        pre_action_evidence = dict(pre_action_copy.get("evidence") or {})
        pre_action_evidence["evidence_refs"] = sorted(
            {
                *[str(item) for item in pre_action_evidence.get("evidence_refs") or [] if str(item).strip()],
                evidence.id,
            }
        )
        pre_action_copy["evidence"] = pre_action_evidence
        signal_payload["pre_action_governance_check"] = pre_action_copy
        evidence.payload = {
            **dict(evidence.payload or {}),
            "pre_action_governance_check": pre_action_copy,
        }

    if event_type == "unknown_ai_detected":
        _project_unknown_browser_domain_hypothesis(
            db,
            tenant_id=tenant_id,
            domain=domain,
            evidence_node_id=evidence.id,
            observed_at=datetime.now(timezone.utc),
        )

    finding = None
    if event_type in {"unknown_ai_detected", "agent_runtime_discovered"}:
        signal.payload = {
            **signal_payload,
            "severity": "high",
            "source": "browser_extension",
            "evidence_node_ids": [evidence.id],
        }
        finding = generate_from_shadow_event(db, signal=signal)
    else:
        finding_event_type = event_type
        intent_decision_for_finding = intent_aware_decision if apply_intent_decision_overlay else None
        if intent_decision_for_finding and intent_aware_decision.get("decision") in {"block", "warn"}:
            if resolved_action_type in {"copy_output", "download_output", "export_output", "share_output", "paste_output_to_external_site"}:
                finding_event_type = "output_flagged"
            elif resolved_action_type in {"upload", "file_upload"}:
                finding_event_type = "file_upload_detected"
            else:
                finding_event_type = "prompt_blocked" if intent_aware_decision.get("decision") == "block" else "prompt_warned"
        finding = generate_from_browser_event(
            db,
            tenant_id=tenant_id,
            event_type=finding_event_type,
            domain=domain,
            ai_system_id=ai_system_id,
            user_id=event_user_id,
            policy_version_id=str(signal_payload["policy_version"]),
            platform_mode=str(signal_payload["platform_mode"]),
            action_taken=signal_payload["action_taken"],
            prompt_preview_redacted=signal_payload["prompt_preview_redacted"],
            input_signal_types=list(signal_payload["input_signal_types"] or []),
            file_meta=list(signal_payload["file_meta"] or []),
            evidence_node_id=evidence.id,
            intent_aware_decision=intent_decision_for_finding,
            source_surface=source_surface,
        )

    db.flush()
    runtime_event_id: str | None = None
    runtime_evidence_node_ids: list[str] = [evidence.id]
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_browser_signal

        with db.begin_nested():
            runtime_row = ingest_from_browser_signal(
                db,
                tenant_id=tenant_id,
                payload=signal_payload | {"event_type": event_type, "severity": severity},
                ai_system_id=ai_system_id,
                evidence_node_id=evidence.id,
                monitoring_signal_id=signal.id,
                trusted_pre_action_governance_check=(
                    dict(signal_payload.get("pre_action_governance_check") or {})
                    if isinstance(signal_payload.get("pre_action_governance_check"), dict)
                    else None
                ),
            )
        runtime_event_id = runtime_row.event_id if runtime_row is not None else None
        if runtime_row is not None and runtime_row.evidence_node_ids:
            runtime_evidence_node_ids = [str(node_id) for node_id in runtime_row.evidence_node_ids if str(node_id).strip()]
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="browser_extension_service",
            tenant_id=tenant_id,
            event_type=event_type,
            correlation_id=correlation_id,
            error_type=type(exc).__name__,
            error=str(exc),
            payload_keys=sorted(str(key) for key in signal_payload.keys())[:80],
        )
        error_logger.error(
            "runtime_intelligence_ingest_failed event_type=%s error_type=%s error=%s",
            event_type,
            type(exc).__name__,
            str(exc),
        )
    if finding is not None:
        enrich_pilot_finding_context(
            db,
            finding=finding,
            user_email=actor_user_email,
            browser_type=browser_type,
            application=application or None,
            decision=_decision_for_browser_event(event_type, signal_payload.get("action_taken")),
            policy_id=str(signal_payload.get("policy_version") or "").strip() or None,
            related_runtime_event_id=runtime_event_id,
            machine_id=machine_id,
        )
        evidence_payload = dict(evidence.payload or {}) if isinstance(evidence.payload, dict) else {}
        evidence_ai_action = dict(evidence_payload.get("ai_action") or {})
        if evidence_ai_action:
            evidence_ai_action["finding_id"] = finding.finding_id
            evidence_payload["ai_action"] = evidence_ai_action
            evidence.payload = evidence_payload
        if runtime_event_id:
            try:
                from app.db.models.runtime_intelligence import RuntimeEvent

                runtime_row = db.get(RuntimeEvent, runtime_event_id)
                if runtime_row is not None:
                    runtime_metadata = dict(runtime_row.metadata_json or {})
                    ai_action = dict(runtime_metadata.get("ai_action") or {})
                    ai_action["finding_id"] = finding.finding_id
                    runtime_metadata["ai_action"] = ai_action
                    runtime_metadata["finding_id"] = finding.finding_id
                    runtime_row.metadata_json = runtime_metadata
                    from app.services.runtime_intelligence.behavior_graph_service import build_behavior_graph_for_event

                    build_behavior_graph_for_event(
                        db,
                        event=runtime_row,
                        finding_ids=[finding.finding_id],
                    )
                    db.flush()
            except Exception:  # pragma: no cover - non-blocking trace enrichment
                pass

    if (
        governance_status.get("status") == "UNKNOWN"
        and (event_type in {"unknown_ai_detected", "agent_runtime_discovered"} or ai_system_id)
        and not _is_hawk_control_plane_browser_surface(domain, payload)
    ):
        generate_unregistered_ai_system_finding(
            db,
            tenant_id=tenant_id,
            source_surface="browser",
            ai_tool=domain,
            requested_ai_system_id=ai_system_id,
            policy_version_id=str(signal_payload["policy_version"]),
            evidence_node_ids=runtime_evidence_node_ids,
            related_control_ids=["CTRL-TENANT-ISO-001"],
            recommended_action=(
                "Unknown AI system detected from browser telemetry. Register in Trust Center before sanctioned usage."
            ),
        )

    auto_quarantine_result: dict[str, Any] | None = None
    if (
        settings.ai_iam_auto_quarantine_new_agents
        and event_type in {"unknown_ai_detected", "agent_runtime_discovered"}
        and agent_id
    ):
        auto_quarantine_result = auto_quarantine_agent_identity(
            db,
            tenant_id=tenant_id,
            discovered_agent_id=agent_id,
            source_surface="browser",
            reason_code="browser_discovery:new_agent_runtime",
            ai_system_id=ai_system_id,
            actor_user_id=actor_user_id,
            metadata={
                "agent_name": agent_name,
                "model_name": model_name,
                "runtime_provider": runtime_provider,
                "tools": detected_tools,
                "action_scope": detected_actions,
                "external_system_access": detected_privileges,
                "environment": agent_environment,
                "domain": domain,
                "url": payload.get("url"),
                "page_title": payload.get("page_title"),
                "event_type": event_type,
            },
            correlation_id=correlation_id,
        )

    try:
        record_activity_event(
            db,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            payload={
                "timestamp": timestamp,
                "event_type": event_type,
                "action_type": _activity_action_type_for_browser_event(event_type),
                "source_surface": "browser",
                "domain": domain,
                "url": payload.get("url"),
                "page_title": payload.get("page_title"),
                "ai_app": domain,
                "ai_model": model_name,
                "action_taken": signal_payload.get("action_taken") or event_type,
                "policy_triggered": ",".join(signal_payload.get("input_signal_types") or []),
                "severity": severity,
                "risk_score": SEVERITY_RISK_SCORE.get(severity, 0.5),
                "correlation_id": correlation_id,
                "runtime_event_id": runtime_event_id,
                "monitoring_signal_id": signal.id,
                "audit_log_id": audit.id,
                "evidence_node_id": evidence.id,
                "finding_id": finding.finding_id if finding else None,
                "prompt_raw": payload.get("raw_prompt") or payload.get("prompt_text"),
                "prompt_preview_redacted": payload.get("prompt_preview_redacted"),
                "prompt_storage_mode": payload.get("prompt_storage_mode"),
                "sensitivity_score": float(detection_result.get("confidence_score") or 0.0),
                "sensitive_detection": detection_result,
                "browser": signal_payload.get("browser"),
                "browser_profile": signal_payload.get("browser_profile"),
                "browser_version": payload.get("browser_version"),
                "extension_name": payload.get("extension_name"),
                "extension_version": signal_payload.get("extension_version"),
                "endpoint_id": payload.get("endpoint_id"),
                "os_type": payload.get("os_type"),
                "os_version": payload.get("os_version"),
                "device_type": payload.get("device_type"),
                "hostname": payload.get("hostname"),
                "ip_address": payload.get("ip_address"),
                "location": payload.get("location"),
                "metadata": {
                    "event_type": event_type,
                    "governance_state": governance_status.get("status"),
                    "governance_enforcement_mode": governance_status.get("enforcement_mode"),
                    "governance_recommendation": governance_recommendation,
                    "input_signal_types": list(signal_payload.get("input_signal_types") or []),
                    "agent_id": agent_id,
                    "agent_name": agent_name,
                    "runtime_provider": runtime_provider,
                    "model_name": model_name,
                    "agent_environment": agent_environment,
                    "detected_tools": detected_tools,
                    "detected_actions": detected_actions,
                    "detected_privileges": detected_privileges,
                    "automation_suspected": automation_suspected,
                    "automation_confidence": automation_confidence,
                    "suspected_tool": suspected_tool,
                    "automation_indicators": automation_indicators,
                    "meeting_surface": signal_payload.get("meeting_surface"),
                    "notetaker_provider": signal_payload.get("notetaker_provider"),
                    "notetaker_label": signal_payload.get("notetaker_label"),
                    "participant_visible": signal_payload.get("participant_visible"),
                    "meeting_signal_source": signal_payload.get("meeting_signal_source"),
                    "calendar_invitee_domain": signal_payload.get("calendar_invitee_domain"),
                    "oauth_app_id": signal_payload.get("oauth_app_id"),
                    "control_mode": signal_payload.get("control_mode"),
                    "auto_quarantine": {
                        "enabled": bool(settings.ai_iam_auto_quarantine_new_agents),
                        "created": bool((auto_quarantine_result or {}).get("created")),
                        "agent_id": str(getattr((auto_quarantine_result or {}).get("agent"), "id", "") or "") or None,
                        "reason": str((auto_quarantine_result or {}).get("reason") or "") or None,
                    },
                },
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking audit trail enrichment
        log_structured(
            "activity_audit_record_failed",
            module="browser_extension_service",
            tenant_id=tenant_id,
            event_type=event_type,
            correlation_id=correlation_id,
            error=str(exc),
        )

    return {
        "status": "ok",
        "monitoring_signal_id": signal.id,
        "audit_log_id": audit.id,
        "evidence_node_id": evidence.id,
        "finding_id": finding.finding_id if finding else None,
        "policy_version": signal_payload["policy_version"],
        "platform_mode": signal_payload["platform_mode"],
        "governance_recommendation": governance_recommendation,
        "runtime_event_id": runtime_event_id,
    }


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _extension_control_target(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "browser": str(payload.get("browser") or "chrome").strip().lower() or "chrome",
        "browser_profile": str(payload.get("browser_profile") or "default").strip() or "default",
        "extension_id": str(payload.get("extension_id") or "").strip(),
        "extension_name": str(payload.get("extension_name") or "").strip(),
        "endpoint_id": str(payload.get("endpoint_id") or "").strip(),
        "hostname": str(payload.get("hostname") or "").strip().lower(),
    }


def _authorization_matches_target(authorization: dict[str, Any], target: dict[str, str]) -> bool:
    for key in ("browser", "browser_profile", "extension_id", "endpoint_id", "hostname"):
        expected = str(authorization.get(key) or "").strip()
        actual = str(target.get(key) or "").strip()
        if expected and actual and expected.lower() != actual.lower():
            return False
        if expected and not actual:
            return False
    authorized_extension_name = str(authorization.get("extension_name") or "").strip()
    if authorized_extension_name and target.get("extension_name"):
        return authorized_extension_name.lower() == target["extension_name"].lower()
    return True


def create_extension_removal_authorization(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    action = str(payload.get("action") or "").strip().lower()
    if action not in EXTENSION_REMOVAL_ACTIONS:
        raise ValueError("action must be disable or remove")
    reason = str(payload.get("reason") or "").strip()
    if len(reason) < 8:
        raise ValueError("reason must describe the approved maintenance purpose")
    expires_minutes = int(payload.get("expires_minutes") or 30)
    if expires_minutes < 1 or expires_minutes > 1440:
        raise ValueError("expires_minutes must be between 1 and 1440")

    target = _extension_control_target(payload)
    if not target["extension_id"] and not target["extension_name"]:
        raise ValueError("extension_id or extension_name is required")

    now = _utc_now()
    expires_at = now + timedelta(minutes=expires_minutes)
    authorization_payload = {
        "authorization_type": "extension_disable_or_removal",
        "action": action,
        "reason": reason,
        "approved_by_user_id": actor_user_id,
        "approved_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "status": "active",
        **target,
        "browser_family": "chromium" if target["browser"] in {"chrome", "edge", "brave"} else target["browser"],
        "safari_control_note": (
            "Safari disable/removal prevention requires MDM/profile enforcement; "
            "this authorization preserves admin intent and audit."
        )
        if target["browser"] == "safari"
        else None,
    }
    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=None,
        signal_type=EXTENSION_REMOVAL_AUTH_SIGNAL_TYPE,
        severity="med",
        payload=authorization_payload,
    )
    db.add(signal)
    db.flush()

    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="extension.removal_authorization.create",
        resource_type="monitoring_signal",
        resource_id=signal.id,
        payload=authorization_payload,
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="extension_removal_authorization",
        signal_type="extension.admin.removal_authorization",
        label=f"Extension {action} authorization",
        payload={
            "authorization_id": signal.id,
            "audit_log_id": audit.id,
            **authorization_payload,
        },
        correlation_id=correlation_id,
    )
    return {
        "status": "active",
        "authorization_id": signal.id,
        "audit_log_id": audit.id,
        "evidence_node_id": evidence.id,
        "action": action,
        "expires_at": expires_at.isoformat(),
        "target": target,
    }


def _find_active_extension_removal_authorization(
    db: Session,
    *,
    tenant_id: str,
    target: dict[str, str],
    action: str,
    authorization_id: str | None,
) -> dict[str, Any] | None:
    rows = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type == EXTENSION_REMOVAL_AUTH_SIGNAL_TYPE,
        )
        .order_by(MonitoringSignal.created_at.desc())
        .limit(100)
    ).all()
    now = _utc_now()
    for row in rows:
        authorization = dict(row.payload or {})
        if authorization_id and row.id != authorization_id:
            continue
        if str(authorization.get("status") or "") != "active":
            continue
        if str(authorization.get("action") or "").strip().lower() not in {action, "remove"}:
            continue
        expires_at = _parse_datetime(authorization.get("expires_at"))
        if expires_at is None or expires_at < now:
            continue
        if not _authorization_matches_target(authorization, target):
            continue
        return {
            "authorization_id": row.id,
            "action": authorization.get("action"),
            "approved_by_user_id": authorization.get("approved_by_user_id"),
            "approved_at": authorization.get("approved_at"),
            "expires_at": authorization.get("expires_at"),
            "reason": authorization.get("reason"),
        }
    return None


def _extension_removal_control_context(
    db: Session,
    *,
    tenant_id: str,
    payload: dict[str, Any],
    status_value: str,
) -> dict[str, Any] | None:
    trigger = str(payload.get("status_trigger") or "").strip().lower()
    if status_value not in EXTENSION_REMOVAL_STATUS_VALUES and trigger not in EXTENSION_REMOVAL_TRIGGER_VALUES:
        return None
    action = "remove" if status_value in {"removed", "uninstalled", "missing"} or "remov" in trigger or "uninstall" in trigger else "disable"
    target = _extension_control_target(payload)
    authorization_id = str(payload.get("removal_authorization_id") or payload.get("disable_authorization_id") or "").strip() or None
    authorization = _find_active_extension_removal_authorization(
        db,
        tenant_id=tenant_id,
        target=target,
        action=action,
        authorization_id=authorization_id,
    )
    if authorization:
        return {
            "classification": "admin_authorized_disable_or_removal",
            "action": action,
            "target": target,
            "authorization": authorization,
            "control_state": "planned_maintenance",
        }
    return {
        "classification": "unauthorized_disable_or_removal",
        "action": action,
        "target": target,
        "authorization": None,
        "control_state": "tamper_suspected",
    }


def process_extension_status_report(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    extension_version = str(payload.get("extension_version") or "").strip()
    if not extension_version:
        raise ValueError("extension_version is required")

    policy_sync = build_extension_policy_sync(db, tenant_id=tenant_id)
    healthy = bool(payload.get("healthy"))
    status_value = str(payload.get("status") or ("ok" if healthy else "degraded")).strip().lower()
    browser = str(payload.get("browser") or "chrome").strip().lower() or "chrome"
    browser_profile = str(payload.get("browser_profile") or "default").strip() or "default"
    active_domain = normalize_domain(payload.get("active_domain") or _domain_from_url(payload.get("active_url")))
    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    extension_removal_control = _extension_removal_control_context(
        db,
        tenant_id=tenant_id,
        payload=payload,
        status_value=status_value,
    )
    removal_classification = (
        str(extension_removal_control.get("classification") or "")
        if isinstance(extension_removal_control, dict)
        else ""
    )
    if removal_classification == "unauthorized_disable_or_removal":
        severity = "critical"
    elif removal_classification == "admin_authorized_disable_or_removal":
        severity = "med"
    else:
        severity = "low" if healthy else "high"
    actor_user_email = _resolve_actor_user_email(db, actor_user_id)

    signal_payload = {
        "event_type": "extension_health_status",
        "status": status_value,
        "healthy": healthy,
        "status_trigger": str(payload.get("status_trigger") or "periodic"),
        "last_sync_at": payload.get("last_sync_at"),
        "telemetry_queue_depth": int(payload.get("telemetry_queue_depth") or 0),
        "last_error": payload.get("last_error"),
        "policy_version": str(payload.get("policy_version") or policy_sync.policy_version),
        "platform_mode": str(payload.get("platform_mode") or policy_sync.platform_mode),
        "browser": browser,
        "browser_profile": browser_profile,
        "browser_version": payload.get("browser_version"),
        "extension_id": payload.get("extension_id"),
        "extension_name": payload.get("extension_name"),
        "extension_version": extension_version,
        "api_base_url": payload.get("api_base_url") or payload.get("backend_url") or payload.get("backendUrl"),
        "backendUrl": payload.get("backendUrl") or payload.get("backend_url") or payload.get("api_base_url"),
        "tenant_id": payload.get("tenant_id") or tenant_id,
        "tenantId": payload.get("tenantId") or payload.get("tenant_id") or tenant_id,
        "user_id": actor_user_id,
        "endpoint_id": payload.get("endpoint_id"),
        "session_id": payload.get("session_id"),
        "hostname": payload.get("hostname"),
        "device_type": payload.get("device_type"),
        "os_type": payload.get("os_type"),
        "os_version": payload.get("os_version"),
        "ip_address": payload.get("ip_address"),
        "location": payload.get("location"),
        "domain": active_domain or None,
        "url": payload.get("active_url"),
        "ai_tool": "browser_extension",
        "tool_name": "browser_extension",
        "application": "browser_extension",
        "operation": "extension_health_status",
        "action_type": "extension_health_status",
        "action_taken": status_value,
        "input_signal_types": ["extension_health"],
        "correlation_id": correlation_id,
        "source_surface": "browser_extension",
        "operational_telemetry": True,
        "extension_removal_control": extension_removal_control,
        "suppress_shadow_ai": True,
        "suppress_ai_discovery": True,
        "suppress_anomaly_detection": True,
        "suppress_live_activity": healthy,
        "suppress_ai_action": True,
    }
    if not healthy:
        if removal_classification == "unauthorized_disable_or_removal":
            signal_payload["governance_recommendation"] = "investigate_extension_tamper_or_unapproved_disablement"
            signal_payload["input_signal_types"] = [
                "extension_health",
                "extension_tamper",
                "runtime_surface_degraded",
            ]
            signal_payload["risk_category"] = "extension_tamper"
        elif removal_classification == "admin_authorized_disable_or_removal":
            signal_payload["governance_recommendation"] = "extension_disable_or_removal_authorized"
            signal_payload["input_signal_types"] = [
                "extension_health",
                "extension_admin_authorization",
                "runtime_surface_degraded",
            ]
            signal_payload["risk_category"] = "extension_authorized_maintenance"
        else:
            signal_payload["governance_recommendation"] = "investigate_extension_runtime_surface"
            signal_payload["input_signal_types"] = ["extension_health", "runtime_surface_degraded"]
            signal_payload["risk_category"] = "extension_health"

    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=None,
        signal_type="browser.extension_health_status",
        severity=severity,
        payload=signal_payload,
    )
    db.add(signal)
    db.flush()

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="extension.status.report",
        resource_type="monitoring_signal",
        resource_id=signal.id,
        payload={
            "healthy": healthy,
            "status": status_value,
            "browser": browser,
            "browser_profile": browser_profile,
            "extension_id": payload.get("extension_id"),
            "extension_removal_control": extension_removal_control,
            "policy_version": signal_payload["policy_version"],
            "platform_mode": signal_payload["platform_mode"],
            "telemetry_queue_depth": signal_payload["telemetry_queue_depth"],
        },
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="extension_health_status",
        signal_type="extension.status.report",
        label=f"Extension status report {status_value}",
        payload={
            "monitoring_signal_id": signal.id,
            "status": status_value,
            "healthy": healthy,
            "browser": browser,
            "browser_profile": browser_profile,
            "extension_name": payload.get("extension_name"),
            "extension_id": payload.get("extension_id"),
            "extension_version": extension_version,
            "policy_version": signal_payload["policy_version"],
            "platform_mode": signal_payload["platform_mode"],
            "active_domain": active_domain or None,
            "governance_recommendation": signal_payload.get("governance_recommendation"),
            "extension_removal_control": extension_removal_control,
        },
        correlation_id=correlation_id,
    )

    finding = None
    if not healthy and removal_classification != "admin_authorized_disable_or_removal":
        finding = generate_from_browser_event(
            db,
            tenant_id=tenant_id,
            event_type="extension_health_status",
            domain=active_domain or "browser_extension",
            ai_system_id=None,
            user_id=actor_user_id,
            policy_version_id=str(signal_payload["policy_version"]),
            platform_mode=str(signal_payload["platform_mode"]),
            action_taken=status_value,
            prompt_preview_redacted=str(payload.get("last_error") or "")[:400],
            input_signal_types=list(signal_payload.get("input_signal_types") or []),
            file_meta=[],
            evidence_node_id=evidence.id,
        )

    runtime_event_id: str | None = None
    if not healthy:
        try:
            from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_browser_signal

            runtime_row = ingest_from_browser_signal(
                db,
                tenant_id=tenant_id,
                payload=signal_payload
                | {
                    "event_type": "extension_health_status",
                    "severity": severity,
                    "domain": "browser_extension",
                },
                ai_system_id=None,
                evidence_node_id=evidence.id,
                monitoring_signal_id=signal.id,
            )
            runtime_event_id = runtime_row.event_id if runtime_row is not None else None
        except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
            if isinstance(exc, CanonicalProjectionError):
                raise
            log_structured(
                "runtime_intelligence_ingest_failed",
                module="browser_extension_service",
                tenant_id=tenant_id,
                event_type="extension_health_status",
                correlation_id=correlation_id,
                error=str(exc),
            )
    if finding is not None:
        enrich_pilot_finding_context(
            db,
            finding=finding,
            user_email=actor_user_email,
            browser_type=browser,
            application=active_domain or "browser_extension",
            decision="warn",
            policy_id=str(signal_payload.get("policy_version") or "").strip() or None,
            related_runtime_event_id=runtime_event_id,
            machine_id=str(payload.get("endpoint_id") or "").strip() or None,
        )

    try:
        record_activity_event(
            db,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            payload={
                "timestamp": payload.get("timestamp") or _now_iso(),
                "event_type": "extension_health_status",
                "action_type": "response",
                "source_surface": "browser",
                "domain": active_domain or "browser_extension",
                "ai_app": active_domain or "browser_extension",
                "action_taken": "allowed" if healthy else "warned",
                "policy_triggered": str(payload.get("status_trigger") or "periodic"),
                "severity": severity,
                "risk_score": SEVERITY_RISK_SCORE.get(severity, 0.5),
                "correlation_id": correlation_id,
                "runtime_event_id": runtime_event_id,
                "monitoring_signal_id": signal.id,
                "audit_log_id": audit.id,
                "evidence_node_id": evidence.id,
                "finding_id": finding.finding_id if finding else None,
                "suppress_ai_action": healthy,
                "browser": browser,
                "browser_profile": browser_profile,
                "browser_version": payload.get("browser_version"),
                "extension_name": payload.get("extension_name"),
                "extension_id": payload.get("extension_id"),
                "extension_version": extension_version,
                "endpoint_id": payload.get("endpoint_id"),
                "os_type": payload.get("os_type"),
                "os_version": payload.get("os_version"),
                "device_type": payload.get("device_type"),
                "hostname": payload.get("hostname"),
                "ip_address": payload.get("ip_address"),
                "location": payload.get("location"),
                "metadata": {
                    "healthy": healthy,
                    "status": status_value,
                    "status_trigger": str(payload.get("status_trigger") or "periodic"),
                    "telemetry_queue_depth": int(payload.get("telemetry_queue_depth") or 0),
                    "extension_removal_control": extension_removal_control,
                    "suppress_ai_action": healthy,
                },
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking audit trail enrichment
        log_structured(
            "activity_audit_record_failed",
            module="browser_extension_service",
            tenant_id=tenant_id,
            event_type="extension_health_status",
            correlation_id=correlation_id,
            error=str(exc),
        )

    return {
        "status": "ok",
        "monitoring_signal_id": signal.id,
        "audit_log_id": audit.id,
        "evidence_node_id": evidence.id,
        "policy_version": str(signal_payload["policy_version"]),
        "platform_mode": str(signal_payload["platform_mode"]),
        "runtime_event_id": runtime_event_id,
        "finding_id": finding.finding_id if finding else None,
    }


def _evaluate_interaction(
    *,
    prompt_preview_redacted: str,
    raw_prompt: str,
    domain: str,
    policy_sync: PolicySyncPayload,
) -> tuple[str, str, list[str], list[str]]:
    evaluation_text = str(raw_prompt or "").strip() or str(prompt_preview_redacted or "")
    tier, decision, input_signal_types = evaluate_browser_interaction_policy(
        prompt_preview_redacted=evaluation_text,
        domain=normalize_domain(domain),
        policy_sync=policy_sync,
        known_ai_domains=KNOWN_AI_DOMAINS,
    )
    reason_codes: list[str] = []
    if not (decision.decision == "allow" and decision.reason_code == "policy_allow"):
        reason_codes = [decision.reason_code]
    final_decision = decision.decision
    # The layered injection engine (normalisation, rules, classifier) with the tenant's thresholds: it can only
    # raise the decision, never lower what the guardian policy above decided.
    try:
        verdict = assess_prompt_injection(evaluation_text, scope="direct")
    except Exception:  # noqa: BLE001 - the guardian policy above still applies
        verdict = None
    if verdict is not None and verdict.detected:
        engine_decision = _BROWSER_DECISION_FOR_INJECTION_ACTION.get(verdict.action, "allow")
        if engine_decision in {"block", "require_approval"}:
            input_signal_types = [*input_signal_types, "prompt_injection", "prompt_injection_engine", *verdict.threat_types]
        else:
            # A suspicion only: the confirmed-attack signals would make the browser policy block it.
            input_signal_types = [*input_signal_types, "prompt_injection_suspected", "prompt_injection_engine"]
        if _decision_rank(engine_decision) > _decision_rank(final_decision):
            final_decision = engine_decision
            reason_codes = [*reason_codes, "prompt_injection_engine"]
            tier = "clear_positive" if engine_decision == "block" else ("ambiguous" if tier == "clear_negative" else tier)
    return tier, final_decision, reason_codes, sorted(set(input_signal_types))


# Browser and desktop decisions for the injection engine's actions (hold asks for approval; redact and log warn,
# as a prompt in the user's own browser cannot be rewritten server-side).
_BROWSER_DECISION_FOR_INJECTION_ACTION = {"block": "block", "hold": "require_approval", "redact": "warn", "log": "warn"}


def _decision_rank(decision: str) -> int:
    normalized = str(decision or "").strip().lower()
    if normalized == "block":
        return 3
    if normalized in {"require_approval", "require_justification"}:
        return 2
    if normalized == "warn":
        return 1
    return 0


def _map_control_engine_browser_decision(decision: str, *, fallback: str = "allow") -> str:
    return map_generic_decision(
        decision,
        mapping={
            "allow": "allow",
            "alert": "warn",
            "modify": "warn",
            "step_up": "warn",
            "block": "block",
        },
        default=fallback,
    )


def _map_scoped_browser_decision(decision: str | None, *, fallback: str = "allow") -> str:
    return map_generic_decision(
        decision or "",
        mapping={
            "allow": "allow",
            "warn": "warn",
            "alert": "warn",
            "redact": "warn",
            "require_justification": "block",
            "require_approval": "block",
            "hold_for_approval": "block",
            "step_up": "block",
            "step-up": "block",
            "block": "block",
            "deny": "block",
        },
        default=fallback,
    )


def _contains_uae_sensitive_identifier(prompt_text: str) -> bool:
    text = str(prompt_text or "")
    if not text:
        return False
    if UAE_EMIRATES_ID_STRICT_PATTERN.search(text):
        return True
    if UAE_EMIRATES_ID_CONTEXT_PATTERN.search(text):
        return True
    if UAE_IDENTIFIER_CONTEXT_PATTERN.search(text) and LONG_IDENTIFIER_PATTERN.search(text):
        return True
    return False


def _contains_uae_bank_signal(prompt_text: str) -> bool:
    text = str(prompt_text or "")
    if not text:
        return False
    if UAE_IBAN_STRICT_PATTERN.search(text):
        return True
    if UAE_BANK_CONTEXT_PATTERN.search(text):
        return True
    return False


def _evaluate_sensitive_interaction_policy(
    *,
    domain: str,
    policy_sync: PolicySyncPayload,
    contains_sensitive: bool,
    platform_mode: str,
    prompt_text: str,
    detected_entity_types: set[str] | None = None,
) -> tuple[str, str]:
    if not contains_sensitive:
        return "allow", "policy_allow"

    entity_types = {str(item).strip().lower() for item in (detected_entity_types or set()) if str(item).strip()}
    if platform_mode != PLATFORM_MODE_DISCOVERY:
        if "emirates_id" in entity_types or _contains_uae_sensitive_identifier(prompt_text):
            return "block", "uae_sensitive_identifier"
        if "bank_account" in entity_types and _contains_uae_bank_signal(prompt_text):
            return "block", "uae_sensitive_bank_account"

    destination_trust = "trusted" if any(_domain_matches(domain, item) for item in (policy_sync.approved_domains or [])) else "untrusted"
    policy = canonical_guardian_policy(
        policy_id="guardian.browser.sensitive_prompt",
        policy_name="Sensitive Browser Prompt Control",
        policy_version="1.0.0",
        tenant_id="*",
        conditions={
            "source": {"type": "browser", "classification": "sensitive"},
            "destination": {"type": "ai_tool", "trust_level": destination_trust},
            "action": {"type": "prompt"},
            "data": {"contains_sensitive": True},
        },
        decision={
            "mode": ("warn" if destination_trust == "trusted" else "block"),
            "confidence_threshold": 0.75,
            "strictness": "high",
        },
        framework_mapping={
            "nist_ai_rmf": ["GV.RM", "MP.AI"],
            "iso_42001": ["A.5", "A.8"],
            "eu_ai_act": ["risk_management", "data_governance"],
            "owasp_genai": ["LLM01", "LLM06"],
            "mitre_atlas": ["AML.TA0001"],
            "control_ids": ["CTRL-DLP-001", "CTRL-INPUT-001"],
        },
        metadata={"active": True},
    )
    decision = evaluate_guardian_policies(
        policies=[policy],
        context={
            "source_type": "browser",
            "source_classification": "sensitive",
            "destination_type": "ai_tool",
            "destination_trust_level": destination_trust,
            "action_type": "prompt",
            "contains_sensitive": True,
            "text": domain,
            "environment": "prod",
        },
        default_decision="allow",
    )
    outcome = str(decision.decision or "allow").strip().lower()
    if platform_mode == PLATFORM_MODE_DISCOVERY and outcome == "block":
        outcome = "warn"
    if outcome == "require_justification":
        outcome = "block" if platform_mode != PLATFORM_MODE_DISCOVERY else "warn"
    if outcome == "require_approval":
        outcome = "block"
    return outcome, str(decision.reason_code or "sensitive_data_detected")


#: What a desktop guard may say it redacted before sending its preview (apps/desktop-guard redaction.py).
ENDPOINT_REDACTED_ENTITY_TYPES = frozenset({"email", "phone", "credit_card", "api_key", "emirates_id", "bank_account"})


def _with_endpoint_redacted_entities(detection_result: dict[str, Any], reported: Any) -> dict[str, Any]:
    """Count what the endpoint redacted before sending (it keeps the values) as detected here, so the sensitive-data
    policy applies as if the API had seen them. It can only add findings, never remove one."""

    if not isinstance(reported, (list, tuple)):
        return detection_result
    types = sorted({str(item).strip().lower() for item in reported if str(item).strip().lower() in ENDPOINT_REDACTED_ENTITY_TYPES})
    if not types:
        return detection_result
    present = {str((row or {}).get("entity_type") or "").strip().lower() for row in detection_result.get("entities") or []}
    added = [
        {"entity_type": entity_type, "value_preview": "[redacted]", "confidence": 0.9, "source": "endpoint_redaction", "context": {}}
        for entity_type in types
        if entity_type not in present
    ]
    return {**detection_result, "entities": [*(detection_result.get("entities") or []), *added], "contains_sensitive": True}


@with_tenant_profile
def evaluate_browser_interaction_and_record(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    payload: dict[str, Any],
    persist_artifacts: bool = True,
    persist_allow_decisions: bool = True,
    degradation_reason: str | None = None,
) -> dict[str, Any]:
    domain = normalize_domain(payload.get("domain") or _domain_from_url(payload.get("url")))
    if not domain:
        raise ValueError("domain or url is required")

    prompt_preview_redacted = str(payload.get("prompt_preview_redacted") or "")
    raw_prompt = str(payload.get("raw_prompt") or payload.get("prompt_text") or "")
    file_meta = [item for item in (payload.get("file_meta") or []) if isinstance(item, dict)]
    policy_sync = build_extension_policy_sync(db, tenant_id=tenant_id)
    actor_user_email = _payload_text(payload, "user_email", "email") or _resolve_actor_user_email(db, actor_user_id)
    event_user_id = _payload_text(payload, "user_id") or actor_user_id
    machine_id = _payload_text(payload, "machine_id", "endpoint_id", "device_id")
    endpoint_id = _payload_text(payload, "endpoint_id", "device_id")
    browser_type = _payload_text(payload, "browser_type", "browser") or "chrome"
    application = _payload_text(payload, "application", "ai_app", "app") or domain
    source_surface = str(payload.get("source_surface") or "browser").strip().lower() or "browser"
    if source_surface not in {"browser", "desktop_app"}:
        source_surface = "browser"
    is_desktop_surface = source_surface == "desktop_app"
    control_mode = "desktop_guard" if is_desktop_surface else "browser_extension"
    route_name = "/telemetry/desktop/interaction-eval" if is_desktop_surface else "/telemetry/browser/interaction-eval"
    policy_version = str(payload.get("policy_version") or policy_sync.policy_version)
    platform_mode = str(payload.get("platform_mode") or policy_sync.platform_mode)
    detection_text_inputs = [text for text in [raw_prompt, prompt_preview_redacted] if str(text).strip()]
    detection_result = detect_sensitive_data(
        text_inputs=detection_text_inputs or [prompt_preview_redacted],
        file_meta=file_meta,
        source="browser",
        destination=domain,
        ai_system_id=str(payload.get("ai_system_id") or "").strip() or None,
        user_id=actor_user_id,
        correlation_id=str(payload.get("correlation_id") or "").strip() or None,
    )
    detection_result = _with_endpoint_redacted_entities(detection_result, payload.get("redacted_entity_types"))
    source_classification = classify_data(
        detection_result=detection_result,
        classification_hint=str(payload.get("source_classification_hint") or ""),
        allow_unknown=True,
    )
    detected_entity_types = {
        str((entity or {}).get("entity_type") or "").strip().lower()
        for entity in (detection_result.get("entities") or [])
        if str((entity or {}).get("entity_type") or "").strip()
    }
    prompt_text_for_policy = "\n".join(
        text for text in [raw_prompt, prompt_preview_redacted] if str(text).strip()
    )
    routing = route_enforcement(
        {
            "policy_id": "browser_interaction_control",
            "policy_version": policy_version or "none",
        },
        {
            "event_id": str(payload.get("event_id") or ""),
            "tenant_id": tenant_id,
            "source_surface": source_surface,
            "action_type": "prompt",
            "ai_system_id": payload.get("ai_system_id"),
            "agent_id": None,
            "data_classification": source_classification,
            "correlation_id": payload.get("correlation_id"),
        },
    )
    fallback_audit_id: str | None = None
    fallback_evidence_id: str | None = None
    try:
        tier, decision, reason_codes, derived_signal_types = _evaluate_interaction(
            prompt_preview_redacted=prompt_preview_redacted,
            raw_prompt=raw_prompt,
            domain=domain,
            policy_sync=policy_sync,
        )
    except Exception as exc:
        fallback = fallback_decision_for_gateway_failure(
            platform_mode=platform_mode,
            normalized_event=dict(routing.get("normalized_event") or {}),
        )
        fallback_audit_id, fallback_evidence_id = record_routing_failure(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            routing=routing,
            stage="browser_interaction_eval",
            error=str(exc),
            fallback_applied="gateway",
        )
        tier = "clear_positive"
        decision = str(fallback["decision"]).strip().lower()
        reason_codes = ["browser_enforcement_failed", str(fallback["reason_code"])]
        derived_signal_types = ["browser_enforcement_failure", "gateway_fallback_enforced"]
    sensitive_policy_decision, sensitive_policy_reason = _evaluate_sensitive_interaction_policy(
        domain=domain,
        policy_sync=policy_sync,
        contains_sensitive=bool(detection_result.get("contains_sensitive")),
        platform_mode=platform_mode,
        prompt_text=prompt_text_for_policy,
        detected_entity_types=detected_entity_types,
    )
    if _decision_rank(sensitive_policy_decision) > _decision_rank(decision):
        decision = sensitive_policy_decision
        if decision == "block":
            tier = "clear_positive"
        elif tier == "clear_negative":
            tier = "ambiguous"
        reason_codes = [*reason_codes, sensitive_policy_reason]
        derived_signal_types = [*derived_signal_types, "guardian_policy_sensitive_data"]
    explicit_signal_types = sorted(
        {
            *[str(item) for item in (payload.get("input_signal_types") or []) if str(item).strip()],
            *detection_signal_types(detection_result),
        }
    )
    input_signal_types = sorted(
        {
            *explicit_signal_types,
            *derived_signal_types,
        }
    )
    intent_context = classify_intent_context(
        declared_intent=_payload_text(payload, "declared_intent", "intent"),
        text=(raw_prompt or prompt_preview_redacted),
        action_type="prompt_submit" if not file_meta else "upload",
        business_context=_payload_text(payload, "business_context"),
    )
    input_content_context = classify_input_content_context(
        raw_prompt or prompt_preview_redacted,
        file_meta=file_meta,
    )
    output_context: dict[str, Any] = {}
    action_alignment_result = evaluate_action_alignment(
        intent_context=intent_context,
        action_type="upload" if file_meta else "prompt_submit",
        input_content_context=input_content_context,
        output_context=output_context,
    )
    intent_policy = dict(payload.get("intent_policy") or {}) if isinstance(payload.get("intent_policy"), dict) else {}
    if not intent_policy:
        intent_policy = dict(policy_sync.intent_aware_action_control or {})
        if platform_mode == PLATFORM_MODE_DISCOVERY and str(intent_policy.get("mode") or "").strip().lower() == "block":
            intent_policy["mode"] = "warn"
    if not intent_policy:
        intent_policy = {
            "policy_id": "INTENT_AWARE_AI_ACTION_CONTROL",
            "mode": "warn" if platform_mode == PLATFORM_MODE_DISCOVERY else "block",
        }
    intent_aware_decision = evaluate_intent_aware_action_control(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        action_type="upload" if file_meta else "prompt_submit",
        policy=intent_policy,
    )
    if intent_aware_decision.get("decision") in {"block", "warn"}:
        intent_decision = str(intent_aware_decision.get("decision") or "").strip().lower()
        if _decision_rank(intent_decision) > _decision_rank(decision):
            decision = intent_decision
            tier = "clear_positive" if decision == "block" else ("ambiguous" if tier == "clear_negative" else tier)
        reason_codes = [*reason_codes, str(intent_aware_decision.get("decision_reason") or "intent_aware_policy")]
        input_signal_types = sorted(
            {
                *input_signal_types,
                "intent_aware_ai_action_control",
                f"intent_category:{intent_context.get('intent_category')}",
                f"input_sensitivity:{input_content_context.get('sensitivity_level')}",
                f"action_alignment:{action_alignment_result.get('alignment')}",
                f"finding_type:{intent_aware_decision.get('finding_type')}",
            }
        )
    ai_system_id = payload.get("ai_system_id") or _resolve_ai_system_for_domain(db, tenant_id=tenant_id, domain=domain)
    business_file_text_parts: list[str] = []
    for item in file_meta:
        for key in ("text_preview", "content_preview", "extracted_text", "ocr_text", "preview", "name", "filename"):
            value = str(item.get(key) or "").strip()
            if value:
                business_file_text_parts.append(value)
    business_prompt_text = "\n".join(
        text
        for text in [
            raw_prompt,
            prompt_preview_redacted,
            *business_file_text_parts,
        ]
        if str(text).strip()
    )
    business_purpose_decision = evaluate_business_purpose_boundary(
        db,
        tenant_id=tenant_id,
        user_id=event_user_id,
        email=actor_user_email,
        prompt_text=business_prompt_text,
        action_type="file_upload" if file_meta else "prompt_submit",
        destination_domain=domain,
        destination_trust_level=_browser_destination_trust_level(
            domain=domain,
            policy_sync=policy_sync,
            ai_system_id=ai_system_id,
        ),
        source_surface=source_surface,
        claims=payload.get("claims") if isinstance(payload.get("claims"), dict) else None,
        extension_role_hint=_payload_text(payload, "actor_role", "role", "business_function", "department"),
    )
    boundary_decision = str(business_purpose_decision.get("decision") or "").strip().lower()
    boundary_browser_decision = "warn" if boundary_decision == "review" else boundary_decision
    if platform_mode == PLATFORM_MODE_DISCOVERY and boundary_browser_decision == "block":
        boundary_browser_decision = "warn"
    if boundary_browser_decision in {"block", "warn"}:
        if _decision_rank(boundary_browser_decision) > _decision_rank(decision):
            decision = boundary_browser_decision
            tier = "clear_positive" if decision == "block" else ("ambiguous" if tier == "clear_negative" else tier)
        reason_codes = [
            *reason_codes,
            str(business_purpose_decision.get("reason") or "business_purpose_boundary"),
        ]
        business_purpose = dict(business_purpose_decision.get("business_purpose") or {})
        code_context = dict(business_purpose_decision.get("code_context") or {})
        role_resolution = dict(business_purpose_decision.get("role_resolution") or {})
        input_signal_types = sorted(
            {
                *input_signal_types,
                "business_purpose_boundary",
                f"business_purpose:{business_purpose.get('purpose_category')}",
                f"tenant_sector:{business_purpose.get('tenant_sector')}",
                f"business_function:{business_purpose.get('business_function')}",
                f"role_resolution:{role_resolution.get('source')}",
                f"code_sql:{code_context.get('sql_type')}",
                f"finding_type:{business_purpose_decision.get('finding_type')}",
            }
        )
    elif boundary_decision in {"shadow", "shadow_would_block"}:
        input_signal_types = sorted(
            {
                *input_signal_types,
                "business_purpose_boundary",
                "business_purpose_shadow_would_block",
            }
        )
    if platform_mode != PLATFORM_MODE_DISCOVERY and decision != "block":
        high_risk_signals = {
            "prompt_injection",
            "prompt_decomposition",
            "jailbreak",
            "tool_output_injection",
            "high_risk_term",
            "sensitive_data_pattern",
            "sensitive_entity:emirates_id",
            "sensitive_entity:bank_account",
            "uae_sensitive_identifier",
            "uae_sensitive_bank_account",
        }
        explicit_signal_set = {str(item).strip().lower() for item in explicit_signal_types if str(item).strip()}
        if explicit_signal_set.intersection(high_risk_signals):
            decision = "block"
            tier = "clear_positive"
            reason_codes = [*reason_codes, "prompt_risk_forced_block"]
            input_signal_types = sorted({*input_signal_types, "prompt_risk_forced_block"})

    # Parity with the LLM gateway (gateway_service._apply_threat_detectors): the same high-precision detector library
    # runs on the prompt typed in the browser. Before, a jailbreak persona, a system-prompt extraction or a spoofed
    # system/role delimiter that the gateway blocks was only warned about here (found by the attack-simulation
    # catalogue, SIM-PROMPT browser scenarios). A blocking finding blocks in enforce mode and warns in discovery mode.
    browser_threats = evaluate_threat_detectors(prompt=prompt_text_for_policy, surface="browser")
    if browser_threats:
        threat_reason_codes = [
            str((row.get("actions_taken") or {}).get("reason_code") or "").strip()
            for row in browser_threats
            if str((row.get("actions_taken") or {}).get("reason_code") or "").strip()
        ]
        reason_codes = [*reason_codes, *[code for code in threat_reason_codes if code not in reason_codes]]
        input_signal_types = sorted(
            {
                *input_signal_types,
                *[str(threat) for row in browser_threats for threat in (row.get("threat_types") or []) if str(threat).strip()],
            }
        )
        threat_blocks = any(str(row.get("decision") or "").strip().lower() == "block" for row in browser_threats)
        if threat_blocks and decision != "block":
            if platform_mode != PLATFORM_MODE_DISCOVERY:
                decision = "block"
                tier = "clear_positive"
                reason_codes = [*reason_codes, "prompt_risk_forced_block"]
                input_signal_types = sorted({*input_signal_types, "prompt_risk_forced_block"})
            elif _decision_rank("warn") > _decision_rank(decision):
                decision = "warn"
                tier = "ambiguous" if tier == "clear_negative" else tier
        elif not threat_blocks and _decision_rank("warn") > _decision_rank(decision):
            decision = "warn"
            tier = "ambiguous" if tier == "clear_negative" else tier

    scoped_policy = resolve_scoped_policy_decision(
        db,
        tenant_id=tenant_id,
        policy_version_id=policy_version,
        context={
            "actor_type": str(payload.get("actor_type") or "human"),
            "actor_user_id": actor_user_id,
            "actor_role": payload.get("actor_role"),
            "actor_department": payload.get("actor_department") or payload.get("department"),
            "endpoint_id": payload.get("endpoint_id"),
            "source_surface": "browser",
            "action_type": ("file_upload" if file_meta else "prompt_input"),
            "operation": ("upload" if file_meta else "prompt_submission"),
            "domain": domain,
            "tool_name": domain,
            "provider": payload.get("provider"),
            "model": payload.get("model_name"),
            "ai_system_id": payload.get("ai_system_id"),
            "data_classification": source_classification,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "risk_tier": payload.get("risk_tier"),
        },
    )
    hard_block_reasons = {
        "uae_sensitive_identifier",
        "uae_sensitive_bank_account",
        "prompt_risk_forced_block",
        "prompt_decomposition_pattern",
    }
    hard_block_active = decision == "block" and any(code in hard_block_reasons for code in reason_codes)
    if scoped_policy.matched:
        scoped_decision = _map_scoped_browser_decision(scoped_policy.decision, fallback=decision)
        if platform_mode == PLATFORM_MODE_DISCOVERY and scoped_decision == "block":
            scoped_decision = "warn"
        if (
            _decision_rank(scoped_decision) > _decision_rank(decision)
            or (_decision_rank(scoped_decision) < _decision_rank(decision) and not hard_block_active)
        ):
            decision = scoped_decision
            if decision == "block":
                tier = "clear_positive"
            elif decision == "warn" and tier == "clear_negative":
                tier = "ambiguous"
            reason_codes = [*reason_codes, str(scoped_policy.reason_code or "scoped_policy_matched")]
            input_signal_types = sorted(
                {
                    *input_signal_types,
                    "scoped_policy_matched",
                    f"scoped_policy_rule:{str(scoped_policy.rule_id or 'default').lower()}",
                    f"scoped_policy_decision:{decision}",
                }
            )
    governance_status = resolve_ai_system_status(
        ai_system_id,
        {
            "db": db,
            "tenant_id": tenant_id,
            "source_hint": "trust_center",
            "route": route_name,
            "module": "desktop_guard" if is_desktop_surface else "browser_extension",
        },
    )
    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    hinted_controls: list[str] = []
    if tier == "clear_positive" and any(
        "prompt_injection" in str(item).lower()
        or "jailbreak" in str(item).lower()
        or "prompt_decomposition" in str(item).lower()
        for item in input_signal_types
    ):
        hinted_controls.append("PROMPT_INJECTION_DETECTION")
    if any("prompt_decomposition" in str(item).lower() for item in input_signal_types):
        hinted_controls.append("CHAIN_OF_ACTION_VALIDATION")
    if bool(detection_result.get("contains_sensitive")):
        hinted_controls.extend(["SENSITIVE_DATA_DETECTION", "PII_EXFILTRATION_PREVENTION"])
    if file_meta:
        hinted_controls.extend(["FILE_UPLOAD_INSPECTION", "OCR_DATA_EXTRACTION_CONTROL"])
    control_input_signal_types = list(input_signal_types)
    if tier == "ambiguous":
        control_input_signal_types = [
            item
            for item in control_input_signal_types
            if (
                "prompt_injection" not in str(item).lower()
                and "jailbreak" not in str(item).lower()
                and "prompt_decomposition" not in str(item).lower()
            )
        ]

    control_decision = evaluate_control_engine(
        AIAction(
            action_id=str(correlation_id or payload.get("event_id") or domain or "browser_interaction"),
            user_id=actor_user_id,
            endpoint_id=str(payload.get("endpoint_id") or "").strip() or None,
            ai_app=domain,
            model=str(payload.get("model_name") or "").strip() or None,
            prompt=(raw_prompt or prompt_preview_redacted),
            file={"file_meta": file_meta} if file_meta else None,
            metadata={
                "source_surface": source_surface,
                "action_type": "prompt",
                "reason_codes": list(reason_codes),
                "input_signal_types": control_input_signal_types,
                "contains_sensitive": bool(detection_result.get("contains_sensitive")),
                "data_classification": source_classification,
                "destination_domain": domain,
                "governance_status": str(governance_status.get("status") or "UNKNOWN"),
                "triggered_controls": hinted_controls,
            },
            source_surface=source_surface,
        ),
        base_decision=decision,
        hinted_control_ids=hinted_controls,
    )
    control_engine_decision = _map_control_engine_browser_decision(control_decision.decision, fallback=decision)
    if platform_mode == PLATFORM_MODE_DISCOVERY and control_engine_decision == "block":
        control_engine_decision = "warn"
    if _decision_rank(control_engine_decision) > _decision_rank(decision):
        decision = control_engine_decision
        reason_codes = [*reason_codes, "control_engine_escalation"]
        input_signal_types = sorted({*input_signal_types, "control_engine_escalation"})

    resolved_interaction_action_type = "upload" if file_meta else "prompt_submit"
    destination_context = {
        "domain": domain,
        "application": str(payload.get("application") or domain),
        "trust_level": _browser_destination_trust_level(
            domain=domain,
            policy_sync=policy_sync,
            ai_system_id=ai_system_id,
        ),
        "control_mode": control_mode,
    }
    intent_aware_evidence_summary = build_intent_aware_evidence_summary(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        intent_aware_decision=intent_aware_decision,
        action_type=resolved_interaction_action_type,
        destination_context=destination_context,
        policy_snapshot={
            "policy_id": str(intent_policy.get("policy_id") or "INTENT_AWARE_AI_ACTION_CONTROL"),
            "policy_version": str(policy_version or "none"),
            "mode": str(intent_policy.get("mode") or "block"),
        },
        control_mode=control_mode,
    )

    prompt_hash = str(payload.get("prompt_hash") or "").strip()
    if not prompt_hash and prompt_preview_redacted:
        prompt_hash = hashlib.sha256(prompt_preview_redacted.encode("utf-8")).hexdigest()

    if (not persist_artifacts) or (decision == "allow" and not persist_allow_decisions):
        fallback_id = str(correlation_id or f"degraded-{uuid4()}")
        return {
            "decision": decision,
            "tier": tier,
            "reason_codes": reason_codes,
            "policy_version": policy_version,
            "platform_mode": platform_mode,
            "correlation_id": correlation_id,
            "input_signal_types": input_signal_types,
            "audit_log_id": f"degraded:{fallback_id}",
            "evidence_node_id": f"degraded:{fallback_id}",
            "finding_id": None,
            "runtime_event_id": None,
            "event_id": None,
            "persistence_mode": "degraded_no_write",
            "degradation_reason": str(degradation_reason or "persistence_disabled"),
        }

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="telemetry.desktop.interaction_eval" if is_desktop_surface else "telemetry.browser.interaction_eval",
        resource_type="tenant",
        resource_id=tenant_id,
        payload={
            "domain": domain,
            "tier": tier,
            "decision": decision,
            "reason_codes": reason_codes,
            "policy_version": policy_version,
            "platform_mode": platform_mode,
            "browser_profile": str(payload.get("browser_profile") or "default"),
            "extension_version": str(payload.get("extension_version") or ""),
            "enforcement_routing": routing,
            "routing_fallback_audit_id": fallback_audit_id,
            "routing_fallback_evidence_id": fallback_evidence_id,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
            "scoped_policy": scoped_policy.to_dict(),
            "control_decision": control_decision.to_dict(),
            "intent_context": intent_context,
            "input_content_context": input_content_context,
            "action_alignment_result": action_alignment_result,
            "intent_aware_decision": intent_aware_decision,
            "business_purpose_decision": business_purpose_decision,
            "destination_context": destination_context,
            "intent_aware_evidence_summary": intent_aware_evidence_summary,
        },
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="browser_interaction_eval",
        signal_type="browser.interaction.eval",
        label=f"{'Desktop app' if is_desktop_surface else 'Browser'} interaction adjudication for {domain}",
        payload={
            "domain": domain,
            "decision": decision,
            "tier": tier,
            "reason_codes": reason_codes,
            "policy_version": policy_version,
            "platform_mode": platform_mode,
            "prompt_hash": prompt_hash,
            "input_signal_types": input_signal_types,
            "browser_profile": str(payload.get("browser_profile") or "default"),
            "extension_version": str(payload.get("extension_version") or ""),
            "enforcement_routing": routing,
            "routing_fallback_audit_id": fallback_audit_id,
            "routing_fallback_evidence_id": fallback_evidence_id,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
            "scoped_policy": scoped_policy.to_dict(),
            "control_decision": control_decision.to_dict(),
            "intent_context": intent_context,
            "input_content_context": input_content_context,
            "action_alignment_result": action_alignment_result,
            "intent_aware_decision": intent_aware_decision,
            "business_purpose_decision": business_purpose_decision,
            "destination_context": destination_context,
            "intent_aware_evidence_summary": intent_aware_evidence_summary,
        },
        correlation_id=correlation_id,
    )

    finding = None
    if decision in {"warn", "block"}:
        finding_event_type = "prompt_blocked" if decision == "block" else "prompt_warned"
        finding = generate_from_browser_event(
            db,
            tenant_id=tenant_id,
            event_type=finding_event_type,
            domain=domain,
            ai_system_id=ai_system_id,
            user_id=actor_user_id,
            policy_version_id=policy_version,
            platform_mode=platform_mode,
            action_taken=decision,
            prompt_preview_redacted=prompt_preview_redacted,
            input_signal_types=input_signal_types,
            file_meta=file_meta,
            evidence_node_id=evidence.id,
            intent_aware_decision=intent_aware_decision,
            source_surface=source_surface,
        )

    runtime_event_id: str | None = None
    try:
        from app.services.runtime_intelligence.runtime_event_normalizer import (
            ingest_from_browser_interaction_eval,
            project_browser_attachment_metadata,
        )

        runtime_row = ingest_from_browser_interaction_eval(
            db,
            tenant_id=tenant_id,
            domain=domain,
            ai_system_id=ai_system_id,
            result={
                "decision": decision,
                "tier": tier,
                "reason_codes": reason_codes,
                "policy_version": policy_version,
                "correlation_id": correlation_id,
                "input_signal_types": input_signal_types,
                "attachment_summary": project_browser_attachment_metadata(file_meta),
                "evidence_node_id": evidence.id,
                "user_id": event_user_id,
                "user_email": actor_user_email,
                "machine_id": machine_id,
                "endpoint_id": endpoint_id,
                "browser": str(payload.get("browser") or browser_type or "").strip() or None,
                "browser_type": browser_type,
                "browser_profile": str(payload.get("browser_profile") or "default"),
                "extension_version": str(payload.get("extension_version") or ""),
                "application": application,
                "url": str(payload.get("url") or "").strip() or None,
                "page_title": str(payload.get("page_title") or "").strip() or None,
                "prompt_preview_redacted": prompt_preview_redacted,
                "contains_sensitive": bool(detection_result.get("contains_sensitive")),
                "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
                "sensitive_entities": list(detection_result.get("entities") or []),
                "triggered_controls": list(control_decision.triggered_controls),
                "evaluated_controls": [item.to_dict() for item in control_decision.evaluated_controls],
                "dominant_control": control_decision.dominant_control,
                "control_decision_reasoning": control_decision.reasoning,
                "control_decision_total_risk": control_decision.total_risk_score,
                "risk_tags": list(control_decision.risk_tags),
                "intent_context": intent_context,
                "input_content_context": input_content_context,
                "output_context": output_context,
                "action_alignment_result": action_alignment_result,
                "intent_aware_decision": intent_aware_decision,
                "business_purpose_decision": business_purpose_decision,
                "intent_category": intent_context.get("intent_category"),
                "intent_confidence": intent_context.get("intent_confidence"),
                "business_context": intent_context.get("business_context"),
                "input_sensitivity": input_content_context.get("sensitivity_level"),
                "output_sensitivity": output_context.get("output_sensitivity"),
                "action_alignment": action_alignment_result.get("alignment"),
                "matched_indicators": list(intent_aware_decision.get("matched_indicators") or []),
                "copy_export_control_applied": bool(intent_aware_decision.get("copy_export_control_applied")),
                "decision_reason": intent_aware_decision.get("decision_reason"),
                "source_surface": source_surface,
                "operation": "upload" if file_meta else ("desktop_prompt_submission" if is_desktop_surface else "browser_interaction"),
                "action_type": "file_upload" if file_meta else ("desktop_prompt_submitted" if is_desktop_surface else "prompt_submitted"),
                "tool_category": "desktop_ai_app" if is_desktop_surface else "browser_interaction",
                "ai_surface": "desktop_ai_app" if is_desktop_surface else "browser",
                "desktop_guard": {
                    "desktop_app": str(payload.get("desktop_app") or payload.get("application") or "").strip() or None,
                    "capture_method": str(payload.get("capture_method") or "").strip() or None,
                    "guard_version": str(payload.get("guard_version") or "").strip() or None,
                    "active_window_title": str(payload.get("active_window_title") or "").strip() or None,
                    "platform": str(payload.get("os_type") or payload.get("platform") or "").strip() or None,
                }
                if is_desktop_surface
                else {},
            },
        )
        runtime_event_id = runtime_row.event_id if runtime_row is not None else None
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="browser_extension_service",
            tenant_id=tenant_id,
            event_type="browser_interaction_eval",
            correlation_id=correlation_id,
            error=str(exc),
        )
    if finding is not None:
        enrich_pilot_finding_context(
            db,
            finding=finding,
            user_email=actor_user_email,
            browser_type=browser_type,
            application=application or None,
            decision=decision,
            policy_id=str(policy_version or "").strip() or None,
            related_runtime_event_id=runtime_event_id,
            machine_id=machine_id,
        )
        evidence_payload = dict(evidence.payload or {}) if isinstance(evidence.payload, dict) else {}
        evidence_ai_action = dict(evidence_payload.get("ai_action") or {})
        if evidence_ai_action:
            evidence_ai_action["finding_id"] = finding.finding_id
            evidence_payload["ai_action"] = evidence_ai_action
            evidence.payload = evidence_payload
        if runtime_event_id:
            try:
                from app.db.models.runtime_intelligence import RuntimeEvent

                runtime_row = db.get(RuntimeEvent, runtime_event_id)
                if runtime_row is not None:
                    runtime_metadata = dict(runtime_row.metadata_json or {})
                    ai_action = dict(runtime_metadata.get("ai_action") or {})
                    ai_action["finding_id"] = finding.finding_id
                    runtime_metadata["ai_action"] = ai_action
                    runtime_metadata["finding_id"] = finding.finding_id
                    runtime_row.metadata_json = runtime_metadata
                    from app.services.runtime_intelligence.behavior_graph_service import build_behavior_graph_for_event

                    build_behavior_graph_for_event(
                        db,
                        event=runtime_row,
                        finding_ids=[finding.finding_id],
                    )
                    db.flush()
            except Exception:  # pragma: no cover - non-blocking trace enrichment
                pass

    try:
        record_activity_event(
            db,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            payload={
                "timestamp": payload.get("timestamp") or _now_iso(),
                "event_type": "browser_interaction_eval",
                "action_type": "desktop_prompt_input" if is_desktop_surface else "prompt_input",
                "source_surface": source_surface,
                "domain": domain,
                "url": payload.get("url"),
                "page_title": payload.get("page_title"),
                "ai_app": domain,
                "ai_model": payload.get("model_name"),
                "data_classification": source_classification,
                "action_taken": decision,
                "policy_triggered": ",".join(reason_codes),
                "severity": ("high" if decision == "block" else ("med" if decision in {"warn", "hold"} else "low")),
                "risk_score": (0.9 if decision == "block" else (0.6 if decision in {"warn", "hold"} else 0.2)),
                "correlation_id": correlation_id,
                "runtime_event_id": runtime_event_id,
                "audit_log_id": audit.id,
                "evidence_node_id": evidence.id,
                "finding_id": finding.finding_id if finding else None,
                "prompt_raw": payload.get("raw_prompt") or payload.get("prompt_text"),
                "prompt_preview_redacted": prompt_preview_redacted,
                "prompt_storage_mode": payload.get("prompt_storage_mode"),
                "sensitivity_score": float(detection_result.get("confidence_score") or 0.0),
                "sensitive_detection": detection_result,
                "browser": payload.get("browser"),
                "browser_profile": payload.get("browser_profile"),
                "browser_version": payload.get("browser_version"),
                "extension_version": payload.get("extension_version"),
                "endpoint_id": payload.get("endpoint_id"),
                "os_type": payload.get("os_type"),
                "os_version": payload.get("os_version"),
                "device_type": payload.get("device_type"),
                "hostname": payload.get("hostname"),
                "ip_address": payload.get("ip_address"),
                "location": payload.get("location"),
                "metadata": {
                    "tier": tier,
                    "reason_codes": list(reason_codes),
                    "input_signal_types": list(input_signal_types or []),
                    "policy_version": policy_version,
                    "platform_mode": platform_mode,
                    "scoped_policy": scoped_policy.to_dict(),
                    "business_purpose_decision": business_purpose_decision,
                    "triggered_controls": list(control_decision.triggered_controls),
                    "dominant_control": control_decision.dominant_control,
                    "control_decision_reasoning": control_decision.reasoning,
                    "control_decision_total_risk": control_decision.total_risk_score,
                    "risk_tags": list(control_decision.risk_tags),
                },
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking audit trail enrichment
        log_structured(
            "activity_audit_record_failed",
            module="browser_extension_service",
            tenant_id=tenant_id,
            event_type="browser_interaction_eval",
            correlation_id=correlation_id,
            error=str(exc),
        )

    db.flush()
    return {
        "decision": decision,
        "tier": tier,
        "reason_codes": reason_codes,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "correlation_id": correlation_id,
        "input_signal_types": input_signal_types,
        "audit_log_id": audit.id,
        "evidence_node_id": evidence.id,
        "finding_id": finding.finding_id if finding else None,
        "runtime_event_id": runtime_event_id,
        # Extended control decision fields are returned for internal service callers
        # (for example simulation execution). API response models keep a bounded subset.
        "event_id": runtime_event_id,
        "triggered_controls": list(control_decision.triggered_controls or []),
        "evaluated_controls": [item.to_dict() for item in (control_decision.evaluated_controls or [])],
        "dominant_control": control_decision.dominant_control,
        "control_decision_reasoning": control_decision.reasoning,
        "control_decision_total_risk": float(control_decision.total_risk_score),
        "risk_tags": list(control_decision.risk_tags or []),
        "business_purpose_decision": business_purpose_decision,
    }
