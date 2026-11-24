from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.control_engine import AIAction, evaluate_control_engine, map_generic_decision
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.core.config import settings
from app.core.observability import log_structured
from app.db.models.discovery import DiscoveryApplication
from app.db.models.monitoring import MonitoringSignal
from app.services.activity_audit_service import record_activity_event
from app.services.ai_iam_service import (
    build_ai_action_record,
    build_intent_aware_evidence_summary,
    classify_input_content_context,
    classify_intent_context,
    classify_output_context,
    evaluate_action_alignment,
    evaluate_intent_aware_action_control,
)
from app.services.audit_service import write_audit_log
from app.services.browser_extension_service import build_extension_policy_sync
from app.services.discovery_service import tool_key_for_name
from app.services.evidence_service import create_evidence_node
from app.services.findings_service import (
    enrich_pilot_finding_context,
    generate_data_transfer_finding,
)
from app.services.enforcement_routing_service import (
    fallback_decision_for_gateway_failure,
    record_routing_failure,
    route_enforcement,
)
from app.services.guardian_policy_engine import evaluate_data_transfer_policy
from app.services.governance_resolution import resolve_ai_system_status
from app.services.policy_scope_service import resolve_scoped_policy_decision
from app.services.shadow_ai.provider_catalog import infer_from_signal
from app.services.sensitive_data_detection_service import (
    classify_data,
    detect_sensitive_data,
    detection_signal_types,
)


ALLOWED_SOURCE_CLASSIFICATIONS = {"protected", "unknown", "public"}
ALLOWED_SOURCE_SURFACES = {"ai_tool", "internal_app", "email", "slack", "document", "unknown"}
ALLOWED_DESTINATION_SURFACES = {"email", "slack", "ai_tool", "saas", "unknown"}
ALLOWED_INPUT_CONTEXT = {"compose_box", "chat_box", "form_field", "unknown"}

INTERNAL_DOMAIN_HINTS = {"localhost", "local", "internal", "intranet", "corp", "company", "acme.ai"}
EXTERNAL_EMAIL_DOMAINS = {"mail.google.com", "outlook.office.com", "outlook.live.com"}
EXTERNAL_SLACK_DOMAINS = {"slack.com", "app.slack.com"}
KNOWN_PUBLIC_AI_DOMAINS = {"chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "perplexity.ai"}

SEVERITY_BY_DECISION = {
    "allow": "low",
    "warn": "med",
    "require_justification": "high",
    "block": "high",
}


@dataclass
class TransferDecision:
    decision: str
    reason_code: str
    explanation: str
    recommended_action: str
    justification_required: bool
    severity: str
    risk_category: str
    data_classification: str | None
    finding_type: str | None
    source_surface: str
    destination_surface: str
    destination_domain: str
    destination_app_name: str | None
    destination_ai_system_id: str | None
    destination_is_known_ai: bool
    destination_is_external: bool
    destination_is_sanctioned: bool
    policy: dict[str, Any] | None


def _transfer_decision_rank(decision: str) -> int:
    normalized = str(decision or "").strip().lower()
    if normalized == "block":
        return 4
    if normalized == "require_justification":
        return 3
    if normalized == "warn":
        return 2
    return 1


def _map_control_engine_transfer_decision(decision: str, *, fallback: str = "allow") -> str:
    return map_generic_decision(
        decision,
        mapping={
            "allow": "allow",
            "alert": "warn",
            "modify": "warn",
            "step_up": "require_justification",
            "block": "block",
        },
        default=fallback,
    )


def _map_scoped_transfer_decision(decision: str | None, *, fallback: str = "allow") -> str:
    return map_generic_decision(
        decision or "",
        mapping={
            "allow": "allow",
            "warn": "warn",
            "alert": "warn",
            "modify": "warn",
            "redact": "block",
            "require_justification": "require_justification",
            "require_approval": "require_justification",
            "hold_for_approval": "require_justification",
            "step_up": "require_justification",
            "step-up": "require_justification",
            "block": "block",
            "deny": "block",
        },
        default=fallback,
    )


def _stable_hash(payload: dict[str, Any]) -> str:
    serialized = json.dumps(payload, default=str, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _build_transfer_decision_spine(
    *,
    tenant_id: str,
    action_id: str | None,
    timestamp: str | None,
    event_type: str,
    decision: str,
    reason_code: str,
    policy_version: str,
    destination_domain: str,
    destination_surface: str,
    destination_app_name: str | None,
    destination_ai_system_id: str | None,
    actor_user_id: str | None,
    actor_user_email: str | None,
    evidence_node_id: str | None,
    correlation_id: str | None,
    payload: dict[str, Any],
    source_classification: str,
    detection_result: dict[str, Any],
    file_meta: list[dict[str, Any]] | None = None,
    intent_aware_decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    response_action_id = str(action_id or correlation_id or f"data-transfer:{_stable_hash({'tenant': tenant_id, 'destination': destination_domain})[:12]}")
    ai_action = build_ai_action_record(
        tenant_id=tenant_id,
        action_id=response_action_id,
        timestamp=timestamp or _now_iso(),
        source_surface="browser",
        event_type=event_type,
        user_id=actor_user_id,
        ai_system_id=destination_ai_system_id,
        app_id=destination_domain,
        machine_id=str(payload.get("machine_id") or payload.get("endpoint_id") or "").strip() or None,
        browser_type=str(payload.get("browser_type") or payload.get("browser") or "").strip() or None,
        application=destination_app_name or destination_domain,
        policy_version_id=policy_version,
        decision=decision,
        evidence_node_ids=[evidence_node_id] if evidence_node_id else [],
        correlation_id=correlation_id,
        metadata={
            "policy_id": "DATA_TRANSFER_CONTROL",
            "reason": reason_code,
            "reason_code": reason_code,
            "action_type": "file_upload" if file_meta else "copy_paste",
            "action_risk": "high" if decision in {"block", "require_justification"} else "medium",
            "platform_mode": payload.get("platform_mode"),
            "user_email": actor_user_email,
            "endpoint_id": payload.get("endpoint_id") or payload.get("machine_id"),
            "machine_id": payload.get("machine_id") or payload.get("endpoint_id"),
            "browser": payload.get("browser"),
            "browser_type": payload.get("browser_type") or payload.get("browser"),
            "application": destination_app_name or destination_domain,
            "destination_domain": destination_domain,
            "destination_context": {
                "domain": destination_domain,
                "surface": destination_surface,
                "application": destination_app_name,
            },
            "input_content_context": {
                "sensitivity_level": "high" if bool(detection_result.get("contains_sensitive")) else source_classification,
                "contains_secrets": any(
                    str((entity or {}).get("entity_type") or (entity or {}).get("type") or "").lower()
                    in {"api_key", "secret", "password", "private_key", "token"}
                    for entity in list(detection_result.get("entities") or [])
                    if isinstance(entity, dict)
                ),
                "contains_business_emails": any(
                    str((entity or {}).get("entity_type") or (entity or {}).get("type") or "").lower() == "email"
                    for entity in list(detection_result.get("entities") or [])
                    if isinstance(entity, dict)
                ),
                "contains_customer_data": source_classification == "protected",
            },
            "intent_aware_decision": dict(intent_aware_decision or {}),
        },
    )
    return {
        "policy_snapshot": dict(ai_action.get("policy_snapshot") or {}),
        "decision_explanation": dict(ai_action.get("decision_explanation") or {}),
        "evidence_bundle": dict(ai_action.get("evidence_bundle") or {}),
    }


def _sensitive_entity_types(detection_result: dict[str, Any]) -> list[str]:
    entity_types: set[str] = set()
    for entity in detection_result.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        entity_type = str(entity.get("entity_type") or entity.get("type") or "").strip()
        if entity_type:
            entity_types.add(entity_type)
    return sorted(entity_types)


def _build_approved_context_envelope(
    *,
    actor_user_id: str | None,
    source_domain: str,
    destination_domain: str,
    destination_surface: str,
    source_classification: str,
    requested_decision: str,
    final_decision: str,
    reason_code: str,
    justification: str,
    policy_version: str,
    platform_mode: str,
    file_meta: list[dict[str, Any]],
    business_spreadsheet: dict[str, Any],
    business_visual: dict[str, Any],
    detection_result: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    context_integrity_status = "valid" if final_decision == "allow" else "incomplete"
    if requested_decision == "block" or final_decision == "block":
        context_integrity_status = "broken"

    action_scope = ["copy_paste"]
    if file_meta:
        action_scope.append("file_upload")

    seed = {
        "actor_user_id": actor_user_id,
        "source_domain": source_domain,
        "destination_domain": destination_domain,
        "destination_surface": destination_surface,
        "source_classification": source_classification,
        "requested_decision": requested_decision,
        "final_decision": final_decision,
        "reason_code": reason_code,
        "policy_version": policy_version,
    }
    envelope = {
        "envelope_id": f"ace_{_stable_hash(seed)[:16]}",
        "approval_type": "data_transfer_justification",
        "approved_for_user_id": actor_user_id,
        "approved_for_agent_id": None,
        "approved_intent": {
            "declared_intent": justification[:240] if final_decision == "allow" else None,
            "intent_category": "business_justification",
            "task_description": "One-time data transfer approval for the current browser action.",
            "allowed_outcomes": ["complete_current_transfer"] if final_decision == "allow" else [],
            "prohibited_outcomes": [
                "reuse_for_other_destinations",
                "send_secrets_or_credentials",
                "expand_scope_without_reapproval",
                "convert_to_bulk_export",
            ],
        },
        "approved_scope": {
            "allowed_actions": action_scope,
            "blocked_actions": [
                "secret_transfer",
                "credential_transfer",
                "destination_drift",
                "scope_drift",
                "bulk_export_without_review",
            ],
            "allowed_source_domains": [source_domain] if source_domain else [],
            "allowed_destination_domains": [destination_domain] if destination_domain else [],
            "allowed_destination_surfaces": [destination_surface] if destination_surface else [],
            "source_classification": source_classification,
            "business_spreadsheet": bool(business_spreadsheet.get("business_spreadsheet_upload")),
            "business_visual": bool(business_visual.get("business_visual_upload")),
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_entity_types": _sensitive_entity_types(detection_result),
        },
        "constraints": {
            "max_action_count": 1,
            "expires_at": None,
            "require_reapproval_for": [
                "actor_change",
                "destination_change",
                "destination_surface_change",
                "source_change",
                "intent_drift",
                "secret_detected",
                "scope_expansion",
                "policy_change",
                "approval_expired",
            ],
        },
        "status": "active" if final_decision == "allow" else "rejected",
        "context_integrity_status": context_integrity_status,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "decision": final_decision,
        "reason_code": reason_code,
    }
    return envelope, context_integrity_status


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_domain(raw: str | None) -> str:
    value = str(raw or "").strip().lower()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"https://{value}")
    host = parsed.netloc or parsed.path
    host = host.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host.strip(".")


def _normalize_source_classification(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in ALLOWED_SOURCE_CLASSIFICATIONS else "unknown"


def _normalize_source_surface(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in ALLOWED_SOURCE_SURFACES else "unknown"


def _normalize_destination_surface(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in ALLOWED_DESTINATION_SURFACES else "unknown"


def _normalize_input_context(value: str | None) -> str:
    normalized = str(value or "unknown").strip().lower()
    return normalized if normalized in ALLOWED_INPUT_CONTEXT else "unknown"


def _business_spreadsheet_context(file_meta: list[dict[str, Any]]) -> dict[str, Any]:
    fallback_secret_context: dict[str, Any] | None = None
    for item in file_meta:
        classification = item.get("spreadsheet_classification")
        if not isinstance(classification, dict):
            continue
        reason_code = str(classification.get("reason_code") or "").strip()
        signal_types = [
            str(signal).strip()
            for signal in (classification.get("signal_types") or [])
            if str(signal).strip()
        ]
        if bool(classification.get("contains_secret")) and fallback_secret_context is None:
            fallback_secret_context = {
                "business_spreadsheet_upload": False,
                "business_related": bool(classification.get("business_related")),
                "contains_secret": True,
                "decision": str(classification.get("decision") or "").strip() or None,
                "reason_code": reason_code or None,
                "signal_types": signal_types,
            }
        if reason_code == "business_spreadsheet_to_public_ai" or "business_spreadsheet_upload" in signal_types:
            return {
                "business_spreadsheet_upload": True,
                "business_related": bool(classification.get("business_related")),
                "contains_secret": bool(classification.get("contains_secret")),
                "decision": str(classification.get("decision") or "").strip() or None,
                "reason_code": reason_code or None,
                "signal_types": signal_types,
            }
    if fallback_secret_context is not None:
        return fallback_secret_context
    return {
        "business_spreadsheet_upload": False,
        "business_related": False,
        "contains_secret": False,
        "decision": None,
        "reason_code": None,
        "signal_types": [],
    }


def _business_visual_context(file_meta: list[dict[str, Any]]) -> dict[str, Any]:
    fallback_secret_context: dict[str, Any] | None = None
    for item in file_meta:
        classification = item.get("visual_classification")
        if not isinstance(classification, dict):
            continue
        reason_code = str(classification.get("reason_code") or "").strip()
        signal_types = [
            str(signal).strip()
            for signal in (classification.get("signal_types") or [])
            if str(signal).strip()
        ]
        if bool(classification.get("contains_secret")) and fallback_secret_context is None:
            fallback_secret_context = {
                "business_visual_upload": False,
                "business_related": bool(classification.get("business_related")),
                "contains_secret": True,
                "decision": str(classification.get("decision") or "").strip() or None,
                "reason_code": reason_code or None,
                "signal_types": signal_types,
            }
        if reason_code == "visual_business_content_to_public_ai" or "visual_business_content" in signal_types:
            return {
                "business_visual_upload": True,
                "business_related": bool(classification.get("business_related")),
                "contains_secret": bool(classification.get("contains_secret")),
                "decision": str(classification.get("decision") or "").strip() or None,
                "reason_code": reason_code or None,
                "signal_types": signal_types,
            }
    if fallback_secret_context is not None:
        return fallback_secret_context
    return {
        "business_visual_upload": False,
        "business_related": False,
        "contains_secret": False,
        "decision": None,
        "reason_code": None,
        "signal_types": [],
    }


def _is_external_domain(domain: str) -> bool:
    normalized = _normalize_domain(domain)
    if not normalized:
        return True
    if normalized.endswith(".local"):
        return False
    for hint in INTERNAL_DOMAIN_HINTS:
        if normalized == hint or normalized.endswith(f".{hint}"):
            return False
    return True


def _domain_match(domain: str, expected: str) -> bool:
    left = _normalize_domain(domain)
    right = _normalize_domain(expected)
    if not left or not right:
        return False
    return left == right or left.endswith(f".{right}")


def _destination_trust_level(
    *,
    decision: TransferDecision,
    destination_surface: str,
    destination_discovery_status: str,
) -> str:
    if str(destination_discovery_status or "").strip().lower() == "blocked":
        return "blocked"
    if decision.destination_is_sanctioned and decision.destination_ai_system_id:
        return "approved_enterprise"
    if decision.destination_is_sanctioned:
        return "approved_public"
    if decision.destination_is_known_ai or destination_surface == "ai_tool" or any(
        _domain_match(decision.destination_domain, item) for item in KNOWN_PUBLIC_AI_DOMAINS
    ):
        return "public_ai"
    return "unknown"


def _resolve_destination_ai_system(
    db: Session,
    *,
    tenant_id: str,
    destination_domain: str,
) -> tuple[str | None, str | None, str]:
    domain = _normalize_domain(destination_domain)
    if not domain:
        return None, None, "unknown"

    row = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == tenant_id,
            DiscoveryApplication.tool_key == tool_key_for_name(domain),
        )
    )
    if row is None:
        row = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == tenant_id,
                DiscoveryApplication.tool_name == domain,
            )
        )
    if row is None:
        return None, None, "unknown"
    return row.ai_system_id, row.tool_name, row.status


def _evaluate_transfer_decision(
    *,
    source_classification: str,
    source_surface: str,
    destination_surface: str,
    destination_domain: str,
    destination_ai_system_id: str | None,
    destination_discovery_status: str,
    platform_mode: str,
    destination_app_name: str | None,
    action_type: str = "copy_paste",
) -> TransferDecision:
    destination_is_external = _is_external_domain(destination_domain)
    destination_is_ai = destination_surface == "ai_tool"
    destination_is_sanctioned = bool(destination_ai_system_id) or destination_discovery_status in {"approved"}
    known_ai_tool = destination_is_ai or (destination_app_name or "").strip().lower() in {
        "chatgpt",
        "claude",
        "gemini",
        "copilot",
        "perplexity",
    }
    engine_decision = evaluate_data_transfer_policy(
        source_classification=source_classification,
        source_surface=source_surface,
        destination_surface=destination_surface,
        destination_domain=destination_domain,
        destination_ai_system_id=destination_ai_system_id,
        destination_discovery_status=destination_discovery_status,
        destination_app_name=destination_app_name,
        destination_is_external=destination_is_external,
        platform_mode=str(platform_mode or "enforce").strip().lower(),
        action_type=action_type,
    )
    decision = engine_decision.decision
    reason_code = engine_decision.reason_code
    explanation = engine_decision.explanation
    recommended_action = engine_decision.recommended_action
    justification_required = bool(engine_decision.justification_required)
    severity = SEVERITY_BY_DECISION.get(decision, engine_decision.severity if engine_decision.severity in {"low", "med", "high"} else "med")
    risk_category = "sensitive_data" if source_classification == "protected" else "data_transfer"
    if decision == "warn" and source_classification == "public" and known_ai_tool and not destination_is_sanctioned:
        risk_category = "shadow_ai"
    data_classification: str | None = "protected" if source_classification == "protected" else None
    finding_type = None
    if engine_decision.policy is not None:
        finding_type = str((engine_decision.policy.get("metadata") or {}).get("finding_type") or "").strip() or None
    if finding_type is None and decision in {"warn", "block", "require_justification"}:
        finding_type = "sensitive_data_external_transfer_attempt"

    return TransferDecision(
        decision=decision,
        reason_code=reason_code,
        explanation=explanation,
        recommended_action=recommended_action,
        justification_required=justification_required,
        severity=severity,
        risk_category=risk_category,
        data_classification=data_classification,
        finding_type=finding_type,
        source_surface=source_surface,
        destination_surface=destination_surface,
        destination_domain=destination_domain,
        destination_app_name=destination_app_name,
        destination_ai_system_id=destination_ai_system_id,
        destination_is_known_ai=known_ai_tool,
        destination_is_external=destination_is_external,
        destination_is_sanctioned=destination_is_sanctioned,
        policy=engine_decision.policy,
    )


def _record_runtime_for_data_transfer(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    monitoring_signal_id: str,
    evidence_node_id: str,
    payload: dict[str, Any],
) -> str | None:
    try:
        from app.services.ai_iam_service import (
            control_mode_for_pre_action_decision,
        )
        from app.services.runtime_intelligence.runtime_event_normalizer import ingest_from_browser_signal

        decision = str(
            payload.get("decision")
            or payload.get("action_taken")
            or ""
        ).strip().lower()
        intent_decision = (
            dict(payload.get("intent_aware_decision") or {})
            if isinstance(payload.get("intent_aware_decision"), dict)
            else {}
        )
        trusted_control_mode = (
            "shadow_would_block"
            if str(intent_decision.get("decision") or "").strip().lower()
            == "allow"
            and str(intent_decision.get("would_decision") or "").strip().lower()
            in {"block", "deny"}
            else control_mode_for_pre_action_decision(decision, inline=True)
        )
        runtime_row = ingest_from_browser_signal(
            db,
            tenant_id=tenant_id,
            payload=payload,
            ai_system_id=ai_system_id,
            evidence_node_id=evidence_node_id,
            monitoring_signal_id=monitoring_signal_id,
            trusted_pre_action_governance_check={
                "control_mode": trusted_control_mode,
            },
        )
        return runtime_row.event_id if runtime_row is not None else None
    except Exception as exc:  # pragma: no cover - non-blocking runtime enrichment
        if isinstance(exc, CanonicalProjectionError):
            raise
        log_structured(
            "runtime_intelligence_ingest_failed",
            module="runtime_control_data_transfer_service",
            tenant_id=tenant_id,
            event_type=str(payload.get("event_type") or "data_transfer_check"),
            correlation_id=str(payload.get("correlation_id") or ""),
            error=str(exc),
        )
        return None


def _governance_state_for_destination(
    db: Session,
    *,
    tenant_id: str,
    destination_ai_system_id: str | None,
) -> dict[str, str]:
    return resolve_ai_system_status(
        destination_ai_system_id,
        {
            "db": db,
            "tenant_id": tenant_id,
            "source_hint": "trust_center",
            "route": "/runtime-control/data-transfer-check",
            "module": "runtime_control",
        },
    )


def evaluate_data_transfer_and_record(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    actor_user_email: str | None = None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    copy_context = dict(payload.get("copy_context") or {})
    paste_context = dict(payload.get("paste_context") or {})

    source_domain = _normalize_domain(copy_context.get("source_domain") or copy_context.get("source_url"))
    destination_domain = _normalize_domain(
        paste_context.get("destination_domain") or paste_context.get("destination_url")
    )
    if not destination_domain:
        raise ValueError("paste_context.destination_domain or destination_url is required")

    source_surface = _normalize_source_surface(copy_context.get("source_surface_type"))
    destination_surface = _normalize_destination_surface(paste_context.get("destination_surface_type"))
    destination_input_context = _normalize_input_context(paste_context.get("destination_input_context"))
    source_classification = _normalize_source_classification(copy_context.get("source_classification_hint"))
    file_meta = [item for item in (payload.get("file_meta") or []) if isinstance(item, dict)]

    source_hash = str(copy_context.get("copied_text_hash") or "").strip()
    if not source_hash:
        raise ValueError("copy_context.copied_text_hash is required")

    policy_sync = build_extension_policy_sync(db, tenant_id=tenant_id)
    policy_version = str(payload.get("policy_version") or policy_sync.policy_version)
    platform_mode = str(payload.get("platform_mode") or policy_sync.platform_mode)
    destination_ai_system_id, resolved_destination_name, destination_discovery_status = _resolve_destination_ai_system(
        db,
        tenant_id=tenant_id,
        destination_domain=destination_domain,
    )
    destination_app_name = (
        str(paste_context.get("destination_app_name") or "").strip()
        or str(resolved_destination_name or "").strip()
        or None
    )
    detection_result = detect_sensitive_data(
        text_inputs=[str(copy_context.get("copied_text_preview_redacted") or "")],
        file_meta=file_meta,
        source="browser",
        destination=destination_surface,
        ai_system_id=destination_ai_system_id,
        user_id=actor_user_id,
        correlation_id=correlation_id,
    )
    detected_classification = classify_data(
        detection_result=detection_result,
        classification_hint=source_classification,
        allow_unknown=True,
    )
    if detected_classification == "protected":
        source_classification = "protected"
    elif detected_classification == "public" and source_classification == "unknown":
        source_classification = "public"
    contains_sensitive = bool(detection_result.get("contains_sensitive"))
    sensitive_upload_detected = bool(file_meta) and contains_sensitive
    policy_action_type = "file_upload" if file_meta else "copy_paste"
    business_spreadsheet = _business_spreadsheet_context(file_meta)
    business_visual = _business_visual_context(file_meta)

    governance_status = _governance_state_for_destination(
        db,
        tenant_id=tenant_id,
        destination_ai_system_id=destination_ai_system_id,
    )
    routing = route_enforcement(
        {
            "policy_id": "data_movement_control",
            "policy_version": policy_version or "none",
        },
        {
            "event_id": str(payload.get("event_id") or ""),
            "tenant_id": tenant_id,
            "source_surface": "browser",
            "action_type": policy_action_type,
            "ai_system_id": destination_ai_system_id,
            "agent_id": None,
            "data_classification": source_classification,
            "correlation_id": correlation_id,
        },
    )
    routing_fallback_audit_id: str | None = None
    routing_fallback_evidence_id: str | None = None
    try:
        decision = _evaluate_transfer_decision(
            source_classification=source_classification,
            source_surface=source_surface,
            destination_surface=destination_surface,
            destination_domain=destination_domain,
            destination_ai_system_id=destination_ai_system_id,
            destination_discovery_status=destination_discovery_status,
            platform_mode=platform_mode,
            destination_app_name=destination_app_name,
            action_type=policy_action_type,
        )
    except Exception as exc:
        fallback = fallback_decision_for_gateway_failure(
            platform_mode=platform_mode,
            normalized_event=dict(routing.get("normalized_event") or {}),
        )
        routing_fallback_audit_id, routing_fallback_evidence_id = record_routing_failure(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            routing=routing,
            stage="runtime_control.data_transfer",
            error=str(exc),
            fallback_applied="gateway",
        )
        fallback_decision = str(fallback["decision"]).strip().lower()
        if fallback_decision not in {"warn", "block"}:
            fallback_decision = "block"
        decision = TransferDecision(
            decision=fallback_decision,
            reason_code=str(fallback["reason_code"]),
            explanation="Primary browser-layer enforcement failed. Applied gateway fallback policy.",
            recommended_action=str(fallback["recommended_action"]),
            justification_required=False,
            severity=("high" if fallback_decision == "block" else "med"),
            risk_category="data_transfer",
            data_classification=("protected" if source_classification == "protected" else None),
            finding_type="sensitive_data_external_transfer_attempt",
            source_surface=source_surface,
            destination_surface=destination_surface,
            destination_domain=destination_domain,
            destination_app_name=destination_app_name,
            destination_ai_system_id=destination_ai_system_id,
            destination_is_known_ai=destination_surface == "ai_tool",
            destination_is_external=_is_external_domain(destination_domain),
            destination_is_sanctioned=bool(destination_ai_system_id),
            policy=None,
        )
    if (
        decision.destination_is_known_ai
        and governance_status.get("status") == "UNKNOWN"
        and not decision.destination_is_sanctioned
        and decision.reason_code != "sensitive_file_upload"
    ):
        decision = TransferDecision(
            **{
                **decision.__dict__,
                "decision": "block" if platform_mode != "discovery" else "warn",
                "reason_code": "unknown_ai_destination_not_registered",
                "explanation": "Destination AI system is not registered in Trust Center.",
                "recommended_action": "route_to_governance",
                "justification_required": False,
                "severity": "high",
                "risk_category": "shadow_ai",
                "finding_type": "sensitive_data_to_public_ai_attempt",
            }
        )
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
            "action_type": ("file_upload" if file_meta else "copy_paste"),
            "operation": ("upload" if file_meta else "copy_paste"),
            "domain": destination_domain,
            "tool_name": destination_app_name or destination_domain,
            "provider": payload.get("provider"),
            "model": payload.get("ai_model"),
            "ai_system_id": destination_ai_system_id,
            "data_classification": source_classification,
            "contains_sensitive": contains_sensitive,
            "risk_tier": payload.get("risk_tier"),
        },
    )
    hard_block_reasons = {
        "sensitive_file_upload",
        "sensitive_file_upload_requires_justification",
        "unknown_ai_destination_not_registered",
    }
    hard_block_active = decision.decision in {"block", "require_justification"} and decision.reason_code in hard_block_reasons
    if scoped_policy.matched:
        scoped_decision = _map_scoped_transfer_decision(scoped_policy.decision, fallback=decision.decision)
        if platform_mode == "discovery" and scoped_decision == "block":
            scoped_decision = "warn"
        scoped_reason_code = str(scoped_policy.reason_code or "scoped_policy_matched")
        apply_scoped_overlay = (
            _transfer_decision_rank(scoped_decision) > _transfer_decision_rank(decision.decision)
            or (_transfer_decision_rank(scoped_decision) < _transfer_decision_rank(decision.decision) and not hard_block_active)
            or (scoped_decision == decision.decision and decision.reason_code != scoped_reason_code and not hard_block_active)
        )
        if apply_scoped_overlay:
            decision = TransferDecision(
                **{
                    **decision.__dict__,
                    "decision": scoped_decision,
                    "reason_code": scoped_reason_code,
                    "explanation": str(scoped_policy.explanation or "Scoped policy rule matched transfer context."),
                    "recommended_action": str(scoped_policy.recommended_action or "monitor"),
                    "justification_required": scoped_decision == "require_justification",
                    "severity": (
                        "high"
                        if scoped_decision in {"block", "require_justification"}
                        else ("med" if scoped_decision == "warn" else "low")
                    ),
                    "finding_type": (
                        decision.finding_type
                        or (
                            "sensitive_data_external_transfer_attempt"
                            if scoped_decision in {"warn", "block", "require_justification"}
                            else None
                        )
                    ),
                }
            )

    copied_preview = str(copy_context.get("copied_text_preview_redacted") or "")
    transfer_action_type = (
        str(payload.get("action_type") or ("file_upload" if file_meta else "paste_output_to_external_site")).strip()
        or ("file_upload" if file_meta else "paste_output_to_external_site")
    )
    intent_context = classify_intent_context(
        declared_intent=str(payload.get("declared_intent") or payload.get("intent") or "").strip() or None,
        text=" ".join(
            item
            for item in [
                copied_preview,
                str(paste_context.get("destination_app_name") or ""),
                str(copy_context.get("source_app_name") or ""),
            ]
            if str(item or "").strip()
        ),
        action_type=transfer_action_type,
        business_context=str(payload.get("business_context") or "").strip() or None,
    )
    input_content_context = classify_input_content_context(copied_preview, file_meta=file_meta)
    output_context = classify_output_context(
        output_text=copied_preview,
        output_ref=str(copy_context.get("copied_text_hash") or "").strip() or correlation_id,
    )
    action_alignment_result = evaluate_action_alignment(
        intent_context=intent_context,
        action_type=transfer_action_type,
        input_content_context=input_content_context,
        output_context=output_context,
    )
    intent_policy = dict(payload.get("intent_policy") or {}) if isinstance(payload.get("intent_policy"), dict) else {}
    if not intent_policy:
        intent_policy = dict(policy_sync.intent_aware_action_control or {})
        if platform_mode == "discovery" and str(intent_policy.get("mode") or "").strip().lower() == "block":
            intent_policy["mode"] = "warn"
    if not intent_policy:
        intent_policy = {
            "policy_id": "INTENT_AWARE_AI_ACTION_CONTROL",
            "mode": "warn" if platform_mode == "discovery" else "block",
        }
    intent_aware_decision = evaluate_intent_aware_action_control(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        action_type=transfer_action_type,
        policy=intent_policy,
    )
    guardian_sensitive_upload_decision = decision.reason_code in {
        "sensitive_file_upload",
        "sensitive_file_upload_requires_justification",
    }
    clean_file_upload_allow = bool(file_meta) and not contains_sensitive and decision.decision == "allow"
    if (
        intent_aware_decision.get("decision") in {"block", "warn"}
        and not guardian_sensitive_upload_decision
        and not clean_file_upload_allow
    ):
        intent_decision = str(intent_aware_decision.get("decision") or "").strip().lower()
        if _transfer_decision_rank(intent_decision) > _transfer_decision_rank(decision.decision):
            decision = TransferDecision(
                **{
                    **decision.__dict__,
                    "decision": intent_decision,
                    "reason_code": str(intent_aware_decision.get("decision_reason") or "intent_aware_policy"),
                    "explanation": "Intent-aware policy evaluated copied output/content and attempted transfer action.",
                    "recommended_action": "Review copied content sensitivity and approved destination policy.",
                    "justification_required": intent_decision == "warn",
                    "severity": "high" if intent_decision == "block" else "med",
                    "risk_category": "intent_aware_ai_action_control",
                    "finding_type": str(intent_aware_decision.get("finding_type") or "AI_OUTPUT_COPY_BLOCKED"),
                }
            )
    approved_public_ai_transfer = (
        decision.destination_is_sanctioned
        and (
            source_classification == "public"
            or (
                not bool(input_content_context.get("contains_secrets"))
                and not bool(input_content_context.get("contains_business_emails"))
                and not bool(input_content_context.get("contains_customer_data"))
                and not bool(input_content_context.get("contains_crm_like_table"))
                and not bool(output_context.get("contains_secret_like_value"))
                and not bool(output_context.get("contains_business_email"))
                and not bool(output_context.get("contains_customer_contact"))
            )
        )
        and str(intent_aware_decision.get("decision") or "").strip().lower() == "allow"
        and str(intent_aware_decision.get("would_decision") or "").strip().lower() in {"", "allow"}
    )
    if approved_public_ai_transfer and decision.decision != "allow":
        decision = TransferDecision(
            **{
                **decision.__dict__,
                "decision": "allow",
                "reason_code": "public_to_approved_ai_allow",
                "explanation": "Public content to an approved AI destination is allowed.",
                "recommended_action": "monitor",
                "justification_required": False,
                "severity": "low",
                "risk_category": "data_transfer",
                "finding_type": None,
            }
        )

    hinted_controls: list[str] = []
    if contains_sensitive:
        hinted_controls.extend(["SENSITIVE_DATA_DETECTION", "PII_EXFILTRATION_PREVENTION"])
    if sensitive_upload_detected:
        hinted_controls.extend(["FILE_UPLOAD_INSPECTION", "OCR_DATA_EXTRACTION_CONTROL"])
    if (
        (decision.destination_is_known_ai or destination_surface == "ai_tool")
        and str(governance_status.get("status") or "").upper() == "UNKNOWN"
        and not decision.destination_is_sanctioned
    ):
        hinted_controls.extend(["AI_SYSTEM_INVENTORY_CONTROL", "SHADOW_AI_DETECTION"])
    if decision.decision in {"warn", "block", "require_justification"}:
        hinted_controls.append("POLICY_ENFORCEMENT_CONTROL")

    control_decision = evaluate_control_engine(
        AIAction(
            action_id=str(correlation_id or payload.get("event_id") or f"transfer:{destination_domain}"),
            user_id=actor_user_id,
            endpoint_id=str(payload.get("endpoint_id") or "").strip() or None,
            ai_app=destination_app_name or destination_domain,
            model=str(payload.get("ai_model") or "").strip() or None,
            prompt=str(copy_context.get("copied_text_preview_redacted") or ""),
            file={"file_meta": file_meta} if file_meta else None,
            metadata={
                "source_surface": "browser",
                "action_type": policy_action_type,
                "reason_code": decision.reason_code,
                "input_signal_types": [
                    "data_transfer",
                    f"source_{source_classification}",
                    f"destination_{destination_surface}",
                    *detection_signal_types(detection_result),
                ],
                "contains_sensitive": contains_sensitive,
                "data_classification": source_classification,
                "destination_domain": destination_domain,
                "destination_is_external": decision.destination_is_external,
                "governance_status": (
                    str(governance_status.get("status") or "UNKNOWN")
                    if (decision.destination_is_known_ai or destination_surface == "ai_tool") and not decision.destination_is_sanctioned
                    else "NOT_APPLICABLE"
                ),
                "triggered_controls": hinted_controls,
            },
            source_surface="browser",
        ),
        base_decision=decision.decision,
        hinted_control_ids=hinted_controls,
    )
    mapped_control_decision = _map_control_engine_transfer_decision(control_decision.decision, fallback=decision.decision)
    if platform_mode == "discovery" and mapped_control_decision == "block":
        mapped_control_decision = "warn"
    intent_shadow_observation = (
        str(intent_aware_decision.get("mode") or "").strip().lower() == "shadow"
        and not bool(input_content_context.get("contains_secrets"))
        and not bool(output_context.get("contains_secret_like_value"))
        and not bool(output_context.get("contains_regulated_data"))
    )
    if (
        _transfer_decision_rank(mapped_control_decision) > _transfer_decision_rank(decision.decision)
        and not intent_shadow_observation
        and not approved_public_ai_transfer
        and not guardian_sensitive_upload_decision
        and not clean_file_upload_allow
    ):
        decision = TransferDecision(
            **{
                **decision.__dict__,
                "decision": mapped_control_decision,
                "reason_code": "control_engine_escalation",
                "explanation": "Central control engine escalated the transfer decision.",
                "recommended_action": "route_to_governance",
                "justification_required": mapped_control_decision == "require_justification",
                "severity": ("high" if mapped_control_decision in {"block", "require_justification"} else "med"),
            }
        )

    destination_context = {
        "domain": destination_domain,
        "application": destination_app_name,
        "surface": destination_surface,
        "trust_level": _destination_trust_level(
            decision=decision,
            destination_surface=destination_surface,
            destination_discovery_status=destination_discovery_status,
        ),
        "control_mode": "browser_extension",
    }
    intent_aware_evidence_summary = build_intent_aware_evidence_summary(
        intent_context=intent_context,
        input_content_context=input_content_context,
        output_context=output_context,
        action_alignment_result=action_alignment_result,
        intent_aware_decision=intent_aware_decision,
        action_type=transfer_action_type,
        destination_context=destination_context,
        policy_snapshot={
            "policy_id": str(intent_policy.get("policy_id") or "INTENT_AWARE_AI_ACTION_CONTROL"),
            "policy_version": policy_version,
            "mode": str(intent_policy.get("mode") or "block"),
        },
        control_mode="browser_extension",
    )

    event_payload = {
        "event_type": "data_transfer_check",
        "action_taken": decision.decision,
        "action_type": transfer_action_type,
        "source_domain": source_domain or None,
        "source_surface_type": source_surface,
        "source_classification_hint": source_classification,
        "destination_domain": destination_domain,
        "destination_surface_type": destination_surface,
        "destination_input_context": destination_input_context,
        "destination_app_name": destination_app_name,
        "copied_text_hash": source_hash,
        "copied_text_preview_redacted": str(copy_context.get("copied_text_preview_redacted") or ""),
        "file_meta": file_meta,
        "business_spreadsheet": business_spreadsheet,
        "business_visual": business_visual,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "reason_code": decision.reason_code,
        "explanation": decision.explanation,
        "recommended_action": decision.recommended_action,
        "correlation_id": correlation_id,
        "source_surface": "browser_extension",
        "severity": decision.severity,
        "risk_category": decision.risk_category,
        "data_classification": decision.data_classification,
        "user_id": actor_user_id,
        "browser": payload.get("browser"),
        "browser_type": payload.get("browser_type") or payload.get("browser"),
        "browser_profile": payload.get("browser_profile"),
        "browser_version": payload.get("browser_version"),
        "extension_name": payload.get("extension_name"),
        "extension_version": payload.get("extension_version"),
        "endpoint_id": payload.get("endpoint_id") or payload.get("machine_id"),
        "machine_id": payload.get("machine_id") or payload.get("endpoint_id"),
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
        "governance_state": governance_status.get("status"),
        "governance_reason": governance_status.get("reason"),
        "governance_enforcement_mode": governance_status.get("enforcement_mode"),
        "enforcement_routing": routing,
        "routing_fallback_audit_id": routing_fallback_audit_id,
        "routing_fallback_evidence_id": routing_fallback_evidence_id,
        "input_signal_types": [
            "data_transfer",
            f"source_{source_classification}",
            f"destination_{destination_surface}",
            decision.reason_code,
            "intent_aware_ai_action_control",
            f"intent_category:{intent_context.get('intent_category')}",
            f"input_sensitivity:{input_content_context.get('sensitivity_level')}",
            f"output_sensitivity:{output_context.get('output_sensitivity')}",
            f"action_alignment:{action_alignment_result.get('alignment')}",
            f"finding_type:{intent_aware_decision.get('finding_type')}",
            *detection_signal_types(detection_result),
        ],
        "contains_sensitive": contains_sensitive,
        "sensitive_upload_detected": sensitive_upload_detected,
        "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
        "sensitive_entities": list(detection_result.get("entities") or []),
        "sensitive_detection": detection_result,
        "guardian_policy_id": str((decision.policy or {}).get("policy_id") or ""),
        "guardian_policy_version": str((decision.policy or {}).get("policy_version") or ""),
        "guardian_framework_mapping": dict((decision.policy or {}).get("framework_mapping") or {}),
        "scoped_policy": scoped_policy.to_dict(),
        "triggered_controls": list(control_decision.triggered_controls),
        "evaluated_controls": [item.to_dict() for item in control_decision.evaluated_controls],
        "dominant_control": control_decision.dominant_control,
        "control_decision_reasoning": control_decision.reasoning,
        "control_decision_total_risk": control_decision.total_risk_score,
        "risk_tags": list(control_decision.risk_tags),
    }
    inferred_provider = infer_from_signal(
        {
            "domain": destination_domain,
            "tool_name": destination_app_name,
        }
    )
    if inferred_provider.get("provider"):
        event_payload["provider"] = inferred_provider["provider"]
        event_payload["model_provider"] = inferred_provider["provider"]
    if inferred_provider.get("tool_name"):
        event_payload["tool_name"] = inferred_provider["tool_name"]
    if inferred_provider.get("tool_category"):
        event_payload["tool_category"] = inferred_provider["tool_category"]

    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=decision.destination_ai_system_id,
        signal_type="runtime_control.data_transfer_check",
        severity=decision.severity,
        payload=event_payload,
    )
    db.add(signal)
    db.flush()

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="runtime_control.data_transfer_check",
        resource_type="monitoring_signal",
        resource_id=signal.id,
        payload={
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "source_domain": source_domain,
            "destination_domain": destination_domain,
            "destination_surface_type": destination_surface,
            "destination_input_context": destination_input_context,
            "policy_version": policy_version,
            "platform_mode": platform_mode,
            "enforcement_routing": routing,
            "routing_fallback_audit_id": routing_fallback_audit_id,
            "routing_fallback_evidence_id": routing_fallback_evidence_id,
            "contains_sensitive": contains_sensitive,
            "sensitive_upload_detected": sensitive_upload_detected,
            "business_spreadsheet": business_spreadsheet,
            "business_visual": business_visual,
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
            "guardian_policy_id": str((decision.policy or {}).get("policy_id") or ""),
            "guardian_policy_version": str((decision.policy or {}).get("policy_version") or ""),
            "scoped_policy": scoped_policy.to_dict(),
            "triggered_controls": list(control_decision.triggered_controls),
            "dominant_control": control_decision.dominant_control,
            "control_decision_reasoning": control_decision.reasoning,
            "control_decision_total_risk": control_decision.total_risk_score,
            "risk_tags": list(control_decision.risk_tags),
            "destination_context": destination_context,
            "intent_aware_evidence_summary": intent_aware_evidence_summary,
        },
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="data_transfer_check",
        signal_type="runtime_control.data_transfer_check",
        label=f"Data transfer check {decision.decision} for {destination_domain}",
        payload={
            "monitoring_signal_id": signal.id,
            "decision": decision.decision,
            "reason_code": decision.reason_code,
            "source_domain": source_domain,
            "destination_domain": destination_domain,
            "source_classification_hint": source_classification,
            "policy_version": policy_version,
            "platform_mode": platform_mode,
            "correlation_id": correlation_id,
            "enforcement_routing": routing,
            "routing_fallback_audit_id": routing_fallback_audit_id,
            "routing_fallback_evidence_id": routing_fallback_evidence_id,
            "contains_sensitive": contains_sensitive,
            "sensitive_upload_detected": sensitive_upload_detected,
            "business_spreadsheet": business_spreadsheet,
            "business_visual": business_visual,
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
            "guardian_policy_id": str((decision.policy or {}).get("policy_id") or ""),
            "guardian_policy_version": str((decision.policy or {}).get("policy_version") or ""),
            "guardian_framework_mapping": dict((decision.policy or {}).get("framework_mapping") or {}),
            "scoped_policy": scoped_policy.to_dict(),
            "triggered_controls": list(control_decision.triggered_controls),
            "dominant_control": control_decision.dominant_control,
            "control_decision_reasoning": control_decision.reasoning,
            "control_decision_total_risk": control_decision.total_risk_score,
            "risk_tags": list(control_decision.risk_tags),
            "destination_context": destination_context,
            "intent_aware_evidence_summary": intent_aware_evidence_summary,
        },
        correlation_id=correlation_id,
    )

    finding = None
    if decision.finding_type is not None or decision.decision in {"warn", "block", "require_justification"}:
        related_controls = [
            str(item).strip()
            for item in ((decision.policy or {}).get("framework_mapping") or {}).get("control_ids", ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"])
            if str(item).strip()
        ]
        related_controls = list(
            dict.fromkeys(
                [
                    *related_controls,
                    *list(control_decision.triggered_controls or []),
                ]
            )
        )
        finding = generate_data_transfer_finding(
            db,
            tenant_id=tenant_id,
            source_surface="browser",
            ai_tool=destination_domain,
            ai_system_id=decision.destination_ai_system_id,
            user_id=actor_user_id,
            policy_version_id=policy_version,
            finding_type=decision.finding_type or "sensitive_data_external_transfer_attempt",
            severity=decision.severity,
            risk_category=decision.risk_category,
            source_classification_hint=source_classification,
            destination_surface_type=destination_surface,
            destination_domain=destination_domain,
            decision=decision.decision,
            evidence_node_ids=[evidence.id],
            related_control_ids=related_controls,
            recommended_action=decision.recommended_action,
        )
        try:
            from app.services.remediation import propose_remediation_from_finding

            occurrence_count = int(finding.occurrence_count or 1)
            repeat_threshold = max(1, int(settings.runtime_intelligence_repeat_threshold or 3))
            trigger_bucket = 1 + ((occurrence_count - 1) // repeat_threshold)
            propose_remediation_from_finding(
                db,
                finding=finding,
                context={
                    "finding_id": finding.finding_id,
                    "finding_type": finding.finding_type,
                    "reason_code": decision.reason_code,
                    "occurrence_count": occurrence_count,
                    "related_control_ids": related_controls,
                    "evidence_node_ids": [evidence.id],
                    "contains_sensitive": contains_sensitive,
                    "file_meta": file_meta,
                    "domain": source_domain or destination_domain,
                    "target_type": "source",
                    "target_id": source_domain or destination_domain,
                    "source_domain": source_domain,
                    "destination_domain": destination_domain,
                    "source_trigger_id": f"{finding.finding_id}:repeat_bucket:{trigger_bucket}",
                },
            )
        except Exception as exc:  # pragma: no cover - remediation must never block enforcement
            log_structured(
                "data_transfer_remediation_proposal_failed",
                module="runtime_control_data_transfer_service",
                tenant_id=tenant_id,
                finding_id=finding.finding_id,
                reason_code=decision.reason_code,
                error=str(exc),
            )

    runtime_event_id = _record_runtime_for_data_transfer(
        db,
        tenant_id=tenant_id,
        ai_system_id=decision.destination_ai_system_id,
        monitoring_signal_id=signal.id,
        evidence_node_id=evidence.id,
        payload=event_payload | {"event_type": "data_transfer_check"},
    )
    if finding is not None:
        enrich_pilot_finding_context(
            db,
            finding=finding,
            user_email=actor_user_email,
            browser_type=str(payload.get("browser_type") or payload.get("browser") or "").strip() or None,
            application=destination_app_name or destination_domain,
            decision=decision.decision,
            policy_id=str(policy_version or "").strip() or None,
            related_runtime_event_id=runtime_event_id,
            machine_id=str(payload.get("machine_id") or payload.get("endpoint_id") or "").strip() or None,
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
                "event_type": "data_transfer_check",
                "action_type": policy_action_type,
                "source_surface": "browser",
                "domain": destination_domain,
                "ai_app": destination_app_name or destination_domain,
                "ai_model": payload.get("ai_model"),
                "data_classification": source_classification,
                "sensitivity_score": float(detection_result.get("confidence_score") or 0.0),
                "policy_triggered": decision.reason_code,
                "enforcement_action": decision.decision,
                "risk_score": 0.9 if decision.decision == "block" else (0.6 if decision.decision in {"warn", "require_justification"} else 0.2),
                "correlation_id": correlation_id,
                "runtime_event_id": runtime_event_id,
                "monitoring_signal_id": signal.id,
                "audit_log_id": audit.id,
                "evidence_node_id": evidence.id,
                "finding_id": finding.finding_id if finding else None,
                "prompt_preview_redacted": str(copy_context.get("copied_text_preview_redacted") or ""),
                "prompt_storage_mode": payload.get("prompt_storage_mode"),
                "sensitive_detection": detection_result,
                "browser": payload.get("browser"),
                "browser_profile": payload.get("browser_profile"),
                "browser_version": payload.get("browser_version"),
                "extension_name": payload.get("extension_name"),
                "extension_version": payload.get("extension_version"),
                "endpoint_id": payload.get("endpoint_id"),
                "os_type": payload.get("os_type"),
                "os_version": payload.get("os_version"),
                "device_type": payload.get("device_type"),
                "hostname": payload.get("hostname"),
                "ip_address": payload.get("ip_address"),
                "location": payload.get("location"),
                "metadata": {
                    "source_domain": source_domain,
                    "destination_domain": destination_domain,
                    "destination_surface_type": destination_surface,
                    "destination_input_context": destination_input_context,
                    "reason_code": decision.reason_code,
                    "recommended_action": decision.recommended_action,
                    "justification_required": decision.justification_required,
                    "scoped_policy": scoped_policy.to_dict(),
                    "triggered_controls": list(control_decision.triggered_controls),
                    "dominant_control": control_decision.dominant_control,
                    "control_decision_total_risk": control_decision.total_risk_score,
                    "risk_tags": list(control_decision.risk_tags),
                },
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking audit enrichment
        log_structured(
            "activity_audit_record_failed",
            module="runtime_control_data_transfer_service",
            tenant_id=tenant_id,
            event_type="data_transfer_check",
            correlation_id=correlation_id,
            error=str(exc),
        )

    decision_spine = _build_transfer_decision_spine(
        tenant_id=tenant_id,
        action_id=runtime_event_id,
        timestamp=str(payload.get("timestamp") or _now_iso()),
        event_type="data_transfer_check",
        decision=decision.decision,
        reason_code=decision.reason_code,
        policy_version=policy_version,
        destination_domain=destination_domain,
        destination_surface=destination_surface,
        destination_app_name=destination_app_name,
        destination_ai_system_id=decision.destination_ai_system_id,
        actor_user_id=actor_user_id,
        actor_user_email=actor_user_email,
        evidence_node_id=evidence.id,
        correlation_id=correlation_id,
        payload=payload,
        source_classification=source_classification,
        detection_result=detection_result,
        file_meta=file_meta,
        intent_aware_decision=intent_aware_decision,
    )

    return {
        "decision": decision.decision,
        "reason_code": decision.reason_code,
        "explanation": decision.explanation,
        "recommended_action": decision.recommended_action,
        "justification_required": decision.justification_required,
        "audit_log_id": audit.id,
        "evidence_node_id": evidence.id,
        "finding_id": finding.finding_id if finding else None,
        "runtime_event_id": runtime_event_id,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "destination_ai_system_id": decision.destination_ai_system_id,
        **decision_spine,
    }


def submit_data_transfer_justification_and_record(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    correlation_id = str(payload.get("correlation_id") or "").strip() or None
    copy_context = dict(payload.get("copy_context") or {})
    paste_context = dict(payload.get("paste_context") or {})
    prior_decision = dict(payload.get("policy_decision") or {})
    justification = str(payload.get("justification") or "").strip()
    submitter_name = str(payload.get("submitter_name") or payload.get("actor_name") or "").strip() or None
    submitter_email = str(payload.get("submitter_email") or payload.get("user_email") or "").strip() or None
    submitter_role = str(payload.get("submitter_role") or payload.get("actor_role") or payload.get("role") or "").strip() or None
    submitter_department = (
        str(payload.get("submitter_department") or payload.get("actor_department") or payload.get("department") or "").strip()
        or None
    )
    actor_role = submitter_role
    actor_department = submitter_department

    destination_domain = _normalize_domain(
        paste_context.get("destination_domain") or paste_context.get("destination_url")
    )
    if not destination_domain:
        raise ValueError("paste_context.destination_domain or destination_url is required")

    source_classification = _normalize_source_classification(copy_context.get("source_classification_hint"))
    destination_surface = _normalize_destination_surface(paste_context.get("destination_surface_type"))
    file_meta = [item for item in (payload.get("file_meta") or []) if isinstance(item, dict)]
    business_spreadsheet = _business_spreadsheet_context(file_meta)
    business_visual = _business_visual_context(file_meta)
    destination_ai_system_id, resolved_destination_name, _status = _resolve_destination_ai_system(
        db,
        tenant_id=tenant_id,
        destination_domain=destination_domain,
    )
    destination_app_name = (
        str(paste_context.get("destination_app_name") or "").strip()
        or str(resolved_destination_name or "").strip()
        or None
    )
    detection_result = detect_sensitive_data(
        text_inputs=[str(copy_context.get("copied_text_preview_redacted") or "")],
        file_meta=file_meta,
        source="browser",
        destination=destination_surface,
        ai_system_id=destination_ai_system_id,
        user_id=actor_user_id,
        correlation_id=correlation_id,
    )
    detected_classification = classify_data(
        detection_result=detection_result,
        classification_hint=source_classification,
        allow_unknown=True,
    )
    if detected_classification == "protected":
        source_classification = "protected"
    elif detected_classification == "public" and source_classification == "unknown":
        source_classification = "public"

    requested_decision = str(prior_decision.get("decision") or "").strip().lower()
    final_decision = "allow"
    reason_code = "justification_accepted"
    explanation = "Justification accepted; data transfer allowed."
    recommended_action = "monitor"
    finding_type: str | None = None

    if requested_decision == "block":
        final_decision = "block"
        reason_code = "blocked_by_policy"
        explanation = "Policy blocked this transfer and does not allow override."
        recommended_action = "route_to_governance"
        finding_type = "repeated_blocked_transfer_attempt"
    elif requested_decision == "require_justification":
        if len(justification) < 8:
            final_decision = "block"
            reason_code = "justification_missing_or_too_short"
            explanation = "A meaningful business justification is required."
            recommended_action = "route_to_governance"
            finding_type = "repeated_blocked_transfer_attempt"
        elif bool(business_spreadsheet.get("contains_secret")):
            final_decision = "block"
            reason_code = "spreadsheet_contains_secret_not_overridable"
            explanation = "Spreadsheets containing secrets or credentials cannot be approved by justification."
            recommended_action = "route_to_governance"
            finding_type = "sensitive_data_to_public_ai_attempt"
        elif bool(business_visual.get("contains_secret")):
            final_decision = "block"
            reason_code = "visual_contains_secret_not_overridable"
            explanation = "Screenshots/images/PDFs containing secrets or credentials cannot be approved by justification."
            recommended_action = "route_to_governance"
            finding_type = "sensitive_data_to_public_ai_attempt"
        elif (
            source_classification == "protected"
            and destination_surface == "ai_tool"
            and not destination_ai_system_id
            and not bool(business_spreadsheet.get("business_spreadsheet_upload"))
            and not bool(business_visual.get("business_visual_upload"))
        ):
            final_decision = "block"
            reason_code = "protected_to_unsanctioned_ai_not_overridable"
            explanation = "Protected data cannot be sent to unsanctioned AI destinations."
            recommended_action = "route_to_governance"
            finding_type = "sensitive_data_to_public_ai_attempt"
        else:
            final_decision = "allow"
            reason_code = "justification_accepted"
            explanation = "Justification recorded and transfer allowed."
            recommended_action = "monitor"
            finding_type = "repeated_justified_sensitive_transfer"
    else:
        final_decision = "allow"
        reason_code = "no_justification_required"
        explanation = "No justification was required."
        recommended_action = "monitor"

    severity = SEVERITY_BY_DECISION.get(final_decision, "med")
    policy_version = str(payload.get("policy_version") or prior_decision.get("policy_version") or "none")
    platform_mode = str(payload.get("platform_mode") or prior_decision.get("platform_mode") or "enforce")
    source_domain = _normalize_domain(copy_context.get("source_domain") or copy_context.get("source_url"))
    approved_context_envelope, context_integrity_status = _build_approved_context_envelope(
        actor_user_id=actor_user_id,
        source_domain=source_domain,
        destination_domain=destination_domain,
        destination_surface=destination_surface,
        source_classification=source_classification,
        requested_decision=requested_decision,
        final_decision=final_decision,
        reason_code=reason_code,
        justification=justification,
        policy_version=policy_version,
        platform_mode=platform_mode,
        file_meta=file_meta,
        business_spreadsheet=business_spreadsheet,
        business_visual=business_visual,
        detection_result=detection_result,
    )

    event_payload = {
        "event_type": "data_transfer_justification",
        "action_taken": final_decision,
        "source_domain": source_domain,
        "destination_domain": destination_domain,
        "destination_surface_type": destination_surface,
        "destination_app_name": destination_app_name,
        "source_classification_hint": source_classification,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "reason_code": reason_code,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "correlation_id": correlation_id,
        "source_surface": "browser_extension",
        "severity": severity,
        "risk_category": "data_transfer",
        "data_classification": "protected" if source_classification == "protected" else None,
        "justification_present": bool(justification),
        "justification_length": len(justification),
        "submitter_name": submitter_name,
        "submitter_email": submitter_email,
        "submitter_role": submitter_role,
        "submitter_department": submitter_department,
        "actor_role": actor_role,
        "actor_department": actor_department,
        "actor_role_missing": actor_role is None,
        "actor_department_missing": actor_department is None,
        "business_spreadsheet": business_spreadsheet,
        "business_visual": business_visual,
        "approved_context_envelope": approved_context_envelope,
        "context_integrity_status": context_integrity_status,
        "contains_sensitive": bool(detection_result.get("contains_sensitive")),
        "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
        "sensitive_entities": list(detection_result.get("entities") or []),
        "sensitive_detection": detection_result,
        "input_signal_types": ["data_transfer_justification", *detection_signal_types(detection_result)],
    }
    inferred_provider = infer_from_signal(
        {
            "domain": destination_domain,
            "tool_name": destination_app_name,
        }
    )
    if inferred_provider.get("provider"):
        event_payload["provider"] = inferred_provider["provider"]
        event_payload["model_provider"] = inferred_provider["provider"]
    if inferred_provider.get("tool_name"):
        event_payload["tool_name"] = inferred_provider["tool_name"]
    if inferred_provider.get("tool_category"):
        event_payload["tool_category"] = inferred_provider["tool_category"]

    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=destination_ai_system_id,
        signal_type="runtime_control.data_transfer_justification",
        severity=severity,
        payload=event_payload,
    )
    db.add(signal)
    db.flush()

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="runtime_control.data_transfer_justify",
        resource_type="monitoring_signal",
        resource_id=signal.id,
        payload={
            "decision": final_decision,
            "reason_code": reason_code,
            "destination_domain": destination_domain,
            "destination_surface_type": destination_surface,
            "justification_present": bool(justification),
            "submitter_name": submitter_name,
            "submitter_email": submitter_email,
            "submitter_role": submitter_role,
            "submitter_department": submitter_department,
            "actor_role": actor_role,
            "actor_department": actor_department,
            "actor_role_missing": actor_role is None,
            "actor_department_missing": actor_department is None,
            "business_spreadsheet": business_spreadsheet,
            "business_visual": business_visual,
            "approved_context_envelope": approved_context_envelope,
            "context_integrity_status": context_integrity_status,
            "policy_version": policy_version,
            "platform_mode": platform_mode,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
        },
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="data_transfer_justification",
        signal_type="runtime_control.data_transfer_justification",
        label=f"Data transfer justification {final_decision} for {destination_domain}",
        payload={
            "monitoring_signal_id": signal.id,
            "decision": final_decision,
            "reason_code": reason_code,
            "destination_domain": destination_domain,
            "destination_surface_type": destination_surface,
            "justification": justification[:1024],
            "submitter_name": submitter_name,
            "submitter_email": submitter_email,
            "submitter_role": submitter_role,
            "submitter_department": submitter_department,
            "actor_role": actor_role,
            "actor_department": actor_department,
            "actor_role_missing": actor_role is None,
            "actor_department_missing": actor_department is None,
            "business_spreadsheet": business_spreadsheet,
            "business_visual": business_visual,
            "approved_context_envelope": approved_context_envelope,
            "context_integrity_status": context_integrity_status,
            "correlation_id": correlation_id,
            "contains_sensitive": bool(detection_result.get("contains_sensitive")),
            "sensitive_confidence_score": float(detection_result.get("confidence_score") or 0.0),
            "sensitive_entities": list(detection_result.get("entities") or []),
        },
        correlation_id=correlation_id,
    )

    finding = None
    if finding_type:
        finding = generate_data_transfer_finding(
            db,
            tenant_id=tenant_id,
            source_surface="browser",
            ai_tool=destination_domain,
            ai_system_id=destination_ai_system_id,
            user_id=actor_user_id,
            policy_version_id=policy_version,
            finding_type=finding_type,
            severity=severity if final_decision != "allow" else "med",
            risk_category="data_transfer",
            source_classification_hint=source_classification,
            destination_surface_type=destination_surface,
            destination_domain=destination_domain,
            decision=final_decision,
            evidence_node_ids=[evidence.id],
            related_control_ids=["CTRL-DLP-001", "CTRL-TENANT-ISO-001"],
            recommended_action=recommended_action,
        )

    runtime_event_id = _record_runtime_for_data_transfer(
        db,
        tenant_id=tenant_id,
        ai_system_id=destination_ai_system_id,
        monitoring_signal_id=signal.id,
        evidence_node_id=evidence.id,
        payload=event_payload | {"event_type": "data_transfer_justification"},
    )

    try:
        record_activity_event(
            db,
            tenant_id=tenant_id,
            user_id=actor_user_id,
            payload={
                "timestamp": payload.get("timestamp") or _now_iso(),
                "event_type": "data_transfer_justification",
                "action_type": "copy_paste",
                "source_surface": "browser",
                "domain": destination_domain,
                "ai_app": destination_app_name or destination_domain,
                "ai_model": payload.get("ai_model"),
                "data_classification": source_classification,
                "sensitivity_score": float(detection_result.get("confidence_score") or 0.0),
                "policy_triggered": reason_code,
                "enforcement_action": final_decision,
                "risk_score": 0.9 if final_decision == "block" else 0.35,
                "correlation_id": correlation_id,
                "runtime_event_id": runtime_event_id,
                "monitoring_signal_id": signal.id,
                "audit_log_id": audit.id,
                "evidence_node_id": evidence.id,
                "finding_id": finding.finding_id if finding else None,
                "prompt_preview_redacted": str(copy_context.get("copied_text_preview_redacted") or ""),
                "prompt_storage_mode": payload.get("prompt_storage_mode"),
                "sensitive_detection": detection_result,
                "browser": payload.get("browser"),
                "browser_profile": payload.get("browser_profile"),
                "browser_version": payload.get("browser_version"),
                "extension_name": payload.get("extension_name"),
                "extension_version": payload.get("extension_version"),
                "endpoint_id": payload.get("endpoint_id"),
                "os_type": payload.get("os_type"),
                "os_version": payload.get("os_version"),
                "device_type": payload.get("device_type"),
                "hostname": payload.get("hostname"),
                "ip_address": payload.get("ip_address"),
                "location": payload.get("location"),
                "metadata": {
                    "reason_code": reason_code,
                    "justification_present": bool(justification),
                    "justification_length": len(justification),
                    "destination_surface_type": destination_surface,
                    "recommended_action": recommended_action,
                    "approved_context_envelope": approved_context_envelope,
                    "context_integrity_status": context_integrity_status,
                },
            },
        )
    except Exception as exc:  # pragma: no cover - non-blocking audit enrichment
        log_structured(
            "activity_audit_record_failed",
            module="runtime_control_data_transfer_service",
            tenant_id=tenant_id,
            event_type="data_transfer_justification",
            correlation_id=correlation_id,
            error=str(exc),
        )

    decision_spine = _build_transfer_decision_spine(
        tenant_id=tenant_id,
        action_id=runtime_event_id,
        timestamp=str(payload.get("timestamp") or _now_iso()),
        event_type="data_transfer_justification",
        decision=final_decision,
        reason_code=reason_code,
        policy_version=policy_version,
        destination_domain=destination_domain,
        destination_surface=destination_surface,
        destination_app_name=destination_app_name,
        destination_ai_system_id=destination_ai_system_id,
        actor_user_id=actor_user_id,
        actor_user_email=submitter_email,
        evidence_node_id=evidence.id,
        correlation_id=correlation_id,
        payload=payload,
        source_classification=source_classification,
        detection_result=detection_result,
        file_meta=file_meta,
    )

    return {
        "decision": final_decision,
        "reason_code": reason_code,
        "explanation": explanation,
        "recommended_action": recommended_action,
        "audit_log_id": audit.id,
        "evidence_node_id": evidence.id,
        "finding_id": finding.finding_id if finding else None,
        "runtime_event_id": runtime_event_id,
        "policy_version": policy_version,
        "platform_mode": platform_mode,
        "destination_ai_system_id": destination_ai_system_id,
        "destination_app_name": destination_app_name,
        **decision_spine,
    }
