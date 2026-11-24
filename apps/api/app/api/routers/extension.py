from __future__ import annotations

import logging
from datetime import datetime
from time import sleep
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.config import settings
from app.core.control_engine.canonical_action import CanonicalProjectionError
from app.core.observability import log_structured
from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.models.user import User
from app.db.models.monitoring import MonitoringSignal
from app.db.session import get_db
from app.services.browser_extension_service import (
    build_extension_policy_sync,
    create_extension_removal_authorization,
    evaluate_browser_interaction_and_record,
    log_extension_policy_sync_access,
    process_extension_status_report,
    process_browser_telemetry_event,
)


router = APIRouter(tags=["extension"])
error_logger = logging.getLogger("uvicorn.error")
SQLITE_LOCK_RETRY_ATTEMPTS = 8
SQLITE_LOCK_RETRY_BACKOFF_SECONDS = 0.1


def _is_sqlite_transient_write_error(exc: Exception) -> bool:
    message = str(exc).lower()
    return (
        "database is locked" in message
        or "database table is locked" in message
        or "unable to open database file" in message
        or "readonly database" in message
        or "disk i/o error" in message
        or "database or disk is full" in message
    )


def _set_sqlite_busy_timeout(db: Session, timeout_ms: int | None) -> int | None:
    if timeout_ms is None:
        return None
    bind = db.get_bind()
    if not bind or bind.dialect.name != "sqlite":
        return None
    current = db.execute(text("PRAGMA busy_timeout;")).scalar()
    db.execute(text(f"PRAGMA busy_timeout={max(1, int(timeout_ms))};"))
    return int(current or 0) or None


def _run_extension_write_with_sqlite_retry(
    db: Session,
    operation,
    *,
    busy_detail: str,
    max_attempts: int = SQLITE_LOCK_RETRY_ATTEMPTS,
    retry_backoff_seconds: float = SQLITE_LOCK_RETRY_BACKOFF_SECONDS,
    sqlite_busy_timeout_ms: int | None = None,
):
    normalized_attempts = max(1, int(max_attempts))
    timeout_to_restore: int | None = None
    if sqlite_busy_timeout_ms is not None:
        try:
            timeout_to_restore = _set_sqlite_busy_timeout(db, sqlite_busy_timeout_ms)
        except Exception:  # noqa: BLE001
            timeout_to_restore = None
    try:
        for attempt in range(1, normalized_attempts + 1):
            try:
                result = operation()
                if isinstance(result, dict) and str(result.get("persistence_mode") or "").lower() == "degraded_no_write":
                    db.rollback()
                    return result
                db.commit()
                return result
            except CanonicalProjectionError:
                db.rollback()
                raise
            except SQLAlchemyError as exc:
                db.rollback()
                if _is_sqlite_transient_write_error(exc) and attempt < normalized_attempts:
                    backoff_seconds = min(0.8, max(0.0, float(retry_backoff_seconds)) * attempt)
                    log_structured(
                        "extension_sqlite_retry",
                        level="warning",
                        attempt=attempt,
                        max_attempts=normalized_attempts,
                        backoff_seconds=backoff_seconds,
                    )
                    sleep(backoff_seconds)
                    continue
                if _is_sqlite_transient_write_error(exc):
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=busy_detail,
                        headers={"Retry-After": "2"},
                    ) from exc
                raise
    finally:
        if timeout_to_restore is not None:
            try:
                _set_sqlite_busy_timeout(db, timeout_to_restore)
            except Exception:  # noqa: BLE001
                pass

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=busy_detail,
    )


class ExtensionInteractionRulesResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_checks_enabled: bool
    output_checks_enabled: bool
    sensitive_patterns: list[str]
    blocked_keywords: list[str]
    high_risk_terms: list[str]
    hold_for_backend_on_ambiguous: bool
    backend_allow_confirmation_enabled: bool


class ExtensionProviderEnforcementHintResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: str
    provider_name: str
    provider_type: str
    trust_level: str
    default_risk_hint: str
    known_domains: list[str]
    sanctioned_domains: list[str]
    blocked_domains: list[str]
    suggested_decision: str
    browser_message: str
    surface_policy_mode: str


class ExtensionPolicySyncResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    platform_mode: str
    policy_version: str
    approved_domains: list[str]
    blocked_domains: list[str]
    warn_domains: list[str]
    critical_domains: list[str]
    unknown_domain_behavior: str
    provider_enforcement_hints: list[ExtensionProviderEnforcementHintResponse]
    interaction_rules: ExtensionInteractionRulesResponse
    browser_automation_control: dict[str, Any]
    intent_aware_action_control: dict[str, Any]


class BrowserTelemetryEventRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    correlation_id: str | None = None
    tenant_id: str | None = None
    browser: str = "chrome"
    browser_version: str | None = None
    browser_profile: str | None = None
    extension_name: str | None = None
    extension_version: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    ip_address: str | None = None
    location: str | None = None
    event_type: str
    domain: str | None = None
    url: str | None = None
    page_title: str | None = None
    timestamp: datetime | None = None
    policy_version: str | None = None
    platform_mode: str | None = None
    action_taken: str | None = None
    action_type: str | None = None
    action_risk: str | None = None
    decision_badge: str | None = None
    reason: str | None = None
    raw_prompt: str | None = None
    prompt_preview_redacted: str | None = None
    prompt_storage_mode: str | None = None
    input_signal_types: list[str] = Field(default_factory=list)
    file_meta: list[dict[str, Any]] = Field(default_factory=list)
    ai_system_id: str | None = None
    severity: str | None = None
    source_surface: str | None = None
    automation_suspected: bool | None = None
    automation_confidence: float | None = None
    automation_source: str | None = None
    suspected_tool: str | None = None
    automation_indicators: list[str] = Field(default_factory=list)
    scope_domain: str | None = None
    current_domain: str | None = None
    current_url: str | None = None
    meeting_surface: str | None = None
    notetaker_provider: str | None = None
    notetaker_label: str | None = None
    participant_visible: bool | None = None
    meeting_id: str | None = None
    meeting_title: str | None = None
    meeting_organizer_email: str | None = None
    meeting_signal_source: str | None = None
    calendar_invitee_domain: str | None = None
    oauth_app_id: str | None = None
    control_mode: str | None = None


class BrowserTelemetryIngestResponse(BaseModel):
    status: str
    monitoring_signal_id: str
    audit_log_id: str
    evidence_node_id: str
    finding_id: str | None = None
    policy_version: str
    platform_mode: str
    governance_recommendation: str | None = None
    runtime_event_id: str | None = None


class ExtensionStatusReportRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    correlation_id: str | None = None
    tenant_id: str | None = None
    browser: str = "chrome"
    browser_version: str | None = None
    browser_profile: str | None = None
    extension_id: str | None = None
    extension_name: str | None = None
    extension_version: str
    endpoint_id: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    ip_address: str | None = None
    location: str | None = None
    healthy: bool = True
    status: str | None = None
    status_trigger: str | None = None
    last_sync_at: datetime | None = None
    telemetry_queue_depth: int = 0
    policy_version: str | None = None
    platform_mode: str | None = None
    last_error: str | None = None
    active_domain: str | None = None
    active_url: str | None = None
    removal_authorization_id: str | None = None
    disable_authorization_id: str | None = None


class ExtensionStatusReportResponse(BaseModel):
    status: str
    monitoring_signal_id: str
    audit_log_id: str
    evidence_node_id: str
    policy_version: str
    platform_mode: str
    runtime_event_id: str | None = None
    finding_id: str | None = None


class ExtensionRemovalAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correlation_id: str | None = None
    tenant_id: str | None = None
    browser: str = "chrome"
    browser_profile: str | None = None
    extension_id: str | None = None
    extension_name: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    action: str
    reason: str
    expires_minutes: int = Field(default=30, ge=1, le=1440)


class ExtensionRemovalAuthorizationResponse(BaseModel):
    status: str
    authorization_id: str
    audit_log_id: str
    evidence_node_id: str
    action: str
    expires_at: str
    target: dict[str, str]


class ExtensionHealthInstanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    extension_id: str | None = None
    extension_name: str | None = None
    extension_version: str | None = None
    browser: str | None = None
    browser_profile: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    healthy: bool | None = None
    status: str | None = None
    last_heartbeat_at: str | None = None
    last_sync_at: str | None = None
    telemetry_queue_depth: int | None = None
    policy_version: str | None = None
    platform_mode: str | None = None
    last_error: str | None = None


class ExtensionTamperEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    classification: str
    action: str | None = None
    control_state: str | None = None
    extension_id: str | None = None
    browser: str | None = None
    browser_profile: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    severity: str | None = None
    observed_at: str | None = None


class ExtensionHealthSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    status: str
    trusted_extension_id: str | None = None
    trusted_source: str
    latest_heartbeat_at: str | None = None
    latest_status: dict[str, Any] | None = None
    duplicate_extension_ids: list[str]
    instances: list[ExtensionHealthInstanceResponse]
    tamper_events: list[ExtensionTamperEventResponse]
    limitations: list[str]


class ExtensionGovernanceControlResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    status: str
    description: str
    evidence: list[str]
    required_owner: str


class ExtensionMdmPolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    browser: str
    status: str
    enforcement_type: str
    required_policy: str
    purpose: str
    trusted_extension_id: str | None = None
    policy_payload: dict[str, Any]
    limitations: list[str]


class ExtensionRemovalGovernanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    status: str
    admin_removal_required: bool
    hard_prevention_requires_mdm: bool
    trusted_extension_id: str | None = None
    trusted_source: str
    last_heartbeat_at: str | None = None
    duplicate_extension_ids: list[str]
    recent_tamper_events: list[ExtensionTamperEventResponse]
    controls: list[ExtensionGovernanceControlResponse]
    mdm_policies: list[ExtensionMdmPolicyResponse]
    admin_workflow: list[str]
    audit_events: list[str]
    limitations: list[str]


class BrowserInteractionEvalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    correlation_id: str | None = None
    tenant_id: str | None = None
    prompt_hash: str | None = None
    raw_prompt: str | None = None
    prompt_preview_redacted: str
    domain: str | None = None
    url: str | None = None
    page_title: str | None = None
    policy_version: str | None = None
    platform_mode: str | None = None
    input_signal_types: list[str] = Field(default_factory=list)
    file_meta: list[dict[str, Any]] = Field(default_factory=list)
    ai_system_id: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    machine_id: str | None = None
    browser_type: str | None = None
    application: str | None = None
    timeout_ms: int | None = None
    browser: str | None = None
    browser_profile: str | None = None
    browser_version: str | None = None
    extension_name: str | None = None
    extension_version: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    ip_address: str | None = None
    location: str | None = None
    prompt_storage_mode: str | None = None


class DesktopInteractionEvalRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    correlation_id: str | None = None
    tenant_id: str | None = None
    prompt_hash: str | None = None
    raw_prompt: str | None = None
    prompt_preview_redacted: str
    application: str = "Claude Desktop"
    desktop_app: str | None = None
    domain: str | None = None
    url: str | None = None
    active_window_title: str | None = None
    capture_method: str | None = None
    guard_version: str | None = None
    platform: str | None = None
    input_signal_types: list[str] = Field(default_factory=list)
    file_meta: list[dict[str, Any]] = Field(default_factory=list)
    ai_system_id: str | None = None
    user_id: str | None = None
    user_email: str | None = None
    machine_id: str | None = None
    endpoint_id: str | None = None
    hostname: str | None = None
    device_type: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    ip_address: str | None = None
    location: str | None = None
    policy_version: str | None = None
    platform_mode: str | None = None
    prompt_storage_mode: str | None = None
    timeout_ms: int | None = None


class BrowserInteractionEvalResponse(BaseModel):
    decision: str
    tier: str
    reason_codes: list[str]
    policy_version: str
    platform_mode: str
    correlation_id: str | None = None
    input_signal_types: list[str]
    audit_log_id: str
    evidence_node_id: str
    finding_id: str | None = None
    runtime_event_id: str | None = None


def _as_iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    text_value = str(value).strip()
    return text_value or None


def _health_payload_text(payload: dict[str, Any], key: str) -> str | None:
    value = payload.get(key)
    if value is None:
        return None
    text_value = str(value).strip()
    return text_value or None


def _extension_instance_key(payload: dict[str, Any]) -> tuple[str, str, str, str, str]:
    return (
        _health_payload_text(payload, "browser") or "unknown_browser",
        _health_payload_text(payload, "browser_profile") or "default",
        _health_payload_text(payload, "endpoint_id") or "unknown_endpoint",
        _health_payload_text(payload, "hostname") or "unknown_host",
        _health_payload_text(payload, "extension_id") or "unknown_extension",
    )


def _extension_health_instance(
    signal: MonitoringSignal,
    payload: dict[str, Any],
) -> ExtensionHealthInstanceResponse:
    return ExtensionHealthInstanceResponse(
        extension_id=_health_payload_text(payload, "extension_id"),
        extension_name=_health_payload_text(payload, "extension_name"),
        extension_version=_health_payload_text(payload, "extension_version"),
        browser=_health_payload_text(payload, "browser"),
        browser_profile=_health_payload_text(payload, "browser_profile"),
        endpoint_id=_health_payload_text(payload, "endpoint_id"),
        hostname=_health_payload_text(payload, "hostname"),
        healthy=bool(payload.get("healthy")) if payload.get("healthy") is not None else None,
        status=_health_payload_text(payload, "status"),
        last_heartbeat_at=_as_iso(signal.created_at),
        last_sync_at=_as_iso(payload.get("last_sync_at")),
        telemetry_queue_depth=int(payload.get("telemetry_queue_depth") or 0),
        policy_version=_health_payload_text(payload, "policy_version"),
        platform_mode=_health_payload_text(payload, "platform_mode"),
        last_error=_health_payload_text(payload, "last_error"),
    )


def _extension_tamper_event(
    signal: MonitoringSignal,
    payload: dict[str, Any],
    removal_control: dict[str, Any],
) -> ExtensionTamperEventResponse:
    target = removal_control.get("target") if isinstance(removal_control.get("target"), dict) else {}
    return ExtensionTamperEventResponse(
        classification=str(removal_control.get("classification") or "unknown"),
        action=_health_payload_text(removal_control, "action"),
        control_state=_health_payload_text(removal_control, "control_state"),
        extension_id=_health_payload_text(payload, "extension_id") or _health_payload_text(target, "extension_id"),
        browser=_health_payload_text(payload, "browser") or _health_payload_text(target, "browser"),
        browser_profile=_health_payload_text(payload, "browser_profile") or _health_payload_text(target, "browser_profile"),
        endpoint_id=_health_payload_text(payload, "endpoint_id") or _health_payload_text(target, "endpoint_id"),
        hostname=_health_payload_text(payload, "hostname") or _health_payload_text(target, "hostname"),
        severity=str(signal.severity or ""),
        observed_at=_as_iso(signal.created_at),
    )


def _chrome_extension_settings_policy(trusted_extension_id: str | None) -> dict[str, Any]:
    if not trusted_extension_id:
        return {
            "*": {"installation_mode": "blocked"},
            "__TRUSTED_EXTENSION_ID__": {
                "installation_mode": "force_installed",
                "update_url": "https://clients2.google.com/service/update2/crx",
            },
        }
    return {
        "*": {"installation_mode": "blocked"},
        trusted_extension_id: {
            "installation_mode": "force_installed",
            "update_url": "https://clients2.google.com/service/update2/crx",
        },
    }


def _extension_removal_governance_from_health(
    *,
    ctx: TenantContext,
    health: ExtensionHealthSummaryResponse,
) -> ExtensionRemovalGovernanceResponse:
    extension_id_status = "current" if health.trusted_extension_id else "unknown"
    heartbeat_status = "current" if health.latest_heartbeat_at else "unknown"
    duplicate_status = "current" if not health.duplicate_extension_ids else "degraded"
    tamper_status = "current" if not health.tamper_events else "attention_required"
    mdm_status = "configuration_required"
    if health.trusted_extension_id:
        mdm_status = "ready_to_export"

    controls = [
        ExtensionGovernanceControlResponse(
            id="trusted_extension_identity",
            label="Trusted extension identity",
            status=extension_id_status,
            description="Only the trusted extension ID should be treated as the managed browser control point.",
            evidence=[health.trusted_source, health.trusted_extension_id or "trusted_extension_id_unavailable"],
            required_owner="security_admin",
        ),
        ExtensionGovernanceControlResponse(
            id="heartbeat_and_tamper_detection",
            label="Heartbeat and tamper detection",
            status=heartbeat_status if tamper_status == "current" else tamper_status,
            description="Missed, disabled, removed, duplicate or unauthorized extension signals remain visible for investigation.",
            evidence=[
                f"latest_heartbeat_at:{health.latest_heartbeat_at or 'unavailable'}",
                f"tamper_events:{len(health.tamper_events)}",
            ],
            required_owner="security_admin",
        ),
        ExtensionGovernanceControlResponse(
            id="admin_removal_authorization",
            label="Admin-approved disable/removal",
            status="available",
            description="Disable or removal is accepted only when a tenant admin creates a short-lived authorization for the target extension/device.",
            evidence=["POST /extension/admin/removal-authorizations", "extension.removal_authorization.create"],
            required_owner="tenant_admin",
        ),
        ExtensionGovernanceControlResponse(
            id="duplicate_extension_cleanup",
            label="Duplicate extension cleanup",
            status=duplicate_status,
            description="Duplicate extension IDs confuse evidence and should be removed through the managed browser rollout.",
            evidence=health.duplicate_extension_ids or ["no_duplicate_extension_id_observed"],
            required_owner="endpoint_admin",
        ),
        ExtensionGovernanceControlResponse(
            id="mdm_hard_prevention",
            label="MDM / managed browser hard prevention",
            status=mdm_status,
            description="The extension cannot prevent its own removal. Hard prevention requires Chrome enterprise policy or Apple MDM/profile enforcement.",
            evidence=["chrome_extension_settings_policy", "safari_mdm_profile_required"],
            required_owner="endpoint_admin",
        ),
    ]

    mdm_policies = [
        ExtensionMdmPolicyResponse(
            browser="chrome",
            status=mdm_status,
            enforcement_type="managed_browser_policy",
            required_policy="ExtensionSettings / force_installed",
            purpose="Force-install the trusted extension and block user-controlled replacement/removal through Chrome enterprise policy.",
            trusted_extension_id=health.trusted_extension_id,
            policy_payload=_chrome_extension_settings_policy(health.trusted_extension_id),
            limitations=[
                "requires_chrome_enterprise_policy_delivery",
                "local_unmanaged_chrome_can_still_remove_developer_extension",
            ],
        ),
        ExtensionMdmPolicyResponse(
            browser="safari",
            status="mdm_required",
            enforcement_type="apple_device_management",
            required_policy="Safari extension management profile",
            purpose="Manage Safari extension installation and allowed state through Apple device management before claiming hard prevention.",
            trusted_extension_id=None,
            policy_payload={
                "managed_by": "apple_mdm_or_configuration_profile",
                "extension_identifier": "__SAFARI_EXTENSION_IDENTIFIER__",
                "state": "managed_enabled",
            },
            limitations=[
                "safari_extension_self_prevention_not_possible",
                "requires_customer_mdm_receipt_before_verified_coverage",
            ],
        ),
    ]

    return ExtensionRemovalGovernanceResponse(
        tenant_id=ctx.tenant.id,
        status="attention_required" if health.status in {"tamper_suspected", "degraded"} else health.status,
        admin_removal_required=True,
        hard_prevention_requires_mdm=True,
        trusted_extension_id=health.trusted_extension_id,
        trusted_source=health.trusted_source,
        last_heartbeat_at=health.latest_heartbeat_at,
        duplicate_extension_ids=health.duplicate_extension_ids,
        recent_tamper_events=health.tamper_events,
        controls=controls,
        mdm_policies=mdm_policies,
        admin_workflow=[
            "Confirm the trusted extension ID and endpoint/browser scope.",
            "Export managed-browser or MDM policy for Chrome/Safari.",
            "Deploy through the customer's MDM or browser-management system.",
            "Require tenant-admin removal authorization before approved disable/removal.",
            "Investigate any disable/removal heartbeat without a matching active authorization.",
        ],
        audit_events=[
            "extension.removal_authorization.create",
            "browser.extension_health_status",
            "extension.admin.removal_authorization",
            "unauthorized_disable_or_removal",
            "admin_authorized_disable_or_removal",
        ],
        limitations=[
            "extension_cannot_prevent_its_own_uninstall",
            "hard_prevention_requires_managed_browser_policy_or_mdm",
            "mdm_policy_export_does_not_prove_deployment_without_customer_mdm_receipt",
        ],
    )


@router.get("/extension/policy-sync", response_model=ExtensionPolicySyncResponse)
def extension_policy_sync(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    payload = build_extension_policy_sync(db, tenant_id=ctx.tenant.id)
    try:
        log_extension_policy_sync_access(
            db,
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            policy_sync=payload,
        )
        db.commit()
    except Exception as exc:  # pragma: no cover - defensive fallback
        db.rollback()
        log_structured(
            "extension_policy_sync_audit_write_failed",
            level="warning",
            tenant_id=ctx.tenant.id,
            actor_user_id=current_user.id,
            error=str(exc),
        )
    return ExtensionPolicySyncResponse(
        tenant_id=payload.tenant_id,
        platform_mode=payload.platform_mode,
        policy_version=payload.policy_version,
        approved_domains=payload.approved_domains,
        blocked_domains=payload.blocked_domains,
        warn_domains=payload.warn_domains,
        critical_domains=payload.critical_domains,
        unknown_domain_behavior=payload.unknown_domain_behavior,
        provider_enforcement_hints=[
            ExtensionProviderEnforcementHintResponse.model_validate(item)
            for item in (payload.provider_enforcement_hints or [])
        ],
        interaction_rules=ExtensionInteractionRulesResponse.model_validate(payload.interaction_rules),
        browser_automation_control=dict(payload.browser_automation_control or {}),
        intent_aware_action_control=dict(payload.intent_aware_action_control or {}),
    )


def _extension_health_summary_for_tenant(db: Session, *, tenant_id: str) -> ExtensionHealthSummaryResponse:
    rows = db.scalars(
        select(MonitoringSignal)
        .where(
            MonitoringSignal.tenant_id == tenant_id,
            MonitoringSignal.signal_type == "browser.extension_health_status",
        )
        .order_by(MonitoringSignal.created_at.desc(), MonitoringSignal.id.desc())
        .limit(100)
    ).all()
    rows = sorted(
        rows,
        key=lambda row: (
            _as_iso((row.payload if isinstance(row.payload, dict) else {}).get("last_sync_at")) or "",
            _as_iso(row.created_at) or "",
            str(row.id or ""),
        ),
        reverse=True,
    )

    if not rows:
        return ExtensionHealthSummaryResponse(
            tenant_id=tenant_id,
            status="unknown",
            trusted_extension_id=None,
            trusted_source="unknown",
            latest_heartbeat_at=None,
            latest_status=None,
            duplicate_extension_ids=[],
            instances=[],
            tamper_events=[],
            limitations=[
                "no_extension_health_signal_observed",
                "hard_removal_prevention_requires_managed_browser_policy_or_mdm",
            ],
        )

    latest = rows[0]
    latest_payload = latest.payload if isinstance(latest.payload, dict) else {}

    latest_by_instance: dict[tuple[str, str, str, str, str], tuple[MonitoringSignal, dict[str, Any]]] = {}
    observed_extension_ids: set[str] = set()
    tamper_events: list[ExtensionTamperEventResponse] = []
    trusted_extension_id: str | None = None
    trusted_source = "unknown"
    unauthorized_tamper_observed = False
    unauthorized_tamper_extension_id: str | None = None

    for row in rows:
        payload = row.payload if isinstance(row.payload, dict) else {}
        extension_id = _health_payload_text(payload, "extension_id")
        if extension_id:
            observed_extension_ids.add(extension_id)
        if trusted_extension_id is None and bool(payload.get("healthy")) and extension_id:
            trusted_extension_id = extension_id
            trusted_source = "latest_healthy_status"
        key = _extension_instance_key(payload)
        latest_by_instance.setdefault(key, (row, payload))
        removal_control = payload.get("extension_removal_control")
        if isinstance(removal_control, dict) and removal_control.get("classification"):
            unauthorized_tamper_observed = (
                unauthorized_tamper_observed
                or str(removal_control.get("classification") or "") == "unauthorized_disable_or_removal"
            )
            if str(removal_control.get("classification") or "") == "unauthorized_disable_or_removal":
                unauthorized_tamper_extension_id = unauthorized_tamper_extension_id or extension_id
            tamper_events.append(_extension_tamper_event(row, payload, removal_control))

    if unauthorized_tamper_extension_id:
        trusted_extension_id = unauthorized_tamper_extension_id
        trusted_source = "tamper_event_extension_id"

    if trusted_extension_id is None:
        trusted_extension_id = _health_payload_text(latest_payload, "extension_id")
        trusted_source = "latest_status" if trusted_extension_id else "unknown"

    duplicate_extension_ids = sorted(observed_extension_ids)
    if len(duplicate_extension_ids) <= 1:
        duplicate_extension_ids = []

    latest_removal_control = latest_payload.get("extension_removal_control")
    latest_removal_classification = (
        str(latest_removal_control.get("classification") or "")
        if isinstance(latest_removal_control, dict)
        else ""
    )
    if latest_removal_classification == "unauthorized_disable_or_removal" or unauthorized_tamper_observed:
        status_value = "tamper_suspected"
    elif duplicate_extension_ids:
        status_value = "degraded"
    elif bool(latest_payload.get("healthy")):
        status_value = "healthy"
    else:
        status_value = "degraded"

    return ExtensionHealthSummaryResponse(
        tenant_id=tenant_id,
        status=status_value,
        trusted_extension_id=trusted_extension_id,
        trusted_source=trusted_source,
        latest_heartbeat_at=_as_iso(latest.created_at),
        latest_status=latest_payload,
        duplicate_extension_ids=duplicate_extension_ids,
        instances=[
            _extension_health_instance(row, payload)
            for row, payload in latest_by_instance.values()
        ],
        tamper_events=tamper_events[:10],
        limitations=[
            "hard_removal_prevention_requires_managed_browser_policy_or_mdm",
            "healthy_heartbeat_does_not_prove_prompt_capture_without_prompt_event_evidence",
        ],
    )


@router.post("/telemetry/browser", response_model=BrowserTelemetryIngestResponse)
def ingest_browser_telemetry(
    request: Request,
    payload: BrowserTelemetryEventRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        result = _run_extension_write_with_sqlite_retry(
            db,
            lambda: process_browser_telemetry_event(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=data,
            ),
            busy_detail="Database busy while ingesting browser telemetry. Retry in a few seconds.",
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except Exception as exc:
        diagnostic = {
            "level": "error",
            "tenant_id": ctx.tenant.id,
            "event_type": str(data.get("event_type") or ""),
            "error_type": type(exc).__name__,
            "payload_keys": sorted(str(key) for key in data),
            "payload_value_types": {str(key): type(value).__name__ for key, value in sorted(data.items())},
        }
        log_structured("browser_telemetry_ingest_failed", **diagnostic)
        error_logger.error("browser_telemetry_ingest_failed %s", diagnostic)
        raise
    return BrowserTelemetryIngestResponse.model_validate(result)


@router.post("/extension/admin/removal-authorizations", response_model=ExtensionRemovalAuthorizationResponse)
def extension_removal_authorization(
    request: Request,
    payload: ExtensionRemovalAuthorizationRequest,
    ctx: TenantContext = Depends(require_role(min_role="admin")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        result = _run_extension_write_with_sqlite_retry(
            db,
            lambda: create_extension_removal_authorization(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=data,
            ),
            busy_detail="Database busy while creating extension removal authorization. Retry in a few seconds.",
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ExtensionRemovalAuthorizationResponse.model_validate(result)


@router.get("/extension/health", response_model=ExtensionHealthSummaryResponse)
def extension_health_summary(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    return _extension_health_summary_for_tenant(db, tenant_id=ctx.tenant.id)


@router.get("/extension/governance/removal", response_model=ExtensionRemovalGovernanceResponse)
def extension_removal_governance(
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    db: Session = Depends(get_db),
):
    health = _extension_health_summary_for_tenant(db, tenant_id=ctx.tenant.id)
    return _extension_removal_governance_from_health(ctx=ctx, health=health)


@router.post("/extension/status", response_model=ExtensionStatusReportResponse)
def extension_status_report(
    request: Request,
    payload: ExtensionStatusReportRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        result = _run_extension_write_with_sqlite_retry(
            db,
            lambda: process_extension_status_report(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=data,
            ),
            busy_detail="Database busy while recording extension status. Retry in a few seconds.",
        )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return ExtensionStatusReportResponse.model_validate(result)


@router.post("/telemetry/browser/interaction-eval", response_model=BrowserInteractionEvalResponse)
def browser_interaction_eval(
    request: Request,
    payload: BrowserInteractionEvalRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    try:
        try:
            result = _run_extension_write_with_sqlite_retry(
                db,
                lambda: evaluate_browser_interaction_and_record(
                    db,
                    tenant_id=ctx.tenant.id,
                    actor_user_id=current_user.id,
                    payload=data,
                    persist_allow_decisions=False,
                ),
                busy_detail="Database busy while evaluating browser interaction. Retry in a few seconds.",
                max_attempts=2,
                retry_backoff_seconds=0.03,
                sqlite_busy_timeout_ms=max(100, int(settings.sqlite_interaction_eval_busy_timeout_ms or 400)),
            )
        except HTTPException as exc:
            if exc.status_code != status.HTTP_503_SERVICE_UNAVAILABLE:
                raise
            db.rollback()
            log_structured(
                "browser_interaction_eval_degraded_no_write",
                level="warning",
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                detail=str(exc.detail),
                correlation_id=data.get("correlation_id"),
            )
            result = evaluate_browser_interaction_and_record(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=data,
                persist_artifacts=False,
                persist_allow_decisions=False,
                degradation_reason="sqlite_busy_fastpath",
            )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return BrowserInteractionEvalResponse.model_validate(result)


@router.post("/telemetry/desktop/interaction-eval", response_model=BrowserInteractionEvalResponse)
def desktop_interaction_eval(
    request: Request,
    payload: DesktopInteractionEvalRequest,
    ctx: TenantContext = Depends(require_role(min_role="viewer")),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if payload.tenant_id and payload.tenant_id != ctx.tenant.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="tenant_id mismatch")
    data = payload.model_dump(mode="json")
    if not data.get("correlation_id"):
        data["correlation_id"] = getattr(request.state, "correlation_id", None)
    application = str(data.get("application") or data.get("desktop_app") or "Claude Desktop").strip() or "Claude Desktop"
    desktop_app = str(data.get("desktop_app") or application).strip() or application
    data.update(
        {
            "application": application,
            "desktop_app": desktop_app,
            "domain": data.get("domain") or f"{desktop_app.lower().replace(' ', '-')}.local",
            "url": data.get("url") or f"desktop://{desktop_app.lower().replace(' ', '-')}",
            "browser": "desktop_guard",
            "browser_type": "desktop_guard",
            "browser_profile": "desktop_app",
            "extension_version": data.get("guard_version") or data.get("extension_version") or "desktop_guard",
            "source_surface": "desktop_app",
            "prompt_storage_mode": data.get("prompt_storage_mode") or "redacted_preview_only",
        }
    )
    try:
        try:
            result = _run_extension_write_with_sqlite_retry(
                db,
                lambda: evaluate_browser_interaction_and_record(
                    db,
                    tenant_id=ctx.tenant.id,
                    actor_user_id=current_user.id,
                    payload=data,
                    persist_allow_decisions=False,
                ),
                busy_detail="Database busy while evaluating desktop AI app interaction. Retry in a few seconds.",
                max_attempts=2,
                retry_backoff_seconds=0.03,
                sqlite_busy_timeout_ms=max(100, int(settings.sqlite_interaction_eval_busy_timeout_ms or 400)),
            )
        except HTTPException as exc:
            if exc.status_code != status.HTTP_503_SERVICE_UNAVAILABLE:
                raise
            db.rollback()
            log_structured(
                "desktop_interaction_eval_degraded_no_write",
                level="warning",
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                detail=str(exc.detail),
                correlation_id=data.get("correlation_id"),
            )
            result = evaluate_browser_interaction_and_record(
                db,
                tenant_id=ctx.tenant.id,
                actor_user_id=current_user.id,
                payload=data,
                persist_artifacts=False,
                persist_allow_decisions=False,
                degradation_reason="sqlite_busy_fastpath",
            )
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return BrowserInteractionEvalResponse.model_validate(result)
