from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.observability import log_structured
from app.db.models.enforcement import EnforcementEvent
from app.db.models.finding import Finding
from app.db.models.monitoring import DriftAlert, MonitoringSignal
from app.db.models.policy import PolicyVersion
from app.services.audit_service import write_audit_log
from app.services.control_graph_service import normalize_control_ids
from app.services.discovery_service import touch_discovery_application_from_finding


SEVERITY_ORDER = {
    "low": 0,
    "med": 1,
    "medium": 1,
    "high": 2,
    "critical": 3,
}

OPEN_FINDING_STATUSES = {"open", "reviewing"}
ALLOWED_SOURCE_SURFACES = {
    "browser",
    "gateway",
    "connector",
    "aiiam",
    "monitoring",
    "endpoint",
    "endpoint-agent",
    "dns",
    "proxy",
    "desktop_app",
    "foundry",
    "copilot",
}
PLACEHOLDER_AI_TOOL_VALUES = {
    "",
    "unknown",
    "unknown_ai",
    "unknown_ai_app",
    "unknown_ai_entity",
    "unknown_ai_system",
    "unknown_tool",
    "extension.local",
    "hawk_extension",
    "browser_extension",
    "localhost",
    "127.0.0.1",
    "::1",
}


def discovery_coverage_gap_candidates(projection: Any) -> list[dict[str, Any]]:
    """Build review candidates; never persist a finding from a read projection.

    Unknown evidence becomes verification work, while an explicit uncovered
    state becomes a coverage-gap candidate.  Neither state is recast as a
    policy block or an authorization decision.
    """

    candidates: list[dict[str, Any]] = []
    for dimension_name, dimension in sorted(projection.dimensions.items()):
        for state, asset_ids in (
            ("not_covered", dimension.not_covered_asset_ids),
            ("unknown", dimension.unknown_asset_ids),
        ):
            for asset_id in sorted(asset_ids):
                candidates.append(
                    {
                        "tenant_id": projection.tenant_id,
                        "asset_id": asset_id,
                        "dimension": dimension_name,
                        "coverage_state": state,
                        "candidate_kind": (
                            "coverage_gap"
                            if state == "not_covered"
                            else "verification_required"
                        ),
                        "evidence_refs": list(dimension.evidence_refs),
                        "missing_evidence": list(dimension.missing_evidence),
                        "recommended_actions": list(
                            dimension.improvement_actions
                        ),
                        "methodology_version": projection.methodology_version,
                        "auto_persist": False,
                        "authorization_effect": "none",
                    }
                )
    return candidates

if TYPE_CHECKING:
    from app.db.models.shadow_ai import ShadowAIEntity


def _normalize_severity(value: str | None) -> str:
    normalized = str(value or "low").strip().lower()
    if normalized == "medium":
        return "med"
    if normalized not in {"low", "med", "high", "critical"}:
        return "low"
    return normalized


def _max_severity(*values: str) -> str:
    ranked = sorted((_normalize_severity(v) for v in values), key=lambda item: SEVERITY_ORDER[item], reverse=True)
    return ranked[0] if ranked else "low"


def _uniq_sorted_strings(values: list[Any]) -> list[str]:
    out = {str(value).strip() for value in values if str(value).strip()}
    return sorted(out)


def _safe_text(value: Any, *, max_len: int = 255) -> str | None:
    token = str(value or "").strip()
    if not token:
        return None
    return token[:max_len]


def _is_placeholder_ai_tool(value: Any) -> bool:
    token = str(value or "").strip().lower()
    return token in PLACEHOLDER_AI_TOOL_VALUES or token.startswith("unknown_")


def _should_suppress_placeholder_unregistered_ai_system(
    *,
    source_surface: str,
    ai_tool: str,
    requested_ai_system_id: str | None,
    recommended_action: str | None,
) -> bool:
    if requested_ai_system_id:
        return False
    surface = str(source_surface or "").strip().lower()
    if surface not in {"browser", "connector", "monitoring", "endpoint", "desktop_app", "foundry", "copilot"}:
        return False
    if not _is_placeholder_ai_tool(ai_tool):
        return False
    action = str(recommended_action or "").strip().lower()
    return (
        not action
        or "runtime trigger referenced unknown ai system" in action
        or "route_to_governance_review" in action
        or "unknown ai usage detected" in action
    )


def _safe_fk_text(value: Any, *, max_len: int = 255) -> str | None:
    token = _safe_text(value, max_len=max_len)
    if token is None:
        return None
    if token.lower() in {"none", "null", "undefined", "unmapped"}:
        return None
    return token


def _safe_user_id(value: str | None) -> str | None:
    candidate = str(value or "").strip()
    if len(candidate) == 36:
        return candidate
    return None


def _resolve_policy_version_fk(
    db: Session,
    *,
    tenant_id: str,
    reported_policy_version_id: str | None,
) -> str | None:
    """Return a tenant-valid policy version FK, or None for source-local evidence.

    Clients can legitimately report policy sync identifiers that are stale,
    source-local, or unavailable in a freshly restored/native tenant.  Those
    values remain useful evidence, but writing them to a policy_versions FK
    drops otherwise valid telemetry.  Keep the relationship unresolved unless
    the platform can prove the policy version exists in this tenant.
    """

    candidate = str(reported_policy_version_id or "").strip()
    if not candidate:
        return None
    exists = db.scalar(
        select(PolicyVersion.id).where(
            PolicyVersion.tenant_id == tenant_id,
            PolicyVersion.id == candidate,
        )
    )
    if exists:
        return str(exists)
    log_structured(
        "reported_policy_version_unresolved",
        module="findings_service",
        tenant_id=tenant_id,
        reported_policy_version_id=candidate,
    )
    return None


def _dedupe_key(*parts: str) -> str:
    material = "|".join(str(part or "").strip().lower() for part in parts)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:64]


def _evaluate_finding_evidence_status(finding: Finding) -> str:
    required_fields = {
        "user_id": _safe_text(finding.user_id, max_len=128),
        "user_email": _safe_text(finding.user_email, max_len=320),
        "machine_id": _safe_text(finding.machine_id, max_len=128),
        "browser_type": _safe_text(finding.browser_type, max_len=32),
        "application": _safe_text(finding.application, max_len=255),
        "policy": _safe_text(finding.policy_id or finding.policy_version_id, max_len=128),
        "decision": _safe_text(finding.decision, max_len=32),
        "related_runtime_event_id": _safe_text(finding.related_runtime_event_id, max_len=64),
    }
    has_evidence_nodes = bool(_uniq_sorted_strings(list(finding.evidence_node_ids or [])))
    has_event_timestamp = bool(finding.last_seen_at or finding.created_at)
    complete = all(required_fields.values()) and has_evidence_nodes and has_event_timestamp
    return "complete" if complete else "incomplete"


def _reason_code_for_finding(finding: Finding) -> str:
    finding_type = str(finding.finding_type or "").strip().lower()
    if finding_type == "sensitive_file_upload_attempt":
        return "sensitive_file_upload"
    if finding_type in {"sensitive_data_to_public_ai_attempt", "sensitive_data_external_transfer_attempt"}:
        return "sensitive_data_exfiltration"
    if finding_type in {"repeated_blocked_transfer_attempt", "repeated_justified_sensitive_transfer"}:
        return "repeated_data_transfer_violation"
    if finding_type in {"agent_action_blocked", "agent_action_requires_approval", "agent_action_warned"}:
        return "agent_tool_abuse"
    if finding_type == "unregistered_ai_system":
        return "unregistered_ai_system"
    if finding_type.startswith("shadow_ai"):
        return "shadow_ai_detection"
    return finding_type or "guardian_violation"


def _source_trigger_id_for_finding(finding: Finding) -> str:
    occurrence_count = max(1, int(finding.occurrence_count or 1))
    repeat_threshold = max(1, int(settings.runtime_intelligence_repeat_threshold or 3))
    finding_type = str(finding.finding_type or "").strip().lower()
    if (finding_type == "unregistered_ai_system" or finding_type.startswith("shadow_ai")) and occurrence_count >= repeat_threshold:
        return f"{finding.finding_id}:repeat_escalation:{occurrence_count}"
    bucket = 1 + ((occurrence_count - 1) // repeat_threshold)
    return f"{finding.finding_id}:repeat_bucket:{bucket}"


def _mcp_finding_profile(
    *,
    decision: str,
    reason: str,
    threat_types: list[str],
) -> tuple[str, str, str]:
    reason_norm = str(reason or "").strip().lower()
    threat_set = {str(item or "").strip().lower() for item in threat_types if str(item or "").strip()}
    if decision in {"hold_for_approval", "require_approval"}:
        return (
            "TOOL_CALL_REQUIRES_APPROVAL",
            "mcp_tool_governance",
            "Tool call requires explicit approval. Route via approval workflow before execution.",
        )
    if "secret" in reason_norm or "credential" in reason_norm or "token" in reason_norm:
        return (
            "TOOL_CALL_WITH_SECRET",
            "mcp_data_exposure",
            "Secret-like data detected in tool arguments. Block call, rotate exposed secret, and restrict tool scope.",
        )
    if "sensitive" in reason_norm or "data_scope" in reason_norm or "exfil" in reason_norm:
        return (
            "TOOL_CALL_WITH_SENSITIVE_DATA",
            "mcp_data_exposure",
            "Sensitive data scope detected in tool call. Enforce need-to-know and tighten MCP data access scope.",
        )
    if "session" in reason_norm or "unattributed" in reason_norm or "identity" in reason_norm:
        return (
            "UNATTRIBUTED_TOOL_CALL",
            "mcp_identity",
            "Tool call missing valid user/session attribution. Require session binding and re-authentication.",
        )
    if "unapproved_client" in reason_norm or "client" in reason_norm:
        return (
            "UNAPPROVED_AI_CLIENT",
            "mcp_client",
            "Tool call came from unapproved AI client. Restrict to approved clients and revoke current grant.",
        )
    if "drift" in reason_norm:
        return (
            "MCP_PERMISSION_DRIFT",
            "mcp_permission",
            "Permission drift detected for MCP access. Recalculate least-privilege grant and require review.",
        )
    if "tool_update" in reason_norm:
        return (
            "MCP_TOOL_UPDATE_RISK",
            "mcp_tool_governance",
            "New/updated tool detected on approved MCP server. Move tool to under review before continued use.",
        )
    if "unapproved" in reason_norm or "unknown" in reason_norm:
        if "server" in reason_norm:
            return (
                "SHADOW_MCP_SERVER",
                "mcp_governance",
                "Shadow/unapproved MCP server detected. Block server access and route asset for Trust Center review.",
            )
        return (
            "UNAPPROVED_MCP_TOOL",
            "mcp_governance",
            "Unapproved MCP tool call detected. Restrict tool and approve explicitly before use.",
        )
    if "over_scope" in reason_norm or "escalation" in reason_norm or "scope_denied" in reason_norm:
        return (
            "HIGH_RISK_TOOL_CALL",
            "mcp_permission",
            "High-risk or over-scoped tool call detected. Revoke broad grants and enforce scoped access.",
        )
    if "agent_over_scope_risk" in threat_set:
        return (
            "AGENT_TOOL_ABUSE",
            "mcp_permission",
            "Agent behavior indicates over-scoped tool usage. Isolate agent and reduce delegated scope.",
        )
    if decision in {"block", "deny"}:
        return (
            "TOOL_CALL_BLOCKED_BY_POLICY",
            "mcp_tool_governance",
            "Tool call blocked by policy. Review reasoning and update approval scope if needed.",
        )
    return (
        "HIGH_RISK_TOOL_CALL",
        "mcp_tool_governance",
        "High-risk MCP tool-call behavior detected. Review call chain, policy, and identity grants.",
    )


def _propose_remediation_non_blocking(db: Session, *, finding: Finding) -> None:
    try:
        from app.services.remediation import propose_remediation_from_finding

        normalized_ai_tool = str(finding.ai_tool or "").strip()
        propose_remediation_from_finding(
            db,
            finding=finding,
            context={
                "finding_id": finding.finding_id,
                "finding_type": finding.finding_type,
                "occurrence_count": int(finding.occurrence_count or 1),
                "reason_code": _reason_code_for_finding(finding),
                "related_control_ids": list(finding.related_control_ids or []),
                "evidence_node_ids": list(finding.evidence_node_ids or []),
                "policy_version_id": finding.policy_version_id,
                "source_trigger_id": _source_trigger_id_for_finding(finding),
                "domain": normalized_ai_tool or None,
                "ai_tool": normalized_ai_tool or None,
                "risk_category": str(finding.risk_category or "").strip().lower(),
                "data_classification": str(finding.data_classification or "").strip().lower() or None,
            },
        )
    except Exception as exc:  # pragma: no cover - remediation must not break finding ingestion
        log_structured(
            "remediation_proposal_failed",
            module="findings_service",
            tenant_id=finding.tenant_id,
            finding_id=finding.finding_id,
            finding_type=finding.finding_type,
            error=str(exc),
        )


def _upsert_finding(
    db: Session,
    *,
    tenant_id: str,
    source_surface: str,
    ai_tool: str,
    ai_system_id: str | None,
    user_id: str | None,
    agent_id: str | None = None,
    machine_id: str | None = None,
    user_email: str | None = None,
    browser_type: str | None = None,
    application: str | None = None,
    department: str | None,
    severity: str,
    finding_type: str,
    risk_category: str,
    data_classification: str | None,
    decision: str | None = None,
    recommended_action: str,
    policy_id: str | None = None,
    policy_version_id: str | None,
    evidence_node_ids: list[str],
    related_event_ids: list[str] | None = None,
    related_control_ids: list[str],
    related_runtime_event_id: str | None = None,
    dedupe_key: str,
) -> Finding:
    now = datetime.now(timezone.utc)
    evidence_ids = _uniq_sorted_strings(evidence_node_ids)
    event_ids = _uniq_sorted_strings(list(related_event_ids or []))
    control_ids = normalize_control_ids(related_control_ids)
    normalized_agent_id = str(agent_id or "").strip() or None
    normalized_machine_id = str(machine_id or "").strip() or None
    normalized_user_email = _safe_text(user_email, max_len=320)
    normalized_browser_type = _safe_text(browser_type, max_len=32)
    normalized_application = _safe_text(application, max_len=255)
    normalized_decision = _safe_text(decision, max_len=32)
    normalized_policy_id = _safe_fk_text(policy_id, max_len=64)
    normalized_policy_version_id = _safe_fk_text(policy_version_id, max_len=64)
    normalized_runtime_event_id = _safe_text(related_runtime_event_id, max_len=64)
    normalized_severity = _normalize_severity(severity)
    normalized_source_surface = str(source_surface or "connector").strip().lower()
    if normalized_source_surface not in ALLOWED_SOURCE_SURFACES:
        normalized_source_surface = "connector"

    existing = db.scalar(
        select(Finding)
        .where(
            Finding.tenant_id == tenant_id,
            Finding.dedupe_key == dedupe_key,
            Finding.status.in_(sorted(OPEN_FINDING_STATUSES)),
        )
        .order_by(Finding.updated_at.desc())
    )

    if existing:
        existing.severity = _max_severity(existing.severity, normalized_severity)
        existing.occurrence_count = int(existing.occurrence_count or 1) + 1
        existing.last_seen_at = now
        existing.source_surface = normalized_source_surface
        existing.evidence_node_ids = _uniq_sorted_strings([*(existing.evidence_node_ids or []), *evidence_ids])
        existing.related_event_ids = _uniq_sorted_strings([*(existing.related_event_ids or []), *event_ids])
        existing.related_control_ids = normalize_control_ids([*(existing.related_control_ids or []), *control_ids])
        if not existing.policy_version_id and normalized_policy_version_id:
            existing.policy_version_id = normalized_policy_version_id
        if not existing.department and department:
            existing.department = department
        if not existing.data_classification and data_classification:
            existing.data_classification = data_classification
        if not existing.user_id and user_id:
            existing.user_id = user_id
        if not existing.agent_id and normalized_agent_id:
            existing.agent_id = normalized_agent_id
        if not existing.machine_id and normalized_machine_id:
            existing.machine_id = normalized_machine_id
        if not existing.user_email and normalized_user_email:
            existing.user_email = normalized_user_email
        if not existing.browser_type and normalized_browser_type:
            existing.browser_type = normalized_browser_type
        if not existing.application and normalized_application:
            existing.application = normalized_application
        if not existing.decision and normalized_decision:
            existing.decision = normalized_decision
        if not existing.policy_id and normalized_policy_id:
            existing.policy_id = normalized_policy_id
        if not existing.related_runtime_event_id and normalized_runtime_event_id:
            existing.related_runtime_event_id = normalized_runtime_event_id
        if not existing.recommended_action and recommended_action:
            existing.recommended_action = recommended_action
        existing.evidence_status = _evaluate_finding_evidence_status(existing)
        db.flush()
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=None,
            actor_type="system",
            action="findings.deduplicated",
            resource_type="finding",
            resource_id=existing.finding_id,
            payload={
                "finding_type": finding_type,
                "occurrence_count": existing.occurrence_count,
                "dedupe_key": dedupe_key,
            },
        )
        touch_discovery_application_from_finding(db, finding=existing)
        _propose_remediation_non_blocking(db, finding=existing)
        return existing

    finding = Finding(
        tenant_id=tenant_id,
        source_surface=normalized_source_surface,
        ai_tool=ai_tool,
        ai_system_id=ai_system_id,
        user_id=user_id,
        agent_id=normalized_agent_id,
        machine_id=normalized_machine_id,
        user_email=normalized_user_email,
        browser_type=normalized_browser_type,
        application=normalized_application,
        department=department,
        severity=normalized_severity,
        finding_type=finding_type,
        risk_category=risk_category,
        data_classification=data_classification,
        decision=normalized_decision,
        status="open",
        recommended_action=recommended_action,
        policy_id=normalized_policy_id,
        policy_version_id=normalized_policy_version_id,
        evidence_node_ids=evidence_ids,
        related_event_ids=event_ids,
        related_control_ids=control_ids,
        related_runtime_event_id=normalized_runtime_event_id,
        dedupe_key=dedupe_key,
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    finding.evidence_status = _evaluate_finding_evidence_status(finding)
    db.add(finding)
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="findings.created",
        resource_type="finding",
        resource_id=finding.finding_id,
        payload={
            "finding_type": finding_type,
            "severity": finding.severity,
            "dedupe_key": dedupe_key,
        },
    )
    touch_discovery_application_from_finding(db, finding=finding)
    _propose_remediation_non_blocking(db, finding=finding)
    return finding


def enrich_pilot_finding_context(
    db: Session,
    *,
    finding: Finding,
    user_email: str | None = None,
    browser_type: str | None = None,
    application: str | None = None,
    decision: str | None = None,
    policy_id: str | None = None,
    related_runtime_event_id: str | None = None,
    machine_id: str | None = None,
) -> Finding:
    if user_email and not finding.user_email:
        finding.user_email = _safe_text(user_email, max_len=320)
    if browser_type and not finding.browser_type:
        finding.browser_type = _safe_text(browser_type, max_len=32)
    if application and not finding.application:
        finding.application = _safe_text(application, max_len=255)
    if decision and not finding.decision:
        finding.decision = _safe_text(decision, max_len=32)
    if policy_id and not finding.policy_id:
        finding.policy_id = _safe_text(policy_id, max_len=64)
    if related_runtime_event_id and not finding.related_runtime_event_id:
        finding.related_runtime_event_id = _safe_text(related_runtime_event_id, max_len=64)
    if machine_id and not finding.machine_id:
        finding.machine_id = _safe_text(machine_id, max_len=128)
    finding.evidence_status = _evaluate_finding_evidence_status(finding)
    db.flush()
    return finding


def generate_from_enforcement_event(db: Session, *, event: EnforcementEvent) -> Finding | None:
    decision = str(event.final_decision or "").strip().lower()
    if decision in {"", "allow"}:
        return None

    controls = _uniq_sorted_strings(
        [item.get("control_id") for item in (event.controls_impacted or []) if isinstance(item, dict)]
    )
    threat_types = _uniq_sorted_strings(
        [
            threat
            for item in (event.guardian_results or [])
            if isinstance(item, dict)
            for threat in (item.get("threat_types") or [])
        ]
    )
    primary_threat_types = _uniq_sorted_strings(
        [
            threat
            for item in (event.guardian_results or [])
            if isinstance(item, dict)
            and str(item.get("guardian_id") or "").strip().lower() != "control_engine"
            for threat in (item.get("threat_types") or [])
        ]
    )
    meta = ((event.final_actions or {}).get("_meta") if isinstance(event.final_actions, dict) else {}) or {}
    strictness_level = int(meta.get("strictness_level") or 0)

    if decision == "block":
        severity = "critical" if strictness_level >= 2 else "high"
    elif decision == "hold_for_approval":
        severity = "high"
    elif decision == "redact":
        severity = "med"
    else:
        severity = "low"

    is_mcp_enforcement = str(event.input_context_summary or "").strip().lower() == "mcp_authorize"
    # Prefer the concrete detected threat over generic control-engine labels so
    # monitor-only reconciliation does not change finding taxonomy.
    specific_threat_types = [
        threat
        for threat in (primary_threat_types or threat_types)
        if threat not in {"governance_gap", "policy_violation"}
    ]
    risk_category = (
        specific_threat_types[0]
        if specific_threat_types
        else threat_types[0]
        if threat_types
        else ("mcp_tool_governance" if is_mcp_enforcement else "interaction_security")
    )
    action_meta = dict((event.final_actions or {}).get("mcp") or {}) if isinstance((event.final_actions or {}).get("mcp"), dict) else {}
    tool_hint = str(action_meta.get("tool_name") or action_meta.get("action") or "").strip()
    ai_tool = tool_hint or ("mcp_gateway" if is_mcp_enforcement else "llm_gateway")
    user_id = _safe_user_id(event.actor_id if str(event.actor_type or "").lower() == "human" else None)
    reason = str(action_meta.get("reason") or "").strip()
    pre_action_check = (
        dict((event.final_actions or {}).get("pre_action_governance_check") or {})
        if isinstance((event.final_actions or {}).get("pre_action_governance_check"), dict)
        else {}
    )
    pre_action_policy = dict(pre_action_check.get("policy") or {}) if isinstance(pre_action_check.get("policy"), dict) else {}
    pre_action_purpose = dict(pre_action_check.get("purpose") or {}) if isinstance(pre_action_check.get("purpose"), dict) else {}
    pre_action_control_mode = str(pre_action_check.get("control_mode") or "").strip().lower()
    need_to_know_decision = (
        dict(meta.get("need_to_know_decision") or {})
        if isinstance(meta.get("need_to_know_decision"), dict)
        else {}
    )
    knowledge_disclosure_event = (
        dict(meta.get("knowledge_disclosure_event") or {})
        if isinstance(meta.get("knowledge_disclosure_event"), dict)
        else {}
    )

    recommended_by_decision = {
        "block": "Immediate triage required. Review blocked request context and tighten guardian enforcement before retry.",
        "hold_for_approval": "Route this workflow through explicit approval and validate policy scope before continuation.",
        "redact": "Apply stronger data minimization and redaction controls prior to resubmission.",
        "warn": "Review repeated warning patterns and tighten thresholds if frequency increases.",
    }
    recommended_action = recommended_by_decision.get(decision, "Review enforcement signal and remediate policy/control gap.")
    finding_type = "enforcement_event"
    if is_mcp_enforcement:
        finding_type, risk_category, recommended_action = _mcp_finding_profile(
            decision=decision,
            reason=reason,
            threat_types=threat_types,
        )
    if pre_action_check and decision in {"block", "hold_for_approval", "warn"}:
        finding_type = "AI_ACTION_BOUNDARY_VIOLATION"
        risk_category = "ai_action_governance"
        if pre_action_purpose.get("violations"):
            finding_type = "AGENT_PURPOSE_SCOPE_VIOLATION"
            risk_category = "agent_control"
        if pre_action_control_mode == "inline_prevented" and decision == "block":
            finding_type = "AI_ACTION_BOUNDARY_VIOLATION"
            recommended_action = (
                "AI action was prevented before execution. Review purpose-bound permission, action scope, "
                "and authority before retry."
            )
    if need_to_know_decision and str(need_to_know_decision.get("decision") or "").strip().lower() != "allow":
        risk_category = "need_to_know_ai_access"
        sensitivity_domain = str(
            need_to_know_decision.get("sensitivity_domain")
            or knowledge_disclosure_event.get("sensitivity_domain")
            or ""
        ).strip().lower()
        data_source = str(((event.final_actions or {}).get("_trace") or {}).get("data_source") or "").strip().lower()
        if "rag" in data_source or "vector" in data_source:
            finding_type = "RAG_PERMISSION_BYPASS_RISK"
        elif sensitivity_domain:
            finding_type = "KNOWLEDGE_EXPOSURE_RISK"
        else:
            finding_type = "AI_OVERSHARING_RISK"
        recommended_action = (
            "Validate the user's need-to-know access for the referenced knowledge asset, then restrict, redact, "
            "or require approval before disclosure."
        )

    dedupe = _dedupe_key(
        "enforcement",
        event.ai_system_id or "",
        finding_type,
        decision,
        risk_category,
        event.policy_version_id or "",
        ",".join(controls),
        ",".join(threat_types),
        tool_hint,
    )
    return _upsert_finding(
        db,
        tenant_id=event.tenant_id,
        source_surface="gateway",
        ai_tool=ai_tool,
        ai_system_id=event.ai_system_id,
        user_id=user_id,
        agent_id=(str(event.actor_id).strip() if str(event.actor_type or "").lower() == "agent" else None),
        department=None,
        severity=severity,
        finding_type=finding_type,
        risk_category=risk_category,
        data_classification=None,
        decision=decision,
        policy_id=str(
            need_to_know_decision.get("policy_id")
            or pre_action_policy.get("policy_snapshot_id")
            or event.policy_version_id
            or ""
        )
        or None,
        recommended_action=recommended_action,
        policy_version_id=event.policy_version_id,
        evidence_node_ids=[str(node_id) for node_id in (event.evidence_nodes_created or []) if str(node_id).strip()],
        related_event_ids=[event.id, event.request_id],
        related_control_ids=controls,
        dedupe_key=dedupe,
    )


def generate_from_shadow_event(db: Session, *, signal: MonitoringSignal) -> Finding | None:
    if not str(signal.signal_type or "").startswith("shadow_ai."):
        return None

    payload = signal.payload if isinstance(signal.payload, dict) else {}
    ai_tool = str(payload.get("ai_tool") or payload.get("tool") or "shadow_ai_discovery")
    department = str(payload.get("department") or "").strip() or None
    user_id = _safe_user_id(payload.get("user_id"))
    event_name = str(signal.signal_type).split(".", 1)[1] if "." in str(signal.signal_type) else str(signal.signal_type)
    recommended_action = (
        "Register discovered AI usage in governance inventory, attach owner, and enforce approved policy pack before continued use."
    )

    dedupe = _dedupe_key(
        "shadow_ai",
        signal.ai_system_id or "",
        event_name,
        ai_tool,
        department or "",
    )
    payload_source = str((payload or {}).get("source_surface") or "").strip().lower()
    signal_source = str(signal.signal_type or "")
    if payload_source in ALLOWED_SOURCE_SURFACES:
        source_surface = payload_source
    elif signal_source.startswith("shadow_ai.browser_"):
        source_surface = "browser"
    elif signal_source.startswith("shadow_ai.endpoint_"):
        source_surface = "endpoint"
    elif signal_source.startswith("shadow_ai.dns_"):
        source_surface = "dns"
    elif signal_source.startswith("shadow_ai.proxy_"):
        source_surface = "proxy"
    else:
        source_surface = "connector"

    return _upsert_finding(
        db,
        tenant_id=signal.tenant_id,
        source_surface=source_surface,
        ai_tool=ai_tool,
        ai_system_id=signal.ai_system_id,
        user_id=user_id,
        department=department,
        severity=_normalize_severity(signal.severity or payload.get("severity")),
        finding_type="shadow_ai_discovery",
        risk_category=str(payload.get("risk_category") or "shadow_ai"),
        data_classification=(str(payload.get("data_classification")) if payload.get("data_classification") else None),
        recommended_action=recommended_action,
        policy_version_id=None,
        evidence_node_ids=[str(node_id) for node_id in (payload.get("evidence_node_ids") or []) if str(node_id).strip()],
        related_control_ids=[str(control_id) for control_id in (payload.get("related_control_ids") or []) if str(control_id).strip()],
        dedupe_key=dedupe,
    )


def generate_from_asymmetry_signal(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str,
    evidence_node_id: str,
    risk_labels: list[str],
    policy_version_id: str | None,
) -> Finding:
    labels = _uniq_sorted_strings(risk_labels)
    has_chain_abuse = "agent_chain_abuse" in labels
    recommended_action = (
        "Run targeted output-injection and agent-misuse simulations, then tighten guardian/tool execution limits for this AI system."
    )
    dedupe = _dedupe_key(
        "asymmetry_signal",
        ai_system_id,
        ",".join(labels),
        policy_version_id or "",
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface="gateway",
        ai_tool="llm_gateway",
        ai_system_id=ai_system_id,
        user_id=None,
        department=None,
        severity="critical" if has_chain_abuse else "high",
        finding_type="asymmetry_signal",
        risk_category=(labels[0] if labels else "output_asymmetry"),
        data_classification=None,
        recommended_action=recommended_action,
        policy_version_id=policy_version_id,
        evidence_node_ids=[evidence_node_id],
        related_control_ids=["CTRL-TOOL-001"] if has_chain_abuse else [],
        dedupe_key=dedupe,
    )


def generate_from_drift_alert(
    db: Session,
    *,
    alert: DriftAlert,
    severity: str | None = None,
    ai_tool: str | None = None,
    evidence_node_ids: list[str] | None = None,
    related_control_ids: list[str] | None = None,
) -> Finding:
    resolved_severity = _normalize_severity(severity or ("high" if "critical" in str(alert.title).lower() else "med"))
    dedupe = _dedupe_key(
        "drift_alert",
        alert.ai_system_id or "",
        alert.title or "",
        ai_tool or "monitoring_connector",
    )
    return _upsert_finding(
        db,
        tenant_id=alert.tenant_id,
        source_surface="connector",
        ai_tool=ai_tool or "monitoring_connector",
        ai_system_id=alert.ai_system_id,
        user_id=None,
        department=None,
        severity=resolved_severity,
        finding_type="drift_alert",
        risk_category="monitoring_drift",
        data_classification=None,
        recommended_action="Review drift source, validate connector telemetry, and remediate control configuration drift.",
        policy_version_id=None,
        evidence_node_ids=evidence_node_ids or [],
        related_control_ids=related_control_ids or [],
        dedupe_key=dedupe,
    )


def generate_from_browser_event(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    domain: str,
    ai_system_id: str | None,
    user_id: str | None,
    policy_version_id: str | None,
    platform_mode: str,
    action_taken: str | None,
    prompt_preview_redacted: str | None,
    input_signal_types: list[str] | None,
    file_meta: list[dict[str, Any]] | None,
    evidence_node_id: str | None,
    intent_aware_decision: dict[str, Any] | None = None,
    source_surface: str = "browser",
) -> Finding | None:
    normalized_event = str(event_type or "").strip().lower()
    actionable_events = {
        "prompt_warned",
        "prompt_blocked",
        "prompt_held",
        "output_flagged",
        "file_upload_detected",
        "clipboard_paste_detected",
        "browser_automation_action",
        "browser_automation_detected",
        "browser_automation_blocked",
        "extension_health_status",
        "meeting_ai_notetaker_detected",
        "meeting_ai_notetaker_block_requested",
        "meeting_ai_notetaker_hidden_suspected",
        "meeting_ai_notetaker_calendar_invitee_detected",
        "meeting_ai_notetaker_oauth_detected",
        "device_audio_notetaker_detected",
        "device_audio_notetaker_control_applied",
        "meeting_transcription_policy_violation",
    }
    if normalized_event not in actionable_events:
        return None

    severity_map = {
        "prompt_warned": "med",
        "prompt_held": "high",
        "prompt_blocked": "critical",
        "output_flagged": "high",
        "file_upload_detected": "high",
        "clipboard_paste_detected": "high",
        "browser_automation_detected": "high",
        "browser_automation_blocked": "critical",
        "extension_health_status": "high",
        "meeting_ai_notetaker_detected": "high",
        "meeting_ai_notetaker_block_requested": "high",
        "meeting_ai_notetaker_hidden_suspected": "high",
        "meeting_ai_notetaker_calendar_invitee_detected": "med",
        "meeting_ai_notetaker_oauth_detected": "high",
        "device_audio_notetaker_detected": "high",
        "device_audio_notetaker_control_applied": "critical",
        "meeting_transcription_policy_violation": "high",
    }
    severity = severity_map.get(normalized_event, "med")
    risk_category = "interaction_security"
    input_signals = _uniq_sorted_strings(input_signal_types or [])
    signal_map: dict[str, str] = {}
    for signal in input_signals:
        if ":" not in signal:
            continue
        key, value = signal.split(":", 1)
        key_norm = str(key or "").strip().lower()
        value_norm = str(value or "").strip()
        if key_norm and value_norm and key_norm not in signal_map:
            signal_map[key_norm] = value_norm
    action_type = str(
        signal_map.get("action_type")
        or signal_map.get("action")
        or ""
    ).strip().lower() or None
    automation_source = str(signal_map.get("automation_source") or "").strip().lower() or None
    decision_badge = str(signal_map.get("decision_badge") or "").strip().lower() or None
    action_token = str(action_taken or "").strip().lower()
    decision = action_token.split(":", 1)[0] if action_token else ""
    if decision not in {"allow", "warn", "block"}:
        if normalized_event == "prompt_blocked" or normalized_event == "browser_automation_blocked":
            decision = "block"
        elif normalized_event in {"prompt_warned", "prompt_held", "browser_automation_detected", "browser_automation_action"}:
            decision = "warn"
        else:
            decision = "allow"
    if normalized_event == "browser_automation_action":
        severity = {
            "block": "critical",
            "warn": "high",
            "allow": "low",
        }.get(decision, severity)
    reason_token = action_token.split(":", 1)[1] if ":" in action_token else action_token
    reason_token = reason_token or str(signal_map.get("reason") or "").strip().lower()
    if input_signals:
        risk_category = input_signals[0]
    if normalized_event in {"browser_automation_action", "browser_automation_detected", "browser_automation_blocked"}:
        risk_category = "browser_automation"
    meeting_events = {
        "meeting_ai_notetaker_detected",
        "meeting_ai_notetaker_block_requested",
        "meeting_ai_notetaker_hidden_suspected",
        "meeting_ai_notetaker_calendar_invitee_detected",
        "meeting_ai_notetaker_oauth_detected",
        "device_audio_notetaker_detected",
        "device_audio_notetaker_control_applied",
        "meeting_transcription_policy_violation",
    }
    if normalized_event in meeting_events:
        risk_category = "meeting_ai_notetaker"

    def _is_action(value: str | None, candidates: set[str]) -> bool:
        if not value:
            return False
        return str(value).strip().lower() in candidates

    def _contains_any(haystack: str | None, needles: set[str]) -> bool:
        token = str(haystack or "").strip().lower()
        if not token:
            return False
        return any(needle in token for needle in needles)

    finding_type = "browser_interaction_security"
    intent_decision = dict(intent_aware_decision or {})
    intent_finding_type = str(intent_decision.get("finding_type") or "").strip()
    if intent_finding_type:
        finding_type = intent_finding_type
        risk_category = "intent_aware_ai_action_control"
        severity = "critical" if decision == "block" else "med"
    if normalized_event in {"browser_automation_action", "browser_automation_detected", "browser_automation_blocked"}:
        if intent_finding_type:
            pass
        elif _contains_any(reason_token, {"scope_violation"}) or decision_badge == "scope_violation":
            finding_type = "BROWSER_AGENT_SCOPE_VIOLATION"
        elif _contains_any(reason_token, {"blocked_domain", "domain_outside_allowlist", "disallowed_domain"}):
            finding_type = "AUTOMATION_ON_BLOCKED_DOMAIN"
        elif _is_action(action_type, {"add_to_cart", "checkout", "purchase_now", "payment_submit"}):
            finding_type = "AUTOMATION_PURCHASE_ACTION_BLOCKED" if decision == "block" else "HIGH_RISK_BROWSER_AUTOMATION_ACTION"
        elif _is_action(action_type, {"submit_form", "credential_submit"}):
            finding_type = "AUTOMATION_FORM_SUBMIT_BLOCKED" if decision == "block" else "HIGH_RISK_BROWSER_AUTOMATION_ACTION"
        elif _is_action(action_type, {"upload_file"}):
            finding_type = "AUTOMATION_FILE_UPLOAD_BLOCKED" if decision == "block" else "HIGH_RISK_BROWSER_AUTOMATION_ACTION"
        elif _is_action(action_type, {"send_message", "send_email", "delete_item", "change_settings", "invite_user", "create_api_key", "access_admin_console", "access_payment_page", "access_credentials_page"}):
            finding_type = "HIGH_RISK_BROWSER_AUTOMATION_ACTION"
        elif automation_source == "suspected_local_agent" or _contains_any(reason_token, {"suspected_local_agent"}):
            finding_type = "LOCAL_AGENT_BROWSER_AUTOMATION_SUSPECTED"
        elif _contains_any(reason_token, {"authenticated"}) or _contains_any(prompt_preview_redacted, {"authenticated browser"}):
            finding_type = "AGENT_USING_AUTHENTICATED_BROWSER"
        else:
            finding_type = "BROWSER_AUTOMATION_DETECTED"
    if normalized_event in meeting_events:
        if normalized_event == "meeting_ai_notetaker_block_requested":
            finding_type = "UNAPPROVED_AI_NOTETAKER"
            decision = "warn" if decision not in {"block", "warn"} else decision
        elif normalized_event == "meeting_ai_notetaker_hidden_suspected":
            finding_type = "HIDDEN_NOTETAKER_SUSPECTED"
            decision = "warn" if decision not in {"block", "warn"} else decision
        elif normalized_event == "meeting_ai_notetaker_oauth_detected":
            finding_type = "OAUTH_NOTETAKER_APP_OVER_SCOPED"
            decision = "warn" if decision not in {"block", "warn"} else decision
        elif normalized_event == "device_audio_notetaker_detected":
            finding_type = "DEVICE_AUDIO_NOTETAKER_SUSPECTED"
            decision = "warn" if decision not in {"block", "warn"} else decision
        elif normalized_event == "device_audio_notetaker_control_applied":
            finding_type = "DEVICE_AUDIO_NOTETAKER_CONTROL_APPLIED"
            decision = "block" if decision not in {"block", "warn"} else decision
        elif normalized_event == "meeting_transcription_policy_violation":
            finding_type = "MEETING_TRANSCRIPTION_POLICY_VIOLATION"
            decision = "warn" if decision not in {"block", "warn"} else decision
        else:
            finding_type = "AI_NOTETAKER_DETECTED"
            decision = "warn" if decision == "allow" else decision
    control_map = {
        "prompt_injection": "CTRL-INPUT-001",
        "prompt_decomposition": "CTRL-INPUT-001",
        "jailbreak": "CTRL-INPUT-002",
        "sensitive_data": "CTRL-DLP-001",
        "sensitive_data_pattern": "CTRL-DLP-001",
        "tool_output": "CTRL-TOOL-001",
        "domain_policy_mismatch": "CTRL-TENANT-ISO-001",
    }
    related_controls = [
        control_map[signal]
        for signal in input_signals
        if signal in control_map
    ]
    if normalized_event == "extension_health_status":
        related_controls = ["CTRL-TENANT-ISO-001"]
        risk_category = "runtime_surface"
    if not related_controls and normalized_event in {"prompt_blocked", "prompt_held", "clipboard_paste_detected", "file_upload_detected"}:
        related_controls = ["CTRL-INPUT-001"]
    if normalized_event in {"browser_automation_detected", "browser_automation_blocked"}:
        related_controls = _uniq_sorted_strings([*related_controls, "CTRL-TENANT-ISO-001", "CTRL-INPUT-001"])
    if normalized_event == "browser_automation_action":
        related_controls = _uniq_sorted_strings([*related_controls, "CTRL-BROWSER-AUTOMATION-001"])
    if normalized_event in meeting_events:
        meeting_controls = ["CTRL-MEETING-AI-NOTETAKER-001"]
        if normalized_event == "meeting_ai_notetaker_oauth_detected":
            meeting_controls.append("CTRL-SAAS-OAUTH-001")
        if normalized_event == "meeting_transcription_policy_violation":
            meeting_controls.append("CTRL-MEETING-TRANSCRIPTION-001")
        related_controls = _uniq_sorted_strings([*related_controls, *meeting_controls])

    action_hint = str(action_taken or normalized_event).replace("_", " ")
    recommended_action = (
        f"Browser interaction {action_hint} for {domain}. Review prompt content, enforce approved tool policy, and run targeted validation."
    )
    if intent_finding_type:
        recommended_action = (
            "Intent-aware AI action control triggered. Review the intent, content sensitivity, attempted action, "
            "and evidence payload to confirm whether the action should remain blocked or move to a scoped exception."
        )
    if platform_mode == "discovery" and normalized_event != "prompt_blocked":
        recommended_action = (
            f"Monitor-first posture active for {domain}. Coach user behavior, validate policy scope, and escalate if repeated."
        )
    if normalized_event == "browser_automation_detected":
        risk_category = "browser_automation"
        recommended_action = (
            "AI browser automation detected in an authenticated browser session. "
            "Restrict automation permissions, review extension allowlist, and require explicit approval for sensitive sites."
        )
    if normalized_event == "browser_automation_blocked":
        risk_category = "browser_automation"
        recommended_action = (
            "Automated browser action was blocked. Review suspected agent extension/client, "
            "revoke session if needed, and enforce approved-browser-automation policy."
        )
    if finding_type == "BROWSER_AUTOMATION_DETECTED" and normalized_event == "browser_automation_blocked":
        finding_type = "HIGH_RISK_BROWSER_AUTOMATION_ACTION"
    if finding_type == "BROWSER_AUTOMATION_DETECTED" and automation_source == "suspected_local_agent":
        finding_type = "LOCAL_AGENT_BROWSER_AUTOMATION_SUSPECTED"
    if normalized_event in meeting_events:
        provider = signal_map.get("notetaker_provider") or "unknown_notetaker"
        label = signal_map.get("notetaker_label") or provider
        surface = signal_map.get("meeting_surface") or domain or "meeting"
        control_mode = signal_map.get("control_mode") or "external_required"
        signal_source = signal_map.get("meeting_signal_source") or ("visible_participant" if signal_map.get("participant_visible") == "true" else "browser")
        if finding_type == "AI_NOTETAKER_DETECTED":
            recommended_action = (
                f"AI notetaker {label} detected on {surface}. Warn participants, validate meeting sensitivity, "
                "and remove the notetaker where the meeting platform exposes host/admin controls."
            )
        elif finding_type == "UNAPPROVED_AI_NOTETAKER":
            recommended_action = (
                f"User requested removal or blocking of AI notetaker {label}. Current control mode is {control_mode}; "
                "trigger Microsoft/Google meeting removal if connector permissions are configured, otherwise guide the host to remove it."
            )
        elif finding_type == "HIDDEN_NOTETAKER_SUSPECTED":
            recommended_action = (
                f"Hidden or non-visible AI notetaker evidence detected from {signal_source}. Correlate calendar invitees, "
                "attendance reports, OAuth grants, and recording/transcription artifacts before claiming inline removal."
            )
        elif finding_type == "OAUTH_NOTETAKER_APP_OVER_SCOPED":
            recommended_action = (
                f"OAuth/app permission evidence suggests {label} may access meeting content. Review consent, revoke app grants "
                "or tokens through Microsoft/Google admin controls, and restrict future notetaker usage."
            )
        elif finding_type == "DEVICE_AUDIO_NOTETAKER_SUSPECTED":
            recommended_action = (
                f"Local/device AI notetaker {label} detected from endpoint audio/process signals on {surface}. "
                "Hawk did not capture raw audio. Terminate the same-user recorder where endpoint policy allows, "
                "revoke microphone permission through MDM/TCC, and block known egress domains if configured."
            )
        elif finding_type == "DEVICE_AUDIO_NOTETAKER_CONTROL_APPLIED":
            recommended_action = (
                f"Endpoint control was triggered for local AI notetaker {label}. Verify process termination, "
                "mic/egress actions, review evidence, and enforce managed endpoint policy for repeat attempts."
            )
        elif finding_type == "MEETING_TRANSCRIPTION_POLICY_VIOLATION":
            recommended_action = (
                f"Meeting transcription or recording policy risk detected on {surface}. Disable transcription/recording where supported "
                "or require documented business approval."
            )

    policy_version_fk = _resolve_policy_version_fk(
        db,
        tenant_id=tenant_id,
        reported_policy_version_id=policy_version_id,
    )
    dedupe = _dedupe_key(
        "browser_interaction",
        domain,
        normalized_event,
        policy_version_id or "",
        ",".join(input_signals),
        action_hint,
        decision,
        action_type or "",
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface=source_surface,
        ai_tool=domain or "browser_ai_tool",
        ai_system_id=ai_system_id,
        user_id=_safe_user_id(user_id),
        department=None,
        severity=severity,
        finding_type=finding_type,
        risk_category=risk_category,
        data_classification="sensitive" if "sensitive_data_pattern" in input_signals else None,
        decision=decision,
        policy_id=_safe_fk_text(policy_version_id, max_len=64),
        recommended_action=recommended_action,
        policy_version_id=policy_version_fk,
        evidence_node_ids=[evidence_node_id] if evidence_node_id else [],
        related_control_ids=_uniq_sorted_strings(related_controls),
        dedupe_key=dedupe,
    )


def generate_runtime_intelligence_finding(
    db: Session,
    *,
    tenant_id: str,
    source_surface: str,
    ai_tool: str,
    ai_system_id: str | None,
    user_id: str | None,
    agent_id: str | None,
    machine_id: str | None,
    policy_version_id: str | None,
    finding_type: str,
    risk_category: str,
    severity: str,
    reason_code: str,
    repeated_count: int,
    evidence_node_ids: list[str],
    related_event_ids: list[str],
    related_control_ids: list[str],
    recommended_action: str,
) -> Finding:
    dedupe = _dedupe_key(
        "runtime_intelligence",
        ai_system_id or "",
        finding_type,
        ai_tool,
        reason_code,
        ",".join(_uniq_sorted_strings(related_control_ids)),
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface=source_surface,
        ai_tool=ai_tool,
        ai_system_id=ai_system_id,
        user_id=_safe_user_id(user_id),
        agent_id=(str(agent_id).strip() if agent_id else None),
        machine_id=(str(machine_id).strip() if machine_id else None),
        department=None,
        severity=severity,
        finding_type=finding_type,
        risk_category=risk_category,
        data_classification=None,
        recommended_action=(f"{recommended_action} (repeat_count={max(1, int(repeated_count))})").strip(),
        policy_version_id=policy_version_id,
        evidence_node_ids=evidence_node_ids,
        related_event_ids=related_event_ids,
        related_control_ids=related_control_ids,
        dedupe_key=dedupe,
    )


def generate_unprotected_path_finding(
    db: Session,
    *,
    tenant_id: str,
    source_surface: str,
    finding_type: str,
    ai_tool: str,
    application: str,
    provider: str | None,
    tool_name: str | None,
    path_fingerprint: str,
    user_id: str | None,
    agent_id: str | None,
    machine_id: str | None,
    policy_version_id: str | None,
    evidence_node_id: str,
    runtime_event_id: str,
    recommended_action: str,
) -> Finding:
    """Persist one tenant- and path-bound finding for observed gateway bypass telemetry."""

    dedupe = _dedupe_key(
        "unprotected_path",
        finding_type,
        user_id or "",
        agent_id or "",
        machine_id or "",
        ai_tool,
        provider or "",
        tool_name or "",
        path_fingerprint,
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface=source_surface,
        ai_tool=ai_tool,
        ai_system_id=None,
        user_id=_safe_user_id(user_id),
        agent_id=(str(agent_id).strip() if agent_id else None),
        machine_id=(str(machine_id).strip() if machine_id else None),
        application=application,
        department=None,
        severity="high",
        finding_type=finding_type,
        risk_category="unprotected_path",
        data_classification=None,
        decision="warn",
        recommended_action=recommended_action,
        policy_version_id=policy_version_id,
        evidence_node_ids=[evidence_node_id],
        related_event_ids=[runtime_event_id],
        related_control_ids=["SHADOW_AI_DETECTION"],
        related_runtime_event_id=runtime_event_id,
        dedupe_key=dedupe,
    )


def generate_data_transfer_finding(
    db: Session,
    *,
    tenant_id: str,
    source_surface: str,
    ai_tool: str,
    ai_system_id: str | None,
    user_id: str | None,
    policy_version_id: str | None,
    finding_type: str,
    severity: str,
    risk_category: str,
    source_classification_hint: str,
    destination_surface_type: str,
    destination_domain: str,
    decision: str,
    evidence_node_ids: list[str],
    related_control_ids: list[str],
    recommended_action: str,
) -> Finding:
    dedupe = _dedupe_key(
        "data_transfer",
        tenant_id,
        finding_type,
        destination_domain,
        source_classification_hint,
        destination_surface_type,
        decision,
        policy_version_id or "",
    )
    recommendation = (
        recommended_action
        or "Review data movement attempt, validate destination governance state, and tighten runtime controls where needed."
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface=source_surface if source_surface in ALLOWED_SOURCE_SURFACES else "browser",
        ai_tool=ai_tool or destination_domain or "browser_data_transfer",
        ai_system_id=ai_system_id,
        user_id=_safe_user_id(user_id),
        department=None,
        severity=severity,
        finding_type=finding_type,
        risk_category=risk_category or "data_transfer",
        data_classification=source_classification_hint if source_classification_hint in {"protected", "public"} else None,
        recommended_action=recommendation,
        policy_version_id=policy_version_id,
        evidence_node_ids=evidence_node_ids,
        related_control_ids=related_control_ids,
        dedupe_key=dedupe,
    )


def generate_unregistered_ai_system_finding(
    db: Session,
    *,
    tenant_id: str,
    source_surface: str,
    ai_tool: str,
    requested_ai_system_id: str | None,
    policy_version_id: str | None,
    evidence_node_ids: list[str],
    related_control_ids: list[str] | None = None,
    recommended_action: str | None = None,
) -> Finding | None:
    if _should_suppress_placeholder_unregistered_ai_system(
        source_surface=source_surface,
        ai_tool=ai_tool,
        requested_ai_system_id=requested_ai_system_id,
        recommended_action=recommended_action,
    ):
        log_structured(
            "unregistered_ai_system_placeholder_suppressed",
            module="findings_service",
            tenant_id=tenant_id,
            source_surface=source_surface,
            ai_tool=ai_tool,
        )
        return None

    dedupe = _dedupe_key(
        "unregistered_ai_system",
        tenant_id,
        source_surface,
        requested_ai_system_id or "",
        ai_tool,
    )
    policy_version_fk = _resolve_policy_version_fk(
        db,
        tenant_id=tenant_id,
        reported_policy_version_id=policy_version_id,
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface=source_surface if source_surface in ALLOWED_SOURCE_SURFACES else "monitoring",
        ai_tool=ai_tool or "unknown_ai_system",
        ai_system_id=None,
        user_id=None,
        department=None,
        severity="high",
        finding_type="unregistered_ai_system",
        risk_category="governance",
        data_classification=None,
        recommended_action=(
            recommended_action
            or "Unknown AI usage detected. Route to governance, register Trust Center record, and enforce approved policy before continued use."
        ),
        policy_version_id=policy_version_fk,
        evidence_node_ids=_uniq_sorted_strings(evidence_node_ids),
        related_control_ids=_uniq_sorted_strings(list(related_control_ids or ["CTRL-TENANT-ISO-001"])),
        dedupe_key=dedupe,
    )


def generate_shadow_ai_entity_finding(
    db: Session,
    *,
    tenant_id: str,
    entity: "ShadowAIEntity",
    finding_type: str,
    severity: str,
    source_surface: str,
    evidence_node_ids: list[str],
    related_control_ids: list[str],
    recommended_action: str,
    ai_system_id: str | None = None,
) -> Finding:
    action_map = {
        "review": "Review shadow AI entity and assign governance owner.",
        "promote": "Promote to Trust Center candidate and route governance workflow.",
        "block": "Block unsanctioned usage path and enforce remediation controls.",
        "route_to_governance": "Route to governance review and approve or reject candidate onboarding.",
    }
    dedupe = _dedupe_key(
        "shadow_ai_entity",
        tenant_id,
        entity.id,
        finding_type,
        source_surface,
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface=source_surface,
        ai_tool=entity.canonical_name,
        ai_system_id=ai_system_id or entity.linked_ai_system_id,
        user_id=None,
        department=None,
        severity=severity,
        finding_type=finding_type,
        risk_category="shadow_ai",
        data_classification=None,
        recommended_action=action_map.get(recommended_action, recommended_action),
        policy_version_id=None,
        evidence_node_ids=evidence_node_ids,
        related_control_ids=related_control_ids,
        dedupe_key=dedupe,
    )


def generate_agent_action_finding(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    agent_id: str | None,
    action_type: str,
    tool_name: str | None,
    target_resource: str | None,
    decision: str,
    reason_code: str,
    policy_version_id: str | None,
    evidence_node_ids: list[str],
    related_control_ids: list[str] | None = None,
    recommended_action: str | None = None,
) -> Finding:
    normalized_decision = str(decision or "").strip().lower()
    finding_type = {
        "block": "agent_action_blocked",
        "require_approval": "agent_action_requires_approval",
        "warn": "agent_action_warned",
    }.get(normalized_decision, "agent_action_flagged")
    severity = {
        "block": "high",
        "require_approval": "high",
        "warn": "med",
    }.get(normalized_decision, "med")
    dedupe = _dedupe_key(
        "agent_action",
        tenant_id,
        ai_system_id or "",
        agent_id or "",
        action_type,
        tool_name or "",
        target_resource or "",
        normalized_decision,
        reason_code,
    )
    return _upsert_finding(
        db,
        tenant_id=tenant_id,
        source_surface="aiiam",
        ai_tool=(tool_name or action_type or "agent_action"),
        ai_system_id=ai_system_id,
        user_id=None,
        department=None,
        severity=severity,
        finding_type=finding_type,
        risk_category="agent_control",
        data_classification=None,
        recommended_action=(
            recommended_action
            or "Review delegated scopes, tool permissions, and governance approvals for this agent action."
        ),
        policy_version_id=policy_version_id,
        evidence_node_ids=_uniq_sorted_strings(evidence_node_ids),
        related_control_ids=_uniq_sorted_strings(list(related_control_ids or ["CTRL-AI-IAM-001", "CTRL-TOOL-001"])),
        dedupe_key=dedupe,
    )
