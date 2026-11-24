from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from datetime import datetime, timedelta, timezone
import math
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.discovery import DiscoveryApplication
from app.db.models.finding import Finding
from app.db.models.monitoring import Connector, MonitoringSignal
from app.db.models.policy import ApprovalRequest
from app.db.models.remediation import RemediationAction
from app.db.models.runtime_intelligence import RuntimeGovernanceRecommendation
from app.db.models.simulation import SimulationRun
from app.services.ai_iam_service import collect_delegation_descendant_agent_ids, revoke_agent_delegations
from app.services.audit_service import write_audit_log
from app.services.crq_service import compute_remediation_crq
from app.services.discovery_service import tool_key_for_name
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.action_integrity.execution_authority import install_generic_seam_authority, invoke_final_seam
from app.services.action_integrity.canonical_v2 import domain_hash
from app.services.policy_service import tighten_enforcement_for_failed_controls


SAFE_AUTO_APPLY_REMEDIATION_TYPES = {
    "policy_tighten",
    "permission_reduce",
    "connector_disable",
    "source_quarantine",
    "trust_center_escalation",
    "ticket_create",
}

ALLOWED_STATUSES = {"proposed", "applied", "rejected", "rolled_back", "failed"}
ALLOWED_ACTION_MODES = {"recommend_only", "auto_apply"}

TRIGGER_MODULE_BY_TYPE = {
    "guardian_violation": "interaction_security",
    "shadow_ai_detection": "shadow_ai_discovery",
    "runtime_pattern": "runtime_intelligence",
    "simulation_failure": "control_validation",
    "drift_alert": "continuous_monitoring",
    "model_integrity_failure": "interaction_security",
    "ingestion_poisoning_indicator": "continuous_monitoring",
}

TARGET_MODULE_BY_TYPE = {
    "ai_system": "trust_center",
    "agent": "ai_iam",
    "tool": "ai_iam",
    "connector": "continuous_monitoring",
    "source": "shadow_ai_discovery",
    "policy": "interaction_security",
    "user": "interaction_security",
}


@dataclass(frozen=True)
class RemediationPlan:
    remediation_type: str
    target_type: str
    target_id: str
    source_trigger_type: str
    recommendation_text: str
    action_mode: str
    risk_level: str
    requires_approval: bool
    rollback_supported: bool
    context: dict[str, Any]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_text(value: Any, *, fallback: str = "") -> str:
    text = str(value or "").strip()
    return text or fallback


def _normalize_action_mode(value: str | None, *, fallback: str = "recommend_only") -> str:
    normalized = str(value or fallback).strip().lower()
    if normalized not in ALLOWED_ACTION_MODES:
        return fallback
    return normalized


def _normalize_status(value: str | None, *, fallback: str = "proposed") -> str:
    normalized = str(value or fallback).strip().lower()
    if normalized not in ALLOWED_STATUSES:
        return fallback
    return normalized


def _normalize_risk_level(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"critical", "high", "medium", "med", "low"}:
        if normalized == "med":
            return "medium"
        return normalized
    return "medium"


def _coerce_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return sorted({str(item).strip() for item in values if str(item).strip()})


def _safe_dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _canonical_decimal_string(value: Decimal) -> str:
    """Render a finite decimal once for canonical seam-hash material."""
    if not value.is_finite():
        raise ValueError("non-finite remediation seam numeric value")
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


def _remediation_seam_hash_material(value: Any) -> Any:
    """Copy only hash input into Canonical V2's allowed scalar vocabulary.

    Remediation execution and evidence keep their original legacy payloads;
    this adapter exists only at the closed-seam parameter-hash boundary.
    """
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, Decimal):
        return _canonical_decimal_string(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite remediation seam numeric value")
        return _canonical_decimal_string(Decimal(str(value)))
    if isinstance(value, list):
        return [_remediation_seam_hash_material(item) for item in value]
    if isinstance(value, dict):
        return {key: _remediation_seam_hash_material(item) for key, item in value.items()}
    return value


def _requires_approval(
    *,
    remediation_type: str,
    risk_level: str,
    context: dict[str, Any],
) -> bool:
    if bool(getattr(settings, "remediation_high_risk_requires_approval", True)) and _risk_rank(risk_level) >= _risk_rank("high"):
        return True
    if bool(context.get("regulated")) or bool(context.get("irreversible")):
        return True
    if remediation_type == "connector_disable" and bool(context.get("permanent")):
        return True
    if remediation_type == "permission_reduce" and bool(context.get("business_critical")):
        return True
    if remediation_type == "trust_center_escalation" and bool(context.get("broad_scope_change")):
        return True
    if remediation_type in {"agent_suspend", "kill_switch"} and bool(context.get("high_business_impact")):
        return True
    return False


def _risk_rank(value: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(_normalize_risk_level(value), 2)


def _prefer_higher_risk(left: str, right: str) -> str:
    return left if _risk_rank(left) >= _risk_rank(right) else right


def _normalize_repeat_count(value: Any, *, fallback: int = 1) -> int:
    try:
        parsed = int(value)
    except Exception:
        return max(1, fallback)
    return max(1, parsed)


def _infer_shadow_ai_type(context: dict[str, Any]) -> str:
    explicit = _normalize_text(context.get("ai_type")).lower()
    if explicit:
        return explicit
    endpoint = _normalize_text(context.get("api_endpoint")).lower()
    domain = _normalize_text(context.get("domain")).lower()
    tool_name = _normalize_text(context.get("tool_name") or context.get("ai_tool")).lower()
    value = " ".join(item for item in [endpoint, domain, tool_name] if item)
    if any(token in value for token in {"api.", "/v1/", "model", "responses", "completions"}):
        return "model_api"
    if any(token in value for token in {"agent", "copilot", "assistant"}):
        return "copilot"
    return "saas_ai"


def _infer_shadow_data_access(context: dict[str, Any]) -> str:
    explicit = _normalize_text(context.get("data_access")).lower()
    if explicit:
        return explicit
    data_classification = _normalize_text(context.get("data_classification")).lower()
    if data_classification in {"sensitive", "protected", "restricted", "confidential", "regulated"}:
        return "sensitive"
    if bool(context.get("contains_sensitive")):
        return "sensitive"
    return "unknown"


def _map_finding_to_trigger_type(finding_type: str) -> str:
    normalized = str(finding_type or "").strip().lower()
    if normalized in {"shadow_ai_discovery", "unregistered_ai_system"} or normalized.startswith("shadow_ai"):
        return "shadow_ai_detection"
    if normalized in {"drift_alert", "connector_health_drift"}:
        return "drift_alert"
    if normalized in {
        "repeated_prompt_injection_attempts",
        "repeated_tool_denials",
        "asymmetry_risk_spike",
        "unknown_ai_adoption_spike",
        "repeated_sensitive_data_attempts",
        "multi_tool_data_exposure",
    }:
        return "runtime_pattern"
    if normalized in {"model_integrity_failure", "model_integrity_anomaly"}:
        return "model_integrity_failure"
    if normalized in {"ingestion_poisoning_indicator", "rag_poisoning_signal"}:
        return "ingestion_poisoning_indicator"
    return "guardian_violation"


def _default_target_for_finding(finding: Finding, context: dict[str, Any]) -> tuple[str, str]:
    explicit_target_type = _normalize_text(context.get("target_type")).lower()
    explicit_target_id = _normalize_text(context.get("target_id"))
    if explicit_target_type and explicit_target_id:
        return explicit_target_type, explicit_target_id
    if str(context.get("agent_id") or "").strip():
        return "agent", str(context["agent_id"]).strip()
    if str(context.get("connector_id") or "").strip():
        return "connector", str(context["connector_id"]).strip()
    if str(finding.ai_system_id or "").strip():
        return "ai_system", str(finding.ai_system_id)
    tool_key = _normalize_text(context.get("domain") or finding.ai_tool, fallback="unknown_source")
    return "source", tool_key


def _build_plan_for_trigger(
    *,
    source_trigger_type: str,
    source_trigger_id: str,
    target_type: str,
    target_id: str,
    severity: str,
    context: dict[str, Any],
) -> RemediationPlan:
    trigger = _normalize_text(source_trigger_type, fallback="guardian_violation").lower()
    risk_level = _normalize_risk_level(severity)
    finding_type = _normalize_text(context.get("finding_type")).lower()
    reason_code = _normalize_text(context.get("reason_code")).lower()
    occurrence_count = int(context.get("occurrence_count") or 1)
    repeat_threshold = max(2, int(settings.runtime_intelligence_repeat_threshold or 3))
    model_integrity_signal = "model_integrity" in reason_code or "model_integrity" in finding_type
    ingestion_signal = "poison" in reason_code or "poison" in finding_type
    tool_abuse_signal = (
        "tool" in reason_code
        or "tool" in finding_type
        or reason_code in {"unauthorized_tool", "denied_tool_action", "restricted_tool"}
        or finding_type in {"agent_action_blocked", "agent_action_requires_approval"}
    )
    unauthorized_tool_signal = reason_code in {"tool_not_allowed", "unauthorized_tool", "denied_tool_action", "restricted_tool"}
    drift_signal = (
        bool(context.get("privilege_drift_detected"))
        or "drift" in reason_code
        or "anomaly" in reason_code
        or reason_code in {"agent_behavior_anomaly_requires_approval", "privilege_drift_detected"}
        or finding_type in {"agent_behavior_anomaly", "agent_privilege_drift"}
    )
    delegation_misuse_signal = (
        bool(context.get("delegation_misuse"))
        or reason_code in {
            "delegation_scope_abuse",
            "agent_token_mismatch",
            "delegation_chain_token_agent_mismatch",
        }
        or ("delegation" in reason_code and "misuse" in reason_code)
    )
    chain_attack_signal = (
        "chain" in reason_code
        or "chain" in finding_type
        or "delegation" in reason_code
        or reason_code in {"chain_depth_exceeded", "agent_impersonation", "agent_chain_attack"}
    )
    sensitive_exfil_signal = (
        "sensitive" in reason_code
        or "exfil" in reason_code
        or finding_type in {
            "sensitive_data_to_public_ai_attempt",
            "sensitive_data_external_transfer_attempt",
            "repeated_sensitive_data_attempts",
        }
        or bool(context.get("contains_sensitive"))
    )
    upload_signal = (
        "upload" in reason_code
        or "upload" in finding_type
        or reason_code in {"ocr_sensitive_upload", "sensitive_file_upload"}
    )
    evidence_gap_signal = (
        bool(context.get("missing_evidence_detected"))
        or bool(context.get("evidence_missing"))
        or bool(context.get("require_revalidation"))
        or "evidence" in reason_code
        or "coverage" in reason_code
    )
    connector_risk_signal = bool(context.get("connector_risk_exposed")) or "connector_risk" in reason_code
    trust_center_lifecycle_signal = reason_code in {
        "trust_center_lifecycle_prereq_missing",
        "trust_center_owner_missing",
    } or finding_type in {"trust_center_lifecycle_block", "trust_center_ownership_missing"}
    trust_center_risk_signal = reason_code in {
        "runtime_or_monitoring_risk_escalation",
        "trust_center_risk_escalation",
    } or finding_type == "trust_center_risk_escalation"

    remediation_type = "policy_tighten"
    recommendation_text = "Tighten active policy controls for repeated incident patterns."
    action_mode = "recommend_only"
    rollback_supported = False

    if trust_center_lifecycle_signal:
        remediation_type = "trust_center_escalation"
        recommendation_text = (
            "Trust Center lifecycle prerequisites are unmet. Enforce restricted/review posture and require ownership/policy completion."
        )
        action_mode = "recommend_only"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif trust_center_risk_signal:
        remediation_type = "trust_center_escalation"
        recommendation_text = (
            "Risk escalation detected from runtime/monitoring. Enforce stricter governance posture and require re-approval."
        )
        action_mode = "recommend_only"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif trigger == "shadow_ai_detection":
        if occurrence_count >= 3:
            remediation_type = "trust_center_escalation"
            recommendation_text = (
                "Repeated unknown AI usage detected. Enforce stricter blocking, notify admins, and require justification before similar usage continues."
            )
            action_mode = "auto_apply"
            rollback_supported = True
            risk_level = _prefer_higher_risk(risk_level, "high")
            context["strict_unknown_usage_blocking"] = True
            context["notify_admin"] = True
            context["require_justification"] = True
            context["repeated_shadow_usage"] = True
        else:
            remediation_type = "trust_center_escalation"
            recommendation_text = (
                "Escalate unknown AI usage to Trust Center, move posture to restricted/review, and enforce pending registration."
            )
            action_mode = "auto_apply" if settings.governance_strict_mode else "recommend_only"
            rollback_supported = True
    elif trigger == "drift_alert":
        if connector_risk_signal and _normalize_text(target_type).lower() == "connector":
            remediation_type = "connector_disable"
            recommendation_text = "Connector risk exposure detected. Restrict connector permissions and disable high-risk actions."
            action_mode = "auto_apply"
            rollback_supported = True
            risk_level = _prefer_higher_risk(risk_level, "high")
            context["disable_high_risk_actions"] = True
            context["restrict_permissions"] = True
        elif bool(context.get("control_drift_detected")):
            remediation_type = "policy_tighten"
            recommendation_text = (
                "Control drift detected. Mark control non-compliant and tighten policy until remediation validation passes."
            )
            action_mode = "auto_apply"
            rollback_supported = False
            risk_level = _prefer_higher_risk(risk_level, "high")
            context["mark_non_compliant"] = True
        elif evidence_gap_signal:
            remediation_type = "policy_tighten"
            recommendation_text = "Evidence coverage weakened. Flag control and require re-validation before restoring posture."
            action_mode = "auto_apply"
            rollback_supported = False
            risk_level = _prefer_higher_risk(risk_level, "high")
            context["require_revalidation"] = True
        else:
            remediation_type = "ticket_create"
            recommendation_text = "Open ITSM ticket for connector/control drift and attach evidence lineage."
            action_mode = "auto_apply"
            rollback_supported = False
    elif trigger == "simulation_failure":
        if occurrence_count >= 3:
            remediation_type = "require_step_up"
            recommendation_text = (
                "Repeated simulation failures detected. Require approval for remediation rollout and block high-risk deployment transitions."
            )
            action_mode = "recommend_only"
            rollback_supported = False
            risk_level = _prefer_higher_risk(risk_level, "critical")
            context["regulated"] = True
        else:
            remediation_type = "policy_tighten"
            recommendation_text = (
                "Simulation failure detected. Tighten policy strictness and schedule targeted validation rerun."
            )
            action_mode = "auto_apply"
            rollback_supported = False
            risk_level = _prefer_higher_risk(risk_level, "high")
    elif trigger == "runtime_pattern":
        if chain_attack_signal and occurrence_count >= 5:
            remediation_type = "kill_switch"
            recommendation_text = "Critical chained agent attack pattern detected. Trigger kill switch and revoke downstream capabilities."
            action_mode = "recommend_only"
            rollback_supported = False
            risk_level = "critical"
        elif delegation_misuse_signal:
            remediation_type = "permission_reduce"
            recommendation_text = (
                "Delegated authority misuse detected. Reduce capabilities, revoke active delegations, and enforce strict allowlist controls."
            )
            action_mode = "auto_apply"
            rollback_supported = True
            risk_level = _prefer_higher_risk(risk_level, "high")
            context["revoke_delegations"] = True
            context["escalate_aiiam"] = True
        elif drift_signal:
            remediation_type = "permission_reduce"
            recommendation_text = (
                "Privilege drift detected against behavioral baseline. Reduce permissions and require supervised execution."
            )
            action_mode = "auto_apply"
            rollback_supported = True
            risk_level = _prefer_higher_risk(risk_level, "high")
            context["privilege_drift_detected"] = True
        elif chain_attack_signal and occurrence_count >= 3:
            remediation_type = "agent_suspend"
            recommendation_text = "Repeated chained attack activity detected. Suspend agent identity and require governance review."
            action_mode = "recommend_only"
            rollback_supported = False
            risk_level = _prefer_higher_risk(risk_level, "high")
        elif tool_abuse_signal and occurrence_count >= 3:
            remediation_type = "permission_reduce"
            recommendation_text = "Repeated tool misuse detected. Reduce tool permissions and enforce stricter allowlist controls."
            action_mode = "auto_apply"
            rollback_supported = True
            risk_level = _prefer_higher_risk(risk_level, "high")
        elif sensitive_exfil_signal and occurrence_count >= repeat_threshold:
            remediation_type = "require_step_up"
            recommendation_text = "Sensitive data exposure pattern repeated. Require step-up approval for future actions."
            action_mode = "recommend_only"
            rollback_supported = False
            risk_level = _prefer_higher_risk(risk_level, "high")
        elif sensitive_exfil_signal:
            remediation_type = "policy_tighten"
            recommendation_text = "Sensitive data exposure pattern detected. Tighten policy strictness and enforce step-up for similar flows."
            action_mode = "auto_apply"
            rollback_supported = False
            risk_level = _prefer_higher_risk(risk_level, "high")
        else:
            remediation_type = "require_step_up"
            recommendation_text = "Require step-up approval for the next similar high-risk action sequence."
            action_mode = "recommend_only"
            rollback_supported = False
    elif trigger == "model_integrity_failure" or model_integrity_signal:
        remediation_type = "trust_center_escalation"
        recommendation_text = (
            "Model integrity failure detected. Restrict affected AI system and require governance review before reuse."
        )
        action_mode = "auto_apply"
        rollback_supported = True
        risk_level = "critical"
    elif trigger == "ingestion_poisoning_indicator" or ingestion_signal:
        remediation_type = "source_quarantine"
        recommendation_text = "Quarantine suspicious source and remove ingestion allowlist on repeated poisoning indicators."
        action_mode = "auto_apply"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif upload_signal and sensitive_exfil_signal:
        remediation_type = "source_quarantine"
        recommendation_text = "Sensitive file upload path detected. Block upload source and quarantine pending governance review."
        action_mode = "auto_apply"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif (
        chain_attack_signal
        and reason_code in {"chain_depth_exceeded", "delegation_chain_depth_mismatch"}
        and occurrence_count >= 3
    ):
        remediation_type = "permission_reduce"
        recommendation_text = (
            "Repeated chain-depth violations detected. Reduce agent capabilities and enforce stricter execution scope."
        )
        action_mode = "auto_apply"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif chain_attack_signal and occurrence_count >= 5:
        remediation_type = "kill_switch"
        recommendation_text = "Critical chained attack persisted. Trigger kill switch and terminate delegated authority."
        action_mode = "recommend_only"
        rollback_supported = False
        risk_level = "critical"
    elif chain_attack_signal and occurrence_count >= 3:
        remediation_type = "agent_suspend"
        recommendation_text = "Multi-step attack behavior detected. Suspend affected agent and route to AI IAM remediation."
        action_mode = "recommend_only"
        rollback_supported = False
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif unauthorized_tool_signal:
        remediation_type = "permission_reduce"
        recommendation_text = "Unauthorized tool usage detected. Remove offending tool capability and enforce strict allowlist."
        action_mode = "auto_apply"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
        context["escalate_aiiam"] = True
    elif delegation_misuse_signal:
        remediation_type = "permission_reduce"
        recommendation_text = "Delegation misuse detected. Revoke delegation path and reduce capabilities for affected agent."
        action_mode = "auto_apply"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
        context["revoke_delegations"] = True
        context["escalate_aiiam"] = True
    elif drift_signal:
        remediation_type = "permission_reduce"
        recommendation_text = "Privilege drift detected. Reduce agent permissions and enforce stricter action scope."
        action_mode = "auto_apply"
        rollback_supported = True
        risk_level = _prefer_higher_risk(risk_level, "high")
        context["privilege_drift_detected"] = True
    elif occurrence_count >= 3 and tool_abuse_signal:
        remediation_type = "permission_reduce"
        recommendation_text = "Repeated unauthorized tool actions detected. Reduce agent capabilities and action scope."
        action_mode = "auto_apply"
        rollback_supported = True
    elif sensitive_exfil_signal and occurrence_count >= repeat_threshold:
        remediation_type = "require_step_up"
        recommendation_text = "Repeated sensitive-data movement attempts detected. Require step-up approval for subsequent attempts."
        action_mode = "recommend_only"
        rollback_supported = False
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif sensitive_exfil_signal:
        remediation_type = "policy_tighten"
        recommendation_text = "Repeated sensitive-data movement attempts detected. Increase guard strictness for destination controls."
        action_mode = "auto_apply"
        rollback_supported = False
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif occurrence_count >= repeat_threshold:
        remediation_type = "policy_tighten"
        recommendation_text = "Repeated violation threshold exceeded. Tighten guardian policy strictness for this target."
        action_mode = "auto_apply"
        rollback_supported = False
        risk_level = _prefer_higher_risk(risk_level, "high")
    elif evidence_gap_signal:
        remediation_type = "policy_tighten"
        recommendation_text = "Evidence missing for monitored controls. Mark non-compliant and require re-validation."
        action_mode = "auto_apply"
        rollback_supported = False
        risk_level = _prefer_higher_risk(risk_level, "high")
        context["mark_non_compliant"] = True
        context["require_revalidation"] = True

    if remediation_type not in SAFE_AUTO_APPLY_REMEDIATION_TYPES:
        action_mode = "recommend_only"
    if not settings.remediation_auto_apply_enabled:
        action_mode = "recommend_only"

    requires_approval = _requires_approval(
        remediation_type=remediation_type,
        risk_level=risk_level,
        context=context,
    )

    return RemediationPlan(
        remediation_type=remediation_type,
        target_type=_normalize_text(target_type, fallback="source"),
        target_id=_normalize_text(target_id, fallback="unknown"),
        source_trigger_type=trigger,
        recommendation_text=recommendation_text,
        action_mode=_normalize_action_mode(action_mode, fallback="recommend_only"),
        risk_level=risk_level,
        requires_approval=requires_approval,
        rollback_supported=bool(rollback_supported),
        context={
            **_safe_dict(context),
            "source_trigger_id": source_trigger_id,
            "source_trigger_type": trigger,
        },
    )


def _find_existing_action(
    db: Session,
    *,
    tenant_id: str,
    plan: RemediationPlan,
    source_trigger_id: str,
) -> RemediationAction | None:
    return db.scalar(
        select(RemediationAction)
        .where(
            RemediationAction.tenant_id == tenant_id,
            RemediationAction.source_trigger_type == plan.source_trigger_type,
            RemediationAction.source_trigger_id == source_trigger_id,
            RemediationAction.remediation_type == plan.remediation_type,
            RemediationAction.target_type == plan.target_type,
            RemediationAction.target_id == plan.target_id,
            RemediationAction.status.in_(["proposed", "applied"]),
        )
        .order_by(RemediationAction.created_at.desc())
    )


def _append_finding_remediation(
    db: Session,
    *,
    finding_id: str | None,
    remediation_id: str,
    remediation_evidence_node_id: str | None,
) -> None:
    finding_id_norm = _normalize_text(finding_id)
    if not finding_id_norm:
        return
    finding = db.scalar(select(Finding).where(Finding.finding_id == finding_id_norm))
    if finding is None:
        return
    existing_ids = _coerce_list(finding.remediation_action_ids or [])
    if remediation_id not in existing_ids:
        existing_ids.append(remediation_id)
    finding.remediation_action_ids = sorted(set(existing_ids))
    if remediation_evidence_node_id:
        evidence_ids = _coerce_list(finding.evidence_node_ids or [])
        evidence_ids.append(remediation_evidence_node_id)
        finding.evidence_node_ids = sorted(set(evidence_ids))
    db.flush()


def _resolve_trigger_evidence_ids(
    db: Session,
    *,
    source_trigger_type: str,
    source_trigger_id: str,
    context: dict[str, Any],
) -> list[str]:
    explicit_ids = _coerce_list(context.get("evidence_node_ids"))
    if explicit_ids:
        return explicit_ids

    trigger_type = _normalize_text(source_trigger_type).lower()
    if trigger_type == "guardian_violation":
        finding = db.scalar(select(Finding).where(Finding.finding_id == source_trigger_id))
        if finding is not None:
            return _coerce_list(finding.evidence_node_ids)
    if trigger_type == "simulation_failure":
        run = db.scalar(select(SimulationRun).where(SimulationRun.id == source_trigger_id))
        if run is not None:
            return _coerce_list(_safe_dict(run.results).get("evidence_node_ids"))
    if trigger_type == "runtime_pattern":
        recommendation = db.scalar(
            select(RuntimeGovernanceRecommendation).where(
                RuntimeGovernanceRecommendation.recommendation_id == source_trigger_id
            )
        )
        if recommendation is not None:
            return _coerce_list(_safe_dict(recommendation.payload).get("evidence_node_ids"))
    if trigger_type == "drift_alert":
        signal = db.scalar(select(MonitoringSignal).where(MonitoringSignal.id == source_trigger_id))
        if signal is not None:
            return _coerce_list(_safe_dict(signal.payload).get("evidence_node_ids"))
    return []


def _create_remediation_evidence_node(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    status: str,
    payload: dict[str, Any],
) -> str:
    row = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="remediation_action",
        signal_type=f"remediation.{status}",
        label=f"Remediation {status}: {remediation.remediation_type}",
        payload=payload,
        correlation_id=remediation.id,
    )
    return row.id


def _source_module_for_trigger(source_trigger_type: str) -> str:
    normalized = _normalize_text(source_trigger_type, fallback="guardian_violation").lower()
    return TRIGGER_MODULE_BY_TYPE.get(normalized, "interaction_security")


def _receiver_modules_for_target(target_type: str) -> list[str]:
    modules = {
        TARGET_MODULE_BY_TYPE.get(_normalize_text(target_type, fallback="source").lower(), "interaction_security"),
        "automated_auditor",
        "continuous_monitoring",
        "runtime_intelligence",
    }
    return sorted(module for module in modules if str(module).strip())


def _emit_remediation_lifecycle_signal(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    status: str,
    context: dict[str, Any] | None = None,
    evidence_node_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> str | None:
    if not bool(getattr(settings, "remediation_emit_lifecycle_signals", True)):
        return None

    lifecycle_phase = _normalize_text(status, fallback="proposed").lower()
    remediation_status = _normalize_status(remediation.status, fallback="proposed")
    context_payload = _safe_dict(context)
    ai_system_id = (
        remediation.target_id
        if _normalize_text(remediation.target_type).lower() == "ai_system"
        else _normalize_text(context_payload.get("ai_system_id")) or None
    )
    payload = {
        "remediation_id": remediation.id,
        "remediation_type": remediation.remediation_type,
        "target_type": remediation.target_type,
        "target_id": remediation.target_id,
        "source_trigger_type": remediation.source_trigger_type,
        "source_trigger_id": remediation.source_trigger_id,
        "risk_level": remediation.risk_level,
        "action_mode": remediation.action_mode,
        "requires_approval": bool(remediation.requires_approval),
        "approved_by": remediation.approved_by,
        "phase": lifecycle_phase,
        "status": remediation_status,
        "source_module": _source_module_for_trigger(remediation.source_trigger_type),
        "receiver_modules": _receiver_modules_for_target(remediation.target_type),
        "correlation_id": remediation.id,
        "ai_system_id": ai_system_id,
        "agent_id": (
            remediation.target_id
            if _normalize_text(remediation.target_type).lower() == "agent"
            else _normalize_text(context_payload.get("agent_id")) or None
        ),
        "reason_code": _normalize_text(context_payload.get("reason_code")),
        "related_control_ids": _coerce_list(context_payload.get("related_control_ids")),
        "evidence_node_ids": _coerce_list(
            [
                evidence_node_id,
                *[str(node_id) for node_id in (context_payload.get("evidence_node_ids") or []) if str(node_id).strip()],
            ]
        ),
        "details": _safe_dict(details),
    }
    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        signal_type=f"remediation.lifecycle.{lifecycle_phase}",
        severity=_normalize_risk_level(remediation.risk_level),
        payload=payload,
    )
    db.add(signal)
    db.flush()
    return signal.id


def _link_trigger_to_remediation(
    db: Session,
    *,
    tenant_id: str,
    trigger_evidence_ids: list[str],
    remediation_node_id: str,
    remediation_id: str,
) -> None:
    for trigger_node_id in trigger_evidence_ids:
        try:
            link_evidence_nodes(
                db,
                tenant_id=tenant_id,
                from_node_id=trigger_node_id,
                to_node_id=remediation_node_id,
                edge_type="triggers_remediation",
                payload={"remediation_id": remediation_id},
            )
        except ValueError:
            continue


def _link_remediation_to_target(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    remediation_node_id: str,
    details: dict[str, Any],
) -> str:
    target_node = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="remediation_target",
        signal_type="remediation.target",
        label=f"Remediation target {remediation.target_type}:{remediation.target_id}",
        payload={
            "remediation_id": remediation.id,
            "target_type": remediation.target_type,
            "target_id": remediation.target_id,
            "details": details,
        },
        correlation_id=remediation.id,
    )
    link_evidence_nodes(
        db,
        tenant_id=tenant_id,
        from_node_id=remediation_node_id,
        to_node_id=target_node.id,
        edge_type="affects_target",
        payload={"remediation_id": remediation.id},
    )
    return target_node.id


def _apply_policy_tighten(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    control_ids = _coerce_list(context.get("related_control_ids"))
    occurrence_count = max(1, int(context.get("occurrence_count") or 1))
    escalation_level = max(1, min(3, 1 + (occurrence_count // 2)))
    if remediation.source_trigger_type in {"simulation_failure", "runtime_pattern"}:
        escalation_level = max(escalation_level, 2)
    updated_policy_version_ids = tighten_enforcement_for_failed_controls(
        db,
        tenant_id=tenant_id,
        control_ids=control_ids,
        reason=f"remediation:{remediation.id}:{remediation.source_trigger_type}",
        escalation_level=escalation_level,
        ai_system_id=_normalize_text(context.get("ai_system_id")) or None,
    )
    return {
        "updated_policy_version_ids": updated_policy_version_ids,
        "related_control_ids": control_ids,
        "escalation_level": escalation_level,
    }, False


def _apply_permission_reduce(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    agent_target_id = remediation.target_id if remediation.target_type == "agent" else _normalize_text(context.get("agent_id"))
    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.id == agent_target_id,
        )
    )
    if agent is None:
        raise ValueError("Agent target not found for permission reduction")

    before = {
        "tool_registry": list(agent.tool_registry or []),
        "action_scope": list(agent.action_scope or []),
        "external_system_access": list(agent.external_system_access or []),
        "max_chain_depth": int(agent.max_chain_depth),
    }
    target_tool = _normalize_text(context.get("tool_name")).lower()
    tool_registry = [str(item).strip() for item in (agent.tool_registry or []) if str(item).strip()]
    if target_tool:
        tool_registry = [item for item in tool_registry if item.lower() != target_tool]
    elif tool_registry:
        tool_registry = tool_registry[:-1]
    if not tool_registry:
        tool_registry = ["read_only_tools"]

    blocked_scopes = {"*", "api_call", "tool_execution", "email_send", "db_query", "tool.run", "tool.email_send"}
    action_scope = [
        scope
        for scope in [str(item).strip() for item in (agent.action_scope or []) if str(item).strip()]
        if scope.lower() not in blocked_scopes
    ]
    if not action_scope:
        action_scope = ["tool.read"]

    agent.tool_registry = sorted(set(tool_registry))
    agent.action_scope = sorted(set(action_scope))
    agent.max_chain_depth = max(1, int(agent.max_chain_depth) - 1)
    now = _now()
    delegations_revoked = 0
    if bool(context.get("revoke_delegations")) or bool(context.get("delegation_misuse")):
        delegations_revoked = revoke_agent_delegations(
            db,
            tenant_id=tenant_id,
            impacted_agent_identity_ids=[agent.id],
            revoked_at=now,
        )
    db.flush()

    notification_payload = {
        "event_type": "permission_reduce",
        "remediation_id": remediation.id,
        "agent_id": agent.id,
        "reason_code": _normalize_text(context.get("reason_code"), fallback="tool_permission_reduction"),
        "removed_tool": target_tool or None,
        "chain_depth_after": int(agent.max_chain_depth),
        "status": "aiiam_notified",
        "privilege_drift_detected": bool(context.get("privilege_drift_detected")),
        "delegation_misuse": bool(context.get("delegation_misuse")) or bool(context.get("revoke_delegations")),
        "delegations_revoked": delegations_revoked,
        "escalation_logged": bool(context.get("escalate_aiiam")),
    }
    signal = MonitoringSignal(
        tenant_id=tenant_id,
        ai_system_id=_normalize_text(context.get("ai_system_id")) or None,
        signal_type="aiiam.remediation.permission_reduce",
        severity="high",
        payload=notification_payload,
    )
    db.add(signal)
    db.flush()

    after = {
        "tool_registry": list(agent.tool_registry or []),
        "action_scope": list(agent.action_scope or []),
        "external_system_access": list(agent.external_system_access or []),
        "max_chain_depth": int(agent.max_chain_depth),
    }
    return {
        "before": before,
        "after": after,
        "aiiam_notification_signal_id": signal.id,
        "delegations_revoked": delegations_revoked,
        "escalation_logged": bool(context.get("escalate_aiiam")),
    }, True


def _apply_connector_disable(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.id == remediation.target_id,
        )
    )
    if connector is None:
        raise ValueError("Connector target not found")
    before = {
        "enabled": bool(connector.enabled),
        "status": str(connector.status),
        "metadata_json": dict(connector.metadata_json or {}),
    }
    connector.enabled = False
    connector.status = "degraded"
    metadata = dict(connector.metadata_json or {})
    metadata["remediation_disabled_at"] = _now().isoformat()
    metadata["cooldown_minutes"] = int(context.get("cooldown_minutes") or settings.remediation_default_cooldown_minutes)
    metadata["remediation_id"] = remediation.id
    metadata["restricted_permissions"] = bool(context.get("restrict_permissions", True))
    metadata["high_risk_actions_disabled"] = bool(context.get("disable_high_risk_actions", True))
    metadata["permission_scope"] = "restricted"
    connector.metadata_json = metadata
    db.flush()
    after = {
        "enabled": bool(connector.enabled),
        "status": str(connector.status),
        "metadata_json": dict(connector.metadata_json or {}),
    }
    return {"before": before, "after": after}, True


def _apply_source_quarantine(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    target_hint = _normalize_text(context.get("domain"), fallback=remediation.target_id)
    normalized_tool_key = tool_key_for_name(target_hint)
    app = db.scalar(
        select(DiscoveryApplication).where(
            DiscoveryApplication.tenant_id == tenant_id,
            DiscoveryApplication.id == remediation.target_id,
        )
    )
    if app is None and target_hint:
        app = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == tenant_id,
                DiscoveryApplication.tool_key == normalized_tool_key,
            )
        )
    if app is None and target_hint:
        app = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == tenant_id,
                DiscoveryApplication.tool_name == target_hint,
            )
        )
    created_shadow_source = False
    if app is None and target_hint:
        app = DiscoveryApplication(
            tenant_id=tenant_id,
            tool_key=normalized_tool_key,
            tool_name=target_hint,
            vendor="Unknown",
            status="discovered",
            metadata_json={"source": "remediation_auto_discovery", "created_by_remediation": remediation.id},
        )
        db.add(app)
        db.flush()
        created_shadow_source = True

    if app is not None:
        before = {"status": str(app.status), "metadata_json": dict(app.metadata_json or {})}
        app.status = "blocked"
        metadata = dict(app.metadata_json or {})
        metadata["quarantined"] = True
        metadata["watchlist"] = True
        metadata["watchlist_added_at"] = _now().isoformat()
        metadata["quarantine_reason"] = _normalize_text(context.get("reason_code"), fallback="ingestion_risk")
        metadata["remediation_id"] = remediation.id
        app.metadata_json = metadata
        db.flush()
        after = {"status": str(app.status), "metadata_json": dict(app.metadata_json or {})}
        return {
            "before": before,
            "after": after,
            "target": "discovery_application",
            "created_shadow_source": created_shadow_source,
            "source_watchlist": True,
        }, True

    connector = db.scalar(
        select(Connector).where(
            Connector.tenant_id == tenant_id,
            Connector.id == remediation.target_id,
        )
    )
    if connector is not None:
        details, rollback_supported = _apply_connector_disable(
            db,
            tenant_id=tenant_id,
            remediation=remediation,
            context=context,
        )
        details["target"] = "connector"
        return details, rollback_supported

    raise ValueError("Source quarantine target not found")


def _apply_require_step_up(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    ai_system_id = (
        remediation.target_id
        if remediation.target_type == "ai_system"
        else _normalize_text(context.get("ai_system_id"))
    )
    if not ai_system_id:
        return {"approval_request_id": None, "status": "recommend_only"}, False

    request_payload = {
        "type": "remediation_step_up",
        "remediation_id": remediation.id,
        "source_trigger_type": remediation.source_trigger_type,
        "source_trigger_id": remediation.source_trigger_id,
        "reason_code": _normalize_text(context.get("reason_code")),
    }
    approval = ApprovalRequest(
        tenant_id=tenant_id,
        enforcement_event_id=None,
        ai_system_id=ai_system_id,
        request_payload=request_payload,
        required_roles=["owner", "admin"],
        sla_minutes=30,
        default_if_timeout="block",
        status="pending",
    )
    db.add(approval)
    db.flush()
    return {"approval_request_id": approval.id, "status": "pending"}, False


def _suspend_agent_identity(
    db: Session,
    *,
    tenant_id: str,
    agent_id: str,
    include_descendants: bool,
) -> dict[str, Any]:
    root_agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.id == agent_id,
        )
    )
    if root_agent is None:
        raise ValueError("Agent target not found")

    descendant_ids = (
        collect_delegation_descendant_agent_ids(
            db,
            tenant_id=tenant_id,
            root_agent_identity_id=root_agent.id,
        )
        if include_descendants
        else []
    )
    impacted_agent_ids = sorted({root_agent.id, *descendant_ids})
    impacted_agents = db.scalars(
        select(AgentIdentity).where(
            AgentIdentity.tenant_id == tenant_id,
            AgentIdentity.id.in_(impacted_agent_ids),
        )
    ).all()
    for row in impacted_agents:
        row.status = "isolated"

    tokens = db.scalars(
        select(CapabilityToken).where(
            CapabilityToken.tenant_id == tenant_id,
            CapabilityToken.agent_identity_id.in_(impacted_agent_ids),
        )
    ).all()
    revoked_tokens = 0
    now = _now()
    for token in tokens:
        if token.revoked_at is None:
            token.revoked_at = now
            revoked_tokens += 1

    delegations_revoked = revoke_agent_delegations(
        db,
        tenant_id=tenant_id,
        impacted_agent_identity_ids=impacted_agent_ids,
        revoked_at=now,
    )
    db.flush()
    return {
        "impacted_agent_ids": impacted_agent_ids,
        "descendant_agent_ids": descendant_ids,
        "revoked_tokens": revoked_tokens,
        "delegations_revoked": delegations_revoked,
    }


def _apply_agent_suspend(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
) -> tuple[dict[str, Any], bool]:
    details = _suspend_agent_identity(
        db,
        tenant_id=tenant_id,
        agent_id=remediation.target_id,
        include_descendants=False,
    )
    return details, False


def _apply_kill_switch(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
) -> tuple[dict[str, Any], bool]:
    details = _suspend_agent_identity(
        db,
        tenant_id=tenant_id,
        agent_id=remediation.target_id,
        include_descendants=True,
    )
    return details, False


def _apply_trust_center_escalation(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    repeat_threshold = max(3, int(settings.runtime_intelligence_repeat_threshold or 3))
    repeat_count = _normalize_repeat_count(context.get("occurrence_count"), fallback=1)
    repeated_shadow_usage = bool(context.get("repeated_shadow_usage")) or (
        remediation.source_trigger_type == "shadow_ai_detection" and repeat_count >= repeat_threshold
    )
    require_justification = bool(context.get("require_justification")) or repeated_shadow_usage
    notify_admin = bool(context.get("notify_admin")) or repeated_shadow_usage
    strict_unknown_usage_blocking = bool(context.get("strict_unknown_usage_blocking")) or repeated_shadow_usage
    inferred_ai_type = _infer_shadow_ai_type(context)
    inferred_data_access = _infer_shadow_data_access(context)
    inferred_deployment = _normalize_text(context.get("deployment_type")) or None

    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.tenant_id == tenant_id,
            AISystem.id == remediation.target_id,
        )
    )
    inferred_name = (
        _normalize_text(context.get("canonical_name"))
        or _normalize_text(context.get("domain"))
        or _normalize_text(context.get("tool_name"))
        or _normalize_text(context.get("ai_tool"))
        or _normalize_text(remediation.target_id, fallback="Unknown AI System")
    )
    if ai_system is None and inferred_name:
        existing_candidate = db.scalar(
            select(AISystem).where(
                AISystem.tenant_id == tenant_id,
                AISystem.name == inferred_name,
            )
        )
        if existing_candidate is not None:
            ai_system = existing_candidate
            remediation.target_type = "ai_system"
            remediation.target_id = existing_candidate.id
            db.flush()

    if ai_system is None:
        candidate = AISystem(
            tenant_id=tenant_id,
            name=inferred_name,
            description="Auto-created remediation candidate for unknown/unapproved AI usage.",
            risk_tier="HIGH",
            status="pending_review",
            metadata_json={
                "source": "SHADOW_DISCOVERY",
                "governance_state": "REVIEW",
                "lifecycle_state": "PENDING_REVIEW",
                "ownership_state": "UNKNOWN",
                "business_owner": "UNKNOWN",
                "technical_owner": "UNKNOWN",
                "discovered_via": list(_coerce_list(context.get("source_surfaces"))),
                "classification_inference": {
                    "ai_type": inferred_ai_type,
                    "deployment_type": inferred_deployment,
                    "data_access": inferred_data_access,
                },
                "strict_unknown_usage_blocking": strict_unknown_usage_blocking,
                "require_justification_on_repeated_shadow_usage": require_justification,
                "notify_admin_on_repeat_shadow_usage": notify_admin,
                "shadow_usage_repeat_count": repeat_count,
                "requires_reapproval": True,
                "remediation_requirements": [
                    "business_owner_assignment",
                    "technical_owner_assignment",
                    "risk_classification",
                    "policy_mapping",
                    "governance_review",
                ],
                "remediation_id": remediation.id,
            },
        )
        db.add(candidate)
        db.flush()
        previous_target = {"target_type": remediation.target_type, "target_id": remediation.target_id}
        remediation.target_type = "ai_system"
        remediation.target_id = candidate.id
        db.flush()
        return {
            "before": {**previous_target, "created_candidate": True},
            "after": {
                "ai_system_id": candidate.id,
                "status": candidate.status,
                "risk_tier": candidate.risk_tier,
                "ownership_state": "UNKNOWN",
                "strict_unknown_usage_blocking": strict_unknown_usage_blocking,
                "notify_admin_on_repeat_shadow_usage": notify_admin,
                "require_justification_on_repeated_shadow_usage": require_justification,
                "shadow_usage_repeat_count": repeat_count,
            },
            "status": "pending_review_registration",
            "recommendation": "assign_owners_and_complete_governance_lifecycle",
        }, True

    before = {
        "risk_tier": ai_system.risk_tier,
        "status": ai_system.status,
        "metadata_json": dict(ai_system.metadata_json or {}),
    }
    current_risk = str(ai_system.risk_tier or "").strip().upper()
    if current_risk not in {"HIGH", "CRITICAL", "RESTRICTED", "PROHIBITED"}:
        ai_system.risk_tier = "HIGH"
    current_status = str(ai_system.status or "").strip().lower()
    if current_status in {"active", "approved", "live"}:
        ai_system.status = "restricted"
    elif current_status in {"pending_review", "proposed", "draft", "review"}:
        ai_system.status = "pending_review"
    else:
        ai_system.status = "review"
    metadata = dict(ai_system.metadata_json or {})
    metadata["governance_state"] = "REVIEW"
    metadata["lifecycle_state"] = "RESTRICTED"
    metadata["remediation_source"] = remediation.source_trigger_type
    metadata["remediation_id"] = remediation.id
    metadata["remediation_reason"] = _normalize_text(context.get("reason_code"))
    metadata["requires_reapproval"] = True
    metadata["ownership_state"] = str(metadata.get("ownership_state") or "UNKNOWN")
    metadata["business_owner"] = str(metadata.get("business_owner") or "UNKNOWN")
    metadata["technical_owner"] = str(metadata.get("technical_owner") or "UNKNOWN")
    metadata["strict_unknown_usage_blocking"] = strict_unknown_usage_blocking
    metadata["require_justification_on_repeated_shadow_usage"] = require_justification
    metadata["notify_admin_on_repeat_shadow_usage"] = notify_admin
    metadata["shadow_usage_repeat_count"] = max(int(metadata.get("shadow_usage_repeat_count") or 0), repeat_count)
    metadata["classification_inference"] = {
        **dict(metadata.get("classification_inference") or {}),
        "ai_type": inferred_ai_type,
        "deployment_type": inferred_deployment,
        "data_access": inferred_data_access,
    }
    metadata["remediation_requirements"] = sorted(
        {
            *_coerce_list(metadata.get("remediation_requirements")),
            "business_owner_assignment",
            "technical_owner_assignment",
            "risk_classification",
            "policy_mapping",
            "policy_alignment_review",
            "risk_reassessment",
        }
    )
    ai_system.metadata_json = metadata
    db.flush()

    notification_signal_id: str | None = None
    if notify_admin:
        signal = MonitoringSignal(
            tenant_id=tenant_id,
            ai_system_id=ai_system.id,
            signal_type="remediation.shadow_ai.repeat_usage_admin_notification",
            severity="high",
            payload={
                "remediation_id": remediation.id,
                "ai_system_id": ai_system.id,
                "reason_code": _normalize_text(context.get("reason_code"), fallback="repeated_shadow_usage"),
                "repeat_count": repeat_count,
                "strict_unknown_usage_blocking": strict_unknown_usage_blocking,
                "require_justification": require_justification,
                "recommended_action": "notify_admin_and_require_justification",
            },
        )
        db.add(signal)
        db.flush()
        notification_signal_id = signal.id

    after = {
        "risk_tier": ai_system.risk_tier,
        "status": ai_system.status,
        "metadata_json": dict(ai_system.metadata_json or {}),
        "notification_signal_id": notification_signal_id,
    }
    return {"before": before, "after": after}, True


def _apply_ticket_create(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    ticket_system = _normalize_ticket_system(_normalize_text(context.get("ticket_system"), fallback="jira"))
    details = _create_ticket_artifact(
        db,
        tenant_id=tenant_id,
        remediation=remediation,
        context=context,
        ticket_system=ticket_system,
    )
    return {
        **details,
        "tickets": [details],
    }, False


def _normalize_ticket_system(value: str | None) -> str:
    normalized = _normalize_text(value).lower()
    if normalized in {"servicenow", "snow", "service_now"}:
        return "servicenow"
    return "jira"


def _ticket_systems_from_context(context: dict[str, Any], *, risk_level: str) -> list[str]:
    systems: list[str] = []
    raw_systems = context.get("ticket_systems")
    if isinstance(raw_systems, list):
        systems.extend(_normalize_ticket_system(str(item)) for item in raw_systems if str(item).strip())
    elif isinstance(raw_systems, str):
        systems.extend(_normalize_ticket_system(item.strip()) for item in raw_systems.split(",") if item.strip())

    explicit_system = _normalize_text(context.get("ticket_system"))
    if explicit_system:
        systems.append(_normalize_ticket_system(explicit_system))

    create_ticket_cfg = _safe_dict(context.get("create_ticket"))
    if create_ticket_cfg:
        cfg_system = _normalize_text(create_ticket_cfg.get("system"))
        if cfg_system:
            systems.append(_normalize_ticket_system(cfg_system))

    if not systems and _risk_rank(risk_level) >= 3:
        # High/critical remediations are ticket-worthy by default for auditability.
        systems.extend(["jira", "servicenow"])

    deduped: list[str] = []
    seen: set[str] = set()
    for system in systems:
        if system in seen:
            continue
        seen.add(system)
        deduped.append(system)
    return deduped


def _append_ticket_note_to_finding(
    db: Session,
    *,
    tenant_id: str,
    finding_id: str | None,
    remediation_id: str,
    ticket_system: str,
    ticket_id: str,
) -> None:
    normalized_finding_id = _normalize_text(finding_id)
    if not normalized_finding_id:
        return
    finding = db.scalar(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.finding_id == normalized_finding_id,
        )
    )
    if finding is None:
        return
    finding.status = "reviewing" if finding.status == "open" else finding.status
    finding.recommended_action = (
        f"{finding.recommended_action}\n\nTicket {ticket_system.upper()}:{ticket_id} opened by remediation {remediation_id}."
    )
    db.flush()


def _create_ticket_artifact(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
    ticket_system: str,
) -> dict[str, Any]:
    now = _now()
    prefix = "JIRA" if ticket_system == "jira" else "SNOW"
    ticket_id = f"{prefix}-{remediation.id[:8].upper()}-{int(now.timestamp())}"
    details = {
        "ticket_id": ticket_id,
        "ticket_system": ticket_system,
        "severity": _normalize_risk_level(remediation.risk_level),
        "title": _normalize_text(context.get("ticket_title"), fallback=f"[{str(remediation.risk_level).upper()}] Remediation action"),
        "description": _normalize_text(context.get("ticket_description"), fallback=remediation.recommendation_text),
        "created_at": now.isoformat(),
        "status": "open",
    }
    _append_ticket_note_to_finding(
        db,
        tenant_id=tenant_id,
        finding_id=_normalize_text(context.get("finding_id")),
        remediation_id=remediation.id,
        ticket_system=ticket_system,
        ticket_id=ticket_id,
    )
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="remediation.ticket.created",
        resource_type="remediation_action",
        resource_id=remediation.id,
        payload=details,
        correlation_id=remediation.id,
    )
    create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="remediation_ticket",
        signal_type="remediation.ticket.created",
        label=f"{ticket_system.upper()} ticket created for remediation {remediation.id}",
        payload={**details, "remediation_id": remediation.id},
        correlation_id=remediation.id,
    )
    return details


def _attach_auto_ticket_artifacts(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
    details: dict[str, Any],
) -> dict[str, Any]:
    details_payload = _safe_dict(details)
    existing_tickets = [row for row in details_payload.get("tickets", []) if isinstance(row, dict)]
    if isinstance(details_payload.get("ticket_id"), str) and details_payload["ticket_id"].strip():
        existing_tickets.append(
            {
                "ticket_id": details_payload.get("ticket_id"),
                "ticket_system": _normalize_ticket_system(_normalize_text(details_payload.get("ticket_system"), fallback="jira")),
                "severity": details_payload.get("severity"),
                "title": details_payload.get("title"),
                "description": details_payload.get("description"),
                "created_at": details_payload.get("created_at"),
                "status": details_payload.get("status", "open"),
            }
        )

    existing_tokens = {
        f"{_normalize_ticket_system(_normalize_text(row.get('ticket_system')))}:{_normalize_text(row.get('ticket_id'))}"
        for row in existing_tickets
        if _normalize_text(row.get("ticket_id"))
    }

    for system in _ticket_systems_from_context(context, risk_level=remediation.risk_level):
        token = f"{system}:"
        if any(item.startswith(token) for item in existing_tokens):
            continue
        ticket_details = _create_ticket_artifact(
            db,
            tenant_id=tenant_id,
            remediation=remediation,
            context=context,
            ticket_system=system,
        )
        existing_tokens.add(f"{system}:{ticket_details['ticket_id']}")
        existing_tickets.append(ticket_details)

    if existing_tickets:
        details_payload["tickets"] = existing_tickets
    if not details_payload.get("ticket_id") and existing_tickets:
        first_ticket = existing_tickets[0]
        details_payload["ticket_id"] = first_ticket.get("ticket_id")
        details_payload["ticket_system"] = first_ticket.get("ticket_system")
        details_payload["severity"] = first_ticket.get("severity")
        details_payload["title"] = first_ticket.get("title")
        details_payload["description"] = first_ticket.get("description")
        details_payload["created_at"] = first_ticket.get("created_at")
    return details_payload


def _execute_remediation(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
    context: dict[str, Any],
) -> tuple[dict[str, Any], bool]:
    if remediation.remediation_type == "policy_tighten":
        return _apply_policy_tighten(db, tenant_id=tenant_id, remediation=remediation, context=context)
    if remediation.remediation_type == "permission_reduce":
        return _apply_permission_reduce(db, tenant_id=tenant_id, remediation=remediation, context=context)
    if remediation.remediation_type == "connector_disable":
        return _apply_connector_disable(db, tenant_id=tenant_id, remediation=remediation, context=context)
    if remediation.remediation_type == "source_quarantine":
        return _apply_source_quarantine(db, tenant_id=tenant_id, remediation=remediation, context=context)
    if remediation.remediation_type == "require_step_up":
        return _apply_require_step_up(db, tenant_id=tenant_id, remediation=remediation, context=context)
    if remediation.remediation_type == "agent_suspend":
        return _apply_agent_suspend(db, tenant_id=tenant_id, remediation=remediation)
    if remediation.remediation_type == "kill_switch":
        return _apply_kill_switch(db, tenant_id=tenant_id, remediation=remediation)
    if remediation.remediation_type == "trust_center_escalation":
        return _apply_trust_center_escalation(db, tenant_id=tenant_id, remediation=remediation, context=context)
    if remediation.remediation_type == "ticket_create":
        return _apply_ticket_create(db, tenant_id=tenant_id, remediation=remediation, context=context)
    raise ValueError(f"Unsupported remediation type: {remediation.remediation_type}")


def _execute_rollback(
    db: Session,
    *,
    tenant_id: str,
    remediation: RemediationAction,
) -> dict[str, Any]:
    payload = _safe_dict(remediation.rollback_payload)
    before = _safe_dict(payload.get("before"))
    if remediation.remediation_type == "permission_reduce":
        agent = db.scalar(
            select(AgentIdentity).where(
                AgentIdentity.tenant_id == tenant_id,
                AgentIdentity.id == remediation.target_id,
            )
        )
        if agent is None:
            raise ValueError("Agent target not found for rollback")
        agent.tool_registry = list(before.get("tool_registry") or [])
        agent.action_scope = list(before.get("action_scope") or [])
        agent.external_system_access = list(before.get("external_system_access") or [])
        if before.get("max_chain_depth") is not None:
            agent.max_chain_depth = int(before["max_chain_depth"])
        db.flush()
        return {"restored": "agent_permissions"}

    if remediation.remediation_type == "connector_disable":
        connector = db.scalar(
            select(Connector).where(
                Connector.tenant_id == tenant_id,
                Connector.id == remediation.target_id,
            )
        )
        if connector is None:
            raise ValueError("Connector target not found for rollback")
        connector.enabled = bool(before.get("enabled", True))
        connector.status = _normalize_text(before.get("status"), fallback=connector.status)
        connector.metadata_json = _safe_dict(before.get("metadata_json"))
        db.flush()
        return {"restored": "connector_state"}

    if remediation.remediation_type == "source_quarantine":
        rollback_target = _normalize_text(payload.get("details", {}).get("target")).lower()
        if rollback_target == "connector":
            connector = db.scalar(
                select(Connector).where(
                    Connector.tenant_id == tenant_id,
                    Connector.id == remediation.target_id,
                )
            )
            if connector is None:
                raise ValueError("Connector target not found for rollback")
            connector.enabled = bool(before.get("enabled", True))
            connector.status = _normalize_text(before.get("status"), fallback=connector.status)
            connector.metadata_json = _safe_dict(before.get("metadata_json"))
            db.flush()
            return {"restored": "connector_source_state"}

        app = db.scalar(
            select(DiscoveryApplication).where(
                DiscoveryApplication.tenant_id == tenant_id,
                DiscoveryApplication.id == remediation.target_id,
            )
        )
        if app is None:
            raise ValueError("Discovery source target not found for rollback")
        app.status = _normalize_text(before.get("status"), fallback=app.status)
        app.metadata_json = _safe_dict(before.get("metadata_json"))
        db.flush()
        return {"restored": "source_state"}

    if remediation.remediation_type == "trust_center_escalation":
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.tenant_id == tenant_id,
                AISystem.id == remediation.target_id,
            )
        )
        if ai_system is None:
            raise ValueError("AI system target not found for rollback")
        if bool(before.get("created_candidate")):
            metadata = dict(ai_system.metadata_json or {})
            metadata["rolled_back"] = True
            metadata["rollback_reason"] = "remediation_rollback"
            ai_system.status = "rejected"
            ai_system.metadata_json = metadata
            db.flush()
            return {"restored": "auto_created_candidate_rejected"}
        ai_system.risk_tier = _normalize_text(before.get("risk_tier"), fallback=ai_system.risk_tier)
        ai_system.status = _normalize_text(before.get("status"), fallback=ai_system.status)
        ai_system.metadata_json = _safe_dict(before.get("metadata_json"))
        db.flush()
        return {"restored": "ai_system_state"}

    raise ValueError("Rollback is not supported for this remediation type")


def list_remediation_actions(
    db: Session,
    *,
    tenant_id: str,
    status: str | None = None,
    source_trigger_type: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    finding_id: str | None = None,
) -> list[RemediationAction]:
    query = select(RemediationAction).where(RemediationAction.tenant_id == tenant_id)
    if status:
        query = query.where(RemediationAction.status == _normalize_status(status))
    if source_trigger_type:
        query = query.where(RemediationAction.source_trigger_type == _normalize_text(source_trigger_type).lower())
    if target_type:
        query = query.where(RemediationAction.target_type == _normalize_text(target_type).lower())
    if target_id:
        query = query.where(RemediationAction.target_id == _normalize_text(target_id))
    rows = db.scalars(query.order_by(RemediationAction.created_at.desc())).all()
    if finding_id:
        finding = db.scalar(
            select(Finding).where(
                Finding.tenant_id == tenant_id,
                Finding.finding_id == _normalize_text(finding_id),
            )
        )
        if finding is None:
            return []
        linked = set(_coerce_list(finding.remediation_action_ids))
        rows = [row for row in rows if row.id in linked]
    return rows


def propose_remediation_action(
    db: Session,
    *,
    tenant_id: str,
    source_trigger_type: str,
    source_trigger_id: str,
    target_type: str,
    target_id: str,
    severity: str,
    context: dict[str, Any] | None = None,
) -> RemediationAction:
    context_payload = _safe_dict(context)
    plan = _build_plan_for_trigger(
        source_trigger_type=source_trigger_type,
        source_trigger_id=source_trigger_id,
        target_type=target_type,
        target_id=target_id,
        severity=severity,
        context=context_payload,
    )
    related_control_ids = _coerce_list(context_payload.get("related_control_ids")) or _coerce_list(plan.context.get("related_control_ids"))
    context_payload = {
        **_safe_dict(plan.context),
        **context_payload,
        "related_control_ids": related_control_ids,
    }
    context_payload["crq"] = compute_remediation_crq(
        remediation_type=plan.remediation_type,
        risk_level=plan.risk_level,
        related_control_ids=related_control_ids,
        context=context_payload,
    )
    existing = _find_existing_action(
        db,
        tenant_id=tenant_id,
        plan=plan,
        source_trigger_id=_normalize_text(source_trigger_id),
    )
    remediation = existing
    if remediation is None:
        remediation = RemediationAction(
            tenant_id=tenant_id,
            remediation_type=plan.remediation_type,
            target_type=plan.target_type,
            target_id=plan.target_id,
            source_trigger_type=plan.source_trigger_type,
            source_trigger_id=_normalize_text(source_trigger_id),
            recommendation_text=plan.recommendation_text,
            action_mode=plan.action_mode,
            status="proposed",
            risk_level=plan.risk_level,
            requires_approval=plan.requires_approval,
            approved_by=None,
            justification=_normalize_text(context_payload.get("justification")) or None,
            rollback_supported=plan.rollback_supported,
            rollback_payload={"context": _safe_dict(context_payload)},
        )
        db.add(remediation)
        db.flush()
    else:
        remediation.recommendation_text = plan.recommendation_text
        remediation.action_mode = plan.action_mode
        remediation.risk_level = _prefer_higher_risk(remediation.risk_level, plan.risk_level)
        remediation.requires_approval = bool(remediation.requires_approval or plan.requires_approval)
        remediation.rollback_supported = bool(remediation.rollback_supported or plan.rollback_supported)
        merged_context = {
            **_safe_dict(_safe_dict(remediation.rollback_payload).get("context")),
            **_safe_dict(context_payload),
        }
        merged_related_control_ids = _coerce_list(merged_context.get("related_control_ids"))
        merged_context["related_control_ids"] = merged_related_control_ids
        merged_context["crq"] = compute_remediation_crq(
            remediation_type=remediation.remediation_type,
            risk_level=remediation.risk_level,
            related_control_ids=merged_related_control_ids,
            context=merged_context,
        )
        remediation.rollback_payload = {
            **_safe_dict(remediation.rollback_payload),
            "context": merged_context,
        }
        context_payload = merged_context
        db.flush()

    trigger_evidence_ids = _resolve_trigger_evidence_ids(
        db,
        source_trigger_type=remediation.source_trigger_type,
        source_trigger_id=remediation.source_trigger_id,
        context=context_payload,
    )
    proposed_node_id = _create_remediation_evidence_node(
        db,
        tenant_id=tenant_id,
        remediation=remediation,
        status="proposed",
        payload={
            "remediation_id": remediation.id,
            "source_trigger_type": remediation.source_trigger_type,
            "source_trigger_id": remediation.source_trigger_id,
            "remediation_type": remediation.remediation_type,
            "target_type": remediation.target_type,
            "target_id": remediation.target_id,
            "action_mode": remediation.action_mode,
            "risk_level": remediation.risk_level,
            "requires_approval": remediation.requires_approval,
            "recommendation_text": remediation.recommendation_text,
            "related_control_ids": _coerce_list(context_payload.get("related_control_ids")),
            "crq": _safe_dict(context_payload.get("crq")),
        },
    )
    _link_trigger_to_remediation(
        db,
        tenant_id=tenant_id,
        trigger_evidence_ids=trigger_evidence_ids,
        remediation_node_id=proposed_node_id,
        remediation_id=remediation.id,
    )

    _append_finding_remediation(
        db,
        finding_id=_normalize_text(context_payload.get("finding_id")) or None,
        remediation_id=remediation.id,
        remediation_evidence_node_id=proposed_node_id,
    )

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="remediation.created",
        resource_type="remediation_action",
        resource_id=remediation.id,
        payload={
            "source_trigger_type": remediation.source_trigger_type,
            "source_trigger_id": remediation.source_trigger_id,
            "remediation_type": remediation.remediation_type,
            "target_type": remediation.target_type,
            "target_id": remediation.target_id,
            "action_mode": remediation.action_mode,
            "risk_level": remediation.risk_level,
            "requires_approval": remediation.requires_approval,
            "crq": _safe_dict(context_payload.get("crq")),
        },
        correlation_id=remediation.id,
    )
    _emit_remediation_lifecycle_signal(
        db,
        tenant_id=tenant_id,
        remediation=remediation,
        status="proposed",
        context=context_payload,
        evidence_node_id=proposed_node_id,
        details={"status": "proposed"},
    )

    should_auto_apply = remediation.action_mode == "auto_apply" and not remediation.requires_approval
    if should_auto_apply and remediation.status == "proposed":
        apply_remediation_action(
            db,
            tenant_id=tenant_id,
            remediation_id=remediation.id,
            actor_user_id=None,
            justification="auto_apply_policy",
            context=context_payload,
        )

    return remediation


def propose_remediation_from_finding(
    db: Session,
    *,
    finding: Finding,
    source_trigger_type: str | None = None,
    context: dict[str, Any] | None = None,
) -> RemediationAction:
    context_payload = _safe_dict(context)
    if "finding_id" not in context_payload:
        context_payload["finding_id"] = finding.finding_id
    if "finding_type" not in context_payload:
        context_payload["finding_type"] = finding.finding_type
    if "occurrence_count" not in context_payload:
        context_payload["occurrence_count"] = int(finding.occurrence_count or 1)
    if "reason_code" not in context_payload:
        context_payload["reason_code"] = finding.finding_type
    if "related_control_ids" not in context_payload:
        context_payload["related_control_ids"] = list(finding.related_control_ids or [])
    if "evidence_node_ids" not in context_payload:
        context_payload["evidence_node_ids"] = list(finding.evidence_node_ids or [])
    source_trigger_id = _normalize_text(context_payload.get("source_trigger_id"), fallback=finding.finding_id)
    trigger_type = source_trigger_type or _map_finding_to_trigger_type(finding.finding_type)
    target_type, target_id = _default_target_for_finding(finding, context_payload)
    return propose_remediation_action(
        db,
        tenant_id=finding.tenant_id,
        source_trigger_type=trigger_type,
        source_trigger_id=source_trigger_id,
        target_type=target_type,
        target_id=target_id,
        severity=finding.severity,
        context=context_payload,
    )


def propose_remediation_from_monitoring_signal(
    db: Session,
    *,
    signal: MonitoringSignal,
    source_trigger_type: str | None = None,
    context: dict[str, Any] | None = None,
) -> RemediationAction:
    payload = _safe_dict(signal.payload)
    signal_type = _normalize_text(signal.signal_type).lower()
    trigger_type = source_trigger_type
    if not trigger_type:
        if "model_integrity" in signal_type:
            trigger_type = "model_integrity_failure"
        elif "poison" in signal_type:
            trigger_type = "ingestion_poisoning_indicator"
        elif "drift" in signal_type:
            trigger_type = "drift_alert"
        elif signal_type.startswith("runtime_intelligence.recommendation."):
            trigger_type = "runtime_pattern"
        else:
            trigger_type = "guardian_violation"

    connector_id = _normalize_text(payload.get("connector_id"))
    if connector_id:
        target_type = "connector"
        target_id = connector_id
    elif signal.ai_system_id:
        target_type = "ai_system"
        target_id = signal.ai_system_id
    else:
        target_type = "source"
        target_id = _normalize_text(payload.get("source_domain") or payload.get("domain"), fallback=signal_type)

    merged_context = {
        "reason_code": _normalize_text(payload.get("reason_code"), fallback=signal_type),
        "related_control_ids": _coerce_list(payload.get("related_control_ids")),
        "evidence_node_ids": _coerce_list(payload.get("evidence_node_ids")),
        "ticket_system": _normalize_text(payload.get("ticket_system"), fallback="jira"),
        **payload,
        **_safe_dict(context),
    }
    return propose_remediation_action(
        db,
        tenant_id=signal.tenant_id,
        source_trigger_type=trigger_type,
        source_trigger_id=signal.id,
        target_type=target_type,
        target_id=target_id,
        severity=signal.severity,
        context=merged_context,
    )


def propose_remediation_from_simulation_failure(
    db: Session,
    *,
    run: SimulationRun,
    context: dict[str, Any] | None = None,
) -> RemediationAction | None:
    results = _safe_dict(run.results)
    if _normalize_text(results.get("result"), fallback="fail").lower() != "fail":
        return None
    context_payload = _safe_dict(context)
    sibling_runs = db.scalars(
        select(SimulationRun).where(
            SimulationRun.tenant_id == run.tenant_id,
            SimulationRun.ai_system_id == run.ai_system_id,
            SimulationRun.simulation_id == run.simulation_id,
        )
    ).all()
    observed_repeated_failures = sum(
        1 for row in sibling_runs if _normalize_text(_safe_dict(row.results).get("result"), fallback="fail").lower() != "pass"
    )
    repeated_failures = max(
        observed_repeated_failures,
        _normalize_repeat_count(context_payload.get("occurrence_count"), fallback=observed_repeated_failures or 1),
    )
    control_ids = [
        str(item.get("control_id")).strip()
        for item in (run.controls_impacted or [])
        if isinstance(item, dict) and str(item.get("control_id") or "").strip()
    ]
    related_control_ids = _coerce_list(context_payload.get("related_control_ids")) or control_ids
    reason_code = _normalize_text(
        context_payload.get("reason_code"),
        fallback=("simulation_failure_repeated" if repeated_failures >= 3 else "simulation_failure"),
    )
    payload = {
        "reason_code": reason_code,
        "related_control_ids": related_control_ids,
        "evidence_node_ids": _coerce_list(results.get("evidence_node_ids")),
        "simulation_id": run.simulation_id,
        "simulation_run_id": run.id,
        "occurrence_count": repeated_failures,
        "regulated": bool(context_payload.get("regulated")) or repeated_failures >= 3,
        **context_payload,
    }
    try:
        from app.services.ai_orchestration.remediation_guidance_service import (
            build_simulation_failure_task,
            generate_remediation_guidance,
            summarize_guidance,
        )

        orchestration_task = build_simulation_failure_task(
            simulation_id=run.simulation_id,
            simulation_run_id=run.id,
            related_control_ids=related_control_ids,
            occurrence_count=repeated_failures,
            evidence_refs=_coerce_list(results.get("evidence_node_ids")),
            severity=("critical" if repeated_failures >= 5 else "high"),
            risk_tier=("critical" if repeated_failures >= 5 else "high"),
        )
        orchestration_result = generate_remediation_guidance(
            db,
            tenant_id=run.tenant_id,
            actor_user_id=None,
            task=orchestration_task,
            correlation_id=run.correlation_id,
        )
        payload["ai_orchestration"] = summarize_guidance(orchestration_result)
    except Exception as exc:  # pragma: no cover - orchestration must remain non-blocking
        payload["ai_orchestration"] = {
            "status": "unavailable",
            "error": str(exc),
        }
    return propose_remediation_action(
        db,
        tenant_id=run.tenant_id,
        source_trigger_type="simulation_failure",
        source_trigger_id=run.id,
        target_type="ai_system",
        target_id=run.ai_system_id,
        severity=("critical" if repeated_failures >= 5 else "high"),
        context=payload,
    )


def propose_remediation_from_runtime_recommendation(
    db: Session,
    *,
    recommendation: RuntimeGovernanceRecommendation,
    context: dict[str, Any] | None = None,
) -> RemediationAction | None:
    payload = _safe_dict(recommendation.payload)
    confidence_gate_passed = payload.get("confidence_gate_passed")
    if confidence_gate_passed is False:
        return None
    confidence_score = float(payload.get("confidence_score") or payload.get("confidence") or 0.0)
    threshold = float(settings.runtime_remediation_confidence_threshold)
    if confidence_score and confidence_score < threshold:
        return None
    return propose_remediation_action(
        db,
        tenant_id=recommendation.tenant_id,
        source_trigger_type="runtime_pattern",
        source_trigger_id=recommendation.recommendation_id,
        target_type="ai_system" if recommendation.ai_system_id else "source",
        target_id=recommendation.ai_system_id or recommendation.recommendation_type,
        severity="high" if _normalize_text(recommendation.priority).lower() in {"high", "critical", "p0", "p1"} else "medium",
        context={
            "reason_code": recommendation.reason_code,
            "related_control_ids": _coerce_list(payload.get("related_control_ids")),
            "evidence_node_ids": _coerce_list(payload.get("evidence_node_ids")),
            **payload,
            **_safe_dict(context),
        },
    )


def approve_remediation_action(
    db: Session,
    *,
    tenant_id: str,
    remediation_id: str,
    approved_by: str | None,
    justification: str | None = None,
) -> RemediationAction:
    row = db.scalar(
        select(RemediationAction).where(
            RemediationAction.tenant_id == tenant_id,
            RemediationAction.id == remediation_id,
        )
    )
    if row is None:
        raise ValueError("Remediation action not found")
    row.approved_by = approved_by
    row.justification = _normalize_text(justification) or row.justification
    row.status = "proposed"
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=approved_by,
        actor_type="human",
        action="remediation.approved",
        resource_type="remediation_action",
        resource_id=row.id,
        payload={"justification": row.justification},
        correlation_id=row.id,
    )
    approved_node_id = _create_remediation_evidence_node(
        db,
        tenant_id=tenant_id,
        remediation=row,
        status="approved",
        payload={
            "remediation_id": row.id,
            "approved_by": approved_by,
            "justification": row.justification,
        },
    )
    _emit_remediation_lifecycle_signal(
        db,
        tenant_id=tenant_id,
        remediation=row,
        status="approved",
        context=_safe_dict(_safe_dict(row.rollback_payload).get("context")),
        evidence_node_id=approved_node_id,
        details={"status": "approved", "approved_by": approved_by},
    )
    return row


def reject_remediation_action(
    db: Session,
    *,
    tenant_id: str,
    remediation_id: str,
    actor_user_id: str | None,
    justification: str | None = None,
) -> RemediationAction:
    row = db.scalar(
        select(RemediationAction).where(
            RemediationAction.tenant_id == tenant_id,
            RemediationAction.id == remediation_id,
        )
    )
    if row is None:
        raise ValueError("Remediation action not found")
    row.status = "rejected"
    row.justification = _normalize_text(justification) or row.justification
    db.flush()
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human",
        action="remediation.rejected",
        resource_type="remediation_action",
        resource_id=row.id,
        payload={"justification": row.justification},
        correlation_id=row.id,
    )
    rejected_node_id = _create_remediation_evidence_node(
        db,
        tenant_id=tenant_id,
        remediation=row,
        status="rejected",
        payload={
            "remediation_id": row.id,
            "justification": row.justification,
        },
    )
    _emit_remediation_lifecycle_signal(
        db,
        tenant_id=tenant_id,
        remediation=row,
        status="rejected",
        context=_safe_dict(_safe_dict(row.rollback_payload).get("context")),
        evidence_node_id=rejected_node_id,
        details={"status": "rejected"},
    )
    return row


def apply_remediation_action(
    db: Session,
    *,
    tenant_id: str,
    remediation_id: str,
    actor_user_id: str | None,
    justification: str | None = None,
    context: dict[str, Any] | None = None,
) -> RemediationAction:
    row = db.scalar(
        select(RemediationAction).where(
            RemediationAction.tenant_id == tenant_id,
            RemediationAction.id == remediation_id,
        )
    )
    if row is None:
        raise ValueError("Remediation action not found")
    if row.status == "applied":
        return row
    if row.status in {"rejected", "rolled_back"}:
        raise ValueError(f"Cannot apply remediation in status={row.status}")
    if row.requires_approval and not row.approved_by:
        raise ValueError("Remediation requires approval before apply")

    merged_context = {**_safe_dict(context), **_safe_dict(_safe_dict(row.rollback_payload).get("context"))}
    if justification:
        row.justification = _normalize_text(justification)

    try:
        install_generic_seam_authority(
            db, tenant_id=tenant_id, seam_ref="remediation.apply", action_id=f"remediation:{row.id}:apply", chain_id=row.id,
            actor_principal=f"user:{actor_user_id or 'unknown'}", executing_principal="service:remediation", operation="remediation_apply",
            tool_or_service_ref=row.remediation_type, parameter_hash=domain_hash("hawk:remediation-apply:v1", _remediation_seam_hash_material(merged_context)), target_ref=row.id,
            approval_requirement="required" if row.requires_approval else "not_required",
        )
        details, rollback_supported = invoke_final_seam(
            db,
            seam_ref="remediation.apply",
            executor=lambda: _execute_remediation(
                db,
                tenant_id=tenant_id,
                remediation=row,
                context=merged_context,
            ),
        )
        details = _attach_auto_ticket_artifacts(
            db,
            tenant_id=tenant_id,
            remediation=row,
            context=merged_context,
            details=_safe_dict(details),
        )
        row.status = "applied"
        row.applied_at = _now()
        row.rollback_supported = bool(rollback_supported)
        row.rollback_payload = {
            "context": merged_context,
            "details": details,
            "before": _safe_dict(details.get("before")),
            "after": _safe_dict(details.get("after")),
            "applied_at": row.applied_at.isoformat() if row.applied_at else None,
        }
        db.flush()

        applied_node_id = _create_remediation_evidence_node(
            db,
            tenant_id=tenant_id,
            remediation=row,
            status="applied",
            payload={
                "remediation_id": row.id,
                "details": details,
                "rollback_supported": row.rollback_supported,
                "approved_by": row.approved_by,
                "justification": row.justification,
            },
        )
        _link_remediation_to_target(
            db,
            tenant_id=tenant_id,
            remediation=row,
            remediation_node_id=applied_node_id,
            details=details,
        )
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="human" if actor_user_id else "system",
            action="remediation.applied",
            resource_type="remediation_action",
            resource_id=row.id,
            payload={
                "remediation_type": row.remediation_type,
                "target_type": row.target_type,
                "target_id": row.target_id,
                "details": details,
                "rollback_supported": row.rollback_supported,
            },
            correlation_id=row.id,
        )
        _emit_remediation_lifecycle_signal(
            db,
            tenant_id=tenant_id,
            remediation=row,
            status="applied",
            context=merged_context,
            evidence_node_id=applied_node_id,
            details=details,
        )
        return row
    except Exception as exc:
        row.status = "failed"
        row.rollback_payload = {
            **_safe_dict(row.rollback_payload),
            "error": str(exc),
            "failed_at": _now().isoformat(),
        }
        db.flush()
        write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            actor_type="human" if actor_user_id else "system",
            action="remediation.failed",
            resource_type="remediation_action",
            resource_id=row.id,
            payload={"error": str(exc)},
            correlation_id=row.id,
        )
        failed_node_id = _create_remediation_evidence_node(
            db,
            tenant_id=tenant_id,
            remediation=row,
            status="failed",
            payload={"remediation_id": row.id, "error": str(exc)},
        )
        _emit_remediation_lifecycle_signal(
            db,
            tenant_id=tenant_id,
            remediation=row,
            status="failed",
            context=merged_context,
            evidence_node_id=failed_node_id,
            details={"error": str(exc)},
        )
        raise


def rollback_remediation_action(
    db: Session,
    *,
    tenant_id: str,
    remediation_id: str,
    actor_user_id: str | None,
    justification: str | None = None,
) -> RemediationAction:
    row = db.scalar(
        select(RemediationAction).where(
            RemediationAction.tenant_id == tenant_id,
            RemediationAction.id == remediation_id,
        )
    )
    if row is None:
        raise ValueError("Remediation action not found")
    if row.status != "applied":
        raise ValueError("Only applied remediation actions can be rolled back")
    if not row.rollback_supported:
        raise ValueError("Rollback is not supported for this remediation action")

    install_generic_seam_authority(
        db, tenant_id=tenant_id, seam_ref="remediation.rollback", action_id=f"remediation:{row.id}:rollback", chain_id=row.id,
        actor_principal=f"user:{actor_user_id or 'unknown'}", executing_principal="service:remediation", operation="remediation_rollback",
        tool_or_service_ref=row.remediation_type, parameter_hash=domain_hash("hawk:remediation-rollback:v1", _remediation_seam_hash_material(_safe_dict(row.rollback_payload))), target_ref=row.id,
        approval_requirement="required" if row.requires_approval else "not_required",
    )
    details = invoke_final_seam(
        db,
        seam_ref="remediation.rollback",
        executor=lambda: _execute_rollback(
            db,
            tenant_id=tenant_id,
            remediation=row,
        ),
    )
    row.status = "rolled_back"
    row.justification = _normalize_text(justification) or row.justification
    payload = _safe_dict(row.rollback_payload)
    payload["rollback_details"] = details
    payload["rolled_back_at"] = _now().isoformat()
    row.rollback_payload = payload
    db.flush()

    rollback_node_id = _create_remediation_evidence_node(
        db,
        tenant_id=tenant_id,
        remediation=row,
        status="rolled_back",
        payload={
            "remediation_id": row.id,
            "details": details,
            "justification": row.justification,
        },
    )
    _link_remediation_to_target(
        db,
        tenant_id=tenant_id,
        remediation=row,
        remediation_node_id=rollback_node_id,
        details={"rollback": details},
    )
    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="remediation.rolled_back",
        resource_type="remediation_action",
        resource_id=row.id,
        payload={
            "remediation_type": row.remediation_type,
            "target_type": row.target_type,
            "target_id": row.target_id,
            "details": details,
            "justification": row.justification,
        },
        correlation_id=row.id,
    )
    _emit_remediation_lifecycle_signal(
        db,
        tenant_id=tenant_id,
        remediation=row,
        status="rolled_back",
        context=_safe_dict(_safe_dict(row.rollback_payload).get("context")),
        evidence_node_id=rollback_node_id,
        details={"rollback": details},
    )
    return row
