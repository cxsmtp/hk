from __future__ import annotations

from dataclasses import dataclass

from app.db.models.shadow_ai import ShadowAIEntity


RISK_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class RiskAssignmentResult:
    provisional_risk_tier: str
    risk_reasoning: list[str]


def _norm(value: str | None) -> str:
    return str(value or "").strip().lower()


def assign_provisional_risk(
    *,
    entity: ShadowAIEntity,
    confidence_score: float,
    confidence_level: str,
    repeated_count: int,
    event_metadata: dict,
) -> RiskAssignmentResult:
    surfaces = {str(item).strip().lower() for item in (entity.source_surfaces or []) if str(item).strip()}
    decision = _norm(event_metadata.get("decision") or event_metadata.get("action_taken"))
    data_classification = _norm(event_metadata.get("data_classification"))
    risk_labels = {_norm(item) for item in (event_metadata.get("risk_labels") or []) if str(item).strip()}
    asymmetry = "asymmetry" in _norm(event_metadata.get("event_type")) or "output_asymmetry" in risk_labels
    process_name = _norm(event_metadata.get("process_name"))
    bytes_sent = int(event_metadata.get("bytes_sent") or 0) if str(event_metadata.get("bytes_sent") or "").isdigit() else 0
    bytes_received = int(event_metadata.get("bytes_received") or 0) if str(event_metadata.get("bytes_received") or "").isdigit() else 0
    host_sensitivity = _norm(event_metadata.get("host_sensitivity"))
    provider_type = _norm(
        event_metadata.get("provider_type")
        or (event_metadata.get("provider_catalog") or {}).get("provider_type")
    )
    trust_level = _norm(
        event_metadata.get("trust_level")
        or (event_metadata.get("provider_catalog") or {}).get("trust_level")
    )
    default_risk_hint = _norm(
        event_metadata.get("default_risk_hint")
        or (event_metadata.get("provider_catalog") or {}).get("default_risk_hint")
    )

    risk = "MEDIUM"
    reasons: list[str] = []

    if not entity.linked_ai_system_id:
        reasons.append("entity_not_governed")
        if confidence_level in {"medium", "high"}:
            risk = "HIGH"
            reasons.append("unknown_entity_with_material_confidence")

    if data_classification in {"sensitive", "confidential", "restricted"}:
        risk = "HIGH"
        reasons.append("sensitive_data_context")

    if any(token in decision for token in {"block", "deny", "hold", "restrict"}):
        risk = "HIGH"
        reasons.append("policy_violation_detected")

    if asymmetry:
        risk = "HIGH"
        reasons.append("asymmetry_risk_signal")

    if repeated_count >= 5:
        risk = "HIGH"
        reasons.append("repeated_usage_cluster")

    if "endpoint" in surfaces:
        risk = "HIGH"
        reasons.append("off_browser_endpoint_discovery")

    if "proxy" in surfaces and repeated_count >= 3:
        risk = "HIGH"
        reasons.append("repeated_unknown_network_usage")

    if "dns" in surfaces and repeated_count <= 1 and confidence_level == "low":
        risk = "LOW"
        reasons.append("dns_only_low_confidence_signal")

    if process_name in {"python", "bash", "powershell", "node", "curl", "wget"} and "endpoint" in surfaces:
        risk = "HIGH"
        reasons.append("endpoint_process_invoking_model_api")

    if provider_type == "local_model" and not entity.linked_ai_system_id:
        risk = "HIGH"
        reasons.append("local_or_oss_model_not_governed")

    if provider_type == "agent_framework" and not entity.linked_ai_system_id:
        risk = "HIGH"
        reasons.append("agent_framework_not_governed")

    if provider_type == "model_api" and not entity.linked_ai_system_id and ("gateway" in surfaces or "proxy" in surfaces or "endpoint" in surfaces):
        risk = "HIGH"
        reasons.append("unsanctioned_model_api_usage")

    if trust_level in {"unknown", "untrusted"} and data_classification in {"sensitive", "confidential", "restricted"}:
        risk = "HIGH"
        reasons.append("sensitive_data_to_unknown_trust_provider")

    if default_risk_hint == "critical":
        risk = "CRITICAL"
        reasons.append("provider_catalog_default_critical_risk")
    elif default_risk_hint == "high":
        if risk != "CRITICAL":
            risk = "HIGH"
        reasons.append("provider_catalog_default_high_risk")

    if bytes_sent >= 100_000 or bytes_received >= 100_000:
        risk = "HIGH"
        reasons.append("material_network_data_transfer_observed")

    if host_sensitivity in {"privileged", "production", "finance", "pii"} and "endpoint" in surfaces:
        risk = "HIGH"
        reasons.append("sensitive_host_context")

    if confidence_score >= 0.9 and ("gateway" in surfaces or "connector" in surfaces):
        risk = "CRITICAL"
        reasons.append("high_confidence_cross_surface_unsanctioned_usage")

    if surfaces == {"monitoring"} and repeated_count <= 1 and confidence_level == "low":
        risk = "LOW"
        reasons.append("single_low_confidence_monitoring_signal")

    if not reasons:
        reasons.append("baseline_risk_from_unknown_usage")

    return RiskAssignmentResult(
        provisional_risk_tier=risk,
        risk_reasoning=reasons,
    )


def is_risk_escalation(previous_tier: str | None, new_tier: str) -> bool:
    prev_rank = RISK_ORDER.get(str(previous_tier or "").strip().upper(), 0)
    new_rank = RISK_ORDER.get(str(new_tier or "").strip().upper(), 0)
    return new_rank > prev_rank
