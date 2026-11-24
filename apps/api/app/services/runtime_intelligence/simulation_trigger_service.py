from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.runtime_intelligence import RuntimeEvent
from app.db.models.runtime_intelligence import RuntimeSimulationTrigger
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.findings_service import generate_unregistered_ai_system_finding
from app.services.governance_resolution import resolve_ai_system_status
from app.services.runtime_intelligence.schemas import TriggerPlan


TRIGGER_PACK_MAP: dict[str, tuple[str, list[str]]] = {
    "repeated_prompt_blocks": ("prompt_attack_pack", ["CTRL-INPUT-001"]),
    "repeated_prompt_injection_attempts": ("prompt_attack_pack", ["CTRL-INPUT-001"]),
    "asymmetry_spike": ("data_leakage_pack", ["CTRL-DLP-001", "CTRL-TOOL-001"]),
    "asymmetry_risk_spike": ("data_leakage_pack", ["CTRL-DLP-001", "CTRL-TOOL-001"]),
    "multi_tool_data_exposure": ("data_leakage_pack", ["CTRL-DLP-001", "CTRL-TOOL-001"]),
    "repeated_denied_tool_actions": ("tool_abuse_pack", ["CTRL-TOOL-001", "CTRL-AI-IAM-001"]),
    "repeated_denied_tool_calls": ("tool_abuse_pack", ["CTRL-TOOL-001", "CTRL-AI-IAM-001"]),
    "repeated_tool_denials": ("tool_abuse_pack", ["CTRL-TOOL-001", "CTRL-AI-IAM-001"]),
    "unusual_tool_sequences": ("tool_abuse_pack", ["CTRL-TOOL-001", "CTRL-AI-IAM-001"]),
    "abnormal_agent_chains": ("tool_abuse_pack", ["CTRL-AI-IAM-001", "CTRL-TOOL-001"]),
    "agent_over_scope_risk": ("ai_identity_abuse_pack", ["AI_IDENTITY_BINDING", "PRIVILEGE_DRIFT_DETECTION", "TOKEN_SCOPE_ENFORCEMENT"]),
    "agent_session_anomaly": ("ai_identity_abuse_pack", ["AI_IDENTITY_BINDING", "NON_HUMAN_IDENTITY_CONTROL", "CHAIN_OF_ACTION_VALIDATION"]),
    "unknown_ai_discovery_spike": ("governance_discovery_validation_pack", ["CTRL-TENANT-ISO-001"]),
    "unknown_ai_adoption_spike": ("governance_discovery_validation_pack", ["CTRL-TENANT-ISO-001"]),
    "repeated_sensitive_data_uploads": ("data_leakage_pack", ["CTRL-DLP-001"]),
    "repeated_sensitive_data_attempts": ("data_leakage_pack", ["CTRL-DLP-001"]),
    "repeated_justified_sensitive_transfers": ("data_leakage_pack", ["CTRL-DLP-001", "CTRL-TENANT-ISO-001"]),
    "oauth_supply_chain_attack": ("tool_abuse_pack", ["CTRL-AI-IAM-001", "CTRL-TOOL-001", "CTRL-DLP-001"]),
}


def _uniq(values: list[str] | None) -> list[str]:
    return sorted({str(item).strip() for item in (values or []) if str(item).strip()})


def build_trigger_plan(
    *,
    reason_code: str,
    related_control_ids: list[str] | None,
    recommended_action: str,
) -> TriggerPlan:
    target_pack, mapped_controls = TRIGGER_PACK_MAP.get(
        str(reason_code or "").strip(),
        ("governance_validation_pack", []),
    )
    controls = _uniq([*mapped_controls, *list(related_control_ids or [])])
    return TriggerPlan(
        reason_code=str(reason_code or "runtime_signal"),
        target_pack=target_pack,
        related_control_ids=controls,
        recommended_action=recommended_action,
    )


def create_runtime_simulation_trigger(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    event_id: str | None,
    reason_code: str,
    related_control_ids: list[str] | None,
    evidence_node_ids: list[str] | None,
    correlation_id: str | None,
    recommended_action: str,
) -> RuntimeSimulationTrigger:
    plan = build_trigger_plan(
        reason_code=reason_code,
        related_control_ids=related_control_ids,
        recommended_action=recommended_action,
    )

    trigger = RuntimeSimulationTrigger(
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        event_id=event_id,
        reason_code=plan.reason_code,
        target_pack=plan.target_pack,
        related_control_ids=plan.related_control_ids,
        evidence_node_ids=_uniq(list(evidence_node_ids or [])),
        correlation_id=correlation_id,
        recommended_action=plan.recommended_action,
        status="pending",
        schedule_decision_id=None,
    )
    db.add(trigger)
    db.flush()

    governance_status = resolve_ai_system_status(
        ai_system_id,
        {
            "db": db,
            "tenant_id": tenant_id,
            "route": "/runtime-intelligence/triggers",
            "module": "runtime_intelligence",
            "source_hint": "trust_center",
        },
    )

    if governance_status.get("status") == "UNKNOWN":
        runtime_evidence_ids = _uniq(list(evidence_node_ids or []))
        if event_id:
            runtime_event = db.scalar(
                select(RuntimeEvent).where(
                    RuntimeEvent.event_id == event_id,
                    RuntimeEvent.tenant_id == tenant_id,
                )
            )
            if runtime_event is not None:
                runtime_evidence_ids = _uniq([*runtime_evidence_ids, *list(runtime_event.evidence_node_ids or [])])

        unknown_node = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="runtime_governance_resolution",
            signal_type="runtime_intelligence.unregistered_ai_system",
            label="Runtime trigger on unregistered AI system",
            payload={
                "runtime_trigger_id": trigger.trigger_id,
                "runtime_event_id": event_id,
                "requested_ai_system_id": ai_system_id,
                "governance_status": governance_status,
            },
            correlation_id=correlation_id,
        )
        runtime_evidence_ids = _uniq([*runtime_evidence_ids, unknown_node.id])

        generate_unregistered_ai_system_finding(
            db,
            tenant_id=tenant_id,
            source_surface="monitoring",
            ai_tool=(ai_system_id or "unknown_ai_system"),
            requested_ai_system_id=ai_system_id,
            policy_version_id=None,
            evidence_node_ids=runtime_evidence_ids,
            related_control_ids=plan.related_control_ids or ["CTRL-TENANT-ISO-001"],
            recommended_action="Runtime trigger referenced unknown AI system. Route to governance before validation scheduling.",
        )

        if settings.governance_strict_mode:
            trigger.status = "blocked_unknown_ai_system"
            db.flush()

    if (
        settings.runtime_intelligence_schedule_simulations
        and ai_system_id
        and governance_status.get("status") != "UNKNOWN"
    ):
        try:
            from app.services.simulation_scheduler_service import schedule_simulation_pack

            decision = schedule_simulation_pack(
                db,
                tenant_id=tenant_id,
                reason_code=f"runtime_intelligence:{plan.reason_code}",
                target_ai_system_id=ai_system_id,
                target_control_ids=plan.related_control_ids,
                target_pack=plan.target_pack,
                trigger_payload={
                    "runtime_event_id": event_id,
                    "runtime_trigger_id": trigger.trigger_id,
                    "target_pack": plan.target_pack,
                },
                actor_user_id=None,
            )
            trigger.schedule_decision_id = decision.id
            trigger.status = "scheduled"
            db.flush()
        except Exception:
            trigger.status = "pending"
            db.flush()

    write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=None,
        actor_type="system",
        action="runtime_intelligence.trigger.created",
        resource_type="runtime_trigger",
        resource_id=trigger.trigger_id,
        payload={
            "event_id": event_id,
            "reason_code": trigger.reason_code,
            "target_pack": trigger.target_pack,
            "related_control_ids": trigger.related_control_ids,
            "status": trigger.status,
            "schedule_decision_id": trigger.schedule_decision_id,
            "governance_status": governance_status,
        },
        correlation_id=correlation_id,
    )
    return trigger
