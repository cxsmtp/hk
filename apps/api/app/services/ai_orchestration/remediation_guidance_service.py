from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.services.control_graph_service import framework_ref_labels_for_control_ids, normalize_control_ids
from app.services.ai_orchestration.orchestrator import run_orchestration_task
from app.services.ai_orchestration.schemas import OrchestrationResult, OrchestrationTaskRequest


def normalize_orchestration_task(task: OrchestrationTaskRequest) -> OrchestrationTaskRequest:
    control_id = normalize_control_ids([str(task.control_id or "")])[0] if str(task.control_id or "").strip() else ""
    if not control_id:
        for item in list(task.current_controls or []):
            normalized = normalize_control_ids([str(item or "")])
            token = normalized[0] if normalized else ""
            if token:
                control_id = token
                break
    if not control_id:
        control_id = "POLICY_ENFORCEMENT_CONTROL"

    current_controls = normalize_control_ids([control_id, *[str(item) for item in (task.current_controls or [])]])
    framework_refs = list(task.framework_refs or []) or framework_ref_labels_for_control_ids(current_controls)

    return task.model_copy(
        update={
            "control_id": control_id,
            "current_controls": current_controls,
            "framework_refs": framework_refs,
        }
    )


def generate_remediation_guidance(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    task: OrchestrationTaskRequest,
    correlation_id: str | None,
) -> OrchestrationResult:
    normalized_task = normalize_orchestration_task(task)
    return run_orchestration_task(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        task=normalized_task,
        correlation_id=correlation_id,
    )


def build_simulation_failure_task(
    *,
    simulation_id: str,
    simulation_run_id: str,
    related_control_ids: list[str],
    occurrence_count: int,
    evidence_refs: list[str],
    severity: str,
    risk_tier: str,
) -> OrchestrationTaskRequest:
    normalized_controls = normalize_control_ids(list(related_control_ids or [])) or ["POLICY_ENFORCEMENT_CONTROL"]
    control_id = normalized_controls[0]
    return OrchestrationTaskRequest(
        task_type="simulation_failure_explanation",
        control_id=control_id,
        issue_type="simulation_failure",
        issue_id=simulation_run_id,
        issue_title=f"Simulation failure for control {control_id}",
        issue_summary=(
            f"Simulation {simulation_id} failed for control set {', '.join(normalized_controls)}. "
            f"Repeated failures observed: {occurrence_count}."
        ),
        severity=severity,
        risk_tier=risk_tier,
        data_sensitivity="internal",
        evidence_refs=list(evidence_refs),
        runtime_event_refs=[],
        current_controls=normalized_controls,
        governance_state="review",
        allowed_remediation_types=[
            "policy_update",
            "restrict_permission",
            "review_owner",
            "run_simulation",
            "ticket",
            "investigate",
            "rollback",
        ],
        framework_refs=framework_ref_labels_for_control_ids(normalized_controls),
        context_payload={
            "simulation_id": simulation_id,
            "simulation_run_id": simulation_run_id,
            "related_control_ids": normalized_controls,
            "occurrence_count": occurrence_count,
            "source_trigger_type": "simulation_failure",
            "preferred_remediation_type": "policy_tighten",
        },
        simulation_result={
            "simulation_run_id": simulation_run_id,
            "final_outcome": "fail",
        },
    )


def summarize_guidance(result: OrchestrationResult) -> dict[str, Any]:
    guidance = result.remediation_guidance
    return {
        "trace_id": result.trace_id,
        "status": result.status,
        "provider": result.provider,
        "model": result.model,
        "prompt_template_id": f"{result.prompt_template_id}.{result.prompt_template_version}",
        "control_id": result.control_id,
        "risk_context": result.risk_context.model_dump(),
        "remediation_impact": result.remediation_impact.model_dump(),
        "root_cause": (guidance.root_cause_hypothesis if guidance is not None else ""),
        "recommended_steps": ([step.model_dump() for step in guidance.recommended_steps] if guidance is not None else []),
        "priority": (guidance.priority if guidance is not None else "high"),
    }
