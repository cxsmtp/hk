from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.core.observability import get_correlation_id
from app.db.models.ai_orchestration import AIReasoningTrace
from app.services.ai_orchestration.prompts import build_prompts
from app.services.ai_orchestration.providers import get_orchestration_provider
from app.services.ai_orchestration.routing_service import resolve_route
from app.services.ai_orchestration.safety import apply_post_call_guards, apply_pre_call_guards
from app.services.ai_orchestration.schemas import (
    OrchestrationResult,
    OrchestrationTaskRequest,
    RemediationGuidance,
    RemediationImpact,
    RemediationStep,
    RiskContext,
)
from app.services.audit_service import write_audit_log
from app.services.brain.rag.retriever import retrieve_knowledge_bundle
from app.services.control_graph_service import CANONICAL_CONTROLS, normalize_control_id
from app.services.crq_service import compute_control_crq_profile, compute_remediation_crq
from app.services.evidence_service import create_evidence_node
from app.services.llm_gateway_secure import SecureCallContext


def _compact_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    except Exception:
        return "{}"


def _estimate_token_usage(*, system_prompt: str, user_prompt: str, output_json: dict[str, Any]) -> dict[str, int]:
    prompt_chars = len(system_prompt) + len(user_prompt)
    completion_chars = len(_compact_json(output_json))
    prompt_tokens = max(1, prompt_chars // 4)
    completion_tokens = max(1, completion_chars // 4)
    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }


def _control_framework_map() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for row in CANONICAL_CONTROLS:
        control_id = str(row.get("control_id") or "").strip().upper()
        if not control_id:
            continue
        refs: list[str] = []
        for item in list(row.get("frameworks") or []):
            if not isinstance(item, dict):
                continue
            token = str(item.get("framework") or "").strip()
            if token and token not in refs:
                refs.append(token)
        out[control_id] = refs
    return out


_CONTROL_FRAMEWORK_MAP = _control_framework_map()


def _default_control_for_issue(issue_type: str) -> str:
    mapping = {
        "simulation_failure": "POLICY_ENFORCEMENT_CONTROL",
        "simulation_run": "POLICY_ENFORCEMENT_CONTROL",
        "drift_alert": "PRIVILEGE_DRIFT_DETECTION",
        "runtime_pattern": "POLICY_ENFORCEMENT_CONTROL",
        "finding": "POLICY_ENFORCEMENT_CONTROL",
        "agent_identity": "AGENT_ACTION_AUTHORIZATION",
        "shadow_ai_entity": "SHADOW_AI_DETECTION",
        "ai_system": "AI_SYSTEM_INVENTORY_CONTROL",
    }
    return mapping.get(str(issue_type or "").strip().lower(), "POLICY_ENFORCEMENT_CONTROL")


def _resolve_control_id(task: OrchestrationTaskRequest) -> str:
    direct = normalize_control_id(task.control_id)
    if direct:
        return direct
    for value in list(task.current_controls or []):
        normalized = normalize_control_id(value)
        if normalized:
            return normalized
    for key in ["dominant_control", "control_id"]:
        normalized = normalize_control_id((task.control_decision or {}).get(key))
        if normalized:
            return normalized
    return _default_control_for_issue(task.issue_type)


def _resolve_linked_frameworks(task: OrchestrationTaskRequest, *, control_id: str) -> list[str]:
    seen: list[str] = []
    for value in list(task.framework_refs or []):
        token = str(value or "").strip()
        if token and token not in seen:
            seen.append(token)
    for value in _CONTROL_FRAMEWORK_MAP.get(control_id, []):
        if value not in seen:
            seen.append(value)
    return seen


def _derive_retrieval_source_ids(retrieval_refs: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for row in retrieval_refs:
        if not isinstance(row, dict):
            continue
        for key in ["id", "source_id", "doc_id", "control_id", "template_id"]:
            token = str(row.get(key) or "").strip()
            if token and token not in out:
                out.append(token)
    return out


def _compute_risk_context(
    *,
    task: OrchestrationTaskRequest,
    control_id: str,
) -> tuple[RiskContext, dict[str, Any], RemediationImpact, dict[str, Any]]:
    risk_tags = [str(item).strip() for item in (task.context_payload or {}).get("risk_tags", []) if str(item).strip()]
    if not risk_tags:
        risk_tags = [str(task.issue_type or "policy_violation").strip().lower() or "policy_violation"]

    simulation_outcome = str((task.simulation_result or {}).get("final_outcome") or "").strip().lower()
    simulation_pass_rate = float((task.simulation_result or {}).get("pass_rate") or 0.0)
    if simulation_outcome == "pass" and simulation_pass_rate <= 0.0:
        simulation_pass_rate = 100.0
    elif simulation_outcome == "fail" and simulation_pass_rate <= 0.0:
        simulation_pass_rate = 0.0

    profile = compute_control_crq_profile(
        control_id=control_id,
        category=str((task.context_payload or {}).get("control_category") or "governance"),
        severity=task.severity,
        risk_tags=risk_tags,
        trigger_count=max(1, int((task.context_payload or {}).get("occurrence_count") or 1)),
        miss_count=max(0, int((task.simulation_result or {}).get("missed_controls_count") or 0)),
        observed_event_count=max(1, int((task.context_payload or {}).get("observed_event_count") or 1)),
        lookback_hours=max(1, int((task.context_payload or {}).get("lookback_hours") or 24)),
        simulation_pass_rate_percent=simulation_pass_rate,
        threat_type=risk_tags[0],
        asset=str((task.context_payload or {}).get("asset") or task.issue_type or "orchestration_task"),
    )

    control_risk_profile = dict(profile.get("control_risk_profile") or {})
    risk_context = RiskContext(
        current_ALE=float(control_risk_profile.get("current_risk") or 0.0),
        potential_ALE=float(control_risk_profile.get("baseline_risk") or 0.0),
        likelihood=float(profile.get("likelihood") or 0.0),
        impact=float(profile.get("risk_if_exploited") or 0.0),
    )

    preferred_action = str((task.context_payload or {}).get("preferred_remediation_type") or "investigate").strip().lower() or "investigate"
    remediation = compute_remediation_crq(
        remediation_type=preferred_action,
        risk_level=task.risk_tier,
        related_control_ids=[control_id],
        current_ale=risk_context.current_ALE,
        baseline_ale=risk_context.potential_ALE,
        context=task.context_payload,
    )
    decision_score = dict(remediation.get("decision_score") or {})
    remediation_impact = RemediationImpact(
        estimated_risk_reduction=float(remediation.get("estimated_risk_reduction") or 0.0),
        new_ALE=float(remediation.get("new_ALE") or 0.0),
        priority_score=float(decision_score.get("priority_score") or 0.0),
    )

    return risk_context, profile, remediation_impact, remediation


def _fallback_guidance(
    task: OrchestrationTaskRequest,
    *,
    reason: str,
    control_id: str,
    linked_frameworks: list[str],
    risk_context: RiskContext,
    remediation_impact: RemediationImpact,
) -> RemediationGuidance:
    allowed = set(task.allowed_remediation_types or [])

    def _allow(action: str, fallback: str) -> str:
        if not allowed:
            return action
        return action if action in allowed else fallback

    linked_controls = list({control_id, *list(task.current_controls or [])})
    steps: list[RemediationStep] = [
        RemediationStep(
            step_order=1,
            action_type=_allow("investigate", "investigate"),
            title="Validate issue evidence",
            description="Review linked evidence and runtime/audit traces before applying changes.",
            requires_approval=False,
            estimated_impact="low",
            linked_controls=linked_controls[:3],
            linked_frameworks=linked_frameworks[:3],
        ),
        RemediationStep(
            step_order=2,
            action_type=_allow("run_simulation", "investigate"),
            title="Run targeted validation",
            description="Execute targeted simulation/validation pack for the affected control path.",
            requires_approval=False,
            estimated_impact="medium",
            linked_controls=linked_controls[:3],
            linked_frameworks=linked_frameworks[:3],
        ),
        RemediationStep(
            step_order=3,
            action_type=_allow("ticket", "investigate"),
            title="Create owner-assigned remediation task",
            description="Create ITSM task with evidence lineage and assign accountable owner.",
            requires_approval=True,
            estimated_impact="medium",
            linked_controls=linked_controls[:2],
            linked_frameworks=linked_frameworks[:2],
        ),
    ]

    return RemediationGuidance(
        issue_id=task.issue_id,
        control_id=control_id,
        summary=f"Fallback remediation guidance generated ({reason}).",
        root_cause_hypothesis="Model reasoning was unavailable or blocked by orchestration safety policy.",
        recommended_steps=steps,
        priority="high" if task.severity in {"high", "critical"} else "med",
        confidence=0.35,
        notes="Human review required. Deterministic enforcement remains authoritative.",
        linked_controls=linked_controls,
        linked_frameworks=linked_frameworks,
        risk_context=risk_context,
        remediation_impact=remediation_impact,
    )


def _enforce_allowed_actions(guidance: RemediationGuidance, allowed: list[str]) -> tuple[RemediationGuidance, int]:
    allow = {str(item).strip() for item in allowed if str(item).strip()}
    adjusted = 0
    updated_steps: list[RemediationStep] = []

    for step in guidance.recommended_steps:
        requires_approval = bool(step.requires_approval)
        if step.action_type in {"policy_update", "restrict_permission", "review_owner", "rollback", "ticket"}:
            requires_approval = True

        if allow and step.action_type not in allow:
            adjusted += 1
            updated_steps.append(
                RemediationStep(
                    step_order=step.step_order,
                    action_type="investigate",
                    title=f"{step.title} (review required)",
                    description=(
                        f"Proposed action '{step.action_type}' is outside allowed remediation types; "
                        "investigate and route for approval."
                    ),
                    requires_approval=True,
                    estimated_impact=step.estimated_impact,
                    linked_controls=step.linked_controls,
                    linked_frameworks=step.linked_frameworks,
                )
            )
            continue

        updated_steps.append(
            RemediationStep(
                step_order=step.step_order,
                action_type=step.action_type,
                title=step.title,
                description=step.description,
                requires_approval=requires_approval,
                estimated_impact=step.estimated_impact,
                linked_controls=step.linked_controls,
                linked_frameworks=step.linked_frameworks,
            )
        )

    return guidance.model_copy(update={"recommended_steps": updated_steps}), adjusted


def _retrieval_refs(
    db: Session,
    *,
    task: OrchestrationTaskRequest,
    tenant_id: str,
) -> list[dict[str, Any]]:
    if task.retrieval_refs:
        return [dict(row) for row in task.retrieval_refs if isinstance(row, dict)]

    question = f"{task.issue_type}: {task.issue_title}\n{task.issue_summary}".strip()
    if not question:
        return []

    bundle = retrieve_knowledge_bundle(
        db,
        question=question,
        tenant_id=tenant_id,
        ai_system_id=str(task.context_payload.get("ai_system_id") or "") or None,
        frameworks_in_scope=task.framework_refs,
    )
    refs: list[dict[str, Any]] = []
    for key in ["top_controls", "top_guardian_contracts", "top_sim_templates", "top_docs"]:
        rows = bundle.get(key) if isinstance(bundle, dict) else []
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    refs.append({"source": key, **row})
    return refs[:40]


def _response_schema() -> dict[str, Any]:
    return RemediationGuidance.model_json_schema()


def run_orchestration_task(
    db: Session,
    *,
    tenant_id: str,
    actor_user_id: str | None,
    task: OrchestrationTaskRequest,
    correlation_id: str | None,
) -> OrchestrationResult:
    corr = correlation_id or get_correlation_id()
    control_id = _resolve_control_id(task)
    current_controls = list({control_id, *[str(item).strip() for item in (task.current_controls or []) if str(item).strip()]})

    normalized_task = task.model_copy(
        update={
            "control_id": control_id,
            "current_controls": current_controls,
            "runtime_event_refs": list(task.runtime_event_refs or []),
        }
    )

    route, _routing_ctx = resolve_route(normalized_task)
    linked_frameworks = _resolve_linked_frameworks(normalized_task, control_id=control_id)
    retrieval_refs = _retrieval_refs(db, task=normalized_task, tenant_id=tenant_id)
    retrieval_source_ids = _derive_retrieval_source_ids(retrieval_refs)
    system_prompt, user_prompt, prompt_vars, template = build_prompts(normalized_task, retrieval_refs=retrieval_refs)

    risk_context, control_crq_profile, remediation_impact_obj, remediation_crq_payload = _compute_risk_context(
        task=normalized_task,
        control_id=control_id,
    )

    redacted_prompt_vars, pre_guard = apply_pre_call_guards(
        task=normalized_task,
        route=route,
        prompt_variables=prompt_vars,
        template=template,
    )

    raw_output: dict[str, Any]
    status = "completed"
    rejection_reason: str | None = None
    output_schema_valid = False
    secure_trace: dict[str, Any] = {}

    if not pre_guard.passed:
        status = "rejected_pre_call"
        rejection_reason = pre_guard.reason
        guidance = _fallback_guidance(
            normalized_task,
            reason=pre_guard.reason,
            control_id=control_id,
            linked_frameworks=linked_frameworks,
            risk_context=risk_context,
            remediation_impact=remediation_impact_obj,
        )
        raw_output = guidance.model_dump()
        output_schema_valid = True
        post_guard = apply_post_call_guards(raw_output=raw_output)
    else:
        try:
            provider = get_orchestration_provider(route)
            secure_result = provider.secure_generate_json(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                json_schema=_response_schema(),
                context=SecureCallContext(
                    task_type=normalized_task.task_type,
                    data_sensitivity=normalized_task.data_sensitivity,
                    risk_tier=normalized_task.risk_tier,
                    cost_ceiling_usd=float(normalized_task.cost_ceiling_usd or 0.0),
                    customer_region=str(normalized_task.customer_region or "global"),
                    region_requirement=str(normalized_task.region_requirement or "global"),
                    residency_requirement=str(normalized_task.residency_requirement or ""),
                    residency_required=bool(normalized_task.residency_required),
                    customer_policy_profile=dict(normalized_task.customer_policy_profile or {}),
                    policy_applied=str(route.routing_policy_id or ""),
                    policy_version=str(normalized_task.policy_version or ""),
                    governance_version=str(normalized_task.governance_version or ""),
                    prompt_template_id=template.template_id,
                    prompt_template_version=template.template_version,
                    retrieval_sources=list(retrieval_source_ids),
                    tool_calls=[],
                ),
                db=db,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=corr,
            )
            secure_trace = dict(secure_result.trace or {})
            if secure_result.blocked:
                reason = str(secure_result.block_reason or "secure_gateway_blocked")
                status = "rejected_post_call" if reason == "post_call_policy_rejected" else "rejected_pre_call"
                rejection_reason = reason
                guidance = _fallback_guidance(
                    normalized_task,
                    reason=reason,
                    control_id=control_id,
                    linked_frameworks=linked_frameworks,
                    risk_context=risk_context,
                    remediation_impact=remediation_impact_obj,
                )
                raw_output = guidance.model_dump()
                output_schema_valid = True
                post_guard = apply_post_call_guards(raw_output=raw_output)
            else:
                raw_output = dict(secure_result.output_json or {})
                post_guard = apply_post_call_guards(raw_output=raw_output)
                try:
                    guidance = RemediationGuidance.model_validate(raw_output)
                    output_schema_valid = True
                except Exception as schema_exc:  # noqa: BLE001
                    status = "output_schema_invalid"
                    rejection_reason = f"output_schema_invalid:{schema_exc}"
                    guidance = _fallback_guidance(
                        normalized_task,
                        reason="output_schema_invalid",
                        control_id=control_id,
                        linked_frameworks=linked_frameworks,
                        risk_context=risk_context,
                        remediation_impact=remediation_impact_obj,
                    )
                    raw_output = guidance.model_dump()
        except Exception as exc:  # noqa: BLE001
            status = "provider_error"
            rejection_reason = f"provider_error:{exc}"
            guidance = _fallback_guidance(
                normalized_task,
                reason="provider_unavailable",
                control_id=control_id,
                linked_frameworks=linked_frameworks,
                risk_context=risk_context,
                remediation_impact=remediation_impact_obj,
            )
            raw_output = guidance.model_dump()
            output_schema_valid = False
            post_guard = apply_post_call_guards(raw_output=raw_output)

    guidance = guidance.model_copy(
        update={
            "control_id": control_id,
            "linked_controls": current_controls,
            "linked_frameworks": linked_frameworks,
            "risk_context": risk_context,
            "remediation_impact": remediation_impact_obj,
        }
    )
    guidance, adjusted_count = _enforce_allowed_actions(guidance, normalized_task.allowed_remediation_types)
    raw_output = guidance.model_dump()

    usage = _estimate_token_usage(system_prompt=system_prompt, user_prompt=user_prompt, output_json=raw_output)
    cost_estimate = round(float(route.estimated_cost_usd) * float(max(1, usage["total_tokens"]) / 1000.0), 6)

    trace = AIReasoningTrace(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        issue_type=normalized_task.issue_type,
        issue_id=normalized_task.issue_id,
        task_type=normalized_task.task_type,
        provider=route.provider,
        model=route.model,
        model_version=route.model_version,
        prompt_template_id=template.template_id,
        prompt_template_version=template.template_version,
        prompt_template_status=template.status,
        prompt_variables_json=redacted_prompt_vars,
        retrieval_refs_json=retrieval_refs,
        retrieval_source_ids_json=retrieval_source_ids,
        evidence_refs_json=list(normalized_task.evidence_refs),
        runtime_event_refs_json=list(normalized_task.runtime_event_refs),
        policy_version=str(normalized_task.policy_version or ""),
        governance_version=str(normalized_task.governance_version or ""),
        control_id=control_id,
        control_decision_json=dict(normalized_task.control_decision or {}),
        simulation_result_json=dict(normalized_task.simulation_result or {}),
        routing_context_json=dict(route.routing_context or {}),
        risk_context_json=risk_context.model_dump(),
        remediation_impact_json=remediation_impact_obj.model_dump(),
        routing_policy_id=route.routing_policy_id,
        policy_route_id=route.route_id,
        region_route=route.region_route,
        pre_call_guard_results_json=pre_guard.model_dump(),
        post_call_guard_results_json={
            **post_guard.model_dump(),
            "adjusted_steps": adjusted_count,
            "route_status": route.route_status,
            "constraint_failures": list(route.constraint_failures or []),
            "secure_gateway_trace": secure_trace,
        },
        output_schema_valid=output_schema_valid,
        token_usage_json=usage,
        cost_estimate_usd=cost_estimate,
        status=status,
        output_json=raw_output,
        rejection_reason=rejection_reason,
        correlation_id=corr,
    )
    db.add(trace)
    db.flush()

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type="human" if actor_user_id else "system",
        action="ai_orchestration.reasoning.generated",
        resource_type="ai_reasoning_trace",
        resource_id=trace.id,
        payload={
            "task_type": normalized_task.task_type,
            "issue_type": normalized_task.issue_type,
            "issue_id": normalized_task.issue_id,
            "control_id": control_id,
            "provider": route.provider,
            "model": route.model,
            "model_version": route.model_version,
            "prompt_template_id": template.template_id,
            "prompt_template_version": template.template_version,
            "routing_policy_id": route.routing_policy_id,
            "policy_route_id": route.route_id,
            "route_status": route.route_status,
            "status": status,
        },
        correlation_id=corr,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="ai_reasoning_trace",
        signal_type=f"ai_orchestration.{normalized_task.task_type}",
        label=f"AI orchestration trace for {normalized_task.issue_type}:{normalized_task.issue_id}",
        payload={
            "trace_id": trace.id,
            "issue_type": normalized_task.issue_type,
            "issue_id": normalized_task.issue_id,
            "control_id": control_id,
            "provider": route.provider,
            "model": route.model,
            "model_version": route.model_version,
            "prompt_template_id": template.template_id,
            "prompt_template_version": template.template_version,
            "routing_policy_id": route.routing_policy_id,
            "policy_route_id": route.route_id,
            "route_status": route.route_status,
            "routing_context": dict(route.routing_context or {}),
            "status": status,
            "rejection_reason": rejection_reason,
            "evidence_refs": list(normalized_task.evidence_refs),
            "runtime_event_refs": list(normalized_task.runtime_event_refs),
            "retrieval_source_ids": retrieval_source_ids,
            "retrieval_refs_count": len(retrieval_refs),
            "control_crq": control_crq_profile,
            "remediation_crq": remediation_crq_payload,
            "audit_log_id": audit.id,
        },
        correlation_id=corr,
    )

    return OrchestrationResult(
        trace_id=trace.id,
        task_type=normalized_task.task_type,
        control_id=control_id,
        provider=route.provider,
        model=route.model,
        model_version=route.model_version,
        prompt_template_id=template.template_id,
        prompt_template_version=template.template_version,
        prompt_template_status=template.status,
        routing_policy_id=route.routing_policy_id,
        policy_route_id=route.route_id,
        region_route=route.region_route,
        routing_context=dict(route.routing_context or {}),
        retrieval_refs=retrieval_refs,
        retrieval_source_ids=retrieval_source_ids,
        evidence_refs=list(normalized_task.evidence_refs),
        runtime_event_refs=list(normalized_task.runtime_event_refs),
        control_decision=dict(normalized_task.control_decision or {}),
        simulation_result=dict(normalized_task.simulation_result or {}),
        policy_version=str(normalized_task.policy_version or ""),
        governance_version=str(normalized_task.governance_version or ""),
        pre_call_guard_results=trace.pre_call_guard_results_json,
        post_call_guard_results=trace.post_call_guard_results_json,
        output_schema_valid=output_schema_valid,
        token_usage=usage,
        cost_estimate_usd=cost_estimate,
        status=status,
        rejection_reason=rejection_reason,
        risk_context=risk_context,
        remediation_impact=remediation_impact_obj,
        remediation_guidance=guidance,
        audit_log_id=audit.id,
        evidence_node_id=evidence.id,
    )
