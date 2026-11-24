from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from app.services.llm_gateway_secure.data_minimizer import sanitize_retrieval_refs
from app.services.llm_gateway_secure.prompt_registry import get_prompt_template as get_registry_prompt_template
from app.services.ai_orchestration.schemas import OrchestrationTaskRequest


class PromptTemplateSpec(BaseModel):
    template_id: str
    template_version: str
    task_type: str
    template_text: str
    expected_output_schema: str
    allowed_models: list[str] = Field(default_factory=list)
    status: str = "active"


def _compact_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    except Exception:
        return "{}"


def get_prompt_template(task_type: str) -> PromptTemplateSpec:
    normalized = str(task_type or "").strip().lower()
    registry_template = get_registry_prompt_template(normalized)
    if registry_template is not None:
        return PromptTemplateSpec(
            template_id=registry_template.template_id,
            template_version=registry_template.version,
            task_type=registry_template.task_type,
            template_text=registry_template.template_text,
            expected_output_schema=registry_template.expected_output_schema or "RemediationGuidance",
            allowed_models=list(registry_template.approved_for_providers),
            status=registry_template.status,
        )
    return PromptTemplateSpec(
        template_id="hawk.generic_reasoning",
        template_version="v1",
        task_type=normalized or "generic",
        template_text="Generate safe, structured recommendation output with explicit uncertainty.",
        expected_output_schema="RemediationGuidance",
        allowed_models=["gpt", "claude", "gemini", "llama"],
    )


def prompt_template_id(task_type: str) -> str:
    template = get_prompt_template(task_type)
    return f"{template.template_id}.{template.template_version}"


def build_prompts(
    task: OrchestrationTaskRequest,
    *,
    retrieval_refs: list[dict[str, Any]],
) -> tuple[str, str, dict[str, Any], PromptTemplateSpec]:
    template = get_prompt_template(task.task_type)
    sanitized_retrieval_refs = sanitize_retrieval_refs(retrieval_refs)
    vars_payload: dict[str, Any] = {
        "task_type": task.task_type,
        "control_id": task.control_id,
        "issue_type": task.issue_type,
        "issue_id": task.issue_id,
        "issue_title": task.issue_title,
        "issue_summary": task.issue_summary,
        "severity": task.severity,
        "risk_tier": task.risk_tier,
        "data_sensitivity": task.data_sensitivity,
        "governance_state": task.governance_state,
        "policy_version": task.policy_version,
        "governance_version": task.governance_version,
        "allowed_remediation_types": list(task.allowed_remediation_types),
        "current_controls": list(task.current_controls),
        "framework_refs": list(task.framework_refs),
        "context_payload": dict(task.context_payload),
        "control_decision": dict(task.control_decision),
        "simulation_result": dict(task.simulation_result),
        "runtime_event_refs": list(task.runtime_event_refs),
        "retrieval_refs": sanitized_retrieval_refs,
    }

    system_prompt = (
        "You are Hawk AI Reasoning Layer. "
        "You generate structured recommendations only. "
        "Never emit direct enforcement commands, shell commands, or autonomous execution steps. "
        "Every recommendation must stay linked to control_id, evidence refs, and framework refs. "
        f"Template={template.template_id}.{template.template_version}. "
        "Return strict JSON matching the requested schema. "
        "If evidence is weak, lower confidence and recommend investigation."
    )

    user_prompt = (
        f"Template instruction: {template.template_text}\n"
        "Generate remediation guidance for this issue. Output must be safe, human-reviewable, "
        "and bounded to allowed remediation types.\n"
        f"INPUT={_compact_json(vars_payload)}"
    )

    return system_prompt, user_prompt, vars_payload, template
