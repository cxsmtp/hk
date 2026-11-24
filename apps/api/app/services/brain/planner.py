from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any

from sqlalchemy.orm import Session

from app.services.agui.registry import get_agui_registry
from app.services.brain.council import ModelCouncil
from app.services.brain.router import ModelRouter
from app.services.brain.providers.base import LLMProvider
from app.services.brain.schemas import BrainPlan, BrainPlanStep
from app.services.brain.store import create_brain_session, save_brain_plan, update_brain_plan_json
from app.services.brain.tools import list_tools, tool_exists


RUNTIME_ALLOWED_TOOLS = [
    "governance.list_ai_systems",
    "governance.get_ai_system",
    "governance.update_ai_system_state",
    "governance.assign_owner",
    "governance.set_risk_tier",
    "findings.list",
    "findings.get",
    "findings.update_status",
    "findings.analyze",
    "policies.get_policy_version",
    "policies.get_guardian_matrix",
    "policies.activate_policy_version",
    "evidence.query",
    "evidence.get_node",
    "evidence.get_trace",
    "enforcement.list_events",
    "simulations.list_for_control",
    "simulations.run",
    "simulations.run_pack",
    "simulations.get_result",
    "auditor.create_snapshot",
    "auditor.export_snapshot",
    "auditor.challenge_control",
    "auditor.get_snapshot",
    "aiiam.get_agent",
    "aiiam.mint_token",
    "aiiam.revoke_token",
    "aiiam.kill_switch",
    "integrations.list",
    "integrations.pull_signals",
    "integrations.get_health",
    "tickets.create_jira",
    "workflows.request_approval",
    "ops.jobs_status",
]


def _allowed_actions() -> list[str]:
    return [row["action_id"] for row in get_agui_registry().list_actions()]


def _plan_json_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "steps": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "step_id": {"type": "string"},
                        "execution_type": {"type": "string", "enum": ["mcp_tool_call", "agui_action_request"]},
                        "tool": {"type": "string"},
                        "action_id": {"type": "string"},
                        "args": {"type": "object"},
                        "expect_schema": {"type": "object"},
                        "on_error": {"type": "string", "enum": ["stop", "continue_with_warning"]},
                    },
                    "required": ["step_id", "args", "expect_schema", "on_error"],
                    "additionalProperties": False,
                },
            }
        },
        "required": ["steps"],
        "additionalProperties": False,
    }


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _runtime_planner_prompt(
    *,
    tenant_id: str,
    user_role: str,
    question: str,
    now_iso: str,
) -> str:
    tools_block = "\n".join(RUNTIME_ALLOWED_TOOLS)
    actions_block = "\n".join(_allowed_actions())
    return (
        "Allowed Tools:\n\n"
        f"{tools_block}\n\n"
        "Allowed AGUI Actions:\n\n"
        f"{actions_block}\n\n"
        f"Tenant: {tenant_id}\n"
        f"User role: {user_role}\n"
        f"Time now (UTC): {now_iso}\n\n"
        "Question:\n"
        f"{question}\n\n"
        "Return a JSON plan that matches the schema exactly."
    )


def _planner_system_prompt() -> str:
    return (
        "You are Hawk Brain Planner.\n\n"
        "You are one model in a multi-model council. Your output will be compared with other models.\n"
        "Therefore:\n\n"
        "You must be deterministic.\n"
        "You must be conservative.\n"
        "You must maximize evidence retrieval and audit defensibility.\n"
        "You must output ONLY valid JSON.\n\n"
        "You MUST output ONLY valid JSON matching the provided JSON Schema.\n"
        "No markdown. No commentary. No extra keys.\n\n"
        "Core rules:\n"
        "1) You are NOT allowed to answer the question directly.\n"
        "2) You must produce a tool plan that retrieves evidence BEFORE conclusions.\n"
        "3) If the question contains words like \"prove\", \"audit\", \"compliance\", \"ISO\", \"SOC2\", \"PDPL\":\n\n"
        "Include evidence.query\n"
        "Include auditor.create_snapshot\n"
        "4) If the question involves enforcement behavior:\n\n"
        "Include enforcement.list_events + evidence.query\n"
        "5) If the question involves simulations or control validation:\n\n"
        "Include simulations.list_for_control + simulations.run\n"
        "6) Plans must be minimal but complete: do not add unnecessary steps.\n"
        "7) Assume the platform is multi-tenant: include ai_system_id/tenant filters where applicable.\n\n"
        "Output strictly JSON matching schema."
    )


def _validate_planner_output(payload: dict[str, Any]) -> list[str]:
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("Planner returned no steps")
    planned_tools: list[str] = []
    allowed_runtime_tools = set(RUNTIME_ALLOWED_TOOLS)
    allowed_actions = set(_allowed_actions())
    for row in raw_steps:
        step = BrainPlanStep.model_validate(row)
        if step.execution_type == "agui_action_request":
            action_id = str(step.action_id or "").strip()
            if not action_id:
                raise ValueError("Planner proposed AGUI action step without action_id")
            if action_id not in allowed_actions:
                raise ValueError(f"Planner proposed unknown AGUI action '{action_id}'")
            continue
        if not tool_exists(step.tool):
            raise ValueError(f"Planner proposed unknown tool '{step.tool}'")
        if str(step.tool or "").strip() not in allowed_runtime_tools:
            raise ValueError(f"Planner proposed disallowed runtime tool '{step.tool}'")
        planned_tools.append(str(step.tool))
    return planned_tools


def create_plan(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    user_role: str,
    question: str,
    context: dict[str, Any],
    provider: LLMProvider | None = None,
    model_router: ModelRouter | None = None,
    model_council: ModelCouncil | None = None,
    risk_tier: str | None = None,
    tenant_policy: dict[str, Any] | None = None,
) -> BrainPlan:
    if not question.strip():
        raise ValueError("question is required")

    _tools = list_tools()
    session = create_brain_session(
        db,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    plan_record = save_brain_plan(
        db,
        session_id=session.id,
        question=question,
        plan_json={
            "question": question,
            "steps": [],
            "status": "planning",
        },
    )

    system_prompt = _planner_system_prompt()
    runtime_prompt = _runtime_planner_prompt(
        tenant_id=tenant_id,
        user_role=user_role,
        question=question,
        now_iso=_utcnow_iso(),
    )
    user_prompt = (
        f"{runtime_prompt}\n\n"
        f"Context JSON:\n{json.dumps(context or {}, sort_keys=True)}\n\n"
        f"Available tools:\n{json.dumps(_tools, sort_keys=True)}\n"
    )
    if model_router and model_council:
        providers = model_router.choose_models(
            task_type="planner",
            risk_tier=risk_tier,
            tenant_policy=tenant_policy,
        )
        model_outputs = model_council.run_all(
            plan_id=plan_record.id,
            task_type="planner",
            providers=providers,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=_plan_json_schema(),
            risk_tier=risk_tier,
            tenant_policy=tenant_policy,
            prompt_template_id="hawk.brain_planner",
            prompt_template_version="v1",
        )
        arbitration = model_council.arbitrate_planner(
            plan_id=plan_record.id,
            outputs=model_outputs,
            validate_plan=_validate_planner_output,
            question=question,
        )
        if not arbitration.winner_output:
            raise ValueError("Planner arbitration failed: no valid plans produced")
        payload = arbitration.winner_output
    else:
        if provider is None:
            raise ValueError("Planner requires provider or model_router/model_council")
        single_council = ModelCouncil(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            correlation_id=None,
        )
        outputs = single_council.run_all(
            plan_id=plan_record.id,
            task_type="planner",
            providers=[provider],
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=_plan_json_schema(),
            risk_tier=risk_tier,
            tenant_policy=tenant_policy,
            prompt_template_id="hawk.brain_planner",
            prompt_template_version="v1",
        )
        first = outputs[0]
        if not first.ok or not isinstance(first.output, dict):
            raise RuntimeError(first.error or "Planner secure generation failed")
        payload = first.output

    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("Planner returned no steps")
    steps = [BrainPlanStep.model_validate(row) for row in raw_steps]
    allowed_actions = set(_allowed_actions())
    allowed_runtime_tools = set(RUNTIME_ALLOWED_TOOLS)
    for step in steps:
        if step.execution_type == "agui_action_request":
            action_id = str(step.action_id or "").strip()
            if action_id not in allowed_actions:
                raise ValueError(f"Planner proposed unknown AGUI action '{action_id}'")
            continue
        if not tool_exists(step.tool):
            raise ValueError(f"Planner proposed unknown tool '{step.tool}'")
        if str(step.tool or "").strip() not in allowed_runtime_tools:
            raise ValueError(f"Planner proposed disallowed runtime tool '{step.tool}'")

    question_lower = question.lower()
    existing_tools = {
        str(step.tool)
        for step in steps
        if step.execution_type == "mcp_tool_call" and str(step.tool or "").strip()
    }

    def append_step(
        *,
        tool: str,
        args: dict[str, Any],
        expect_schema: dict[str, Any],
        on_error: str = "continue_with_warning",
    ) -> None:
        if tool in existing_tools:
            return
        step_index = len(steps) + 1
        step = BrainPlanStep(
            step_id=f"s{step_index}",
            tool=tool,
            args=args,
            expect_schema=expect_schema,
            on_error=on_error,
        )
        steps.append(step)
        existing_tools.add(tool)

    # Always include at least one evidence retrieval step.
    append_step(
        tool="evidence.query",
        args={"time_range": {}, "filters": {}, "limit": 25, "cursor": "0"},
        expect_schema={"items": "array", "total": "number", "evidence_node_ids": "array"},
        on_error="continue_with_warning",
    )

    if any(keyword in question_lower for keyword in ("enforcement", "blocked", "decision", "outcome")):
        append_step(
            tool="enforcement.list_events",
            args={
                "filters": {"ai_system_id": context.get("ai_system_id")},
                "limit": 25,
                "cursor": "0",
            },
            expect_schema={"items": "array", "total": "number", "evidence_node_ids": "array"},
            on_error="continue_with_warning",
        )
        append_step(
            tool="evidence.query",
            args={"time_range": {}, "filters": {}, "limit": 50, "cursor": "0"},
            expect_schema={"items": "array", "total": "number", "evidence_node_ids": "array"},
            on_error="continue_with_warning",
        )

    if any(keyword in question_lower for keyword in ("audit proof", "prove compliance", "compliance proof", "auditor", "audit")):
        append_step(
            tool="auditor.create_snapshot",
            args={
                "framework": context.get("framework", "NIST-AI-RMF"),
                "period": context.get("period", {"days": 30}),
                "ai_system_id": context.get("ai_system_id"),
            },
            expect_schema={"snapshot_id": "string", "snapshot_ids": "array"},
            on_error="continue_with_warning",
        )
        append_step(
            tool="evidence.query",
            args={"time_range": {}, "filters": {}, "limit": 50, "cursor": "0"},
            expect_schema={"items": "array", "total": "number", "evidence_node_ids": "array"},
            on_error="continue_with_warning",
        )

    update_brain_plan_json(
        db,
        plan=plan_record,
        plan_json={
            "question": question,
            "steps": [step.model_dump() for step in steps],
            "status": "planned",
        },
    )
    return BrainPlan(
        plan_id=plan_record.id,
        question=question,
        steps=steps,
    )
