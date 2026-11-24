from __future__ import annotations

from typing import Any

from app.services.brain.council import ModelCouncil
from app.services.brain.providers.base import LLMProvider


def _plan_step(step_id: str, tool: str) -> dict[str, Any]:
    return {
        "step_id": step_id,
        "tool": tool,
        "args": {},
        "expect_schema": {"type": "object"},
        "on_error": "stop",
    }


def _validate_plan(payload: dict[str, Any]) -> list[str]:
    raw_steps = payload.get("steps")
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ValueError("invalid")
    tools: list[str] = []
    for step in raw_steps:
        if not isinstance(step, dict):
            raise ValueError("invalid")
        tool = str(step.get("tool") or "").strip()
        if not tool:
            raise ValueError("invalid")
        tools.append(tool)
    return tools


class FakeProvider(LLMProvider):
    def __init__(self, name: str, payload: dict[str, Any] | None = None, error: str | None = None) -> None:
        self.name = name
        self.model = f"{name}-model"
        self._payload = payload
        self._error = error

    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict[str, Any]) -> dict[str, Any]:
        if self._error:
            raise RuntimeError(self._error)
        return dict(self._payload or {})

    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        if self._error:
            raise RuntimeError(self._error)
        return "ok"

    def health(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self._error is None, "model": self.model}


def _new_council() -> ModelCouncil:
    return ModelCouncil(db=None, tenant_id=None, user_id=None, correlation_id=None)


def test_planner_arbitration_identical_outputs() -> None:
    council = _new_council()
    plan = {"steps": [_plan_step("s1", "evidence.query")]}
    outputs = council.run_all(
        plan_id="plan-1",
        task_type="planner",
        providers=[FakeProvider("openai", plan), FakeProvider("claude", plan)],
        system_prompt="sys",
        user_prompt="usr",
        json_schema={"type": "object"},
    )
    decision = council.arbitrate_planner(plan_id="plan-1", outputs=outputs, validate_plan=_validate_plan, question="show posture")
    assert decision.winner_provider in {"openai", "claude"}
    assert decision.winner_output == plan
    assert decision.merge_strategy == "identical"


def test_planner_arbitration_conflicting_valid_outputs_prefers_evidence_and_snapshot() -> None:
    council = _new_council()
    weaker = {"steps": [_plan_step("s1", "evidence.query")]}
    stronger = {
        "steps": [
            _plan_step("s1", "evidence.query"),
            _plan_step("s2", "evidence.query"),
            _plan_step("s3", "auditor.create_snapshot"),
        ]
    }
    outputs = council.run_all(
        plan_id="plan-1",
        task_type="planner",
        providers=[FakeProvider("openai", weaker), FakeProvider("claude", stronger)],
        system_prompt="sys",
        user_prompt="usr",
        json_schema={"type": "object"},
    )
    decision = council.arbitrate_planner(plan_id="plan-1", outputs=outputs, validate_plan=_validate_plan, question="prove compliance")
    assert decision.winner_provider == "claude"
    assert decision.winner_output == stronger
    assert "conflicting_valid_outputs" in decision.reason_codes


def test_planner_arbitration_one_invalid_picks_valid() -> None:
    council = _new_council()
    valid = {"steps": [_plan_step("s1", "evidence.query")]}
    outputs = council.run_all(
        plan_id="plan-1",
        task_type="planner",
        providers=[FakeProvider("openai", valid), FakeProvider("claude", error="boom")],
        system_prompt="sys",
        user_prompt="usr",
        json_schema={"type": "object"},
    )
    decision = council.arbitrate_planner(plan_id="plan-1", outputs=outputs, validate_plan=_validate_plan, question="show posture")
    assert decision.winner_provider == "openai"
    assert decision.winner_output == valid
    assert decision.merge_strategy == "single_valid"


def test_planner_arbitration_both_invalid_returns_error_decision() -> None:
    council = _new_council()
    outputs = council.run_all(
        plan_id="plan-1",
        task_type="planner",
        providers=[FakeProvider("openai", error="boom-1"), FakeProvider("claude", error="boom-2")],
        system_prompt="sys",
        user_prompt="usr",
        json_schema={"type": "object"},
    )
    decision = council.arbitrate_planner(plan_id="plan-1", outputs=outputs, validate_plan=_validate_plan, question="show posture")
    assert decision.winner_provider is None
    assert decision.winner_output is None
    assert "both_invalid" in decision.reason_codes


def test_summarizer_arbitration_prefers_refusal_over_uncited_claims() -> None:
    council = _new_council()
    uncited = {
        "answer": "System is compliant.",
        "citations": [],
        "controls": [],
        "policies": [],
        "actions_taken": [],
        "confidence": 0.7,
        "missing_evidence": [],
        "proposed_actions": [],
    }
    refusal = {
        "answer": "INSUFFICIENT EVIDENCE",
        "citations": [],
        "controls": [],
        "policies": [],
        "actions_taken": ["evidence.query"],
        "confidence": 0.2,
        "missing_evidence": ["No evidence"],
        "proposed_actions": [{"tool": "evidence.query", "args": {}}],
    }
    outputs = council.run_all(
        plan_id="plan-1",
        task_type="summarizer",
        providers=[FakeProvider("openai", uncited), FakeProvider("claude", refusal)],
        system_prompt="sys",
        user_prompt="usr",
        json_schema={"type": "object"},
    )
    decision = council.arbitrate_summarizer(plan_id="plan-1", outputs=outputs, allowed_citation_ids=set())
    assert decision.winner_provider == "claude"
    assert decision.winner_output == refusal
    assert "prefer_refusal_over_uncited_claims" in decision.reason_codes
