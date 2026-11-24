from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


class BrainClaim(BaseModel):
    id: str
    text: str


class BrainCitation(BaseModel):
    type: Literal["evidence_node", "snapshot"]
    id: str
    supports: list[str] = Field(default_factory=list)
    note: str | None = None
    ts: str | None = None


class BrainProposedAction(BaseModel):
    tool: str | None = None
    action_id: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_action_ref(self) -> "BrainProposedAction":
        if not str(self.tool or "").strip() and not str(self.action_id or "").strip():
            raise ValueError("Proposed action must include tool or action_id.")
        return self


class BrainPlanStep(BaseModel):
    step_id: str
    execution_type: Literal["mcp_tool_call", "agui_action_request"] = "mcp_tool_call"
    tool: str | None = None
    action_id: str | None = None
    args: dict[str, Any] = Field(default_factory=dict)
    expect_schema: dict[str, Any] = Field(default_factory=dict)
    on_error: Literal["stop", "continue_with_warning"] = "stop"

    @model_validator(mode="after")
    def validate_step_ref(self) -> "BrainPlanStep":
        if self.execution_type == "mcp_tool_call":
            if not str(self.tool or "").strip():
                raise ValueError("mcp_tool_call step requires tool")
            return self
        if not str(self.action_id or "").strip():
            raise ValueError("agui_action_request step requires action_id")
        return self


class BrainPlan(BaseModel):
    plan_id: str
    question: str
    steps: list[BrainPlanStep]


class BrainStepExecution(BaseModel):
    step_id: str
    execution_type: Literal["mcp_tool_call", "agui_action_request"] = "mcp_tool_call"
    tool: str | None = None
    action_id: str | None = None
    status: Literal["success", "fail", "needs_approval"]
    args: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    tool_call_id: str


class BrainExecutionResult(BaseModel):
    plan_id: str
    steps_executed: list[BrainStepExecution]
    citations: list[BrainCitation]
    confidence: float
    missing_evidence: list[str]
    proposed_actions: list[BrainProposedAction]


class BrainAnswer(BaseModel):
    answer: str
    claims: list[BrainClaim]
    citations: list[BrainCitation]
    controls: list[str]
    frameworks: list[str]
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float
    missing_evidence: list[str]
    proposed_actions: list[BrainProposedAction]

    @model_validator(mode="after")
    def validate_structured_citations(self) -> "BrainAnswer":
        refusal = self.answer == "INSUFFICIENT EVIDENCE"
        if refusal:
            if self.citations:
                raise ValueError("Refusal responses must have empty citations.")
            if not self.proposed_actions:
                raise ValueError("Refusal responses must include proposed_actions.")
            return self

        if not self.claims:
            raise ValueError("Non-refusal responses must include claims.")
        if not self.citations:
            raise ValueError("Non-refusal responses must include citations.")

        claim_ids = {claim.id for claim in self.claims}
        supported_claims: set[str] = set()
        for citation in self.citations:
            if not citation.supports:
                raise ValueError("Each citation must support at least one claim id.")
            for claim_id in citation.supports:
                if claim_id not in claim_ids:
                    raise ValueError(f"Citation references unknown claim id '{claim_id}'.")
                supported_claims.add(claim_id)

        missing = claim_ids - supported_claims
        if missing:
            raise ValueError(f"Claims without citation support: {sorted(missing)}")
        return self
