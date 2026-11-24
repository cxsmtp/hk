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
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


class BrainAnswerContract(BaseModel):
    answer: str
    claims: list[BrainClaim] = Field(default_factory=list)
    citations: list[BrainCitation] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    missing_evidence: list[str] = Field(default_factory=list)
    proposed_actions: list[BrainProposedAction] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_structured_citations(self) -> "BrainAnswerContract":
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
