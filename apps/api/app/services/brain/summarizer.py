from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, Field

from app.services.brain.council import ModelCouncil
from app.services.brain.router import ModelRouter
from app.services.brain.providers.base import LLMProvider
from app.services.brain.schemas import BrainAnswer, BrainCitation, BrainClaim, BrainExecutionResult


class _SummaryPayload(BaseModel):
    answer: str
    claims: list[dict[str, Any]] = Field(default_factory=list)
    citations: list[Any] = Field(default_factory=list)
    controls: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    confidence: float = 0.0
    missing_evidence: list[str] = Field(default_factory=list)
    proposed_actions: list[dict[str, Any]] = Field(default_factory=list)


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _default_refusal_actions(execution_result: BrainExecutionResult) -> list[dict[str, Any]]:
    if execution_result.proposed_actions:
        return execution_result.proposed_actions
    return [
        {
            "tool": "evidence.query",
            "args": {"time_range": {}, "filters": {}, "limit": 100, "cursor": "0"},
        }
    ]


def _refusal(
    *,
    execution_result: BrainExecutionResult,
    controls: list[str],
    frameworks: list[str],
    missing_evidence: list[str],
    proposed_actions: list[dict[str, Any]] | None,
) -> BrainAnswer:
    actions = proposed_actions or _default_refusal_actions(execution_result)
    actions_taken = _build_actions_taken(execution_result)
    return BrainAnswer(
        answer="INSUFFICIENT EVIDENCE",
        claims=[],
        citations=[],
        controls=controls,
        frameworks=frameworks,
        actions_taken=actions_taken,
        confidence=execution_result.confidence,
        missing_evidence=_dedupe(missing_evidence),
        proposed_actions=actions if actions else _default_refusal_actions(execution_result),
    )


def _summary_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "answer": {"type": "string"},
            "claims": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "text": {"type": "string"},
                    },
                    "required": ["id", "text"],
                    "additionalProperties": False,
                },
            },
            "citations": {
                "type": "array",
                "items": {
                    "oneOf": [
                        {"type": "string"},
                        {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["evidence_node", "snapshot"]},
                                "id": {"type": "string"},
                                "supports": {"type": "array", "items": {"type": "string"}},
                                "note": {"type": "string"},
                                "ts": {"type": "string"},
                            },
                            "required": ["type", "id"],
                            "additionalProperties": False,
                        },
                    ]
                },
            },
            "controls": {"type": "array", "items": {"type": "string"}},
            "frameworks": {"type": "array", "items": {"type": "string"}},
            "actions_taken": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "tool_name": {"type": "string"},
                        "action_id": {"type": "string"},
                        "status": {"type": "string"},
                        "evidence_node_ids": {"type": "array", "items": {"type": "string"}},
                        "snapshot_ids": {"type": "array", "items": {"type": "string"}},
                    },
                    "additionalProperties": True,
                },
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "missing_evidence": {"type": "array", "items": {"type": "string"}},
            "proposed_actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "args": {"type": "object"},
                    },
                    "required": ["tool", "args"],
                    "additionalProperties": True,
                },
            },
        },
        "required": [
            "answer",
            "claims",
            "citations",
            "controls",
            "frameworks",
            "actions_taken",
            "confidence",
            "missing_evidence",
            "proposed_actions",
        ],
        "additionalProperties": False,
    }


def _extract_controls_and_frameworks(execution_result: BrainExecutionResult) -> tuple[list[str], list[str]]:
    controls: list[str] = []
    frameworks: list[str] = []
    for step in execution_result.steps_executed:
        result = step.result or {}
        if isinstance(result.get("controls_impacted"), list):
            for control in result.get("controls_impacted", []):
                if isinstance(control, dict):
                    controls.append(str(control.get("control_id") or ""))
                else:
                    controls.append(str(control))

        if isinstance(result.get("framework"), str):
            frameworks.append(result["framework"])
        if isinstance(result.get("frameworks"), list):
            frameworks.extend(str(item) for item in result["frameworks"])

        if isinstance(result.get("mapped_framework_refs"), list):
            for item in result["mapped_framework_refs"]:
                if isinstance(item, dict):
                    frameworks.append(str(item.get("framework") or ""))

        if isinstance(result.get("items"), list):
            for item in result["items"]:
                if not isinstance(item, dict):
                    continue
                if "control_id" in item:
                    controls.append(str(item.get("control_id") or ""))
                if "framework" in item:
                    frameworks.append(str(item.get("framework") or ""))
                if isinstance(item.get("mapped_framework_refs"), list):
                    for ref in item["mapped_framework_refs"]:
                        if isinstance(ref, dict):
                            frameworks.append(str(ref.get("framework") or ""))
    return _dedupe(controls), _dedupe(frameworks)


def _parse_claims(raw_claims: list[dict[str, Any]], answer: str) -> list[BrainClaim]:
    claims: list[BrainClaim] = []
    for raw in raw_claims:
        if not isinstance(raw, dict):
            continue
        claim_id = str(raw.get("id") or "").strip()
        text = str(raw.get("text") or "").strip()
        if not claim_id or not text:
            continue
        if any(existing.id == claim_id for existing in claims):
            continue
        claims.append(BrainClaim(id=claim_id, text=text))

    if claims:
        return claims

    answer_text = str(answer or "").strip()
    if not answer_text or answer_text == "INSUFFICIENT EVIDENCE":
        return []
    return [BrainClaim(id="claim_1", text=answer_text)]


def _normalize_output_citations(
    *,
    raw_citations: list[Any],
    claims: list[BrainClaim],
    allowed: list[BrainCitation],
) -> list[BrainCitation]:
    allowed_by_id = {row.id: row for row in allowed}
    claim_ids = [row.id for row in claims]

    normalized: list[BrainCitation] = []
    for raw in raw_citations:
        if isinstance(raw, str):
            citation_id = raw.strip()
            if not citation_id:
                continue
            allowed_row = allowed_by_id.get(citation_id)
            if not allowed_row:
                continue
            normalized.append(
                BrainCitation(
                    type=allowed_row.type,
                    id=allowed_row.id,
                    supports=list(claim_ids),
                    note=allowed_row.note,
                    ts=allowed_row.ts,
                )
            )
            continue

        if not isinstance(raw, dict):
            continue
        citation_id = str(raw.get("id") or "").strip()
        if not citation_id:
            continue
        allowed_row = allowed_by_id.get(citation_id)
        if not allowed_row:
            continue

        raw_type = str(raw.get("type") or "").strip()
        citation_type = raw_type if raw_type in {"evidence_node", "snapshot"} else allowed_row.type

        supports_raw = raw.get("supports")
        if "supports" in raw:
            supports = [
                str(item).strip()
                for item in (supports_raw if isinstance(supports_raw, list) else [])
                if str(item).strip() and str(item).strip() in claim_ids
            ]
        else:
            supports = list(claim_ids)

        normalized.append(
            BrainCitation(
                type=citation_type,
                id=allowed_row.id,
                supports=supports,
                note=str(raw.get("note") or "").strip() or allowed_row.note,
                ts=str(raw.get("ts") or "").strip() or allowed_row.ts,
            )
        )

    by_key: dict[tuple[str, str], BrainCitation] = {}
    ordered_keys: list[tuple[str, str]] = []
    for citation in normalized:
        key = (citation.type, citation.id)
        if key not in by_key:
            by_key[key] = BrainCitation(
                type=citation.type,
                id=citation.id,
                supports=list(citation.supports),
                note=citation.note,
                ts=citation.ts,
            )
            ordered_keys.append(key)
            continue

        existing = by_key[key]
        existing.supports = _dedupe(existing.supports + citation.supports)
        if not existing.note:
            existing.note = citation.note
        if not existing.ts:
            existing.ts = citation.ts

    return [by_key[key] for key in ordered_keys]


def _build_actions_taken(execution_result: BrainExecutionResult) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    for step in execution_result.steps_executed:
        result = step.result or {}
        evidence_ids = result.get("evidence_node_ids")
        snapshot_ids = result.get("snapshot_ids")
        actions.append(
            {
                "step_id": step.step_id,
                "execution_type": step.execution_type,
                "tool_name": step.tool,
                "action_id": step.action_id or result.get("action_id"),
                "status": step.status,
                "tool_call_id": step.tool_call_id,
                "evidence_node_ids": evidence_ids if isinstance(evidence_ids, list) else [],
                "snapshot_ids": snapshot_ids if isinstance(snapshot_ids, list) else [],
            }
        )
    return actions


def summarize(
    *,
    question: str,
    execution_result: BrainExecutionResult,
    provider: LLMProvider | None = None,
    model_router: ModelRouter | None = None,
    model_council: ModelCouncil | None = None,
    risk_tier: str | None = None,
    tenant_policy: dict[str, Any] | None = None,
) -> BrainAnswer:
    controls, frameworks = _extract_controls_and_frameworks(execution_result)
    actions_taken = _build_actions_taken(execution_result)

    if execution_result.missing_evidence:
        return _refusal(
            execution_result=execution_result,
            controls=controls,
            frameworks=frameworks,
            missing_evidence=execution_result.missing_evidence,
            proposed_actions=execution_result.proposed_actions,
        )

    if not execution_result.citations:
        return _refusal(
            execution_result=execution_result,
            controls=controls,
            frameworks=frameworks,
            missing_evidence=["No citations were produced by tool execution."],
            proposed_actions=execution_result.proposed_actions,
        )

    system_prompt = (
        "You are Hawk Brain Summarizer for an enterprise AI control plane and proof engine.\n\n"
        "You MUST ONLY use the provided tool results and available citations.\n"
        "You MUST NOT use external knowledge.\n\n"
        "Non-negotiable rules:\n"
        "1) Every factual statement MUST map to at least one claim.\n"
        "2) Every claim MUST be supported by at least one citation.\n"
        "3) Citations can ONLY be evidence_node or snapshot ids from allowed citations.\n"
        "4) If citations are insufficient, return INSUFFICIENT EVIDENCE with non-empty proposed_actions.\n"
        "5) Legacy citation arrays of string ids are allowed for input parsing only.\n"
        "   The final output MUST use structured citation objects.\n\n"
        "6) Include actions_taken entries with tool_name/action_id where applicable.\n\n"
        "Output JSON keys:\n"
        "answer, claims, citations, controls, frameworks, actions_taken, confidence, missing_evidence, proposed_actions\n"
        "No markdown. No commentary."
    )
    allowed_citations_payload = [
        {
            "type": row.type,
            "id": row.id,
            "note": row.note,
            "ts": row.ts,
        }
        for row in execution_result.citations
    ]
    allowed_citation_ids = [row.id for row in execution_result.citations]
    user_prompt = (
        f"Question: {question}\n\n"
        f"Execution result JSON:\n{execution_result.model_dump_json()}\n\n"
        f"Allowed citations:\n{json.dumps(allowed_citations_payload, sort_keys=True)}\n"
    )
    if model_router and model_council:
        providers = model_router.choose_models(
            task_type="summarizer",
            risk_tier=risk_tier,
            tenant_policy=tenant_policy,
        )
        model_outputs = model_council.run_all(
            plan_id=execution_result.plan_id,
            task_type="summarizer",
            providers=providers,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=_summary_schema(),
            risk_tier=risk_tier,
            tenant_policy=tenant_policy,
            prompt_template_id="hawk.brain_summarizer",
            prompt_template_version="v1",
        )
        arbitration = model_council.arbitrate_summarizer(
            plan_id=execution_result.plan_id,
            outputs=model_outputs,
            allowed_citation_ids=set(allowed_citation_ids),
        )
        if not arbitration.winner_output:
            return _refusal(
                execution_result=execution_result,
                controls=controls,
                frameworks=frameworks,
                missing_evidence=[
                    "Summarizer arbitration failed: no valid cited outputs.",
                    *execution_result.missing_evidence,
                ],
                proposed_actions=execution_result.proposed_actions,
            )
        raw = arbitration.winner_output
    else:
        if provider is None:
            raise ValueError("Summarizer requires provider or model_router/model_council")
        single_council = ModelCouncil(
            db=None,
            tenant_id=None,
            user_id=None,
            correlation_id=None,
        )
        outputs = single_council.run_all(
            plan_id=execution_result.plan_id,
            task_type="summarizer",
            providers=[provider],
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            json_schema=_summary_schema(),
            risk_tier=risk_tier,
            tenant_policy=tenant_policy,
            prompt_template_id="hawk.brain_summarizer",
            prompt_template_version="v1",
        )
        first = outputs[0]
        if not first.ok or not isinstance(first.output, dict):
            raise RuntimeError(first.error or "Summarizer secure generation failed")
        raw = first.output

    parsed = _SummaryPayload.model_validate(raw)
    claims = _parse_claims(parsed.claims, parsed.answer)
    filtered_citations = _normalize_output_citations(
        raw_citations=parsed.citations,
        claims=claims,
        allowed=execution_result.citations,
    )

    if parsed.answer == "INSUFFICIENT EVIDENCE":
        return _refusal(
            execution_result=execution_result,
            controls=controls,
            frameworks=frameworks,
            missing_evidence=parsed.missing_evidence or ["Summarizer reported insufficient evidence."],
            proposed_actions=parsed.proposed_actions or execution_result.proposed_actions,
        )

    if not claims:
        return _refusal(
            execution_result=execution_result,
            controls=controls,
            frameworks=frameworks,
            missing_evidence=["Successful answer is missing structured claims."],
            proposed_actions=execution_result.proposed_actions,
        )

    if not filtered_citations:
        return _refusal(
            execution_result=execution_result,
            controls=controls,
            frameworks=frameworks,
            missing_evidence=["Summarizer produced uncited claims."],
            proposed_actions=execution_result.proposed_actions,
        )

    supported_claim_ids = {
        claim_id
        for citation in filtered_citations
        for claim_id in citation.supports
    }
    unsupported_claims = [claim.id for claim in claims if claim.id not in supported_claim_ids]
    if unsupported_claims:
        return _refusal(
            execution_result=execution_result,
            controls=controls,
            frameworks=frameworks,
            missing_evidence=[
                f"Claims without citation support: {', '.join(sorted(unsupported_claims))}",
            ],
            proposed_actions=execution_result.proposed_actions,
        )

    return BrainAnswer(
        answer=parsed.answer,
        claims=claims,
        citations=filtered_citations,
        controls=_dedupe(controls + parsed.controls),
        frameworks=_dedupe(frameworks + parsed.frameworks),
        actions_taken=actions_taken,
        confidence=max(0.0, min(1.0, parsed.confidence if parsed.confidence else execution_result.confidence)),
        missing_evidence=[],
        proposed_actions=[],
    )
