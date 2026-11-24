from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.services.audit_service import write_audit_log
from app.services.brain.providers.base import LLMProvider
from app.services.brain.secure_llm import secure_brain_generate_json
from app.services.brain.store import save_arbitration, save_model_call
from app.services.evidence_service import create_evidence_node


def _stable_hash(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _paragraph_count(text: str) -> int:
    lines = [line.strip() for line in str(text or "").splitlines() if line.strip()]
    return len(lines) if lines else 1


def _collect_json_diff_paths(values: list[Any], path: str = "$") -> list[str]:
    if not values:
        return []
    first = values[0]
    if all(item == first for item in values):
        return []
    if all(isinstance(item, dict) for item in values):
        keys: set[str] = set()
        for item in values:
            keys.update(item.keys())
        diffs: list[str] = []
        for key in sorted(keys):
            nested_values = [(item.get(key) if isinstance(item, dict) else None) for item in values]
            nested_path = f"{path}.{key}" if path else key
            diffs.extend(_collect_json_diff_paths(nested_values, nested_path))
        return diffs
    return [path]


@dataclass
class ModelOutput:
    provider: str
    ok: bool
    output: dict[str, Any] | None
    error: str | None
    output_hash: str


@dataclass
class ArbitrationDecision:
    winner_provider: str | None
    winner_output: dict[str, Any] | None
    dissenting_models: list[str]
    merge_strategy: str
    reason_codes: list[str]
    disagreement_paths: list[str]


class ModelCouncil:
    def __init__(
        self,
        *,
        db: Session | None,
        tenant_id: str | None,
        user_id: str | None,
        correlation_id: str | None,
    ) -> None:
        self.db = db
        self.tenant_id = tenant_id
        self.user_id = user_id
        self.correlation_id = correlation_id

    def _log_model_call(
        self,
        *,
        plan_id: str | None,
        provider: str,
        task_type: str,
        prompt_hash: str,
        output_hash: str,
        output_json: dict[str, Any],
        ok: bool,
        error: str | None,
    ) -> None:
        if self.db and plan_id:
            save_model_call(
                self.db,
                plan_id=plan_id,
                task_type=task_type,
                provider=provider,
                prompt_hash=prompt_hash,
                output_hash=output_hash,
                output_json=output_json,
            )
        if not self.db or not self.tenant_id:
            return
        audit = write_audit_log(
            self.db,
            tenant_id=self.tenant_id,
            actor_user_id=self.user_id,
            actor_type="human",
            action="brain.model_call",
            resource_type="brain_model",
            resource_id=provider,
            payload={
                "provider": provider,
                "task_type": task_type,
                "plan_id": plan_id,
                "prompt_hash": prompt_hash,
                "output_hash": output_hash,
                "ok": ok,
                "error": error,
                "correlation_id": self.correlation_id,
            },
            correlation_id=self.correlation_id,
        )
        create_evidence_node(
            self.db,
            tenant_id=self.tenant_id,
            node_type="brain_model_output",
            signal_type="brain.model_call",
            label=f"Brain model output from {provider} ({task_type})",
            payload={
                "provider": provider,
                "task_type": task_type,
                "plan_id": plan_id,
                "prompt_hash": prompt_hash,
                "output_hash": output_hash,
                "ok": ok,
                "error": error,
                "correlation_id": self.correlation_id,
                "audit_log_id": audit.id,
            },
            correlation_id=self.correlation_id,
        )

    def _log_arbitration(self, *, plan_id: str | None, task_type: str, decision: ArbitrationDecision) -> None:
        if self.db and plan_id:
            save_arbitration(
                self.db,
                plan_id=plan_id,
                task_type=task_type,
                winner=decision.winner_provider,
                dissenters_json=decision.dissenting_models,
                reason_codes_json=decision.reason_codes,
            )
        if not self.db or not self.tenant_id:
            return
        audit = write_audit_log(
            self.db,
            tenant_id=self.tenant_id,
            actor_user_id=self.user_id,
            actor_type="human",
            action="brain.arbitration",
            resource_type="brain_task",
            resource_id=task_type,
            payload={
                "winner_provider": decision.winner_provider,
                "dissenting_models": decision.dissenting_models,
                "merge_strategy": decision.merge_strategy,
                "reason_codes": decision.reason_codes,
                "disagreement_paths": decision.disagreement_paths,
                "plan_id": plan_id,
                "correlation_id": self.correlation_id,
            },
            correlation_id=self.correlation_id,
        )
        create_evidence_node(
            self.db,
            tenant_id=self.tenant_id,
            node_type="brain_arbitration",
            signal_type="brain.arbitration",
            label=f"Brain arbitration for {task_type}",
            payload={
                "winner_provider": decision.winner_provider,
                "dissenters": decision.dissenting_models,
                "reason_codes": decision.reason_codes,
                "merge_strategy": decision.merge_strategy,
                "plan_id": plan_id,
                "correlation_id": self.correlation_id,
                "audit_log_id": audit.id,
            },
            correlation_id=self.correlation_id,
        )

    def run_all(
        self,
        *,
        plan_id: str | None,
        task_type: str,
        providers: list[LLMProvider],
        system_prompt: str,
        user_prompt: str,
        json_schema: dict[str, Any],
        risk_tier: str | None = None,
        tenant_policy: dict[str, Any] | None = None,
        prompt_template_id: str = "",
        prompt_template_version: str = "v1",
    ) -> list[ModelOutput]:
        outputs: list[ModelOutput] = []
        prompt_hash = _stable_hash(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "json_schema": json_schema,
            }
        )
        for provider in providers:
            try:
                generated, _secure_trace = secure_brain_generate_json(
                    provider=provider,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    json_schema=json_schema,
                    task_type=task_type,
                    risk_tier=risk_tier,
                    tenant_policy=tenant_policy,
                    tenant_id=self.tenant_id,
                    actor_user_id=self.user_id,
                    db=self.db,
                    correlation_id=self.correlation_id,
                    prompt_template_id=prompt_template_id or f"hawk.brain.{task_type}",
                    prompt_template_version=prompt_template_version,
                )
                if not isinstance(generated, dict):
                    raise RuntimeError("Model output must be a JSON object")
                output_hash = _stable_hash(generated)
                row = ModelOutput(
                    provider=provider.name,
                    ok=True,
                    output=generated,
                    error=None,
                    output_hash=output_hash,
                )
                output_json = generated
            except Exception as exc:  # noqa: BLE001
                output_json = {"error": str(exc)}
                output_hash = _stable_hash(output_json)
                row = ModelOutput(
                    provider=provider.name,
                    ok=False,
                    output=None,
                    error=str(exc),
                    output_hash=output_hash,
                )
            outputs.append(row)
            self._log_model_call(
                plan_id=plan_id,
                provider=row.provider,
                task_type=task_type,
                prompt_hash=prompt_hash,
                output_hash=row.output_hash,
                output_json=output_json,
                ok=row.ok,
                error=row.error,
            )
        return outputs

    def detect_disagreements(self, outputs: list[ModelOutput]) -> list[str]:
        valid_outputs = [row.output for row in outputs if row.ok and isinstance(row.output, dict)]
        if len(valid_outputs) <= 1:
            return []
        return _collect_json_diff_paths(valid_outputs)

    def arbitrate_planner(
        self,
        *,
        plan_id: str | None,
        outputs: list[ModelOutput],
        validate_plan: Any,
        question: str,
    ) -> ArbitrationDecision:
        disagreements = self.detect_disagreements(outputs)
        question_lower = question.lower()
        require_snapshot = "prove" in question_lower
        reason_codes: list[str] = []

        valid_rows: list[tuple[ModelOutput, list[str]]] = []
        invalid_rows: list[str] = []
        for row in outputs:
            if not row.ok or not isinstance(row.output, dict):
                invalid_rows.append(row.provider)
                continue
            try:
                step_tools = validate_plan(row.output)
                valid_rows.append((row, step_tools))
            except Exception:
                invalid_rows.append(row.provider)

        if not valid_rows:
            decision = ArbitrationDecision(
                winner_provider=None,
                winner_output=None,
                dissenting_models=[],
                merge_strategy="none",
                reason_codes=["both_invalid"],
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="planner", decision=decision)
            return decision

        if len(valid_rows) == 1:
            winner = valid_rows[0][0]
            reason_codes.append("single_valid")
            decision = ArbitrationDecision(
                winner_provider=winner.provider,
                winner_output=winner.output,
                dissenting_models=[name for name in invalid_rows if name != winner.provider],
                merge_strategy="single_valid",
                reason_codes=reason_codes,
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="planner", decision=decision)
            return decision

        canonical = [_stable_hash(row.output) for row, _ in valid_rows]
        if len(set(canonical)) == 1:
            winner = valid_rows[0][0]
            reason_codes.append("identical_valid")
            decision = ArbitrationDecision(
                winner_provider=winner.provider,
                winner_output=winner.output,
                dissenting_models=[row.provider for row, _ in valid_rows[1:]],
                merge_strategy="identical",
                reason_codes=reason_codes,
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="planner", decision=decision)
            return decision

        required_tools = {"evidence.query"}
        if require_snapshot:
            required_tools.add("auditor.create_snapshot")
        invariant_rows = [
            (row, tools)
            for row, tools in valid_rows
            if required_tools.issubset(set(tools))
        ]
        candidate_rows = invariant_rows or valid_rows
        if invariant_rows:
            reason_codes.append("required_invariants_satisfied")

        def score(item: tuple[ModelOutput, list[str]]) -> tuple[int, int, int, str]:
            row, tools = item
            evidence_count = sum(1 for tool in tools if tool == "evidence.query")
            has_snapshot = int(("auditor.create_snapshot" in tools) if require_snapshot else 1)
            step_count = len(tools)
            return (has_snapshot, evidence_count, -step_count, row.provider)

        winner_row, _winner_tools = sorted(candidate_rows, key=score, reverse=True)[0]
        reason_codes.extend(["conflicting_valid_outputs", "evidence_density_preference", "minimal_steps_preference"])
        dissenters = [row.provider for row, _ in candidate_rows if row.provider != winner_row.provider]
        decision = ArbitrationDecision(
            winner_provider=winner_row.provider,
            winner_output=winner_row.output,
            dissenting_models=dissenters,
            merge_strategy="best_plan_selection",
            reason_codes=reason_codes,
            disagreement_paths=disagreements,
        )
        self._log_arbitration(plan_id=plan_id, task_type="planner", decision=decision)
        return decision

    def arbitrate_summarizer(
        self,
        *,
        plan_id: str | None,
        outputs: list[ModelOutput],
        allowed_citation_ids: set[str],
    ) -> ArbitrationDecision:
        disagreements = self.detect_disagreements(outputs)
        reason_codes: list[str] = []

        parsed_rows: list[tuple[ModelOutput, dict[str, Any]]] = []
        for row in outputs:
            if row.ok and isinstance(row.output, dict):
                parsed_rows.append((row, row.output))
        if not parsed_rows:
            decision = ArbitrationDecision(
                winner_provider=None,
                winner_output=None,
                dissenting_models=[],
                merge_strategy="none",
                reason_codes=["both_invalid"],
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="summarizer", decision=decision)
            return decision

        canonical = [_stable_hash(payload) for _, payload in parsed_rows]
        if len(set(canonical)) == 1:
            winner = parsed_rows[0][0]
            decision = ArbitrationDecision(
                winner_provider=winner.provider,
                winner_output=winner.output,
                dissenting_models=[row.provider for row, _ in parsed_rows[1:]],
                merge_strategy="identical",
                reason_codes=["identical_valid"],
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="summarizer", decision=decision)
            return decision

        def normalize_citations(payload: dict[str, Any]) -> list[str]:
            raw = payload.get("citations")
            if not isinstance(raw, list):
                return []
            citation_ids: list[str] = []
            for item in raw:
                if isinstance(item, str):
                    value = item.strip()
                    if value:
                        citation_ids.append(value)
                    continue
                if isinstance(item, dict):
                    value = str(item.get("id") or "").strip()
                    if value:
                        citation_ids.append(value)
            return citation_ids

        def citation_density(payload: dict[str, Any]) -> float:
            citations = set(normalize_citations(payload))
            answer = str(payload.get("answer") or "")
            return len(citations) / float(_paragraph_count(answer))

        def is_refusal(payload: dict[str, Any]) -> bool:
            return str(payload.get("answer") or "").strip() == "INSUFFICIENT EVIDENCE"

        def has_valid_citations(payload: dict[str, Any]) -> bool:
            citations = normalize_citations(payload)
            if not citations:
                return False
            return all(citation in allowed_citation_ids for citation in citations)

        refusals = [(row, payload) for row, payload in parsed_rows if is_refusal(payload)]
        cited = [(row, payload) for row, payload in parsed_rows if (not is_refusal(payload) and has_valid_citations(payload))]
        uncited = [(row, payload) for row, payload in parsed_rows if (not is_refusal(payload) and not has_valid_citations(payload))]

        if refusals and uncited and not cited:
            winner = refusals[0]
            reason_codes.extend(["prefer_refusal_over_uncited_claims", "conflicting_valid_outputs"])
            decision = ArbitrationDecision(
                winner_provider=winner[0].provider,
                winner_output=winner[1],
                dissenting_models=[row.provider for row, _ in parsed_rows if row.provider != winner[0].provider],
                merge_strategy="prefer_refusal",
                reason_codes=reason_codes,
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="summarizer", decision=decision)
            return decision

        if cited:
            cited_sorted = sorted(
                cited,
                key=lambda item: (citation_density(item[1]), item[0].provider),
                reverse=True,
            )
            winner = cited_sorted[0]
            reason_codes.extend(["citation_density_preference", "conflicting_valid_outputs"])
            if len(cited_sorted) > 1:
                a_citations = set(normalize_citations(cited_sorted[0][1]))
                b_citations = set(normalize_citations(cited_sorted[1][1]))
                overlap_ratio = (len(a_citations & b_citations) / float(max(1, min(len(a_citations), len(b_citations)))))
                if overlap_ratio >= 0.6 and (a_citations & b_citations):
                    answer_a = str(cited_sorted[0][1].get("answer") or "")
                    answer_b = str(cited_sorted[1][1].get("answer") or "")
                    merged_lines: list[str] = []
                    seen: set[str] = set()
                    for line in (answer_a.splitlines() + answer_b.splitlines()):
                        text = line.strip()
                        if not text or text in seen:
                            continue
                        seen.add(text)
                        merged_lines.append(text)
                    merged_payload = dict(cited_sorted[0][1])
                    merged_payload["answer"] = "\n".join(merged_lines)
                    winner_output = merged_payload
                    merge_strategy = "merge_substantial_overlap"
                    reason_codes.append("merge_substantial_evidence_overlap")
                else:
                    winner_output = winner[1]
                    merge_strategy = "select_best_cited"
            else:
                winner_output = winner[1]
                merge_strategy = "select_best_cited"

            decision = ArbitrationDecision(
                winner_provider=winner[0].provider,
                winner_output=winner_output,
                dissenting_models=[row.provider for row, _ in parsed_rows if row.provider != winner[0].provider],
                merge_strategy=merge_strategy,
                reason_codes=reason_codes,
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="summarizer", decision=decision)
            return decision

        if refusals:
            winner = refusals[0]
            decision = ArbitrationDecision(
                winner_provider=winner[0].provider,
                winner_output=winner[1],
                dissenting_models=[row.provider for row, _ in parsed_rows if row.provider != winner[0].provider],
                merge_strategy="fallback_refusal",
                reason_codes=["fallback_refusal"],
                disagreement_paths=disagreements,
            )
            self._log_arbitration(plan_id=plan_id, task_type="summarizer", decision=decision)
            return decision

        decision = ArbitrationDecision(
            winner_provider=None,
            winner_output=None,
            dissenting_models=[row.provider for row, _ in parsed_rows],
            merge_strategy="none",
            reason_codes=["no_cited_answers"],
            disagreement_paths=disagreements,
        )
        self._log_arbitration(plan_id=plan_id, task_type="summarizer", decision=decision)
        return decision
