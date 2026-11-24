from __future__ import annotations

from datetime import datetime, timezone
import inspect
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.observability import get_correlation_id
from app.db.models.agui import AGUIDecision
from app.services.agui.context import AGUIExecutionContext
from app.services.agui.contracts import AGUIActionContract, AGUIActionRegistration, AGUIDecisionRecord
from app.services.audit_service import write_audit_log
from app.services.evidence_service import create_evidence_node
from app.services.action_integrity.execution_authority import install_generic_seam_authority, invoke_final_seam
from app.services.action_integrity.canonical_v2 import domain_hash


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AGUIRegistry:
    def __init__(self) -> None:
        self._registry: dict[str, AGUIActionRegistration] = {}

    def register_action(self, action_registration: AGUIActionRegistration) -> None:
        action_id = action_registration.contract.action_id
        if action_id in self._registry:
            raise ValueError(f"Action '{action_id}' is already registered")
        self._registry[action_id] = action_registration

    def get_action(self, action_id: str) -> AGUIActionRegistration | None:
        return self._registry.get(action_id)

    def list_actions(self) -> list[dict[str, Any]]:
        items = [row.contract.model_dump(mode="json") for row in self._registry.values()]
        return sorted(items, key=lambda row: row["action_id"])

    def validate_decision(
        self,
        *,
        action_id: str,
        context: AGUIExecutionContext,
        decision: str,
        justification: str | None = None,
        evidence_node_ids: list[str] | None = None,
        decision_payload: dict[str, Any] | None = None,
    ) -> tuple[AGUIActionRegistration, str, str | None, list[str]]:
        registration = self.get_action(action_id)
        if registration is None:
            raise ValueError(f"Unknown action '{action_id}'")
        contract = registration.contract

        if context.user_role not in contract.required_role:
            raise PermissionError(
                f"Insufficient role for action '{action_id}'. "
                f"Required one of: {', '.join(contract.required_role)}"
            )

        normalized_decision = str(decision or "").strip()
        if not normalized_decision:
            raise ValueError("decision is required")
        if normalized_decision not in contract.decision_options:
            raise ValueError(
                f"Invalid decision '{normalized_decision}' for action '{action_id}'. "
                f"Allowed: {', '.join(contract.decision_options)}"
            )

        normalized_justification = str(justification or "").strip() or None
        if contract.requires_justification and not normalized_justification:
            raise ValueError(f"Action '{action_id}' requires justification")

        if contract.requires_evidence_display and not context.evidence_displayed:
            raise PermissionError(f"Action '{action_id}' requires evidence display before decision")

        if contract.requires_diff_preview and not context.diff_preview_displayed:
            raise PermissionError(f"Action '{action_id}' requires diff preview before decision")

        if decision_payload is not None and not isinstance(decision_payload, dict):
            raise ValueError("decision_payload must be an object")

        normalized_evidence_ids = _normalize_evidence_node_ids(evidence_node_ids)
        return registration, normalized_decision, normalized_justification, normalized_evidence_ids

    def execute_decision(
        self,
        *,
        db: Session,
        context: AGUIExecutionContext,
        action_id: str,
        decision: str,
        justification: str | None = None,
        evidence_node_ids: list[str] | None = None,
        decision_payload: dict[str, Any] | None = None,
    ) -> AGUIDecisionRecord:
        registration = self.get_action(action_id)
        if registration is None:
            raise ValueError(f"Unknown action '{action_id}'")
        contract = registration.contract

        correlation_id = context.correlation_id or get_correlation_id()
        effective_context = context.model_copy(update={"correlation_id": correlation_id})
        decided_at = _utcnow()
        decision_id = str(uuid4())
        payload_obj = decision_payload or {}

        status = "success"
        error: str | None = None
        normalized_decision = str(decision or "").strip()
        normalized_justification = str(justification or "").strip() or None
        normalized_evidence_ids = _normalize_evidence_node_ids(evidence_node_ids)
        execution_exc: Exception | None = None
        execution_result: dict[str, Any] = {}
        source_module = contract.source_module
        source_object_type = contract.source_object_type
        source_object_id = contract.source_object_id

        try:
            (
                registration,
                normalized_decision,
                normalized_justification,
                normalized_evidence_ids,
            ) = self.validate_decision(
                action_id=action_id,
                context=effective_context,
                decision=normalized_decision,
                justification=normalized_justification,
                evidence_node_ids=normalized_evidence_ids,
                decision_payload=payload_obj,
            )
            source_module, source_object_type, source_object_id = _resolve_lineage(
                contract=registration.contract,
                decision_payload=payload_obj,
            )
            if registration.executor is not None:
                install_generic_seam_authority(
                    db, tenant_id=effective_context.tenant_id, seam_ref="agui.actual_executor", action_id=contract.action_id,
                    chain_id=effective_context.correlation_id or decision_id, actor_principal=f"user:{effective_context.user_id}",
                    executing_principal="service:agui", operation=contract.action_type, tool_or_service_ref=contract.action_id,
                    parameter_hash=domain_hash("hawk:agui-decision:v1", payload_obj), target_ref=source_object_id or contract.action_id,
                )
                raw_result = invoke_final_seam(
                    db,
                    seam_ref="agui.actual_executor",
                    executor=lambda: _invoke_executor(
                        registration=registration,
                        db=db,
                        context=effective_context,
                        decision=normalized_decision,
                        justification=normalized_justification,
                        evidence_node_ids=list(normalized_evidence_ids),
                        decision_payload=payload_obj,
                    ),
                )
                if raw_result is None:
                    execution_result = {}
                elif isinstance(raw_result, dict):
                    execution_result = raw_result
                else:
                    raise ValueError("AGUI action executor must return an object or null")
        except Exception as exc:  # noqa: BLE001
            status = "fail"
            error = str(exc)
            execution_exc = exc

        audit = write_audit_log(
            db,
            tenant_id=effective_context.tenant_id,
            actor_user_id=effective_context.user_id,
            actor_type="human",
            action="agui.decision.execute",
            resource_type="agui_action",
            resource_id=decision_id,
            payload={
                "decision_id": decision_id,
                "action_id": contract.action_id,
                "action_type": contract.action_type,
                "decision": normalized_decision,
                "status": status,
                "error": error,
                "requires_justification": contract.requires_justification,
                "requires_evidence_display": contract.requires_evidence_display,
                "requires_diff_preview": contract.requires_diff_preview,
                "justification_present": bool(normalized_justification),
                "evidence_node_ids": list(normalized_evidence_ids),
                "source_module": source_module,
                "source_object_type": source_object_type,
                "source_object_id": source_object_id,
                "side_effect_level": contract.side_effect_level,
                "decision_options": list(contract.decision_options),
                "decision_payload": payload_obj,
                "execution_result": execution_result,
                "correlation_id": correlation_id,
            },
            correlation_id=correlation_id,
        )
        decision_evidence = create_evidence_node(
            db,
            tenant_id=effective_context.tenant_id,
            node_type="agui_decision",
            signal_type="agui.decision.execute",
            label=f"AGUI decision for action '{contract.action_id}' ({status})",
            payload={
                "decision_id": decision_id,
                "action_id": contract.action_id,
                "action_type": contract.action_type,
                "decision": normalized_decision,
                "status": status,
                "error": error,
                "audit_log_id": audit.id,
                "source_module": source_module,
                "source_object_type": source_object_type,
                "source_object_id": source_object_id,
                "justification_present": bool(normalized_justification),
                "side_effect_level": contract.side_effect_level,
                "correlation_id": correlation_id,
            },
            correlation_id=correlation_id,
        )
        all_evidence_ids = _merge_evidence_ids(normalized_evidence_ids, [decision_evidence.id])

        db.add(
            AGUIDecision(
                decision_id=decision_id,
                tenant_id=effective_context.tenant_id,
                action_id=contract.action_id,
                decision=normalized_decision or "",
                justification=normalized_justification,
                decided_by=effective_context.user_id,
                decided_at=decided_at,
                correlation_id=correlation_id,
                evidence_node_ids=all_evidence_ids,
                audit_log_id=audit.id,
                source_module=source_module,
                source_object_type=source_object_type,
                source_object_id=source_object_id,
            )
        )
        db.flush()

        if execution_exc is not None:
            raise execution_exc

        return AGUIDecisionRecord(
            decision_id=decision_id,
            action_id=contract.action_id,
            decision=normalized_decision,
            justification=normalized_justification,
            decided_by=effective_context.user_id,
            decided_at=decided_at,
            correlation_id=correlation_id,
            evidence_node_ids=all_evidence_ids,
            audit_log_id=audit.id,
        )


def _invoke_executor(
    *,
    registration: AGUIActionRegistration,
    db: Session,
    context: AGUIExecutionContext,
    decision: str,
    justification: str | None,
    evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any] | None:
    executor = registration.executor
    if executor is None:
        return None
    signature = inspect.signature(executor)
    positional = [
        p
        for p in signature.parameters.values()
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ]
    has_varargs = any(p.kind == inspect.Parameter.VAR_POSITIONAL for p in signature.parameters.values())
    if has_varargs or len(positional) >= 7:
        return executor(
            db,
            context,
            registration.contract,
            decision,
            justification,
            evidence_node_ids,
            decision_payload,
        )
    return executor(
        db,
        context,
        registration.contract,
        decision,
        justification,
        evidence_node_ids,
    )


def _normalize_evidence_node_ids(evidence_node_ids: list[str] | None) -> list[str]:
    if evidence_node_ids is None:
        return []
    if not isinstance(evidence_node_ids, list):
        raise ValueError("evidence_node_ids must be an array")
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in evidence_node_ids:
        value = str(raw or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        cleaned.append(value)
    return cleaned


def _merge_evidence_ids(first: list[str], second: list[str]) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for value in list(first) + list(second):
        if value in seen:
            continue
        seen.add(value)
        merged.append(value)
    return merged


def _resolve_lineage(*, contract: AGUIActionContract, decision_payload: dict[str, Any]) -> tuple[str, str, str]:
    source_module = str(decision_payload.get("source_module") or contract.source_module or "").strip()
    source_object_type = str(decision_payload.get("source_object_type") or contract.source_object_type or "").strip()
    source_object_id = str(decision_payload.get("source_object_id") or contract.source_object_id or "").strip()
    runtime_markers = {"runtime", "__runtime__", "*"}

    if source_object_id in runtime_markers:
        for key in (
            "finding_id",
            "application_id",
            "ai_system_id",
            "policy_version_id",
            "simulation_run_id",
            "simulation_id",
            "conflict_id",
            "snapshot_id",
            "agent_id",
            "token_id",
            "control_id",
            "approval_request_id",
        ):
            value = str(decision_payload.get(key) or "").strip()
            if value:
                source_object_id = value
                break
        if source_object_id in runtime_markers:
            source_object_id = "unknown"

    if not source_module:
        source_module = "agui"
    if not source_object_type:
        source_object_type = "unknown"
    if not source_object_id:
        source_object_id = "unknown"
    return source_module, source_object_type, source_object_id


_AGUI_REGISTRY: AGUIRegistry | None = None


def get_agui_registry() -> AGUIRegistry:
    global _AGUI_REGISTRY
    if _AGUI_REGISTRY is None:
        _AGUI_REGISTRY = AGUIRegistry()
        from app.services.agui.core_actions import register_core_agui_actions

        register_core_agui_actions(_AGUI_REGISTRY)
    return _AGUI_REGISTRY
