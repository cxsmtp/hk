from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.models.evidence import EvidenceNode
from app.db.models.maturity import ControlConflict
from app.db.models.snapshot import AuditorSnapshot
from app.services.agui.contracts import AGUIActionContract, AGUIActionRegistration
from app.services.agui.registry import get_agui_registry
from app.services.audit_service import write_audit_log
from app.services.brain.schemas import BrainCitation, BrainExecutionResult, BrainPlanStep, BrainStepExecution
from app.services.brain.store import get_brain_plan_for_tenant, save_tool_call_finish, save_tool_call_start
from app.services.brain.tools import execute_tool, get_tool_contract
from app.services.evidence_service import create_evidence_node
from app.services.mcp.contracts import ToolContract

def _hash_json(payload: dict[str, Any]) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _append_unique_citation(citations: list[BrainCitation], citation_type: str, citation_id: Any) -> None:
    value = str(citation_id or "").strip()
    if not value:
        return
    if citation_type not in {"evidence_node", "snapshot"}:
        return
    if any(row.type == citation_type and row.id == value for row in citations):
        return
    citations.append(BrainCitation(type=citation_type, id=value, supports=[]))


def _collect_citations_from_object(payload: Any, citations: list[BrainCitation]) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in {"evidence_node_ids", "evidence_nodes_created"} and isinstance(value, list):
                for item in value:
                    _append_unique_citation(citations, "evidence_node", item)
            elif key == "evidence_node_id":
                _append_unique_citation(citations, "evidence_node", value)
            elif key == "snapshot_ids" and isinstance(value, list):
                for item in value:
                    _append_unique_citation(citations, "snapshot", item)
            elif key == "snapshot_id":
                _append_unique_citation(citations, "snapshot", value)
            _collect_citations_from_object(value, citations)
        return

    if isinstance(payload, list):
        for item in payload:
            _collect_citations_from_object(item, citations)


def _normalize_available_citations(
    db: Session,
    *,
    tenant_id: str,
    citations: list[BrainCitation],
) -> list[BrainCitation]:
    evidence_ids = sorted({row.id for row in citations if row.type == "evidence_node"})
    snapshot_ids = sorted({row.id for row in citations if row.type == "snapshot"})

    evidence_rows = (
        db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id.in_(evidence_ids),
            )
        ).all()
        if evidence_ids
        else []
    )
    snapshot_rows = (
        db.scalars(
            select(AuditorSnapshot).where(
                AuditorSnapshot.tenant_id == tenant_id,
                AuditorSnapshot.id.in_(snapshot_ids),
            )
        ).all()
        if snapshot_ids
        else []
    )

    evidence_by_id = {row.id: row for row in evidence_rows}
    snapshot_by_id = {row.id: row for row in snapshot_rows}

    normalized: list[BrainCitation] = []
    for row in citations:
        if row.type == "evidence_node":
            evidence = evidence_by_id.get(row.id)
            if not evidence:
                continue
            normalized.append(
                BrainCitation(
                    type="evidence_node",
                    id=evidence.id,
                    supports=[],
                    note=evidence.signal_type or evidence.label,
                    ts=evidence.created_at.isoformat() if evidence.created_at else None,
                )
            )
            continue

        snapshot = snapshot_by_id.get(row.id)
        if not snapshot:
            continue
        normalized.append(
            BrainCitation(
                type="snapshot",
                id=snapshot.id,
                supports=[],
                note=snapshot.trigger_type,
                ts=snapshot.created_at.isoformat() if snapshot.created_at else None,
            )
        )

    deduped: list[BrainCitation] = []
    for row in normalized:
        if any(existing.type == row.type and existing.id == row.id for existing in deduped):
            continue
        deduped.append(row)
    return deduped


def _calculate_confidence(
    db: Session,
    *,
    tenant_id: str,
    citations: list[BrainCitation],
) -> float:
    # Phase 1 deterministic confidence:
    # start 0.5
    # +0.1 for each independent evidence source
    # -0.2 for conflicts/contested
    # cap 0..1
    source_keys: set[str] = set()
    evidence_ids = sorted({c.id for c in citations if c.type == "evidence_node"})
    if evidence_ids:
        rows = db.scalars(
            select(EvidenceNode).where(
                EvidenceNode.tenant_id == tenant_id,
                EvidenceNode.id.in_(evidence_ids),
            )
        ).all()
        for row in rows:
            payload = row.payload or {}
            source = payload.get("source")
            if isinstance(source, str) and source.strip():
                source_keys.add(f"evidence:{source.strip().lower()}")
            else:
                source_keys.add(f"evidence:{(row.signal_type or row.node_type or 'unknown').lower()}")

    snapshot_ids = {c.id for c in citations if c.type == "snapshot"}
    for snapshot_id in snapshot_ids:
        source_keys.add(f"snapshot:{snapshot_id}")

    conflict_count = db.scalar(
        select(func.count())
        .select_from(ControlConflict)
        .where(
            ControlConflict.tenant_id == tenant_id,
            ControlConflict.status.in_(["open", "contested"]),
        )
    )
    score = 0.5 + (0.1 * float(len(source_keys)))
    if int(conflict_count or 0) > 0:
        score -= 0.2
    return round(max(0.0, min(1.0, score)), 4)


def _approval_action_id_for_tool(tool_name: str) -> str:
    compact = "".join(ch if ch.isalnum() else "_" for ch in str(tool_name or "").strip().lower())
    compact = compact.strip("_") or "tool"
    return f"brain.approve_tool.{compact}"


def _ensure_approval_action_registered(contract: ToolContract) -> str:
    action_id = _approval_action_id_for_tool(contract.tool_name)
    registry = get_agui_registry()
    if registry.get_action(action_id):
        return action_id
    registry.register_action(
        AGUIActionRegistration(
            contract=AGUIActionContract(
                action_id=action_id,
                action_type="approval",
                title=f"Approve {contract.tool_name}",
                description=f"Human approval required before executing MCP tool '{contract.tool_name}'.",
                source_module=contract.module,
                source_object_type="mcp_tool",
                source_object_id="__runtime__",
                required_role=["owner", "admin"],
                decision_options=["approve", "deny"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level=contract.side_effect_level,
            ),
            executor=None,
        )
    )
    return action_id


def _create_agui_action_request(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    user_role: str,
    plan_id: str,
    session_id: str,
    step_id: str,
    action_id: str,
    step_args: dict[str, Any],
    correlation_id: str | None,
    requested_tool: str | None = None,
    requested_contract: ToolContract | None = None,
) -> dict[str, Any]:
    registry = get_agui_registry()
    action_registration = registry.get_action(action_id)
    if action_registration is None:
        raise ValueError(f"Unknown AGUI action '{action_id}'")

    ai_system_id = str(step_args.get("ai_system_id") or "").strip() or None
    args_hash = _hash_json(step_args)

    approval_request_id: str | None = None
    if requested_tool:
        if not ai_system_id:
            raise ValueError(
                f"Tool '{requested_tool}' requires approval but ai_system_id was not provided in args or execution context"
            )
        approval_payload = execute_tool(
            db=db,
            tenant_id=tenant_id,
            user_id=user_id,
            user_role=user_role,
            tool_name="workflows.request_approval",
            args={
                "ai_system_id": ai_system_id,
                "request_payload": {
                    "requested_tool": requested_tool,
                    "requested_tool_version": requested_contract.version if requested_contract else None,
                    "requested_tool_module": requested_contract.module if requested_contract else None,
                    "requested_args_hash": args_hash,
                    "brain_plan_id": plan_id,
                    "brain_session_id": session_id,
                    "step_id": step_id,
                },
                "required_roles": ["owner", "admin"],
                "sla_minutes": int(step_args.get("sla_minutes") or 60),
                "default_if_timeout": str(step_args.get("default_if_timeout") or "block"),
            },
            correlation_id=correlation_id,
            ai_system_id=ai_system_id,
            policy_version_id=str(step_args.get("policy_version_id") or "").strip() or None,
            brain_session_id=session_id,
            brain_plan_id=plan_id,
        )
        approval_request_id = str(approval_payload.get("approval_request_id") or "").strip() or None

    audit = write_audit_log(
        db,
        tenant_id=tenant_id,
        actor_user_id=user_id,
        actor_type="human",
        action="brain.action_request",
        resource_type="brain_plan",
        resource_id=plan_id,
        payload={
            "step_id": step_id,
            "action_id": action_id,
            "requested_tool": requested_tool,
            "requested_args_hash": args_hash,
            "approval_request_id": approval_request_id,
            "ai_system_id": ai_system_id,
            "correlation_id": correlation_id,
        },
        correlation_id=correlation_id,
    )
    evidence = create_evidence_node(
        db,
        tenant_id=tenant_id,
        node_type="brain_action_request",
        signal_type="brain.action_request",
        label=f"Brain action request '{action_id}' created",
        payload={
            "plan_id": plan_id,
            "session_id": session_id,
            "step_id": step_id,
            "action_id": action_id,
            "requested_tool": requested_tool,
            "requested_args_hash": args_hash,
            "approval_request_id": approval_request_id,
            "ai_system_id": ai_system_id,
            "correlation_id": correlation_id,
            "audit_log_id": audit.id,
            "required_role": action_registration.contract.required_role,
            "decision_options": action_registration.contract.decision_options,
        },
        correlation_id=correlation_id,
    )

    proposed_action_args = {
        "source_module": action_registration.contract.source_module,
        "source_object_type": action_registration.contract.source_object_type,
        "source_object_id": plan_id,
        "requested_tool": requested_tool,
        "requested_args_hash": args_hash,
        "approval_request_id": approval_request_id,
        "ai_system_id": ai_system_id,
    }
    return {
        "action_id": action_id,
        "status": "pending",
        "approval_request_id": approval_request_id,
        "requested_tool": requested_tool,
        "requested_args_hash": args_hash,
        "required_role": action_registration.contract.required_role,
        "decision_options": action_registration.contract.decision_options,
        "evidence_node_ids": [evidence.id],
        "proposed_action": {"action_id": action_id, "args": proposed_action_args},
    }


def execute_plan(
    db: Session,
    *,
    tenant_id: str,
    user_id: str,
    user_role: str,
    plan_id: str,
    correlation_id: str | None,
) -> BrainExecutionResult:
    plan_record = get_brain_plan_for_tenant(db, tenant_id=tenant_id, plan_id=plan_id)
    if not plan_record:
        raise ValueError("Brain plan not found for tenant")

    raw_steps = (plan_record.plan_json or {}).get("steps") or []
    steps = [BrainPlanStep.model_validate(row) for row in raw_steps]
    if not steps:
        raise ValueError("Brain plan has no steps")

    steps_executed: list[BrainStepExecution] = []
    citations: list[BrainCitation] = []
    missing_evidence: list[str] = []
    proposed_actions: list[dict[str, Any]] = []

    for step in steps:
        step_ref = str(step.tool or step.action_id or "").strip() or "brain.step"
        tool_call = save_tool_call_start(
            db,
            plan_id=plan_record.id,
            tool_name=step_ref,
            args_json=step.args,
        )

        status = "success"
        error: str | None = None
        result: dict[str, Any] = {}
        try:
            if step.execution_type == "agui_action_request":
                action_id = str(step.action_id or "").strip()
                if not action_id:
                    raise ValueError("AGUI action request step is missing action_id")
                result = _create_agui_action_request(
                    db,
                    tenant_id=tenant_id,
                    user_id=user_id,
                    user_role=user_role,
                    plan_id=plan_record.id,
                    session_id=plan_record.session_id,
                    step_id=step.step_id,
                    action_id=action_id,
                    step_args=step.args,
                    correlation_id=correlation_id,
                    requested_tool=None,
                )
                status = "needs_approval"
            else:
                contract = get_tool_contract(str(step.tool))
                if contract is None:
                    raise ValueError(f"Unknown MCP tool '{step.tool}'")
                side_effect_level = str(contract.side_effect_level or "").strip().lower()
                high_impact_side_effect = side_effect_level in {"write", "enforce"}
                if contract.requires_approval or high_impact_side_effect:
                    action_id = _ensure_approval_action_registered(contract)
                    result = _create_agui_action_request(
                        db,
                        tenant_id=tenant_id,
                        user_id=user_id,
                        user_role=user_role,
                        plan_id=plan_record.id,
                        session_id=plan_record.session_id,
                        step_id=step.step_id,
                        action_id=action_id,
                        step_args=step.args,
                        correlation_id=correlation_id,
                        requested_tool=contract.tool_name,
                        requested_contract=contract,
                    )
                    status = "needs_approval"
                else:
                    result = execute_tool(
                        db=db,
                        tenant_id=tenant_id,
                        user_id=user_id,
                        user_role=user_role,
                        tool_name=step.tool,
                        args=step.args,
                        correlation_id=correlation_id,
                        brain_session_id=plan_record.session_id,
                        brain_plan_id=plan_record.id,
                    )
        except Exception as exc:
            status = "fail"
            error = str(exc)
            result = {"error": error}

        save_tool_call_finish(
            db,
            tool_call=tool_call,
            status=status,
            result_json=result,
            error=error,
        )

        args_hash = _hash_json(step.args)
        audit = write_audit_log(
            db,
            tenant_id=tenant_id,
            actor_user_id=user_id,
            actor_type="human",
            action="brain.tool_call",
            resource_type="brain_plan",
            resource_id=plan_record.id,
            payload={
                "tool_call_id": tool_call.id,
                "step_id": step.step_id,
                "execution_type": step.execution_type,
                "tool": step.tool,
                "action_id": step.action_id,
                "status": status,
                "args_hash": args_hash,
                "correlation_id": correlation_id,
                "error": error,
            },
            correlation_id=correlation_id,
        )
        tool_evidence = create_evidence_node(
            db,
            tenant_id=tenant_id,
            node_type="brain_tool_call",
            signal_type="brain.tool_call",
            label=f"Brain step {step_ref} {status}",
            payload={
                "tool_call_id": tool_call.id,
                "plan_id": plan_record.id,
                "step_id": step.step_id,
                "execution_type": step.execution_type,
                "tool": step.tool,
                "action_id": step.action_id,
                "status": status,
                "args_hash": args_hash,
                "correlation_id": correlation_id,
                "result_keys": sorted(result.keys()),
                "audit_log_id": audit.id,
                "error": error,
            },
            correlation_id=correlation_id,
        )
        _append_unique_citation(citations, "evidence_node", tool_evidence.id)
        _collect_citations_from_object(result, citations)

        if status == "fail":
            if step.execution_type == "agui_action_request":
                missing_evidence.append(f"AGUI action request '{step.action_id}' failed: {error}")
                proposed_actions.append({"action_id": step.action_id, "args": step.args})
            else:
                missing_evidence.append(f"Tool '{step.tool}' failed: {error}")
                proposed_actions.append({"tool": step.tool, "args": step.args})
        elif status == "needs_approval":
            requested_ref = str(result.get("requested_tool") or step.tool or step.action_id or "").strip()
            missing_evidence.append(f"Approval pending for '{requested_ref}'.")
            proposed = result.get("proposed_action")
            if isinstance(proposed, dict):
                proposed_actions.append(proposed)
            elif step.execution_type == "agui_action_request":
                proposed_actions.append({"action_id": step.action_id, "args": step.args})
            else:
                proposed_actions.append({"action_id": result.get("action_id"), "args": step.args})
        elif step.tool == "evidence.query" and int(result.get("total") or 0) == 0:
            missing_evidence.append("No evidence matched the current query.")
            proposed_actions.append(
                {
                    "tool": "evidence.query",
                    "args": {
                        "time_range": {"start": None, "end": None},
                        "filters": {},
                        "limit": 100,
                        "cursor": "0",
                    },
                }
            )
            proposed_actions.append(
                {
                    "tool": "ops.jobs_status",
                    "args": {"limit": 10},
                }
            )

        steps_executed.append(
            BrainStepExecution(
                step_id=step.step_id,
                execution_type=step.execution_type,
                tool=step.tool,
                action_id=step.action_id,
                status=status,
                args=step.args,
                result=result,
                error=error,
                tool_call_id=tool_call.id,
            )
        )

        if status in {"fail", "needs_approval"} and step.on_error == "stop":
            break

    confidence = _calculate_confidence(
        db,
        tenant_id=tenant_id,
        citations=_normalize_available_citations(
            db,
            tenant_id=tenant_id,
            citations=citations,
        ),
    )
    available_citations = _normalize_available_citations(
        db,
        tenant_id=tenant_id,
        citations=citations,
    )
    return BrainExecutionResult(
        plan_id=plan_record.id,
        steps_executed=steps_executed,
        citations=available_citations,
        confidence=confidence,
        missing_evidence=missing_evidence,
        proposed_actions=proposed_actions,
    )
