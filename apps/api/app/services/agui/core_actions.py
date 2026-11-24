from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.db.models.ai_iam import AgentIdentity, CapabilityToken
from app.db.models.ai_system import AISystem
from app.db.models.discovery import DiscoveryApplication
from app.db.models.evidence import EvidenceNode
from app.db.models.finding import Finding
from app.db.models.maturity import ConflictResolution, ControlConflict
from app.db.models.policy import GuardianContractBindingV2, PolicyPack, PolicyVersion
from app.db.models.simulation import Control, SimulationDefinition, SimulationRun
from app.db.models.user import UserTenantRole
from app.services.agui.context import AGUIExecutionContext
from app.services.agui.contracts import AGUIActionContract, AGUIActionRegistration
from app.services.agui.registry import AGUIRegistry
from app.services.ai_iam_service import (
    mint_capability_token,
    mint_capability_token_with_authority,
    revoke_capability_token,
)
from app.services.discovery_service import (
    assign_discovery_application_owner,
    block_discovery_application,
    get_discovery_application,
    promote_discovery_application,
)
from app.services.evidence_service import create_evidence_node, link_evidence_nodes
from app.services.maturity_service import recalculate_control_maturity
from app.services.simulation_service import run_simulation
from app.services.snapshot_service import create_auditor_snapshot, export_audit_artifacts


CORE_AGUI_ACTION_IDS = [
    "findings.accept_recommendation",
    "findings.reject_recommendation",
    "findings.escalate_to_governance",
    "findings.assign_owner",
    "findings.accept_risk",
    "governance.approve_application",
    "governance.block_application",
    "governance.assign_owner",
    "governance.change_risk_tier",
    "policies.approve_activation",
    "policies.override_enforcement",
    "policies.disable_guardian_binding",
    "simulations.approve_pack_run",
    "simulations.suppress_failure_with_justification",
    "auditor.challenge_assertion",
    "auditor.resolve_contested_control",
    "auditor.approve_export_pack",
    "aiiam.approve_token_mint",
    "aiiam.approve_kill_switch",
    "aiiam.revoke_privilege",
]

_SEVERITY_ORDER = ["low", "med", "high", "critical"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _is_approved(decision: str) -> bool:
    return str(decision or "").strip().lower() in {"approve", "accept", "accept_risk"}


def _reject_result(*, action: str, decision: str) -> dict[str, Any]:
    return {
        "action": action,
        "status": "not_applied",
        "applied": False,
        "decision": str(decision or "").strip().lower(),
    }


def _required_str(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def _optional_str(payload: dict[str, Any], key: str) -> str | None:
    value = str(payload.get(key) or "").strip()
    return value or None


def _optional_list_of_str(payload: dict[str, Any], key: str) -> list[str]:
    raw = payload.get(key)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValueError(f"{key} must be an array")
    values: list[str] = []
    for item in raw:
        candidate = str(item or "").strip()
        if candidate:
            values.append(candidate)
    return values


def _validate_tenant_user_membership(db: Session, *, tenant_id: str, user_id: str) -> None:
    membership = db.scalar(
        select(UserTenantRole).where(
            UserTenantRole.tenant_id == tenant_id,
            UserTenantRole.user_id == user_id,
        )
    )
    if membership is None:
        raise ValueError("user_id not found in tenant")


def _load_finding(db: Session, *, tenant_id: str, finding_id: str) -> Finding:
    row = db.scalar(
        select(Finding).where(
            Finding.tenant_id == tenant_id,
            Finding.finding_id == finding_id,
        )
    )
    if row is None:
        raise ValueError("finding_id not found in tenant")
    return row


def _load_ai_system(db: Session, *, tenant_id: str, ai_system_id: str) -> AISystem:
    row = db.scalar(
        select(AISystem).where(
            AISystem.tenant_id == tenant_id,
            AISystem.id == ai_system_id,
        )
    )
    if row is None:
        raise ValueError("ai_system_id not found in tenant")
    return row


def _normalize_severity(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "medium":
        normalized = "med"
    if normalized not in _SEVERITY_ORDER:
        return "low"
    return normalized


def _increase_severity(current: str) -> str:
    normalized = _normalize_severity(current)
    idx = _SEVERITY_ORDER.index(normalized)
    return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]


def _exec_findings_accept_recommendation(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "findings.accept_recommendation"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    finding_id = _required_str(decision_payload, "finding_id")
    finding = _load_finding(db, tenant_id=ctx.tenant_id, finding_id=finding_id)
    finding.status = "resolved"
    return {
        "action": action,
        "applied": True,
        "finding_id": finding.finding_id,
        "status": finding.status,
    }


def _exec_findings_reject_recommendation(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "findings.reject_recommendation"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    finding_id = _required_str(decision_payload, "finding_id")
    finding = _load_finding(db, tenant_id=ctx.tenant_id, finding_id=finding_id)
    finding.status = "reviewing"
    rejection_note = str(justification or decision_payload.get("note") or "").strip()
    if rejection_note:
        finding.recommended_action = rejection_note
    return {
        "action": action,
        "applied": True,
        "finding_id": finding.finding_id,
        "status": finding.status,
    }


def _exec_findings_escalate_to_governance(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "findings.escalate_to_governance"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    finding_id = _required_str(decision_payload, "finding_id")
    finding = _load_finding(db, tenant_id=ctx.tenant_id, finding_id=finding_id)
    finding.severity = _increase_severity(finding.severity)
    finding.status = "reviewing"
    return {
        "action": action,
        "applied": True,
        "finding_id": finding.finding_id,
        "severity": finding.severity,
        "status": finding.status,
    }


def _exec_findings_assign_owner(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "findings.assign_owner"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    finding_id = _required_str(decision_payload, "finding_id")
    owner_user_id = _optional_str(decision_payload, "owner_user_id")
    owner_department = _optional_str(decision_payload, "owner_department")
    if not owner_user_id and not owner_department:
        raise ValueError("owner_user_id or owner_department is required")
    if owner_user_id:
        _validate_tenant_user_membership(db, tenant_id=ctx.tenant_id, user_id=owner_user_id)
    finding = _load_finding(db, tenant_id=ctx.tenant_id, finding_id=finding_id)
    finding.user_id = owner_user_id
    if owner_department:
        finding.department = owner_department
    return {
        "action": action,
        "applied": True,
        "finding_id": finding.finding_id,
        "owner_user_id": finding.user_id,
        "owner_department": finding.department,
    }


def _exec_findings_accept_risk(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "findings.accept_risk"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    finding_id = _required_str(decision_payload, "finding_id")
    finding = _load_finding(db, tenant_id=ctx.tenant_id, finding_id=finding_id)
    finding.status = "accepted_risk"
    note = str(justification or "").strip()
    if note:
        finding.recommended_action = note
    return {
        "action": action,
        "applied": True,
        "finding_id": finding.finding_id,
        "status": finding.status,
    }


def _exec_governance_approve_application(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "governance.approve_application"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    application_id = _required_str(decision_payload, "application_id")
    app = get_discovery_application(db, tenant_id=ctx.tenant_id, application_id=application_id)
    if app is None:
        raise ValueError("application_id not found in tenant")
    promoted = promote_discovery_application(
        db,
        tenant_id=ctx.tenant_id,
        application=app,
        action="approve",
        provisional_risk_tier=_optional_str(decision_payload, "provisional_risk_tier"),
        actor_user_id=ctx.user_id,
    )
    return {
        "action": action,
        "applied": True,
        "application_id": promoted.id,
        "ai_system_id": promoted.ai_system_id,
        "status": promoted.status,
    }


def _exec_governance_block_application(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "governance.block_application"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    application_id = _required_str(decision_payload, "application_id")
    app = get_discovery_application(db, tenant_id=ctx.tenant_id, application_id=application_id)
    if app is None:
        raise ValueError("application_id not found in tenant")
    reason = _optional_str(decision_payload, "reason") or str(justification or "").strip() or "agui_block"
    blocked = block_discovery_application(
        db,
        tenant_id=ctx.tenant_id,
        application=app,
        reason=reason,
        actor_user_id=ctx.user_id,
    )
    return {
        "action": action,
        "applied": True,
        "application_id": blocked.id,
        "status": blocked.status,
    }


def _exec_governance_assign_owner(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "governance.assign_owner"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    application_id = _required_str(decision_payload, "application_id")
    owner_user_id = _optional_str(decision_payload, "owner_user_id")
    owner_department = _optional_str(decision_payload, "owner_department")
    if not owner_user_id and not owner_department:
        raise ValueError("owner_user_id or owner_department is required")
    app = get_discovery_application(db, tenant_id=ctx.tenant_id, application_id=application_id)
    if app is None:
        raise ValueError("application_id not found in tenant")
    if owner_user_id:
        _validate_tenant_user_membership(db, tenant_id=ctx.tenant_id, user_id=owner_user_id)
    updated = assign_discovery_application_owner(
        db,
        tenant_id=ctx.tenant_id,
        application=app,
        owner_user_id=owner_user_id,
        owner_department=owner_department,
        actor_user_id=ctx.user_id,
    )
    return {
        "action": action,
        "applied": True,
        "application_id": updated.id,
        "owner_user_id": updated.owner_user_id,
        "owner_department": updated.owner_department,
    }


def _exec_governance_change_risk_tier(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "governance.change_risk_tier"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    ai_system_id = _required_str(decision_payload, "ai_system_id")
    risk_tier = _required_str(decision_payload, "risk_tier").upper()
    ai_system = _load_ai_system(db, tenant_id=ctx.tenant_id, ai_system_id=ai_system_id)
    ai_system.risk_tier = risk_tier
    status_override = _optional_str(decision_payload, "status")
    if status_override:
        ai_system.status = status_override
    metadata = dict(ai_system.metadata_json or {})
    governance_state = _optional_str(decision_payload, "governance_state")
    if governance_state:
        metadata["governance_state"] = governance_state
    ai_system.metadata_json = metadata
    return {
        "action": action,
        "applied": True,
        "ai_system_id": ai_system.id,
        "risk_tier": ai_system.risk_tier,
        "status": ai_system.status,
    }


def _exec_policies_approve_activation(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "policies.approve_activation"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    policy_version_id = _required_str(decision_payload, "policy_version_id")
    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("policy_version_id not found in tenant")
    pack = db.scalar(
        select(PolicyPack).where(
            PolicyPack.id == row.pack_id,
            PolicyPack.tenant_id == ctx.tenant_id,
        )
    )
    if pack is None:
        raise ValueError("policy pack not found for policy_version_id")
    pack.status = "active"
    return {
        "action": action,
        "applied": True,
        "policy_version_id": row.id,
        "pack_id": pack.id,
        "pack_status": pack.status,
    }


def _exec_policies_override_enforcement(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "policies.override_enforcement"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    policy_version_id = _required_str(decision_payload, "policy_version_id")
    default_decision = _required_str(decision_payload, "default_decision").lower()
    allowed = {"allow", "warn", "block", "redact", "hold_for_approval"}
    if default_decision not in allowed:
        raise ValueError(f"default_decision must be one of: {', '.join(sorted(allowed))}")

    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("policy_version_id not found in tenant")

    defaults = dict(row.enforcement_defaults or {})
    defaults["default_decision"] = default_decision
    defaults["agui_override"] = {
        "decided_by": ctx.user_id,
        "decided_at": _utcnow().isoformat(),
        "justification": str(justification or "").strip(),
    }
    row.enforcement_defaults = defaults

    contract_json = dict(row.contract_json or {})
    contract_json["enforcement_defaults"] = defaults
    row.contract_json = contract_json
    return {
        "action": action,
        "applied": True,
        "policy_version_id": row.id,
        "default_decision": default_decision,
    }


def _exec_policies_disable_guardian_binding(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "policies.disable_guardian_binding"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    policy_version_id = _required_str(decision_payload, "policy_version_id")
    guardian_contract_id = _optional_str(decision_payload, "guardian_contract_id") or _optional_str(
        decision_payload, "guardian_id"
    )
    if not guardian_contract_id:
        raise ValueError("guardian_contract_id (or guardian_id) is required")

    row = db.scalar(
        select(PolicyVersion).where(
            PolicyVersion.id == policy_version_id,
            PolicyVersion.tenant_id == ctx.tenant_id,
        )
    )
    if row is None:
        raise ValueError("policy_version_id not found in tenant")

    changed_v1 = 0
    guardians = list(row.guardian_contracts or [])
    for guardian in guardians:
        g_id = str(guardian.get("guardian_id") or guardian.get("guardian_contract_id") or "").strip()
        if g_id != guardian_contract_id:
            continue
        if bool(guardian.get("enabled", True)):
            guardian["enabled"] = False
            changed_v1 += 1
    if changed_v1:
        row.guardian_contracts = guardians
        contract_json = dict(row.contract_json or {})
        contract_json["guardian_contracts"] = guardians
        row.contract_json = contract_json

    v2_rows = db.scalars(
        select(GuardianContractBindingV2).where(
            GuardianContractBindingV2.tenant_id == ctx.tenant_id,
            GuardianContractBindingV2.guardian_contract_id == guardian_contract_id,
            or_(
                GuardianContractBindingV2.policy_version_id.is_(None),
                GuardianContractBindingV2.policy_version_id == policy_version_id,
            ),
            GuardianContractBindingV2.enabled.is_(True),
        )
    ).all()
    changed_v2 = 0
    for binding in v2_rows:
        binding.enabled = False
        changed_v2 += 1

    if changed_v1 == 0 and changed_v2 == 0:
        raise ValueError("No active guardian binding found to disable")

    return {
        "action": action,
        "applied": True,
        "policy_version_id": row.id,
        "guardian_contract_id": guardian_contract_id,
        "disabled_v1_count": changed_v1,
        "disabled_v2_count": changed_v2,
    }


def _exec_simulations_approve_pack_run(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "simulations.approve_pack_run"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    ai_system_id = _required_str(decision_payload, "ai_system_id")
    ai_system = _load_ai_system(db, tenant_id=ctx.tenant_id, ai_system_id=ai_system_id)
    mode = _optional_str(decision_payload, "mode") or "deterministic"
    stochastic_runs = int(decision_payload.get("stochastic_runs") or 5)
    inputs_used = decision_payload.get("inputs_used") if isinstance(decision_payload.get("inputs_used"), dict) else {}
    requested_ids = _optional_list_of_str(decision_payload, "simulation_ids")
    if not requested_ids:
        raise ValueError("simulation_ids is required")

    rows = db.scalars(
        select(SimulationDefinition).where(
            SimulationDefinition.tenant_id == ctx.tenant_id,
            SimulationDefinition.id.in_(requested_ids),
        )
    ).all()
    by_id = {row.id: row for row in rows}
    missing = [sim_id for sim_id in requested_ids if sim_id not in by_id]
    if missing:
        raise ValueError(f"Unknown simulation_ids for tenant: {', '.join(missing)}")

    run_ids: list[str] = []
    results: list[dict[str, Any]] = []
    for sim_id in requested_ids:
        sim = by_id[sim_id]
        run = run_simulation(
            db,
            tenant_id=ctx.tenant_id,
            simulation=sim,
            ai_system_id=ai_system_id,
            mode=mode,
            stochastic_runs=stochastic_runs,
            inputs_used=inputs_used,
            actor_user_id=ctx.user_id,
        )
        run_ids.append(run.id)
        run_result = run.results if isinstance(run.results, dict) else {}
        results.append(
            {
                "simulation_run_id": run.id,
                "simulation_id": sim.id,
                "result": str(run_result.get("result") or ""),
                "pass_rate": float(run_result.get("pass_rate") or 0.0),
            }
        )
    return {
        "action": action,
        "applied": True,
        "ai_system_id": ai_system_id,
        "simulation_run_ids": run_ids,
        "results": results,
    }


def _exec_simulations_suppress_failure(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "simulations.suppress_failure_with_justification"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    simulation_run_id = _required_str(decision_payload, "simulation_run_id")
    run = db.scalar(
        select(SimulationRun).where(
            SimulationRun.id == simulation_run_id,
            SimulationRun.tenant_id == ctx.tenant_id,
        )
    )
    if run is None:
        raise ValueError("simulation_run_id not found in tenant")

    reason = str(justification or "").strip()
    if not reason:
        raise ValueError("justification is required")

    results = dict(run.results or {})
    results["suppressed"] = True
    results["suppression_reason"] = reason
    results["suppressed_by"] = ctx.user_id
    results["suppressed_at"] = _utcnow().isoformat()
    run.results = results
    note_line = f"[agui_suppressed] {reason}"
    run.notes = f"{note_line}\n{run.notes}".strip()
    return {
        "action": action,
        "applied": True,
        "simulation_run_id": run.id,
        "suppressed": True,
    }


def _exec_auditor_challenge_assertion(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "auditor.challenge_assertion"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    ai_system_id = _required_str(decision_payload, "ai_system_id")
    control_id = _required_str(decision_payload, "control_id")
    challenge_reason = _optional_str(decision_payload, "challenge_reason") or str(justification or "").strip()
    if not challenge_reason:
        raise ValueError("challenge_reason is required")

    _load_ai_system(db, tenant_id=ctx.tenant_id, ai_system_id=ai_system_id)
    control = db.scalar(
        select(Control).where(
            Control.id == control_id,
            Control.tenant_id == ctx.tenant_id,
        )
    )
    if control is None:
        raise ValueError("control_id not found")

    referenced = db.scalars(
        select(EvidenceNode).where(
            EvidenceNode.tenant_id == ctx.tenant_id,
            EvidenceNode.id.in_(evidence_node_ids) if evidence_node_ids else EvidenceNode.id == "__none__",
        )
    ).all()
    found = {row.id for row in referenced}
    missing = [node_id for node_id in evidence_node_ids if node_id not in found]
    if missing:
        raise ValueError(f"Unknown evidence_node_ids for tenant: {', '.join(missing)}")

    challenge_node = create_evidence_node(
        db,
        tenant_id=ctx.tenant_id,
        node_type="auditor_challenge",
        signal_type="control.challenge.created",
        label=f"Auditor challenge for {control_id}",
        payload={
            "ai_system_id": ai_system_id,
            "control_id": control_id,
            "challenge_reason": challenge_reason,
            "evidence_node_ids": evidence_node_ids,
            "source": "agui",
        },
        correlation_id=ctx.correlation_id,
    )
    conflict = ControlConflict(
        tenant_id=ctx.tenant_id,
        ai_system_id=ai_system_id,
        control_id=control_id,
        status="open",
        reason="auditor_challenge",
        positive_signals=0,
        negative_signals=0,
        latest_signal_at=_utcnow(),
        evidence_node_ids=[*evidence_node_ids, challenge_node.id],
        details={
            "challenge_reason": challenge_reason,
            "requires_human_resolution": True,
            "challenge_node_id": challenge_node.id,
            "lineage_preserved": True,
        },
        audit_log_id=None,
    )
    db.add(conflict)
    db.flush()

    for node_id in evidence_node_ids:
        link_evidence_nodes(
            db,
            tenant_id=ctx.tenant_id,
            from_node_id=node_id,
            to_node_id=challenge_node.id,
            edge_type="challenged_by",
            payload={"conflict_id": conflict.id, "control_id": control_id},
        )

    recalculate_control_maturity(
        db,
        tenant_id=ctx.tenant_id,
        ai_system_id=ai_system_id,
        control_ids=[control_id],
        reason=f"agui_challenge:{conflict.id}",
    )
    return {
        "action": action,
        "applied": True,
        "conflict_id": conflict.id,
        "ai_system_id": ai_system_id,
        "control_id": control_id,
    }


def _exec_auditor_resolve_contested_control(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "auditor.resolve_contested_control"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    conflict_id = _required_str(decision_payload, "conflict_id")
    resolution_decision = _optional_str(decision_payload, "resolution_decision") or "inconclusive"
    notes = str(justification or "").strip()

    conflict = db.scalar(
        select(ControlConflict).where(
            ControlConflict.id == conflict_id,
            ControlConflict.tenant_id == ctx.tenant_id,
        )
    )
    if conflict is None:
        raise ValueError("conflict_id not found in tenant")
    if conflict.status != "open":
        raise ValueError("conflict is not open")

    now = _utcnow()
    conflict.status = "resolved"
    conflict.resolved_at = now
    conflict.resolution_decision = resolution_decision
    conflict.resolution_notes = notes
    conflict.resolved_by = ctx.user_id

    chosen_evidence_id = (conflict.details or {}).get("chosen_evidence_id")
    if not chosen_evidence_id and conflict.evidence_node_ids:
        chosen_evidence_id = conflict.evidence_node_ids[0]
    discarded_evidence_ids = [node_id for node_id in (conflict.evidence_node_ids or []) if node_id != chosen_evidence_id]
    db.add(
        ConflictResolution(
            tenant_id=ctx.tenant_id,
            ai_system_id=conflict.ai_system_id,
            control_id=conflict.control_id,
            conflict_id=conflict.id,
            chosen_evidence_id=chosen_evidence_id,
            discarded_evidence_ids=discarded_evidence_ids,
            reason=f"agui_resolution:{resolution_decision}",
        )
    )

    resolution_node = create_evidence_node(
        db,
        tenant_id=ctx.tenant_id,
        node_type="control_conflict_resolution",
        signal_type="control.conflict.resolved",
        label=f"Control conflict resolved for {conflict.control_id}",
        payload={
            "conflict_id": conflict.id,
            "control_id": conflict.control_id,
            "ai_system_id": conflict.ai_system_id,
            "decision": resolution_decision,
            "notes": notes,
            "source": "agui",
        },
        correlation_id=ctx.correlation_id,
    )
    existing_node_ids = list(conflict.evidence_node_ids or [])
    if existing_node_ids:
        try:
            link_evidence_nodes(
                db,
                tenant_id=ctx.tenant_id,
                from_node_id=existing_node_ids[0],
                to_node_id=resolution_node.id,
                edge_type="adjudicated",
                payload={"conflict_id": conflict.id},
            )
        except ValueError:
            pass
    conflict.evidence_node_ids = [*existing_node_ids, resolution_node.id]

    recalculate_control_maturity(
        db,
        tenant_id=ctx.tenant_id,
        ai_system_id=conflict.ai_system_id,
        control_ids=[conflict.control_id],
        reason=f"agui_conflict_resolved:{conflict.id}:{resolution_decision}",
    )

    return {
        "action": action,
        "applied": True,
        "conflict_id": conflict.id,
        "status": conflict.status,
        "resolution_decision": resolution_decision,
    }


def _exec_auditor_approve_export_pack(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "auditor.approve_export_pack"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    ai_system_id = _optional_str(decision_payload, "ai_system_id")
    period_start = _optional_str(decision_payload, "period_start") or (_utcnow() - timedelta(days=30)).isoformat()
    period_end = _optional_str(decision_payload, "period_end") or _utcnow().isoformat()

    artifacts = export_audit_artifacts(
        db,
        tenant_id=ctx.tenant_id,
        ai_system_id=ai_system_id,
        period_start=period_start,
        period_end=period_end,
    )
    snapshot = create_auditor_snapshot(
        db,
        tenant_id=ctx.tenant_id,
        ai_system_id=ai_system_id,
        trigger_type="agui_export_approved",
        payload={"period_start": period_start, "period_end": period_end, "artifacts": artifacts},
        actor_user_id=ctx.user_id,
        artifact_hash=artifacts.get("hash"),
        artifact_relative_path=artifacts.get("json_relative_path"),
    )
    return {
        "action": action,
        "applied": True,
        "snapshot_id": snapshot.id,
        "artifact_path": snapshot.artifact_path,
        "json_relative_path": artifacts.get("json_relative_path"),
        "csv_relative_path": artifacts.get("csv_relative_path"),
    }


def _exec_aiiam_approve_token_mint(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "aiiam.approve_token_mint"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    agent_id = _required_str(decision_payload, "agent_id")
    ai_system_id = _required_str(decision_payload, "ai_system_id")
    ai_system = _load_ai_system(db, tenant_id=ctx.tenant_id, ai_system_id=ai_system_id)
    scopes = _optional_list_of_str(decision_payload, "scopes")
    if not scopes:
        raise ValueError("scopes is required")

    raw_token = f"agui_{uuid4().hex}"
    expires_minutes = int(decision_payload.get("expires_minutes") or 60)
    chain_depth = int(decision_payload.get("chain_depth") or 1)
    approval_request_id = _optional_str(decision_payload, "approval_request_id")
    token, consumed_approval_id = mint_capability_token_with_authority(
        db,
        tenant_id=ctx.tenant_id,
        ai_system=ai_system,
        agent_identity_id=agent_id,
        raw_token=raw_token,
        scopes=scopes,
        expires_minutes=expires_minutes,
        chain_depth=chain_depth,
        issued_by_user_id=ctx.user_id,
        approval_request_id=approval_request_id,
    )
    return {
        "action": action,
        "applied": True,
        "token_id": token.id,
        "capability_token": raw_token,
        "agent_id": token.agent_identity_id,
        "ai_system_id": ai_system_id,
        "approval_request_id": consumed_approval_id,
        "scopes": token.scopes,
        "expires_at": token.expires_at.isoformat(),
    }


def _exec_aiiam_approve_kill_switch(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "aiiam.approve_kill_switch"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    agent_id = _required_str(decision_payload, "agent_id")
    agent = db.scalar(
        select(AgentIdentity).where(
            AgentIdentity.id == agent_id,
            AgentIdentity.tenant_id == ctx.tenant_id,
        )
    )
    if agent is None:
        raise ValueError("agent_id not found in tenant")

    now = _utcnow()
    agent.status = "isolated"
    tokens = db.scalars(
        select(CapabilityToken).where(
            CapabilityToken.tenant_id == ctx.tenant_id,
            CapabilityToken.agent_identity_id == agent_id,
        )
    ).all()
    revoked_tokens = 0
    for token in tokens:
        if token.revoked_at is None:
            token.revoked_at = now
            revoked_tokens += 1

    ai_system_id = _optional_str(decision_payload, "ai_system_id")
    snapshot = create_auditor_snapshot(
        db,
        tenant_id=ctx.tenant_id,
        ai_system_id=ai_system_id,
        trigger_type="agui_kill_switch",
        payload={
            "agent_id": agent_id,
            "reason": str(justification or decision_payload.get("reason") or "agui_kill_switch").strip(),
            "revoked_tokens": revoked_tokens,
        },
        actor_user_id=ctx.user_id,
    )
    return {
        "action": action,
        "applied": True,
        "agent_id": agent_id,
        "status": agent.status,
        "revoked_tokens": revoked_tokens,
        "snapshot_id": snapshot.id,
    }


def _exec_aiiam_revoke_privilege(
    db: Session,
    ctx: AGUIExecutionContext,
    _contract: AGUIActionContract,
    decision: str,
    _justification: str | None,
    _evidence_node_ids: list[str],
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    action = "aiiam.revoke_privilege"
    if not _is_approved(decision):
        return _reject_result(action=action, decision=decision)
    token_id = _required_str(decision_payload, "token_id")
    token = revoke_capability_token(db, tenant_id=ctx.tenant_id, token_id=token_id)
    if token is None:
        raise ValueError("token_id not found in tenant")
    return {
        "action": action,
        "applied": True,
        "token_id": token.id,
        "status": "revoked",
        "revoked_at": token.revoked_at.isoformat() if token.revoked_at else None,
    }


def _register(registry: AGUIRegistry, contract: AGUIActionContract, executor) -> None:
    if registry.get_action(contract.action_id) is not None:
        return
    registry.register_action(AGUIActionRegistration(contract=contract, executor=executor))


def register_core_agui_actions(registry: AGUIRegistry) -> None:
    contracts_and_executors: list[tuple[AGUIActionContract, Any]] = [
        (
            AGUIActionContract(
                action_id="findings.accept_recommendation",
                action_type="approve",
                title="Accept Finding Recommendation",
                description="Accept recommendation for a finding and resolve it.",
                source_module="findings",
                source_object_type="finding",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="write",
            ),
            _exec_findings_accept_recommendation,
        ),
        (
            AGUIActionContract(
                action_id="findings.reject_recommendation",
                action_type="override",
                title="Reject Finding Recommendation",
                description="Reject recommendation and keep finding under review.",
                source_module="findings",
                source_object_type="finding",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="recommend",
            ),
            _exec_findings_reject_recommendation,
        ),
        (
            AGUIActionContract(
                action_id="findings.escalate_to_governance",
                action_type="escalate",
                title="Escalate Finding To Governance",
                description="Escalate severity and route finding to governance review.",
                source_module="findings",
                source_object_type="finding",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="enforce",
            ),
            _exec_findings_escalate_to_governance,
        ),
        (
            AGUIActionContract(
                action_id="findings.assign_owner",
                action_type="assign",
                title="Assign Finding Owner",
                description="Assign owner and department for finding remediation.",
                source_module="findings",
                source_object_type="finding",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=False,
                requires_diff_preview=False,
                side_effect_level="write",
            ),
            _exec_findings_assign_owner,
        ),
        (
            AGUIActionContract(
                action_id="findings.accept_risk",
                action_type="accept_risk",
                title="Accept Finding Risk",
                description="Accept risk for a finding with explicit justification.",
                source_module="findings",
                source_object_type="finding",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="admin",
            ),
            _exec_findings_accept_risk,
        ),
        (
            AGUIActionContract(
                action_id="governance.approve_application",
                action_type="approve",
                title="Approve Discovery Application",
                description="Promote discovered application into governed trust center state.",
                source_module="governance",
                source_object_type="discovery_application",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="enforce",
            ),
            _exec_governance_approve_application,
        ),
        (
            AGUIActionContract(
                action_id="governance.block_application",
                action_type="block",
                title="Block Discovery Application",
                description="Block discovered application and mark lifecycle as prohibited.",
                source_module="governance",
                source_object_type="discovery_application",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="enforce",
            ),
            _exec_governance_block_application,
        ),
        (
            AGUIActionContract(
                action_id="governance.assign_owner",
                action_type="assign",
                title="Assign Governance Owner",
                description="Assign owner to discovered application prior to promotion.",
                source_module="governance",
                source_object_type="discovery_application",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=False,
                requires_diff_preview=False,
                side_effect_level="write",
            ),
            _exec_governance_assign_owner,
        ),
        (
            AGUIActionContract(
                action_id="governance.change_risk_tier",
                action_type="update",
                title="Change AI System Risk Tier",
                description="Change governed AI system risk tier for runtime strictness propagation.",
                source_module="governance",
                source_object_type="ai_system",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=True,
                side_effect_level="enforce",
            ),
            _exec_governance_change_risk_tier,
        ),
        (
            AGUIActionContract(
                action_id="policies.approve_activation",
                action_type="approve",
                title="Approve Policy Activation",
                description="Activate policy pack for the chosen policy version.",
                source_module="policies",
                source_object_type="policy_version",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=True,
                side_effect_level="enforce",
            ),
            _exec_policies_approve_activation,
        ),
        (
            AGUIActionContract(
                action_id="policies.override_enforcement",
                action_type="override",
                title="Override Policy Enforcement",
                description="Override enforcement defaults for policy version with full justification.",
                source_module="policies",
                source_object_type="policy_version",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=True,
                side_effect_level="admin",
            ),
            _exec_policies_override_enforcement,
        ),
        (
            AGUIActionContract(
                action_id="policies.disable_guardian_binding",
                action_type="disable",
                title="Disable Guardian Binding",
                description="Disable guardian binding for policy version in controlled override flow.",
                source_module="policies",
                source_object_type="policy_version",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=True,
                side_effect_level="admin",
            ),
            _exec_policies_disable_guardian_binding,
        ),
        (
            AGUIActionContract(
                action_id="simulations.approve_pack_run",
                action_type="approve",
                title="Approve Simulation Pack Run",
                description="Approve and execute a simulation pack run against target AI system.",
                source_module="simulations",
                source_object_type="simulation_definition",
                source_object_id="__runtime__",
                required_role=["operator", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="enforce",
            ),
            _exec_simulations_approve_pack_run,
        ),
        (
            AGUIActionContract(
                action_id="simulations.suppress_failure_with_justification",
                action_type="suppress",
                title="Suppress Simulation Failure",
                description="Suppress simulation failure only with explicit human justification.",
                source_module="simulations",
                source_object_type="simulation_run",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=True,
                side_effect_level="admin",
            ),
            _exec_simulations_suppress_failure,
        ),
        (
            AGUIActionContract(
                action_id="auditor.challenge_assertion",
                action_type="challenge",
                title="Challenge Auditor Assertion",
                description="Create challenge record against control assertion and preserve lineage.",
                source_module="auditor",
                source_object_type="control_conflict",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="enforce",
            ),
            _exec_auditor_challenge_assertion,
        ),
        (
            AGUIActionContract(
                action_id="auditor.resolve_contested_control",
                action_type="resolve",
                title="Resolve Contested Control",
                description="Resolve open contested control with deterministic adjudication.",
                source_module="auditor",
                source_object_type="control_conflict",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=True,
                side_effect_level="enforce",
            ),
            _exec_auditor_resolve_contested_control,
        ),
        (
            AGUIActionContract(
                action_id="auditor.approve_export_pack",
                action_type="approve",
                title="Approve Auditor Export Pack",
                description="Approve generation of auditor export pack and immutable snapshot.",
                source_module="auditor",
                source_object_type="auditor_snapshot",
                source_object_id="__runtime__",
                required_role=["auditor", "admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="export",
            ),
            _exec_auditor_approve_export_pack,
        ),
        (
            AGUIActionContract(
                action_id="aiiam.approve_token_mint",
                action_type="approve",
                title="Approve AI IAM Token Mint",
                description="Approve minting of AI IAM capability token.",
                source_module="aiiam",
                source_object_type="agent_identity",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="enforce",
            ),
            _exec_aiiam_approve_token_mint,
        ),
        (
            AGUIActionContract(
                action_id="aiiam.approve_kill_switch",
                action_type="approve",
                title="Approve AI IAM Kill Switch",
                description="Approve agent isolation and token revocation kill switch flow.",
                source_module="aiiam",
                source_object_type="agent_identity",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=True,
                requires_evidence_display=True,
                requires_diff_preview=True,
                side_effect_level="admin",
            ),
            _exec_aiiam_approve_kill_switch,
        ),
        (
            AGUIActionContract(
                action_id="aiiam.revoke_privilege",
                action_type="revoke",
                title="Revoke AI IAM Privilege",
                description="Revoke an existing AI IAM capability token.",
                source_module="aiiam",
                source_object_type="capability_token",
                source_object_id="__runtime__",
                required_role=["admin", "owner"],
                decision_options=["approve", "reject"],
                requires_justification=False,
                requires_evidence_display=True,
                requires_diff_preview=False,
                side_effect_level="enforce",
            ),
            _exec_aiiam_revoke_privilege,
        ),
    ]
    for contract, executor in contracts_and_executors:
        _register(registry, contract, executor)
