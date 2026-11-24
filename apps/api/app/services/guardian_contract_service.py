from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.policy import ControlGuardianBinding, GuardianContract, PolicyVersion


def _normalize_conditions(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        conditions = value.get("conditions")
        if isinstance(conditions, list):
            return [item for item in conditions if isinstance(item, dict)]
    return []


def _strength_from_impact(impact: dict[str, Any] | None) -> str:
    level = int((impact or {}).get("enforcement_strictness_increase", 0))
    if level >= 2:
        return "maximum"
    if level >= 1:
        return "strict"
    return "baseline"


def _contract_payload_from_legacy_guardian(guardian: dict[str, Any]) -> dict[str, Any]:
    trigger_conditions = _normalize_conditions(guardian.get("trigger"))
    block_conditions = _normalize_conditions(guardian.get("block_conditions"))
    decision = guardian.get("decision") or {}
    if not block_conditions and str(decision.get("on_fail", "")).strip().lower() == "block":
        block_conditions = list(trigger_conditions)

    actions = guardian.get("actions") or {}
    escalation_path = guardian.get("escalation_path") or {}
    if guardian.get("approval_workflow"):
        escalation_path = {**escalation_path, "approval_workflow": guardian.get("approval_workflow")}

    evidence = guardian.get("evidence") or {}
    framework_mappings = guardian.get("framework_mappings") or {
        "control_ids": list(evidence.get("link_to_controls") or []),
    }

    return {
        "name": str(guardian.get("description") or guardian.get("guardian_id") or "guardian_contract"),
        "trigger_conditions": trigger_conditions,
        "block_conditions": block_conditions,
        "mandatory_actions": actions,
        "escalation_path": escalation_path,
        "evidence_requirements": evidence,
        "framework_mappings": framework_mappings,
    }


def sync_policy_guardians_to_contracts(db: Session, *, policy_version: PolicyVersion) -> list[GuardianContract]:
    synced: list[GuardianContract] = []
    for guardian in policy_version.guardian_contracts or []:
        guardian_id = str(guardian.get("guardian_id") or "").strip()
        if not guardian_id:
            continue
        payload = _contract_payload_from_legacy_guardian(guardian)
        row = db.get(GuardianContract, guardian_id)
        if row is None:
            row = GuardianContract(id=guardian_id, **payload)
            db.add(row)
            db.flush()
        else:
            row.name = payload["name"]
            row.trigger_conditions = payload["trigger_conditions"]
            row.block_conditions = payload["block_conditions"]
            row.mandatory_actions = payload["mandatory_actions"]
            row.escalation_path = payload["escalation_path"]
            row.evidence_requirements = payload["evidence_requirements"]
            row.framework_mappings = payload["framework_mappings"]

        controls = list((payload["evidence_requirements"] or {}).get("link_to_controls") or [])
        strength = _strength_from_impact(guardian.get("control_impact") or {})
        for control_id in controls:
            exists = db.scalar(
                select(ControlGuardianBinding).where(
                    ControlGuardianBinding.control_id == str(control_id),
                    ControlGuardianBinding.guardian_contract_id == guardian_id,
                )
            )
            if exists:
                exists.enforcement_strength = strength
            else:
                db.add(
                    ControlGuardianBinding(
                        control_id=str(control_id),
                        guardian_contract_id=guardian_id,
                        enforcement_strength=strength,
                    )
                )
        synced.append(row)
    if synced:
        db.flush()
    return synced


def load_policy_guardian_contracts(db: Session, *, policy_version: PolicyVersion | None) -> list[dict[str, Any]]:
    if policy_version is None:
        return []
    sync_policy_guardians_to_contracts(db, policy_version=policy_version)

    out: list[dict[str, Any]] = []
    for guardian in policy_version.guardian_contracts or []:
        guardian_id = str(guardian.get("guardian_id") or "").strip()
        if not guardian_id:
            continue
        row = db.get(GuardianContract, guardian_id)
        if row is None:
            continue
        out.append(
            {
                "guardian_contract_id": row.id,
                "guardian_id": guardian_id,
                "name": row.name,
                "enabled": bool(guardian.get("enabled", True)),
                "trigger_conditions": row.trigger_conditions or [],
                "block_conditions": row.block_conditions or [],
                "mandatory_actions": row.mandatory_actions or {},
                "escalation_path": row.escalation_path or {},
                "evidence_requirements": row.evidence_requirements or {},
                "framework_mappings": row.framework_mappings or {},
                "legacy_evaluation": guardian.get("evaluation") or {},
                "legacy_decision": guardian.get("decision") or {},
                "legacy_control_impact": guardian.get("control_impact") or {},
                "legacy_approval_workflow": guardian.get("approval_workflow") or {},
            }
        )
    return out


def get_guardian_contract_matrix(
    db: Session,
    *,
    policy_version: PolicyVersion | None = None,
) -> dict[str, Any]:
    filter_ids: set[str] | None = None
    if policy_version is not None:
        contracts = sync_policy_guardians_to_contracts(db, policy_version=policy_version)
        filter_ids = {row.id for row in contracts}

    query = select(GuardianContract)
    if filter_ids is not None:
        if not filter_ids:
            return {"items": [], "total": 0}
        query = query.where(GuardianContract.id.in_(filter_ids))
    rows = db.scalars(query.order_by(GuardianContract.id.asc())).all()

    bindings = db.scalars(select(ControlGuardianBinding)).all()
    by_guardian: dict[str, list[dict[str, Any]]] = {}
    for row in bindings:
        if filter_ids is not None and row.guardian_contract_id not in filter_ids:
            continue
        bucket = by_guardian.setdefault(row.guardian_contract_id, [])
        bucket.append(
            {
                "control_id": row.control_id,
                "enforcement_strength": row.enforcement_strength,
            }
        )

    items = []
    for row in rows:
        items.append(
            {
                "guardian_contract_id": row.id,
                "name": row.name,
                "trigger_conditions": row.trigger_conditions or [],
                "block_conditions": row.block_conditions or [],
                "mandatory_actions": row.mandatory_actions or {},
                "escalation_path": row.escalation_path or {},
                "evidence_requirements": row.evidence_requirements or {},
                "framework_mappings": row.framework_mappings or {},
                "control_bindings": sorted(by_guardian.get(row.id, []), key=lambda x: (x["control_id"], x["enforcement_strength"])),
            }
        )
    return {"items": items, "total": len(items)}
