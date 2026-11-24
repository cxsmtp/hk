from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models.ai_system import AISystem
from app.db.models.policy import GuardianContractBindingV2, GuardianContractV2, PolicyVersion
from app.services.guardian_policy_engine import (
    canonical_guardian_policy,
    framework_mapping_is_valid,
    normalize_framework_mapping,
)


DEFAULT_V2_CONTRACTS: list[dict[str, Any]] = [
    {
        "id": "prompt_injection_guard",
        "version": "2.0",
        "name": "Prompt Injection Guard",
        "trigger_conditions": [
            {"field": "prompt.text", "operator": "contains", "value": "ignore previous instructions", "case_sensitive": False}
        ],
        "block_conditions": [
            {"field": "prompt.text", "operator": "contains", "value": "reveal secrets", "case_sensitive": False}
        ],
        "mandatory_actions": {"notify": {"channels": ["email"]}},
        "escalation_path": {"mode": "notify"},
        "evidence_requirements": {"link_to_controls": ["CTRL-PI-001"]},
        "framework_mappings": {
            "control_ids": ["CTRL-PI-001"],
            "nist_ai_rmf": ["GV.RM", "MP.AI", "ME.AI"],
            "iso_42001": ["A.5", "A.8", "A.12"],
            "eu_ai_act": ["risk_management", "transparency"],
            "owasp_genai": ["LLM01"],
            "mitre_atlas": ["AML.TA0001"],
        },
    },
    {
        "id": "sensitive_data_leak_guard",
        "version": "2.0",
        "name": "Sensitive Data Leak Guard",
        "trigger_conditions": [
            {"field": "prompt.text", "operator": "contains", "value": "ssn", "case_sensitive": False}
        ],
        "block_conditions": [
            {"field": "prompt.text", "operator": "contains", "value": "customer data", "case_sensitive": False}
        ],
        "mandatory_actions": {"redact": {"fields": ["prompt"], "strategy": "mask"}},
        "escalation_path": {"mode": "notify"},
        "evidence_requirements": {"link_to_controls": ["CTRL-DLP-001"]},
        "framework_mappings": {
            "control_ids": ["CTRL-DLP-001"],
            "nist_ai_rmf": ["MP.AI", "ME.AI"],
            "iso_42001": ["A.8", "A.12"],
            "eu_ai_act": ["data_governance", "risk_management"],
            "owasp_genai": ["LLM06"],
            "mitre_atlas": ["AML.TA0004"],
        },
    },
    {
        "id": "tool_output_injection_guard",
        "version": "2.0",
        "name": "Tool Output Injection Guard",
        "trigger_conditions": [
            {"field": "tool_output", "operator": "contains", "value": "ignore policy", "case_sensitive": False}
        ],
        "block_conditions": [
            {"field": "tool_output", "operator": "contains", "value": "execute shell", "case_sensitive": False}
        ],
        "mandatory_actions": {"mutate_output": {"enabled": True, "strategy": "safe_completion"}},
        "escalation_path": {"mode": "notify"},
        "evidence_requirements": {"link_to_controls": ["CTRL-TOOL-001"]},
        "framework_mappings": {
            "control_ids": ["CTRL-TOOL-001"],
            "nist_ai_rmf": ["GV.RM", "ME.AI"],
            "iso_42001": ["A.8", "A.12"],
            "eu_ai_act": ["human_oversight", "transparency"],
            "owasp_genai": ["LLM08"],
            "mitre_atlas": ["AML.TA0003"],
        },
    },
]


def _build_canonical_policy(contract: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    framework = normalize_framework_mapping(contract.get("framework_mappings") or {})
    if not framework_mapping_is_valid(framework):
        raise ValueError("framework_mappings must include NIST AI RMF, ISO 42001, and EU AI Act mappings")
    return canonical_guardian_policy(
        policy_id=str(contract.get("id") or "").strip(),
        policy_name=str(contract.get("name") or contract.get("id") or "guardian_contract").strip(),
        policy_version=str(contract.get("version") or "2.0"),
        tenant_id=tenant_id,
        scope={
            "ai_system_ids": ["*"],
            "agent_ids": ["*"],
            "user_groups": ["*"],
            "environments": ["prod", "staging", "dev"],
        },
        conditions={
            "source": {"type": "api", "classification": "internal"},
            "destination": {"type": "ai_tool", "trust_level": "unknown"},
            "action": {"type": "prompt"},
            "data": {"patterns": []},
        },
        decision={
            "mode": "block",
            "confidence_threshold": float((contract.get("evidence_requirements") or {}).get("confidence_threshold", 0.7)),
            "strictness": "high",
        },
        enforcement={"fail_mode": "fail_secure", "log": True, "create_finding": True, "require_evidence": True},
        governance={"risk_level": "high", "approval_required": False, "policy_owner": "system", "review_cycle_days": 30},
        framework_mapping=framework,
        metadata={
            "active": True,
            "legacy_trigger_conditions": list(contract.get("trigger_conditions") or []),
            "legacy_block_conditions": list(contract.get("block_conditions") or []),
            "legacy_mandatory_actions": dict(contract.get("mandatory_actions") or {}),
            "legacy_escalation_path": dict(contract.get("escalation_path") or {}),
            "legacy_evidence_requirements": dict(contract.get("evidence_requirements") or {}),
        },
    )


def _normalize_contract_payload(payload: dict[str, Any], *, tenant_id: str) -> dict[str, Any]:
    normalized = dict(payload)
    normalized["framework_mappings"] = normalize_framework_mapping(normalized.get("framework_mappings") or {})
    if not framework_mapping_is_valid(normalized["framework_mappings"]):
        raise ValueError("framework_mappings must include NIST AI RMF, ISO 42001, and EU AI Act mappings")
    normalized["canonical_policy"] = _build_canonical_policy(normalized, tenant_id=tenant_id)
    normalized["tenant_id"] = tenant_id
    return normalized


def seed_default_v2_contracts(db: Session, *, tenant_id: str) -> list[GuardianContractV2]:
    seeded: list[GuardianContractV2] = []
    for contract in DEFAULT_V2_CONTRACTS:
        normalized_contract = _normalize_contract_payload(contract, tenant_id=tenant_id)
        dialect_name = db.get_bind().dialect.name
        if dialect_name == "postgresql":
            db.execute(
                postgresql_insert(GuardianContractV2)
                .values(**normalized_contract)
                .on_conflict_do_nothing(index_elements=["tenant_id", "id"])
            )
        elif dialect_name == "sqlite":
            db.execute(
                sqlite_insert(GuardianContractV2)
                .values(**normalized_contract)
                .on_conflict_do_nothing(index_elements=["tenant_id", "id"])
            )
        else:
            try:
                with db.begin_nested():
                    db.add(GuardianContractV2(**normalized_contract))
                    db.flush()
            except IntegrityError:
                pass

        row = db.get(GuardianContractV2, (tenant_id, contract["id"]), populate_existing=True)
        if row is None:
            raise RuntimeError(f"Failed to persist default Guardian contract {contract['id']}")
        row.framework_mappings = normalized_contract["framework_mappings"]
        row.canonical_policy = normalized_contract["canonical_policy"]
        seeded.append(row)
    db.flush()
    return seeded


def list_v2_contracts(db: Session, *, tenant_id: str) -> list[GuardianContractV2]:
    return db.scalars(
        select(GuardianContractV2)
        .where(GuardianContractV2.tenant_id == tenant_id)
        .order_by(GuardianContractV2.id.asc())
    ).all()


def get_v2_contract(db: Session, *, tenant_id: str, contract_id: str) -> GuardianContractV2 | None:
    return db.get(GuardianContractV2, (tenant_id, contract_id))


def create_v2_contract(db: Session, *, tenant_id: str, payload: dict[str, Any]) -> GuardianContractV2:
    normalized = _normalize_contract_payload(payload, tenant_id=tenant_id)
    row = GuardianContractV2(**normalized)
    db.add(row)
    db.flush()
    return row


def update_v2_contract(
    db: Session,
    *,
    tenant_id: str,
    row: GuardianContractV2,
    payload: dict[str, Any],
) -> GuardianContractV2:
    if row.tenant_id != tenant_id:
        raise ValueError("guardian_contract_v2_not_found")
    merged = {
        "id": row.id,
        "version": row.version,
        "name": row.name,
        "trigger_conditions": row.trigger_conditions,
        "block_conditions": row.block_conditions,
        "mandatory_actions": row.mandatory_actions,
        "escalation_path": row.escalation_path,
        "evidence_requirements": row.evidence_requirements,
        "framework_mappings": row.framework_mappings,
        "canonical_policy": row.canonical_policy,
    }
    merged.update(payload)
    normalized = _normalize_contract_payload(merged, tenant_id=tenant_id)
    for field, value in normalized.items():
        if field in {"id", "tenant_id"}:
            continue
        setattr(row, field, value)
    db.flush()
    return row


def delete_v2_contract(db: Session, *, tenant_id: str, row: GuardianContractV2) -> None:
    if row.tenant_id != tenant_id:
        raise ValueError("guardian_contract_v2_not_found")
    db.delete(row)
    db.flush()


def _validate_binding_scope(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None,
    policy_version_id: str | None,
) -> None:
    if ai_system_id:
        ai_system = db.scalar(
            select(AISystem).where(
                AISystem.id == ai_system_id,
                AISystem.tenant_id == tenant_id,
            )
        )
        if ai_system is None:
            raise ValueError("AI system not found for tenant")

    if policy_version_id:
        version = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.id == policy_version_id,
                PolicyVersion.tenant_id == tenant_id,
            )
        )
        if version is None:
            raise ValueError("Policy version not found for tenant")


def upsert_v2_binding(
    db: Session,
    *,
    tenant_id: str,
    guardian_contract_id: str,
    ai_system_id: str | None,
    policy_version_id: str | None,
    enforcement_strength: str,
    enabled: bool,
) -> GuardianContractBindingV2:
    _validate_binding_scope(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        policy_version_id=policy_version_id,
    )

    ai_system_filter = (
        GuardianContractBindingV2.ai_system_id.is_(None)
        if ai_system_id is None
        else GuardianContractBindingV2.ai_system_id == ai_system_id
    )
    policy_filter = (
        GuardianContractBindingV2.policy_version_id.is_(None)
        if policy_version_id is None
        else GuardianContractBindingV2.policy_version_id == policy_version_id
    )
    row = db.scalar(
        select(GuardianContractBindingV2).where(
            GuardianContractBindingV2.tenant_id == tenant_id,
            GuardianContractBindingV2.guardian_contract_id == guardian_contract_id,
            ai_system_filter,
            policy_filter,
        )
    )
    if row is None:
        row = GuardianContractBindingV2(
            tenant_id=tenant_id,
            guardian_contract_id=guardian_contract_id,
            ai_system_id=ai_system_id,
            policy_version_id=policy_version_id,
            enforcement_strength=enforcement_strength,
            enabled=enabled,
        )
        db.add(row)
    else:
        row.enforcement_strength = enforcement_strength
        row.enabled = enabled
    db.flush()
    return row


def list_v2_bindings(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None = None,
    policy_version_id: str | None = None,
) -> list[GuardianContractBindingV2]:
    query = select(GuardianContractBindingV2).where(GuardianContractBindingV2.tenant_id == tenant_id)
    if ai_system_id:
        query = query.where(
            or_(
                GuardianContractBindingV2.ai_system_id.is_(None),
                GuardianContractBindingV2.ai_system_id == ai_system_id,
            )
        )
    if policy_version_id:
        query = query.where(
            or_(
                GuardianContractBindingV2.policy_version_id.is_(None),
                GuardianContractBindingV2.policy_version_id == policy_version_id,
            )
        )
    rows = db.scalars(query).all()
    rows.sort(
        key=lambda row: (
            str(row.guardian_contract_id),
            str(row.ai_system_id or ""),
            str(row.policy_version_id or ""),
            str(row.id),
        )
    )
    return rows


def get_v2_matrix(
    db: Session,
    *,
    tenant_id: str,
    ai_system_id: str | None = None,
    policy_version_id: str | None = None,
) -> list[dict[str, Any]]:
    contracts = list_v2_contracts(db, tenant_id=tenant_id)
    bindings = list_v2_bindings(
        db,
        tenant_id=tenant_id,
        ai_system_id=ai_system_id,
        policy_version_id=policy_version_id,
    )
    by_contract: dict[str, list[dict[str, Any]]] = {}
    for binding in bindings:
        by_contract.setdefault(binding.guardian_contract_id, []).append(
            {
                "binding_id": binding.id,
                "tenant_id": binding.tenant_id,
                "ai_system_id": binding.ai_system_id,
                "policy_version_id": binding.policy_version_id,
                "enforcement_strength": binding.enforcement_strength,
                "enabled": binding.enabled,
            }
        )

    items: list[dict[str, Any]] = []
    for contract in contracts:
        items.append(
            {
                "guardian_contract_id": contract.id,
                "version": contract.version,
                "name": contract.name,
                "trigger_conditions": contract.trigger_conditions or [],
                "block_conditions": contract.block_conditions or [],
                "mandatory_actions": contract.mandatory_actions or {},
                "escalation_path": contract.escalation_path or {},
                "evidence_requirements": contract.evidence_requirements or {},
                "framework_mappings": contract.framework_mappings or {},
                "canonical_policy": contract.canonical_policy or {},
                "bindings": by_contract.get(contract.id, []),
            }
        )
    return items
