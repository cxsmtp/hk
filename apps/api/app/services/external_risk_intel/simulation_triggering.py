from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.simulation import SimulationCatalogEntry


DEFAULT_CONTROL_SIM_MAP: dict[str, list[str]] = {
    "PROMPT_INJECTION_DETECTION": ["SIM-PROMPT-001", "SIM-PROMPT-002", "SIM-PROMPT-004"],
    "MODEL_ACCESS_CONTROL": ["SIM-MODEL-001", "SIM-MODEL-002"],
    "MODEL_OUTPUT_VALIDATION": ["SIM-DATA-005", "SIM-DECISION-001"],
    "TOOL_CALL_VALIDATION": ["SIM-TOOL-001", "SIM-TOOL-002"],
    "AGENT_ACTION_AUTHORIZATION": ["SIM-TOOL-003", "SIM-IAM-001"],
    "RAG_POISONING_DETECTION": ["SIM-RAG-001", "SIM-RAG-002"],
    "AI_IDENTITY_BINDING": ["SIM-IAM-001", "SIM-IAM-004"],
    "TOKEN_SCOPE_ENFORCEMENT": ["SIM-IAM-002"],
    "PRIVILEGE_DRIFT_DETECTION": ["SIM-IAM-003"],
    "SENSITIVE_DATA_DETECTION": ["SIM-DATA-001", "SIM-DATA-003"],
    "PII_EXFILTRATION_PREVENTION": ["SIM-DATA-001", "SIM-DATA-004"],
    "POLICY_ENFORCEMENT_CONTROL": ["SIM-DECISION-002"],
}


def recommend_simulations(
    db: Session,
    *,
    tenant_id: str,
    control_ids: list[str],
    severity: str,
    exploit_status: str,
) -> dict[str, Any]:
    normalized_controls = sorted({str(control_id).strip() for control_id in control_ids if str(control_id).strip()})

    rows = db.scalars(select(SimulationCatalogEntry).where(SimulationCatalogEntry.tenant_id == tenant_id)).all()
    recommended: list[dict[str, Any]] = []

    for row in rows:
        catalog_controls = [str(item).strip() for item in (row.control_ids or []) if str(item).strip()]
        if not set(catalog_controls).intersection(normalized_controls):
            continue
        recommended.append(
            {
                "simulation_id": row.simulation_id,
                "executable_status": row.executable_status,
                "required_executor": row.required_executor,
                "category": row.category,
                "severity": row.severity,
            }
        )

    if not recommended:
        fallback_ids: list[str] = []
        for control_id in normalized_controls:
            fallback_ids.extend(DEFAULT_CONTROL_SIM_MAP.get(control_id, []))
        dedup_fallback = sorted(set(fallback_ids))[:8]
        recommended = [
            {
                "simulation_id": sim_id,
                "executable_status": "not_yet_executable",
                "required_executor": "unresolved",
                "category": "external_risk",
                "severity": "high",
            }
            for sim_id in dedup_fallback
        ]

    priority = "critical" if str(severity).lower() == "critical" or str(exploit_status).lower() == "known_exploited" else "high"
    reason = (
        f"Risk-correlated controls {normalized_controls or ['POLICY_ENFORCEMENT_CONTROL']} "
        f"require validation under exploit_status={exploit_status}."
    )

    return {
        "priority": priority,
        "reason": reason,
        "simulation_ids": [item["simulation_id"] for item in recommended[:10]],
        "details": recommended[:10],
    }
