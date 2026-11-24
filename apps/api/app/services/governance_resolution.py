from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.ai_system import AISystem


APPROVED_STATES = {"APPROVED", "ACTIVE", "LIVE"}
PROPOSED_STATES = {"PROPOSED", "PENDING", "DRAFT", "REVIEW", "PENDING_REVIEW"}
REJECTED_STATES = {"REJECTED", "BLOCKED", "PROHIBITED", "DENIED", "RETIRED", "RESTRICTED"}
LEGACY_NEUTRAL_STATES = {"DRAFT", "PENDING", "REVIEW", "PENDING_REVIEW", "PAUSED"}


def _normalize_risk_tier(value: str | None) -> str:
    normalized = str(value or "").strip().upper()
    return normalized or "HIGH"


def _raw_state_from_ai_system(ai_system: AISystem) -> str:
    metadata = ai_system.metadata_json if isinstance(ai_system.metadata_json, dict) else {}
    governance_state = str(metadata.get("governance_state") or "").strip().upper()
    lifecycle_state = str(metadata.get("lifecycle_state") or "").strip().upper()
    compliance_state = str(metadata.get("compliance_state") or "").strip().upper()
    ownership_state = str(metadata.get("ownership_state") or "").strip().upper()
    status_value = str(ai_system.status or "").strip().upper()
    if compliance_state == "NON_COMPLIANT" or ownership_state in {"UNKNOWN", "MISSING"}:
        return "REVIEW"
    if governance_state:
        return governance_state
    if lifecycle_state:
        return lifecycle_state
    if status_value and status_value not in LEGACY_NEUTRAL_STATES:
        return status_value
    # Missing explicit governance state must not silently authorize an AI system.
    return "UNKNOWN"


def _status_from_raw_state(raw_state: str) -> str:
    if raw_state in APPROVED_STATES:
        return "APPROVED"
    if raw_state in PROPOSED_STATES:
        return "PROPOSED"
    if raw_state in REJECTED_STATES:
        return "REJECTED"
    return "UNKNOWN"


def resolve_ai_system_status(ai_system_id: str | None, context: dict[str, Any]) -> dict[str, str]:
    db: Session | None = context.get("db")
    tenant_id = str(context.get("tenant_id") or "").strip()
    source_hint = str(context.get("source_hint") or "").strip().lower()

    if not ai_system_id:
        return {
            "status": "UNKNOWN",
            "risk_tier": "HIGH",
            "enforcement_mode": ("block" if settings.governance_strict_mode else "monitor"),
            "reason": "ai_system_id_missing",
            "source": "shadow_discovery",
        }

    if db is None or not tenant_id:
        return {
            "status": "UNKNOWN",
            "risk_tier": "HIGH",
            "enforcement_mode": ("block" if settings.governance_strict_mode else "monitor"),
            "reason": "governance_context_missing",
            "source": "shadow_discovery",
        }

    ai_system = db.scalar(
        select(AISystem).where(
            AISystem.id == ai_system_id,
            AISystem.tenant_id == tenant_id,
        )
    )
    if ai_system is None:
        return {
            "status": "UNKNOWN",
            "risk_tier": "HIGH",
            "enforcement_mode": ("block" if settings.governance_strict_mode else "monitor"),
            "reason": "ai_system_not_registered",
            "source": "shadow_discovery" if source_hint != "trust_center" else "trust_center",
        }

    raw_state = _raw_state_from_ai_system(ai_system)
    status = _status_from_raw_state(raw_state)
    risk_tier = _normalize_risk_tier(ai_system.risk_tier)

    if status == "REJECTED":
        enforcement_mode = "block"
        reason = "governance_state_rejected"
    elif status == "PROPOSED":
        enforcement_mode = "strict" if settings.governance_strict_mode else "monitor"
        reason = "governance_state_proposed"
    elif status == "APPROVED":
        enforcement_mode = "strict"
        reason = "governance_state_approved"
    else:
        enforcement_mode = "block" if settings.governance_strict_mode else "monitor"
        reason = "governance_state_unknown"
        risk_tier = "HIGH"

    return {
        "status": status,
        "risk_tier": risk_tier,
        "enforcement_mode": enforcement_mode,
        "reason": reason,
        "source": "trust_center",
    }
