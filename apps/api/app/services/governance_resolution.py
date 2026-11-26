from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.ai_system import AISystem


APPROVED_STATES = {"APPROVED", "ACTIVE", "LIVE"}
# PENDING_APPROVAL / PENDING_REAPPROVAL: an approval was asked for, or a one-time or time-bound approval was used up,
# ran out or was revoked (app/services/ai_system_approval_service.py). Neither is approved.
PROPOSED_STATES = {"PROPOSED", "PENDING", "DRAFT", "REVIEW", "PENDING_REVIEW", "PENDING_APPROVAL", "PENDING_REAPPROVAL"}

#: Where a session remembers the AI systems whose one-time approval it consumed: the rest of that same governed use
#: (the checks after the first, in the same request) still sees them approved (app/services/ai_system_approval_service.py).
ONE_TIME_IN_USE_KEY = "ai_system_one_time_approval_in_use"
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


def _as_utc(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str) and value.strip():
        try:
            moment = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment.astimezone(timezone.utc)


def approval_has_lapsed(ai_system: AISystem, *, now: datetime | None = None) -> bool:
    """Whether the AI system's standing approval (metadata ``approval``) is time-bound and its time is up, or was used
    up, revoked or replaced, even before the scheduled check has moved the system to pending re-approval."""

    metadata = ai_system.metadata_json if isinstance(ai_system.metadata_json, dict) else {}
    approval = metadata.get("approval")
    if not isinstance(approval, dict):
        return False
    if str(approval.get("state") or "active").strip().lower() != "active":
        return True
    if str(approval.get("scope") or "").strip().lower() != "time_bound":
        return False
    expires_at = _as_utc(approval.get("expires_at"))
    if expires_at is None:
        # A time-bound approval without a readable end is not trusted.
        return True
    return expires_at <= (now or datetime.now(timezone.utc))


def one_time_approval_in_use(db: Session | None, ai_system: AISystem) -> bool:
    """Whether this session consumed the system's one-time approval for the governed use it is handling now."""

    info = getattr(db, "info", None) if db is not None else None
    in_use = info.get(ONE_TIME_IN_USE_KEY) if isinstance(info, dict) else None
    if not isinstance(in_use, dict) or ai_system.id not in in_use:
        return False
    metadata = ai_system.metadata_json if isinstance(ai_system.metadata_json, dict) else {}
    approval = metadata.get("approval")
    return isinstance(approval, dict) and approval.get("grant_id") == in_use.get(ai_system.id)


def ai_system_is_approved(ai_system: AISystem, *, db: Session | None = None, now: datetime | None = None) -> bool:
    """The governance reading of one AI system: approved, and its approval not lapsed."""

    if one_time_approval_in_use(db, ai_system):
        return True
    status = _status_from_raw_state(_raw_state_from_ai_system(ai_system))
    return status == "APPROVED" and not approval_has_lapsed(ai_system, now=now)


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
    lapsed = False
    if one_time_approval_in_use(db, ai_system):
        # The governed use that consumed a one-time approval runs to its end.
        status = "APPROVED"
    elif status == "APPROVED" and approval_has_lapsed(ai_system):
        status = "PROPOSED"
        lapsed = True

    if status == "REJECTED":
        enforcement_mode = "block"
        reason = "governance_state_rejected"
    elif status == "PROPOSED":
        enforcement_mode = "strict" if settings.governance_strict_mode else "monitor"
        reason = "approval_lapsed" if lapsed else "governance_state_proposed"
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
