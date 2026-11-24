from __future__ import annotations

from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models.tenant import Tenant


PLATFORM_MODE_DISCOVERY = "discovery"
PLATFORM_MODE_ENFORCE = "enforce"
PLATFORM_MODES = {PLATFORM_MODE_DISCOVERY, PLATFORM_MODE_ENFORCE}

CRITICAL_RISK_TIERS = {"CRITICAL", "RESTRICTED", "PROHIBITED"}
CRITICAL_THREAT_TYPES = {"sensitive_data_leakage", "ai_identity_misuse", "action_auth_abuse"}


def normalize_platform_mode(value: str | None, *, fallback: str | None = None) -> str:
    default_mode = str(fallback or settings.platform_mode_default or PLATFORM_MODE_ENFORCE).strip().lower()
    if default_mode not in PLATFORM_MODES:
        default_mode = PLATFORM_MODE_ENFORCE

    mode = str(value or "").strip().lower()
    if mode in PLATFORM_MODES:
        return mode
    return default_mode


def get_tenant_platform_mode(db: Session, *, tenant_id: str) -> str:
    row = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if row is None:
        return normalize_platform_mode(None)
    return normalize_platform_mode(row.platform_mode)


def set_tenant_platform_mode(db: Session, *, tenant_id: str, platform_mode: str) -> Tenant:
    row = db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if row is None:
        raise ValueError("Tenant not found")
    row.platform_mode = normalize_platform_mode(platform_mode)
    db.flush()
    return row


def is_explicitly_critical(
    *,
    risk_tier: str | None,
    threat_types: Iterable[str] | None = None,
    severity_hint: str | None = None,
    reason_hint: str | None = None,
) -> bool:
    risk = str(risk_tier or "").strip().upper()
    if risk in CRITICAL_RISK_TIERS:
        return True

    severity = str(severity_hint or "").strip().lower()
    if severity == "critical":
        return True

    threat_set = {str(item).strip().lower() for item in (threat_types or []) if str(item).strip()}
    if threat_set.intersection(CRITICAL_THREAT_TYPES):
        return True

    reason = str(reason_hint or "").strip().lower()
    if "critical" in reason or "system_kill_switch" in reason:
        return True

    return False
