from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.core.observability import get_correlation_id
from app.db.models.audit import AuditLog
from app.services.privacy_sanitizer import sanitize_privacy_payload

#: Every audit record also makes one log line (app/core/log_config.py): what was done, to what, by whom, never the
#: record's payload. People, roles, sign-in, licence, backups, HTTPS and settings changes all go through here.
logger = logging.getLogger("app.audit")

#: Per-call records (one or more for each gateway, telemetry or runtime call): DEBUG, so the log is not flooded.
_HIGH_VOLUME_PREFIXES = (
    "gateway.",
    "llm_gateway.",
    "telemetry.",
    "runtime.",
    "runtime_control.",
    "runtime_intelligence.",
    "endpoint.",
    "extension.",
    "hmair.",
    "discovery.",
    "shadow_ai.",
    "tools.",
    # Sign-in events have their own line, with the address (app/api/routers/auth.py).
    "auth.sign_in",
)
_REFUSAL_WORDS = ("refused", "denied", "blocked", "failed", "fail_closed", "rejected", "locked")


def _outcome(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("outcome", "final_decision", "decision", "status"):
        value = payload.get(key)
        if isinstance(value, str) and 0 < len(value) <= 40:
            return value
    return None


def _log_audit_entry(
    *,
    tenant_id: str | None,
    actor_user_id: str | None,
    actor_type: str,
    action: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any] | None,
) -> None:
    try:
        from app.core.log_config import mask_email

        action_text = str(action or "")
        if action_text.startswith(_HIGH_VOLUME_PREFIXES):
            level = logging.DEBUG
        elif any(word in action_text for word in _REFUSAL_WORDS):
            level = logging.WARNING
        else:
            level = logging.INFO
        if not logger.isEnabledFor(level):
            return
        fields: dict[str, Any] = {
            "audit_action": action_text,
            "resource_type": resource_type,
            "resource_id": mask_email(str(resource_id or "")[:128]),
            "actor_type": actor_type,
        }
        if tenant_id:
            fields["tenant_id"] = tenant_id
        if actor_user_id:
            fields["actor_user_id"] = actor_user_id
        outcome = _outcome(payload)
        if outcome:
            fields["outcome"] = outcome
        logger.log(level, "Audit: %s %s", action_text, resource_type, extra=fields)
    except Exception:  # noqa: BLE001 - the log line never stands in the way of the audit record
        pass


def write_audit_log(
    db: Session,
    *,
    tenant_id: str | None,
    actor_user_id: str | None,
    actor_type: str,
    action: str,
    resource_type: str,
    resource_id: str,
    payload: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        tenant_id=tenant_id,
        correlation_id=correlation_id or get_correlation_id(),
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=sanitize_privacy_payload(payload or {}),
    )
    db.add(entry)
    db.flush()
    _log_audit_entry(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        actor_type=actor_type,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        payload=payload,
    )
    return entry
