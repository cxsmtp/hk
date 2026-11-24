from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.observability import get_correlation_id
from app.db.models.audit import AuditLog
from app.services.privacy_sanitizer import sanitize_privacy_payload


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
    return entry
