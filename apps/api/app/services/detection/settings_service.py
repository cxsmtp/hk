"""Reading and saving a tenant's detection settings (the detection_settings row) and exact-data-match sets.

Fingerprint values arrive once, are digested with the tenant's salt and dropped: only digests are stored, and no
response, log or audit entry carries a value.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.db.models.detection import DetectionSettings
from app.services.detection import fingerprints as edm
from app.services.detection import profile as profile_module
from app.services.detection.categories import DOCUMENT_CATEGORIES
from app.services.detection.profile import ConfigError, default_config, sanitize_config, utcnow


class DetectionSettingsError(ValueError):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


def _row(db: Session, tenant_id: str, *, create: bool = False) -> DetectionSettings | None:
    row = db.get(DetectionSettings, tenant_id)
    if row is None and create:
        row = DetectionSettings(
            tenant_id=tenant_id, config=default_config(), fingerprint_salt=edm.new_salt(), fingerprints=[], revision=0, updated_by=""
        )
        db.add(row)
    return row


def _sets_view(fingerprints: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [
        {
            "id": item.get("id"),
            "name": item.get("name"),
            "category": item.get("category"),
            "count": len(item.get("digests") or []),
            "enabled": bool(item.get("enabled", True)),
            "created_at": item.get("created_at"),
            "created_by": item.get("created_by"),
        }
        for item in (fingerprints or [])
        if isinstance(item, dict)
    ]


def view(db: Session, tenant_id: str) -> dict[str, Any]:
    row = _row(db, tenant_id)
    config = sanitize_config(row.config) if row is not None else default_config()
    return {
        "config": config,
        "fingerprint_sets": _sets_view(row.fingerprints if row else []),
        "revision": int(row.revision or 0) if row else 0,
        "updated_at": row.updated_at.isoformat() if row and row.updated_at else None,
        "updated_by": (row.updated_by or None) if row else None,
        "defaults": default_config(),
    }


def save_config(db: Session, tenant_id: str, body: Any, *, by: str) -> dict[str, Any]:
    try:
        config = sanitize_config(body)
    except ConfigError as error:
        raise DetectionSettingsError(str(error)) from None
    row = _row(db, tenant_id, create=True)
    if row is None:  # pragma: no cover - created above
        raise DetectionSettingsError("could not create the settings", 500)
    row.config = config
    row.revision = int(row.revision or 0) + 1
    row.updated_at = utcnow()
    row.updated_by = by or ""
    db.flush()
    profile_module.invalidate(tenant_id)
    return view(db, tenant_id)


def add_fingerprint_set(db: Session, tenant_id: str, body: Any, *, by: str) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise DetectionSettingsError("send an object with name and values (a list) or csv (text)")
    name = str(body.get("name") or "").strip()[:80]
    if not name:
        raise DetectionSettingsError("name is required")
    category = str(body.get("category") or "custom").strip()
    if category != "custom" and category not in DOCUMENT_CATEGORIES:
        raise DetectionSettingsError(f"category must be custom or one of {', '.join(DOCUMENT_CATEGORIES)}")
    values: list[str]
    if body.get("csv") is not None:
        if not isinstance(body.get("csv"), str):
            raise DetectionSettingsError("csv must be text")
        column = body.get("column")
        if column is not None and not isinstance(column, (str, int)):
            raise DetectionSettingsError("column must be a header name or a 0-based index")
        try:
            values = edm.values_from_csv(body["csv"], column=column, has_header=body.get("has_header"))
        except (ValueError, IndexError) as error:
            raise DetectionSettingsError(str(error)) from None
    elif isinstance(body.get("values"), list):
        values = [str(v) for v in body["values"] if v is not None]
    else:
        raise DetectionSettingsError("send values (a list) or csv (text)")
    if not values:
        raise DetectionSettingsError("no values to fingerprint")
    row = _row(db, tenant_id, create=True)
    if row is None:  # pragma: no cover - created above
        raise DetectionSettingsError("could not create the settings", 500)
    if not row.fingerprint_salt:
        row.fingerprint_salt = edm.new_salt()
    existing = list(row.fingerprints or [])
    if len(existing) >= edm.MAX_SETS_PER_TENANT:
        raise DetectionSettingsError(f"at most {edm.MAX_SETS_PER_TENANT} fingerprint sets; delete one first", 409)
    try:
        digests, skipped = edm.hash_values(row.fingerprint_salt, values)
    except ValueError as error:
        raise DetectionSettingsError(str(error), 413) from None
    if not digests:
        raise DetectionSettingsError(f"every value was shorter than {edm.MIN_VALUE_CHARS} characters")
    total = sum(len(item.get("digests") or []) for item in existing) + len(digests)
    if total > edm.MAX_VALUES_PER_TENANT:
        raise DetectionSettingsError(f"at most {edm.MAX_VALUES_PER_TENANT} fingerprinted values per tenant", 413)
    set_id = uuid.uuid4().hex[:12]
    existing.append(
        {
            "id": set_id,
            "name": name,
            "category": category,
            "digests": digests,
            "enabled": True,
            "created_at": utcnow().isoformat(),
            "created_by": by or "",
        }
    )
    row.fingerprints = existing
    row.revision = int(row.revision or 0) + 1
    row.updated_at = utcnow()
    row.updated_by = by or ""
    db.flush()
    profile_module.invalidate(tenant_id)
    return {"id": set_id, "name": name, "category": category, "count": len(digests), "skipped": skipped}


def delete_fingerprint_set(db: Session, tenant_id: str, set_id: str, *, by: str) -> bool:
    row = _row(db, tenant_id)
    if row is None:
        return False
    kept = [item for item in (row.fingerprints or []) if str(item.get("id")) != set_id]
    if len(kept) == len(row.fingerprints or []):
        return False
    row.fingerprints = kept
    row.revision = int(row.revision or 0) + 1
    row.updated_at = utcnow()
    row.updated_by = by or ""
    db.flush()
    profile_module.invalidate(tenant_id)
    return True
