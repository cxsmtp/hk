"""Settings → Compliance (/settings/guide/compliance; app/services/compliance_service.py).

- GET /compliance: the controls the software takes part in under DESC ISR v3, the UAE IA Standard and CERT-In's
  directions, each with its status and where its evidence is; the clock; encryption at rest; the settings below.
  Owners, admins and auditors (audit.view).
- PUT /compliance/settings: how long the user activity and connector API activity are kept (180 days at least), the
  data location statement and the incident contact. Owners and admins (settings.manage); recorded in the audit log.
- GET /compliance/incident-report?from=…&to=…: the security events of a time window, for a report to DESC or to
  CERT-In within 6 hours, as JSON with an evidence signature (audit.export); recorded in the audit log.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services import compliance_service, evidence_signing
from app.services.audit_service import write_audit_log

router = APIRouter(tags=["compliance"])
NO_STORE = {"Cache-Control": "no-store"}
#: An incident report covers at most this many days.
MAX_WINDOW_DAYS = 31


def _refused(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message, "detail": message}, headers=NO_STORE)


def _audit(db: Session, ctx: TenantContext, action: str, payload: dict[str, Any]) -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action=action,
        resource_type="compliance",
        resource_id="settings",
        payload=payload,
    )


def view(db: Session, *, may_change: bool) -> dict[str, Any]:
    clock = compliance_service.time_status(db)
    items = compliance_service.controls(db, time_view=clock)
    return {
        "standards": compliance_service.STANDARDS,
        "controls": items,
        "summary": compliance_service.summary(items),
        "clock": clock,
        "encryption": compliance_service.encryption_status(),
        "settings": compliance_service.settings_view(db),
        "dataLocation": compliance_service.data_location(db),
        "mayChange": may_change,
    }


@router.get("/compliance")
def get_compliance(ctx: TenantContext = Depends(require_permission("audit.view")), db: Session = Depends(get_db)):
    result = view(db, may_change="settings.manage" in ctx.permissions)
    db.commit()
    return JSONResponse(result, headers=NO_STORE)


@router.put("/compliance/settings")
def put_compliance_settings(
    ctx: TenantContext = Depends(require_permission("settings.manage")),
    body: Annotated[dict[str, Any] | None, Body()] = None,
    db: Session = Depends(get_db),
):
    values, problem = compliance_service.clean_settings(body or {})
    if problem:
        return _refused(400, problem)
    row = compliance_service.policy(db)
    names = {
        "activity_retention_days": "User activity kept (days)",
        "connector_retention_days": "Connector API activity kept (days)",
        "data_location": "Data location",
        "incident_contact": "Incident contact",
    }
    changes = []
    for column, value in values.items():
        before = getattr(row, column)
        if before != value:
            changes.append(f"{names[column]}: {before or '—'} → {value or '—'}.")
            setattr(row, column, value)
    for reason in changes:
        _audit(db, ctx, "compliance.settings.changed", {"outcome": "info", "reason": reason})
    db.commit()
    return JSONResponse(view(db, may_change=True), headers=NO_STORE)


def _moment(value: str, *, end: bool = False) -> dt.datetime | None:
    text_value = str(value or "").strip()
    if not text_value:
        return None
    try:
        if len(text_value) == 10:
            text_value += "T23:59:59.999999+00:00" if end else "T00:00:00+00:00"
        moment = dt.datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


@router.get("/compliance/incident-report")
def incident_report(
    since: str = Query(default="", alias="from"),
    until: str = Query(default="", alias="to"),
    ctx: TenantContext = Depends(require_permission("audit.export")),
    db: Session = Depends(get_db),
):
    now = dt.datetime.now(dt.timezone.utc)
    end = _moment(until, end=True) if until else now
    start = _moment(since) if since else now - dt.timedelta(hours=24)
    if start is None or end is None:
        return _refused(400, "Give the window as dates (2026-11-26) or times (2026-11-26T08:00:00Z).")
    if start >= end:
        return _refused(400, "The window must start before it ends.")
    if end - start > dt.timedelta(days=MAX_WINDOW_DAYS):
        return _refused(400, f"An incident report covers at most {MAX_WINDOW_DAYS} days: export the audit log for longer.")
    who = ctx.user.email if ctx.user else "system"
    report = compliance_service.incident_report(db, tenant_id=ctx.tenant.id, since=start, until=end, generated_by=who)
    _audit(
        db,
        ctx,
        "compliance.incident_report",
        {"outcome": "info", "reason": f"Incident report made for {report['window']['from']} to {report['window']['to']} ({len(report['entries'])} entries).", "rows": len(report["entries"])},
    )
    db.commit()
    data = (json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n").encode("utf-8")
    stamp = now.strftime("%Y-%m-%dT%H%MZ")
    headers = {
        "Content-Disposition": f'attachment; filename="hawk-incident-report-{stamp}.json"',
        **NO_STORE,
        **evidence_signing.service().header_for(data, artifact="incident_report.json"),
    }
    return Response(data, media_type="application/json; charset=utf-8", headers=headers)
