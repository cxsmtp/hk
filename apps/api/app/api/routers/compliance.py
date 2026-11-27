"""Settings → Compliance (/settings/guide/compliance; app/services/compliance_service.py).

- GET /compliance: the controls the software takes part in under DESC ISR v3, the UAE IA Standard and CERT-In's
  directions, each with its status and where its evidence is; the clock; encryption at rest; the settings below.
  Owners, admins and auditors (audit.view).
- PUT /compliance/settings: how long the user activity and connector API activity are kept (180 days at least), the
  data location statement and the incident contact. Kept once for the whole server: its administrators only (the
  owners and admins of the first tenant, app/core/installation.py); recorded in the audit log.
- GET /compliance/incident-report?from=…&to=…: the security events of a time window, for a report to DESC or to
  CERT-In within 6 hours, as JSON with an evidence signature (audit.export); recorded in the audit log.

Framework packs (app/services/compliance_packs):

- GET /compliance/packs: every pack with its counts (audit.view).
- GET /compliance/packs/{id}: one pack, each requirement with its status, controls and record (audit.view).
- GET /compliance/controls: the control registry with each control's status now (audit.view).
- GET /compliance/packs/{id}/evidence?from=…&to=…: the signed evidence bundle (zip) for a window of at most a year,
  30 days by default (audit.export); recorded in the audit log.
- PUT / DELETE /compliance/packs/{id}/requirements/{requirement}/record: record that a requirement is in place (the
  organisation's own process, where its evidence is) or not applicable (settings.manage); recorded in the audit log.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, Query
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.installation import SET_BY_SERVER, is_installation_admin, require_installation_admin
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services import compliance_packs, compliance_service, evidence_signing
from app.services.compliance_packs import evidence as pack_evidence
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


def view(db: Session, *, may_change: bool, tenant_id: str | None = None, read_only_note: str = "") -> dict[str, Any]:
    clock = compliance_service.time_status(db)
    items = compliance_service.controls(db, time_view=clock, tenant_id=tenant_id)
    return {
        "standards": compliance_service.STANDARDS,
        "controls": items,
        "summary": compliance_service.summary(items),
        "clock": clock,
        "encryption": compliance_service.encryption_status(),
        "settings": compliance_service.settings_view(db),
        "dataLocation": compliance_service.data_location(db),
        # The settings (retention, data location, incident contact) and the recommended baseline are the whole
        # server's: only its administrators change them (app/core/installation.py).
        "mayChange": may_change,
        "readOnlyNote": "" if may_change else read_only_note,
    }


@router.get("/compliance")
def get_compliance(ctx: TenantContext = Depends(require_permission("audit.view")), db: Session = Depends(get_db)):
    manages = "settings.manage" in ctx.permissions
    result = view(db, may_change=manages and is_installation_admin(db, ctx), tenant_id=ctx.tenant.id, read_only_note=SET_BY_SERVER if manages else "")
    db.commit()
    return JSONResponse(result, headers=NO_STORE)


@router.put("/compliance/settings")
def put_compliance_settings(
    ctx: TenantContext = Depends(require_installation_admin("settings.manage")),
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
    return JSONResponse(view(db, may_change=True, tenant_id=ctx.tenant.id), headers=NO_STORE)


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


# ---- Framework packs ------------------------------------------------------------------------------------------------


def _pack_refused(error: compliance_packs.PackError) -> JSONResponse:
    return _refused(error.status_code, error.message)


@router.get("/compliance/packs")
def list_packs(ctx: TenantContext = Depends(require_permission("audit.view")), db: Session = Depends(get_db)):
    result = compliance_packs.overview(db, ctx.tenant.id)
    result["mayRecord"] = "settings.manage" in ctx.permissions
    result["mayExport"] = "audit.export" in ctx.permissions
    db.commit()
    return JSONResponse(result, headers=NO_STORE)


@router.get("/compliance/controls")
def list_controls(ctx: TenantContext = Depends(require_permission("audit.view")), db: Session = Depends(get_db)):
    result = compliance_packs.control_registry(db, ctx.tenant.id)
    db.commit()
    return JSONResponse(result, headers=NO_STORE)


@router.get("/compliance/packs/{pack_id}")
def get_pack(pack_id: str, ctx: TenantContext = Depends(require_permission("audit.view")), db: Session = Depends(get_db)):
    try:
        result = compliance_packs.evaluate_pack(db, ctx.tenant.id, pack_id)
    except compliance_packs.PackError as error:
        return _pack_refused(error)
    result["mayRecord"] = "settings.manage" in ctx.permissions
    result["mayExport"] = "audit.export" in ctx.permissions
    db.commit()
    return JSONResponse(result, headers=NO_STORE)


@router.put("/compliance/packs/{pack_id}/requirements/{requirement_id}/record")
def record_requirement(
    pack_id: str,
    requirement_id: str,
    body: Annotated[dict[str, Any] | None, Body()] = None,
    ctx: TenantContext = Depends(require_permission("settings.manage")),
    db: Session = Depends(get_db),
):
    try:
        _, reason = compliance_packs.save_attestation(
            db, tenant_id=ctx.tenant.id, pack_id=pack_id, requirement_id=requirement_id, body=body,
            user_id=ctx.user.id if ctx.user else None, email=ctx.user.email if ctx.user else "",
        )
    except compliance_packs.PackError as error:
        db.rollback()
        return _pack_refused(error)
    _audit(db, ctx, "compliance.pack.recorded", {"outcome": "changed", "reason": reason, "pack": pack_id, "requirement": requirement_id})
    db.commit()
    return get_pack(pack_id, ctx, db)


@router.delete("/compliance/packs/{pack_id}/requirements/{requirement_id}/record")
def remove_requirement_record(pack_id: str, requirement_id: str, ctx: TenantContext = Depends(require_permission("settings.manage")), db: Session = Depends(get_db)):
    try:
        reason = compliance_packs.delete_attestation(db, tenant_id=ctx.tenant.id, pack_id=pack_id, requirement_id=requirement_id)
    except compliance_packs.PackError as error:
        db.rollback()
        return _pack_refused(error)
    _audit(db, ctx, "compliance.pack.record_removed", {"outcome": "changed", "reason": reason, "pack": pack_id, "requirement": requirement_id})
    db.commit()
    return get_pack(pack_id, ctx, db)


@router.get("/compliance/packs/{pack_id}/evidence")
def pack_evidence_bundle(
    pack_id: str,
    since: str = Query(default="", alias="from"),
    until: str = Query(default="", alias="to"),
    ctx: TenantContext = Depends(require_permission("audit.export")),
    db: Session = Depends(get_db),
):
    now = dt.datetime.now(dt.timezone.utc)
    end = _moment(until, end=True) if until else now
    start = _moment(since) if since else now - dt.timedelta(days=30)
    if start is None or end is None:
        return _refused(400, "Give the window as dates (2026-11-26) or times (2026-11-26T08:00:00Z).")
    who = ctx.user.email if ctx.user else "system"
    try:
        data, manifest = pack_evidence.build(db, tenant_id=ctx.tenant.id, pack_id=pack_id, since=start, until=end, generated_by=who)
    except compliance_packs.PackError as error:
        return _pack_refused(error)
    except evidence_signing.EvidenceSigningError as error:
        return _refused(503, f"The evidence could not be signed: {error}")
    signature = manifest[evidence_signing.SIGNATURE_FIELD]
    _audit(
        db,
        ctx,
        "compliance.pack.evidence",
        {
            "outcome": "info",
            "reason": f"Signed evidence for {manifest['pack']['framework']} ({pack_id} {manifest['pack']['version']}) made for {manifest['window']['from']} to {manifest['window']['to']} ({manifest['auditEntries']} audit entries).",
            "pack": pack_id,
            "rows": manifest["auditEntries"],
            "kid": signature["kid"],
            "digest": signature["digest"],
        },
    )
    db.commit()
    stamp = now.strftime("%Y-%m-%dT%H%MZ")
    headers = {
        "Content-Disposition": f'attachment; filename="hawk-{pack_id}-evidence-{stamp}.zip"',
        **NO_STORE,
        evidence_signing.STATUS_HEADER: "signed",
    }
    return Response(data, media_type="application/zip", headers=headers)
