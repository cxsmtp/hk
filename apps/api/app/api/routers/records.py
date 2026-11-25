"""Records: the audit log, the user activity log and the connector API activity, for the console's Records pages.

- /audit/log: the audit log as FTR Command Center's Audit page shows it (server/routes/diagnostics.js: filters, the
  people and the actions to filter by, "Older entries"), its check (CxMissionZero's GET /api/audit/verify: every
  broken entry named) and its exports (CSV with formulas defused, and JSON Lines with each entry's MAC for a SIEM).
- /activity/log: the user activity log (CxMissionZero's GET /api/activity and its CSV export).
- /connector-activity: the calls Hawk's connectors made (FTR's /api/activity, the CxOne API audit).

Owners, admins and auditors of the tenant read them (MZ's audit.view and audit.export); each sees their own tenant.
"""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.audit import AuditLog
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services import audit_chain, connector_activity, user_activity
from app.services.audit_service import write_audit_log

router = APIRouter(tags=["records"])
readers = require_permission("audit.view")
exporters = require_permission("audit.export")
PAGE = 100


def _iso(moment: Any) -> str:
    return audit_chain.iso(moment).replace(".000000Z", "Z") if moment else ""


def _date(value: str | None, *, end: bool = False) -> dt.datetime | None:
    text_value = str(value or "").strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}", text_value):
        return None
    try:
        if len(text_value) == 10:
            text_value += "T23:59:59.999999+00:00" if end else "T00:00:00+00:00"
        moment = dt.datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


def refused(row: AuditLog) -> bool:
    payload = row.payload if isinstance(row.payload, dict) else {}
    return "refused" in str(row.action) or payload.get("outcome") == "refused"


def _people(db: Session, tenant_id: str) -> dict[str, User]:
    rows = db.scalars(select(User).join(UserTenantRole, UserTenantRole.user_id == User.id).where(UserTenantRole.tenant_id == tenant_id)).all()
    return {u.id: u for u in rows}


def _actor(row: AuditLog, people: dict[str, User], db: Session) -> dict[str, str] | None:
    if not row.actor_user_id:
        return None
    user = people.get(row.actor_user_id) or db.get(User, row.actor_user_id)
    if user is None:
        return {"name": "", "email": ""}
    return {"name": user.full_name or user.email, "email": user.email}


def _details(row: AuditLog) -> dict[str, Any]:
    payload = dict(row.payload) if isinstance(row.payload, dict) else {}
    payload.pop("ip", None)
    return payload


def _event(row: AuditLog, people: dict[str, User], db: Session) -> dict[str, Any]:
    payload = row.payload if isinstance(row.payload, dict) else {}
    action = str(row.action)
    if refused(row) and "refused" not in action:
        action = f"refused: {action}"
    return {
        "id": row.id,
        "seq": row.seq,
        "at": _iso(row.created_at),
        "actor": _actor(row, people, db),
        "action": action,
        "target": f"{row.resource_type} {row.resource_id}".strip(),
        "details": _details(row),
        "ip": str(payload.get("ip") or ""),
        "mac": row.mac,
    }


def _audit_query(ctx: TenantContext, db: Session, *, q: str, who: str, what: str, since: str, until: str, outcome: str) -> Any:
    query = select(AuditLog).where(AuditLog.tenant_id == ctx.tenant.id)
    if who:
        user = db.scalar(select(User).where(func.lower(User.email) == who.strip().lower()))
        query = query.where(AuditLog.actor_user_id == (user.id if user else "-"))
    if what:
        query = query.where(or_(AuditLog.action == what, AuditLog.action.like(f"{what}.%")))
    start, end = _date(since), _date(until, end=True)
    if start:
        query = query.where(AuditLog.created_at >= start)
    if end:
        query = query.where(AuditLog.created_at <= end)
    if outcome == "refused":
        query = query.where(or_(AuditLog.action.like("%refused%"), cast(AuditLog.payload, String).like('%"outcome": "refused"%'), cast(AuditLog.payload, String).like('%"outcome":"refused"%')))
    elif outcome == "done":
        query = query.where(~AuditLog.action.like("%refused%"), ~cast(AuditLog.payload, String).like('%"outcome": "refused"%'), ~cast(AuditLog.payload, String).like('%"outcome":"refused"%'))
    needle = str(q or "").strip().lower()[:200]
    if needle:
        like = f"%{needle}%"
        query = query.where(
            or_(
                func.lower(AuditLog.action).like(like),
                func.lower(AuditLog.resource_type).like(like),
                func.lower(AuditLog.resource_id).like(like),
                func.lower(cast(AuditLog.payload, String)).like(like),
            )
        )
    return query


@router.get("/audit/log")
def audit_log(
    q: str = "",
    who: str = "",
    what: str = "",
    since: str = Query(default="", alias="from"),
    until: str = Query(default="", alias="to"),
    outcome: str = "",
    before: str = "",
    ctx: TenantContext = Depends(readers),
    db: Session = Depends(get_db),
):
    """Newest first, 100 at a time; ``before`` (the time of the last one shown) for older entries."""

    query = _audit_query(ctx, db, q=q, who=who, what=what, since=since, until=until, outcome=outcome)
    edge = _date(before)
    if edge:
        query = query.where(AuditLog.created_at < edge)
    rows = db.scalars(query.order_by(AuditLog.created_at.desc(), AuditLog.seq.desc()).limit(PAGE + 1)).all()
    people = _people(db, ctx.tenant.id)
    actions = sorted(a for (a,) in db.execute(select(AuditLog.action).where(AuditLog.tenant_id == ctx.tenant.id).distinct().limit(1000)).all() if a)
    return {
        "events": [_event(r, people, db) for r in rows[:PAGE]],
        "more": len(rows) > PAGE,
        "people": sorted(({"name": u.full_name or u.email, "email": u.email} for u in people.values()), key=lambda p: p["email"]),
        "actions": actions,
    }


@router.get("/audit/log/verify")
def verify_audit_log(ctx: TenantContext = Depends(readers), db: Session = Depends(get_db)):
    """Walk this tenant's chain: any edited, removed or reordered entry is found, and named."""

    result = audit_chain.verify(db, audit_chain.chain_of(ctx.tenant.id))
    first = result["problems"][0] if result["problems"] else None
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="audit.verify",
        resource_type="audit",
        resource_id="chain",
        payload={
            "outcome": "info",
            "reason": f"Audit log verified intact ({result['entries']} entries)." if result["ok"] else f"Audit log verification found {len(result['problems'])} problem(s).",
            "verify": {"ok": result["ok"], "entries": result["entries"], "problems": result["problems"][:10]},
        },
    )
    db.commit()
    return {
        **result,
        # FTR's page reads these.
        "events": result["entries"],
        "brokenAt": first["seq"] if first else None,
        "why": first["problem"].rstrip(".") if first else "",
    }


CSV_HEADER = ["When", "Who", "Email", "Action", "On", "Details", "Address", "Seq", "MAC"]


def _export(ctx: TenantContext, db: Session, fmt: str, filters: dict[str, str]) -> Response:
    rows = db.scalars(_audit_query(ctx, db, **filters).order_by(AuditLog.created_at, AuditLog.seq)).all()
    people = _people(db, ctx.tenant.id)
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action="audit.export",
        resource_type="audit",
        resource_id=fmt,
        payload={"outcome": "info", "reason": f"Exported the audit log ({len(rows)} entries, {fmt.upper()}).", "rows": len(rows), "filters": {k: v for k, v in filters.items() if v}},
    )
    db.commit()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    if fmt == "jsonl":
        import json

        body = "\n".join([json.dumps({"notice": audit_chain.EXPORT_NOTICE}), *(audit_chain.jsonl_entry(r) for r in rows if r.mac)]) + "\n"
        return Response(body, media_type="application/x-ndjson; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.jsonl"', "Cache-Control": "no-store"})
    out = []
    for r in rows:
        event = _event(r, people, db)
        actor = event["actor"] or {}
        out.append([event["at"], actor.get("name", ""), actor.get("email", ""), event["action"], event["target"], event["details"], event["ip"], r.seq, r.mac])
    body = audit_chain.to_csv(CSV_HEADER, out, notice=audit_chain.EXPORT_NOTICE)
    return Response(body, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="audit-{stamp}.csv"', "Cache-Control": "no-store"})


@router.get("/audit/log/export.csv")
def export_audit_csv(q: str = "", who: str = "", what: str = "", since: str = Query(default="", alias="from"), until: str = Query(default="", alias="to"), outcome: str = "", ctx: TenantContext = Depends(exporters), db: Session = Depends(get_db)):
    return _export(ctx, db, "csv", {"q": q, "who": who, "what": what, "since": since, "until": until, "outcome": outcome})


@router.get("/audit/log/export.jsonl")
def export_audit_jsonl(q: str = "", who: str = "", what: str = "", since: str = Query(default="", alias="from"), until: str = Query(default="", alias="to"), outcome: str = "", ctx: TenantContext = Depends(exporters), db: Session = Depends(get_db)):
    return _export(ctx, db, "jsonl", {"q": q, "who": who, "what": what, "since": since, "until": until, "outcome": outcome})


# ---- The user activity log ------------------------------------------------------------------------------------------


@router.get("/activity/log")
def activity_log(
    limit: int = 50,
    offset: int = 0,
    user: str = "",
    q: str = "",
    kind: str = "",
    since: str = Query(default="", alias="from"),
    until: str = Query(default="", alias="to"),
    ctx: TenantContext = Depends(readers),
    db: Session = Depends(get_db),
):
    return user_activity.listing(db, ctx.tenant.id, limit=limit, offset=offset, user=user, q=q, kind=kind, since=since, until=until)


@router.get("/activity/log/export.csv")
def export_activity_csv(ctx: TenantContext = Depends(exporters), db: Session = Depends(get_db)):
    body = audit_chain.to_csv(user_activity.CSV_COLUMNS, user_activity.csv_rows(db, ctx.tenant.id))
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    return Response(body, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="activity-{stamp}.csv"', "Cache-Control": "no-store"})


# ---- Connector API activity -----------------------------------------------------------------------------------------


@router.get("/connector-activity")
def connector_calls(
    connector: str = "",
    host: str = "",
    outcome: str = "",
    since: str = Query(default="", alias="from"),
    until: str = Query(default="", alias="to"),
    before: str = "",
    ctx: TenantContext = Depends(readers),
    db: Session = Depends(get_db),
):
    split = lambda v: [x for x in str(v or "").split(",") if x]  # noqa: E731
    return connector_activity.listing(db, ctx.tenant.id, connectors=split(connector), hosts=split(host), outcome=outcome, since=since, until=until, before=before)


@router.get("/connector-activity/export.csv")
def export_connector_calls(ctx: TenantContext = Depends(exporters), db: Session = Depends(get_db)):
    body = audit_chain.to_csv(connector_activity.CSV_HEADER, connector_activity.csv_rows(db, ctx.tenant.id))
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    return Response(body, media_type="text/csv; charset=utf-8", headers={"Content-Disposition": f'attachment; filename="connector-activity-{stamp}.csv"', "Cache-Control": "no-store"})
