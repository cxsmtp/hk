"""Connector API activity: every call a connector makes to an outside service, for Records → Connector API activity
(FTR Command Center's "CxOne API audit", server/activity.js, which records every call made to a customer's Checkmarx
One tenant: on whose behalf, for which account, with its result and time).

What is kept of a call: when, the tenant and the connector it was made for, the method, the host, the path without
its query (a query may carry a token), the status, how long it took, and a short error when it failed. Never a
header, a body or a query string.

Recorded where Hawk's connectors make their calls: the credentialed egress every connector, single sign-on and SIEM
export go through (app/services/outbound_destination_policy.py ``request_with_redirect_validation``), the hosted
discovery sources' HTTP client (app/services/hmair/source_connectors) and the AWS connector's boto3 calls. The tenant
and the connector come from :func:`connector_scope`, which the connector run sets (app/services/monitoring_service.py);
a call made outside one is kept with the connector named by its source and no tenant.

Written in a session of its own, so a call is recorded whether the work that made it is committed or not; recording
never fails the call.
"""

from __future__ import annotations

import contextlib
import contextvars
import datetime as dt
import re
import time
from collections.abc import Iterator
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

KEEP_DAYS = 90
SUMMARY_DAYS = 30

_scope: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar("hawk_connector_scope", default=None)

#: Path segments that look like a secret or a long opaque id (a token in the path): shown as "…".
_OPAQUE = re.compile(r"^[A-Za-z0-9_\-.=+]{40,}$")


@contextlib.contextmanager
def connector_scope(*, tenant_id: str | None, connector: str, connector_id: str | None = None, user_id: str | None = None) -> Iterator[None]:
    """Calls made inside are recorded for this tenant and connector."""

    token = _scope.set({"tenant_id": tenant_id, "connector": connector, "connector_id": connector_id, "user_id": user_id})
    try:
        yield
    finally:
        _scope.reset(token)


def current_scope() -> dict[str, Any] | None:
    return _scope.get()


def safe_path(url: str) -> tuple[str, str]:
    """(host, path) of a URL: the query and fragment dropped, opaque segments hidden, at most 300 characters."""

    try:
        parts = urlsplit(str(url or ""))
        host = (parts.hostname or "").lower()
        path = parts.path or "/"
    except ValueError:
        return "", ""
    path = "/".join("…" if _OPAQUE.match(segment) else segment for segment in path.split("/"))
    return host[:253], path[:300]


def session_factory() -> Any:
    """A database session of the recorder's own (tests point this at their database)."""

    from app.db.session import SessionLocal

    return SessionLocal()


def record_call(method: str, url: str, *, status: int | None, ms: float | None, error: str = "", source: str = "", now: dt.datetime | None = None) -> None:
    """Keep one call. Never raises."""

    try:
        from app.db.models.platform_records import ConnectorCall

        scope = _scope.get() or {}
        host, path = safe_path(url)
        ok = not error and status is not None and status < 400
        row = ConnectorCall(
            tenant_id=scope.get("tenant_id"),
            at=now or dt.datetime.now(dt.timezone.utc),
            connector=str(scope.get("connector") or source or "")[:120],
            connector_id=scope.get("connector_id"),
            user_id=scope.get("user_id"),
            method=str(method or "").upper()[:10],
            host=host,
            path=path,
            status=status,
            ok=ok,
            ms=int(round(ms)) if ms is not None else None,
            error=_short_error(error),
        )
        with session_factory() as db:
            db.add(row)
            db.commit()
    except Exception:  # noqa: BLE001 - recording never fails the call
        return


def _short_error(error: Any) -> str:
    text_value = " ".join(str(error or "").split())
    # A URL in an error may carry its query: dropped.
    text_value = re.sub(r"(https?://[^\s?#]+)\?[^\s]*", r"\1", text_value)
    return text_value[:300]


@contextlib.contextmanager
def timed(method: str, url: str, *, source: str = "") -> Iterator[dict[str, Any]]:
    """Record the call made inside: ``box["status"]`` is read at the end; an exception is recorded as the error."""

    box: dict[str, Any] = {"status": None}
    started = time.perf_counter()
    try:
        yield box
    except Exception as exc:
        record_call(method, url, status=box.get("status"), ms=(time.perf_counter() - started) * 1000, error=f"{type(exc).__name__}: {exc}", source=source)
        raise
    record_call(method, url, status=box.get("status"), ms=(time.perf_counter() - started) * 1000, source=source)


def httpx_hooks(source: str) -> dict[str, list[Any]]:
    """httpx event hooks that record each response (for clients made by a connector)."""

    def on_request(request: Any) -> None:
        request.extensions["hawk_started"] = time.perf_counter()

    def on_response(response: Any) -> None:
        started = response.request.extensions.get("hawk_started")
        record_call(response.request.method, str(response.request.url), status=response.status_code, ms=(time.perf_counter() - started) * 1000 if started else None, source=source)

    return {"request": [on_request], "response": [on_response]}


def boto3_hook(source: str = "aws") -> Any:
    """A botocore ``after-call`` handler: one record per AWS API call."""

    def after_call(http_response: Any = None, parsed: Any = None, model: Any = None, **kwargs: Any) -> None:  # noqa: ARG001
        try:
            status = int(getattr(http_response, "status_code", 0) or 0) or None
            url = str(getattr(http_response, "url", "") or "")
            context = kwargs.get("context") or {}
            started = context.get("hawk_started")
            record_call(getattr(model, "http", {}).get("method", "POST") if model is not None else "POST", url, status=status, ms=(time.perf_counter() - started) * 1000 if started else None, source=source)
        except Exception:  # noqa: BLE001
            return

    return after_call


def boto3_before_hook() -> Any:
    def before_call(context: Any = None, **kwargs: Any) -> None:  # noqa: ARG001
        if isinstance(context, dict):
            context["hawk_started"] = time.perf_counter()

    return before_call


# ---------------------------------------------------------------------------------------------------------------------
# The page (FTR's /api/activity)
# ---------------------------------------------------------------------------------------------------------------------


def _iso(moment: Any) -> str:
    if isinstance(moment, dt.datetime):
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=dt.timezone.utc)
        return moment.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return str(moment or "")


def _parse(value: str, *, end: bool = False) -> dt.datetime:
    text_value = str(value).strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text_value):
        text_value += "T23:59:59.999999+00:00" if end else "T00:00:00+00:00"
    moment = dt.datetime.fromisoformat(text_value.replace("Z", "+00:00"))
    return moment if moment.tzinfo else moment.replace(tzinfo=dt.timezone.utc)


def view(row: Any) -> dict[str, Any]:
    return {
        "at": _iso(row.at),
        "connector": row.connector,
        "connectorId": row.connector_id,
        "method": row.method,
        "host": row.host,
        "path": row.path,
        "status": row.status,
        "ok": bool(row.ok),
        "ms": row.ms,
        "detail": row.error,
    }


def listing(
    db: Session,
    tenant_id: str,
    *,
    connectors: list[str] | None = None,
    hosts: list[str] | None = None,
    outcome: str = "",
    since: str = "",
    until: str = "",
    before: str = "",
    limit: int = 100,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    from app.db.models.platform_records import ConnectorCall

    now = now or dt.datetime.now(dt.timezone.utc)
    base = [ConnectorCall.tenant_id == tenant_id, ConnectorCall.at >= now - dt.timedelta(days=KEEP_DAYS)]
    conditions = list(base)
    if connectors:
        conditions.append(ConnectorCall.connector.in_(connectors))
    if hosts:
        conditions.append(ConnectorCall.host.in_(hosts))
    if outcome == "ok":
        conditions.append(ConnectorCall.ok.is_(True))
    elif outcome == "failed":
        conditions.append(ConnectorCall.ok.is_(False))
    if since:
        conditions.append(ConnectorCall.at >= _parse(since))
    if until:
        conditions.append(ConnectorCall.at <= _parse(until, end=True))
    page_conditions = list(conditions)
    if before:
        page_conditions.append(ConnectorCall.at < _parse(before))
    size = min(500, max(1, int(limit or 100)))
    rows = db.scalars(select(ConnectorCall).where(*page_conditions).order_by(ConnectorCall.at.desc(), ConnectorCall.id.desc()).limit(size + 1)).all()
    window = [ConnectorCall.tenant_id == tenant_id, ConnectorCall.at >= now - dt.timedelta(days=SUMMARY_DAYS)]
    calls, avg_ms = db.execute(select(func.count(), func.avg(ConnectorCall.ms)).where(*window)).one()
    failed = int(db.scalar(select(func.count()).select_from(ConnectorCall).where(*window, ConnectorCall.ok.is_(False))) or 0)
    connector_count = int(db.scalar(select(func.count(func.distinct(ConnectorCall.connector))).where(*window)) or 0)
    host_count = int(db.scalar(select(func.count(func.distinct(ConnectorCall.host))).where(*window)) or 0)
    return {
        "events": [view(r) for r in rows[:size]],
        "more": len(rows) > size,
        "summary": {"calls": int(calls or 0), "avgMs": int(round(float(avg_ms or 0))), "failed": failed, "connectors": connector_count, "hosts": host_count},
        "connectors": sorted({c for (c,) in db.execute(select(ConnectorCall.connector).where(*base).distinct()).all() if c}),
        "hosts": sorted({h for (h,) in db.execute(select(ConnectorCall.host).where(*base).distinct()).all() if h}),
        "keepDays": KEEP_DAYS,
    }


CSV_HEADER = ["When", "Connector", "Method", "Host", "Path", "Status", "ms", "Error"]


def csv_rows(db: Session, tenant_id: str, *, now: dt.datetime | None = None) -> Iterator[list[Any]]:
    from app.db.models.platform_records import ConnectorCall

    now = now or dt.datetime.now(dt.timezone.utc)
    for row in db.scalars(
        select(ConnectorCall).where(ConnectorCall.tenant_id == tenant_id, ConnectorCall.at >= now - dt.timedelta(days=KEEP_DAYS)).order_by(ConnectorCall.at, ConnectorCall.id)
    ):
        yield [_iso(row.at), row.connector, row.method, row.host, row.path, row.status, row.ms, row.error]


def prune(db: Session, *, now: dt.datetime | None = None) -> int:
    from sqlalchemy import delete

    from app.db.models.platform_records import ConnectorCall

    now = now or dt.datetime.now(dt.timezone.utc)
    return int(db.execute(delete(ConnectorCall).where(ConnectorCall.at < now - dt.timedelta(days=KEEP_DAYS)).execution_options(synchronize_session=False)).rowcount or 0)
