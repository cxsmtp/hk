"""Settings → HTTPS (owners and admins): the certificate Hawk AI serves with, and how (app/services/https_manager.py).
Ported from CxMissionZero's src/routes/https.js.

The routes under /https (/api/https from the browser): the state, a certificate to inspect, upload, put back or
remove, a self-signed one, a certificate request, the mode (http, both, https only), hardening, and the browser's own
check; and under /https/acme a free certificate from Let's Encrypt, got and renewed by this server
(app/services/acme_service.py). Every change is written to the audit log. /.well-known/acme-challenge/<token> answers
Let's Encrypt's check (open: the CA is not signed in).
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Body, Depends, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from sqlalchemy.orm import Session

from app.core.rbac import require_role
from app.core.tenant import TenantContext
from app.db.session import get_db
from app.services import https_runtime
from app.services.acme_service import valid_name
from app.services.audit_service import write_audit_log
from app.services.https_manager import MODE_NAMES, HttpsError

router = APIRouter(tags=["https"])
admin_only = require_role(min_role="admin")
FALLBACK_NAMES = {"environment": "the deployment's certificate", "self-signed": "a self-signed one"}


def _host_of(value: str) -> str:
    host = str(value or "").strip().lower()
    host = re.sub(r"^\[(.*)\](:\d+)?$", r"\1", host)
    host = re.sub(r"^([^:]+):\d+$", r"\1", host)
    return host if host and len(host) < 254 and re.match(r"^[a-z0-9.:*-]+$", host) else ""


def _https_hosts(request: Request, extra: Any = None) -> list[str]:
    """The names people use to reach this server: this page's, the deployment's address (HAWK_HOST, PUBLIC_URL /
    WEB_ORIGIN), and any given."""

    hosts: list[str] = []

    def add(value: Any) -> None:
        host = _host_of(str(value or ""))
        if host and host not in hosts:
            hosts.append(host)

    add(request.headers.get("host"))
    add(os.environ.get("HAWK_HOST"))
    for option in ("PUBLIC_URL", "WEB_ORIGIN"):
        try:
            add(urlsplit(str(os.environ.get(option) or "")).hostname)
        except ValueError:
            pass
    for host in (extra if isinstance(extra, list) else [])[:10]:
        add(host)
    return hosts


def _port(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name) or default).strip())
    except ValueError:
        return default


def _viewing(request: Request, mode: str) -> dict[str, Any]:
    host = request.headers.get("host") or "localhost"
    hostname = _host_of(host) or "localhost"
    if ":" in hostname:
        hostname = f"[{hostname}]"
    https_port = _port("HTTPS_PUBLIC_PORT", 443)
    http_port = _port("HTTP_REDIRECT_PORT", 80)
    return {
        "secure": request.url.scheme == "https",
        "host": host,
        "httpsUrl": f"https://{hostname}{'' if https_port == 443 else f':{https_port}'}",
        # Plain http is on its own port next to HTTPS (Caddy cannot answer both on one port), or on the main port when HTTPS is off.
        "httpUrl": f"http://{host}" if mode == "http" else f"http://{hostname}{'' if http_port == 80 else f':{http_port}'}",
        "httpRedirectPort": http_port,
        "httpsPort": https_port,
    }


def _acme_view(request: Request) -> dict[str, Any]:
    return {
        **https_runtime.acme().status(),
        "suggested": [h for h in _https_hosts(request) if valid_name(h)],
        "fromEnvironment": https_runtime.letsencrypt_domain(),
    }


def _status(request: Request) -> dict[str, Any]:
    m = https_runtime.manager()
    return {
        **m.status(_https_hosts(request)),
        "viewing": _viewing(request, m.mode),
        "acme": _acme_view(request),
    }


def _refusal(error: HttpsError) -> JSONResponse:
    return JSONResponse(status_code=error.status, content=error.body(), headers={"Cache-Control": "no-store"})


def _actor(ctx: TenantContext) -> str:
    return ctx.user.email if ctx.user else "an administrator"


def _audit(db: Session, ctx: TenantContext, *, action: str, reason: str, details: dict[str, Any] | None = None, outcome: str = "changed") -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human" if ctx.user else "system",
        action=action,
        resource_type="https",
        resource_id="https",
        payload={"outcome": outcome, "reason": reason, "actor_id": _actor(ctx), **({"https": details} if details else {})},
    )
    db.commit()


def _body(body: dict[str, Any] | None) -> dict[str, Any]:
    return body if isinstance(body, dict) else {}


@router.get("/https")
def https_status(request: Request, response: Response, ctx: TenantContext = Depends(admin_only)):
    del ctx
    response.headers["Cache-Control"] = "no-store"
    return _status(request)


@router.post("/https/inspect")
def https_inspect(request: Request, body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(admin_only)):
    del ctx
    b = _body(body)
    try:
        return https_runtime.manager().inspect(files=b.get("files"), passphrase=str(b.get("passphrase") or ""), hosts=_https_hosts(request, b.get("hosts")))
    except HttpsError as error:
        return _refusal(error)


@router.post("/https/certificate")
def https_install(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    b = _body(body)
    try:
        report = https_runtime.manager().install(
            files=b.get("files"),
            passphrase=str(b.get("passphrase") or ""),
            hosts=_https_hosts(request, b.get("hosts")),
            confirm=bool(b.get("confirm")),
            by=_actor(ctx),
        )
    except HttpsError as error:
        return _refusal(error)
    s = report["summary"]
    _audit(
        db,
        ctx,
        action="https.certificate.installed",
        reason=f"HTTPS certificate for {s['subject']} put to use (valid until {s['validTo'][:10]}).",
        details={"subject": s["subject"], "names": s["names"], "issuer": s["issuer"], "validTo": s["validTo"], "fingerprint": s["fingerprint"]},
    )
    print(f"[https] Certificate for {s['subject']} put to use by {_actor(ctx)}.", flush=True)
    return {"report": report, "status": _status(request)}


@router.post("/https/certificate/previous")
def https_previous(request: Request, db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    try:
        https_runtime.manager().restore_previous(by=_actor(ctx))
    except HttpsError as error:
        return _refusal(error)
    _audit(db, ctx, action="https.certificate.restored", reason="Previous HTTPS certificate put back.")
    return _status(request)


@router.delete("/https/certificate")
def https_remove(request: Request, confirm: str = "", db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    try:
        fallback = https_runtime.manager().remove_uploaded(confirm=confirm == "1", by=_actor(ctx))
    except HttpsError as error:
        return _refusal(error)
    _audit(
        db,
        ctx,
        action="https.certificate.removed",
        reason=f"Uploaded HTTPS certificate no longer used (now {FALLBACK_NAMES[fallback]}).",
    )
    return _status(request)


@router.post("/https/self-signed")
def https_self_signed(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    names = _https_hosts(request, _body(body).get("names"))
    try:
        https_runtime.manager().self_sign(names=names, by=_actor(ctx))
    except HttpsError as error:
        return _refusal(error)
    _audit(db, ctx, action="https.self_signed.created", reason=f"Self-signed certificate made for {', '.join(names)}.")
    return _status(request)


@router.post("/https/request")
def https_request(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    b = _body(body)
    names = [str(n) for n in b.get("names")][:20] if isinstance(b.get("names"), list) else []
    try:
        csr = https_runtime.manager().create_request(names=names, organisation=str(b.get("organization") or ""), by=_actor(ctx))
    except HttpsError as error:
        return _refusal(error)
    _audit(db, ctx, action="https.request.created", reason=f"Certificate request created for {', '.join(names)}.")
    return {"csr": csr, "status": _status(request)}


@router.get("/https/request.csr")
def https_request_csr(ctx: TenantContext = Depends(admin_only)):
    del ctx
    csr = https_runtime.manager().request_csr()
    if not csr:
        return JSONResponse(status_code=404, content={"error": "No certificate request was made here."})
    return PlainTextResponse(csr, media_type="application/pkcs10", headers={"Content-Disposition": 'attachment; filename="hawk-ai.csr"', "Cache-Control": "no-store"})


@router.post("/https/mode")
def https_mode(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    b = _body(body)
    mode = str(b.get("mode") or "")
    m = https_runtime.manager()
    before = m.mode
    try:
        m.set_mode(mode, secure=request.url.scheme == "https", confirm=bool(b.get("confirm")), by=_actor(ctx))
    except HttpsError as error:
        return _refusal(error)
    if mode != before:
        _audit(db, ctx, action="https.mode.changed", reason=f"Server switched from {MODE_NAMES[before]} to {MODE_NAMES[mode]}.", details={"from": before, "to": mode})
        print(f"[https] {MODE_NAMES[mode]}, switched by {_actor(ctx)}.", flush=True)
    return _status(request)


@router.post("/https/hardening")
def https_hardening(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    b = _body(body)
    hsts = b.get("hsts") if isinstance(b.get("hsts"), dict) else None
    min_version = str(b.get("minVersion")) if b.get("minVersion") else None
    m = https_runtime.manager()
    try:
        m.set_hardening(hsts=hsts, min_version=min_version, by=_actor(ctx))
    except HttpsError as error:
        return _refusal(error)
    s = m.state
    h = s["hsts"]
    _audit(
        db,
        ctx,
        action="https.hardening.changed",
        reason=f"HTTPS hardening: HSTS {'on (' + str(h['maxAge']) + ' s' + (', subdomains' if h['includeSubDomains'] else '') + ')' if h['enabled'] else 'off'}, lowest TLS version {s['minVersion']}.",
        details={"hsts": h, "minVersion": s["minVersion"]},
    )
    return _status(request)


@router.post("/https/browser-check")
def https_browser_check(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(admin_only)):
    b = _body(body)
    https_runtime.manager().record_browser_check(ok=b.get("ok"), url=b.get("url"), by=_actor(ctx))
    return {"ok": True}


# ---- Free certificate from Let's Encrypt (app/services/acme_service.py) ----


@router.get("/https/acme")
def https_acme(request: Request, response: Response, ctx: TenantContext = Depends(admin_only)):
    del ctx
    response.headers["Cache-Control"] = "no-store"
    return _acme_view(request)


@router.post("/https/acme", status_code=202)
def https_acme_start(request: Request, body: dict[str, Any] | None = Body(default=None), db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    b = _body(body)
    service = https_runtime.acme()
    try:
        service.start(
            names=b.get("names"),
            email=b.get("email") or "",
            staging=b.get("staging") is True,
            agree=b.get("agree") is True,
            skip_precheck=b.get("skipPrecheck") is True,
            by=_actor(ctx),
        )
    except HttpsError as error:
        return _refusal(error)
    names = ", ".join((service.status().get("last") or {}).get("names") or [])
    _audit(db, ctx, action="https.letsencrypt.requested", reason=f"Free certificate requested from Let's Encrypt{' (staging)' if b.get('staging') is True else ''} for {names}.")
    return _acme_view(request)


@router.post("/https/acme/renew", status_code=202)
def https_acme_renew(request: Request, db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    try:
        https_runtime.acme().renew(by=_actor(ctx))
    except HttpsError as error:
        return _refusal(error)
    _audit(db, ctx, action="https.letsencrypt.renewal_started", reason="Let's Encrypt certificate renewal started by hand.")
    return _acme_view(request)


@router.delete("/https/acme")
def https_acme_disable(request: Request, db: Session = Depends(get_db), ctx: TenantContext = Depends(admin_only)):
    try:
        https_runtime.acme().disable()
    except HttpsError as error:
        return _refusal(error)
    _audit(
        db,
        ctx,
        action="https.letsencrypt.renewal_disabled",
        reason="Automatic renewal of the Let's Encrypt certificate turned off (the certificate in use stays until it expires or is replaced).",
    )
    return _acme_view(request)


@router.get("/.well-known/acme-challenge/{token}")
def acme_challenge(token: str):
    """Let's Encrypt's check (HTTP-01): answered over plain http in every HTTPS mode (the proxy sends it here)."""

    value = https_runtime.acme().challenge(token)
    return PlainTextResponse(value or "Not found", status_code=200 if value else 404, headers={"Cache-Control": "no-store"})
