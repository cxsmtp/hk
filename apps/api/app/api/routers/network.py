"""Settings → Network & proxy (app/services/network_proxy.py) and the certificates outgoing HTTPS trusts
(app/services/trust_store.py). Ported from CxMissionZero's src/routes/network.js and src/routes/trust.js.

- /network: the proxy in use, what the network team needs to allow (the sheet, also as text), a step-by-step check
  of the way to a service with what is typed, saving (only when the proxy lets the service through) and removing.
- /trust: the certificates added, why a service's certificate is not trusted (and its root, to trust with one click),
  trusting it, an upload, and removing one.

Both apply to the whole installation: owners and admins change them (as Settings → HTTPS). Every change is audited.
A proxy change takes effect when api, worker and beat restart (Hawk runs as several containers, without MZ's launcher
to restart them); a trusted certificate applies at once.
"""

from __future__ import annotations

import datetime as dt
import os
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Body, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_permission
from app.core.tenant import TenantContext
from app.db.models.monitoring import Connector
from app.db.session import get_db
from app.services import network_proxy, trust_store
from app.services.audit_service import write_audit_log

router = APIRouter(tags=["network"])
admin_only = require_permission("network.manage")

CHECK_HINT = "Give the address of a service to check, for example graph.microsoft.com (one of the services your connectors use)."


def _error(status_code: int, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message, "detail": message, **extra})


def _actor(ctx: TenantContext) -> str:
    return ctx.user.email if ctx.user else "an administrator"


def _audit(db: Session, ctx: TenantContext, *, action: str, reason: str, details: dict[str, Any] | None = None) -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action=action,
        resource_type="settings",
        resource_id="network",
        payload={"outcome": "changed", "reason": reason, **(details or {})},
    )


def _host_of(url: str) -> tuple[str, int]:
    try:
        parts = urlsplit(str(url or ""))
        return (parts.hostname or "").lower(), parts.port or 443
    except ValueError:
        return "", 443


def _connector_hosts(db: Session) -> list[dict[str, Any]]:
    """The services the connectors set up here call (every tenant's: the network is the whole installation's)."""

    from app.services.checkmarx_one_service import CHECKMARX_REGIONS
    from app.services.integration_connector_service import PROVIDERS

    out: list[dict[str, Any]] = []
    for c in db.scalars(select(Connector).where(Connector.enabled.is_(True))).all():
        key = c.provider_key or c.connector_type
        provider = PROVIDERS.get(key)
        config = c.config if isinstance(c.config, dict) else {}
        label = provider.display_name if provider else key
        urls = [str(config.get("base_url") or (provider.base_url if provider else "") or "")]
        if key == "checkmarx":
            region = CHECKMARX_REGIONS.get(str(config.get("region") or "us").lower(), CHECKMARX_REGIONS["us"])
            urls = [str(config.get("base_url") or region["api_url"]), str(config.get("iam_url") or region["iam_url"])]
        if key in {"entra_id", "microsoft_365", "outlook", "teams", "onedrive_sharepoint", "office_apps", "microsoft_defender", "power_platform"}:
            urls.append("https://login.microsoftonline.com")
        for url in urls:
            if "{{" in url:
                continue
            host, port = _host_of(url)
            if host:
                out.append({"what": label, "host": host, "port": port})
    return out


def _catalogue() -> list[dict[str, Any]]:
    """Every service Hawk's connectors can call (app/services/integration_connector_service.py, the Checkmarx One
    regions, the AI providers of the brain), for a network team that prepares before connecting."""

    from app.services.checkmarx_one_service import CHECKMARX_REGIONS
    from app.services.integration_connector_service import PROVIDERS

    out: list[dict[str, Any]] = []
    for provider in PROVIDERS.values():
        if not provider.supports_live_pull or provider.auth_mode == "aws_sdk":
            continue
        base = str(provider.base_url or "")
        if not base or "{{" in base:
            continue
        host, port = _host_of(base)
        out.append({"what": provider.display_name, "host": host, "port": port})
    out.append({"what": "Microsoft sign-in (Microsoft connectors)", "host": "login.microsoftonline.com", "port": 443})
    for region in CHECKMARX_REGIONS.values():
        for url in (region["iam_url"], region["api_url"]):
            host, port = _host_of(url)
            out.append({"what": "Checkmarx One", "host": host, "port": port})
    out.append({"what": "AWS (AWS connector)", "host": "cloudtrail.<region>.amazonaws.com, iam.amazonaws.com, s3.amazonaws.com", "port": 443})
    return out


def _sso_hosts() -> list[dict[str, Any]]:
    from app.services import oidc_auth_service

    try:
        rows = oidc_auth_service.providers()
    except Exception:  # noqa: BLE001 - a broken setting is reported on the single sign-on page
        return []
    out = []
    for p in rows:
        host, port = _host_of(p.issuer)
        if host:
            out.append({"host": host, "port": port})
    return out


def _lets_encrypt() -> bool:
    from app.services.state_file import read_state

    try:
        state = read_state(network_proxy.data_dir() / "acme.json", fallback=None)
    except Exception:  # noqa: BLE001
        return False
    return bool(state)


def network_view(db: Session) -> dict[str, Any]:
    proxy = network_proxy.active_proxy()
    smtp_host = str(settings.smtp_host or "").strip()
    backup_mail = {"host": os.environ.get("BACKUP_EMAIL_IMAP_HOST", ""), "port": os.environ.get("BACKUP_EMAIL_IMAP_PORT", "993")} if os.environ.get("BACKUP_EMAIL") else None
    rows = network_proxy.requirements(
        connectors=_connector_hosts(db),
        catalogue=_catalogue(),
        smtp={"host": smtp_host, "port": settings.smtp_port or 587} if smtp_host else None,
        sso=_sso_hosts(),
        lets_encrypt=_lets_encrypt(),
        inbound_port=int(os.environ.get("PORT") or 3000),
        proxy=proxy,
        backup_mail=backup_mail,
    )
    saved = network_proxy.read_network()
    targets = [{"host": c["host"], "port": c["port"]} for c in _connector_hosts(db)]
    return {
        "proxy": {**proxy, "hasPassword": bool(((saved or {}).get("proxy") or {}).get("password"))} if proxy else None,
        "changedAt": (saved or {}).get("changedAt", ""),
        "restart": network_proxy.RESTART,
        "targets": list({t["host"]: t for t in targets}.values()),
        "requirements": rows,
        "text": network_proxy.requirements_text(rows, proxy=proxy),
    }


def _typed_proxy(body: dict[str, Any]) -> dict[str, str] | None:
    """The proxy typed in the form, with the saved password when the same user leaves it blank."""

    if not str(body.get("url") or "").strip():
        return None
    typed = network_proxy.clean_proxy(url=body.get("url"), username=body.get("username"), password=body.get("password"), no_proxy=body.get("noProxy"))
    saved = (network_proxy.read_network() or {}).get("proxy")
    if typed["username"] and not typed["password"] and saved and saved.get("username") == typed["username"] and saved.get("url") == typed["url"]:
        typed["password"] = saved.get("password", "")
    return typed


def _targets(db: Session, typed: Any) -> list[dict[str, Any]]:
    if str(typed or "").strip():
        return [network_proxy.check_target(typed)]
    seen: dict[str, dict[str, Any]] = {}
    for c in _connector_hosts(db):
        seen.setdefault(c["host"], {"host": c["host"], "port": c["port"]})
    return list(seen.values())[:5]


@router.get("/network")
def get_network(ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    del ctx
    return JSONResponse(network_view(db), headers={"Cache-Control": "no-store"})


@router.post("/network/check")
async def check_network(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    """Check the way to a service with the proxy typed (or directly), step by step, before anything is saved."""

    del ctx
    body = body or {}
    try:
        proxy = _typed_proxy(body)
        targets = _targets(db, body.get("target"))
    except network_proxy.NetworkError as error:
        return _error(error.status_code, str(error))
    if not targets:
        return _error(400, CHECK_HINT)
    results = []
    for t in targets:
        results.append(await run_in_threadpool(network_proxy.check_route, proxy=network_proxy.proxy_with_auth(proxy) if proxy else "", host=t["host"], port=t["port"]))
    return {"ok": all(r["ok"] for r in results), "via": proxy["url"] if proxy else "direct", "results": results}


@router.put("/network")
async def save_network(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    """Save the proxy, after the same check: a proxy that cannot be reached, or refuses the service, is not saved."""

    body = body or {}
    try:
        proxy = _typed_proxy(body)
        if proxy is None:
            return _error(400, "Give the proxy as host:port, for example proxy.acme.local:8080.")
        targets = _targets(db, body.get("target"))
    except network_proxy.NetworkError as error:
        return _error(error.status_code, str(error))
    if not targets:
        return _error(400, CHECK_HINT)
    results = []
    for t in targets:
        results.append(await run_in_threadpool(network_proxy.check_route, proxy=network_proxy.proxy_with_auth(proxy), host=t["host"], port=t["port"]))
    blocked = next((r for r in results if any(not s["ok"] and s["step"] in ("proxy", "tunnel") for s in r["steps"])), None)
    if blocked is not None:
        return _error(422, "Not saved: the service could not be reached through this proxy.", results=results)
    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    signing = f" (signing in as {proxy['username']})" if proxy["username"] else ""
    network_proxy.save_network({"proxy": proxy, "changedAt": now, "changedBy": _actor(ctx)})
    _audit(
        db,
        ctx,
        action="settings.network",
        reason=f"Outgoing connections now go through the proxy {proxy['url']}{signing}.",
        details={"url": proxy["url"], "username": proxy["username"], "noProxy": proxy["noProxy"]},
    )
    db.commit()
    return {**network_view(db), "results": results, "restartRequired": True}


@router.delete("/network")
def remove_network(ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    if not network_proxy.read_network():
        return _error(404, "No proxy is set here.")
    network_proxy.save_network(None)
    _audit(db, ctx, action="settings.network", reason="Outgoing connections no longer go through the proxy set in Settings.")
    db.commit()
    return {**network_view(db), "restartRequired": True}


# ---- Trusted certificates -------------------------------------------------------------------------------------------


def _names(certificates: list[dict[str, Any]]) -> str:
    return ", ".join(f'"{c["subject"]}"' for c in certificates)


def _trust_target(body: dict[str, Any]) -> tuple[str, int]:
    host = str(body.get("host") or "").strip().lower()
    try:
        port = int(body.get("port") or 443)
    except (TypeError, ValueError):
        port = 0
    from app.services.outbound_url import blocked_host

    if not network_proxy.SERVER_NAME.match(host) or blocked_host(host) or not 1 <= port <= 65535:
        raise trust_store.TrustError("Give a server name and port, for example graph.microsoft.com and 443.")
    return host, port


@router.get("/trust")
def list_trusted(ctx: TenantContext = Depends(admin_only)):
    del ctx
    return JSONResponse({"certificates": trust_store.store().list()}, headers={"Cache-Control": "no-store"})


@router.post("/trust/diagnose")
async def diagnose(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    """Why a service's certificate is not trusted: a left-out intermediate is completed at once (and audited); a
    company proxy's root is shown, to trust with "Trust and connect"; otherwise an upload is asked for."""

    try:
        host, port = _trust_target(body or {})
        found = await run_in_threadpool(trust_store.store().diagnose, host, port)
    except trust_store.TrustError as error:
        return _error(error.status_code, str(error))
    except network_proxy.StepError as error:
        return _error(502, str(error))
    except OSError as error:
        return _error(502, f"{body.get('host') if body else 'The server'} could not be reached: {error}.")
    if found["status"] == "repaired":
        _audit(db, ctx, action="settings.trust", reason=f"{host} left out its intermediate certificate: fetched {_names(found['added'])} from its issuer, which a trusted root vouches for.", details={"host": host, "port": port, "added": found["added"]})
        db.commit()
    return found


@router.post("/trust/presented")
async def trust_presented(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    """Trust the root a server presents, by the fingerprint the administrator was shown (looked up again here)."""

    body = body or {}
    try:
        host, port = _trust_target(body)
        done = await run_in_threadpool(lambda: trust_store.store().trust_presented(host, port, str(body.get("fingerprint256") or ""), by=_actor(ctx)))
    except trust_store.TrustError as error:
        return _error(error.status_code, str(error))
    except (network_proxy.StepError, OSError) as error:
        return _error(502, str(error))
    if done.get("added"):
        _audit(db, ctx, action="settings.trust", reason=f"Trusted the certificate {host} presents: {_names(done['added'])}.", details={"host": host, "port": port, "added": done["added"]})
        db.commit()
    return {**done, "certificates": trust_store.store().list()}


@router.post("/trust/upload")
async def upload_certificate(body: dict[str, Any] | None = Body(default=None), ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    """Upload certificate authorities; with the server that failed, only those its chain needs are kept."""

    body = body or {}
    data = str(body.get("data") or "")
    if not data.strip():
        return _error(400, "Choose a certificate file (.pem, .crt or .cer).")
    if len(data) > 3_000_000:
        return _error(413, "That file is too large for certificates (3 MB at most).")
    try:
        target = _trust_target(body) if body.get("host") else None
        chain = None
        if target:
            try:
                chain = (await run_in_threadpool(trust_store.inspect, target[0], target[1]))["chain"]
            except Exception:  # noqa: BLE001 - not reachable now: the whole file is looked at
                chain = None
        added = trust_store.store().upload(data, by=_actor(ctx), chain=chain, host=target[0] if target else "")
    except trust_store.TrustError as error:
        return _error(error.status_code, str(error))
    if added:
        _audit(db, ctx, action="settings.trust", reason=f"Trusted uploaded certificate{'' if len(added) == 1 else 's'}: {_names(added)}.", details={"host": target[0] if target else "", "added": added})
        db.commit()
    trusted = None
    if target:
        try:
            now = await run_in_threadpool(lambda: trust_store.store().diagnose(target[0], target[1], repair=False))
            trusted = now["status"] == "trusted"
        except Exception:  # noqa: BLE001
            trusted = None
    return {"added": added, "trusted": trusted, "certificates": trust_store.store().list()}


@router.delete("/trust/{fingerprint}")
def remove_certificate(fingerprint: str, request: Request, ctx: TenantContext = Depends(admin_only), db: Session = Depends(get_db)):
    del request
    removed = trust_store.store().remove(str(fingerprint))
    if removed is None:
        return _error(404, "That certificate is not in the list.")
    _audit(db, ctx, action="settings.trust", reason=f'No longer trusts the certificate "{removed["subject"]}".', details={"removed": removed})
    db.commit()
    return {"certificates": trust_store.store().list()}
