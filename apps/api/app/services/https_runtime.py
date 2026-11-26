"""The API's one HTTPS manager and Let's Encrypt service, started with the API (app/main.py), and the audit entries
for what they do on their own. Ported from the HTTPS parts of CxMissionZero's src/server.js."""

from __future__ import annotations

import logging
import os
import re
import threading
from typing import Any

from app.core.config import settings
from app.services.acme_service import RENEW_DAYS, AcmeService, clean_names
from app.services.https_manager import HttpsError, HttpsManager
from app.services.tls_service import describe_certificate

log = logging.getLogger("hawk.https")

_lock = threading.Lock()
_manager: HttpsManager | None = None
_acme: AcmeService | None = None
_TRUE = re.compile(r"^(1|true|yes|on)$", re.I)


def manager() -> HttpsManager:
    global _manager
    with _lock:
        if _manager is None:
            _manager = HttpsManager(data_dir=settings.hawk_data_dir)
        return _manager


def acme() -> AcmeService:
    global _acme
    m = manager()
    with _lock:
        if _acme is None:
            # ACME_DIRECTORY_URL: another ACME certificate authority (or a test one) instead of Let's Encrypt.
            directory = str(os.environ.get("ACME_DIRECTORY_URL") or "").strip()
            _acme = AcmeService(data_dir=settings.hawk_data_dir, https=m, directories={"production": directory, "staging": directory} if directory else None)
            _acme.on_event(_audit_acme_event)
        return _acme


def reset_for_tests(new_manager: HttpsManager | None = None, new_acme: AcmeService | None = None) -> None:
    global _manager, _acme
    with _lock:
        _manager, _acme = new_manager, new_acme
    if new_acme is not None:
        new_acme.on_event(_audit_acme_event)


def letsencrypt_domain() -> str:
    return str(os.environ.get("LETSENCRYPT_DOMAIN") or "").strip()


def audit_system(*, action: str, outcome: str, reason: str, actor: str, details: dict[str, Any] | None = None) -> None:
    """An audit entry for something the server did by itself (Let's Encrypt, the command line)."""

    from app.db.session import SessionLocal
    from app.services.audit_service import write_audit_log

    try:
        with SessionLocal() as db:
            write_audit_log(
                db,
                tenant_id=None,
                actor_user_id=None,
                actor_type="system",
                action=action,
                resource_type="https",
                resource_id="https",
                payload={"outcome": outcome, "reason": reason, "actor_id": actor, **({"https": details} if details else {})},
            )
            db.commit()
    except Exception as error:  # noqa: BLE001 - the audit log being unreachable never stops HTTPS working
        log.warning("! [https] Could not write the audit entry (%s): %s", reason, error)


def _audit_acme_event(event: dict[str, Any]) -> None:
    names = ", ".join(event["names"])
    staging = " (staging: not trusted by browsers)" if event.get("staging") else ""
    actor = event.get("by") or "Let's Encrypt"
    if event["kind"] == "issued":
        audit_system(
            action="https.letsencrypt.issued",
            outcome="changed",
            reason=f"Let's Encrypt certificate for {names} put to use{staging}, valid until {event['validTo'][:10]}.",
            actor=actor,
            details={"letsEncrypt": {"names": event["names"], "staging": event.get("staging"), "validTo": event["validTo"]}},
        )
        m = manager()
        try:
            # A trusted certificate is in: deployed with LETSENCRYPT_DOMAIN, the server goes HTTPS only by itself; from
            # the Settings page, http and https side by side (switch to HTTPS only there).
            if event.get("by") == "LETSENCRYPT_DOMAIN" and not event.get("staging"):
                before = m.mode
                m.set_mode("https", system=True, by="Let's Encrypt")
                if before != "https":
                    audit_system(action="https.mode.changed", outcome="changed", reason="Server switched to HTTPS only (Let's Encrypt, LETSENCRYPT_DOMAIN).", actor="Let's Encrypt", details={"from": before, "to": "https"})
            elif m.mode == "http":
                m.set_mode("both", by="Let's Encrypt")
                audit_system(action="https.mode.changed", outcome="changed", reason="Server switched from HTTP only to HTTP and HTTPS side by side (Let's Encrypt).", actor="Let's Encrypt", details={"from": "http", "to": "both"})
        except HttpsError as error:
            log.warning("! [https] %s", error)
    else:
        audit_system(
            action="https.letsencrypt.failed",
            outcome="failed",
            reason=f"Let's Encrypt certificate for {names} not obtained{staging}: {event.get('error')}",
            actor=actor,
            details={"letsEncrypt": {"names": event["names"], "staging": event.get("staging"), "error": event.get("error")}},
        )


def start() -> None:
    """At API start: check the certificate in use (a bad one stops the start, never falling back to plain http), hand
    the configuration to the proxy, watch for changes, and get or renew the Let's Encrypt certificate."""

    m = manager()
    try:
        m.check()
    except Exception as error:
        raise RuntimeError(f"HTTPS is not set up correctly: {error}") from error
    mode = m.mode
    print(f"[https] {'HTTP only' if mode == 'http' else 'HTTPS only: plain http is redirected to https.' if mode == 'https' else 'HTTP and HTTPS side by side. Switch to HTTPS only under Settings → HTTPS once it works.'}", flush=True)
    pem = m.context() if mode != "http" else None
    if pem is not None:
        described = m.describe()
        source = {"uploaded": "uploaded under Settings → HTTPS", "environment": "from the deployment's options"}.get(described["source"], "")
        print(f"[https] {'Self-signed certificate (browsers warn until it is trusted)' if described['selfSigned'] else f'Certificate ({source})'}: {describe_certificate(pem)}", flush=True)
        if described["selfSigned"]:
            print(
                "! [https] Self-signed: traffic is encrypted, but browsers warn. For production upload your certificate under Settings → HTTPS "
                "(or give TLS_CERT_FILE and TLS_KEY_FILE), or set LETSENCRYPT_DOMAIN. See /settings/guide/https.",
                flush=True,
            )
    m.watch()
    service = acme()
    domain = letsencrypt_domain()
    if domain:
        try:
            names = clean_names(domain)
            s = service.status()
            issued = s.get("issued") or {}
            current = issued and not issued.get("staging") and all(n in (issued.get("names") or []) for n in names) and (s.get("daysLeft") or 0) > RENEW_DAYS
            if current:
                print(f"[https] Let's Encrypt certificate for {', '.join(names)} in use until {issued['validTo'][:10]}; renewed by itself.", flush=True)
            else:
                print(f"[https] Getting a Let's Encrypt certificate for {', '.join(names)} (LETSENCRYPT_DOMAIN)…", flush=True)
                service.start(
                    names=names,
                    email=os.environ.get("LETSENCRYPT_EMAIL") or "",
                    staging=bool(_TRUE.match(str(os.environ.get("LETSENCRYPT_STAGING") or ""))),
                    skip_precheck=bool(_TRUE.match(str(os.environ.get("LETSENCRYPT_SKIP_CHECK") or ""))),
                    agree=True,
                    by="LETSENCRYPT_DOMAIN",
                )
        except HttpsError as error:
            print(f"! [https] LETSENCRYPT_DOMAIN: {error}", flush=True)
    service.start_renewal()


def stop() -> None:
    if _manager is not None:
        _manager.stop()
    if _acme is not None:
        _acme.stop()
