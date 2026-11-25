"""Settings → General, Branding, Email (SMTP) and About, and what the Settings menu needs, ported from FTR Command
Center's server/routes/branding.js and server/routes/email.js (CC-01.116.00), with CxMissionZero's tested-send rule.

- GET /settings/me: the permissions of the person signed in, so the Settings menu shows only what they may open
  (FTR's settingsNav filters by can(…)).
- GET /settings/general: the server address and the host names this server answers to, as set when it started.
- GET /branding, /branding/logo, /branding/icon: open to anyone (the sign-in page shows them, as FTR's). PUT
  /settings/branding: saved as it changes; everything is checked first, so a refused change leaves the last good one.
- GET/PUT /settings/smtp, POST /settings/smtp/test and /settings/smtp/send-test: the one email server Hawk AI sends
  through (app/services/mailer.py). Saved as typed and tested at once: settings that fail give way to the last ones
  that worked. Nothing is sent for sign-in, people, support or hands-off until the settings in force were tested.
- GET /settings/about: the version, the licence (the activation), the terms of use and the version log (CHANGELOG.md,
  in the API image), and third-party notices when the image carries them.

Everything but /settings/me, /settings/about and the branding images needs settings.manage (Owners and Admins).
"""

from __future__ import annotations

from email.utils import parseaddr
from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.rbac import require_permission
from app.core.tenant import TenantContext, require_tenant
from app.db.session import get_db
from app.services import account_security, branding, mailer, password_reset_service
from app.services.audit_service import write_audit_log
from app.version import APP_VERSION, PACKAGE_VERSION, VERSION_FILE

router = APIRouter(tags=["settings"])
SettingsContext = Annotated[TenantContext, Depends(require_permission("settings.manage"))]
NO_STORE = {"Cache-Control": "no-store"}
#: Third-party notices, when the image carries them (beside VERSION and CHANGELOG.md).
NOTICE_FILES = ("THIRD_PARTY_NOTICES", "THIRD_PARTY_NOTICES.txt", "NOTICE", "NOTICE.txt")


def _refused(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message, "detail": message}, headers=NO_STORE)


def _audit(db: Session, ctx: TenantContext, action: str, target: str, payload: dict[str, Any]) -> None:
    write_audit_log(
        db,
        tenant_id=ctx.tenant.id,
        actor_user_id=ctx.user.id if ctx.user else None,
        actor_type="human",
        action=action,
        resource_type="settings",
        resource_id=(target or "-")[:128],
        payload=payload,
    )


def _organisation(db: Session) -> str:
    from app.services import terms_service

    try:
        return terms_service.organisation_name(db)
    except Exception:  # noqa: BLE001 - a name is never worth an error
        return ""


# ---- The Settings menu ----------------------------------------------------------------------------------------------


@router.get("/settings/me")
def settings_me(ctx: TenantContext = Depends(require_tenant)):
    return JSONResponse({"role": ctx.role_key, "permissions": sorted(ctx.permissions)}, headers=NO_STORE)


# ---- General --------------------------------------------------------------------------------------------------------


@router.get("/settings/general")
def general(ctx: SettingsContext):
    del ctx
    hosts = [h.strip() for h in str(settings.trusted_hosts or "").split(",") if h.strip()]
    return JSONResponse(
        {
            "serverAddress": password_reset_service.link_base(),
            "webOrigin": str(settings.web_origin or ""),
            "trustedHosts": hosts,
        },
        headers=NO_STORE,
    )


# ---- Branding -------------------------------------------------------------------------------------------------------


@router.get("/branding")
def get_branding(db: Session = Depends(get_db)):
    return JSONResponse(branding.public_view(branding.load(), _organisation(db)), headers=NO_STORE)


def _image(key: str) -> Response:
    found = branding.image(key)
    if found is None:
        return _refused(404, "No logo is set." if key == "logo" else "No browser icon is set.")
    data, kind = found
    return Response(content=data, media_type=kind, headers=branding.IMAGE_HEADERS)


@router.get("/branding/logo")
def branding_logo():
    return _image("logo")


@router.get("/branding/icon")
def branding_icon():
    return _image("icon")


@router.put("/settings/branding")
def put_branding(ctx: SettingsContext, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    body = body if isinstance(body, dict) else {}
    try:
        after, changed = branding.merge(branding.load(), body)
    except branding.BrandingError as error:
        return _refused(error.status_code, error.message)
    branding.save(after)
    _audit(db, ctx, "settings.branding", ", ".join(changed), {"changed": changed})
    db.commit()
    return JSONResponse(branding.public_view(after, _organisation(db)), headers=NO_STORE)


# ---- Email (SMTP) ---------------------------------------------------------------------------------------------------


def smtp_view(db: Session) -> dict[str, Any]:
    from app.api.routers.sign_in import password_reset_ready

    smtp = mailer.current()
    saved = mailer.read_saved()
    row = account_security.policy(db)
    return {
        "smtp": mailer.public_smtp(smtp),
        "source": mailer.source(),
        "verified": mailer.verified(db, smtp),
        "verifiedAt": saved.get("verifiedAt") if mailer.verified(db, smtp) else None,
        "passwordReset": row.password_reset,
        "reset": password_reset_ready(db),
        "publicUrl": password_reset_service.link_base(),
    }


@router.get("/settings/smtp")
def get_smtp(ctx: SettingsContext, db: Session = Depends(get_db)):
    del ctx
    view = smtp_view(db)
    db.commit()
    return JSONResponse(view, headers=NO_STORE)


@router.put("/settings/smtp")
async def put_smtp(ctx: SettingsContext, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    body = body if isinstance(body, dict) else {}
    incoming = body.get("smtp") if isinstance(body.get("smtp"), dict) else None
    changed: list[str] = []
    if incoming is not None:
        try:
            next_smtp = mailer.merge_smtp(mailer.current(), incoming)
        except mailer.MailError as error:
            return _refused(400, str(error))
        mailer.save_smtp(next_smtp)
        changed = [k for k in incoming if k != "password"] + (["password"] if incoming.get("password") else [])
    # Saved as typed, then tested at once: settings that do not work give way to the last ones that did (FTR).
    if body.get("test") is True and incoming is not None and mailer.current().host:
        smtp = mailer.current()
        try:
            await run_in_threadpool(mailer.test_connection, smtp)
        except mailer.MailError as error:
            good = mailer.put_back_good()
            if good is not None:
                if mailer.configured(good):
                    account_security.policy(db).smtp_verified = mailer.fingerprint(good)
                _audit(db, ctx, "settings.smtp.rollback", good.host, {"error": str(error)})
                db.commit()
                return _refused(409, f"{error} The last email settings that worked are back.")
            # These settings were just seen not to work: nothing goes out with them until a test passes.
            account_security.policy(db).smtp_verified = ""
            _audit(db, ctx, "settings.smtp", smtp.host, {"tested": False, "error": str(error)})
            db.commit()
            return _refused(400, f"Saved, but the test failed: {error}")
        mailer.mark_verified(db, smtp)
    if "passwordReset" in body:
        wanted = str(body.get("passwordReset") or "")
        if wanted not in password_reset_service.RESET_POLICIES:
            return _refused(400, "Choose who may reset a forgotten password by email.")
        account_security.policy(db).password_reset = wanted
        changed.append("passwordReset")
    _audit(db, ctx, "settings.smtp", mailer.current().host, {"changed": changed})
    db.commit()
    return JSONResponse(smtp_view(db), headers=NO_STORE)


@router.post("/settings/smtp/test")
async def test_smtp(ctx: SettingsContext, db: Session = Depends(get_db)):
    smtp = mailer.current()
    try:
        await run_in_threadpool(mailer.test_connection, smtp)
    except mailer.MailError as error:
        _audit(db, ctx, "settings.smtp.test", smtp.host, {"ok": False, "error": str(error)})
        db.commit()
        return _refused(400, str(error))
    mailer.mark_verified(db, smtp)
    _audit(db, ctx, "settings.smtp.test", smtp.host, {"ok": True})
    db.commit()
    signed = " and signed in" if smtp.signs_in else ""
    return JSONResponse({**smtp_view(db), "message": f"Connected to {smtp.host}:{smtp.port}{signed}. Email can be sent."}, headers=NO_STORE)


@router.post("/settings/smtp/send-test")
async def send_test_smtp(ctx: SettingsContext, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    body = body if isinstance(body, dict) else {}
    to = mailer.plain(body.get("to")).lower() or (str(ctx.user.email).lower() if ctx.user else "")
    if not mailer.EMAIL.match(to) or parseaddr(to)[1] != to:
        return _refused(400, "That is not an email address.")
    smtp = mailer.current()
    if not mailer.configured(smtp):
        return _refused(400, "Set up the email server first: a mail server and a From address.")
    name = mailer.brand_name()
    message = mailer.system_email(
        subject=f"{name}: test message",
        lines=[f"This is a test message from {name}.", "The email server is working: password reset links, welcome emails, support cases and hands-off emails can be sent."],
    )
    try:
        await run_in_threadpool(mailer.send, message, to, smtp=smtp)
    except mailer.MailError as error:
        _audit(db, ctx, "settings.smtp.sendTest", to, {"ok": False, "error": str(error)})
        db.commit()
        return _refused(400, str(error))
    # A test email that went out proves these settings as well as a connection test (MZ's isVerified).
    mailer.mark_verified(db, smtp)
    _audit(db, ctx, "settings.smtp.sendTest", to, {"ok": True})
    db.commit()
    return JSONResponse({"message": f"A test message went to {to}."}, headers=NO_STORE)


@router.delete("/settings/smtp")
def forget_smtp(ctx: SettingsContext, db: Session = Depends(get_db)):
    """Back to the environment's settings (SMTP_*): the saved ones, and their password, are removed."""

    mailer.forget_saved()
    _audit(db, ctx, "settings.smtp.forgotten", "-", {})
    db.commit()
    return JSONResponse(smtp_view(db), headers=NO_STORE)


# ---- About ----------------------------------------------------------------------------------------------------------


def _read(name: str, limit: int = 2_000_000) -> str:
    try:
        return (VERSION_FILE.parent / name).read_text(encoding="utf-8")[:limit]
    except OSError:
        return ""


@router.get("/settings/about")
def about(ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    from app.services import activation_service, terms_service

    product = activation_service.load_store(db).product()
    try:
        terms = terms_service.current()
        terms_version = terms.version
    except OSError:
        terms_version = ""
    org = terms_service.organisation(db)
    accepted = bool(ctx.user and org is not None and terms_service.accepted_by(db, ctx.user.id, org))
    mine = terms_service.user_acceptance(db, ctx.user.id) if ctx.user else None
    at = mine.accepted_at if mine else (org.accepted_at if org is not None and org.everyone else None)
    notices = next(((name, text) for name in NOTICE_FILES if (text := _read(name))), None)
    view = {
        "appName": branding.app_name(),
        "version": PACKAGE_VERSION,
        "versionLabel": APP_VERSION,
        "licence": {
            "active": product["active"],
            "until": product["until"],
            "daysLeft": product["daysLeft"],
            "activation": product["activation"],
            "message": product["message"],
        },
        "terms": {"version": terms_version, "accepted": accepted, "at": at.isoformat() if at else None},
        "organisationName": branding.load().get("organisationName") or _organisation(db),
        "changelog": _read("CHANGELOG.md"),
        "notices": {"name": notices[0], "text": notices[1]} if notices else None,
        "canUpdate": "system.update" in ctx.permissions,
    }
    db.commit()
    return JSONResponse(view, headers=NO_STORE)
