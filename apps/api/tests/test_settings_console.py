"""Settings → General, Branding, Email (SMTP) and About (app/api/routers/settings_console.py), ported from FTR Command
Center; the one mailer both the sign-in emails and the backups go through (app/services/mailer.py); the self-check's
look at every connector that has a health call; support emails to everyone holding support.manage; and the hands-off
routes' permission."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.routers import hands_off as hands_off_router
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.monitoring import Connector
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import branding, iam_service, integration_connector_service, mailer
from app.services.auth_service import issue_tokens
from app.services.self_check import SelfCheck

PASSWORD = "correct-Horse-2026"
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 64
SVG = b'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>'


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    folder = tmp_path / "data"
    folder.mkdir()
    monkeypatch.setattr(settings, "hawk_data_dir", str(folder))
    monkeypatch.setattr(settings, "web_origin", "https://hawk.example.test")
    for name in ("smtp_host", "smtp_user", "smtp_pass", "smtp_from"):
        monkeypatch.setattr(settings, name, "")
    for name in ("SMTP_HOST", "SMTP_PASSWORD", "SMTP_PASS_FILE", "SMTP_FROM_ADDRESS"):
        monkeypatch.delenv(name, raising=False)
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'settings.sqlite3'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    # Nothing reaches a mail server: what would be sent, and the connection tests, are recorded here.
    world: dict = {"sent": [], "tests": [], "fail": None, "batches": []}

    def fake_test(smtp=None):
        world["tests"].append(smtp or mailer.current())
        if world["fail"]:
            raise mailer.MailError(world["fail"])

    class FakeClient:
        def __init__(self, smtp):
            self.smtp = smtp

        def send_message(self, message, from_addr=None, to_addrs=None):
            world["sent"].append({"smtp": self.smtp, "to": list(to_addrs or []), "subject": str(message["Subject"]), "from": str(message["From"]), "message": message})
            return {}

        def noop(self):
            return None

        def quit(self):
            return None

        def close(self):
            return None

    monkeypatch.setattr(mailer, "test_connection", fake_test)
    monkeypatch.setattr(mailer, "_connect", lambda smtp: FakeClient(smtp))
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield {"client": client, "db": factory, "world": world, "dir": folder}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def member(env, email: str, role: str = "viewer") -> dict:
    with env["db"]() as db:
        t = db.scalar(select(Tenant).where(Tenant.slug == "acme"))
        if t is None:
            t = Tenant(name="Acme", slug="acme", is_active=True)
            db.add(t)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0].title(), hashed_password=get_password_hash(PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=t.id, role=role))
        db.flush()
        tokens = issue_tokens(db, user=user, tenant_id=t.id, role=role)
        db.commit()
        return {"id": user.id, "tenant": t.id, "h": {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": t.id}}


SMTP = {"host": "smtp.acme.test", "port": 587, "secure": False, "requireAuth": True, "rejectUnauthorized": True, "user": "hawk@acme.test", "password": "s3cret-pass", "fromName": "Hawk AI", "fromAddress": "hawk@acme.test"}


# ---- Who may ---------------------------------------------------------------------------------------------------------


def test_settings_need_settings_manage_and_the_menu_learns_the_permissions(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    viewer = member(env, "viewer@acme.test", "viewer")
    me = c.get("/settings/me", headers=viewer["h"]).json()
    assert me["role"] == "viewer" and "settings.manage" not in me["permissions"] and "dashboard.view" in me["permissions"]
    assert "settings.manage" in c.get("/settings/me", headers=admin["h"]).json()["permissions"]
    for method, path in (("GET", "/settings/general"), ("GET", "/settings/smtp"), ("PUT", "/settings/smtp"), ("PUT", "/settings/branding"), ("POST", "/settings/smtp/test"), ("POST", "/settings/smtp/send-test"), ("DELETE", "/settings/smtp")):
        assert c.request(method, path, headers=viewer["h"], **({} if method in ("GET", "DELETE") else {"json": {}})).status_code == 403, path
        assert c.request(method, path).status_code in (401, 403), path
    # About is for everyone signed in (FTR: whoever sees Settings, and the menu's foot for the others).
    assert c.get("/settings/about", headers=viewer["h"]).status_code == 200
    general = c.get("/settings/general", headers=admin["h"]).json()
    assert general["serverAddress"] == "https://hawk.example.test" and "testserver" in general["trustedHosts"]


def test_hands_off_routes_check_a_permission_not_a_role():
    for route in hands_off_router.router.routes:
        if route.path.startswith("/hands-off/link"):
            continue
        held = [getattr(dep.call, "permissions", None) for dep in route.dependant.dependencies]
        assert ("settings.manage",) in held, route.path


# ---- Branding ----------------------------------------------------------------------------------------------------------


def test_branding_is_kept_on_the_server_checked_and_open_to_every_page(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    first = c.get("/branding").json()
    assert first["appName"] == "Hawk AI" and first["logo"] is None and first["limits"] == {"logo": 200 * 1024, "icon": 100 * 1024}
    saved = c.put("/settings/branding", headers=admin["h"], json={"appName": "Acme Guard", "tagline": "AI controls", "organisationName": "Acme Bank", "mode": "light", "logo": {"upload": f"data:image/png;base64,{b64(PNG)}"}})
    assert saved.status_code == 200, saved.text
    view = c.get("/branding").json()
    assert (view["appName"], view["tagline"], view["organisationName"], view["mode"]) == ("Acme Guard", "AI controls", "Acme Bank", "light")
    assert view["logo"].startswith("/branding/logo?v=") and view["logoBytes"] == len(PNG)
    logo = c.get("/branding/logo")
    assert logo.status_code == 200 and logo.content == PNG and logo.headers["content-type"] == "image/png"
    assert "sandbox" in logo.headers["content-security-policy"] and logo.headers["x-content-type-options"] == "nosniff"
    assert c.get("/branding/icon").status_code == 404
    # Kept in the data folder, for the whole installation.
    kept = json.loads((env["dir"] / branding.FILE_NAME).read_text())
    assert kept["appName"] == "Acme Guard" and kept["logo"]["type"] == "image/png"
    # An SVG icon is taken, and served so it runs nothing.
    assert c.put("/settings/branding", headers=admin["h"], json={"icon": {"upload": b64(SVG)}}).status_code == 200
    assert c.get("/branding/icon").headers["content-type"] == "image/svg+xml"
    # Emails carry the product's name.
    message = mailer.system_email(subject="S", lines=["one"])
    assert "Acme Guard" in message.get_body(("html",)).get_content()


def test_branding_limits_refuse_and_keep_the_last_good(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    c.put("/settings/branding", headers=admin["h"], json={"appName": "Acme Guard"})
    too_big = c.put("/settings/branding", headers=admin["h"], json={"appName": "Changed", "logo": {"upload": b64(PNG + b"\0" * (200 * 1024))}})
    assert too_big.status_code == 413 and "at most 200 KB" in too_big.json()["error"]
    icon = c.put("/settings/branding", headers=admin["h"], json={"icon": {"upload": b64(PNG + b"\0" * (100 * 1024))}})
    assert icon.status_code == 413 and "at most 100 KB" in icon.json()["error"]
    assert c.put("/settings/branding", headers=admin["h"], json={"icon": {"upload": b64(PNG + b"\0" * (90 * 1024))}}).status_code == 200
    assert c.put("/settings/branding", headers=admin["h"], json={"logo": {"upload": b64(b"GIF89a not ours")}}).status_code == 415
    assert c.put("/settings/branding", headers=admin["h"], json={"logo": {"url": "https://example.test/logo.png"}}).status_code == 400
    assert c.put("/settings/branding", headers=admin["h"], json={"mode": "neon"}).status_code == 400
    assert c.put("/settings/branding", headers=admin["h"], json={"accent": "red"}).status_code == 400
    assert c.put("/settings/branding", headers=admin["h"], json={"organisationName": "  "}).status_code == 400
    # Nothing refused was kept: the name from before the refused change stays.
    assert c.get("/branding").json()["appName"] == "Acme Guard"
    # Removing the icon.
    assert c.put("/settings/branding", headers=admin["h"], json={"icon": None}).json()["icon"] is None


# ---- Email (SMTP) ---------------------------------------------------------------------------------------------------


def test_email_settings_are_saved_on_the_server_with_the_password_encrypted(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    empty = c.get("/settings/smtp", headers=admin["h"]).json()
    assert empty["smtp"]["host"] == "" and empty["source"] == "" and not empty["verified"]
    saved = c.put("/settings/smtp", headers=admin["h"], json={"smtp": SMTP, "passwordReset": "not-admins"})
    assert saved.status_code == 200, saved.text
    view = saved.json()
    assert view["source"] == "settings" and view["smtp"]["passwordSet"] and "password" not in view["smtp"] and view["passwordReset"] == "not-admins"
    assert not view["verified"]  # saved, but not tested: nothing is sent yet
    raw = (env["dir"] / mailer.FILE_NAME).read_text()
    assert "s3cret-pass" not in raw and "smtp.acme.test" in raw
    assert mailer.current().password == "s3cret-pass" and mailer.current().host == "smtp.acme.test"
    # A password left empty keeps the one kept; a new host forgets it.
    c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"fromName": "Acme"}})
    assert mailer.current().password == "s3cret-pass"
    c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"host": "smtp.other.test"}})
    assert mailer.current().password == ""
    # Checked: mail ports only, a host name, STARTTLS ports without implicit TLS, a From address.
    assert c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"port": 6379}}).status_code == 400
    assert c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"host": "smtp acme"}}).status_code == 400
    assert c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"secure": True, "port": 587}}).status_code == 400
    assert c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"fromAddress": "nope"}}).status_code == 400
    # Forgotten: back to the environment's.
    assert c.delete("/settings/smtp", headers=admin["h"]).json()["source"] == ""
    assert not (env["dir"] / mailer.FILE_NAME).exists()


def test_saved_as_typed_and_tested_at_once_the_last_good_settings_come_back(env):
    c = env["client"]
    world = env["world"]
    admin = member(env, "admin@acme.test", "admin")
    tested = c.put("/settings/smtp", headers=admin["h"], json={"smtp": SMTP, "test": True})
    assert tested.status_code == 200 and tested.json()["verified"] and tested.json()["verifiedAt"]
    assert world["tests"][-1].host == "smtp.acme.test"
    # A change that does not work gives way to the last one that did, still tested.
    world["fail"] = "The server rejected that username and password."
    rolled = c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"user": "wrong@acme.test", "password": "nope-nope"}, "test": True})
    assert rolled.status_code == 409 and "The last email settings that worked are back." in rolled.json()["error"]
    view = c.get("/settings/smtp", headers=admin["h"]).json()
    assert view["smtp"]["user"] == "hawk@acme.test" and view["verified"] and mailer.current().password == "s3cret-pass"
    # With no settings that worked before: saved, but the test failed, and nothing is sent.
    c.delete("/settings/smtp", headers=admin["h"])
    first = c.put("/settings/smtp", headers=admin["h"], json={"smtp": SMTP, "test": True})
    assert first.status_code == 400 and first.json()["error"].startswith("Saved, but the test failed")
    assert not c.get("/settings/smtp", headers=admin["h"]).json()["verified"]
    # Test connection, then it may send.
    world["fail"] = None
    ok = c.post("/settings/smtp/test", headers=admin["h"])
    assert ok.status_code == 200 and ok.json()["verified"] and "signed in" in ok.json()["message"]


def test_nothing_goes_out_for_sign_in_until_tested_and_a_test_email_opens_the_gate(env):
    c = env["client"]
    world = env["world"]
    admin = member(env, "admin@acme.test", "admin")
    c.put("/settings/smtp", headers=admin["h"], json={"smtp": SMTP})
    view = c.get("/settings/smtp", headers=admin["h"]).json()
    assert not view["reset"]["ready"] and any("Email (SMTP)" in m for m in view["reset"]["missing"])
    assert c.post("/settings/smtp/send-test", headers=admin["h"], json={"to": "not an address"}).status_code == 400
    sent = c.post("/settings/smtp/send-test", headers=admin["h"], json={})
    assert sent.status_code == 200 and sent.json()["message"] == "A test message went to admin@acme.test."
    assert world["sent"][-1]["to"] == ["admin@acme.test"] and world["sent"][-1]["smtp"].host == "smtp.acme.test"
    assert '"Hawk AI" <hawk@acme.test>' == world["sent"][-1]["from"] or world["sent"][-1]["from"] == "Hawk AI <hawk@acme.test>"
    view = c.get("/settings/smtp", headers=admin["h"]).json()
    assert view["verified"] and view["reset"]["ready"]
    # Changing any setting asks for a new test.
    c.put("/settings/smtp", headers=admin["h"], json={"smtp": {"port": 2525}})
    assert not c.get("/settings/smtp", headers=admin["h"]).json()["verified"]


# ---- One mailer for both callers ---------------------------------------------------------------------------------------


def test_sign_in_and_backups_send_through_the_one_mailer_and_its_saved_settings(env, tmp_path, monkeypatch):
    world = env["world"]
    # Nothing saved: the environment's SMTP_* (the sign-in settings and the backups' extra names alike).
    monkeypatch.setattr(settings, "smtp_host", "smtp.env.test")
    monkeypatch.setattr(settings, "smtp_user", "robot@env.test")
    monkeypatch.setenv("SMTP_REJECT_UNAUTHORIZED", "false")
    assert mailer.source() == "environment" and mailer.current().host == "smtp.env.test" and not mailer.current().reject_unauthorized
    assert mailer.smtp_settings().from_address == "robot@env.test"
    mailer.send(mailer.system_email(subject="Reset", lines=["x"]), "pat@acme.test")
    assert world["sent"][-1]["smtp"].host == "smtp.env.test"
    # Saved under Settings → Email (SMTP): both callers use it.
    mailer.save_smtp(mailer.merge_smtp(None, SMTP))
    mailer.send(mailer.system_email(subject="Reset", lines=["x"]), "pat@acme.test")
    assert world["sent"][-1]["smtp"].host == "smtp.acme.test" and world["sent"][-1]["to"] == ["pat@acme.test"]
    result = mailer.send_mail(["backups@acme.test", "ops@acme.test"], subject="Hawk AI backup", text="t", attachments=[("b.hkbackup", b"sealed", "application/octet-stream")])
    assert result == {"accepted": ["backups@acme.test", "ops@acme.test"], "rejected": []}
    last = world["sent"][-1]
    assert last["smtp"].host == "smtp.acme.test" and last["to"] == ["backups@acme.test", "ops@acme.test"]
    assert [p.get_filename() for p in last["message"].iter_attachments()] == ["b.hkbackup"]
    # The backups see a mail server whether it is saved here or set in the environment.
    assert mailer.smtp_settings({}) is not None  # saved wins, whatever the environment says
    mailer.forget_saved()
    assert mailer.smtp_settings({}) is None
    # The password never shows in an error.
    secret = mailer.Smtp(host="h", user="u", password="pw-123")
    assert mailer.redact_secrets(f"no {base64.b64encode(b'pw-123').decode()} pw-123", secret) == "no [hidden] [hidden]"


def test_the_old_backup_mailer_is_gone():
    root = Path(__file__).resolve().parents[1] / "app" / "services"
    assert not (root / "backup_mailer.py").exists()


# ---- About -------------------------------------------------------------------------------------------------------------


def test_about_has_the_version_licence_terms_and_version_log(env, tmp_path, monkeypatch):
    from app.api.routers import settings_console

    # The image's files beside VERSION: a version log and third-party notices of the test's own.
    image = tmp_path / "image"
    image.mkdir()
    (image / "CHANGELOG.md").write_text("# Version log\n\n## HK-09.09.09 — pending\n\n- **New.** Thing.\n")
    (image / "THIRD_PARTY_NOTICES").write_text("libfoo: MIT")
    monkeypatch.setattr(settings_console, "VERSION_FILE", image / "VERSION")
    c = env["client"]
    viewer = member(env, "viewer@acme.test", "viewer")
    view = c.get("/settings/about", headers=viewer["h"]).json()
    assert view["versionLabel"].startswith("HK-") and view["version"]
    assert view["licence"]["active"] is True and view["licence"]["until"]
    assert view["terms"]["version"] and "accepted" in view["terms"]
    assert view["changelog"].startswith("# Version log") and "## HK-09.09.09" in view["changelog"]
    assert view["notices"] == {"name": "THIRD_PARTY_NOTICES", "text": "libfoo: MIT"}
    assert view["canUpdate"] is False and view["appName"] == "Hawk AI"


# ---- Support emails go to whoever holds support.manage --------------------------------------------------------------


def test_support_emails_go_to_everyone_holding_support_manage(env):
    c = env["client"]
    world = env["world"]
    admin = member(env, "admin@acme.test", "admin")
    member(env, "owner@acme.test", "owner")
    desk = member(env, "desk@acme.test", "viewer")
    asker = member(env, "pat@acme.test", "viewer")
    role = c.put("/iam/roles/new", headers=admin["h"], json={"name": "Support desk", "permissions": ["support.manage", "dashboard.view"]}).json()["role"]
    assert c.put(f"/iam/people/{desk['id']}", headers=admin["h"], json={"role": role["id"]}).status_code == 200
    c.put("/settings/smtp", headers=admin["h"], json={"smtp": SMTP, "test": True})
    with env["db"]() as db:
        assert iam_service.emails_holding(db, asker["tenant"], "support.manage") == ["admin@acme.test", "desk@acme.test", "owner@acme.test"]
    world["sent"].clear()
    made = c.post("/support", headers=asker["h"], json={"kind": "case", "subject": "It stops", "text": "At 40%", "priority": "normal"})
    assert made.status_code == 201, made.text
    told = sorted(addr for m in world["sent"] for addr in m["to"])
    assert told == ["admin@acme.test", "desk@acme.test", "owner@acme.test", "pat@acme.test"]


# ---- The self-check looks at every connector with a health call -------------------------------------------------------


def test_the_self_check_covers_connectors_beyond_checkmarx(env, tmp_path):
    admin = member(env, "admin@acme.test", "admin")
    with env["db"]() as db:
        entra = Connector(tenant_id=admin["tenant"], name="Entra", connector_type="identity", provider_key="entra_id", config={}, encrypted_secrets="")
        stub = Connector(tenant_id=admin["tenant"], name="Stub", connector_type="identity", provider_key="entra_id", config={}, is_stub=True)
        off = Connector(tenant_id=admin["tenant"], name="Off", connector_type="identity", provider_key="entra_id", config={}, enabled=False)
        unknown = Connector(tenant_id=admin["tenant"], name="Odd", connector_type="x", provider_key="no_such_provider", config={})
        db.add_all([entra, stub, off, unknown])
        db.commit()
        entra_id = entra.id
    failing: dict = {}

    def probe(connector):
        if connector.id in failing:
            raise failing[connector.id]

    check = SelfCheck(data_dir=env["dir"], session_factory=env["db"], send=lambda m, to: None, probe_connector=probe, test_smtp=lambda: None, redis_factory=lambda: None)
    with env["db"]() as db:
        assert [c.id for c in check.other_connectors(db)] == [entra_id]
        assert not [p for p in check.collect(db) if p["key"].startswith("connector:")]
        failing[entra_id] = integration_connector_service.ConnectorHealthError("Microsoft Entra ID answered 401.", 401)
        problems = [p for p in check.collect(db) if p["key"].startswith("connector:")]
        assert problems == [{"key": f"connector:{admin['tenant']}:{entra_id}", "title": "Microsoft Entra ID connection (Entra)", "detail": "Microsoft Entra ID answered 401.", "tenant": admin["tenant"], "outside": False}]
        failing[entra_id] = integration_connector_service.ConnectorHealthError("Microsoft Entra ID answered 503.", 503)
        outside = [p for p in check.collect(db) if p["key"].startswith("connector:")][0]
        assert outside["outside"] and "on Microsoft Entra ID's side" in outside["detail"]
        assert not check.recheck(db, outside["key"])
        # Signing in again is the repair; once it works, it is fixed.
        failing.clear()
        assert check.repair(db, outside)


def test_a_connector_health_check_signs_in_and_reads_once(monkeypatch):
    calls = []

    class Answer:
        def __init__(self, status):
            self.status_code = status

    monkeypatch.setattr(integration_connector_service, "validate_monitoring_connector_destination", lambda **kw: type("Policy", (), {"validate": lambda self, url, source=None: None})())
    status = {"now": 200}
    monkeypatch.setattr(integration_connector_service, "request_with_redirect_validation", lambda method, url, **kw: calls.append((method, url, kw["headers"])) or Answer(status["now"]))
    assert integration_connector_service.has_health_check("entra_id") and not integration_connector_service.has_health_check("checkmarx_nope")
    integration_connector_service.check_connector_health(provider_key="entra_id", connector_config={}, secrets={"access_token": "tok"})
    assert calls[-1:] == [("GET", "https://graph.microsoft.com/v1.0/auditLogs/signIns?$top=5", {"Authorization": "Bearer tok"})]
    status["now"] = 503
    with pytest.raises(integration_connector_service.ConnectorHealthError) as error:
        integration_connector_service.check_connector_health(provider_key="entra_id", connector_config={}, secrets={"access_token": "tok"})
    assert error.value.http_status == 503
