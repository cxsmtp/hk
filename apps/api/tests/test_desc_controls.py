"""DESC ISR / UAE IA / CERT-In controls (/settings/guide/compliance; migration 0104): the password rule (length,
kinds of character, history, expiry), the idle sign-out set from Settings → Sign-in, the sign-in notice, activity
kept at least 180 days, the clock in /health, the data location in About, the CEF export, the incident report and
Settings → Compliance."""

from __future__ import annotations

import datetime as dt
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.security import decode_token, get_password_hash
from app.db.models.audit import AuditLog
from app.db.models.platform_records import ConnectorCall, UserActivity
from app.db.models.tenant import Tenant
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import account_security, compliance_service, connector_activity, password_policy, sign_in_store, user_activity
from app.services.audit_service import write_audit_log

PASSWORD = "correct-Horse-2026"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'desc.sqlite3'}", connect_args={"check_same_thread": False})
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

    monkeypatch.setattr(settings, "hawk_data_dir", str(tmp_path / "data"))
    monkeypatch.delenv("TIME_SYNC_NTP_SERVER", raising=False)
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "db": factory}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def make_user(env, email: str, *, role: str = "owner", password: str = PASSWORD) -> tuple[str, str]:
    with env["db"]() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "acme"))
        if tenant is None:
            tenant = Tenant(name="Acme", slug="acme", is_active=True)
            db.add(tenant)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0], hashed_password=get_password_hash(password), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
        db.commit()
        return user.id, tenant.id


def login(env, email: str, password: str = PASSWORD):
    return env["client"].post("/auth/login", json={"email": email, "password": password})


def bearer(tokens) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}


def signed_in(env, email: str = "owner@example.test", role: str = "owner") -> dict[str, str]:
    make_user(env, email, role=role)
    response = login(env, email)
    assert response.status_code == 200, response.text
    return bearer(response.json())


def set_rule(env, **values) -> None:
    with env["db"]() as db:
        row = account_security.policy(db)
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()


# --- The password rule -------------------------------------------------------------------------------------------


def test_default_rule_is_unchanged_twelve_characters():
    assert password_policy.problem(None, "short") == "Use at least 12 characters."
    assert password_policy.problem(None, "all-lower-case-but-long") == ""
    assert password_policy.rule(None).view() == {"minLength": 12, "classes": 0, "history": 0, "maxAgeDays": 0}


def test_rule_length_classes_and_history(env):
    user_id, _ = make_user(env, "rule@example.test")
    set_rule(env, password_min_length=14, password_classes=3, password_history=3)
    with env["db"]() as db:
        user = db.get(User, user_id)
        assert password_policy.problem(db, "Abcdefgh-123") == "Use at least 14 characters."
        assert "Mix at least 3" in password_policy.problem(db, "abcdefghijklmnop")
        assert password_policy.problem(db, "abcdefgh-ijklmnop") .startswith("Mix at least 3")
        assert password_policy.problem(db, "Abcdefgh-ijklmnop") == ""
        # The current password and the last ones may not come back.
        assert "not used recently" in password_policy.problem(db, PASSWORD + "xx", user=SimpleNamespace(hashed_password=get_password_hash(PASSWORD + "xx"), password_history=None))
        first = "First-Password-01"
        second = "Second-Password-02"
        third = "Third-Password-003"
        password_policy.remember(user, get_password_hash(first))
        password_policy.remember(user, get_password_hash(second))
        password_policy.remember(user, get_password_hash(third))
        assert user.password_changed_at is not None
        assert len(json.loads(user.password_history)) == 3  # PASSWORD, first, second
        assert "not used recently" in password_policy.problem(db, first, user=user)
        assert "not used recently" in password_policy.problem(db, third, user=user)
        # Three remembered: the current one and the two before it; the fourth back may come again.
        assert password_policy.problem(db, PASSWORD + "-Again", user=user) == ""


def test_clean_refuses_out_of_range_values():
    assert password_policy.clean({"minLength": 7})[1]
    assert password_policy.clean({"minLength": 65})[1]
    assert password_policy.clean({"classes": 1})[1]
    assert password_policy.clean({"history": 25})[1]
    assert password_policy.clean({"maxAgeDays": 400})[1]
    assert password_policy.clean({"maxAgeDays": True})[1]
    assert password_policy.clean({"minLength": "16", "classes": 3, "history": 5, "maxAgeDays": 90}) == ({"minLength": 16, "classes": 3, "history": 5, "maxAgeDays": 90}, "")


def test_change_password_follows_the_rule_and_history(env):
    make_user(env, "change@example.test")
    tokens = login(env, "change@example.test").json()
    set_rule(env, password_classes=3, password_history=5)
    client = env["client"]
    weak = client.post("/auth/me/password", json={"current": PASSWORD, "next": "only-lower-case-letters"}, headers=bearer(tokens))
    assert weak.status_code == 400 and "Mix at least 3" in weak.json()["detail"]
    ok = client.post("/auth/me/password", json={"current": PASSWORD, "next": "New-Password-2026"}, headers=bearer(tokens))
    assert ok.status_code == 200, ok.text
    tokens = ok.json()
    back = client.post("/auth/me/password", json={"current": "New-Password-2026", "next": PASSWORD}, headers=bearer(tokens))
    assert back.status_code == 400 and "not used recently" in back.json()["detail"]


def test_expired_password_must_be_changed_at_sign_in(env):
    user_id, _ = make_user(env, "old@example.test")
    set_rule(env, password_max_age_days=90)
    with env["db"]() as db:
        db.get(User, user_id).password_changed_at = datetime.now(timezone.utc) - timedelta(days=91)
        db.commit()
    response = login(env, "old@example.test")
    assert response.status_code == 200
    assert response.json()["must_change_password"] is True
    with env["db"]() as db:
        user = db.get(User, user_id)
        assert user.must_change_password is True
        # A fresh password is not expired; an account without a password (single sign-on) never is.
        user.password_changed_at = datetime.now(timezone.utc)
        assert not password_policy.expired(db, user)
        assert not password_policy.expired(db, SimpleNamespace(hashed_password="!sso", password_changed_at=None, created_at=None))


# --- Idle sign-out and the sign-in notice -------------------------------------------------------------------------


def test_sign_in_settings_save_rule_idle_and_banner(env):
    headers = signed_in(env)
    client = env["client"]
    saved = client.put(
        "/auth/sign-in-settings",
        json={"passwordRule": {"minLength": 12, "classes": 3, "history": 5, "maxAgeDays": 90}, "sessionIdleMinutes": 15, "banner": "Authorised use only. Activity is monitored."},
        headers=headers,
    )
    assert saved.status_code == 200, saved.text
    view = saved.json()
    assert view["passwordRule"]["classes"] == 3 and view["passwordRule"]["maxAgeDays"] == 90
    assert view["sessionIdleMinutes"] == 15 and view["sessionIdleSet"] == 15
    assert view["banner"].startswith("Authorised use only")
    assert client.put("/auth/sign-in-settings", json={"sessionIdleMinutes": 2}, headers=headers).status_code == 400
    assert client.put("/auth/sign-in-settings", json={"passwordRule": {"minLength": 6}}, headers=headers).status_code == 400
    assert client.put("/auth/sign-in-settings", json={"banner": "x" * 2001}, headers=headers).status_code == 400
    # Shown before signing in.
    assert client.get("/auth/sign-in-options").json()["banner"].startswith("Authorised use only")
    with env["db"]() as db:
        reasons = [row.payload.get("reason", "") for row in db.scalars(select(AuditLog).where(AuditLog.action == "auth.sign_in_policy.changed"))]
    assert any(r.startswith("Password rule:") for r in reasons)
    assert any(r.startswith("Idle sign-out:") for r in reasons)
    assert any(r.startswith("Sign-in notice:") for r in reasons)
    # Back to SESSION_IDLE_MINUTES.
    assert client.put("/auth/sign-in-settings", json={"sessionIdleMinutes": None}, headers=headers).json()["sessionIdleSet"] is None


def test_short_idle_limit_shortens_access_tokens_and_ends_idle_sign_ins(env):
    make_user(env, "idle@example.test")
    set_rule(env, session_idle_minutes=15)
    tokens = login(env, "idle@example.test").json()
    claims = decode_token(tokens["access_token"])
    assert claims["exp"] - claims["iat"] <= 7 * 60 + 1  # half the idle limit
    with env["db"]() as db:
        record = db.scalar(select(RefreshToken).where(RefreshToken.revoked_at.is_(None)))
        record.created_at = datetime.now(timezone.utc) - timedelta(minutes=16)
        db.commit()
    idle = env["client"].post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert idle.status_code == 401
    with env["db"]() as db:
        assert account_security.idle_minutes(db) == 15
        assert account_security.access_minutes(db) == 7
    # Without a value set here, SESSION_IDLE_MINUTES and the 30-minute token, as before.
    assert account_security.idle_minutes(None) == settings.session_idle_minutes
    assert account_security.access_minutes(None) == settings.access_token_expire_minutes


# --- Retention ----------------------------------------------------------------------------------------------------


def test_activity_is_kept_at_least_180_days(env):
    with env["db"]() as db:
        assert user_activity.keep_days(db) == 365
        assert connector_activity.keep_days(db) == 180
        row = compliance_service.policy(db)
        row.activity_retention_days = 30  # below the floor (set directly): still 180
        row.connector_retention_days = 400
        db.commit()
        assert user_activity.keep_days(db) == 180
        assert connector_activity.keep_days(db) == 400
    _, tenant_id = make_user(env, "keep@example.test")
    now = datetime.now(timezone.utc)
    with env["db"]() as db:
        for days in (10, 170, 200):
            db.add(ConnectorCall(tenant_id=tenant_id, connector="c", method="GET", host="h", path="/", status=200, ms=1, ok=True, at=now - timedelta(days=days)))
        db.commit()
        assert connector_activity.prune(db, now=now) == 0
        db.commit()
        row = compliance_service.policy(db)
        row.connector_retention_days = 180
        db.commit()
        assert connector_activity.prune(db, now=now) == 1


def test_activity_row_cap_never_removes_rows_younger_than_180_days(env, monkeypatch):
    _, tenant_id = make_user(env, "cap@example.test")
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(user_activity, "MAX_ROWS", 2)
    with env["db"]() as db:
        for days in (1, 2, 3, 100, 190):
            db.add(UserActivity(tenant_id=tenant_id, at=now - timedelta(days=days), user="u", name="u", role="owner", ip="", kind="action", action="x", target="", fields=[], status=200, ms=1))
        db.commit()
        removed = user_activity.prune(db, tenant_id, now=now)
        db.commit()
        assert removed == 1
        left = sorted(round((now - (r.at if r.at.tzinfo else r.at.replace(tzinfo=timezone.utc))).total_seconds() / 86400) for r in db.scalars(select(UserActivity)))
        assert left == [1, 2, 3, 100]


# --- The clock ----------------------------------------------------------------------------------------------------


def test_clock_in_health_and_status(env, monkeypatch):
    monkeypatch.setattr(compliance_service, "kernel_clock", lambda: {"synchronized": True, "source": "kernel", "maxErrorMs": 1.0})
    assert env["client"].get("/health").json()["clock"] == {"synchronized": True}
    monkeypatch.setattr(compliance_service, "kernel_clock", lambda: {"synchronized": False, "source": "kernel"})
    status = compliance_service.time_status(None)
    assert status["synchronized"] is False and "not synchronised" in status["problems"][0]
    monkeypatch.setattr(compliance_service, "kernel_clock", lambda: {"synchronized": None, "source": "kernel", "reason": "blocked"})
    assert compliance_service.time_status(None)["synchronized"] is None
    monkeypatch.setenv("TIME_SYNC_NTP_SERVER", "ntp.example.test")
    monkeypatch.setattr(compliance_service, "ntp_offset", lambda server: {"server": server, "ok": True, "offsetSeconds": 3.2, "stratum": 2})
    status = compliance_service.time_status(None)
    assert status["synchronized"] is False and "3.2 s" in status["problems"][0]


def test_kernel_clock_reads_or_says_why_not():
    result = compliance_service.kernel_clock()
    assert result["synchronized"] in (True, False, None)


def test_ntp_offset_from_a_local_server():
    import socket
    import struct
    import threading
    import time

    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    port = server.getsockname()[1]

    def answer():
        _, address = server.recvfrom(64)
        now = time.time() + 2.0 + 2_208_988_800  # two seconds ahead
        seconds, fraction = int(now), int((now % 1) * 2**32)
        reply = bytearray(48)
        reply[0], reply[1] = 0x24, 2
        reply[32:48] = struct.pack("!IIII", seconds, fraction, seconds, fraction)
        server.sendto(bytes(reply), address)

    thread = threading.Thread(target=answer)
    thread.start()
    try:
        result = compliance_service.ntp_offset("127.0.0.1", port=port)
    finally:
        thread.join(5)
        server.close()
    assert result["ok"] is True and result["stratum"] == 2
    assert 1.5 < result["offsetSeconds"] < 2.5


# --- Settings → Compliance, About, CEF and the incident report -------------------------------------------------------


def test_compliance_page_lists_controls_and_saves_settings(env, monkeypatch):
    monkeypatch.setattr(compliance_service, "kernel_clock", lambda: {"synchronized": True, "source": "kernel"})
    headers = signed_in(env)
    client = env["client"]
    page = client.get("/compliance", headers=headers)
    assert page.status_code == 200, page.text
    body = page.json()
    ids = {c["id"]: c for c in body["controls"]}
    assert {"AC-01", "AC-02", "AC-04", "AC-05", "LG-02", "LG-03", "IR-01", "CR-02", "DR-01"} <= set(ids)
    assert ids["AC-01"]["status"] == "action" and ids["LG-02"]["status"] == "met" and ids["LG-03"]["status"] == "met"
    assert sum(body["summary"].values()) == len(body["controls"])
    assert body["mayChange"] is True and body["settings"]["minRetentionDays"] == 180
    assert client.put("/compliance/settings", json={"activityRetentionDays": 90}, headers=headers).status_code == 400
    saved = client.put("/compliance/settings", json={"activityRetentionDays": 400, "dataLocation": "Dubai,  United Arab Emirates", "incidentContact": "soc@acme.example"}, headers=headers)
    assert saved.status_code == 200, saved.text
    ids = {c["id"]: c for c in saved.json()["controls"]}
    assert ids["DR-01"]["status"] == "met" and ids["IR-01"]["status"] == "met"
    assert saved.json()["settings"]["activityRetentionDays"] == 400
    about = client.get("/settings/about", headers=headers).json()
    assert about["dataResidency"]["location"] == "Dubai, United Arab Emirates"
    assert "nothing is sent to the vendor" in about["dataResidency"]["statement"]
    # The baseline makes the sign-in controls met.
    client.put("/auth/sign-in-settings", json={"passwordRule": dict(minLength=12, classes=3, history=5, maxAgeDays=90), "sessionIdleMinutes": 15, "banner": "Authorised use only.", "twoStepRequired": True}, headers=headers)
    ids = {c["id"]: c for c in client.get("/compliance", headers=headers).json()["controls"]}
    assert all(ids[k]["status"] == "met" for k in ("AC-01", "AC-02", "AC-04", "AC-05"))


def test_compliance_permissions(env):
    headers = signed_in(env, "viewer@example.test", role="viewer")
    assert env["client"].get("/compliance", headers=headers).status_code == 403
    auditor = signed_in(env, "auditor@example.test", role="auditor")
    page = env["client"].get("/compliance", headers=auditor)
    assert page.status_code == 200 and page.json()["mayChange"] is False
    assert env["client"].put("/compliance/settings", json={"dataLocation": "x"}, headers=auditor).status_code == 403


def test_cef_line_escapes_and_maps():
    line = compliance_service.cef_line(
        {"id": "e1", "seq": 7, "mac": "ab", "at": "2026-11-26T08:00:00Z", "actor": {"email": "a@b.c"}, "action": "auth.sign_in.refused", "target": "user u|1", "details": {"reason": "Wrong=password\nagain"}, "ip": "10.0.0.1"},
        version="HK-00.03.01",
    )
    assert line.startswith("CEF:0|Hawk AI|Hawk AI|HK-00.03.01|auth.sign_in.refused|")
    parts = line.split("|", 7)
    extension = parts[7]
    assert parts[6] == "6"
    assert "suser=a@b.c" in extension and "src=10.0.0.1" in extension and "outcome=failure" in extension
    assert "msg=Wrong\\=password\\nagain" in extension and "\n" not in line
    assert "cs1=7" in extension and "rt=1795680000000" in extension


def test_audit_export_cef_and_incident_report(env):
    headers = signed_in(env)
    client = env["client"]
    login(env, "owner@example.test", "wrong-password-here")
    cef = client.get("/audit/log/export.cef", headers=headers)
    assert cef.status_code == 200, cef.text
    lines = [line for line in cef.text.splitlines() if line]
    assert lines and all(line.startswith("CEF:0|Hawk AI|Hawk AI|") for line in lines)
    assert any("auth.sign_in.refused" in line for line in lines)
    assert "X-Hawk-Evidence-Signature-Status" in cef.headers or "X-Hawk-Evidence-Signature" in cef.headers

    report = client.get("/compliance/incident-report", headers=headers)
    assert report.status_code == 200, report.text
    assert report.headers["content-disposition"].startswith('attachment; filename="hawk-incident-report-')
    body = report.json()
    assert body["kind"] == "hawk-ai-incident-report"
    assert body["counts"].get("signInRefused", 0) >= 1
    assert all("mac" in e and "seq" in e for e in body["entries"])
    assert "6 hours" in body["reporting"]["certIn"]["deadline"]
    assert client.get("/compliance/incident-report?from=2026-01-01&to=2026-03-01", headers=headers).status_code == 400
    assert client.get("/compliance/incident-report?from=2026-02-01&to=2026-01-01", headers=headers).status_code == 400
    assert client.get("/compliance/incident-report?from=nonsense", headers=headers).status_code == 400
    with env["db"]() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "compliance.incident_report")) is not None


def test_migration_0104_follows_0103_and_0105_follows_it():
    from pathlib import Path

    from alembic.config import Config
    from alembic.script import ScriptDirectory

    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parents[1] / "app/db/migrations"))
    script = ScriptDirectory.from_config(config)
    assert script.get_heads() == ["0105_compliance_packs"]
    assert script.get_revision("0104_desc_controls").down_revision == "0103_terms_acceptance"
    assert script.get_revision("0105_compliance_packs").down_revision == "0104_desc_controls"


def test_policy_row_created_concurrently_is_read_not_failed(tmp_path):
    """Two requests on first load both find no row; the loser reads the winner's row and its transaction stays usable."""

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.session import Base
    from app.db.models.access import CompliancePolicy
    from app.services import compliance_service

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'race.sqlite3'}")
    Base.metadata.create_all(bind=engine, tables=[CompliancePolicy.__table__])
    make = sessionmaker(bind=engine)
    first, second = make(), make()
    assert first.get(CompliancePolicy, compliance_service.POLICY_ID) is None
    assert second.get(CompliancePolicy, compliance_service.POLICY_ID) is None
    compliance_service.policy(first)
    first.commit()
    # The second request looked before the first committed: its first lookup still says "no row", so its insert loses.
    real_get = second.get
    calls = {"n": 0}

    def stale_get(*args, **kwargs):
        calls["n"] += 1
        return None if calls["n"] == 1 else real_get(*args, **kwargs)

    second.get = stale_get
    row = compliance_service.policy(second)
    assert row is not None and row.id == compliance_service.POLICY_ID
    second.execute(CompliancePolicy.__table__.select())  # the transaction is still usable
    second.close(); first.close()
