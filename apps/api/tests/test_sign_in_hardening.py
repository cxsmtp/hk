"""Sign-in hardening (/settings/guide/people-and-access), ported from CxMissionZero's src/iam.js, src/mfa.js, src/password-reset.js,
src/oidc.js and src/routes/session.js: the lock after wrong passwords, the limit per address, idle sign-ins, two-step
sign-in, forgotten passwords, single sign-on's rules, the Executive MCP OAuth fix and the read-only auditor."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.routers import sign_in as sign_in_routes
from app.cli import reset_admin as reset_admin_cli
from app.core.config import settings
from app.core.permissions import PERMISSION_BY_ID
from app.core.rbac import READ_ONLY_ROLES, legacy_level, role_meets, roles_meeting
from app.core.security import get_password_hash
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import account_security, mailer, mfa_service, oidc_auth_service, password_reset_service, sign_in_store


PASSWORD = "correct-Horse-2026"
NEW_PASSWORD = "a-new-Password-2026"


class Clock:
    def __init__(self) -> None:
        self.t = datetime.now(timezone.utc).timestamp()

    def __call__(self) -> float:
        return self.t

    def move(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'sign-in.sqlite3'}", connect_args={"check_same_thread": False})
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

    clock = Clock()
    monkeypatch.setattr(sign_in_store, "now", clock)
    monkeypatch.setattr(settings, "web_origin", "https://hawk.example.test")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_from", "hawk@example.test")
    monkeypatch.setattr(settings, "smtp_pass", "smtp-secret")
    sent: list[tuple[str, str, str]] = []
    monkeypatch.setattr(mailer, "send", lambda message, to, smtp=None: sent.append((to, message["Subject"], message.get_body(("plain",)).get_content())))
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "db": factory, "clock": clock, "sent": sent}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def make_user(env, email: str, *, role: str = "owner", tenant: str | None = None, password: str = PASSWORD) -> tuple[str, str]:
    with env["db"]() as db:
        tenant_row = db.scalar(select(Tenant).where(Tenant.slug == (tenant or "acme")))
        if tenant_row is None:
            tenant_row = Tenant(name=tenant or "Acme", slug=tenant or "acme", is_active=True)
            db.add(tenant_row)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0], hashed_password=get_password_hash(password), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant_row.id, role=role))
        db.commit()
        return user.id, tenant_row.id


def login(env, email: str, password: str = PASSWORD):
    return env["client"].post("/auth/login", json={"email": email, "password": password})


def bearer(tokens) -> dict[str, str]:
    return {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}


def user_row(env, user_id: str) -> User:
    with env["db"]() as db:
        user = db.get(User, user_id)
        db.expunge(user)
        return user


def verified_smtp(env) -> None:
    with env["db"]() as db:
        account_security.policy(db).smtp_verified = mailer.fingerprint()
        db.commit()


def set_policy(env, **values) -> None:
    with env["db"]() as db:
        row = account_security.policy(db)
        for key, value in values.items():
            setattr(row, key, value)
        db.commit()


# --- TOTP (RFC 6238) ------------------------------------------------------------------------------------------------


RFC_SECRET = mfa_service.base32_encode(b"12345678901234567890")


@pytest.mark.parametrize(
    ("seconds", "code"),
    [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924"), (2000000000, "279037"), (20000000000, "353130")],
)
def test_totp_matches_the_rfc_6238_sha1_test_vectors(seconds, code):
    # RFC 6238 appendix B lists 8 digits; the 6-digit code is the same number modulo 10^6.
    assert mfa_service.totp(RFC_SECRET, seconds) == code


def test_totp_accepts_one_step_either_side_and_each_code_once():
    now = 1_700_000_015.0
    step = mfa_service.totp_step(now)
    assert step == int(now // 30)
    for offset in (-1, 0, 1):
        assert mfa_service.match_totp(RFC_SECRET, mfa_service.code_at(RFC_SECRET, step + offset), now=now) == step + offset
    assert mfa_service.match_totp(RFC_SECRET, mfa_service.code_at(RFC_SECRET, step + 2), now=now) == 0
    assert mfa_service.match_totp(RFC_SECRET, mfa_service.code_at(RFC_SECRET, step - 2), now=now) == 0
    # A code at or before the last one used never works again.
    assert mfa_service.match_totp(RFC_SECRET, mfa_service.code_at(RFC_SECRET, step), now=now, after=step) == 0
    assert mfa_service.match_totp(RFC_SECRET, "123 456".replace(" ", ""), now=now) in (0, step - 1, step, step + 1)
    assert mfa_service.typed_code("123 456") == "123456"
    assert mfa_service.typed_code("12345") == ""


def test_base32_secrets_recovery_codes_and_the_otpauth_address():
    secret = mfa_service.new_secret()
    assert re.fullmatch(r"[A-Z2-7]{32}", secret)
    assert mfa_service.base32_decode(secret.lower()) == mfa_service.base32_decode(mfa_service.grouped_key(secret))
    with pytest.raises(ValueError):
        mfa_service.base32_decode("not base32!")
    codes = mfa_service.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10
    assert all(re.fullmatch(r"[A-HJ-NP-Z2-9]{5}-[A-HJ-NP-Z2-9]{5}", code) for code in codes)
    assert mfa_service.recovery_hash("u1", codes[0]) == mfa_service.recovery_hash("u1", codes[0].lower().replace("-", ""))
    assert mfa_service.recovery_hash("u1", codes[0]) != mfa_service.recovery_hash("u2", codes[0])
    uri = mfa_service.otpauth_uri("ann@example.test", secret)
    assert uri == f"otpauth://totp/Hawk%20AI:ann%40example.test?secret={secret}&issuer=Hawk%20AI&algorithm=SHA1&digits=6&period=30"


# --- Passwords: the lock, the limit, idle sign-ins ------------------------------------------------------------------


def test_register_uses_the_password_rule(env):
    response = env["client"].post("/auth/register", json={"email": "short@example.com", "password": "short", "full_name": "S"})
    assert response.status_code == 400
    assert response.json()["detail"] == "Use at least 12 characters."


def test_five_wrong_passwords_lock_the_account_for_15_minutes(env):
    user_id, _ = make_user(env, "lock@example.test")
    for _ in range(4):
        assert login(env, "lock@example.test", "wrong-password-0").status_code == 401
    assert user_row(env, user_id).failed_logins == 4
    wrong = login(env, "lock@example.test", "wrong-password-0")
    assert wrong.status_code == 401 and wrong.json()["detail"] == "Wrong email or password."
    # Locked: the right password learns it (423); a wrong one looks like any wrong password.
    locked = login(env, "lock@example.test")
    assert locked.status_code == 423
    assert locked.json()["detail"].startswith("Too many failed attempts: try again after ")
    assert login(env, "lock@example.test", "wrong-password-0").status_code == 401
    env["clock"].move(14 * 60 + 59)
    assert login(env, "lock@example.test").status_code == 423
    env["clock"].move(2)
    ok = login(env, "lock@example.test")
    assert ok.status_code == 200, ok.text
    assert user_row(env, user_id).failed_logins == 0
    assert user_row(env, user_id).locked_until is None
    # An unknown address gets the same sentence.
    assert login(env, "nobody@example.test").json()["detail"] == "Wrong email or password."


def test_thirty_sign_in_attempts_per_ten_minutes_per_address(env):
    make_user(env, "limit@example.test")
    for i in range(30):
        assert login(env, f"nobody{i}@example.test").status_code == 401
    blocked = login(env, "limit@example.test")
    assert blocked.status_code == 429
    assert blocked.json()["detail"] == "Too many sign-in attempts from this address. Wait a few minutes."
    # A spoofed X-Forwarded-For changes nothing: the address is the connection's.
    assert env["client"].post("/auth/login", json={"email": "limit@example.test", "password": PASSWORD}, headers={"X-Forwarded-For": "203.0.113.9"}).status_code == 429
    env["clock"].move(10 * 60 + 1)
    assert login(env, "limit@example.test").status_code == 200


def test_disabled_account_is_told_only_with_the_right_password(env):
    user_id, _ = make_user(env, "off@example.test")
    with env["db"]() as db:
        db.get(User, user_id).is_active = False
        db.commit()
    assert login(env, "off@example.test", "wrong-password-0").status_code == 401
    response = login(env, "off@example.test")
    assert response.status_code == 403
    assert response.json()["detail"] == "This account is disabled. Ask an administrator."


def test_idle_sign_in_ends_after_session_idle_minutes(env):
    make_user(env, "idle@example.test")
    tokens = login(env, "idle@example.test").json()
    refreshed = env["client"].post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200
    latest = refreshed.json()["refresh_token"]
    with env["db"]() as db:
        record = db.scalar(select(RefreshToken).where(RefreshToken.revoked_at.is_(None)))
        record.created_at = datetime.now(timezone.utc) - timedelta(minutes=settings.session_idle_minutes + 1)
        db.commit()
    idle = env["client"].post("/auth/refresh", json={"refresh_token": latest})
    assert idle.status_code == 401
    assert settings.session_idle_minutes == 480


# --- Two-step sign-in -----------------------------------------------------------------------------------------------


def turn_on_two_step(env, tokens) -> tuple[str, list[str]]:
    client = env["client"]
    setup = client.post("/auth/me/two-step/setup", headers=bearer(tokens))
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    assert setup.json()["otpauth"].startswith("otpauth://totp/Hawk%20AI:")
    assert client.post("/auth/me/two-step/enable", headers=bearer(tokens), json={"code": "000000" if mfa_service.totp(secret, env["clock"]()) != "000000" else "111111"}).status_code == 400
    enabled = client.post("/auth/me/two-step/enable", headers=bearer(tokens), json={"code": mfa_service.totp(secret, env["clock"]())})
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["two_step"]["on"] is True
    assert enabled.json()["two_step"]["recoveryLeft"] == 10
    return secret, enabled.json()["recovery_codes"]


def test_two_step_sign_in_gives_a_ticket_then_tokens_and_each_code_works_once(env):
    user_id, _ = make_user(env, "mfa@example.test")
    tokens = login(env, "mfa@example.test").json()
    secret, codes = turn_on_two_step(env, tokens)
    # The secret is kept encrypted, recovery codes only as hashes.
    stored = user_row(env, user_id)
    assert secret not in (stored.mfa_secret or "")
    assert all(code not in (stored.mfa_recovery or "") for code in codes)

    env["clock"].move(30)
    first = login(env, "mfa@example.test")
    assert first.status_code == 200
    body = first.json()
    assert body["two_step"] is True and body["minutes"] == 5 and "access_token" not in body
    code = mfa_service.totp(secret, env["clock"]())
    done = env["client"].post("/auth/two-step", json={"ticket": body["ticket"], "code": code})
    assert done.status_code == 200, done.text
    assert done.json()["access_token"]
    # The ticket is used up, and the same code never works again.
    assert env["client"].post("/auth/two-step", json={"ticket": body["ticket"], "code": code}).status_code == 401
    again = login(env, "mfa@example.test").json()
    replay = env["client"].post("/auth/two-step", json={"ticket": again["ticket"], "code": code})
    assert replay.status_code == 401
    # A recovery code works once.
    recovery = env["client"].post("/auth/two-step", json={"ticket": again["ticket"], "code": codes[0]})
    assert recovery.status_code == 200, recovery.text
    third = login(env, "mfa@example.test").json()
    assert env["client"].post("/auth/two-step", json={"ticket": third["ticket"], "code": codes[0]}).status_code == 401
    assert user_row(env, user_id).mfa_recovery.count(",") == 8  # 9 left


def test_two_step_ticket_lasts_five_minutes_and_five_wrong_codes_end_it_and_count_toward_the_lock(env):
    user_id, _ = make_user(env, "wrong@example.test")
    secret, _ = turn_on_two_step(env, login(env, "wrong@example.test").json())
    env["clock"].move(60)
    ticket = login(env, "wrong@example.test").json()["ticket"]
    env["clock"].move(5 * 60 + 1)
    late = env["client"].post("/auth/two-step", json={"ticket": ticket, "code": mfa_service.totp(secret, env["clock"]())})
    assert late.status_code == 401 and late.json()["restart"] is True

    ticket = login(env, "wrong@example.test").json()["ticket"]
    bad = "000000" if mfa_service.totp(secret, env["clock"]()) != "000000" else "111112"
    for i in range(4):
        answer = env["client"].post("/auth/two-step", json={"ticket": ticket, "code": bad})
        assert answer.status_code == 401
        assert answer.json()["restart"] is False
    fifth = env["client"].post("/auth/two-step", json={"ticket": ticket, "code": bad})
    # The fifth wrong code (with no wrong password before) locks the account and ends the ticket.
    assert fifth.status_code == 401 and fifth.json()["restart"] is True
    assert account_security.locked(user_row(env, user_id), account_security.utcnow())
    assert env["client"].post("/auth/two-step", json={"ticket": ticket, "code": mfa_service.totp(secret, env["clock"]())}).status_code == 401
    assert login(env, "wrong@example.test").status_code == 423


def test_required_two_step_is_set_up_at_sign_in_and_cannot_be_turned_off(env):
    make_user(env, "owner@example.test")
    set_policy(env, two_step_required=True)
    first = login(env, "owner@example.test").json()
    assert first["two_step"] is True
    secret = first["setup"]["secret"]
    assert first["setup"]["key"].replace(" ", "") == secret
    done = env["client"].post("/auth/two-step", json={"ticket": first["ticket"], "code": mfa_service.totp(secret, env["clock"]())})
    assert done.status_code == 200, done.text
    assert len(done.json()["recovery_codes"]) == 10
    tokens = done.json()
    env["clock"].move(30)
    off = env["client"].post("/auth/me/two-step/disable", headers=bearer(tokens), json={"code": mfa_service.totp(secret, env["clock"]())})
    assert off.status_code == 403


REGISTER_BODY = {"email": "newcomer@example.com", "password": PASSWORD, "full_name": "Newcomer"}


def test_register_without_required_two_step_still_gives_tokens(env, monkeypatch):
    monkeypatch.setattr(settings, "self_registration_enabled", True)
    response = env["client"].post("/auth/register", json=REGISTER_BODY)
    assert response.status_code == 200, response.text
    assert response.json()["access_token"]


def test_register_with_required_two_step_gives_no_tokens_until_it_is_set_up(env, monkeypatch):
    monkeypatch.setattr(settings, "self_registration_enabled", True)
    set_policy(env, two_step_required=True)
    response = env["client"].post("/auth/register", json=REGISTER_BODY)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["two_step"] is True
    assert "access_token" not in body and "refresh_token" not in body
    assert response.headers["cache-control"] == "no-store"
    secret = body["setup"]["secret"]
    with env["db"]() as db:
        user = db.scalar(select(User).where(User.email == REGISTER_BODY["email"]))
        assert user is not None and not user.mfa_secret
        assert db.scalar(select(RefreshToken).where(RefreshToken.user_id == user.id)) is None

    wrong = env["client"].post("/auth/two-step", json={"ticket": body["ticket"], "code": "000000"})
    assert wrong.status_code == 401
    done = env["client"].post("/auth/two-step", json={"ticket": body["ticket"], "code": mfa_service.totp(secret, env["clock"]())})
    assert done.status_code == 200, done.text
    assert len(done.json()["recovery_codes"]) == 10
    assert env["client"].get("/auth/me", headers=bearer(done.json())).json()["two_step"]["on"] is True


def test_register_with_required_two_step_keeps_nothing_when_no_ticket_can_be_made(env, monkeypatch):
    monkeypatch.setattr(settings, "self_registration_enabled", True)
    set_policy(env, two_step_required=True)

    def unavailable(*_args, **_kwargs):
        raise sign_in_store.StoreUnavailable("down")

    monkeypatch.setattr(mfa_service, "issue_ticket", unavailable)
    response = env["client"].post("/auth/register", json=REGISTER_BODY)
    assert response.status_code == 503
    assert "access_token" not in response.json()
    with env["db"]() as db:
        assert db.scalar(select(User).where(User.email == REGISTER_BODY["email"])) is None


def test_turning_off_and_new_recovery_codes_need_a_current_app_code(env):
    make_user(env, "self@example.test")
    tokens = login(env, "self@example.test").json()
    secret, codes = turn_on_two_step(env, tokens)
    assert env["client"].post("/auth/me/two-step/recovery-codes", headers=bearer(tokens), json={"code": codes[1]}).status_code == 400
    env["clock"].move(30)
    fresh = env["client"].post("/auth/me/two-step/recovery-codes", headers=bearer(tokens), json={"code": mfa_service.totp(secret, env["clock"]())})
    assert fresh.status_code == 200 and len(fresh.json()["recovery_codes"]) == 10
    env["clock"].move(30)
    off = env["client"].post("/auth/me/two-step/disable", headers=bearer(tokens), json={"code": mfa_service.totp(secret, env["clock"]())})
    assert off.status_code == 200 and off.json()["two_step"]["on"] is False


def test_admin_resets_someones_two_step_but_not_above_their_role(env):
    admin_id, _ = make_user(env, "admin@example.test", role="admin")
    viewer_id, _ = make_user(env, "viewer@example.test", role="viewer")
    owner_id, _ = make_user(env, "boss@example.test", role="owner")
    turn_on_two_step(env, login(env, "viewer@example.test").json())
    admin_tokens = login(env, "admin@example.test").json()
    people = env["client"].get("/auth/sign-in-settings/people", headers=bearer(admin_tokens)).json()["people"]
    assert next(p for p in people if p["id"] == viewer_id)["twoStep"] is True
    reset = env["client"].delete(f"/auth/sign-in-settings/people/{viewer_id}/two-step", headers=bearer(admin_tokens))
    assert reset.status_code == 200
    assert user_row(env, viewer_id).mfa_secret is None
    assert env["client"].delete(f"/auth/sign-in-settings/people/{owner_id}/two-step", headers=bearer(admin_tokens)).status_code == 403
    assert env["client"].delete(f"/auth/sign-in-settings/people/{admin_id}/two-step", headers=bearer(admin_tokens)).status_code == 400
    viewer_tokens = login(env, "viewer@example.test").json()
    assert viewer_tokens.get("access_token")
    assert env["client"].get("/auth/sign-in-settings/people", headers=bearer(viewer_tokens)).status_code == 403


def test_reset_two_step_from_the_environment_works_once_and_is_audited(env):
    user_id, _ = make_user(env, "only@example.test")
    turn_on_two_step(env, login(env, "only@example.test").json())
    lines: list[str] = []
    with env["db"]() as db:
        assert sign_in_routes.reset_two_step_from_environment(db, "Only@Example.test", log=lines.append) == "reset"
        db.commit()
    assert user_row(env, user_id).mfa_secret is None
    assert any("Two-step sign-in was reset for only@example.test" in line for line in lines)
    turn_on_two_step(env, login(env, "only@example.test").json())
    with env["db"]() as db:
        assert sign_in_routes.reset_two_step_from_environment(db, "only@example.test", log=lines.append) == "used-before"
        db.commit()
        assert db.scalar(select(AuditLog).where(AuditLog.action == "auth.two_step.reset")) is not None
    assert user_row(env, user_id).mfa_secret is not None
    with env["db"]() as db:
        assert sign_in_routes.reset_two_step_from_environment(db, "", log=lines.append) == ""
        assert sign_in_routes.reset_two_step_from_environment(db, "nobody@example.test", log=lines.append) == "unknown"
        db.commit()


def test_reset_admin_also_takes_two_step_off_and_clears_the_lock(env, capsys):
    user_id, _ = make_user(env, "root@example.test")
    turn_on_two_step(env, login(env, "root@example.test").json())
    with env["db"]() as db:
        db.get(User, user_id).locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
        db.commit()
    assert reset_admin_cli.main(["root@example.test"], session_factory=env["db"]) == 0
    out = capsys.readouterr().out
    assert "Their two-step sign-in was taken off" in out
    row = user_row(env, user_id)
    assert row.mfa_secret is None and row.locked_until is None and row.must_change_password is True


# --- Forgotten passwords --------------------------------------------------------------------------------------------


def ask(env, email: str):
    return env["client"].post("/auth/password-reset", json={"email": email})


def link_token(env) -> str:
    text = env["sent"][-1][2]
    match = re.search(r"https://hawk\.example\.test/login/reset#reset=([A-Za-z0-9_-]{43})", text)
    assert match, text
    return match.group(1)


def test_forgot_password_answers_alike_and_sends_only_to_the_accounts_own_address(env):
    make_user(env, "ann@example.test")
    assert env["client"].get("/auth/sign-in-options").json()["passwordReset"] is False
    verified_smtp(env)
    assert env["client"].get("/auth/sign-in-options").json()["passwordReset"] is True
    known = ask(env, "ANN@example.test")
    unknown = ask(env, "nobody@example.test")
    assert known.status_code == unknown.status_code == 202
    assert known.json() == unknown.json() == {"message": password_reset_service.RESET_ASKED}
    assert [to for to, _, _ in env["sent"]] == ["ann@example.test"]
    token = link_token(env)
    # Only the SHA-256 is kept.
    store = sign_in_store.store()
    assert store.get(f"reset:{hashlib.sha256(token.encode()).hexdigest()}") is not None
    assert all(token not in json.dumps(value) for value in store._values.values())  # type: ignore[attr-defined]


def test_reset_link_needs_an_https_server_address(env, monkeypatch):
    make_user(env, "ann@example.test")
    verified_smtp(env)
    monkeypatch.setattr(settings, "web_origin", "http://hawk.example.test")
    assert password_reset_service.link_base() == ""
    ask(env, "ann@example.test")
    assert env["sent"] == []
    monkeypatch.setattr(settings, "web_origin", "http://localhost:3000")
    assert password_reset_service.link_base() == "http://localhost:3000"


def test_reset_link_works_once_signs_out_everywhere_and_confirms_by_email(env):
    user_id, _ = make_user(env, "ann@example.test")
    verified_smtp(env)
    tokens = login(env, "ann@example.test").json()
    for _ in range(4):
        login(env, "ann@example.test", "wrong-password-0")
    ask(env, "ann@example.test")
    token = link_token(env)
    check = env["client"].post("/auth/password-reset/check", json={"token": token})
    assert check.status_code == 200 and check.json() == {"email": "a••@example.test", "minutes": 30}
    assert env["client"].post("/auth/password-reset/confirm", json={"token": token, "password": "short"}).json()["detail"] == "Use at least 12 characters."
    assert env["client"].post("/auth/password-reset/confirm", json={"token": token, "password": PASSWORD}).json()["detail"] == "Choose a password different from the current one."
    env["clock"].move(1)
    done = env["client"].post("/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD})
    assert done.status_code == 200, done.text
    assert env["client"].post("/auth/password-reset/confirm", json={"token": token, "password": NEW_PASSWORD + "x"}).status_code == 400
    # Signed out everywhere: the refresh token is revoked, and the earlier access token refused.
    assert env["client"].post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    row = user_row(env, user_id)
    row_signed_out = int(row.signed_out_at.replace(tzinfo=timezone.utc).timestamp()) if row.signed_out_at.tzinfo is None else int(row.signed_out_at.timestamp())
    from app.core.security import decode_token

    if decode_token(tokens["access_token"])["iat"] < row_signed_out:
        assert env["client"].get("/auth/me", headers=bearer(tokens)).status_code == 401
    assert row.failed_logins == 0
    assert env["sent"][-1][0] == "ann@example.test"
    assert env["sent"][-1][1] == "Your Hawk AI password was changed"
    assert login(env, "ann@example.test", NEW_PASSWORD).status_code == 200


def test_reset_link_lasts_30_minutes_and_a_newer_one_replaces_it(env):
    make_user(env, "ann@example.test")
    verified_smtp(env)
    ask(env, "ann@example.test")
    first = link_token(env)
    env["clock"].move(61)
    ask(env, "ann@example.test")
    second = link_token(env)
    assert env["client"].post("/auth/password-reset/check", json={"token": first}).status_code == 400
    assert env["client"].post("/auth/password-reset/check", json={"token": second}).status_code == 200
    env["clock"].move(30 * 60 + 1)
    dead = env["client"].post("/auth/password-reset/check", json={"token": second})
    assert dead.status_code == 400 and dead.json()["detail"] == password_reset_service.RESET_DEAD


def test_reset_limits_per_person_and_per_address(env):
    make_user(env, "ann@example.test")
    verified_smtp(env)
    ask(env, "ann@example.test")
    ask(env, "ann@example.test")  # within a minute: no second link
    assert len(env["sent"]) == 1
    env["clock"].move(61)
    ask(env, "ann@example.test")
    env["clock"].move(61)
    ask(env, "ann@example.test")
    env["clock"].move(61)
    ask(env, "ann@example.test")  # a fourth in the hour: none
    assert len(env["sent"]) == 3
    # 10 requests a quarter of an hour from one address (5 made so far), then 429.
    for i in range(5):
        assert ask(env, f"x{i}@example.test").status_code == 202
    blocked = ask(env, "ann@example.test")
    assert blocked.status_code == 429 and blocked.json()["detail"] == "Too many requests from this address. Wait a quarter of an hour."
    assert env["client"].post("/auth/password-reset/check", json={"token": "A" * 43}).status_code == 429
    env["clock"].move(15 * 60 + 1)
    assert ask(env, "ann@example.test").status_code == 202


def test_reset_policy_everyone_except_admins_and_nobody(env):
    make_user(env, "boss@example.test", role="owner")
    make_user(env, "dev@example.test", role="viewer")
    verified_smtp(env)
    set_policy(env, password_reset="not-admins")
    ask(env, "boss@example.test")
    ask(env, "dev@example.test")
    assert [to for to, _, _ in env["sent"]] == ["dev@example.test"]
    set_policy(env, password_reset="off")
    token = link_token(env)
    assert env["client"].post("/auth/password-reset/check", json={"token": token}).status_code == 400
    assert env["client"].get("/auth/sign-in-options").json()["passwordReset"] is False


def test_admin_sets_the_sign_in_rules(env):
    make_user(env, "boss@example.test", role="owner")
    make_user(env, "op@example.test", role="operator")
    tokens = login(env, "boss@example.test").json()
    op_tokens = login(env, "op@example.test").json()
    client = env["client"]
    view = client.get("/auth/sign-in-settings", headers=bearer(tokens)).json()
    assert view["passwordReset"] == "everyone" and view["twoStepRequired"] is False and view["sessionIdleMinutes"] == 480
    assert client.put("/auth/sign-in-settings", headers=bearer(tokens), json={"passwordReset": "maybe"}).status_code == 400
    changed = client.put("/auth/sign-in-settings", headers=bearer(tokens), json={"passwordReset": "not-admins", "twoStepRequired": True})
    assert changed.status_code == 200 and changed.json()["twoStepRequired"] is True
    assert client.put("/auth/sign-in-settings", headers=bearer(tokens), json={"sso": {"provision": "create"}}).status_code == 400
    assert client.put("/auth/sign-in-settings", headers=bearer(tokens), json={"sso": {"provision": "create", "domains": "example.test", "role": "admin"}}).status_code == 400
    assert client.put("/auth/sign-in-settings", headers=bearer(tokens), json={"sso": {"domains": "not a domain!"}}).status_code == 400
    ok = client.put("/auth/sign-in-settings", headers=bearer(tokens), json={"sso": {"provision": "create", "domains": "@Example.test, example.test", "role": "auditor"}})
    assert ok.status_code == 200 and ok.json()["sso"]["domains"] == ["example.test"]
    assert client.put("/auth/sign-in-settings", headers=bearer(tokens), json={"sso": {"passwordAdminsOnly": True}}).status_code == 400
    with env["db"]() as db:
        reasons = [row.payload.get("reason") for row in db.scalars(select(AuditLog).where(AuditLog.action == "auth.sign_in_policy.changed"))]
    assert any("everyone with a password → everyone except Admins" in str(r) for r in reasons)
    assert client.get("/auth/sign-in-settings", headers=bearer(op_tokens)).status_code == 403


def test_test_email_marks_the_email_server_tested(env):
    make_user(env, "boss@example.test", role="owner")
    tokens = login(env, "boss@example.test").json()
    sent = env["client"].post("/auth/sign-in-settings/test-email", headers=bearer(tokens))
    assert sent.status_code == 200 and sent.json()["email"]["tested"] is True
    assert env["sent"][-1][0] == "boss@example.test"


def test_only_admins_may_still_sign_in_with_a_password(env, monkeypatch):
    make_user(env, "boss@example.test", role="owner")
    make_user(env, "dev@example.test", role="viewer")
    monkeypatch.setattr(settings, "company_sso_enabled", True)
    set_policy(env, sso_password_admins_only=True)
    refused = login(env, "dev@example.test")
    assert refused.status_code == 403 and refused.json()["sso"] is True
    assert login(env, "dev@example.test", "wrong-password-0").status_code == 401
    assert login(env, "boss@example.test").status_code == 200


# --- The mail sender ------------------------------------------------------------------------------------------------


def test_smtp_settings_use_mission_zeros_names_and_a_test_binds_them(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "mail.example.test")
    monkeypatch.setattr(settings, "smtp_user", "robot@example.test")
    monkeypatch.setattr(settings, "smtp_from", "")
    monkeypatch.setattr(settings, "smtp_pass", "p4ss")
    smtp = mailer.current()
    assert smtp.from_address == "robot@example.test" and smtp.port == 587 and smtp.secure is False
    before = mailer.fingerprint()
    monkeypatch.setattr(settings, "smtp_pass", "other")
    assert mailer.fingerprint() != before
    assert mailer.from_header(mailer.Smtp("h", 1, False, "", "", 'a"b@x.test', 'Ha<w>k\r\nBcc: x')) == '"HawkBcc: x" <ab@x.test>'
    message = mailer.system_email(subject="S", lines=["one"], buttons=[("Go", "https://x.test/#reset=abc"), ("Bad", "javascript:alert(1)")])
    html = message.get_body(("html",)).get_content()
    assert "https://x.test/#reset=abc" in html and "javascript:" not in html


# --- Single sign-on -------------------------------------------------------------------------------------------------


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def int_b64(value: int, length: int | None = None) -> str:
    return b64(value.to_bytes(length or (value.bit_length() + 7) // 8, "big"))


def sign(alg: str, claims: dict, key, kid: str = "k1") -> str:
    header = b64(json.dumps({"alg": alg, "kid": kid, "typ": "JWT"}).encode())
    body = b64(json.dumps(claims).encode())
    data = f"{header}.{body}".encode()
    if alg == "RS256":
        signature = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    elif alg == "PS256":
        signature = key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    elif alg == "ES256":
        r, s = decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        import hmac as _hmac

        signature = _hmac.new(b"secret", data, hashlib.sha256).digest()
    return f"{header}.{body}.{b64(signature)}"


def rsa_jwk(key, kid="k1") -> dict:
    numbers = key.public_key().public_numbers()
    return {"kty": "RSA", "kid": kid, "n": int_b64(numbers.n), "e": int_b64(numbers.e)}


def ec_jwk(key, kid="k1") -> dict:
    numbers = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "kid": kid, "x": int_b64(numbers.x, 32), "y": int_b64(numbers.y, 32)}


ISSUER = "https://idp.example.test"


def claims(**overrides) -> dict:
    now = int(datetime.now(timezone.utc).timestamp())
    base = {"iss": ISSUER, "aud": "client-1", "sub": "subject-1", "nonce": "n1", "iat": now, "exp": now + 300, "email": "ann@example.test", "email_verified": True, "amr": ["pwd", "mfa"]}
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def verify(token: str, keys: list) -> dict:
    return oidc_auth_service.verify_id_token(token, keys=keys, issuer=ISSUER, client_id="client-1", nonce="n1")


def test_id_tokens_rs256_ps256_and_es256_only():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    assert verify(sign("RS256", claims(), rsa_key), [rsa_jwk(rsa_key)])["sub"] == "subject-1"
    assert verify(sign("PS256", claims(), rsa_key), [rsa_jwk(rsa_key)])["sub"] == "subject-1"
    assert verify(sign("ES256", claims(), ec_key), [ec_jwk(ec_key)])["sub"] == "subject-1"
    for alg in ("HS256", "none", "RS512"):
        with pytest.raises(oidc_auth_service.OIDCError, match="not accepted"):
            verify(sign(alg, claims(), rsa_key) if alg != "RS512" else sign("HS256", claims(), rsa_key).replace(b64(json.dumps({"alg": "HS256", "kid": "k1", "typ": "JWT"}).encode()), b64(json.dumps({"alg": "RS512", "kid": "k1", "typ": "JWT"}).encode())), [rsa_jwk(rsa_key)])
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(oidc_auth_service.OIDCError, match="signature"):
        verify(sign("RS256", claims(), other), [rsa_jwk(rsa_key)])
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(oidc_auth_service.OIDCError, match="2048"):
        verify(sign("RS256", claims(), small), [rsa_jwk(small)])
    with pytest.raises(oidc_auth_service.OIDCError, match="does not publish"):
        verify(sign("RS256", claims(), rsa_key, kid="other"), [rsa_jwk(rsa_key)])


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"iss": "https://evil.example"}, "another issuer"),
        ({"aud": "other"}, "audience"),
        ({"aud": ["client-1", "other"]}, "several audiences"),
        ({"azp": "other"}, "authorized party"),
        ({"exp": 1}, "expired"),
        ({"iat": None}, "issue time"),
        ({"iat": 9_999_999_999}, "issue time"),
        ({"nbf": 9_999_999_999}, "not valid yet"),
        ({"nonce": "other"}, "nonce"),
        ({"sub": ""}, "subject"),
    ],
)
def test_id_token_claims_are_checked(overrides, message):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(oidc_auth_service.OIDCError, match=message):
        verify(sign("RS256", claims(**overrides), key), [rsa_jwk(key)])


def provider(tenant_id: str):
    return oidc_auth_service.OIDCProvider(key="okta", kind="okta", display_name="Okta", workspace_slug="acme", issuer=ISSUER, client_id="client-1", tenant_id=tenant_id)


def identity(**overrides) -> dict:
    base = {"email": "ann@example.test", "verified": True, "name": "Ann", "sub": "subject-1", "issuer": ISSUER}
    base.update(overrides)
    return base


def test_sso_links_existing_people_by_issuer_and_subject(env):
    user_id, tenant_id = make_user(env, "ann@example.test", role="viewer")
    with env["db"]() as db:
        assert oidc_auth_service.resolve_user(db, provider(tenant_id), identity()).id == user_id
        db.commit()
    row = user_row(env, user_id)
    assert (row.sso_issuer, row.sso_subject) == (ISSUER, "subject-1")
    # From then on the subject decides, whatever the email says.
    with env["db"]() as db:
        assert oidc_auth_service.resolve_user(db, provider(tenant_id), identity(email="renamed@example.test")).id == user_id
        # Another subject for the same email is refused.
        with pytest.raises(oidc_auth_service.OIDCError) as refused:
            oidc_auth_service.resolve_user(db, provider(tenant_id), identity(sub="subject-2"))
        assert refused.value.code == "link"


def test_sso_refuses_unverified_unknown_and_other_domains(env):
    _, tenant_id = make_user(env, "boss@example.test", role="owner")
    with env["db"]() as db:
        for ident, code in (
            (identity(email="boss@example.test", verified=False), "email"),
            (identity(email=""), "email"),
            (identity(email="nobody@example.test"), "unknown"),
        ):
            with pytest.raises(oidc_auth_service.OIDCError) as refused:
                oidc_auth_service.resolve_user(db, provider(tenant_id), ident)
            assert refused.value.code == code
        account_security.policy(db).sso_domains = json.dumps(["corp.test"])
        with pytest.raises(oidc_auth_service.OIDCError) as refused:
            oidc_auth_service.resolve_user(db, provider(tenant_id), identity(email="boss@example.test"))
        assert refused.value.code == "domain"
        # With the verified check off, an owner is still never linked on an unverified address.
        row = account_security.policy(db)
        row.sso_domains = "[]"
        row.sso_require_verified_email = False
        with pytest.raises(oidc_auth_service.OIDCError) as refused:
            oidc_auth_service.resolve_user(db, provider(tenant_id), identity(email="boss@example.test", verified=False))
        assert refused.value.code == "email"


def test_sso_adds_people_in_allowed_domains_with_the_chosen_role_never_admin(env):
    _, tenant_id = make_user(env, "boss@example.test", role="owner")
    set_policy(env, sso_provision="create", sso_role="admin", sso_domains=json.dumps(["example.test"]))
    with env["db"]() as db:
        user = oidc_auth_service.resolve_user(db, provider(tenant_id), identity(email="new@example.test", sub="s-new"))
        db.commit()
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user.id))
        # A role that is not allowed falls back to viewer: never owner or admin.
        assert membership.role == "viewer"
        assert user.hashed_password.startswith("!")
    assert login(env, "new@example.test", "!").status_code == 401


def test_sso_state_lasts_ten_minutes_by_default():
    assert settings.oidc_state_ttl_seconds == 600


# --- The Executive MCP connector's OAuth ----------------------------------------------------------------------------


def pkce() -> tuple[str, str]:
    verifier = b64(b"v" * 40)
    return verifier, b64(hashlib.sha256(verifier.encode()).digest())


def register(env, uris=("https://claude.ai/api/mcp/auth_callback",)):
    response = env["client"].post("/mcp/executive/register", json={"client_name": "Claude", "redirect_uris": list(uris)})
    assert response.status_code == 200, response.text
    return response.json()["client_id"]


def authorize(env, client_id, *, redirect="https://claude.ai/api/mcp/auth_callback", challenge=None, method="S256", password=PASSWORD, email="exec@example.test", code=""):
    return env["client"].post(
        "/mcp/executive/authorize",
        data={"response_type": "code", "client_id": client_id, "redirect_uri": redirect, "state": "st", "scope": "executive_mcp:read", "code_challenge": challenge or "", "code_challenge_method": method, "email": email, "password": password, "code": code},
        follow_redirects=False,
    )


def test_mcp_registration_keeps_exact_redirect_uris(env):
    assert env["client"].post("/mcp/executive/register", json={"redirect_uris": ["javascript:alert(1)"]}).status_code == 400
    assert env["client"].post("/mcp/executive/register", json={"redirect_uris": ["http://evil.example/cb"]}).status_code == 400
    assert env["client"].post("/mcp/executive/register", json={}).status_code == 400
    first = register(env)
    second = register(env)
    assert first != second
    assert register(env, ("http://127.0.0.1:33418/callback",)).startswith("hawk_exec_")


def test_mcp_authorize_never_redirects_to_an_unregistered_uri_and_requires_s256(env):
    make_user(env, "exec@example.test")
    client_id = register(env)
    verifier, challenge = pkce()
    page = env["client"].get("/mcp/executive/authorize", params={"client_id": client_id, "redirect_uri": "https://evil.example/cb", "code_challenge": challenge, "code_challenge_method": "S256"})
    assert page.status_code == 400
    assert authorize(env, client_id, redirect="https://evil.example/cb", challenge=challenge).status_code == 400
    assert authorize(env, "hawk_exec_unknown", challenge=challenge).status_code == 400
    assert authorize(env, client_id, challenge=None).status_code == 400
    assert authorize(env, client_id, challenge=verifier, method="plain").status_code == 400
    good = env["client"].get("/mcp/executive/authorize", params={"client_id": client_id, "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "code_challenge": challenge, "code_challenge_method": "S256"})
    assert good.status_code == 200 and 'name="code"' in good.text


def test_mcp_code_is_single_use_bound_to_client_redirect_and_verifier(env):
    make_user(env, "exec@example.test")
    client_id = register(env)
    other_client = register(env)
    verifier, challenge = pkce()

    def code_from(response):
        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert location.startswith("https://claude.ai/api/mcp/auth_callback?")
        return re.search(r"code=([^&]+)", location).group(1)

    def token(code, **overrides):
        body = {"grant_type": "authorization_code", "code": code, "redirect_uri": "https://claude.ai/api/mcp/auth_callback", "client_id": client_id, "code_verifier": verifier}
        body.update(overrides)
        return env["client"].post("/mcp/executive/token", data=body)

    code = code_from(authorize(env, client_id, challenge=challenge))
    assert token(code, client_id=other_client).status_code == 401
    # The code is gone after any attempt.
    assert token(code).status_code == 401
    code = code_from(authorize(env, client_id, challenge=challenge))
    assert token(code, code_verifier=b64(b"w" * 40)).status_code == 401
    code = code_from(authorize(env, client_id, challenge=challenge))
    assert token(code, redirect_uri="https://claude.ai/other").status_code == 401
    code = code_from(authorize(env, client_id, challenge=challenge))
    ok = token(code)
    assert ok.status_code == 200, ok.text and ok.json()["access_token"]
    assert token(code).status_code == 401
    code = code_from(authorize(env, client_id, challenge=challenge))
    env["clock"].move(5 * 60 + 1)
    assert token(code).status_code == 401


def test_mcp_password_form_has_the_lock_and_the_two_step_code(env):
    user_id, _ = make_user(env, "exec@example.test")
    client_id = register(env)
    _, challenge = pkce()
    for _ in range(5):
        assert authorize(env, client_id, challenge=challenge, password="wrong-password-0").status_code == 401
    locked = authorize(env, client_id, challenge=challenge)
    assert locked.status_code == 401 and "Too many failed attempts" in locked.text
    env["clock"].move(15 * 60 + 1)
    tokens = login(env, "exec@example.test").json()
    secret, _ = turn_on_two_step(env, tokens)
    env["clock"].move(30)
    assert authorize(env, client_id, challenge=challenge).status_code == 401
    assert authorize(env, client_id, challenge=challenge, code=mfa_service.totp(secret, env["clock"]())).status_code == 302
    assert user_row(env, user_id).failed_logins == 0


def test_mcp_metadata_offers_only_s256():
    from app.services.executive_remote_mcp_service import build_oauth_authorization_server_metadata

    assert build_oauth_authorization_server_metadata("https://x.test")["code_challenge_methods_supported"] == ["S256"]


# --- The auditor reads, and never changes -----------------------------------------------------------------------------


def test_role_rules_keep_the_auditor_read_only():
    assert READ_ONLY_ROLES == {"auditor"}
    assert role_meets("auditor", "operator", write=False) is True
    assert role_meets("auditor", "operator", write=True) is False
    assert role_meets("auditor", "auditor", write=True) is True
    assert role_meets("auditor", "viewer", write=True) is True
    assert role_meets("auditor", "admin", write=False) is False
    assert role_meets("operator", "operator", write=True) is True
    assert role_meets("operator", "auditor", write=False) is False
    assert roles_meeting("operator", write=True) == ["operator", "admin", "owner"]


def _api_routes(routes, prefix: str = ""):
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from _api_routes(original.routes, prefix + (route.include_context.prefix or ""))
        elif hasattr(route, "dependant"):
            yield prefix + route.path, route


def _min_role_routes(method: str, min_role: str) -> list[str]:
    found = []
    for path, route in _api_routes(app.routes):
        # Routes with dependencies of their own (governance checks on the payload) answer before the role check.
        if method not in getattr(route, "methods", set()) or "{" in path or getattr(route, "dependencies", None):
            continue
        # Routes name permissions now (app/core/rbac.py); the level a permission sits at is the old min_role check
        # (app/core/permissions.py).
        level = legacy_level(min_role, None, write=method not in ("GET", "HEAD", "OPTIONS"))
        stack = list(route.dependant.dependencies)
        while stack:
            dep = stack.pop()
            held = getattr(dep.call, "permissions", None)
            if held and all(PERMISSION_BY_ID[pid].level == level for pid in held):
                found.append(path)
            stack.extend(dep.dependencies)
    return sorted(set(found))


def test_auditor_gets_403_on_operator_writes_and_still_reads(env):
    make_user(env, "auditor@example.test", role="auditor")
    make_user(env, "operator@example.test", role="operator")
    auditor = bearer(login(env, "auditor@example.test").json())
    operator = bearer(login(env, "operator@example.test").json())
    writes = [path for path in _min_role_routes("POST", "operator") if not path.startswith("/mcp")][:30]
    client = TestClient(app, raise_server_exceptions=False)
    try:
        checked = 0
        for path in writes:
            as_operator = client.post(path, headers=operator, json={}).status_code
            if as_operator == 404:  # shadowed by a route with a path parameter
                continue
            assert as_operator != 403, path
            assert client.post(path, headers=auditor, json={}).status_code == 403, path
            checked += 1
        assert checked >= 10, checked
        reads = _min_role_routes("GET", "auditor")
        assert reads
        for path in reads:
            assert client.get(path, headers=auditor).status_code not in (401, 403), path
        assert client.get("/auditor/dashboard", headers=auditor).status_code == 200
        operator_reads = _min_role_routes("GET", "operator")
        assert operator_reads
        assert client.get(operator_reads[0], headers=auditor).status_code != 403
    finally:
        client.close()
