"""First run, reset_admin, the forced password change and the terms of use (/settings/guide/install), ported from
CxMissionZero's prepareAccess, scripts/reset-admin.mjs, requireSession and src/terms.js."""

from __future__ import annotations

import hashlib
import re
import stat
import threading
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.cli import reset_admin as reset_admin_cli
from app.api.routers import access as access_routes
from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.access import ImmutableRecordError, TermsAcceptance
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import activation_service, first_run_service, mailer, terms_copy_service, terms_service
from app.services.passwords import ALPHABET, generate_password, password_problem
from app.version import APP_VERSION, display_version


GENERATED = re.compile(r"^[A-HJ-NP-Za-km-z2-9]{5}(-[A-HJ-NP-Za-km-z2-9]{5}){3}$")
SETUP_CODE = re.compile(r"^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
NEW_PASSWORD = "a-new-Password-2026"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'first-run.sqlite3'}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    data_dir = tmp_path / "data"
    monkeypatch.setattr(settings, "hawk_data_dir", str(data_dir))
    for name in ("ADMIN_EMAIL", "ADMIN_PASSWORD", "FIRST_ADMIN", "ACCEPT_TERMS", "ORGANISATION_NAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(terms_service, "_organisation_accepted_hash", None)
    app.dependency_overrides[get_db] = override_get_db
    access_routes.setup_tries.clear()
    client = TestClient(app)
    lines: list[str] = []
    try:
        yield {"client": client, "db": session_factory, "data_dir": data_dir, "log": lines}
    finally:
        client.close()
        app.dependency_overrides.clear()
        access_routes.setup_tries.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def prepare(env, **variables):
    lines = env["log"]
    lines.clear()
    return first_run_service.prepare_access(env["db"], env=variables, log=lines.append)


def sign_in(client, email, password):
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return response.json()


def bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}


# --- Generated passwords and the version --------------------------------------------------------------------------


def test_generated_passwords_are_four_groups_of_five_from_the_unambiguous_alphabet():
    assert ALPHABET == "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    seen = {generate_password() for _ in range(50)}
    assert len(seen) == 50
    assert all(GENERATED.match(password) for password in seen)
    assert all(password_problem(password) == "" for password in seen)


def test_password_rule():
    assert password_problem("short") == "Use at least 12 characters."
    assert password_problem("aaaaaaaaaaaaaaa") == "That password is too repetitive."
    assert password_problem("x" * 60 + "abcdefghijklm") == "That password is too long."
    assert password_problem(NEW_PASSWORD) == ""


def test_version_shown_like_mission_zero(env):
    assert display_version("1.2.3") == "HK-01.02.03"
    assert display_version("0.1") == "HK-00.01.00"
    assert display_version("10.0.7-beta") == "HK-10.00.07"
    assert APP_VERSION == display_version((Path(__file__).resolve().parents[3] / "VERSION").read_text().strip())
    assert env["client"].get("/health").json()["version"] == APP_VERSION


# --- The first administrator --------------------------------------------------------------------------------------


def test_first_start_creates_the_administrator_prints_it_once_and_keeps_it_in_an_owner_only_file(env):
    outcome = prepare(env)
    assert outcome.kind == "generated"
    assert outcome.email == "admin@hawk.local"
    assert GENERATED.match(outcome.password)

    log = env["log"]
    banner = [line for line in log if line and set(line) == {"="}]
    assert banner == ["=" * 64, "=" * 64]
    assert "  First start: an administrator was created. Sign in with:" in log
    assert "      Email:    admin@hawk.local" in log
    assert f"      Password: {outcome.password}" in log
    assert any("docker compose exec api python -m app.cli.reset_admin" in line for line in log)

    path = env["data_dir"] / "first-admin-password.txt"
    assert path.read_text() == f"{outcome.password}\n"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(env["data_dir"].stat().st_mode) == 0o700

    with env["db"]() as db:
        user = db.scalar(select(User).where(User.email == "admin@hawk.local"))
        assert user.must_change_password is True
        membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user.id))
        assert membership.role == "owner"
        assert db.get(Tenant, membership.tenant_id).name == "My organisation"
        audit = db.scalar(select(AuditLog).where(AuditLog.action == "access.administrator"))
        assert "created with a generated password" in audit.payload["reason"]
        assert outcome.password not in str(audit.payload)

    # A second start prints no password: it names an administrator and the way back in.
    again = prepare(env)
    assert again.kind == "existing"
    assert env["log"] == [
        "[access] Users already set up in this database; an administrator is admin@hawk.local. Lost the password? Run: "
        "python -m app.cli.reset_admin  (with Docker: docker compose exec api python -m app.cli.reset_admin)"
    ]
    with env["db"]() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1


def test_the_administrator_signs_in_must_change_the_password_first_and_the_file_goes(env):
    outcome = prepare(env)
    client = env["client"]
    tokens = sign_in(client, "admin@hawk.local", outcome.password)
    assert tokens["must_change_password"] is True

    refused = client.get("/auth/tenants", headers=bearer(tokens))
    assert refused.status_code == 403
    assert refused.json() == {"error": "Choose a new password before continuing.", "code": "password_change_required", "mustChangePassword": True}
    me = client.get("/auth/me", headers=bearer(tokens))
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True
    assert me.json()["version"] == APP_VERSION

    wrong = client.post("/auth/me/password", headers=bearer(tokens), json={"current": "nope", "next": NEW_PASSWORD})
    assert wrong.status_code == 400 and wrong.json()["detail"] == "Your current password is wrong."
    same = client.post("/auth/me/password", headers=bearer(tokens), json={"current": outcome.password, "next": outcome.password})
    assert same.json()["detail"] == "Choose a password different from the current one."
    weak = client.post("/auth/me/password", headers=bearer(tokens), json={"current": outcome.password, "next": "short"})
    assert weak.json()["detail"] == "Use at least 12 characters."

    changed = client.post("/auth/me/password", headers=bearer(tokens), json={"current": outcome.password, "next": NEW_PASSWORD})
    assert changed.status_code == 200, changed.text
    fresh = changed.json()
    assert fresh["must_change_password"] is False
    assert not (env["data_dir"] / "first-admin-password.txt").exists()
    assert client.get("/auth/tenants", headers=bearer(fresh)).status_code == 200
    # The refresh token from before the change no longer works; the new one does.
    assert client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": fresh["refresh_token"]}).status_code == 200
    sign_in(client, "admin@hawk.local", NEW_PASSWORD)


def test_admin_email_and_password_set_the_administrator_explicitly(env):
    outcome = prepare(env, ADMIN_EMAIL="Owner@Example.COM", ADMIN_PASSWORD="Chosen-Password-2026")
    assert outcome.kind == "from_environment"
    assert env["log"] == ["[access] First administrator created from ADMIN_EMAIL; they choose a new password at first sign-in."]
    assert not (env["data_dir"] / "first-admin-password.txt").exists()
    tokens = sign_in(env["client"], "Owner@example.com", "Chosen-Password-2026")
    assert tokens["must_change_password"] is True


def test_a_refused_admin_password_falls_back_to_a_generated_one_for_that_email(env):
    outcome = prepare(env, ADMIN_EMAIL="owner@example.com", ADMIN_PASSWORD="weak")
    assert env["log"][0] == "! [access] ADMIN_EMAIL / ADMIN_PASSWORD could not be used: Use at least 12 characters."
    assert outcome.kind == "generated" and outcome.email == "owner@example.com"
    with env["db"]() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1


def test_organisation_name_names_the_first_tenant(env):
    prepare(env, ORGANISATION_NAME="Acme Bank")
    with env["db"]() as db:
        assert db.scalar(select(Tenant.name)) == "Acme Bank"


def test_the_first_administrator_respects_the_activation_codes(env, monkeypatch):
    calls = []
    monkeypatch.setattr(activation_service, "assert_may_add_tenant", lambda db: calls.append("tenant"))
    monkeypatch.setattr(activation_service, "assert_may_add_member", lambda db, tenant_id: calls.append("member"))
    prepare(env)
    assert calls == ["tenant", "member"]

    def refuse(db):
        raise HTTPException(status_code=403, detail="Without a tenants activation code Hawk AI serves 1 tenant, and it is in use.")

    with env["db"]() as db:
        monkeypatch.setattr(activation_service, "assert_may_add_tenant", refuse)
        with pytest.raises(HTTPException):
            first_run_service.create_administrator(db, email="second@example.com", password=NEW_PASSWORD)


def test_setup_code_creates_the_first_administrator_once(env):
    outcome = prepare(env, FIRST_ADMIN="setup-code")
    assert outcome.kind == "setup_code"
    assert SETUP_CODE.match(outcome.setup_code)
    assert env["log"] == [
        "",
        "  No users yet. Open Hawk AI and create the first administrator with this setup code:",
        f"      {outcome.setup_code}",
        "",
    ]
    client = env["client"]
    with env["db"]() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0
    assert client.get("/setup").json() == {"setup": True}

    body = {"code": "AAAA-BBBB-CCCC", "email": "first@example.com", "name": "First Admin", "password": NEW_PASSWORD}
    wrong = client.post("/setup", json=body)
    assert wrong.status_code == 403
    assert wrong.json() == {"error": "Wrong setup code. It is printed in the server log at start-up."}

    weak = client.post("/setup", json={**body, "code": outcome.setup_code.lower(), "password": "short"})
    assert weak.status_code == 400 and weak.json()["error"] == "Use at least 12 characters."

    created = client.post("/setup", json={**body, "code": outcome.setup_code.lower()})
    assert created.status_code == 201, created.text
    tokens = created.json()
    assert tokens["user"]["email"] == "first@example.com"
    assert tokens["tenants"][0]["role"] == "owner"
    assert tokens["must_change_password"] is False
    assert client.get("/auth/tenants", headers=bearer(tokens)).status_code == 200

    assert client.post("/setup", json={**body, "code": outcome.setup_code}).status_code == 409
    assert client.get("/setup").json() == {"setup": False}
    with env["db"]() as db:
        reasons = [row.payload["reason"] for row in db.scalars(select(AuditLog).order_by(AuditLog.created_at))]
    assert "First-administrator setup refused: wrong setup code." in reasons
    assert "First administrator [email] created with the setup code." in reasons


def _require_two_step_for_everyone(env):
    from app.services import account_security

    with env["db"]() as db:
        account_security.policy(db).two_step_required = True
        db.commit()


def test_setup_code_with_required_two_step_gives_no_tokens_until_it_is_set_up(env):
    from app.db.models.user import RefreshToken
    from app.services import mfa_service

    code = prepare(env, FIRST_ADMIN="setup-code").setup_code
    _require_two_step_for_everyone(env)
    client = env["client"]
    body = {"code": code, "email": "first@example.com", "name": "First Admin", "password": NEW_PASSWORD}
    created = client.post("/setup", json=body)
    assert created.status_code == 201, created.text
    challenge = created.json()
    assert challenge["two_step"] is True
    assert "access_token" not in challenge and "refresh_token" not in challenge
    assert created.headers["cache-control"] == "no-store"
    with env["db"]() as db:
        admin = db.scalar(select(User).where(User.email == "first@example.com"))
        assert admin is not None and not admin.mfa_secret
        assert db.scalar(select(RefreshToken).where(RefreshToken.user_id == admin.id)) is None
    # The setup code is used up all the same: the administrator exists and signs in with two-step from here.
    assert client.post("/setup", json=body).status_code == 409

    secret = challenge["setup"]["secret"]
    done = client.post("/auth/two-step", json={"ticket": challenge["ticket"], "code": mfa_service.totp(secret)})
    assert done.status_code == 200, done.text
    assert len(done.json()["recovery_codes"]) == 10
    assert done.json()["access_token"]


def test_setup_code_stays_usable_when_no_two_step_ticket_can_be_made(env, monkeypatch):
    from app.services import mfa_service, sign_in_store

    code = prepare(env, FIRST_ADMIN="setup-code").setup_code
    _require_two_step_for_everyone(env)

    def unavailable(*_args, **_kwargs):
        raise sign_in_store.StoreUnavailable("down")

    body = {"code": code, "email": "first@example.com", "name": "First Admin", "password": NEW_PASSWORD}
    with monkeypatch.context() as patched:
        patched.setattr(mfa_service, "issue_ticket", unavailable)
        refused = env["client"].post("/setup", json=body)
    assert refused.status_code == 503
    assert "access_token" not in refused.json()
    with env["db"]() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 0
    assert env["client"].get("/setup").json() == {"setup": True}
    assert env["client"].post("/setup", json=body).status_code == 201


def test_a_new_start_replaces_the_setup_code(env):
    first = prepare(env, FIRST_ADMIN="setup-code").setup_code
    second = prepare(env, FIRST_ADMIN="setup-code").setup_code
    body = {"email": "first@example.com", "name": "First", "password": NEW_PASSWORD}
    assert env["client"].post("/setup", json={**body, "code": first}).status_code == 403
    assert env["client"].post("/setup", json={**body, "code": second}).status_code == 201


def test_two_processes_starting_together_make_one_administrator(env):
    barrier = threading.Barrier(4)
    outcomes = []

    def start():
        barrier.wait()
        outcomes.append(first_run_service.prepare_access(env["db"], env={}, log=lambda line: None))

    threads = [threading.Thread(target=start) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcome.kind for outcome in outcomes) == ["existing", "existing", "existing", "generated"]
    with env["db"]() as db:
        assert db.scalar(select(func.count()).select_from(User)) == 1


def test_postgres_takes_the_advisory_lock():
    executed = []

    class Dialect:
        name = "postgresql"

    class Bind:
        dialect = Dialect()

    class FakeSession:
        def get_bind(self):
            return Bind()

        def execute(self, statement, params=None):
            executed.append((str(statement), params))

    with first_run_service.bootstrap_lock(FakeSession()):
        pass
    assert executed == [("SELECT pg_advisory_xact_lock(:lock_id)", {"lock_id": 7_269_001_010})]


# --- reset_admin --------------------------------------------------------------------------------------------------


def test_reset_admin_sets_a_temporary_password_on_a_running_server(env, capsys):
    outcome = prepare(env)
    client = env["client"]
    tokens = sign_in(client, "admin@hawk.local", outcome.password)
    client.post("/auth/me/password", headers=bearer(tokens), json={"current": outcome.password, "next": NEW_PASSWORD})

    assert reset_admin_cli.main([], session_factory=env["db"]) == 0
    printed = capsys.readouterr().out
    assert "  Password reset — sign in with:" in printed
    assert "      Email:    admin@hawk.local" in printed
    password = re.search(r"Password: (\S+)", printed).group(1)
    assert GENERATED.match(password)
    assert "They choose their own password at sign-in (also anyone already signed in as them, at their next click)." in printed

    again = sign_in(client, "admin@hawk.local", password)
    assert again["must_change_password"] is True
    assert client.get("/auth/tenants", headers=bearer(again)).json()["code"] == "password_change_required"
    with env["db"]() as db:
        reasons = [row.payload.get("reason") for row in db.scalars(select(AuditLog))]
    assert "Temporary password set for [email] from the command line (reset_admin)." in reasons


def test_reset_admin_by_email_enables_a_disabled_administrator(env, capsys):
    prepare(env, ADMIN_EMAIL="owner@example.com", ADMIN_PASSWORD=NEW_PASSWORD)
    with env["db"]() as db:
        db.scalar(select(User)).is_active = False
        db.commit()
    assert reset_admin_cli.main(["owner@example.com"], session_factory=env["db"]) == 0
    password = re.search(r"Password: (\S+)", capsys.readouterr().out).group(1)
    sign_in(env["client"], "owner@example.com", password)


def test_reset_admin_names_the_users_when_the_email_is_unknown(env, capsys):
    prepare(env)
    assert reset_admin_cli.main(["nobody@example.com"], session_factory=env["db"]) == 1
    assert "No user nobody@example.com. Users: admin@hawk.local (owner)" in capsys.readouterr().err


def test_reset_admin_creates_an_administrator_when_there_is_none(env, capsys):
    assert reset_admin_cli.main([], session_factory=env["db"]) == 0
    printed = capsys.readouterr().out
    assert "  Administrator created — sign in with:" in printed
    password = re.search(r"Password: (\S+)", printed).group(1)
    assert sign_in(env["client"], "admin@hawk.local", password)["must_change_password"] is True


# --- The licence agreement and terms of use ------------------------------------------------------------------------


def _add_member(env, tenant_id: str, email: str, role: str = "viewer") -> None:
    with env["db"]() as db:
        user = User(email=email, full_name="Member Person", hashed_password=get_password_hash(NEW_PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant_id, role=role))
        db.commit()


def _owner(env):
    client = env["client"]
    prepare(env, ADMIN_EMAIL="owner@example.com", ADMIN_PASSWORD="Chosen-Password-2026")
    first = sign_in(client, "owner@example.com", "Chosen-Password-2026")
    return client.post("/auth/me/password", headers=bearer(first), json={"current": "Chosen-Password-2026", "next": NEW_PASSWORD}).json()


def _full(**overrides):
    terms = terms_service.current()
    body = {
        "version": terms.version,
        "hash": terms.hash,
        "forOrganisation": True,
        "read": True,
        "companyName": "Acme Bank PJSC",
        "fullName": "Olivia Owner",
        "email": "olivia@acme.example",
        "authorised": True,
    }
    body.update(overrides)
    return {k: v for k, v in body.items() if v is not None}


class _Outbox:
    """mailer.send, recorded (and failing while ``fail`` is set)."""

    def __init__(self) -> None:
        self.sent: list[tuple[object, str]] = []
        self.fail = False

    def __call__(self, message, to, *, smtp=None):
        if self.fail:
            raise mailer.MailError("Sending failed: the mail server is down.")
        self.sent.append((message, to))


@pytest.fixture()
def outbox(monkeypatch):
    """A mail server that is set up (mailer.current) but not tested until a test passes; mailer.send recorded."""

    box = _Outbox()
    smtp = mailer.Smtp(host="mail.acme.example", port=587, from_address="hawk@acme.example", from_name="Hawk AI", require_auth=False)
    monkeypatch.setattr(mailer, "current", lambda: smtp)
    monkeypatch.setattr(mailer, "test_connection", lambda smtp=None: None)
    monkeypatch.setattr(mailer, "send", box)
    return box


def test_terms_render_the_licensor_settings_into_a_versioned_hashed_text(monkeypatch):
    terms = terms_service.current()
    assert terms.version == "2.0"
    assert terms.text.startswith("# Hawk AI End User Licence Agreement and Terms of Use")
    assert terms.hash == hashlib.sha256(terms.text.encode("utf-8")).hexdigest()
    assert "{{" not in terms.text
    # The defaults read sensibly: UAE law, DIAC arbitration seated onshore in Dubai, in English, one arbitrator.
    assert "**the licensor named in your order or activation code** (address: as stated in your order or activation code)" in terms.text
    assert "governed by the federal laws of the United Arab Emirates as applied in the Emirate of Dubai, without regard" in terms.text
    assert "Dubai International Arbitration Centre (DIAC)" in terms.text and "onshore Dubai, and not the Dubai International Financial Centre" in terms.text
    assert "five hundred UAE dirhams (AED 500)" in terms.text
    for clause in ("## 9. AI outputs", "## 11. Limitation of liability", "## 13. Bringing claims", "## Schedule 1", "## Schedule 2"):
        assert clause in terms.text

    monkeypatch.setattr(settings, "licensor_legal_name", "Example Licensing FZ-LLC.")
    monkeypatch.setattr(settings, "licensor_address", "Office 1, Dubai, United Arab Emirates")
    monkeypatch.setattr(settings, "licensor_notice_email", "legal@example.com")
    monkeypatch.setattr(settings, "liability_cap_no_fees", "AED 100 {{GOVERNING_LAW}}\n")
    named = terms_service.current()
    assert "**Example Licensing FZ-LLC** (address: Office 1, Dubai, United Arab Emirates)" in named.text
    assert "Notices to the Licensor go to legal@example.com" in named.text
    assert "if no such Fees were paid, AED 100 GOVERNING_LAW." in named.text
    assert named.version == "2.0" and named.hash != terms.hash
    assert named.hash == hashlib.sha256(named.text.encode("utf-8")).hexdigest()

    users = terms_service.user_terms(named.text)
    assert users.startswith("## Schedule 2 — Terms of use for users and acceptable use")
    assert "## 11." not in users and "Licensor and acceptance details" not in users


@pytest.mark.terms_gate
def test_hawk_is_closed_until_an_administrator_accepts_the_agreement_then_each_person(env):
    client = env["client"]
    owner = _owner(env)
    tenant_id = owner["selected_tenant_id"]
    _add_member(env, tenant_id, "member@example.com")
    member = sign_in(client, "member@example.com", NEW_PASSWORD)
    terms = terms_service.current()

    closed = client.get("/auth/tenants", headers=bearer(owner))
    assert closed.status_code == 403
    assert closed.json() == {"error": "Accept the terms of use for your organisation to continue.", "code": "terms_required", "termsRequired": True}
    assert client.get("/auth/tenants", headers=bearer(member)).json()["error"] == "An administrator must accept the terms of use before Hawk AI can be used."
    # Health, the licence, setup, the terms themselves and one's own account stay open.
    for path in ("/health/live", "/licence", "/setup", "/terms"):
        assert client.get(path).status_code == 200, path
    me = client.get("/auth/me", headers=bearer(owner)).json()
    assert me["terms"] == {"version": "2.0", "organisationAccepted": False, "accepted": False, "canAcceptForOrganisation": True, "scope": "organisation"}
    readable = client.get("/terms", headers=bearer(member)).json()
    assert readable["version"] == "2.0" and readable["hash"] == terms.hash and readable["text"] == terms.text
    assert readable["userText"].startswith("## Schedule 2")
    assert readable["you"] == {"accepted": False, "at": None, "canAcceptForOrganisation": False, "scope": "user", "email": "member@example.com", "fullName": "Member Person"}

    # A stale version or text, and someone who is not an administrator, are refused.
    assert client.post("/terms/accept", headers=bearer(owner), json=_full(version="1.0")).status_code == 409
    assert client.post("/terms/accept", headers=bearer(owner), json=_full(hash="0" * 64)).status_code == 409
    assert client.post("/terms/accept", headers=bearer(member), json=_full()).json()["error"] == "An administrator must accept the terms of use for the organisation first."
    # Every field is required: read to the end, company, full name, email and "authorised".
    assert client.post("/terms/accept", headers=bearer(owner), json=_full(read=None)).json()["error"] == "Read the terms to the end and confirm that you have read them."
    for field, value in (("companyName", " "), ("fullName", ""), ("email", "not-an-email"), ("authorised", False)):
        refused = client.post("/terms/accept", headers=bearer(owner), json=_full(**{field: value}))
        assert refused.status_code == 400, field
        assert list(refused.json()["fields"]) == [field]
    assert client.get("/auth/tenants", headers=bearer(owner)).status_code == 403

    accepted = client.post("/terms/accept", headers={**bearer(owner), "User-Agent": "Browser/1.0"}, json=_full())
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["terms"]["accepted"] is True
    assert client.get("/auth/tenants", headers=bearer(owner)).json()["items"][0]["name"] == "Acme Bank PJSC"

    # The organisation has accepted; everyone else accepts the terms of use for users (no company fields).
    assert client.get("/auth/tenants", headers=bearer(member)).json()["error"] == "Accept the terms of use to continue."
    assert client.post("/terms/accept", headers=bearer(member), json={"version": "2.0", "hash": terms.hash}).status_code == 400
    assert client.post("/terms/accept", headers=bearer(member), json={"version": "2.0", "hash": terms.hash, "read": True}).status_code == 200
    assert client.get("/auth/tenants", headers=bearer(member)).status_code == 200

    # Another administrator accepts the whole agreement too, at their own sign-in: the terms of use are not enough.
    _add_member(env, tenant_id, "admin2@example.com", role="admin")
    second = sign_in(client, "admin2@example.com", NEW_PASSWORD)
    assert client.get("/auth/tenants", headers=bearer(second)).json()["code"] == "terms_required"
    assert client.post("/terms/accept", headers=bearer(second), json={"version": "2.0", "hash": terms.hash, "read": True}).status_code == 400
    assert client.post("/terms/accept", headers=bearer(second), json=_full(fullName="Adam Admin", email="admin2@example.com")).status_code == 200
    assert client.get("/auth/tenants", headers=bearer(second)).status_code == 200

    with env["db"]() as db:
        assert terms_service.organisation_accepted(db) is True
        rows = db.scalars(select(TermsAcceptance).order_by(TermsAcceptance.accepted_at)).all()
        first_row = next(r for r in rows if r.email == "olivia@acme.example")
        assert (first_row.scope, first_row.organisation_name, first_row.full_name, first_row.authorised) == ("organisation", "Acme Bank PJSC", "Olivia Owner", True)
        assert (first_row.version, first_row.text_hash, first_row.tenant_id, first_row.user_agent) == ("2.0", terms.hash, tenant_id, "Browser/1.0")
        assert first_row.ip and first_row.user_id
        assert sorted(r.scope for r in rows) == ["organisation", "organisation", "user"]
        audit = db.scalars(select(AuditLog).where(AuditLog.action == "terms.accepted").order_by(AuditLog.created_at)).all()
    assert [entry.payload["terms"]["scope"] for entry in audit] == ["organisation", "user", "organisation"]
    assert audit[0].resource_id == first_row.id
    assert audit[0].payload["terms"]["hash"] == terms.hash
    assert audit[0].payload["acceptance"]["companyName"] == "Acme Bank PJSC"
    assert audit[0].payload["reason"].startswith("Licence agreement v2.0 accepted for Acme Bank PJSC by Olivia Owner")


@pytest.mark.terms_gate
def test_changed_terms_are_asked_for_again(env, monkeypatch):
    client = env["client"]
    owner = _owner(env)
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    assert client.get("/auth/tenants", headers=bearer(owner)).status_code == 200

    changed = terms_service.TermsText(terms_service.current().text.replace("Version 2.0", "Version 2.1") + "\n## 29. New\n")
    monkeypatch.setattr(terms_service, "current", lambda: changed)
    assert client.get("/auth/tenants", headers=bearer(owner)).json()["code"] == "terms_required"
    assert client.get("/auth/me", headers=bearer(owner)).json()["terms"]["accepted"] is False
    assert client.post("/terms/accept", headers=bearer(owner), json=_full(version="2.0", hash=changed.hash)).status_code == 409
    assert client.post("/terms/accept", headers=bearer(owner), json=_full(version="2.1", hash=changed.hash)).status_code == 200
    assert client.get("/auth/tenants", headers=bearer(owner)).status_code == 200


@pytest.mark.terms_gate
def test_a_changed_licensor_setting_is_asked_for_again(env, monkeypatch):
    client = env["client"]
    owner = _owner(env)
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    monkeypatch.setattr(terms_service, "_organisation_accepted_hash", None)
    monkeypatch.setattr(settings, "governing_law", "the laws of the Emirate of Dubai")
    assert client.get("/auth/tenants", headers=bearer(owner)).json()["code"] == "terms_required"
    with env["db"]() as db:
        assert terms_service.organisation_accepted(db) is False


@pytest.mark.terms_gate
def test_acceptances_are_never_changed_or_deleted(env):
    client = env["client"]
    owner = _owner(env)
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    with env["db"]() as db:
        row_id = db.scalar(select(TermsAcceptance.id))
    for method in ("put", "patch", "delete"):
        assert getattr(client, method)(f"/terms/acceptances/{row_id}", headers=bearer(owner)).status_code in (404, 405), method
    with env["db"]() as db:
        row = db.get(TermsAcceptance, row_id)
        row.full_name = "Someone Else"
        with pytest.raises(ImmutableRecordError):
            db.flush()
        db.rollback()
        row = db.get(TermsAcceptance, row_id)
        db.delete(row)
        with pytest.raises(ImmutableRecordError):
            db.flush()
        db.rollback()
        assert db.get(TermsAcceptance, row_id).full_name == "Olivia Owner"


@pytest.mark.terms_gate
def test_the_copy_waits_for_the_email_server_and_goes_once_a_test_passes(env, outbox):
    client = env["client"]
    owner = _owner(env)
    terms = terms_service.current()
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    # The mail server is set up but not tested: nothing is sent, the copy waits.
    assert outbox.sent == []
    listed = client.get("/terms/acceptances", headers=bearer(owner)).json()
    assert listed["emailReady"] is False
    [item] = listed["acceptances"]
    assert item["copy"]["state"] == "waiting" and item["copy"]["to"] == "olivia@acme.example"
    with env["db"]() as db:
        assert terms_copy_service.deliver_due(db) == {"sent": 0, "failed": 0, "waiting": 1, "retrying": 0}

    # Settings → Email (SMTP) → Test: the copy goes out at once.
    tested = client.post("/settings/smtp/test", headers=bearer(owner))
    assert tested.status_code == 200, tested.text
    assert len(outbox.sent) == 1
    message, to = outbox.sent[0]
    assert to == "olivia@acme.example"
    assert "licence agreement (version 2.0)" in message["Subject"]
    body = message.get_body(("plain",)).get_content()
    assert terms.hash in body and "Acme Bank PJSC" in body and "Olivia Owner" in body
    assert "## 11. Limitation of liability" in body
    html_body = message.get_body(("html",)).get_content()
    assert "Limitation of liability" in html_body and "<script" not in html_body
    attachments = {part.get_filename(): part.get_content() for part in message.iter_attachments()}
    assert hashlib.sha256(attachments["hawk-ai-licence-agreement-v2.0.txt"]).hexdigest() == terms.hash
    assert "Acme Bank PJSC" in attachments["hawk-ai-licence-agreement-v2.0-accepted.html"].decode("utf-8")

    item = client.get("/terms/acceptances", headers=bearer(owner)).json()["acceptances"][0]
    assert item["copy"]["state"] == "sent" and item["copy"]["sentAt"]
    # Sent once: the scheduler finds nothing more to send.
    with env["db"]() as db:
        assert terms_copy_service.deliver_due(db)["sent"] == 0
    assert len(outbox.sent) == 1


@pytest.mark.terms_gate
def test_a_failed_send_is_retried_with_backoff_then_given_up(env, outbox):
    from datetime import datetime, timedelta, timezone

    from app.db.models.access import TermsCopyEmail

    client = env["client"]
    owner = _owner(env)
    with env["db"]() as db:
        mailer.mark_verified(db, mailer.current())
        db.commit()
    outbox.fail = True
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    with env["db"]() as db:
        row = db.scalar(select(TermsCopyEmail))
        assert (row.status, row.attempts) == ("queued", 1)
        assert "mail server is down" in row.last_error
        first_retry = row.next_attempt_at
        assert first_retry is not None
    copy = client.get("/terms/acceptances", headers=bearer(owner)).json()["acceptances"][0]["copy"]
    assert copy["state"] == "retrying" and copy["attempts"] == 1

    now = datetime.now(timezone.utc)
    with env["db"]() as db:
        assert terms_copy_service.deliver_due(db, now=now)["retrying"] == 1  # not due yet
        db.commit()
    outbox.fail = False
    with env["db"]() as db:
        assert terms_copy_service.deliver_due(db, now=now + timedelta(minutes=2))["sent"] == 1
        db.commit()
    assert len(outbox.sent) == 1

    # A copy that keeps failing is given up after MAX_ATTEMPTS, with growing waits in between.
    outbox.fail = True
    with env["db"]() as db:
        acceptance = db.scalar(select(TermsAcceptance))
        terms_copy_service.queue(db, acceptance)
        db.commit()
        waits = []
        moment = now
        for _ in range(terms_copy_service.MAX_ATTEMPTS):
            terms_copy_service.deliver_due(db, now=moment)
            db.commit()
            row = terms_copy_service.latest(db, acceptance.id)
            if row.next_attempt_at is not None:
                due = row.next_attempt_at if row.next_attempt_at.tzinfo else row.next_attempt_at.replace(tzinfo=timezone.utc)
                waits.append((due - moment).total_seconds())
                moment = due
        assert (row.status, row.attempts) == ("failed", terms_copy_service.MAX_ATTEMPTS)
    assert waits[:4] == [60, 300, 900, 3600]
    assert client.get("/terms/acceptances", headers=bearer(owner)).json()["acceptances"][0]["copy"]["state"] == "failed"


@pytest.mark.terms_gate
def test_send_again_and_download_the_accepted_copy(env, outbox):
    client = env["client"]
    owner = _owner(env)
    terms = terms_service.current()
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    _add_member(env, owner["selected_tenant_id"], "member@example.com")
    member = sign_in(client, "member@example.com", NEW_PASSWORD)
    assert client.post("/terms/accept", headers=bearer(member), json={"version": "2.0", "hash": terms.hash, "read": True}).status_code == 200
    with env["db"]() as db:
        row_id = db.scalar(select(TermsAcceptance.id).where(TermsAcceptance.scope == "organisation"))

    exact = client.get(f"/terms/acceptances/{row_id}/copy?format=txt", headers=bearer(owner))
    assert exact.status_code == 200
    assert hashlib.sha256(exact.content).hexdigest() == terms.hash
    assert "attachment" in exact.headers["content-disposition"]
    page = client.get(f"/terms/acceptances/{row_id}/copy", headers=bearer(owner))
    assert page.status_code == 200 and "Acme Bank PJSC" in page.text and terms.hash in page.text
    assert client.get(f"/terms/acceptances/{row_id}/copy?format=exe", headers=bearer(owner)).status_code == 400
    assert client.get(f"/terms/acceptances/{row_id}/copy", headers=bearer(member)).status_code == 403
    # Someone who is not an administrator sees only their own acceptance, and cannot send copies.
    mine = client.get("/terms/acceptances", headers=bearer(member)).json()["acceptances"]
    assert [a["scope"] for a in mine] == ["user"]
    assert client.post(f"/terms/acceptances/{row_id}/resend", headers=bearer(member), json={}).status_code == 403

    # Not tested yet: the re-sent copy waits too; once the test passes both go.
    again = client.post(f"/terms/acceptances/{row_id}/resend", headers=bearer(owner), json={"to": "legal@acme.example"})
    assert again.status_code == 200 and again.json()["copy"]["state"] == "waiting" and again.json()["copy"]["to"] == "legal@acme.example"
    assert client.post(f"/terms/acceptances/{row_id}/resend", headers=bearer(owner), json={"to": "nope"}).status_code == 400
    assert client.post("/settings/smtp/test", headers=bearer(owner)).status_code == 200
    assert sorted(to for _, to in outbox.sent) == ["legal@acme.example", "olivia@acme.example"]
    # Once tested, a re-send goes at once (just after the answer).
    assert client.post(f"/terms/acceptances/{row_id}/resend", headers=bearer(owner), json={}).json()["copy"]["state"] == "queued"
    assert client.get("/terms/acceptances", headers=bearer(owner)).json()["acceptances"][0]["copy"]["state"] == "sent"
    assert len(outbox.sent) == 3
    with env["db"]() as db:
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "terms.copy.resend")) == 2


@pytest.mark.terms_gate
def test_acceptances_are_in_the_auditor_export(env):
    from app.services.snapshot_service import _terms_acceptance_rows

    client = env["client"]
    owner = _owner(env)
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    with env["db"]() as db:
        [row] = _terms_acceptance_rows(db, owner["selected_tenant_id"])
    assert row["companyName"] == "Acme Bank PJSC" and row["fullName"] == "Olivia Owner" and row["email"] == "olivia@acme.example"
    assert row["hash"] == terms_service.current().hash and row["authorised"] is True and row["acceptedAt"]


@pytest.mark.terms_gate
def test_accept_terms_from_the_environment_accepts_for_everyone_on_record(env, monkeypatch):
    client = env["client"]
    owner = _owner(env)
    monkeypatch.setenv("ORGANISATION_NAME", "Deployer Co")
    with env["db"]() as db:
        assert terms_service.organisation_accepted(db) is False

    with env["db"]() as db:
        with pytest.raises(ValueError, match="ACCEPT_TERMS must be the email address"):
            terms_service.accept_from_environment(db, "not an email")
        assert terms_service.accept_from_environment(db, "deployer@example.com") is True
        db.commit()
        assert terms_service.accept_from_environment(db, "deployer@example.com") is False
        row = db.scalar(select(TermsAcceptance))
        assert (row.scope, row.email, row.via, row.everyone, row.organisation_name) == ("organisation", "deployer@example.com", "ACCEPT_TERMS", True, "Deployer Co")
        # Its copy waits for the email server too.
        assert terms_copy_service.status(db, row)["state"] == "waiting"
    assert client.get("/auth/tenants", headers=bearer(owner)).status_code == 200
    assert client.get("/terms", headers=bearer(owner)).json()["organisation"]["via"] == "ACCEPT_TERMS"


@pytest.mark.terms_gate
def test_background_tasks_wait_for_the_terms(env, monkeypatch):
    from app.jobs import licence_task

    monkeypatch.setattr(licence_task, "_waiting_for_terms", False)
    monkeypatch.setattr(terms_service, "organisation_accepted", lambda db=None: False)
    assert licence_task._terms_accepted("app.jobs.example") is False
    monkeypatch.setattr(terms_service, "organisation_accepted", lambda db=None: True)
    assert licence_task._terms_accepted("app.jobs.example") is True


def test_the_scheduler_sends_the_waiting_copies_every_five_minutes():
    from app.jobs import terms_jobs
    from app.jobs.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["terms-copy-emails"]
    assert entry["task"] == terms_jobs.TERMS_COPY_TASK == "app.jobs.terms_jobs.send_terms_copies"
    assert entry["schedule"] == 300.0


@pytest.mark.terms_gate
def test_another_tenants_admin_sees_only_their_own_tenants_acceptances(env, outbox):
    """Checkmarx triage (PR 11): the acceptances carry people's names, email, address and browser. An owner or admin
    of another tenant sees, downloads and re-sends only their own tenant's; the installation's admins see all."""

    from datetime import datetime, timedelta, timezone

    client = env["client"]
    owner = _owner(env)
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    with env["db"]() as db:
        other = Tenant(name="Other Co", slug="other-co", created_at=datetime.now(timezone.utc) + timedelta(days=1))
        db.add(other)
        db.commit()
        other_id = other.id
        owners_row = db.scalar(select(TermsAcceptance.id).where(TermsAcceptance.scope == "organisation"))
    _add_member(env, other_id, "admin@other.example", role="admin")
    admin = sign_in(client, "admin@other.example", NEW_PASSWORD)
    mine = client.post("/terms/accept", headers=bearer(admin), json=_full(companyName="Other Co", fullName="Oscar Other", email="oscar@other.example"))
    assert mine.status_code == 200, mine.text

    listed = client.get("/terms/acceptances", headers=bearer(admin)).json()["acceptances"]
    assert [item["email"] for item in listed] == ["oscar@other.example"]
    assert client.get(f"/terms/acceptances/{owners_row}/copy", headers=bearer(admin)).status_code == 404
    assert client.post(f"/terms/acceptances/{owners_row}/resend", headers=bearer(admin), json={"to": "x@attacker.example"}).status_code == 404
    with env["db"]() as db:
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "terms.copy.resend")) == 0

    # The installation's admins (its first tenant's) see every tenant's.
    everyone = client.get("/terms/acceptances", headers=bearer(owner)).json()["acceptances"]
    assert sorted(item["email"] for item in everyone) == ["olivia@acme.example", "oscar@other.example"]


@pytest.mark.terms_gate
def test_a_copy_another_worker_already_sent_is_not_sent_again(env, outbox, monkeypatch):
    """The scheduler and the request that queued a copy can deliver at once: only the one whose claim on the row lands
    sends it (Checkmarx PR 12, the terms_jobs race)."""

    from app.db.models.access import TermsCopyEmail

    client = env["client"]
    owner = _owner(env)
    assert client.post("/terms/accept", headers=bearer(owner), json=_full()).status_code == 200
    assert outbox.sent == []  # the mail server is not tested yet: the copy waits

    def verified_while_another_worker_sends(db, smtp):
        # Between this worker reading the queue and sending, another one sent the copy.
        from sqlalchemy import update

        db.execute(update(TermsCopyEmail).values(status="sent", attempts=TermsCopyEmail.attempts + 1))
        return True

    monkeypatch.setattr(mailer, "verified", verified_while_another_worker_sends)
    with env["db"]() as db:
        counts = terms_copy_service.deliver_due(db)
        db.commit()
        assert db.scalar(select(TermsCopyEmail.attempts)) == 1
    assert counts["sent"] == 0 and outbox.sent == []
