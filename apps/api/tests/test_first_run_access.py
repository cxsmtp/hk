"""First run, reset_admin, the forced password change and the terms of use (deploy/README.md), ported from
CxMissionZero's prepareAccess, scripts/reset-admin.mjs, requireSession and src/terms.js."""

from __future__ import annotations

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
from app.db.models.access import TermsAcceptance
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import activation_service, first_run_service, terms_service
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


# --- The terms of use ---------------------------------------------------------------------------------------------


def _add_member(env, tenant_id: str, email: str, role: str = "viewer") -> None:
    with env["db"]() as db:
        user = User(email=email, full_name="Member", hashed_password=get_password_hash(NEW_PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant_id, role=role))
        db.commit()


@pytest.mark.terms_gate
def test_terms_text_version_and_hash():
    terms = terms_service.current()
    assert terms.version == "1.0"
    assert re.fullmatch(r"[0-9a-f]{16}", terms.hash)
    assert "Bhawani Singh" in terms.text


@pytest.mark.terms_gate
def test_hawk_is_closed_until_an_administrator_accepts_the_terms_then_each_person(env):
    client = env["client"]
    prepare(env, ADMIN_EMAIL="owner@example.com", ADMIN_PASSWORD="Chosen-Password-2026")
    first = sign_in(client, "owner@example.com", "Chosen-Password-2026")
    owner = client.post("/auth/me/password", headers=bearer(first), json={"current": "Chosen-Password-2026", "next": NEW_PASSWORD}).json()
    tenant_id = owner["selected_tenant_id"]
    _add_member(env, tenant_id, "member@example.com")
    member = sign_in(client, "member@example.com", NEW_PASSWORD)

    closed = client.get("/auth/tenants", headers=bearer(owner))
    assert closed.status_code == 403
    assert closed.json() == {"error": "Accept the terms of use for your organisation to continue.", "code": "terms_required", "termsRequired": True}
    assert client.get("/auth/tenants", headers=bearer(member)).json()["error"] == "An administrator must accept the terms of use before Hawk AI can be used."
    # Health, the licence, setup, the terms themselves and one's own account stay open.
    for path in ("/health/live", "/licence", "/setup", "/terms"):
        assert client.get(path).status_code == 200, path
    me = client.get("/auth/me", headers=bearer(owner)).json()
    assert me["terms"] == {"version": "1.0", "organisationAccepted": False, "accepted": False, "canAcceptForOrganisation": True}
    readable = client.get("/terms", headers=bearer(member)).json()
    assert readable["version"] == "1.0" and readable["text"].startswith("# Hawk AI terms of use")
    assert readable["you"] == {"accepted": False, "at": None, "canAcceptForOrganisation": False}

    assert client.post("/terms/accept", headers=bearer(owner), json={"version": "0.9", "forOrganisation": True}).status_code == 409
    assert client.post("/terms/accept", headers=bearer(member), json={"version": "1.0", "forOrganisation": True}).json()["error"] == (
        "An administrator must accept the terms of use for the organisation first."
    )
    unnamed = client.post("/terms/accept", headers=bearer(owner), json={"version": "1.0", "forOrganisation": True})
    assert unnamed.status_code == 400
    accepted = client.post("/terms/accept", headers=bearer(owner), json={"version": "1.0", "forOrganisation": True, "organisationName": "Acme Bank"})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["terms"]["accepted"] is True
    assert client.get("/auth/tenants", headers=bearer(owner)).status_code == 200
    assert client.get("/auth/tenants", headers=bearer(owner)).json()["items"][0]["name"] == "Acme Bank"

    # The organisation has accepted; each person still accepts once.
    assert client.get("/auth/tenants", headers=bearer(member)).json()["error"] == "Accept the terms of use to continue."
    assert client.post("/terms/accept", headers=bearer(member), json={"version": "1.0"}).status_code == 200
    assert client.get("/auth/tenants", headers=bearer(member)).status_code == 200
    with env["db"]() as db:
        assert terms_service.organisation_accepted(db) is True

    with env["db"]() as db:
        reasons = [row.payload["reason"] for row in db.scalars(select(AuditLog).where(AuditLog.action == "terms.accepted"))]
    assert reasons == [
        "Terms of use v1.0 accepted for the organisation by [email] (organisation name: Acme Bank).",
        "Terms of use v1.0 accepted by [email].",
        "Terms of use v1.0 accepted by [email].",
    ]


@pytest.mark.terms_gate
def test_changed_terms_are_asked_for_again(env, monkeypatch):
    client = env["client"]
    prepare(env, ADMIN_EMAIL="owner@example.com", ADMIN_PASSWORD="Chosen-Password-2026")
    first = sign_in(client, "owner@example.com", "Chosen-Password-2026")
    owner = client.post("/auth/me/password", headers=bearer(first), json={"current": "Chosen-Password-2026", "next": NEW_PASSWORD}).json()
    client.post("/terms/accept", headers=bearer(owner), json={"version": "1.0", "forOrganisation": True, "organisationName": "Acme"})
    assert client.get("/auth/tenants", headers=bearer(owner)).status_code == 200

    changed = terms_service.TermsText(terms_service.current().text + "\n## 12. New\n")
    monkeypatch.setattr(terms_service, "current", lambda: changed)
    assert client.get("/auth/tenants", headers=bearer(owner)).json()["code"] == "terms_required"
    # The organisation's name is kept, so it is not asked for again.
    assert client.post("/terms/accept", headers=bearer(owner), json={"version": "1.0", "forOrganisation": True}).status_code == 200
    assert client.get("/auth/tenants", headers=bearer(owner)).status_code == 200


@pytest.mark.terms_gate
def test_accept_terms_from_the_environment_accepts_for_everyone_on_record(env):
    client = env["client"]
    prepare(env, ADMIN_EMAIL="owner@example.com", ADMIN_PASSWORD="Chosen-Password-2026")
    first = sign_in(client, "owner@example.com", "Chosen-Password-2026")
    owner = client.post("/auth/me/password", headers=bearer(first), json={"current": "Chosen-Password-2026", "next": NEW_PASSWORD}).json()
    with env["db"]() as db:
        assert terms_service.organisation_accepted(db) is False

    with env["db"]() as db:
        with pytest.raises(ValueError, match="ACCEPT_TERMS must be the email address"):
            terms_service.accept_from_environment(db, "not an email")
        assert terms_service.accept_from_environment(db, "deployer@example.com") is True
        db.commit()
        assert terms_service.accept_from_environment(db, "deployer@example.com") is False
        row = db.scalar(select(TermsAcceptance))
        assert (row.scope, row.email, row.via, row.everyone) == ("organisation", "deployer@example.com", "ACCEPT_TERMS", True)
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
