"""People, teams and roles (app/api/routers/iam.py), ported from FTR Command Center: custom roles and their lifecycle,
the grant ceiling, which roles one sees, the last Owner, people (add, change, email change told to both addresses,
unlock, reset two-step, access off), teams and their scope, and joining by oneself with its review, the activation
code's cap and required two-step sign-in."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.permissions import PERMISSION_IDS, default_permissions
from app.core.security import get_password_hash
from app.db.models.iam import IamRole
from app.db.models.tenant import Tenant
from app.db.models.user import RefreshToken, User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import account_security, activation_service, iam_service, mailer
from app.services.auth_service import issue_tokens

PASSWORD = "correct-Horse-2026"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'iam.sqlite3'}", connect_args={"check_same_thread": False})
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

    monkeypatch.setattr(settings, "web_origin", "https://hawk.example.test")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_from", "hawk@example.test")
    sent: list[tuple[str, str, str]] = []
    monkeypatch.setattr(mailer, "send", lambda message, to, smtp=None: sent.append((to, message["Subject"], message.get_body(("plain",)).get_content())))
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield {"client": client, "db": factory, "sent": sent}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def member(env, email: str, role: str = "viewer", *, tenant: str = "acme", team_id: str | None = None) -> dict:
    with env["db"]() as db:
        t = db.scalar(select(Tenant).where(Tenant.slug == tenant))
        if t is None:
            t = Tenant(name=tenant.title(), slug=tenant, is_active=True)
            db.add(t)
            db.flush()
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(email=email, full_name=email.split("@")[0].title(), hashed_password=get_password_hash(PASSWORD), is_active=True)
            db.add(user)
            db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=t.id, role=role, team_id=team_id))
        db.flush()
        tokens = issue_tokens(db, user=user, tenant_id=t.id, role=role)
        db.commit()
        return {"id": user.id, "tenant": t.id, "h": {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": t.id}}


def mail_tested(env) -> None:
    with env["db"]() as db:
        account_security.policy(db).smtp_verified = mailer.fingerprint()
        db.commit()


# --- Roles ------------------------------------------------------------------------------------------------------------


def test_custom_role_create_rename_duplicate_compare_assign_and_remove(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    person = member(env, "pat@acme.test", "viewer")
    made = c.put("/iam/roles/new", headers=admin["h"], json={"name": "Discovery lead", "description": "Runs discovery", "permissions": ["discovery.view", "discovery.manage", "dashboard.view"]})
    assert made.status_code == 200, made.text
    role = made.json()["role"]
    assert role["id"].startswith("role-") and role["permissions"] == ["dashboard.view", "discovery.view", "discovery.manage"]
    # Rename: the permissions stay.
    renamed = c.put(f"/iam/roles/{role['id']}", headers=admin["h"], json={"name": "Discovery owner", "description": "x"}).json()["role"]
    assert renamed["name"] == "Discovery owner" and renamed["permissions"] == role["permissions"]
    # Duplicate (FTR's "Start from"): a new role with another's permissions.
    copy = c.put("/iam/roles/new", headers=admin["h"], json={"name": "Copy of Operator", "permissions": sorted(default_permissions("operator"))}).json()["role"]
    assert set(copy["permissions"]) == default_permissions("operator")
    # Compare: the list carries every role's permissions, the matrix shows the differences.
    listed = {r["id"]: r for r in c.get("/iam/people", headers=admin["h"]).json()["roles"]}
    assert set(listed[copy["id"]]["permissions"]) ^ set(listed["auditor"]["permissions"])
    # Assigned, it changes what the person may do at once.
    assert c.post("/discovery/source-connections", headers=person["h"], json={}).status_code == 403
    assert c.put(f"/iam/people/{person['id']}", headers=admin["h"], json={"role": role["id"]}).status_code == 200
    assert c.post("/discovery/source-connections", headers=person["h"], json={}).status_code != 403
    with env["db"]() as db:
        perms, floor = iam_service.resolve(db, admin["tenant"], role["id"])
        assert "discovery.manage" in perms and floor == ""
    # Held: not removed; given another first, removed.
    assert c.delete(f"/iam/roles/{role['id']}", headers=admin["h"]).status_code == 409
    assert c.put(f"/iam/people/{person['id']}", headers=admin["h"], json={"role": "viewer"}).status_code == 200
    assert c.delete(f"/iam/roles/{role['id']}", headers=admin["h"]).status_code == 200
    assert c.delete("/iam/roles/viewer", headers=admin["h"]).status_code == 400  # built-in


def test_custom_role_reaches_routes_by_permission(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    person = member(env, "pat@acme.test", "viewer")
    # A Viewer cannot read the audit log; a role with audit.view can, and only reads it.
    assert c.get("/audit/log", headers=person["h"]).status_code == 403
    role = c.put("/iam/roles/new", headers=admin["h"], json={"name": "Log reader", "permissions": ["audit.view"]}).json()["role"]
    c.put(f"/iam/people/{person['id']}", headers=admin["h"], json={"role": role["id"]})
    assert c.get("/audit/log", headers=person["h"]).status_code == 200
    assert c.get("/audit/log/export.csv", headers=person["h"]).status_code == 403
    # It no longer sees what only Viewers' permissions showed.
    assert c.get("/dashboard/notifications", headers=person["h"]).status_code == 403


def test_the_grant_ceiling_and_roles_seen(env):
    c = env["client"]
    owner = member(env, "owner@acme.test", "owner")
    admin = member(env, "admin@acme.test", "admin")
    lead_role = None
    with env["db"]() as db:
        lead_role = iam_service.save_role(db, admin["tenant"], None, name="People lead", description="", permissions=["users.manage", "roles.manage", "dashboard.view", "discovery.view"], actor_permissions=frozenset(PERMISSION_IDS), actor_role_key="owner").key
        db.commit()
    lead = member(env, "lead@acme.test", lead_role)
    viewer = member(env, "viewer@acme.test", "viewer")
    # Nobody gives a role holding more than they hold.
    assert c.put("/iam/roles/new", headers=lead["h"], json={"name": "More", "permissions": ["discovery.manage"]}).status_code == 403
    assert c.put("/iam/roles/viewer", headers=lead["h"], json={"permissions": ["dashboard.view", "policies.view"]}).status_code == 403
    # The viewer is in no team of the lead's, and holds a role the lead could not give: not one of theirs.
    assert c.put(f"/iam/people/{viewer['id']}", headers=lead["h"], json={"role": "operator"}).status_code == 404
    # The Admin-only permissions stay with the locked roles, even for an Owner.
    assert c.put("/iam/roles/new", headers=owner["h"], json={"name": "Backups", "permissions": ["backup.manage"]}).status_code == 403
    # Locked roles are only renamed: they keep every permission.
    renamed = c.put("/iam/roles/admin", headers=owner["h"], json={"name": "Administrator", "permissions": []}).json()["role"]
    assert renamed["name"] == "Administrator" and len(renamed["permissions"]) == len(PERMISSION_IDS)
    # Only an Owner gives the Owner role; an Admin does not even see it.
    assert c.put(f"/iam/people/{viewer['id']}", headers=admin["h"], json={"role": "owner"}).status_code == 403
    seen_by_admin = {r["id"] for r in c.get("/iam/people", headers=admin["h"]).json()["roles"]}
    assert "owner" not in seen_by_admin and {"admin", "auditor", "operator", "viewer", lead_role} <= seen_by_admin
    seen_by_lead = {r["id"] for r in c.get("/iam/people", headers=lead["h"]).json()["roles"]}
    assert seen_by_lead == {lead_role}  # Viewer holds evidence.view etc., which the lead does not
    seen_by_viewer = {r["id"] for r in c.get("/iam/people", headers=viewer["h"]).json()["roles"]}
    assert seen_by_viewer == {"viewer"}
    # The Admin cannot manage the Owner at all.
    assert c.post(f"/iam/people/{owner['id']}/unlock", headers=admin["h"]).status_code == 404
    assert c.post(f"/iam/people/{viewer['id']}/unlock", headers=lead["h"]).status_code == 404  # no team in the lead's scope


def test_the_last_owner_is_protected(env):
    c = env["client"]
    owner = member(env, "owner@acme.test", "owner")
    second = member(env, "second@acme.test", "owner")
    # Nobody changes their own role or turns themselves off.
    assert c.put(f"/iam/people/{owner['id']}", headers=owner["h"], json={"role": "admin"}).status_code == 400
    # With two Owners, one may be made Admin; then the last one cannot lose the role, access or the tenant.
    assert c.put(f"/iam/people/{second['id']}", headers=owner["h"], json={"role": "admin"}).status_code == 200
    with env["db"]() as db:
        m = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == owner["id"]))
        u = db.get(User, owner["id"])
        for kwargs in ({"new_role": "admin"}, {"deactivate": True}, {"remove": True}):
            with pytest.raises(HTTPException) as refused:
                iam_service.keep_an_owner(db, m, u, **kwargs)
            assert refused.value.status_code == 409


def test_built_in_roles_can_be_changed_but_never_reach_admin_only(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    operator = member(env, "op@acme.test", "operator")
    perms = sorted(default_permissions("operator") - {"simulations.operate"})
    assert c.put("/iam/roles/operator", headers=admin["h"], json={"permissions": perms}).status_code == 200
    assert operator["id"]
    with env["db"]() as db:
        held, floor = iam_service.resolve(db, admin["tenant"], "operator")
        assert "simulations.operate" not in held and floor == "viewer"
        row = db.scalar(select(IamRole).where(IamRole.key == "operator"))
        row.permissions = [*perms, "backup.manage"]  # stored by hand: never honoured
        db.commit()
        held, _ = iam_service.resolve(db, admin["tenant"], "operator")
        assert "backup.manage" not in held


# --- People -----------------------------------------------------------------------------------------------------------


def test_add_change_email_unlock_two_step_and_access_off(env):
    c = env["client"]
    mail_tested(env)
    admin = member(env, "admin@acme.test", "admin")
    added = c.post("/iam/people", headers=admin["h"], json={"email": "New.Person@acme.test", "name": "New Person", "role": "operator", "sendWelcome": True})
    assert added.status_code == 200, added.text
    temporary = added.json()["temporary"]
    assert len(temporary) == 23 and added.json()["welcomed"] is True
    assert any(to == "new.person@acme.test" and "access" in subject for to, subject, _ in env["sent"])
    new_id = added.json()["user"]["id"]
    assert c.post("/iam/people", headers=admin["h"], json={"email": "new.person@acme.test", "role": "viewer"}).status_code == 409
    login = c.post("/auth/login", json={"email": "new.person@acme.test", "password": temporary}).json()
    assert login["must_change_password"] is True
    # A changed sign-in email is told to both addresses.
    env["sent"].clear()
    assert c.put(f"/iam/people/{new_id}", headers=admin["h"], json={"email": "renamed@acme.test", "title": "Analyst"}).status_code == 200
    assert sorted(to for to, subject, _ in env["sent"] if "sign-in email" in subject) == ["new.person@acme.test", "renamed@acme.test"]
    # Unlock: the lock after wrong passwords is lifted at once.
    with env["db"]() as db:
        u = db.get(User, new_id)
        u.locked_until = datetime.now(timezone.utc) + timedelta(minutes=10)
        u.mfa_secret = "sealed"
        db.commit()
    people = {p["id"]: p for p in c.get("/iam/people", headers=admin["h"]).json()["people"]}
    assert people[new_id]["status"] == "locked" and people[new_id]["title"] == "Analyst"
    assert c.post(f"/iam/people/{new_id}/unlock", headers=admin["h"]).status_code == 200
    assert c.post(f"/iam/people/{new_id}/two-step-reset", headers=admin["h"]).status_code == 200
    with env["db"]() as db:
        u = db.get(User, new_id)
        assert u.locked_until is None and u.mfa_secret is None
    # Access off: signed out everywhere; on again, counted against the cap.
    assert c.put(f"/iam/people/{new_id}", headers=admin["h"], json={"active": False}).status_code == 200
    with env["db"]() as db:
        assert db.get(User, new_id).is_active is False
        assert all(t.revoked_at is not None for t in db.scalars(select(RefreshToken).where(RefreshToken.user_id == new_id)))
    reset = c.post(f"/iam/people/{new_id}/reset", headers=admin["h"]).json()
    assert len(reset["temporary"]) == 23


def test_adding_respects_the_activation_cap(env, monkeypatch):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")

    def full(db, tenant_id):
        raise HTTPException(status_code=403, detail="The activation code allows up to 1 active user in each tenant.")

    monkeypatch.setattr(activation_service, "assert_may_add_member", full)
    refused = c.post("/iam/people", headers=admin["h"], json={"email": "x@acme.test", "role": "viewer"})
    assert refused.status_code == 403 and "activation code" in refused.text
    with env["db"]() as db:
        assert db.scalar(select(User).where(User.email == "x@acme.test")) is None


def test_someone_in_another_tenant_is_changed_only_by_who_manages_them_there(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    shared = member(env, "shared@acme.test", "viewer")
    member(env, "shared@acme.test", "owner", tenant="other")
    # Role and team here: yes. Name, email, access, password: no (they are the same in the other tenant).
    assert c.put(f"/iam/people/{shared['id']}", headers=admin["h"], json={"role": "operator"}).status_code == 200
    assert c.put(f"/iam/people/{shared['id']}", headers=admin["h"], json={"active": False}).status_code == 403
    assert c.post(f"/iam/people/{shared['id']}/reset", headers=admin["h"]).status_code == 403
    # Removing them from this tenant leaves their account working elsewhere.
    assert c.delete(f"/iam/people/{shared['id']}", headers=admin["h"]).status_code == 200
    with env["db"]() as db:
        assert db.get(User, shared["id"]).is_active is True


# --- Teams ------------------------------------------------------------------------------------------------------------


def test_teams_tree_leaders_and_scope(env):
    c = env["client"]
    admin = member(env, "admin@acme.test", "admin")
    top = c.post("/iam/teams", headers=admin["h"], json={"name": "Global", "region": "All"}).json()["team"]
    emea = c.post("/iam/teams", headers=admin["h"], json={"name": "EMEA", "parentId": top["id"]}).json()["team"]
    north = c.post("/iam/teams", headers=admin["h"], json={"name": "EMEA North", "parentId": emea["id"]}).json()["team"]
    other = c.post("/iam/teams", headers=admin["h"], json={"name": "APAC", "parentId": top["id"]}).json()["team"]
    assert c.put(f"/iam/teams/{top['id']}", headers=admin["h"], json={"parentId": north["id"]}).status_code == 400  # no loop
    with env["db"]() as db:
        lead_role = iam_service.save_role(db, admin["tenant"], None, name="Leader", description="", permissions=[*default_permissions("viewer"), "users.manage", "teams.manage"], actor_permissions=frozenset(PERMISSION_IDS), actor_role_key="owner").key
        db.commit()
    lead = member(env, "lead@acme.test", lead_role, team_id=emea["id"])
    inside = member(env, "in@acme.test", "viewer", team_id=north["id"])
    outside = member(env, "out@acme.test", "viewer", team_id=other["id"])
    with env["db"]() as db:
        m = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == inside["id"]))
        assert m.team_id == north["id"]
    # The leader is in EMEA (their own team) and leads it: they see EMEA and EMEA North, not APAC.
    assert c.put(f"/iam/teams/{emea['id']}", headers=admin["h"], json={"leaderIds": [lead["id"]]}).status_code == 200
    people = {p["email"] for p in c.get("/iam/people", headers=lead["h"]).json()["people"]}
    assert people == {"lead@acme.test", "in@acme.test"}
    assert c.post(f"/iam/people/{outside['id']}/unlock", headers=lead["h"]).status_code == 404
    assert c.post(f"/iam/people/{inside['id']}/unlock", headers=lead["h"]).status_code == 200
    assert c.put(f"/iam/people/{inside['id']}", headers=lead["h"], json={"teamId": other["id"]}).status_code == 403
    # Teams within their own: below EMEA yes, at the top no.
    assert c.post("/iam/teams", headers=lead["h"], json={"name": "Nordics", "parentId": emea["id"]}).status_code == 200
    assert c.post("/iam/teams", headers=lead["h"], json={"name": "Top"}).status_code == 403
    assert c.put(f"/iam/teams/{other['id']}", headers=lead["h"], json={"name": "Mine"}).status_code == 403
    # A team with people or teams below it is not removed.
    assert c.delete(f"/iam/teams/{north['id']}", headers=admin["h"]).status_code == 409
    assert c.delete(f"/iam/teams/{top['id']}", headers=admin["h"]).status_code == 409
    teams = {t["name"]: t for t in c.get("/iam/people", headers=admin["h"]).json()["teams"]}
    assert teams["EMEA North"]["path"] == "Global › EMEA › EMEA North" and teams["EMEA"]["leaders"][0]["id"] == lead["id"]


# --- Joining by oneself -----------------------------------------------------------------------------------------------


def _join_on(env, admin, **extra):
    body = {"enabled": True, "domains": "acme.test", "roles": ["viewer", "operator"], **extra}
    return env["client"].put("/iam/join-settings", headers=admin["h"], json=body)


def _token(env) -> str:
    text = next(body for to, subject, body in env["sent"] if subject == "Finish joining Hawk AI")
    return text.split("#token=")[1].split()[0]


def test_join_is_off_until_turned_on_and_offers_no_managing_role(env):
    c = env["client"]
    mail_tested(env)
    admin = member(env, "admin@acme.test", "admin")
    assert c.get("/auth/join", params={"workspace": "acme"}).json() == {"available": False, "domains": []}
    assert c.post("/auth/join", json={"workspace": "acme", "email": "new@acme.test"}).status_code == 409
    view = c.get("/iam/join-settings", headers=admin["h"]).json()
    assert view["enabled"] is False and {r["id"] for r in view["allRoles"] if not r["open"]} == {"owner", "admin"}
    assert _join_on(env, admin, roles=["admin"]).status_code == 400
    assert _join_on(env, admin).status_code == 200
    assert c.get("/auth/join", params={"workspace": "acme"}).json() == {"available": True, "domains": ["acme.test"]}
    assert c.post("/auth/join", json={"workspace": "acme", "email": "someone@gmail.com"}).status_code == 400


def test_join_review_and_approve(env):
    c = env["client"]
    mail_tested(env)
    admin = member(env, "admin@acme.test", "admin")
    team = c.post("/iam/teams", headers=admin["h"], json={"name": "Security"}).json()["team"]
    _join_on(env, admin)
    asked = c.post("/auth/join", json={"workspace": "acme", "email": "Joiner@acme.test"})
    assert asked.status_code == 202 and "Check your inbox" in asked.json()["message"]
    token = _token(env)
    checked = c.post("/auth/join/check", json={"token": token}).json()
    assert checked["email"] == "joiner@acme.test" and [r["id"] for r in checked["roles"]] == ["operator", "viewer"]
    assert c.post("/auth/join/confirm", json={"token": token, "name": "Jo", "teamId": team["id"], "role": "admin", "password": PASSWORD}).status_code == 400
    done = c.post("/auth/join/confirm", json={"token": token, "name": "Jo Iner", "teamId": team["id"], "role": "operator", "password": PASSWORD})
    assert done.status_code == 200 and done.json()["access_token"]
    # The link works once.
    assert c.post("/auth/join/confirm", json={"token": token, "name": "Jo", "teamId": team["id"], "role": "operator", "password": PASSWORD}).status_code in (400, 409)
    view = c.get("/iam/people", headers=admin["h"]).json()
    assert view["joinersToReview"] == 1
    joiner = next(p for p in view["people"] if p["email"] == "joiner@acme.test")
    assert joiner["joined"]["role"] == "operator" and joiner["joined"]["reviewedAt"] is None
    # Put right, then approved.
    assert c.put(f"/iam/people/{joiner['id']}", headers=admin["h"], json={"role": "viewer"}).status_code == 200
    assert c.post(f"/iam/people/{joiner['id']}/approve", headers=admin["h"]).status_code == 200
    view = c.get("/iam/people", headers=admin["h"]).json()
    assert view["joinersToReview"] == 0
    assert next(p for p in view["people"] if p["email"] == "joiner@acme.test")["joined"]["reviewedAt"]


def test_join_respects_the_cap_and_required_two_step(env, monkeypatch):
    c = env["client"]
    mail_tested(env)
    admin = member(env, "admin@acme.test", "admin")
    _join_on(env, admin)
    c.post("/auth/join", json={"workspace": "acme", "email": "capped@acme.test"})
    token = _token(env)

    def full(db, tenant_id):
        raise HTTPException(status_code=403, detail="The activation code allows up to 1 active user in each tenant.")

    monkeypatch.setattr(activation_service, "assert_may_add_member", full)
    refused = c.post("/auth/join/confirm", json={"token": token, "name": "Cap", "role": "viewer", "password": PASSWORD})
    assert refused.status_code == 403
    with env["db"]() as db:
        assert db.scalar(select(User).where(User.email == "capped@acme.test")) is None
    monkeypatch.setattr(activation_service, "assert_may_add_member", lambda db, tenant_id: None)
    with env["db"]() as db:
        account_security.policy(db).two_step_required = True
        db.commit()
    joined = c.post("/auth/join/confirm", json={"token": token, "name": "Cap", "role": "viewer", "password": PASSWORD})
    assert joined.status_code == 200 and joined.json()["twoStep"] is True and "access_token" not in joined.json()
    # Signing in, they set two-step sign-in up before any token.
    login = c.post("/auth/login", json={"email": "capped@acme.test", "password": PASSWORD}).json()
    assert login["two_step"] is True and login["setup"]


def test_existing_account_asking_to_join_gets_no_link(env):
    c = env["client"]
    mail_tested(env)
    admin = member(env, "admin@acme.test", "admin")
    _join_on(env, admin)
    assert c.post("/auth/join", json={"workspace": "acme", "email": "admin@acme.test"}).status_code == 202
    assert [subject for _, subject, _ in env["sent"]] == ["Your access to Hawk AI"]
