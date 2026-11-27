"""People, teams and roles, ported from FTR Command Center (server/routes/people.js, server/routes/join.js and the teams
and roles routes of server/routes/support.js), with CxMissionZero's src/routes/people.js for changing someone's sign-in
email (both addresses are told). The console's Settings → People, Teams and Roles & permissions use them.

Signed in, in a tenant:
- GET  /iam/people                                the people one sees, the roles one could give, the teams, the catalogue
- POST /iam/people                                add a person (users.manage), with a temporary password
- PUT  /iam/people/{id}                           name, title, email, role, team, reports to, access on or off
- POST /iam/people/{id}/reset | unlock | signout | two-step-reset | welcome | approve
- DELETE /iam/people/{id}                         remove them from the tenant
- PUT/DELETE /iam/roles/{id}                      roles ("new" makes one; roles.manage)
- POST /iam/teams, PUT/DELETE /iam/teams/{id}     teams (teams.manage, within one's teams)
- GET/PUT /iam/join-settings                      joining by oneself (FTR CC-01.116.00): off until turned on

Before signing in (FTR's /api/auth/join):
- GET /auth/join, POST /auth/join, POST /auth/join/check, POST /auth/join/confirm

Who may do what (FTR): whoever manages people changes only the people in the teams they work in (every team with "See
every team"), and only those whose role they could give themselves; nobody gives a role holding a permission they do
not hold; only an Owner gives or takes the Owner role; there is always an active Owner. A person's name, email, password,
two-step sign-in and access are theirs in every tenant they belong to, so those are changed only by someone who may
manage them in each of those tenants.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import secrets
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import session_cookies
from app.core.log_config import mask_email
from app.core.permissions import ADMIN_ONLY, GROUPS, LOCKED_ROLES, PERMISSIONS
from app.core.rbac import require_permission
from app.core.security import get_password_hash
from app.core.tenant import TenantContext, require_tenant
from app.db.models.iam import IamJoinSettings, IamTeam
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import get_db
from app.services import account_security, activation_service, iam_service, mailer, password_reset_service, sign_in_store
from app.services.audit_service import write_audit_log
from app.services.iam_service import Refused, clean
from app.services import password_policy
from app.services.passwords import generate_password
from app.services.sign_in_store import StoreUnavailable


router = APIRouter(tags=["iam"])

EMAIL = re.compile(r"^(?=.{3,254}$)[^\s@<>\"]+@[^\s@<>\"]+\.[^\s@<>\"]+$")
NOT_YOURS = "That person is not one you can change."


logger = logging.getLogger(__name__)


def _no_store(content: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content=content, status_code=status_code, headers={"Cache-Control": "no-store"})


def _refused(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": message, "detail": message}, headers={"Cache-Control": "no-store"})


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _record(db: Session, ctx: TenantContext | None, action: str, target: str, *, tenant_id: str | None = None, actor_id: str | None = None, **details: Any) -> None:
    write_audit_log(
        db,
        tenant_id=tenant_id or (ctx.tenant.id if ctx else None),
        actor_user_id=actor_id or (ctx.user.id if ctx and ctx.user else None),
        actor_type="human",
        action=action,
        resource_type="iam",
        resource_id=target[:200] or "iam",
        payload={k: v for k, v in details.items() if v is not None},
    )


def mail_ready(db: Session) -> bool:
    """Email is set up and a test email arrived with exactly these settings (Settings → Sign-in)."""

    return bool(mailer.configured()) and account_security.policy(db).smtp_verified == mailer.fingerprint()


def _send(message, to: str) -> None:  # type: ignore[no-untyped-def]
    try:
        mailer.send(message, to)
    except mailer.MailError as error:
        logger.warning("[people] An email to %s could not be sent: %s", mask_email(to), error)


# ---------------------------------------------------------------------------------------------------------------------
# Who may change whom
# ---------------------------------------------------------------------------------------------------------------------


class Scope:
    """What the asking person works on: their teams (FTR's ctx.scope) and the tenant's teams."""

    def __init__(self, db: Session, ctx: TenantContext) -> None:
        self.teams = iam_service.teams(db, ctx.tenant.id)
        membership = ctx.membership
        self.ids = iam_service.scope_of(ctx.user.id if ctx.user else "", membership.team_id if membership else None, ctx.permissions, self.teams)
        self.all = "scope.all" in ctx.permissions

    def has(self, team_id: str | None) -> bool:
        return self.all or (bool(team_id) and team_id in self.ids)


def can_manage(db: Session, ctx: TenantContext, scope: Scope, membership: UserTenantRole) -> bool:
    """FTR's canManage: people.manage, the person in one's teams, and their role one one could give."""

    if "users.manage" not in ctx.permissions:
        return False
    if not scope.has(membership.team_id):
        return False
    return iam_service.can_grant(ctx.permissions, ctx.role_key, iam_service.role(db, ctx.tenant.id, membership.role))


def manages_everywhere(db: Session, ctx: TenantContext, user: User) -> bool:
    """A person's name, email, password, two-step sign-in and access are the same in every tenant they belong to: they
    are changed only by someone who could manage them in each of those tenants."""

    if ctx.user is None:
        return False
    for other in db.scalars(select(UserTenantRole).where(UserTenantRole.user_id == user.id, UserTenantRole.tenant_id != ctx.tenant.id)):
        mine = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == ctx.user.id, UserTenantRole.tenant_id == other.tenant_id))
        if mine is None:
            return False
        permissions, _ = iam_service.resolve(db, other.tenant_id, mine.role)
        if "users.manage" not in permissions or "scope.all" not in permissions:
            return False
        if not iam_service.can_grant(permissions, mine.role, iam_service.role(db, other.tenant_id, other.role)):
            return False
    return True


def _target(db: Session, ctx: TenantContext, user_id: str) -> tuple[User, UserTenantRole, Scope]:
    membership = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == user_id, UserTenantRole.tenant_id == ctx.tenant.id))
    user = db.get(User, user_id) if membership is not None else None
    scope = Scope(db, ctx)
    if user is None or membership is None or not can_manage(db, ctx, scope, membership):
        raise Refused(404, NOT_YOURS)
    return user, membership, scope


def _everywhere(db: Session, ctx: TenantContext, user: User) -> None:
    if not manages_everywhere(db, ctx, user):
        raise Refused(403, "This person also works in another tenant where you cannot manage them: their name, email, password, two-step sign-in and access are changed by someone who can manage them there too.")


# ---------------------------------------------------------------------------------------------------------------------
# GET /iam/people
# ---------------------------------------------------------------------------------------------------------------------


def _people_view(db: Session, ctx: TenantContext) -> dict[str, Any]:
    tenant_id = ctx.tenant.id
    scope = Scope(db, ctx)
    all_teams = scope.teams
    rows = db.execute(select(User, UserTenantRole).join(UserTenantRole, UserTenantRole.user_id == User.id).where(UserTenantRole.tenant_id == tenant_id)).all()
    roles = iam_service.roles(db, tenant_id)
    role_by_key = {r.key: r for r in roles}
    names = {user.id: (user.full_name or user.email) for user, _ in rows}
    me_id = ctx.user.id if ctx.user else ""
    # The people one sees: everyone in the teams one works in, and oneself (FTR's peopleInScope).
    visible = [(u, m) for u, m in rows if u.id == me_id or scope.has(m.team_id)]
    now = account_security.utcnow()
    people = []
    for user, m in sorted(visible, key=lambda pair: (pair[0].full_name or pair[0].email).lower()):
        manageable = can_manage(db, ctx, scope, m)
        people.append(
            {
                "id": user.id,
                "email": user.email,
                "name": user.full_name or user.email.split("@")[0],
                "title": m.title or "",
                "role": m.role,
                "roleName": role_by_key[m.role].name if m.role in role_by_key else m.role,
                "teamId": m.team_id,
                "team": next((t.name for t in all_teams if t.id == m.team_id), ""),
                "teamPath": iam_service.path_text(all_teams, m.team_id),
                "leads": [t.name for t in all_teams if user.id in (t.leader_ids or [])],
                "managerId": m.manager_id,
                "manager": names.get(m.manager_id or "", ""),
                "reports": [{"id": u.id, "name": names[u.id]} for u, mm in rows if mm.manager_id == user.id],
                "active": bool(user.is_active),
                "status": iam_service.status_of(user, now),
                "lockedUntil": _iso(user.locked_until) if account_security.locked(user, now) else None,
                "twoStep": account_security.two_step_on(user),
                "signIn": "sso" if user.sso_subject else "password",
                "createdAt": _iso(m.created_at),
                "lastSignInAt": _iso(user.last_login_at),
                "joined": {"at": _iso(m.joined_at), "role": m.joined_role, "teamId": m.joined_team_id, "reviewedAt": _iso(m.reviewed_at), "reviewedBy": m.reviewed_by} if m.joined_at else None,
                "manageable": manageable and user.id != me_id,
                "you": user.id == me_id,
            }
        )
    counts = iam_service.holders(db, tenant_id)
    # People see only the roles at their level and below: those they could give (FTR's grantable).
    seen_roles = [r for r in roles if iam_service.can_grant(ctx.permissions, ctx.role_key, r) or r.key == ctx.role_key]
    managers = (
        sorted(({"id": u.id, "name": names[u.id], "title": m.title or ""} for u, m in rows if u.is_active), key=lambda x: x["name"].lower())
        if "users.manage" in ctx.permissions
        else []
    )
    teams_view = [
        {
            "id": t.id,
            "name": t.name,
            "region": t.region or "",
            "parentId": t.parent_id,
            "leaderIds": list(t.leader_ids or []),
            "path": iam_service.path_text(all_teams, t.id),
            "leaders": [{"id": lid, "name": names.get(lid, "")} for lid in (t.leader_ids or []) if lid in names],
            "members": sum(1 for _, m in rows if m.team_id == t.id),
        }
        for t in all_teams
        if scope.has(t.id) or "teams.manage" in ctx.permissions
    ]
    return {
        "people": people,
        "roles": [{**r.view(), "grantable": iam_service.can_grant(ctx.permissions, ctx.role_key, r), "holders": counts.get(r.key, 0)} for r in seen_roles],
        "teams": teams_view,
        "permissions": [p.view() for p in PERMISSIONS],
        "groups": list(GROUPS),
        "managers": managers,
        "mail": mail_ready(db),
        "me": {"id": me_id, "role": ctx.role_key, "teamId": ctx.membership.team_id if ctx.membership else None, "permissions": sorted(ctx.permissions)},
        "joinersToReview": sum(1 for p in people if p["joined"] and not p["joined"]["reviewedAt"] and p["active"] and p["manageable"]),
    }


@router.get("/iam/people")
def list_people(ctx: TenantContext = Depends(require_tenant), db: Session = Depends(get_db)):
    return _no_store(_people_view(db, ctx))


# ---------------------------------------------------------------------------------------------------------------------
# Adding and changing people
# ---------------------------------------------------------------------------------------------------------------------


def _check_team(db: Session, scope: Scope, team_id: Any) -> str | None:
    if team_id in (None, ""):
        return None
    team_id = str(team_id)
    if not any(t.id == team_id for t in scope.teams):
        raise Refused(400, "Choose their team.")
    if not scope.has(team_id):
        raise Refused(403, "That team is not one you work in.")
    return team_id


def _welcome(db: Session, ctx: TenantContext, user: User, role_name: str, team_name: str) -> Any:
    base = password_reset_service.link_base()
    who = (ctx.user.full_name or ctx.user.email) if ctx.user else "An administrator"
    return mailer.system_email(
        subject="You have access to Hawk AI",
        lines=[
            f"{who} gave you access to Hawk AI ({ctx.tenant.name}) as {role_name}{f' in {team_name}' if team_name else ''}.",
            'To set your password, open the link below, choose "Forgot your password?" and enter this address: a link to choose your password follows. Or sign in with the one-time password your administrator gives you.',
        ],
        buttons=[("Open Hawk AI", f"{base}/login")] if base else [],
        footer="You will be asked to accept the terms of use when you first sign in.",
    )


@router.post("/iam/people")
def add_person(
    background: BackgroundTasks,
    body: Annotated[dict[str, Any] | None, Body()] = None,
    ctx: TenantContext = Depends(require_permission("users.manage")),
    db: Session = Depends(get_db),
):
    body = body or {}
    try:
        scope = Scope(db, ctx)
        role_key = str(body.get("role") or "viewer")
        role = iam_service.role(db, ctx.tenant.id, role_key)
        if role is None:
            raise Refused(400, "Choose a role.")
        if not iam_service.can_grant(ctx.permissions, ctx.role_key, role):
            raise Refused(403, "You cannot give a role with permissions you do not hold.")
        team_id = _check_team(db, scope, body.get("teamId"))
        address = clean(body.get("email"), 254).lower()
        if not EMAIL.match(address):
            raise Refused(400, "Give a valid email address.")
        existing = account_security.find_by_email(db, address)
        if existing is not None and db.scalar(select(UserTenantRole.id).where(UserTenantRole.user_id == existing.id, UserTenantRole.tenant_id == ctx.tenant.id)) is not None:
            raise Refused(409, "Someone with that email already has access.")
        # The activation code's limit of active users in each tenant (/settings/guide/licence).
        activation_service.assert_may_add_member(db, ctx.tenant.id)
        temporary = None
        if existing is None:
            password = str(body.get("password") or "")
            if password:
                problem = password_policy.problem(db, password)
                if problem:
                    raise Refused(400, f"Temporary password: {problem}")
            temporary = password or generate_password()
            user = User(email=address, full_name=clean(body.get("name")) or address.split("@")[0], hashed_password=get_password_hash(temporary), is_active=True, must_change_password=True)
            db.add(user)
            db.flush()
        else:
            # Already signs in to another tenant: added here with the password they have.
            user = existing
        membership = UserTenantRole(user_id=user.id, tenant_id=ctx.tenant.id, role=role.key, team_id=team_id, title=clean(body.get("title")))
        db.add(membership)
        db.flush()
        team_name = next((t.name for t in scope.teams if t.id == team_id), "")
        _record(db, ctx, "user.create", user.email, role=role.name, team=team_name or None, existingAccount=existing is not None or None)
        welcomed = False
        if body.get("sendWelcome") and mail_ready(db):
            background.add_task(_send, _welcome(db, ctx, user, role.name, team_name), user.email)
            welcomed = True
            _record(db, ctx, "user.welcome", user.email)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"user": {"id": user.id, "email": user.email}, "temporary": temporary, "existingAccount": existing is not None, "welcomed": welcomed})


@router.put("/iam/people/{user_id}")
def change_person(
    user_id: str,
    background: BackgroundTasks,
    body: Annotated[dict[str, Any] | None, Body()] = None,
    ctx: TenantContext = Depends(require_permission("users.manage")),
    db: Session = Depends(get_db),
):
    body = body or {}
    try:
        user, membership, scope = _target(db, ctx, user_id)
        me = ctx.user.id if ctx.user else ""
        if user.id == me and (body.get("role") is not None or body.get("active") is False):
            raise Refused(400, "Ask another Admin to change your own role or access.")
        changed: list[str] = []
        global_fields = [k for k in ("name", "email", "active") if k in body]
        if global_fields:
            _everywhere(db, ctx, user)
        if body.get("role") is not None and str(body["role"]) != membership.role:
            role = iam_service.role(db, ctx.tenant.id, str(body["role"]))
            if role is None:
                raise Refused(400, "Choose a role.")
            if not iam_service.can_grant(ctx.permissions, ctx.role_key, role):
                raise Refused(403, "You cannot give a role with permissions you do not hold.")
            iam_service.keep_an_owner(db, membership, user, new_role=role.key)
            membership.role = role.key
            changed.append("role")
        if "teamId" in body:
            team_id = _check_team(db, scope, body.get("teamId"))
            if team_id != membership.team_id:
                membership.team_id = team_id
                changed.append("team")
        if "title" in body:
            membership.title = clean(body.get("title"))
            changed.append("title")
        if "managerId" in body:
            manager_id = str(body.get("managerId") or "") or None
            if manager_id:
                if manager_id == user.id:
                    raise Refused(400, "Nobody reports to themselves.")
                boss = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == manager_id, UserTenantRole.tenant_id == ctx.tenant.id))
                boss_user = db.get(User, manager_id) if boss else None
                if boss is None or boss_user is None or not boss_user.is_active:
                    raise Refused(400, "Choose someone who has access as the one they report to.")
                seen: set[str] = set()
                up = boss
                while up is not None and up.user_id not in seen:
                    if up.user_id == user.id:
                        raise Refused(400, f"{boss_user.full_name or boss_user.email} already reports to {user.full_name or user.email}, directly or through others: that would make a circle.")
                    seen.add(up.user_id)
                    up = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == up.manager_id, UserTenantRole.tenant_id == ctx.tenant.id)) if up.manager_id else None
            if manager_id != membership.manager_id:
                membership.manager_id = manager_id
                changed.append("reportsTo")
        if "name" in body:
            name = clean(body.get("name"))
            if name and name != user.full_name:
                user.full_name = name
                changed.append("name")
        email_before = None
        if "email" in body:
            address = clean(body.get("email"), 254).lower()
            if not EMAIL.match(address):
                raise Refused(400, "Enter a valid email address.")
            if address != user.email.lower():
                taken = account_security.find_by_email(db, address)
                if taken is not None and taken.id != user.id:
                    raise Refused(409, "That email address already signs in here.")
                email_before = user.email
                user.email = address
                changed.append("email")
        if "active" in body:
            active = body.get("active") is True
            if active != bool(user.is_active):
                if active:
                    activation_service.assert_may_add_member(db, ctx.tenant.id)
                else:
                    iam_service.keep_an_owner(db, membership, user, deactivate=True)
                    account_security.sign_out_everywhere(db, user)
                    try:
                        password_reset_service.revoke_user(user.id)
                    except StoreUnavailable:
                        pass
                user.is_active = active
                if active:
                    user.failed_logins = 0
                    user.locked_until = None
                changed.append("access on" if active else "access off")
        if email_before is not None:
            # A reset link sent to the old address must not reset the account now that it is someone else's.
            try:
                password_reset_service.revoke_user(user.id)
            except StoreUnavailable:
                pass
            _tell_email_changed(db, background, email_before, user.email, (ctx.user.email if ctx.user else ""))
        if changed:
            _record(db, ctx, "user.update", email_before or user.email, changed=changed, email=f"{email_before} → {user.email}" if email_before else None, role=membership.role if "role" in changed else None)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True, "changed": changed})


def _tell_email_changed(db: Session, background: BackgroundTasks, before: str, after: str, by: str) -> None:
    """Both addresses hear about a changed sign-in email (CxMissionZero's tellEmailChanged): only when email works."""

    if not mail_ready(db):
        return
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    notes = [
        (before, f"The sign-in email of your Hawk AI account was changed from {before} to {after} by {by}. From now on you sign in with {after}, and links go there."),
        (after, f"This address now signs in to Hawk AI: {by} changed the account's email from {before} to {after}."),
    ]
    for to, line in notes:
        message = mailer.system_email(subject="Your Hawk AI sign-in email was changed", lines=[line], facts=[("Changed at", stamp)], footer="Not expected? Tell an administrator at once.")
        background.add_task(_send, message, to)


@router.post("/iam/people/{user_id}/reset")
def reset_password(user_id: str, ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    """A new temporary password, shown once. Their current one stops working and they are signed out everywhere."""

    try:
        user, _, _ = _target(db, ctx, user_id)
        _everywhere(db, ctx, user)
        temporary = generate_password()
        password_policy.remember(user, get_password_hash(temporary))
        user.must_change_password = True
        user.failed_logins = 0
        user.locked_until = None
        account_security.sign_out_everywhere(db, user)
        try:
            password_reset_service.revoke_user(user.id)
        except StoreUnavailable:
            pass
        _record(db, ctx, "user.reset", user.email)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"temporary": temporary})


@router.post("/iam/people/{user_id}/unlock")
def unlock(user_id: str, ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    """After 5 wrong passwords an account waits 15 minutes (app/services/account_security.py); this lifts it at once."""

    try:
        user, _, _ = _target(db, ctx, user_id)
        _everywhere(db, ctx, user)
        user.failed_logins = 0
        user.locked_until = None
        _record(db, ctx, "user.unlock", user.email)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


@router.post("/iam/people/{user_id}/signout")
def sign_out(user_id: str, ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    try:
        user, _, _ = _target(db, ctx, user_id)
        _everywhere(db, ctx, user)
        count = account_security.sign_out_everywhere(db, user)
        _record(db, ctx, "user.signout", user.email, sessions=count)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


@router.post("/iam/people/{user_id}/two-step-reset")
def reset_two_step(user_id: str, ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    """Two-step sign-in taken off (a lost phone): they set it up again themselves, at once when it is required."""

    try:
        if ctx.user is not None and user_id == ctx.user.id:
            raise Refused(400, "Turn your own two-step sign-in off under Settings → Two-step sign-in.")
        user, _, _ = _target(db, ctx, user_id)
        _everywhere(db, ctx, user)
        if account_security.reset_two_step(user):
            _record(db, ctx, "auth.two_step.reset", user.email)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


@router.post("/iam/people/{user_id}/welcome")
def welcome(user_id: str, background: BackgroundTasks, ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    try:
        user, membership, scope = _target(db, ctx, user_id)
        if not mail_ready(db):
            raise Refused(409, "The email server is not set up and tested yet.")
        role = iam_service.role(db, ctx.tenant.id, membership.role)
        team_name = next((t.name for t in scope.teams if t.id == membership.team_id), "")
        background.add_task(_send, _welcome(db, ctx, user, role.name if role else membership.role, team_name), user.email)
        _record(db, ctx, "user.welcome", user.email)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


@router.delete("/iam/people/{user_id}")
def remove_person(user_id: str, ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    """Remove someone from this tenant. With no tenant left, their account is turned off (it is never deleted: the audit
    log keeps naming them)."""

    try:
        if ctx.user is not None and user_id == ctx.user.id:
            raise Refused(400, "Ask another Admin to remove you.")
        user, membership, _ = _target(db, ctx, user_id)
        iam_service.keep_an_owner(db, membership, user, remove=True)
        db.delete(membership)
        iam_service.forget_leader(db, ctx.tenant.id, user.id)
        # Those who reported to them report to whom they reported to (or to nobody).
        for m in db.scalars(select(UserTenantRole).where(UserTenantRole.tenant_id == ctx.tenant.id, UserTenantRole.manager_id == user.id)):
            m.manager_id = membership.manager_id
        db.flush()
        if db.scalar(select(UserTenantRole.id).where(UserTenantRole.user_id == user.id).limit(1)) is None:
            user.is_active = False
            account_security.sign_out_everywhere(db, user)
        _record(db, ctx, "user.remove", user.email)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


@router.post("/iam/people/{user_id}/approve")
def approve(user_id: str, ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    """Approved: their team and role are right (changed first, as for anyone, where they were not)."""

    try:
        user, membership, scope = _target(db, ctx, user_id)
        if membership.joined_at is None:
            raise Refused(400, "Only someone who joined by themselves is approved.")
        membership.reviewed_at = datetime.now(timezone.utc)
        membership.reviewed_by = (ctx.user.full_name or ctx.user.email) if ctx.user else ""
        names = {t.id: t.name for t in scope.teams}
        _record(
            db,
            ctx,
            "user.join.approve",
            user.email,
            team=names.get(membership.team_id or ""),
            role=membership.role,
            asked={"team": names.get(membership.joined_team_id or ""), "role": membership.joined_role},
        )
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


# ---------------------------------------------------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------------------------------------------------


@router.put("/iam/roles/{role_id}")
def save_role(role_id: str, body: Annotated[dict[str, Any] | None, Body()] = None, ctx: TenantContext = Depends(require_permission("roles.manage")), db: Session = Depends(get_db)):
    body = body or {}
    try:
        saved = iam_service.save_role(
            db,
            ctx.tenant.id,
            None if role_id == "new" else role_id,
            name=body.get("name"),
            description=body.get("description"),
            permissions=body.get("permissions"),
            actor_permissions=ctx.permissions,
            actor_role_key=ctx.role_key,
        )
        _record(db, ctx, "role.save", saved.name, role=saved.key, permissions=sorted(saved.permissions))
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"role": saved.view()})


@router.delete("/iam/roles/{role_id}")
def remove_role(role_id: str, ctx: TenantContext = Depends(require_permission("roles.manage")), db: Session = Depends(get_db)):
    try:
        gone = iam_service.remove_role(db, ctx.tenant.id, role_id, actor_permissions=ctx.permissions, actor_role_key=ctx.role_key)
        _record(db, ctx, "role.remove", gone.name, role=gone.key)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


# ---------------------------------------------------------------------------------------------------------------------
# Teams (within the teams one works in; at the top only with "See every team")
# ---------------------------------------------------------------------------------------------------------------------


def _team_in_scope(scope: Scope, team_id: str | None) -> None:
    if not team_id:
        if not scope.all:
            raise Refused(403, "Only someone who sees every team can add a team at the top.")
        return
    if not scope.has(team_id):
        raise Refused(403, "That team is outside the teams you manage.")


def _valid_leaders(db: Session, ctx: TenantContext, scope: Scope, ids: Any) -> list[str]:
    if not isinstance(ids, list):
        return []
    out = []
    for raw in ids:
        m = db.scalar(select(UserTenantRole).where(UserTenantRole.user_id == str(raw), UserTenantRole.tenant_id == ctx.tenant.id))
        if m is None:
            continue
        if not scope.has(m.team_id):
            raise Refused(403, "A leader must be someone from the teams you manage.")
        out.append(m.user_id)
    return out


@router.post("/iam/teams")
def create_team(body: Annotated[dict[str, Any] | None, Body()] = None, ctx: TenantContext = Depends(require_permission("teams.manage")), db: Session = Depends(get_db)):
    body = body or {}
    try:
        scope = Scope(db, ctx)
        parent = str(body.get("parentId") or "") or None
        _team_in_scope(scope, parent)
        team = iam_service.create_team(db, ctx.tenant.id, name=body.get("name"), region=body.get("region"), parent_id=parent, leader_ids=_valid_leaders(db, ctx, scope, body.get("leaderIds")))
        _record(db, ctx, "team.create", team.name)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"team": {"id": team.id, "name": team.name}})


@router.put("/iam/teams/{team_id}")
def change_team(team_id: str, body: Annotated[dict[str, Any] | None, Body()] = None, ctx: TenantContext = Depends(require_permission("teams.manage")), db: Session = Depends(get_db)):
    body = body or {}
    try:
        scope = Scope(db, ctx)
        _team_in_scope(scope, team_id)
        parent: Any = ...
        if "parentId" in body:
            parent = str(body.get("parentId") or "") or None
            _team_in_scope(scope, parent)
        team = iam_service.update_team(
            db,
            ctx.tenant.id,
            team_id,
            name=body.get("name"),
            region=body.get("region"),
            parent_id=parent,
            leader_ids=_valid_leaders(db, ctx, scope, body.get("leaderIds")) if "leaderIds" in body else None,
        )
        _record(db, ctx, "team.update", team.name, changed=sorted(body.keys()))
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"team": {"id": team.id, "name": team.name}})


@router.delete("/iam/teams/{team_id}")
def delete_team(team_id: str, ctx: TenantContext = Depends(require_permission("teams.manage")), db: Session = Depends(get_db)):
    try:
        scope = Scope(db, ctx)
        _team_in_scope(scope, team_id)
        team = iam_service.remove_team(db, ctx.tenant.id, team_id)
        _record(db, ctx, "team.remove", team.name)
        db.commit()
    except Refused as refusal:
        db.rollback()
        return _refused(refusal.status_code, refusal.message)
    return _no_store({"ok": True})


# ---------------------------------------------------------------------------------------------------------------------
# Joining by oneself (FTR CC-01.116.00: "people join by themselves; whoever manages people reviews them")
# ---------------------------------------------------------------------------------------------------------------------

JOIN_ASKED = "Check your inbox. If the address may join, an email is on its way: a link to finish joining, or, if you already have access, how to sign in. It works once, for 30 minutes. Nothing arrived? Check spam, or ask an Admin."
JOIN_DEAD = "This link no longer works: it was used, a newer one was sent, or it is more than 30 minutes old. Ask for a new one."
JOIN_TTL_SECONDS = 30 * 60
JOIN_PER_IP = 10
JOIN_IP_WINDOW = 15 * 60
JOIN_PER_ADDRESS_PER_HOUR = 3
#: A role that manages people, roles or teams, sees every team, or holds an Admin-only permission is never offered.
NEVER = frozenset({"users.manage", "roles.manage", "teams.manage", "scope.all"}) | ADMIN_ONLY


def _openable(role: iam_service.Role | None) -> bool:
    return role is not None and role.key not in LOCKED_ROLES and not (role.permissions & NEVER)


def join_rules(db: Session, tenant_id: str) -> dict[str, Any]:
    """The rules an Admin chose (Settings → People → Sign-in): off, no domain, every role open to joining, until set."""

    row = db.get(IamJoinSettings, tenant_id)
    all_roles = iam_service.roles(db, tenant_id)
    chosen = [str(r) for r in row.roles] if row is not None and row.roles is not None else [r.key for r in all_roles]
    open_keys = [r.key for r in all_roles if _openable(r) and r.key in chosen]
    return {"enabled": bool(row.enabled) if row is not None else False, "domains": [str(d) for d in (row.domains or [])] if row is not None else [], "roles": open_keys}


def join_ready(db: Session, tenant_id: str) -> dict[str, Any]:
    rules = join_rules(db, tenant_id)
    missing = []
    if not rules["enabled"]:
        missing.append("Turned off: an Admin turns it on here.")
    if not rules["domains"]:
        missing.append("No email domain is allowed to join.")
    if not mail_ready(db):
        missing.append("The email server is not set up and tested (Settings → Sign-in).")
    if not password_reset_service.link_base():
        missing.append("PUBLIC_URL is not set to the https address people use.")
    if not rules["roles"]:
        missing.append("No role is open to joining.")
    return {"ready": not missing, "missing": missing}


def _tenant_by_slug(db: Session, workspace: Any) -> Tenant | None:
    slug = clean(workspace, 100).lower()
    if not slug:
        return None
    tenant = db.scalar(select(Tenant).where(func.lower(Tenant.slug) == slug))
    return tenant if tenant is not None and tenant.is_active else None


def _key(token: str) -> str:
    return hashlib.sha256(f"hawk-join\n{token}".encode("utf-8")).hexdigest()


def _ip_blocked(ip: str) -> bool:
    return sign_in_store.store().count(f"join-ip:{ip or 'unknown'}", JOIN_IP_WINDOW, sign_in_store.now()) >= JOIN_PER_IP


def _note_ip(ip: str) -> None:
    sign_in_store.store().hit(f"join-ip:{ip or 'unknown'}", JOIN_IP_WINDOW, sign_in_store.now())


@router.get("/auth/join")
def join_available(workspace: str = Query(default="", max_length=100), db: Session = Depends(get_db)):
    tenant = _tenant_by_slug(db, workspace)
    if tenant is None:
        return _no_store({"available": False, "domains": []})
    rules = join_rules(db, tenant.id)
    available = join_ready(db, tenant.id)["ready"]
    db.commit()
    return _no_store({"available": available, "domains": rules["domains"] if available else []})


def _join_email(db: Session, tenant: Tenant, email: str, ip: str) -> tuple[Any, str] | None:
    """What is emailed, by whether the address has access (FTR's answer()). None: nothing is sent."""

    user = account_security.find_by_email(db, email)
    footer = f"You get this because someone asked to join Hawk AI ({tenant.name}) with this address from the sign-in page. Did not ask? Ignore it: nothing changes."
    base = password_reset_service.link_base()
    if user is not None:
        member = db.scalar(select(UserTenantRole.id).where(UserTenantRole.user_id == user.id, UserTenantRole.tenant_id == tenant.id)) is not None
        if not user.is_active:
            outcome = "access turned off"
            lines = [f"You already have an account ({email}), but its access is turned off.", "Ask an Admin to turn it on again."]
        elif member:
            outcome = "has access"
            lines = [f"You already have an account on Hawk AI ({email}) in {tenant.name}.", 'Sign in with your password, or with single sign-on if your organisation uses it. Forgotten? Use "Forgot your password?" on the sign-in page, or ask an Admin.']
        else:
            outcome = "has an account elsewhere"
            lines = [f"You already have a Hawk AI account ({email}).", f"Sign in with it, and ask an Admin of {tenant.name} to add you there."]
        _record(db, None, "join.asked", email, tenant_id=tenant.id, actor_id=user.id, outcome=outcome, ip=ip)
        return mailer.system_email(subject="Your access to Hawk AI", lines=lines, buttons=[("Open Hawk AI", f"{base}/login")] if base else [], footer=footer), email
    store = sign_in_store.store()
    now = sign_in_store.now()
    sent_key = f"join-sent:{tenant.id}:{hashlib.sha256(email.encode()).hexdigest()}"
    if len(store.times(sent_key, 3600, now)) >= JOIN_PER_ADDRESS_PER_HOUR:
        _record(db, None, "join.asked", email, tenant_id=tenant.id, outcome="new: asked too often", ip=ip)
        return None
    pointer = f"join-email:{tenant.id}:{hashlib.sha256(email.encode()).hexdigest()}"
    old = store.take(pointer)
    if old and old.get("key"):
        store.delete(f"join:{old['key']}")
    token = secrets.token_urlsafe(32)
    key = _key(token)
    exp = now + JOIN_TTL_SECONDS
    store.put(f"join:{key}", {"email": email, "tenant_id": tenant.id, "exp": exp}, JOIN_TTL_SECONDS + 5)
    store.put(pointer, {"key": key}, JOIN_TTL_SECONDS + 5)
    store.hit(sent_key, 3600, now)
    _record(db, None, "join.asked", email, tenant_id=tenant.id, outcome="new: link to join", ip=ip)
    return (
        mailer.system_email(
            subject="Finish joining Hawk AI",
            lines=[f"Welcome. To finish joining {tenant.name} on Hawk AI with {email}, open this link: give your name, choose your team and your role, and a password.", "It works once, for 30 minutes. An Admin reviews everyone who joins."],
            buttons=[("Finish joining", f"{base}/join#token={token}")],
            footer=footer,
        ),
        email,
    )


@router.post("/auth/join")
def ask_to_join(request: Request, background: BackgroundTasks, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    body = body or {}
    ip = account_security.client_ip(request)
    tenant = _tenant_by_slug(db, body.get("workspace"))
    if tenant is None or not join_ready(db, tenant.id)["ready"]:
        return _refused(409, "Joining by yourself is not available here: ask an Admin to add you.")
    try:
        if _ip_blocked(ip):
            return _refused(429, "Too many requests from this address. Wait a quarter of an hour.")
        _note_ip(ip)
    except StoreUnavailable:
        return _refused(503, "Joining is unavailable for a moment. Try again shortly.")
    email = clean(body.get("email"), 254).lower()
    if not EMAIL.match(email):
        return _refused(400, "Enter your work email address.")
    domains = join_rules(db, tenant.id)["domains"]
    # Which domains may join is no secret: said on the page, so a personal address gets a plain answer.
    if email.split("@")[-1] not in domains:
        return _refused(400, f"Use your {' or '.join('@' + d for d in domains)} address.")
    try:
        outgoing = _join_email(db, tenant, email, ip)
    except StoreUnavailable:
        outgoing = None
    db.commit()
    if outgoing is not None:
        background.add_task(_send, outgoing[0], outgoing[1])
    return _no_store({"message": JOIN_ASKED}, 202)


def _live_link(db: Session, request: Request, token: Any) -> tuple[Tenant, str]:
    ip = account_security.client_ip(request)
    if _ip_blocked(ip):
        raise Refused(429, "Too many requests from this address. Wait a quarter of an hour.")
    text = str(token or "")
    link = sign_in_store.store().get(f"join:{_key(text)}") if re.fullmatch(r"[A-Za-z0-9_-]{43}", text) else None
    tenant = db.get(Tenant, str(link.get("tenant_id") or "")) if link else None
    email = str(link.get("email") or "") if link else ""
    if not link or float(link.get("exp", 0)) <= sign_in_store.now() or tenant is None or not tenant.is_active or not join_ready(db, tenant.id)["ready"] or email.split("@")[-1] not in join_rules(db, tenant.id)["domains"]:
        _note_ip(ip)
        raise Refused(400, JOIN_DEAD)
    if account_security.find_by_email(db, email) is not None:
        raise Refused(409, 'This address has joined already: sign in, or use "Forgot your password?".')
    return tenant, email


@router.post("/auth/join/check")
def check_join_link(request: Request, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    try:
        tenant, email = _live_link(db, request, (body or {}).get("token"))
    except StoreUnavailable:
        return _refused(503, "Joining is unavailable for a moment. Try again shortly.")
    except Refused as refusal:
        return _refused(refusal.status_code, refusal.message)
    all_teams = iam_service.teams(db, tenant.id)
    rules = join_rules(db, tenant.id)
    roles = {r.key: r for r in iam_service.roles(db, tenant.id)}
    name = " ".join(w[:1].upper() + w[1:] for w in re.split(r"[._-]", email.split("@")[0]) if w)
    return _no_store(
        {
            "email": email,
            "name": name,
            "workspace": tenant.name,
            "teams": sorted(({"id": t.id, "path": iam_service.path_text(all_teams, t.id)} for t in all_teams), key=lambda t: t["path"].lower()),
            "roles": [{"id": key, "name": roles[key].name, "description": roles[key].description} for key in rules["roles"] if key in roles],
            "twoStepRequired": account_security.two_step_required(db),
        }
    )


@router.post("/auth/join/confirm")
def confirm_join(request: Request, body: Annotated[dict[str, Any] | None, Body()] = None, db: Session = Depends(get_db)):
    body = body or {}
    try:
        tenant, email = _live_link(db, request, body.get("token"))
        name = clean(body.get("name"))
        if not name:
            raise Refused(400, "Give your name.")
        all_teams = iam_service.teams(db, tenant.id)
        team_id = str(body.get("teamId") or "") or None
        if all_teams and not any(t.id == team_id for t in all_teams):
            raise Refused(400, "Choose your team.")
        if not all_teams:
            team_id = None
        role_key = str(body.get("role") or "")
        if role_key not in join_rules(db, tenant.id)["roles"]:
            raise Refused(400, "Choose your role from the list.")
        password = str(body.get("password") or "")
        problem = password_policy.problem(db, password)
        if problem:
            raise Refused(400, problem)
        # The activation code's limit of active users in each tenant (/settings/guide/licence).
        activation_service.assert_may_add_member(db, tenant.id)
        # The link is spent first: a second press of the button cannot make a second person.
        if not sign_in_store.store().take(f"join:{_key(str(body.get('token') or ''))}"):
            raise Refused(400, JOIN_DEAD)
    except StoreUnavailable:
        return _refused(503, "Joining is unavailable for a moment. Try again shortly.")
    except Refused as refusal:
        return _refused(refusal.status_code, refusal.message)
    now = datetime.now(timezone.utc)
    user = User(email=email, full_name=name, hashed_password=get_password_hash(password), is_active=True, must_change_password=False)
    db.add(user)
    db.flush()
    db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role_key, team_id=team_id, title=clean(body.get("title")), joined_at=now, joined_role=role_key, joined_team_id=team_id))
    _record(db, None, "user.join", email, tenant_id=tenant.id, actor_id=user.id, team=next((t.name for t in all_teams if t.id == team_id), None), role=role_key)
    # Required two-step sign-in (/settings/guide/people-and-access): no tokens before the second step is set up. They sign in, and the
    # sign-in page walks them through it.
    if account_security.needs_two_step(db, user):
        db.commit()
        return _no_store({"ok": True, "twoStep": True, "message": "You have joined. Sign in with your email and password: two-step sign-in is required here, so you set it up first."})
    from app.api.routers.auth import signed_in_response

    account_security.record_sign_in(user)
    result = signed_in_response(db, user)
    db.commit()
    # The console's session: the tokens as cookies (app/core/session_cookies.py).
    return session_cookies.answer(request, json.loads(result.model_dump_json()))


@router.get("/iam/join-settings")
def get_join_settings(ctx: TenantContext = Depends(require_permission("users.manage")), db: Session = Depends(get_db)):
    rules = join_rules(db, ctx.tenant.id)
    view = {
        **rules,
        "ready": join_ready(db, ctx.tenant.id),
        "workspace": ctx.tenant.slug,
        "canChange": "settings.manage" in ctx.permissions,
        "allRoles": [{"id": r.key, "name": r.name, "open": _openable(r)} for r in iam_service.roles(db, ctx.tenant.id)],
        "twoStepRequired": account_security.two_step_required(db),
    }
    db.commit()
    return _no_store(view)


@router.put("/iam/join-settings")
def put_join_settings(body: Annotated[dict[str, Any] | None, Body()] = None, ctx: TenantContext = Depends(require_permission("settings.manage")), db: Session = Depends(get_db)):
    body = body or {}
    rules = join_rules(db, ctx.tenant.id)
    if "enabled" in body:
        rules["enabled"] = body.get("enabled") is True
    if "domains" in body:
        try:
            domains = account_security.clean_domains(body.get("domains"))
        except ValueError as error:
            return _refused(400, str(error))
        if not domains:
            return _refused(400, "Give one or more email domains, such as company.com.")
        rules["domains"] = domains[:10]
    if "roles" in body:
        wanted = [str(x) for x in (body.get("roles") if isinstance(body.get("roles"), list) else [])]
        all_roles = {r.key: r for r in iam_service.roles(db, ctx.tenant.id)}
        if any(not _openable(all_roles.get(key)) for key in wanted):
            return _refused(400, "A role that manages people, roles or teams, or sees every team, cannot be chosen when joining.")
        rules["roles"] = wanted
    row = db.get(IamJoinSettings, ctx.tenant.id)
    if row is None:
        row = IamJoinSettings(tenant_id=ctx.tenant.id, enabled=False, domains=[], roles=[])
        db.add(row)
    row.enabled = rules["enabled"]
    row.domains = rules["domains"]
    row.roles = rules["roles"]
    row.updated_by = ctx.user.email if ctx.user else ""
    _record(db, ctx, "settings.join", "on" if rules["enabled"] else "off", domains=rules["domains"], roles=rules["roles"])
    db.commit()
    return get_join_settings(ctx, db)
