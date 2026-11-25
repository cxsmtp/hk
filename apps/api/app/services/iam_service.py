"""Roles, people and teams of a tenant, ported from FTR Command Center's server/iam.js (roles, canGrant, the last Admin),
server/rbac.js (scopeOf, peopleInScope, subtree, wouldLoop) and server/teams.js, with CxMissionZero's src/iam.js for
what FTR does not have (changing someone's sign-in email).

- A role is a set of permissions (app/core/permissions.py). The built-in roles need no row; a row renames one, or
  changes what a role that is not locked holds. Owner and Admin are locked: they always hold every permission.
- Nobody hands out more than they hold: a role can be given, built or changed only by someone holding every one of its
  permissions; only an Owner gives or takes the Owner role. People see only the roles they could give.
- There is always at least one active Owner in a tenant.
- Teams form a tree with leaders. A person works in their own team and every team below the ones they lead; with "See
  every team", in all of them. Teams decide whose people one sees and manages (FTR: and whose accounts; Hawk's records
  belong to the tenant, not to a team, so in Hawk teams scope people only).
"""

from __future__ import annotations

import re
import secrets
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.permissions import (
    ADMIN_ONLY,
    BUILTIN_ORDER,
    BUILTIN_ROLES,
    LOCKED_ROLES,
    PERMISSION_IDS,
    clean_permissions,
    default_permissions,
    legacy_floor,
)
from app.db.models.iam import IamRole, IamTeam
from app.db.models.user import User, UserTenantRole


class Refused(HTTPException):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(status_code=status_code, detail=message)
        self.message = message


_CONTROL = re.compile(r"[\u0000-\u001f\u007f]")


def clean(value: Any, limit: int = 120) -> str:
    """FTR's clean(): no control characters, single spaces, trimmed, at most ``limit`` characters."""

    return re.sub(r"\s+", " ", _CONTROL.sub(" ", str(value if value is not None else ""))).strip()[:limit]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------------------------------------------------


@dataclass
class Role:
    key: str
    name: str
    description: str
    permissions: frozenset[str]
    builtin: bool
    locked: bool

    def view(self) -> dict[str, Any]:
        return {
            "id": self.key,
            "name": self.name,
            "description": self.description,
            "permissions": [pid for pid in PERMISSION_IDS if pid in self.permissions],
            "builtin": self.builtin,
            "locked": self.locked,
        }


def _role_from(key: str, row: IamRole | None) -> Role | None:
    if key in BUILTIN_ROLES:
        meta = BUILTIN_ROLES[key]
        locked = bool(meta["locked"])
        if locked or row is None or row.permissions is None:
            permissions = default_permissions(key)
        else:
            # A built-in role that is not locked never holds an Admin-only permission (FTR's normalise()).
            permissions = frozenset(clean_permissions(row.permissions)) - ADMIN_ONLY
        return Role(
            key=key,
            name=(row.name if row is not None and row.name else str(meta["name"])),
            description=(row.description if row is not None and row.description else str(meta["description"])),
            permissions=permissions,
            builtin=True,
            locked=locked,
        )
    if row is None:
        return None
    return Role(key=key, name=row.name or key, description=row.description or "", permissions=frozenset(clean_permissions(row.permissions or [])) - ADMIN_ONLY, builtin=False, locked=False)


def role(db: Session, tenant_id: str, key: str) -> Role | None:
    if key in BUILTIN_ROLES and not _roles_table(db):
        return _role_from(key, None)
    row = db.scalar(select(IamRole).where(IamRole.tenant_id == tenant_id, IamRole.key == key))
    return _role_from(key, row)


def _roles_table(db: Session) -> bool:
    """Whether iam_roles is there. Always, once migration 0099 has run; a database made with only some tables (tests of
    one feature) has none, and then the built-in roles hold their defaults. Asked once per engine."""

    try:
        bind = db.get_bind()
        engine = getattr(bind, "engine", bind)
        known = _TABLE_SEEN.get(engine)
    except Exception:  # noqa: BLE001 - a session we cannot inspect: ask the table itself
        return True
    if known is None:
        from sqlalchemy import inspect as sa_inspect

        try:
            known = sa_inspect(bind).has_table(IamRole.__tablename__)
        except Exception:  # noqa: BLE001 - not known: ask the table itself, as when it is there
            return True
        if known:
            _TABLE_SEEN[engine] = True
    return bool(known)


_TABLE_SEEN: "weakref.WeakKeyDictionary[Any, bool]" = weakref.WeakKeyDictionary()


def resolve(db: Session, tenant_id: str, key: str) -> tuple[frozenset[str], str]:
    """What a membership's role holds in its tenant, and the highest built-in role that covers it. A role that no longer
    exists holds nothing (as a role name the old order did not know passed no check)."""

    found = role(db, tenant_id, key)
    permissions = found.permissions if found else frozenset()
    return permissions, legacy_floor(permissions, key)


def roles(db: Session, tenant_id: str) -> list[Role]:
    """Every role of the tenant: the built-in ones highest first, then the ones made here by name."""

    rows = {row.key: row for row in db.scalars(select(IamRole).where(IamRole.tenant_id == tenant_id))}
    out = [_role_from(key, rows.get(key)) for key in BUILTIN_ORDER]
    made = sorted((row for key, row in rows.items() if key not in BUILTIN_ROLES), key=lambda r: (r.name or r.key).lower())
    out.extend(_role_from(row.key, row) for row in made)
    return [r for r in out if r is not None]


def emails_holding(db: Session, tenant_id: str, permission: str) -> list[str]:
    """The addresses of the active people of a tenant whose role holds this permission (whatever the role is called:
    a role made here holds it as much as a built-in one). Lower case, sorted, once each."""

    rows = db.execute(
        select(User.email, UserTenantRole.role)
        .join(UserTenantRole, UserTenantRole.user_id == User.id)
        .where(UserTenantRole.tenant_id == tenant_id, User.is_active.is_(True))
    ).all()
    holds: dict[str, bool] = {}
    out: set[str] = set()
    for email, key in rows:
        if not email:
            continue
        if key not in holds:
            found = role(db, tenant_id, str(key or ""))
            holds[key] = bool(found and permission in found.permissions)
        if holds[key]:
            out.add(str(email).lower())
    return sorted(out)


def holders(db: Session, tenant_id: str) -> dict[str, int]:
    return {key: int(n) for key, n in db.execute(select(UserTenantRole.role, func.count()).where(UserTenantRole.tenant_id == tenant_id).group_by(UserTenantRole.role))}


def can_grant(actor_permissions: frozenset[str], actor_role_key: str, target: Role | None) -> bool:
    """May someone holding ``actor_permissions`` give this role (every one of its permissions is theirs)? Only an Owner
    gives the Owner role (Owner and Admin hold the same permissions; the Owner ranks above)."""

    if target is None:
        return False
    if target.key == "owner" and actor_role_key != "owner":
        return False
    return target.permissions <= actor_permissions


def _new_key(db: Session, tenant_id: str) -> str:
    while True:
        key = f"role-{secrets.token_hex(4)}"
        if db.scalar(select(IamRole.id).where(IamRole.tenant_id == tenant_id, IamRole.key == key)) is None:
            return key


def save_role(
    db: Session,
    tenant_id: str,
    key: str | None,
    *,
    name: Any,
    description: Any,
    permissions: Any,
    actor_permissions: frozenset[str],
    actor_role_key: str,
) -> Role:
    """FTR's saveRole: changed by its own id, or made new (key None). Never with permissions the actor does not hold,
    never an Admin-only permission outside the locked roles; a locked role is only renamed and described."""

    if key is not None:
        existing = role(db, tenant_id, key)
        if existing is None:
            raise Refused(404, "That role no longer exists.")
        if not can_grant(actor_permissions, actor_role_key, existing):
            raise Refused(403, "You cannot change a role with permissions you do not hold.")
    else:
        existing = None
    row = db.scalar(select(IamRole).where(IamRole.tenant_id == tenant_id, IamRole.key == key)) if key is not None else None
    label = clean(name, 60)
    if existing is not None and existing.locked:
        if row is None:
            row = IamRole(tenant_id=tenant_id, key=key, name=label or existing.name, description=existing.description, permissions=None, builtin=True)
            db.add(row)
        row.name = label or existing.name
        if description is not None:
            row.description = clean(description, 300)
        db.flush()
        return role(db, tenant_id, key)  # type: ignore[arg-type,return-value]
    wanted = frozenset(clean_permissions(permissions if permissions is not None else (existing.permissions if existing else [])))
    if wanted - actor_permissions:
        raise Refused(403, "A role cannot be given permissions you do not hold.")
    if wanted & ADMIN_ONLY:
        raise Refused(403, "HTTPS, sign-in and single sign-on, updates, backups, activation codes, the network and settings stay with the Owner and Admin roles: no other role can hold them.")
    if row is None:
        if key is None:
            key = _new_key(db, tenant_id)
        meta = BUILTIN_ROLES.get(key)
        row = IamRole(tenant_id=tenant_id, key=key, name=str(meta["name"]) if meta else "New role", description=str(meta["description"]) if meta else "", builtin=bool(meta))
        db.add(row)
    row.name = label or row.name or "New role"
    if description is not None:
        row.description = clean(description, 300)
    row.permissions = [pid for pid in PERMISSION_IDS if pid in wanted]
    db.flush()
    return role(db, tenant_id, row.key)  # type: ignore[return-value]


def remove_role(db: Session, tenant_id: str, key: str, *, actor_permissions: frozenset[str], actor_role_key: str) -> Role:
    found = role(db, tenant_id, key)
    if found is None:
        raise Refused(404, "That role no longer exists.")
    if found.builtin:
        raise Refused(400, "Built-in roles cannot be removed.")
    if not can_grant(actor_permissions, actor_role_key, found):
        raise Refused(403, "You cannot remove a role with permissions you do not hold.")
    if db.scalar(select(UserTenantRole.id).where(UserTenantRole.tenant_id == tenant_id, UserTenantRole.role == key).limit(1)) is not None:
        raise Refused(409, "People still have that role: give them another first.")
    if key in join_roles_of(db, tenant_id):
        from app.db.models.iam import IamJoinSettings

        settings_row = db.get(IamJoinSettings, tenant_id)
        if settings_row is not None:
            settings_row.roles = [r for r in (settings_row.roles or []) if r != key]
    db.query(IamRole).filter(IamRole.tenant_id == tenant_id, IamRole.key == key).delete()
    db.flush()
    return found


def join_roles_of(db: Session, tenant_id: str) -> list[str]:
    from app.db.models.iam import IamJoinSettings

    row = db.get(IamJoinSettings, tenant_id)
    return [str(r) for r in (row.roles or [])] if row is not None else []


# ---------------------------------------------------------------------------------------------------------------------
# Teams (server/rbac.js, server/teams.js)
# ---------------------------------------------------------------------------------------------------------------------


def teams(db: Session, tenant_id: str) -> list[IamTeam]:
    return list(db.scalars(select(IamTeam).where(IamTeam.tenant_id == tenant_id).order_by(IamTeam.name)))


def subtree(all_teams: list[IamTeam], root_id: str | None) -> set[str]:
    """A team and every team below it."""

    children: dict[str | None, list[IamTeam]] = {}
    for t in all_teams:
        children.setdefault(t.parent_id, []).append(t)
    out: set[str] = set()
    if not root_id or not any(t.id == root_id for t in all_teams):
        return out
    stack = [root_id]
    while stack:
        current = stack.pop()
        if current in out:
            continue
        out.add(current)
        stack.extend(c.id for c in children.get(current, []))
    return out


def team_path(all_teams: list[IamTeam], team_id: str | None) -> list[IamTeam]:
    by_id = {t.id: t for t in all_teams}
    out: list[IamTeam] = []
    current = by_id.get(team_id or "")
    seen: set[str] = set()
    while current is not None and current.id not in seen and len(out) < 50:
        out.insert(0, current)
        seen.add(current.id)
        current = by_id.get(current.parent_id or "")
    return out


def path_text(all_teams: list[IamTeam], team_id: str | None) -> str:
    return " › ".join(t.name for t in team_path(all_teams, team_id))


def would_loop(all_teams: list[IamTeam], team_id: str, parent_id: str | None) -> bool:
    return bool(parent_id) and parent_id in subtree(all_teams, team_id)


def scope_of(user_id: str, team_id: str | None, permissions: frozenset[str], all_teams: list[IamTeam]) -> set[str]:
    """The teams a person works in: their own, every team below each team they lead, or every team."""

    if "scope.all" in permissions:
        return {t.id for t in all_teams}
    out: set[str] = set()
    if team_id and any(t.id == team_id for t in all_teams):
        out.add(team_id)
    for t in all_teams:
        if user_id in (t.leader_ids or []):
            out |= subtree(all_teams, t.id)
    return out


def create_team(db: Session, tenant_id: str, *, name: Any, region: Any = "", parent_id: str | None = None, leader_ids: list[str] | None = None) -> IamTeam:
    label = clean(name, 80)
    if not label:
        raise Refused(400, "Give the team a name.")
    if parent_id and db.scalar(select(IamTeam).where(IamTeam.tenant_id == tenant_id, IamTeam.id == parent_id)) is None:
        raise Refused(400, "The team above it no longer exists.")
    team = IamTeam(tenant_id=tenant_id, name=label, region=clean(region, 60), parent_id=parent_id or None, leader_ids=list(dict.fromkeys(leader_ids or []))[:20])
    db.add(team)
    db.flush()
    return team


def update_team(db: Session, tenant_id: str, team_id: str, *, name: Any = None, region: Any = None, parent_id: Any = ..., leader_ids: list[str] | None = None) -> IamTeam:
    all_teams = teams(db, tenant_id)
    team = next((t for t in all_teams if t.id == team_id), None)
    if team is None:
        raise Refused(404, "That team no longer exists.")
    if name is not None:
        team.name = clean(name, 80) or team.name
    if region is not None:
        team.region = clean(region, 60)
    if parent_id is not ...:
        if parent_id and not any(t.id == parent_id for t in all_teams):
            raise Refused(400, "The team above it no longer exists.")
        if parent_id == team_id or would_loop(all_teams, team_id, parent_id):
            raise Refused(400, "A team cannot sit below itself or one of its own teams.")
        team.parent_id = parent_id or None
    if leader_ids is not None:
        team.leader_ids = list(dict.fromkeys(str(x) for x in leader_ids))[:20]
    db.flush()
    return team


def remove_team(db: Session, tenant_id: str, team_id: str) -> IamTeam:
    all_teams = teams(db, tenant_id)
    team = next((t for t in all_teams if t.id == team_id), None)
    if team is None:
        raise Refused(404, "That team no longer exists.")
    if any(t.parent_id == team_id for t in all_teams):
        raise Refused(409, "Move or remove the teams below it first.")
    if db.scalar(select(UserTenantRole.id).where(UserTenantRole.tenant_id == tenant_id, UserTenantRole.team_id == team_id).limit(1)) is not None:
        raise Refused(409, "Move its people to another team first.")
    db.delete(team)
    db.flush()
    return team


def forget_leader(db: Session, tenant_id: str, user_id: str) -> None:
    """Someone removed from the tenant: no longer leads anything."""

    for t in teams(db, tenant_id):
        if user_id in (t.leader_ids or []):
            t.leader_ids = [x for x in t.leader_ids if x != user_id]


# ---------------------------------------------------------------------------------------------------------------------
# People
# ---------------------------------------------------------------------------------------------------------------------


def active_owners(db: Session, tenant_id: str, *, except_user: str | None = None) -> int:
    query = (
        select(func.count())
        .select_from(UserTenantRole)
        .join(User, User.id == UserTenantRole.user_id)
        .where(UserTenantRole.tenant_id == tenant_id, UserTenantRole.role == "owner", User.is_active.is_(True))
    )
    if except_user:
        query = query.where(UserTenantRole.user_id != except_user)
    return int(db.scalar(query) or 0)


def keep_an_owner(db: Session, membership: UserTenantRole, user: User, *, new_role: str | None = None, deactivate: bool = False, remove: bool = False) -> None:
    """There must always be at least one active Owner (FTR: at least one active Admin)."""

    if membership.role != "owner" or not user.is_active:
        return
    losing = remove or deactivate or (new_role is not None and new_role != "owner")
    if losing and active_owners(db, membership.tenant_id, except_user=user.id) == 0:
        raise Refused(409, "There must always be at least one active Owner.")


def status_of(user: User, now: datetime | None = None) -> str:
    """FTR's statusOf: off, locked (too many wrong passwords), must set password, or active."""

    from app.services import account_security

    if not user.is_active:
        return "disabled"
    if account_security.locked(user, now):
        return "locked"
    if user.must_change_password:
        return "pending"
    return "active"
