"""Editable roles change nobody's access on upgrade (app/core/permissions.py, app/core/rbac.py).

tests/fixtures/iam_legacy_route_roles.json is every route's role check as it was before roles became editable: the
min_role / allow_list of each ``require_role`` on the route, recorded from the app before the conversion. Here:

- route by route, each built-in role passes the new permission checks exactly when it passed the old role checks;
- no route is left without a check it had, and no router still uses require_role;
- over HTTP, for a representative route of every router (a read and a change where it has them), each built-in role is
  refused (403) exactly when it was refused before;
- require_role, kept as a compatibility wrapper, still answers as before for the built-in roles.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.permissions import ADMIN_ONLY, BUILTIN_ORDER, LEVEL_ROLES, PERMISSIONS, default_permissions, legacy_floor
from app.core.rbac import legacy_level, require_role, role_meets
from app.core.security import get_password_hash
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services.auth_service import issue_tokens

LEGACY = json.loads((Path(__file__).parent / "fixtures" / "iam_legacy_route_roles.json").read_text())
READS = {"GET", "HEAD", "OPTIONS"}


def _api_routes(routes, prefix: str = ""):
    for route in routes:
        original = getattr(route, "original_router", None)
        if original is not None:
            yield from _api_routes(original.routes, prefix + (route.include_context.prefix or ""))
        elif hasattr(route, "dependant"):
            yield prefix + route.path, route


def _checks(route) -> tuple[list[tuple[str, ...]], list[object]]:
    permissions, legacy = [], []
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        held = getattr(dep.call, "permissions", None)
        if held:
            permissions.append(tuple(held))
        if getattr(dep.call, "__qualname__", "") == "require_role.<locals>.checker":
            legacy.append(dep.call)
        stack.extend(dep.dependencies)
    return permissions, legacy


ROUTES = {(method, path): route for path, route in _api_routes(app.routes) for method in (getattr(route, "methods", None) or [])}


def _legacy_passes(role: str, method: str, checks: list[dict]) -> bool:
    write = method not in READS
    for check in checks:
        if check["allow_list"]:
            if role not in check["allow_list"]:
                return False
        elif not role_meets(role, check["min_role"], write=write):
            return False
    return True


def test_every_route_keeps_a_check_and_each_built_in_role_passes_exactly_as_before():
    assert len(LEGACY) >= 600
    mismatches = []
    for entry in LEGACY:
        route = ROUTES.get((entry["method"], entry["path"]))
        assert route is not None, f"{entry['method']} {entry['path']} is gone"
        permissions, legacy = _checks(route)
        assert not legacy, f"{entry['method']} {entry['path']} still checks a role"
        assert permissions, f"{entry['method']} {entry['path']} lost its check"
        for role in BUILTIN_ORDER:
            before = _legacy_passes(role, entry["method"], entry["checks"])
            after = all(set(ids) <= default_permissions(role) for ids in permissions)
            if before != after:
                mismatches.append((entry["method"], entry["path"], role, before, after))
    assert not mismatches, mismatches[:20]


def test_no_router_uses_require_role_any_more():
    routers = Path(__file__).resolve().parents[1] / "app" / "api" / "routers"
    users = [p.name for p in routers.glob("*.py") if "require_role(" in p.read_text()]
    assert users == []


def test_the_catalogue_levels_are_exactly_the_old_role_order():
    # Each level holds the roles that passed the old check it stands for.
    assert LEVEL_ROLES["view"] == {r for r in BUILTIN_ORDER if role_meets(r, "viewer", write=True)}
    assert LEVEL_ROLES["inspect"] == {r for r in BUILTIN_ORDER if role_meets(r, "operator", write=False)}
    assert LEVEL_ROLES["operate"] == {r for r in BUILTIN_ORDER if role_meets(r, "operator", write=True)}
    assert LEVEL_ROLES["review"] == {r for r in BUILTIN_ORDER if role_meets(r, "auditor", write=True)}
    assert LEVEL_ROLES["manage"] == {r for r in BUILTIN_ORDER if role_meets(r, "admin", write=True)}
    # Owner and Admin hold everything; the Admin-only permissions are theirs alone.
    assert default_permissions("owner") == default_permissions("admin") == {p.id for p in PERMISSIONS}
    for role in ("auditor", "operator", "viewer"):
        assert not default_permissions(role) & ADMIN_ONLY
    # The auditor never holds a permission to change things at the operator's level.
    assert not {p.id for p in PERMISSIONS if p.level == "operate"} & default_permissions("auditor")
    # Each built-in role is its own floor.
    for role in BUILTIN_ORDER:
        assert legacy_floor(default_permissions(role), role) == role


def test_require_role_compatibility_wrapper_answers_as_before():
    for min_role in ("viewer", "operator", "auditor", "admin"):
        for write in (False, True):
            level = legacy_level(min_role, None, write=write)
            assert LEVEL_ROLES[level] == {r for r in BUILTIN_ORDER if role_meets(r, min_role, write=write)}
    for allow in (["owner", "admin"], ["owner", "admin", "auditor"], ["owner", "admin", "auditor", "operator"], ["operator", "admin", "owner"]):
        assert LEVEL_ROLES[legacy_level(None, allow, write=True)] == set(allow)
    assert callable(require_role(min_role="admin"))


# --- Over HTTP: a read and a change of every router, as each built-in role -----------------------------------------


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'iam-eq.sqlite3'}", connect_args={"check_same_thread": False})
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

    app.dependency_overrides[get_db] = override_get_db
    headers = {}
    with factory() as db:
        tenant = Tenant(name="Acme", slug="acme", is_active=True)
        db.add(tenant)
        db.flush()
        for role in BUILTIN_ORDER:
            user = User(email=f"{role}@example.test", full_name=role, hashed_password=get_password_hash("correct-Horse-2026"), is_active=True)
            db.add(user)
            db.flush()
            db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
            db.flush()
            tokens = issue_tokens(db, user=user, tenant_id=tenant.id, role=role)
            headers[role] = {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tenant.id}
        db.commit()
    client = TestClient(app, raise_server_exceptions=False)
    try:
        yield client, headers
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _representatives() -> list[dict]:
    by_module: dict[str, dict[str, dict]] = defaultdict(dict)
    for entry in LEGACY:
        route = ROUTES[(entry["method"], entry["path"])]
        # Routes with dependencies of their own (feature gates, governance checks) answer before the role check.
        if "{" in entry["path"] or getattr(route, "dependencies", None) or entry["path"].startswith("/mcp"):
            continue
        module = entry["endpoint"].rsplit(".", 1)[0]
        kind = "read" if entry["method"] in READS else "write"
        # Prefer a route that some built-in role is refused (it shows the check), then any.
        refused_somewhere = not all(_legacy_passes(r, entry["method"], entry["checks"]) for r in BUILTIN_ORDER)
        current = by_module[module].get(kind)
        if current is None or (refused_somewhere and current.get("_open")):
            by_module[module][kind] = {**entry, "_open": not refused_somewhere}
    return [entry for kinds in by_module.values() for entry in kinds.values()]


def test_a_read_and_a_change_of_every_router_answer_each_built_in_role_as_before(env):
    client, headers = env
    picked = _representatives()
    assert len({e["endpoint"].rsplit(".", 1)[0] for e in picked}) >= 45
    wrong = []
    for entry in picked:
        for role in BUILTIN_ORDER:
            if entry["method"] in READS:
                status = client.request(entry["method"], entry["path"], headers=headers[role]).status_code
            else:
                status = client.request(entry["method"], entry["path"], headers=headers[role], json={}).status_code
            allowed = _legacy_passes(role, entry["method"], entry["checks"])
            if allowed and status == 403:
                # A 403 from the route itself (not the role check) carries its own reason; the role check says this.
                body = client.request(entry["method"], entry["path"], headers=headers[role], **({} if entry["method"] in READS else {"json": {}})).text
                if "Your role does not allow that." in body:
                    wrong.append((entry["method"], entry["path"], role, "refused"))
            if not allowed and status != 403:
                wrong.append((entry["method"], entry["path"], role, f"let through ({status})"))
    assert not wrong, wrong[:20]
