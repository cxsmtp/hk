from __future__ import annotations

import argparse
import json
import re
import sys

from pydantic import EmailStr, TypeAdapter
from sqlalchemy import func, select, text

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import SessionLocal
from app.services.audit_service import write_audit_log
from app.services.production_hardening import validate_initial_admin_password


BOOTSTRAP_LOCK_ID = 7_269_001_010
_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?$")


def create_initial_administrator(
    *,
    email: str,
    full_name: str,
    tenant_name: str,
    tenant_slug: str,
    password: str,
) -> dict[str, str]:
    normalized_email = str(TypeAdapter(EmailStr).validate_python(email)).casefold()
    normalized_full_name = full_name.strip()
    normalized_tenant_name = tenant_name.strip()
    normalized_slug = tenant_slug.strip().casefold()
    if not normalized_full_name or len(normalized_full_name) > 255:
        raise ValueError("Initial administrator full name is invalid.")
    if not normalized_tenant_name or len(normalized_tenant_name) > 255:
        raise ValueError("Initial tenant name is invalid.")
    if not _SLUG.fullmatch(normalized_slug):
        raise ValueError("Initial tenant slug is invalid.")
    validate_initial_admin_password(password)

    with SessionLocal() as db:
        db.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {"lock_id": BOOTSTRAP_LOCK_ID})
        existing_users = int(db.scalar(select(func.count()).select_from(User)) or 0)
        existing_tenants = int(db.scalar(select(func.count()).select_from(Tenant)) or 0)
        if existing_users or existing_tenants:
            raise RuntimeError("Initial administrator bootstrap is permanently closed for this database.")

        tenant = Tenant(name=normalized_tenant_name, slug=normalized_slug, is_active=True)
        user = User(
            email=normalized_email,
            full_name=normalized_full_name,
            hashed_password=get_password_hash(password),
            is_active=True,
        )
        db.add_all([tenant, user])
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role="owner"))
        write_audit_log(
            db,
            tenant_id=tenant.id,
            actor_user_id=user.id,
            actor_type="human",
            action="production.bootstrap.initial_admin",
            resource_type="tenant",
            resource_id=tenant.id,
            payload={"bootstrap": "one_time", "role": "owner"},
        )
        db.commit()
        return {"tenant_id": tenant.id, "user_id": user.id, "email": normalized_email}


def verify_production_bootstrap_context() -> None:
    if settings.deployment_topology != "single_node_compose" or settings.env.lower() not in {"prod", "production"}:
        raise RuntimeError("Production bootstrap may run only for the supported production topology.")
    if settings.self_registration_enabled or settings.demo_mode:
        raise RuntimeError("Production bootstrap forbids demo seeding and self-registration.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Hawk bounded production bootstrap.")
    parser.add_argument("--create-initial-admin", action="store_true")
    parser.add_argument("--password-stdin", action="store_true")
    parser.add_argument("--email")
    parser.add_argument("--full-name")
    parser.add_argument("--tenant-name")
    parser.add_argument("--tenant-slug")
    arguments = parser.parse_args()
    verify_production_bootstrap_context()
    if not arguments.create_initial_admin:
        print("Production bootstrap verified: no demo tenant or default administrator was created.")
        return
    if not arguments.password_stdin:
        raise RuntimeError("Initial administrator password is accepted only through standard input.")
    if not all((arguments.email, arguments.full_name, arguments.tenant_name, arguments.tenant_slug)):
        raise RuntimeError("Initial administrator identity and tenant arguments are required.")
    password = sys.stdin.readline(514).rstrip("\r\n")
    if len(password) > 512:
        raise ValueError("Initial administrator password exceeds the supported bound.")
    result = create_initial_administrator(
        email=arguments.email,
        full_name=arguments.full_name,
        tenant_name=arguments.tenant_name,
        tenant_slug=arguments.tenant_slug,
        password=password,
    )
    print(json.dumps({"status": "created", **result}, sort_keys=True))


if __name__ == "__main__":
    main()
