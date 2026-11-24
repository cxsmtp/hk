#!/usr/bin/env python3
"""Provision existing Policy Pack Platform access for one confirmed tenant.

This is an operator-only deployment command. It is intentionally separate
from customer APIs: tenants cannot self-enable a commercial capability merely
by calling a route. It never creates a policy assignment or turns enforcement
on; it only enables a validated entitlement and vendor catalog access.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from sqlalchemy import select


API_ROOT = Path(__file__).resolve().parents[1]
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.db.models.user import UserTenantRole
from app.db.session import SessionLocal
from app.services.audit_service import write_audit_log
from app.services.policy_pack_platform.service import (
    PolicyPackPlatformError,
    provision_policy_pack_entitlement,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--confirm-tenant-id", required=True)
    parser.add_argument("--actor-user-id", required=True)
    parser.add_argument("--package-tier", default="secure", choices=("secure", "control", "assurance", "enterprise"))
    parser.add_argument("--reason", required=True)
    return parser.parse_args()


def main() -> int:
    args = _arguments()
    if os.getenv("HAWK_POLICY_PACK_PROVISIONING") != "1":
        print("Set HAWK_POLICY_PACK_PROVISIONING=1 to run this operator command.", file=sys.stderr)
        return 2
    if args.tenant_id != args.confirm_tenant_id:
        print("--confirm-tenant-id must exactly match --tenant-id.", file=sys.stderr)
        return 2

    with SessionLocal() as db:
        try:
            role = db.scalar(
                select(UserTenantRole).where(
                    UserTenantRole.tenant_id == args.tenant_id,
                    UserTenantRole.user_id == args.actor_user_id,
                    UserTenantRole.role.in_(("owner", "admin")),
                )
            )
            if role is None:
                raise PolicyPackPlatformError("policy_pack_provisioning_actor_not_authorized")
            entitlement, catalog_count = provision_policy_pack_entitlement(
                db,
                tenant_id=args.tenant_id,
                package_tier=args.package_tier,
            )
            audit = write_audit_log(
                db,
                tenant_id=args.tenant_id,
                actor_user_id=args.actor_user_id,
                actor_type="platform_operator",
                action="policy_pack_platform.provisioned",
                resource_type="policy_pack_platform_entitlement",
                resource_id=entitlement.id,
                payload={
                    "package_tier": entitlement.package_tier,
                    "enabled": entitlement.enabled,
                    "catalog_definition_count": catalog_count,
                    "reason": args.reason,
                    "scope": "catalog_only_no_policy_instance_or_enforcement",
                },
            )
            result = {
                "status": "provisioned",
                "tenant_id": args.tenant_id,
                "package_tier": entitlement.package_tier,
                "catalog_definition_count": catalog_count,
                "audit_id": audit.id,
                "enforcement_changed": False,
            }
            db.commit()
        except Exception as exc:
            db.rollback()
            print(f"Policy Pack Platform provisioning failed: {exc}", file=sys.stderr)
            return 1

    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
