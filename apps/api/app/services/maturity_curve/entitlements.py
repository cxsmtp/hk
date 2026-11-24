"""Backend entitlement checks for the Maturity Curve product layer."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models.maturity_curve import TenantMaturityEntitlement


TIER_ORDER = {"secure": 0, "control": 1, "assurance": 2, "enterprise": 3}
CAPABILITY_TIER = {
    "visibility": "secure",
    "baselines": "secure",
    "recommendations": "secure",
    "simulations": "secure",
    "basic_policy_draft": "secure",
    "executive_reporting": "secure",
    "detailed_policy_scope": "control",
    "approval_workflow": "control",
    "nested_conditions": "control",
    "business_purpose_binding": "control",
    "effectiveness": "assurance",
    "validation_evidence": "assurance",
    "continuous_validation": "assurance",
    "inherited_scopes": "enterprise",
    "custom_attributes": "enterprise",
    "api_automation": "enterprise",
}


class MaturityEntitlementError(PermissionError):
    """Raised when a tenant has not purchased or enabled a capability."""


def require_maturity_capability(
    db: Session,
    *,
    tenant_id: str,
    capability: str,
) -> TenantMaturityEntitlement:
    required_tier = CAPABILITY_TIER.get(str(capability or "").strip())
    if required_tier is None:
        raise MaturityEntitlementError("maturity_capability_unknown")
    entitlement = db.scalar(
        select(TenantMaturityEntitlement).where(TenantMaturityEntitlement.tenant_id == tenant_id)
    )
    if entitlement is None:
        raise MaturityEntitlementError("maturity_entitlement_missing")
    if not entitlement.enabled:
        raise MaturityEntitlementError("maturity_entitlement_disabled")
    if TIER_ORDER.get(entitlement.package_tier, -1) < TIER_ORDER[required_tier]:
        raise MaturityEntitlementError("maturity_capability_not_entitled")
    if capability == "custom_attributes" and not entitlement.custom_attributes_enabled:
        raise MaturityEntitlementError("maturity_custom_attributes_not_enabled")
    return entitlement


def set_maturity_entitlement(
    db: Session,
    *,
    tenant_id: str,
    package_tier: str,
    enabled: bool,
    custom_attributes_enabled: bool = False,
) -> TenantMaturityEntitlement:
    tier = str(package_tier or "").strip().lower()
    if tier not in TIER_ORDER:
        raise ValueError("invalid_maturity_package_tier")
    row = db.scalar(
        select(TenantMaturityEntitlement).where(TenantMaturityEntitlement.tenant_id == tenant_id)
    )
    if row is None:
        row = TenantMaturityEntitlement(
            tenant_id=tenant_id,
            package_tier=tier,
            enabled=bool(enabled),
            custom_attributes_enabled=bool(custom_attributes_enabled),
        )
        db.add(row)
        db.flush()
        return row
    row.package_tier = tier
    row.enabled = bool(enabled)
    row.custom_attributes_enabled = bool(custom_attributes_enabled)
    db.flush()
    return row
