"""Frozen signing domains and safe pseudonymization for Account Boundary."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from app.services.action_integrity.signing import SigningKeyProvider, active_key_id, sign_object, verify_signed_object


ACCOUNT_SESSION_PERMIT_PURPOSE = "account_session_permit_signing"
ACCOUNT_ACCESS_RECEIPT_PURPOSE = "account_access_receipt_signing"
VALIDATION_PURPOSE = "account_boundary_validation_signing"

ACCOUNT_SESSION_PERMIT_DOMAIN = "hawk.account-boundary.account-session-permit.v1"
ACCOUNT_ACCESS_RECEIPT_DOMAIN = "hawk.account-boundary.account-access-receipt.v1"
VALIDATION_DOMAIN = "hawk.account-boundary.validation.v1"


def pseudonymize(key: str, *, tenant_id: str, purpose: str, value: str | None) -> str | None:
    """Return a tenant- and purpose-separated opaque reference, never plaintext."""
    if value is None:
        return None
    if not key or len(key) < 32:
        raise ValueError("account-boundary pseudonymization key is unavailable")
    payload = f"{tenant_id}\0{purpose}\0{value}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


__all__ = [
    "ACCOUNT_ACCESS_RECEIPT_DOMAIN",
    "ACCOUNT_ACCESS_RECEIPT_PURPOSE",
    "ACCOUNT_SESSION_PERMIT_DOMAIN",
    "ACCOUNT_SESSION_PERMIT_PURPOSE",
    "SigningKeyProvider",
    "VALIDATION_DOMAIN",
    "VALIDATION_PURPOSE",
    "active_key_id",
    "pseudonymize",
    "sign_object",
    "verify_signed_object",
]
