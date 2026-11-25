"""Tenant-bound signing for HMAIR Deep Scan unit completion receipts."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import hmac
import json
from typing import Any

from app.core.config import settings
from app.services.hmair.contracts import canonical_json_bytes
from app.services.hmair.deep_scan_contracts import DeepScanUnitCompletionReceipt


_DOMAIN = b"hawk.hmair.deep-scan-unit-receipt.v1"
_MAX_PRIVATE_VALUE_BYTES = 4_096


def _private_bytes(value: object, *, field: str) -> bytes:
    if type(value) is not str:
        raise ValueError(f"{field} is invalid")
    encoded = value.strip().encode("utf-8")
    if not encoded or len(encoded) > _MAX_PRIVATE_VALUE_BYTES:
        raise ValueError(f"{field} is invalid")
    return encoded


def _keyring(settings_obj: Any) -> tuple[str, dict[str, bytes]]:
    active = str(
        getattr(settings_obj, "receipt_signing_active_key_id", "") or ""
    ).strip()
    raw = getattr(settings_obj, "receipt_signing_keys_json", "{}")
    if isinstance(raw, Mapping):
        decoded = dict(raw)
    else:
        try:
            decoded = json.loads(str(raw or "{}"))
        except json.JSONDecodeError as exc:
            raise ValueError("completion receipt signing keyring is invalid") from exc
    if not active or not isinstance(decoded, Mapping):
        raise ValueError("completion receipt signing keyring is unavailable")
    keys: dict[str, bytes] = {}
    for key_id, secret in decoded.items():
        if type(key_id) is not str or type(secret) is not str:
            raise ValueError("completion receipt signing keyring is invalid")
        normalized_id = key_id.strip()
        encoded_secret = secret.strip().encode("utf-8")
        if not normalized_id or len(encoded_secret) < 32:
            raise ValueError("completion receipt signing keyring is incomplete")
        keys[normalized_id] = encoded_secret
    if active not in keys:
        raise ValueError("completion receipt active signing key is unavailable")
    return active, keys


def _keyed_hash(secret: bytes, *, purpose: bytes, value: bytes) -> str:
    return hmac.new(secret, _DOMAIN + b"\0" + purpose + b"\0" + value, hashlib.sha256).hexdigest()


def _tenant_binding(*, secret: bytes, tenant_id: str) -> str:
    return _keyed_hash(
        secret,
        purpose=b"tenant",
        value=_private_bytes(tenant_id, field="tenant_id"),
    )


def _receipt_material(receipt: DeepScanUnitCompletionReceipt) -> dict[str, object]:
    return receipt.model_dump(
        mode="json", exclude={"receipt_digest", "signature"}
    )


def issue_deep_scan_unit_completion_receipt(
    *,
    tenant_id: str,
    scan_id: str,
    target_id: str,
    collector_id: str,
    unit_id: str,
    source_record_id: str,
    observed_at: datetime,
    settings_obj: Any = settings,
) -> DeepScanUnitCompletionReceipt:
    active, keys = _keyring(settings_obj)
    secret = keys[active]
    unsigned = DeepScanUnitCompletionReceipt(
        scan_id=scan_id,
        target_id=target_id,
        collector_id=collector_id,
        tenant_binding_hash=_tenant_binding(secret=secret, tenant_id=tenant_id),
        unit_id_hash=_keyed_hash(
            secret,
            purpose=b"unit",
            value=_private_bytes(unit_id, field="unit_id"),
        ),
        source_record_hash=_keyed_hash(
            secret,
            purpose=b"source-record",
            value=_private_bytes(source_record_id, field="source_record_id"),
        ),
        observed_at=observed_at,
        signing_key_id=active,
        receipt_digest="0" * 64,
        signature="0" * 64,
    )
    material = _receipt_material(unsigned)
    digest = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
    signature = hmac.new(
        secret,
        _DOMAIN + b"\0signature\0" + digest.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return unsigned.model_copy(
        update={"receipt_digest": digest, "signature": signature}
    )


def verify_deep_scan_unit_completion_receipt(
    receipt: DeepScanUnitCompletionReceipt | Mapping[str, object],
    *,
    tenant_id: str,
    settings_obj: Any = settings,
) -> bool:
    try:
        parsed = (
            receipt
            if isinstance(receipt, DeepScanUnitCompletionReceipt)
            else DeepScanUnitCompletionReceipt.model_validate(receipt)
        )
        _active, keys = _keyring(settings_obj)
        secret = keys.get(parsed.signing_key_id)
        if secret is None:
            return False
        if not hmac.compare_digest(
            parsed.tenant_binding_hash,
            _tenant_binding(secret=secret, tenant_id=tenant_id),
        ):
            return False
        digest = hashlib.sha256(
            canonical_json_bytes(_receipt_material(parsed))
        ).hexdigest()
        if not hmac.compare_digest(parsed.receipt_digest, digest):
            return False
        expected_signature = hmac.new(
            secret,
            _DOMAIN + b"\0signature\0" + digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(parsed.signature, expected_signature)
    except (TypeError, ValueError):
        return False


__all__ = [
    "issue_deep_scan_unit_completion_receipt",
    "verify_deep_scan_unit_completion_receipt",
]
