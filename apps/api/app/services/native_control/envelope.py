from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
from threading import Lock
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


MAX_ENVELOPE_BYTES = 65_536
MAX_CLOCK_SKEW = timedelta(seconds=60)
MAX_EVENT_LIFETIME = timedelta(minutes=5)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _b64url_decode(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except (ValueError, TypeError) as exc:
        raise ValueError("signature_invalid") from exc


@dataclass(frozen=True, slots=True)
class WorkloadCredential:
    credential_id: str
    credential_epoch: int
    tenant_id: str
    integration_instance_id: str
    provider: str
    product: str
    environment: str
    allowed_event_types: tuple[str, ...]
    public_key_pem: str
    expires_at: datetime
    revoked: bool


@dataclass(frozen=True, slots=True)
class TrustedControlEnvelope:
    event_id: str
    integration_instance_id: str
    tenant_binding: str
    provider: str
    product: str
    provider_event_id: str
    provider_event_type: str
    provider_version: str
    adapter_version: str
    issued_at: datetime
    expires_at: datetime
    nonce: str
    session_id: str
    chain_id: str
    correlation_id: str
    payload_hash: str
    canonical_action_hash: str | None
    credential_id: str
    credential_epoch: int
    signature_algorithm: str
    signature: str

    def as_dict(self, *, include_signature: bool = True) -> dict[str, object]:
        payload: dict[str, object] = {
            "event_id": self.event_id,
            "integration_instance_id": self.integration_instance_id,
            "tenant_binding": self.tenant_binding,
            "provider": self.provider,
            "product": self.product,
            "provider_event_id": self.provider_event_id,
            "provider_event_type": self.provider_event_type,
            "provider_version": self.provider_version,
            "adapter_version": self.adapter_version,
            "issued_at": _utc(self.issued_at).isoformat(),
            "expires_at": _utc(self.expires_at).isoformat(),
            "nonce": self.nonce,
            "session_id": self.session_id,
            "chain_id": self.chain_id,
            "correlation_id": self.correlation_id,
            "payload_hash": self.payload_hash,
            "canonical_action_hash": self.canonical_action_hash,
            "credential_id": self.credential_id,
            "credential_epoch": self.credential_epoch,
            "signature_algorithm": self.signature_algorithm,
        }
        if include_signature:
            payload["signature"] = self.signature
        return payload


@dataclass(frozen=True, slots=True)
class ValidatedEnvelopePrincipal:
    credential_id: str
    credential_epoch: int
    tenant_id: str
    integration_instance_id: str
    provider: str
    product: str
    event_id: str
    provider_event_type: str
    correlation_id: str


class ReplayStore(Protocol):
    def claim(
        self,
        *,
        tenant_id: str,
        integration_id: str,
        event_id: str,
        nonce: str,
        expires_at: datetime,
        now: datetime,
    ) -> bool: ...


class InMemoryReplayStore:
    """Thread-safe test/local replay store; production persistence uses the DB model."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._events: dict[tuple[str, str, str], datetime] = {}
        self._nonces: dict[tuple[str, str, str], datetime] = {}

    def claim(
        self,
        *,
        tenant_id: str,
        integration_id: str,
        event_id: str,
        nonce: str,
        expires_at: datetime,
        now: datetime,
    ) -> bool:
        current = _utc(now)
        event_key = (tenant_id, integration_id, event_id)
        nonce_key = (tenant_id, integration_id, nonce)
        with self._lock:
            self._events = {key: expiry for key, expiry in self._events.items() if _utc(expiry) >= current}
            self._nonces = {key: expiry for key, expiry in self._nonces.items() if _utc(expiry) >= current}
            if event_key in self._events or nonce_key in self._nonces:
                return False
            self._events[event_key] = _utc(expires_at)
            self._nonces[nonce_key] = _utc(expires_at)
            return True


def canonical_envelope_body(envelope: TrustedControlEnvelope) -> bytes:
    return json.dumps(
        envelope.as_dict(include_signature=False),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = value
    return result


def _depth(value: object, current: int = 0) -> int:
    if isinstance(value, dict):
        return max([current, *(_depth(item, current + 1) for item in value.values())])
    if isinstance(value, list):
        return max([current, *(_depth(item, current + 1) for item in value)])
    return current


def parse_envelope_json(raw: bytes) -> TrustedControlEnvelope:
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope_too_large")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except UnicodeDecodeError as exc:
        raise ValueError("invalid_envelope_json") from exc
    except json.JSONDecodeError as exc:
        raise ValueError("invalid_envelope_json") from exc
    if not isinstance(payload, dict):
        raise ValueError("invalid_envelope_shape")
    if _depth(payload) > 4:
        raise ValueError("envelope_too_deep")
    expected = set(TrustedControlEnvelope.__dataclass_fields__)
    unknown = sorted(set(payload) - expected)
    missing = sorted(expected - set(payload))
    if unknown:
        raise ValueError(f"unknown_envelope_field:{unknown[0]}")
    if missing:
        raise ValueError(f"missing_envelope_field:{missing[0]}")
    try:
        payload["issued_at"] = datetime.fromisoformat(str(payload["issued_at"]))
        payload["expires_at"] = datetime.fromisoformat(str(payload["expires_at"]))
        payload["credential_epoch"] = int(payload["credential_epoch"])
        envelope = TrustedControlEnvelope(**payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid_envelope_field") from exc
    for name in (
        "event_id",
        "integration_instance_id",
        "tenant_binding",
        "provider",
        "product",
        "provider_event_type",
        "nonce",
        "credential_id",
        "signature",
    ):
        value = getattr(envelope, name)
        if not isinstance(value, str) or not value or len(value) > 512:
            raise ValueError(f"invalid_envelope_field:{name}")
    if len(envelope.payload_hash) != 64 or any(char not in "0123456789abcdef" for char in envelope.payload_hash.lower()):
        raise ValueError("invalid_payload_hash")
    return envelope


def _load_key(public_key_pem: str) -> ec.EllipticCurvePublicKey:
    if len(public_key_pem) > 2048:
        raise ValueError("credential_key_invalid")
    try:
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ValueError("credential_key_invalid") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("credential_key_invalid")
    return key


def validate_trusted_envelope(
    envelope: TrustedControlEnvelope,
    *,
    credential: WorkloadCredential,
    payload: bytes,
    now: datetime,
    replay_store: ReplayStore,
    payload_hash_override: str | None = None,
) -> ValidatedEnvelopePrincipal:
    now = _utc(now)
    if credential.revoked:
        raise ValueError("credential_revoked")
    # Expiry is an exclusive bound. A callback at the exact instant an
    # enrolled key expires has no remaining authority.
    if _utc(credential.expires_at) <= now:
        raise ValueError("credential_expired")
    if envelope.credential_id != credential.credential_id:
        raise ValueError("credential_id_mismatch")
    if envelope.credential_epoch != credential.credential_epoch:
        raise ValueError("credential_epoch_mismatch")
    if envelope.tenant_binding != credential.tenant_id:
        raise ValueError("tenant_binding_mismatch")
    if envelope.integration_instance_id != credential.integration_instance_id:
        raise ValueError("integration_binding_mismatch")
    if envelope.provider != credential.provider or envelope.product != credential.product:
        raise ValueError("provider_product_mismatch")
    if envelope.provider_event_type not in credential.allowed_event_types:
        raise ValueError("event_type_not_allowed")
    issued_at = _utc(envelope.issued_at)
    expires_at = _utc(envelope.expires_at)
    if issued_at > now + MAX_CLOCK_SKEW:
        raise ValueError("issued_in_future")
    if expires_at <= now:
        raise ValueError("event_expired")
    if expires_at <= issued_at or expires_at - issued_at > MAX_EVENT_LIFETIME:
        raise ValueError("event_lifetime_invalid")
    expected_payload_hash = payload_hash_override or hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(envelope.payload_hash, expected_payload_hash):
        raise ValueError("payload_hash_mismatch")
    if envelope.signature_algorithm != "ES256":
        raise ValueError("signature_algorithm_invalid")
    key = _load_key(credential.public_key_pem)
    try:
        key.verify(_b64url_decode(envelope.signature), canonical_envelope_body(envelope), ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        raise ValueError("signature_invalid") from exc
    if not replay_store.claim(
        tenant_id=credential.tenant_id,
        integration_id=credential.integration_instance_id,
        event_id=envelope.event_id,
        nonce=envelope.nonce,
        expires_at=envelope.expires_at,
        now=now,
    ):
        raise ValueError("replay_detected")
    return ValidatedEnvelopePrincipal(
        credential_id=credential.credential_id,
        credential_epoch=credential.credential_epoch,
        tenant_id=credential.tenant_id,
        integration_instance_id=credential.integration_instance_id,
        provider=credential.provider,
        product=credential.product,
        event_id=envelope.event_id,
        provider_event_type=envelope.provider_event_type,
        correlation_id=envelope.correlation_id,
    )
