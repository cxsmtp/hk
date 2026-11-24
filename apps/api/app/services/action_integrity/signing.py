"""Purpose-separated development signing with strict unpadded base64url."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Protocol

from .canonical_v2 import canonical_json_bytes


class SigningKeyProvider(Protocol):
    """A purpose- and tenant-scoped provider; callers never handle raw production keys."""

    def sign(self, *, purpose: str, tenant_id: str, key_id: str, algorithm: str | None = None, payload: bytes) -> str: ...
    def verify(self, *, purpose: str, tenant_id: str, key_id: str, algorithm: str | None = None, payload: bytes, signature: str) -> bool: ...
    def metadata(self, *, purpose: str, tenant_id: str, key_id: str) -> dict[str, str]: ...


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _validate_scope(*, purpose: str, tenant_id: str, key_id: str | None = None) -> None:
    if not isinstance(purpose, str) or not purpose or not purpose.isascii():
        raise ValueError("signing purpose must be non-empty ASCII")
    if not isinstance(tenant_id, str) or not tenant_id or tenant_id != tenant_id.strip():
        raise ValueError("signing tenant is invalid")
    if key_id is not None and (not isinstance(key_id, str) or not key_id or not key_id.isascii()):
        raise ValueError("signing key id must be non-empty ASCII")


def _validate_algorithm(*, requested: str | None, actual: str) -> str:
    if actual not in {"HS256", "ES256", "EdDSA"}:
        raise ValueError("signing algorithm is unsupported")
    if requested is not None and requested != actual:
        raise ValueError("signing algorithm does not match key metadata")
    return actual


def _decode_strict(signature: str, *, expected_length: int) -> bytes | None:
    if not isinstance(signature, str) or len(signature) != expected_length:
        return None
    if "=" in signature or "+" in signature or "/" in signature or any(character.isspace() for character in signature):
        return None
    if any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for character in signature):
        return None
    try:
        decoded = base64.urlsafe_b64decode(signature + "=" * ((4 - len(signature) % 4) % 4))
    except (ValueError, UnicodeEncodeError):
        return None
    return decoded if _encode(decoded) == signature else None


_P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _valid_asymmetric_signature(algorithm: str, signature: str) -> bool:
    """Enforce the frozen raw RFC 4648 §5 signatures before provider verify."""
    raw = _decode_strict(signature, expected_length=86)
    if raw is None or len(raw) != 64:
        return False
    if algorithm == "EdDSA":
        return True
    if algorithm != "ES256":
        return False
    r, s = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    return 0 < r < _P256_ORDER and 0 < s <= _P256_ORDER // 2


def sign_hs256(*, purpose: str, tenant_id: str, key: bytes, payload: bytes) -> str:
    _validate_scope(purpose=purpose, tenant_id=tenant_id)
    if len(key) < 32:
        raise ValueError("signing key too short")
    # Purpose/tenant/key isolation is enforced by provider lookup.  The signed
    # bytes themselves are frozen as DOMAIN || NUL || canonical-object.
    return _encode(hmac.new(key, payload, hashlib.sha256).digest())


def verify_hs256(*, purpose: str, tenant_id: str, key: bytes, payload: bytes, signature: str) -> bool:
    try:
        _validate_scope(purpose=purpose, tenant_id=tenant_id)
    except ValueError:
        return False
    if _decode_strict(signature, expected_length=43) is None:
        return False
    return hmac.compare_digest(sign_hs256(purpose=purpose, tenant_id=tenant_id, key=key, payload=payload), signature)


@dataclass
class _KeyRecord:
    secret: bytes
    state: str = "active"


class LocalSigningKeyProvider:
    """Purpose- and tenant-isolated HS256 provider for test/development only."""

    def __init__(self, *, development: bool) -> None:
        if not development:
            raise ValueError("local HMAC signing is forbidden outside development/test")
        self._keys: dict[tuple[str, str, str], _KeyRecord] = {}

    def add_key(self, *, purpose: str, tenant_id: str, key_id: str, secret: bytes) -> None:
        _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        if len(secret) < 32:
            raise ValueError("signing key too short")
        key = (purpose, tenant_id, key_id)
        if key in self._keys:
            raise ValueError("key already exists")
        # Key material is purpose and tenant isolated.  Reusing it would make
        # a bug in a caller's scope/domain selection materially exploitable.
        if any(hmac.compare_digest(record.secret, secret) for record in self._keys.values()):
            raise ValueError("signing key material cannot be reused across scopes")
        self._keys[key] = _KeyRecord(secret=secret)

    def set_state(self, *, purpose: str, tenant_id: str, key_id: str, state: str) -> None:
        _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        if state not in {"active", "verify_only", "revoked"}:
            raise ValueError("invalid key state")
        self._keys[(purpose, tenant_id, key_id)].state = state

    def metadata(self, *, purpose: str, tenant_id: str, key_id: str) -> dict[str, str]:
        _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        record = self._keys[(purpose, tenant_id, key_id)]
        return {"algorithm": "HS256", "key_id": key_id, "state": record.state}

    def active_key_id(self, *, purpose: str, tenant_id: str) -> str:
        _validate_scope(purpose=purpose, tenant_id=tenant_id)
        active = [key_id for (candidate_purpose, candidate_tenant, key_id), record in self._keys.items() if candidate_purpose == purpose and candidate_tenant == tenant_id and record.state == "active"]
        if len(active) != 1:
            raise ValueError("exactly one active signing key is required")
        return active[0]

    def sign(self, *, purpose: str, tenant_id: str, key_id: str, algorithm: str | None = None, payload: bytes) -> str:
        _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        record = self._keys[(purpose, tenant_id, key_id)]
        _validate_algorithm(requested=algorithm, actual="HS256")
        if record.state != "active":
            raise ValueError("key is not active")
        return sign_hs256(purpose=purpose, tenant_id=tenant_id, key=record.secret, payload=payload)

    def verify(self, *, purpose: str, tenant_id: str, key_id: str, algorithm: str | None = None, payload: bytes, signature: str) -> bool:
        try:
            _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
            _validate_algorithm(requested=algorithm, actual="HS256")
        except ValueError:
            return False
        record = self._keys.get((purpose, tenant_id, key_id))
        return record is not None and verify_hs256(purpose=purpose, tenant_id=tenant_id, key=record.secret, payload=payload, signature=signature)


class KmsHsmSigningKeyProvider:
    """Production adapter boundary.

    The actual KMS/HSM implementation is injected by deployment configuration;
    this class deliberately has no software fallback and rejects HS256.
    """

    authoritative = True

    def __init__(self, delegate: SigningKeyProvider | None = None) -> None:
        self._delegate = delegate

    def _delegate_or_fail(self) -> SigningKeyProvider:
        if self._delegate is None:
            raise ValueError("authoritative signing requires a configured KMS/HSM provider")
        return self._delegate

    def sign(self, *, purpose: str, tenant_id: str, key_id: str, algorithm: str | None = None, payload: bytes) -> str:
        _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        metadata = self.metadata(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        actual_algorithm = _validate_algorithm(requested=algorithm, actual=str(metadata.get("algorithm")))
        if actual_algorithm not in {"ES256", "EdDSA"} or metadata.get("state") != "active":
            raise ValueError("production authority requires an active ES256 or EdDSA key")
        delegate = self._delegate_or_fail()
        try:
            signature = delegate.sign(
                purpose=purpose, tenant_id=tenant_id, key_id=key_id,
                algorithm=actual_algorithm, payload=payload,
            )
        except TypeError as exc:
            raise ValueError("signature provider does not support explicit algorithm binding") from exc
        if not _valid_asymmetric_signature(actual_algorithm, signature):
            raise ValueError("KMS/HSM returned an invalid raw asymmetric signature")
        return signature

    def verify(self, *, purpose: str, tenant_id: str, key_id: str, algorithm: str | None = None, payload: bytes, signature: str) -> bool:
        try:
            _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        except ValueError:
            return False
        metadata = self.metadata(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        try:
            actual_algorithm = _validate_algorithm(requested=algorithm, actual=str(metadata.get("algorithm")))
        except ValueError:
            return False
        if actual_algorithm not in {"ES256", "EdDSA"}:
            return False
        if not _valid_asymmetric_signature(actual_algorithm, signature):
            return False
        try:
            return bool(self._delegate_or_fail().verify(
                purpose=purpose, tenant_id=tenant_id, key_id=key_id,
                algorithm=actual_algorithm, payload=payload, signature=signature,
            ))
        except TypeError:
            return False
        except (KeyError, ValueError):
            return False

    def metadata(self, *, purpose: str, tenant_id: str, key_id: str) -> dict[str, str]:
        return self._delegate_or_fail().metadata(purpose=purpose, tenant_id=tenant_id, key_id=key_id)

    def active_key_id(self, *, purpose: str, tenant_id: str) -> str:
        """Select only a live asymmetric key exposed by the deployment adapter."""
        finder = getattr(self._delegate_or_fail(), "active_key_id", None)
        if not callable(finder):
            raise ValueError("configured KMS/HSM provider does not expose an active key selector")
        key_id = str(finder(purpose=purpose, tenant_id=tenant_id))
        metadata = self.metadata(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
        if metadata.get("algorithm") not in {"ES256", "EdDSA"} or metadata.get("state") != "active":
            raise ValueError("production authority requires an active ES256 or EdDSA key")
        return key_id


def signed_object_bytes(domain: str, value: dict[str, Any]) -> bytes:
    """Frozen cross-language signature input: only the signature is omitted."""
    if not domain or not domain.isascii():
        raise ValueError("signature domain must be non-empty ASCII")
    unsigned = dict(value)
    unsigned.pop("signature", None)
    return domain.encode("ascii") + b"\0" + canonical_json_bytes(unsigned)


def sign_object(
    provider: SigningKeyProvider,
    *,
    purpose: str,
    domain: str,
    tenant_id: str,
    key_id: str,
    value: dict[str, Any],
) -> dict[str, Any]:
    _validate_scope(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
    metadata = provider.metadata(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
    if metadata.get("state") != "active":
        raise ValueError("signing key is not active")
    signed = dict(value)
    algorithm = _validate_algorithm(requested=None, actual=str(metadata.get("algorithm")))
    signed["algorithm"] = algorithm
    signed["signing_key_id"] = key_id
    signed["signature"] = provider.sign(purpose=purpose, tenant_id=tenant_id, key_id=key_id, algorithm=algorithm, payload=signed_object_bytes(domain, signed))
    return signed


def verify_signed_object(
    provider: SigningKeyProvider,
    *,
    purpose: str,
    domain: str,
    tenant_id: str,
    value: dict[str, Any],
    current_authority: bool = False,
) -> bool:
    try:
        _validate_scope(purpose=purpose, tenant_id=tenant_id)
    except ValueError:
        return False
    if value.get("tenant_id") != tenant_id:
        return False
    key_id = value.get("signing_key_id")
    signature = value.get("signature")
    algorithm = value.get("algorithm")
    if not isinstance(key_id, str) or not isinstance(signature, str) or not isinstance(algorithm, str):
        return False
    try:
        metadata = provider.metadata(purpose=purpose, tenant_id=tenant_id, key_id=key_id)
    except (KeyError, ValueError):
        return False
    if metadata.get("algorithm") != algorithm or (current_authority and metadata.get("state") != "active"):
        return False
    if algorithm in {"ES256", "EdDSA"} and not _valid_asymmetric_signature(algorithm, signature):
        return False
    try:
        return bool(provider.verify(purpose=purpose, tenant_id=tenant_id, key_id=key_id, algorithm=algorithm, payload=signed_object_bytes(domain, value), signature=signature))
    except (KeyError, ValueError):
        return False


def active_key_id(provider: SigningKeyProvider, *, purpose: str, tenant_id: str) -> str:
    finder = getattr(provider, "active_key_id", None)
    if not callable(finder):
        raise ValueError("signing provider does not expose an active key selector")
    return str(finder(purpose=purpose, tenant_id=tenant_id))
