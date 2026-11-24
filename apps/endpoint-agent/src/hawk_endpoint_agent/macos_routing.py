"""Short-lived, scope-bound readiness receipts for managed macOS routing.

The Network Extension never treats a socket path or a non-empty configuration
string as proof that the local Hawk broker is alive.  The enrolled device key
signs a bounded declaration of the exact application/destination routing scope,
policy epoch, and semantic-inspection requirement.  The extension verifies the
same canonical wire representation before activating the relay.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import re
import secrets
import struct
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .auth.device_key import (
    DeviceKeyProvider,
    DevicePublicIdentity,
    public_key_thumbprint,
)


_MAGIC = b"HAWKRR01"
_BROKER_KEY_AUTHORIZATION_MAGIC = b"HAWKRK01"
_VERSION = 1
_MAX_LIFETIME_SECONDS = 900
_MAX_BROKER_KEY_AUTHORIZATION_LIFETIME_SECONDS = 2_592_000
_MAX_FUTURE_SKEW_SECONDS = 60
_MAX_ITEMS = 256
_MAX_APPLICATION_BYTES = 255
_MAX_DESTINATION_BYTES = 253
_NONCE_SIZE = 16
_UINT64_MAX = (1 << 64) - 1
_APPLICATION_IDENTIFIER = re.compile(r"^[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$")
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IDENTITY_CHALLENGE = b"hawk-routing-identity-self-test-v1"
ROUTING_SCOPE_DOMAIN = b"hawk.macos-routing-scope.v1\0"
_ROUTING_FIELDS = {
    "schema", "version", "source_policy_sha256", "native_policy_sha256", "tenant_id", "device_id",
    "policy_version", "policy_epoch", "delivery_sequence", "mode", "issued_at", "expires_at",
    "routing_transport", "application_signing_identifiers", "destination_host_suffixes", "semantic_inspection_required",
}


def routing_scope_signing_bytes(payload: dict) -> bytes:
    """Encode bounded tenant authority; no signing implementation is present."""
    if (not isinstance(payload, dict) or set(payload) != _ROUTING_FIELDS or
            payload["schema"] != "hawk.macos-routing-scope" or type(payload["version"]) is not int or
            payload["version"] != 1 or payload["mode"] not in {"monitor", "enforce"} or
            payload["routing_transport"] != "direct_transparent_relay" or payload["semantic_inspection_required"] is not False):
        raise ValueError("routing_scope_schema_invalid")
    for field in ("source_policy_sha256", "native_policy_sha256"):
        if not isinstance(payload[field], str) or re.fullmatch(r"[0-9a-f]{64}", payload[field]) is None:
            raise ValueError("routing_scope_digest_invalid")
    for field in ("tenant_id", "device_id", "policy_version"):
        if not isinstance(payload[field], str) or not 0 < len(payload[field].encode()) < 64 or "\0" in payload[field]:
            raise ValueError("routing_scope_identity_invalid")
    for field in ("policy_epoch", "delivery_sequence"):
        if type(payload[field]) is not int or not 0 < payload[field] <= _UINT64_MAX:
            raise ValueError("routing_scope_epoch_invalid")
    routing_scope_expiry(payload)
    for field, normalize in (("application_signing_identifiers", _normalize_application_identifier),
                             ("destination_host_suffixes", _normalize_destination_suffix)):
        values = payload[field]
        try:
            if not isinstance(values, list) or not 0 < len(values) <= 256 or values != sorted({normalize(value) for value in values}):
                raise ValueError("routing_scope_list_invalid")
        except (RoutingReceiptError, TypeError) as exc:
            raise ValueError("routing_scope_list_invalid") from exc
    for suffix in payload["destination_host_suffixes"]:
        try:
            ipaddress.ip_address(suffix)
        except ValueError:
            continue
        raise ValueError("routing_scope_ip_literal_forbidden")
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) > 192 * 1024:
        raise ValueError("routing_scope_oversized")
    return ROUTING_SCOPE_DOMAIN + encoded


def routing_scope_expiry(payload: dict) -> tuple[int, int]:
    values = []
    for field in ("issued_at", "expires_at"):
        value = payload[field]
        if not isinstance(value, str) or not value.endswith("Z"):
            raise ValueError("routing_scope_time_invalid")
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.microsecond or parsed.utcoffset().total_seconds() != 0:
            raise ValueError("routing_scope_time_invalid")
        values.append(int(parsed.timestamp()))
    if not 0 < values[0] < values[1] <= _UINT64_MAX or values[1] - values[0] > 86400:
        raise ValueError("routing_scope_lifetime_invalid")
    return values[0], values[1]


def verify_routing_scope(envelope: dict, *, trusted_public_keys: Mapping[str, bytes],
                         expected_key_id: str, now: datetime | None = None) -> dict:
    if (not isinstance(envelope, dict) or set(envelope) != {"schema", "version", "key_id", "algorithm", "payload", "signature"} or
            envelope["schema"] != "hawk.macos-routing-scope-envelope" or type(envelope["version"]) is not int or
            envelope["version"] != 1 or envelope["algorithm"] != "Ed25519" or
            not isinstance(envelope["key_id"], str) or envelope["key_id"] != expected_key_id or
            not all(isinstance(envelope[field], str) for field in ("payload", "signature"))):
        raise ValueError("routing_envelope_invalid")
    try:
        raw = base64.b64decode(envelope["payload"], validate=True)
        if len(raw) > 192 * 1024:
            raise ValueError("routing_scope_oversized")
        payload = json.loads(raw)
        signing = routing_scope_signing_bytes(payload)
        if signing != ROUTING_SCOPE_DOMAIN + raw:
            raise ValueError("routing_scope_not_canonical")
        signature = base64.b64decode(envelope["signature"], validate=True)
        Ed25519PublicKey.from_public_bytes(trusted_public_keys[expected_key_id]).verify(signature, signing)
        issued, expires = routing_scope_expiry(payload)
        if not issued <= int((now or datetime.now(UTC)).timestamp()) < expires:
            raise ValueError("routing_scope_expired")
        return payload
    except (KeyError, TypeError, InvalidSignature, UnicodeDecodeError) as exc:
        raise ValueError("routing_scope_signature_invalid") from exc


class RoutingReceiptError(RuntimeError):
    """Raised when a production routing receipt cannot be issued safely."""


def _normalize_application_identifier(value: str) -> str:
    if not isinstance(value, str):
        raise RoutingReceiptError("invalid application routing scope")
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RoutingReceiptError("invalid application routing scope") from exc
    if (
        not encoded
        or len(encoded) > _MAX_APPLICATION_BYTES
        or _APPLICATION_IDENTIFIER.fullmatch(value) is None
        or value.startswith(".")
        or value.endswith(".")
        or ".." in value
    ):
        raise RoutingReceiptError("invalid application routing scope")
    return value


def _normalize_destination_suffix(value: str) -> str:
    if not isinstance(value, str):
        raise RoutingReceiptError("invalid destination routing scope")
    normalized = value.lower()
    if normalized.endswith("."):
        normalized = normalized[:-1]
    try:
        encoded = normalized.encode("ascii")
    except UnicodeEncodeError as exc:
        raise RoutingReceiptError("invalid destination routing scope") from exc
    labels = normalized.split(".")
    if (
        not encoded
        or len(encoded) > _MAX_DESTINATION_BYTES
        or any(_HOST_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise RoutingReceiptError("invalid destination routing scope")
    return normalized


def _length_prefixed_ascii(value: str) -> bytes:
    encoded = value.encode("ascii")
    return struct.pack(">I", len(encoded)) + encoded


def create_broker_key_authorization(
    *,
    broker_public_key_x963: bytes,
    issued_at_unix_seconds: int,
    expires_at_unix_seconds: int,
    key_epoch: int,
    nonce: bytes,
) -> bytes:
    """Create the canonical payload signed by the offline policy trust root.

    This helper does not sign the payload and never receives the trust-root
    private key. Production enrollment signs it in the existing separated
    policy-signing service, then delivers the payload and signature to the
    endpoint with the device enrollment material.
    """
    if not isinstance(broker_public_key_x963, bytes) or len(broker_public_key_x963) != 65:
        raise RoutingReceiptError("invalid broker public key")
    try:
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), broker_public_key_x963
        )
    except ValueError as exc:
        raise RoutingReceiptError("invalid broker public key") from exc
    del public_key
    if (
        type(issued_at_unix_seconds) is not int
        or type(expires_at_unix_seconds) is not int
        or issued_at_unix_seconds <= 0
        or expires_at_unix_seconds <= issued_at_unix_seconds
        or expires_at_unix_seconds - issued_at_unix_seconds
        > _MAX_BROKER_KEY_AUTHORIZATION_LIFETIME_SECONDS
        or expires_at_unix_seconds > _UINT64_MAX
    ):
        raise RoutingReceiptError("broker key authorization lifetime is invalid")
    if type(key_epoch) is not int or key_epoch <= 0 or key_epoch > _UINT64_MAX:
        raise RoutingReceiptError("broker key authorization epoch is invalid")
    if not isinstance(nonce, bytes) or len(nonce) != _NONCE_SIZE or not any(nonce):
        raise RoutingReceiptError("broker key authorization nonce is invalid")
    payload = b"".join(
        (
            _BROKER_KEY_AUTHORIZATION_MAGIC,
            struct.pack(">IQQQ", _VERSION, issued_at_unix_seconds, expires_at_unix_seconds, key_epoch),
            hashlib.sha256(broker_public_key_x963).digest(),
            nonce,
        )
    )
    if len(payload) != 84:
        raise RoutingReceiptError("broker key authorization encoding failed")
    return payload


def _verify_broker_key_authorization(
    *,
    authorization: bytes,
    signature_der: bytes,
    trust_root_public_key_x963: bytes,
    broker_public_key_x963: bytes,
    now_unix_seconds: int,
) -> tuple[int, int]:
    if (
        not isinstance(authorization, bytes)
        or len(authorization) != 84
        or not isinstance(signature_der, bytes)
        or not (64 <= len(signature_der) <= 80)
        or not isinstance(trust_root_public_key_x963, bytes)
        or len(trust_root_public_key_x963) != 65
    ):
        raise RoutingReceiptError("invalid broker key authorization")
    try:
        magic = authorization[:8]
        version, issued_at, expires_at, key_epoch = struct.unpack(
            ">IQQQ", authorization[8:36]
        )
        broker_digest = authorization[36:68]
        nonce = authorization[68:84]
        trust_root = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), trust_root_public_key_x963
        )
        if (
            magic != _BROKER_KEY_AUTHORIZATION_MAGIC
            or version != _VERSION
            or key_epoch <= 0
            or issued_at <= 0
            or expires_at <= issued_at
            or expires_at - issued_at
            > _MAX_BROKER_KEY_AUTHORIZATION_LIFETIME_SECONDS
            or expires_at <= now_unix_seconds
            or (issued_at > now_unix_seconds and issued_at - now_unix_seconds > _MAX_FUTURE_SKEW_SECONDS)
            or not any(nonce)
            or not secrets.compare_digest(
                broker_digest, hashlib.sha256(broker_public_key_x963).digest()
            )
        ):
            raise RoutingReceiptError("invalid broker key authorization")
        trust_root.verify(
            signature_der,
            authorization,
            ec.ECDSA(hashes.SHA256()),
        )
        return expires_at, key_epoch
    except RoutingReceiptError:
        raise
    except (InvalidSignature, TypeError, ValueError, struct.error) as exc:
        raise RoutingReceiptError("invalid broker key authorization") from exc


@dataclass(frozen=True)
class ManagedRoutingScope:
    application_signing_identifiers: tuple[str, ...]
    destination_host_suffixes: tuple[str, ...]
    policy_epoch: int
    semantic_inspection_required: bool

    @classmethod
    def create(
        cls,
        *,
        application_signing_identifiers: list[str] | tuple[str, ...],
        destination_host_suffixes: list[str] | tuple[str, ...],
        policy_epoch: int,
        semantic_inspection_required: bool,
    ) -> "ManagedRoutingScope":
        applications = tuple(
            sorted(
                {
                    _normalize_application_identifier(value)
                    for value in application_signing_identifiers
                }
            )
        )
        destinations = tuple(
            sorted(
                {
                    _normalize_destination_suffix(value)
                    for value in destination_host_suffixes
                }
            )
        )
        if not applications or len(applications) > _MAX_ITEMS:
            raise RoutingReceiptError("invalid application routing scope")
        if not destinations or len(destinations) > _MAX_ITEMS:
            raise RoutingReceiptError("invalid destination routing scope")
        if (
            type(policy_epoch) is not int
            or policy_epoch <= 0
            or policy_epoch > _UINT64_MAX
        ):
            raise RoutingReceiptError("invalid routing policy epoch")
        if type(semantic_inspection_required) is not bool:
            raise RoutingReceiptError("invalid semantic inspection requirement")
        return cls(
            application_signing_identifiers=applications,
            destination_host_suffixes=destinations,
            policy_epoch=policy_epoch,
            semantic_inspection_required=semantic_inspection_required,
        )

    def canonical_digest(self) -> bytes:
        material = bytearray(b"hawk-routing-scope-v1\x00")
        material.extend(struct.pack(">I", len(self.application_signing_identifiers)))
        for identifier in self.application_signing_identifiers:
            material.extend(_length_prefixed_ascii(identifier))
        material.extend(struct.pack(">I", len(self.destination_host_suffixes)))
        for suffix in self.destination_host_suffixes:
            material.extend(_length_prefixed_ascii(suffix))
        material.extend(struct.pack(">Q", self.policy_epoch))
        material.append(1 if self.semantic_inspection_required else 0)
        return hashlib.sha256(material).digest()


@dataclass(frozen=True)
class IssuedRoutingReceipt:
    scope: ManagedRoutingScope
    receipt: bytes
    signature_der: bytes
    public_key_x963: bytes
    provider_configuration: Mapping[str, object]


class MacRoutingReceiptIssuer:
    """Issue a managed routing declaration using the enrolled device key."""

    def __init__(
        self,
        *,
        provider: DeviceKeyProvider,
        identity: DevicePublicIdentity,
        broker_key_authorization: bytes,
        broker_key_authorization_signature_der: bytes,
        trust_root_public_key_x963: bytes,
        clock: Callable[[], float] = time.time,
        nonce_source: Callable[[int], bytes] = secrets.token_bytes,
        require_hardware_backed: bool = True,
    ) -> None:
        if require_hardware_backed and identity.hardware_backed is not True:
            raise RoutingReceiptError("hardware-backed routing identity required")
        try:
            public_key = serialization.load_pem_public_key(
                identity.public_key_pem.encode("ascii")
            )
        except (TypeError, ValueError) as exc:
            raise RoutingReceiptError("invalid routing public identity") from exc
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise RoutingReceiptError("routing identity must use P-256")
        try:
            if public_key_thumbprint(identity.public_key_pem) != identity.key_thumbprint:
                raise RoutingReceiptError("routing identity mismatch")
            proof = provider.sign(_IDENTITY_CHALLENGE)
            public_key.verify(
                proof,
                _IDENTITY_CHALLENGE,
                ec.ECDSA(hashes.SHA256()),
            )
        except RoutingReceiptError:
            raise
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise RoutingReceiptError("routing identity mismatch") from exc

        self._provider = provider
        self._public_key = public_key
        self._public_key_x963 = public_key.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self._clock = clock
        self._nonce_source = nonce_source
        current = self._clock()
        if not isinstance(current, (int, float)) or not math.isfinite(current):
            raise RoutingReceiptError("routing receipt clock is invalid")
        authorization_expiry, authorization_key_epoch = _verify_broker_key_authorization(
            authorization=broker_key_authorization,
            signature_der=broker_key_authorization_signature_der,
            trust_root_public_key_x963=trust_root_public_key_x963,
            broker_public_key_x963=self._public_key_x963,
            now_unix_seconds=int(current),
        )
        self._broker_key_authorization = bytes(broker_key_authorization)
        self._broker_key_authorization_signature_der = bytes(
            broker_key_authorization_signature_der
        )
        self._broker_key_authorization_expiry = authorization_expiry
        self._broker_key_authorization_key_epoch = authorization_key_epoch

    @property
    def authorization_expiry(self) -> int:
        return self._broker_key_authorization_expiry

    def issue(
        self,
        *,
        application_signing_identifiers: list[str] | tuple[str, ...],
        destination_host_suffixes: list[str] | tuple[str, ...],
        policy_epoch: int,
        semantic_inspection_required: bool,
        lifetime_seconds: int = 120,
    ) -> IssuedRoutingReceipt:
        if (
            type(lifetime_seconds) is not int
            or lifetime_seconds <= 0
            or lifetime_seconds > _MAX_LIFETIME_SECONDS
        ):
            raise RoutingReceiptError("routing receipt lifetime is invalid")
        current = self._clock()
        if not isinstance(current, (int, float)) or not math.isfinite(current):
            raise RoutingReceiptError("routing receipt clock is invalid")
        issued_at = int(current)
        if issued_at <= 0 or issued_at > _UINT64_MAX - lifetime_seconds:
            raise RoutingReceiptError("routing receipt clock is invalid")
        if issued_at + lifetime_seconds > self._broker_key_authorization_expiry:
            raise RoutingReceiptError(
                "broker key authorization expires before routing receipt"
            )

        scope = ManagedRoutingScope.create(
            application_signing_identifiers=application_signing_identifiers,
            destination_host_suffixes=destination_host_suffixes,
            policy_epoch=policy_epoch,
            semantic_inspection_required=semantic_inspection_required,
        )
        nonce = self._nonce_source(_NONCE_SIZE)
        if not isinstance(nonce, bytes) or len(nonce) != _NONCE_SIZE or not any(nonce):
            raise RoutingReceiptError("routing receipt nonce is invalid")
        receipt = b"".join(
            (
                _MAGIC,
                struct.pack(">IQQQ", _VERSION, issued_at, issued_at + lifetime_seconds, policy_epoch),
                scope.canonical_digest(),
                nonce,
            )
        )
        if len(receipt) != 84:
            raise RoutingReceiptError("routing receipt encoding failed")
        try:
            signature = self._provider.sign(receipt)
            self._public_key.verify(
                signature,
                receipt,
                ec.ECDSA(hashes.SHA256()),
            )
        except (InvalidSignature, TypeError, ValueError) as exc:
            raise RoutingReceiptError("routing receipt signing failed") from exc

        configuration: dict[str, object] = {
            "managedRoutingEnabled": True,
            "functionalRelayEnabled": True,
            "sourceAppSigningIdentifiers": list(
                scope.application_signing_identifiers
            ),
            "destinationHostSuffixes": list(scope.destination_host_suffixes),
            "policyEpoch": scope.policy_epoch,
            "semanticInspectionRequired": scope.semantic_inspection_required,
            "HawkRoutingReceipt": base64.b64encode(receipt).decode("ascii"),
            "HawkRoutingReceiptSignatureDER": base64.b64encode(signature).decode(
                "ascii"
            ),
            "HawkRoutingReceiptPublicKeyX963": base64.b64encode(
                self._public_key_x963
            ).decode("ascii"),
            "HawkRoutingBrokerKeyAuthorization": base64.b64encode(
                self._broker_key_authorization
            ).decode("ascii"),
            "HawkRoutingBrokerKeyAuthorizationSignatureDER": base64.b64encode(
                self._broker_key_authorization_signature_der
            ).decode("ascii"),
        }
        return IssuedRoutingReceipt(
            scope=scope,
            receipt=receipt,
            signature_der=signature,
            public_key_x963=self._public_key_x963,
            provider_configuration=MappingProxyType(configuration),
        )


def issue_authorized_routing_configuration(issuer: MacRoutingReceiptIssuer, scope: dict, *,
                                           now_unix_seconds: int) -> dict:
    routing_scope_signing_bytes(scope)
    issued, expires = routing_scope_expiry(scope)
    if not issued <= now_unix_seconds < expires:
        raise ValueError("routing_scope_expired")
    lifetime = min(120, expires - now_unix_seconds, issuer.authorization_expiry - now_unix_seconds)
    if lifetime <= 0:
        raise ValueError("routing_authorization_expired")
    return dict(issuer.issue(application_signing_identifiers=scope["application_signing_identifiers"],
        destination_host_suffixes=scope["destination_host_suffixes"], policy_epoch=scope["policy_epoch"],
        semantic_inspection_required=False, lifetime_seconds=lifetime).provider_configuration)


def verify_routing_provider_configuration(configuration: dict, *, scope: dict,
        trust_root_public_key_x963: bytes, now_unix_seconds: int) -> int:
    fields = {"managedRoutingEnabled", "functionalRelayEnabled", "sourceAppSigningIdentifiers",
        "destinationHostSuffixes", "policyEpoch", "semanticInspectionRequired", "HawkRoutingReceipt",
        "HawkRoutingReceiptSignatureDER", "HawkRoutingReceiptPublicKeyX963",
        "HawkRoutingBrokerKeyAuthorization", "HawkRoutingBrokerKeyAuthorizationSignatureDER"}
    if (not isinstance(configuration, dict) or set(configuration) != fields or
            configuration["managedRoutingEnabled"] is not True or configuration["functionalRelayEnabled"] is not True or
            configuration["semanticInspectionRequired"] is not False or
            configuration["sourceAppSigningIdentifiers"] != scope["application_signing_identifiers"] or
            configuration["destinationHostSuffixes"] != scope["destination_host_suffixes"] or
            type(configuration["policyEpoch"]) is not int or configuration["policyEpoch"] != scope["policy_epoch"]):
        raise ValueError("routing_provider_scope_mismatch")
    try:
        values = {field: base64.b64decode(configuration[field], validate=True) for field in fields if field.startswith("Hawk")}
        receipt = values["HawkRoutingReceipt"]
        public = values["HawkRoutingReceiptPublicKeyX963"]
        authorization_expiry, _ = _verify_broker_key_authorization(
            authorization=values["HawkRoutingBrokerKeyAuthorization"],
            signature_der=values["HawkRoutingBrokerKeyAuthorizationSignatureDER"],
            trust_root_public_key_x963=trust_root_public_key_x963, broker_public_key_x963=public,
            now_unix_seconds=now_unix_seconds)
        if len(receipt) != 84 or receipt[:8] != _MAGIC:
            raise ValueError("routing_receipt_invalid")
        version, issued, expires, epoch = struct.unpack(">IQQQ", receipt[8:36])
        material = ManagedRoutingScope.create(application_signing_identifiers=scope["application_signing_identifiers"],
            destination_host_suffixes=scope["destination_host_suffixes"], policy_epoch=scope["policy_epoch"], semantic_inspection_required=False)
        scope_issued, scope_expires = routing_scope_expiry(scope)
        if (version != 1 or epoch != scope["policy_epoch"] or not scope_issued <= issued <= now_unix_seconds < expires or
                expires - issued > 120 or expires > min(scope_expires, authorization_expiry) or
                receipt[36:68] != material.canonical_digest() or not any(receipt[68:])):
            raise ValueError("routing_receipt_binding_invalid")
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public).verify(
            values["HawkRoutingReceiptSignatureDER"], receipt, ec.ECDSA(hashes.SHA256()))
        return expires
    except (RoutingReceiptError, InvalidSignature, TypeError, KeyError) as exc:
        raise ValueError("routing_receipt_invalid") from exc
