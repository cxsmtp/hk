"""Verified projection of the signed endpoint policy into macOS wire v2.

The module only verifies public-key signatures. Private-key operations remain
with the existing tenant policy and native policy signing boundaries.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from datetime import UTC, datetime, timedelta
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .endpoint_floor.contracts import EndpointPrimitive
from .endpoint_floor.local_policy import EndpointPolicyFastPath, canonical_policy_bytes
from .endpoint_floor.policy_compiler import _SUPPORTED_PREDICATES
from .macos_native import (
    EXTENSION_BUNDLE_IDS, HOST_BUNDLE_ID, macos_code_identity_reference,
)


_BINDING_DOMAIN = b"hawk.macos-native-bindings.v1\0"
_BINDING_FIELDS = {
    "schema", "version", "source_policy_sha256", "tenant_id", "device_id",
    "policy_version", "policy_epoch", "issued_at", "expires_at", "mode",
    "delivery_sequence", "identities", "resource_classifications",
    "destination_classifications",
}
_IDENTITY_FIELDS = {
    "source_identity", "team_id", "signing_id", "cdhash", "platform_binary",
    "identity_sha256",
}
_CLASSIFICATION_FIELDS = {"classification", "mask", "reference_sha256"}
_HEADER_FORMAT = "<IIQQQQIIIIII32s32s40I64s"
_HEADER_SIZE = struct.calcsize(_HEADER_FORMAT)
_RULE_FORMAT = "<QIIIIB7x32s64s"
_RULE_SIZE = struct.calcsize(_RULE_FORMAT)
_CLASSIFICATION_FORMAT = "<32sI"
_CLASSIFICATION_SIZE = struct.calcsize(_CLASSIFICATION_FORMAT)
_NATIVE_PRIMITIVES = {
    "file_open", "file_read", "file_write", "file_create", "file_rename",
    "file_delete", "file_truncate", "file_memory_map", "file_metadata_change",
    "process_execute", "network_connect", "network_quic", "network_localhost",
}
_PRIMITIVE_INDEX = {primitive.value: index for index, primitive in enumerate(EndpointPrimitive)}
_ACTION = {"allow": 0, "block": 1, "allow_with_evidence": 5}
_HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
_HEX_20 = re.compile(r"[0-9a-f]{40}\Z")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def _uint(value: Any, bits: int, name: str) -> int:
    _require(type(value) is int and 0 < value <= (1 << bits) - 1, f"{name} is invalid")
    return value


def _sha256_hex(value: Any, name: str) -> bytes:
    _require(isinstance(value, str) and _HEX_32.fullmatch(value) is not None,
             f"{name} digest is invalid")
    return bytes.fromhex(value)


def _utc_seconds(value: Any, name: str) -> int:
    _require(isinstance(value, str) and value.endswith("Z"), f"{name} UTC is invalid")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{name} UTC is invalid") from exc
    _require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)
             and parsed.microsecond == 0, f"{name} UTC is invalid")
    return _uint(int(parsed.timestamp()), 64, name)


def _binding_shape(bindings: Mapping[str, Any]) -> None:
    _require(isinstance(bindings, dict) and set(bindings) == _BINDING_FIELDS,
             "binding schema is invalid")
    _require(bindings["schema"] == "hawk.macos-native-bindings" and
             bindings["version"] == 1, "binding version is invalid")
    _sha256_hex(bindings["source_policy_sha256"], "source policy")
    for name in ("tenant_id", "device_id", "policy_version"):
        value = bindings[name]
        _require(isinstance(value, str) and 0 < len(value.encode("utf-8")) < 64
                 and "\0" not in value, f"binding {name} is invalid")
    _uint(bindings["policy_epoch"], 64, "policy epoch")
    _uint(bindings["delivery_sequence"], 64, "delivery sequence")
    _require(bindings["mode"] in {"monitor", "enforce"}, "binding mode is invalid")
    issued = _utc_seconds(bindings["issued_at"], "issued")
    expires = _utc_seconds(bindings["expires_at"], "expiry")
    _require(issued < expires and expires - issued <= 86400, "binding lifetime is invalid")
    for name, maximum in (("identities", 256), ("resource_classifications", 1024),
                          ("destination_classifications", 1024)):
        _require(isinstance(bindings[name], list) and len(bindings[name]) <= maximum,
                 f"binding {name} count is invalid")


def binding_signing_bytes(bindings: Mapping[str, Any]) -> bytes:
    """Return domain-separated bytes for the existing tenant Ed25519 signer."""
    _binding_shape(bindings)
    encoded = canonical_policy_bytes(bindings)
    _require(len(encoded) <= 256 * 1024, "binding manifest is oversized")
    return _BINDING_DOMAIN + encoded


def _verified_bindings(envelope: Mapping[str, Any], key: bytes, source_key_id: str) -> dict:
    _require(isinstance(envelope, Mapping) and set(envelope) ==
             {"schema", "version", "key_id", "algorithm", "bindings", "signature"},
             "binding envelope schema is invalid")
    _require(envelope["schema"] == "hawk.macos-native-bindings-envelope"
             and type(envelope["version"]) is int and envelope["version"] == 1
             and all(isinstance(envelope[name], str)
                     for name in ("key_id", "algorithm", "signature"))
             and isinstance(envelope["bindings"], dict),
             "binding envelope schema or version is invalid")
    _require(envelope["key_id"] == source_key_id and envelope["algorithm"] == "Ed25519",
             "binding signer does not match source policy")
    bindings = envelope["bindings"]
    payload = binding_signing_bytes(bindings)
    try:
        signature = base64.b64decode(envelope["signature"], validate=True)
        _require(len(signature) == 64, "binding signature length is invalid")
        Ed25519PublicKey.from_public_bytes(key).verify(signature, payload)
    except (ValueError, TypeError, binascii.Error, InvalidSignature) as exc:
        raise ValueError("binding signature is invalid") from exc
    return dict(bindings)


def _identity_map(bindings: dict, expected: set[str]) -> tuple[dict[str, bytes], bytes]:
    identities: dict[str, bytes] = {}
    digests: set[bytes] = set()
    for row in bindings["identities"]:
        _require(isinstance(row, dict) and set(row) == _IDENTITY_FIELDS,
                 "identity binding schema is invalid")
        source = row["source_identity"]
        team = row["team_id"]
        signing = row["signing_id"]
        cdhash = row["cdhash"]
        platform = row["platform_binary"]
        _require(isinstance(team, str) and re.fullmatch(r"[A-Z0-9]{10}", team) is not None
                 and isinstance(signing, str) and 0 < len(signing.encode("utf-8")) <= 255
                 and isinstance(source, str) and source == f"{team}:{signing}"
                 and isinstance(cdhash, str) and _HEX_20.fullmatch(cdhash) is not None
                 and type(platform) is bool, "identity tuple is invalid")
        digest = _sha256_hex(row["identity_sha256"], "identity")
        _require(digest.hex() == macos_code_identity_reference(team, signing,
                 bytes.fromhex(cdhash), platform), "identity digest mismatch")
        _require(source not in identities and digest not in digests and source in expected,
                 "duplicate or extra identity binding")
        identities[source] = digest
        digests.add(digest)
    _require(set(identities) == expected, "missing signed code identity")
    return identities, b"".join(sorted(digests))


def _classification_map(rows: list, expected: set[str], name: str) -> tuple[dict[str, int], bytes]:
    mapping: dict[str, int] = {}
    references: set[bytes] = set()
    masks: set[int] = set()
    encoded: list[tuple[bytes, int]] = []
    for row in rows:
        _require(isinstance(row, dict) and set(row) == _CLASSIFICATION_FIELDS,
                 f"{name} binding schema is invalid")
        classification = row["classification"]
        mask = row["mask"]
        _require(isinstance(classification, str) and classification in expected
                 and type(mask) is int and 0 < mask <= 0x8000
                 and mask & (mask - 1) == 0, f"{name} classification is invalid")
        digest = _sha256_hex(row["reference_sha256"], name)
        _require(digest not in references, f"duplicate {name} reference")
        if classification in mapping:
            _require(mapping[classification] == mask, f"conflicting {name} mask")
        else:
            _require(mask not in masks, f"ambiguous {name} mask")
            mapping[classification] = mask
            masks.add(mask)
        references.add(digest)
        encoded.append((digest, mask))
    _require(set(mapping) == expected, f"missing or extra {name} classification")
    return mapping, b"".join(struct.pack(_CLASSIFICATION_FORMAT, digest, mask)
                              for digest, mask in sorted(encoded))


def render_native_payload(
    *, source_envelope: Mapping[str, Any], binding_envelope: Mapping[str, Any],
    trusted_public_keys: Mapping[str, bytes], expected_tenant_id: str,
    expected_device_id: str, minimum_delivery_sequence: int,
    minimum_policy_epoch: int, now: datetime | None = None,
) -> bytes:
    """Verify both existing-authority envelopes and render one canonical v2 payload."""
    observed = now or datetime.now(UTC)
    result = EndpointPolicyFastPath.try_load_signed(
        source_envelope, trusted_public_keys=trusted_public_keys,
        expected_tenant_id=expected_tenant_id, expected_device_id=expected_device_id,
        now=observed,
    )
    _require(result.accepted and result.fast_path is not None,
             "signed source policy is invalid")
    policy = source_envelope["policy"]
    _require(policy["version"] == 2, "macOS projection requires source v2")
    key_id = source_envelope["key_id"]
    key = trusted_public_keys.get(key_id)
    _require(isinstance(key, bytes) and len(key) == 32, "tenant policy key is invalid")
    bindings = _verified_bindings(binding_envelope, key, key_id)
    overlap = {
        "tenant_id": "tenant_id", "device_id": "device_id",
        "policy_version": "policy_version", "policy_epoch": "policy_epoch",
        "issued_at": "issued_at", "expires_at": "expires_at",
    }
    _require(all(bindings[binding] == policy[source] for binding, source in overlap.items())
             and bindings["source_policy_sha256"] == hashlib.sha256(
                 canonical_policy_bytes(policy)).hexdigest(),
             "binding/source policy mismatch")
    _require(type(minimum_delivery_sequence) is int and minimum_delivery_sequence >= 0
             and type(minimum_policy_epoch) is int and minimum_policy_epoch >= 0
             and bindings["delivery_sequence"] > minimum_delivery_sequence
             and bindings["policy_epoch"] >= minimum_policy_epoch,
             "native policy rollback")
    _require(_utc_seconds(bindings["issued_at"], "issued") <= int(observed.timestamp())
             < _utc_seconds(bindings["expires_at"], "expiry"),
             "native policy is not current")
    _require(policy["supported_predicates"] == sorted(_SUPPORTED_PREDICATES),
             "source supported_predicates is not canonical")
    for name in ("business_purpose_references", "exception_references", "omitted_predicates",
                 "required_remote_context", "platform_capability_requirements"):
        _require(policy[name] == [], f"source {name} is not projectable")
    _require(policy["user_group_scope"] == {"users": [], "groups": []},
             "user/group scope is not projectable")
    rules = policy["rules"]
    _require(isinstance(rules, list) and 0 < len(rules) <= 4096,
             "native rule count is invalid")
    source_identities: set[str] = set()
    resource_names: set[str] = set()
    destination_names: set[str] = set()
    primitives: set[str] = set()
    for rule in rules:
        match = rule["match"]
        _require(set(match).issubset({"primitives", "resource_classifications",
                                      "destination_classifications", "binary_identities"})
                 and isinstance(match.get("primitives"), list) and match["primitives"]
                 and rule["action"] in _ACTION,
                 "native rule action or predicate is unsupported")
        for scope in ("binary_identities", "resource_classifications", "destination_classifications"):
            _require(scope not in match or bool(match[scope]), "native rule scope is empty")
        if rule["action"] == "block":
            _require(isinstance(match.get("binary_identities"), list)
                     and match["binary_identities"], "non-allow rule is not binary scoped")
        for primitive in match["primitives"]:
            _require(primitive in _NATIVE_PRIMITIVES, "native primitive unsupported")
            primitives.add(primitive)
        for key_name, aggregate in (("binary_identities", source_identities),
                                    ("resource_classifications", resource_names),
                                    ("destination_classifications", destination_names)):
            values = match.get(key_name, [])
            _require(isinstance(values, list) and len(values) <= 1024 and
                     all(isinstance(item, str) and item for item in values),
                     "native rule scope is invalid")
            aggregate.update(values)
    _require(policy["classification_rules"] == sorted(resource_names),
             "source classification_rules does not match rule scopes")
    _require(policy["destination_rules"] == sorted(destination_names),
             "source destination_rules does not match rule scopes")
    _require(set(policy["supported_primitives"]) == primitives,
             "source primitive coverage is incomplete")
    identity_map, identity_bytes = _identity_map(bindings, source_identities)
    resource_map, resource_bytes = _classification_map(
        bindings["resource_classifications"], resource_names, "resource")
    destination_map, destination_bytes = _classification_map(
        bindings["destination_classifications"], destination_names, "destination")
    encoded_rules: list[bytes] = []
    for rule in sorted(rules, key=lambda row: (row["priority"], row["rule_id"])):
        match = rule["match"]
        primitive_mask = sum(1 << _PRIMITIVE_INDEX[name] for name in set(match["primitives"]))
        resource_mask = sum(resource_map[name] for name in set(match.get("resource_classifications", [])))
        destination_mask = sum(destination_map[name] for name in set(match.get("destination_classifications", [])))
        reference = rule["rule_id"].encode("utf-8")
        _require(0 < len(reference) < 64 and b"\0" not in reference,
                 "native rule reference is invalid")
        for identity in sorted(set(match.get("binary_identities", []))) or [None]:
            _require(len(encoded_rules) < 4096, "native rule expansion is oversized")
            encoded_rules.append(struct.pack(
                _RULE_FORMAT, primitive_mask, resource_mask, destination_mask,
                0, _ACTION[rule["action"]], 1 if identity is not None else 0,
                identity_map[identity] if identity is not None else bytes(32),
                reference.ljust(64, b"\0"),
            ))
    policy_version = policy["policy_version"].encode("utf-8")
    _require(0 < len(policy_version) < 64 and b"\0" not in policy_version,
             "native policy version is invalid")
    header = struct.pack(
        _HEADER_FORMAT, 2, 2, bindings["delivery_sequence"], policy["policy_epoch"],
        _utc_seconds(policy["issued_at"], "issued"), _utc_seconds(policy["expires_at"], "expiry"),
        len(encoded_rules), 0, len(identity_bytes) // 32,
        len(resource_bytes) // _CLASSIFICATION_SIZE,
        len(destination_bytes) // _CLASSIFICATION_SIZE,
        2 if bindings["mode"] == "enforce" else 1,
        hashlib.sha256(expected_tenant_id.encode("utf-8")).digest(),
        hashlib.sha256(expected_device_id.encode("utf-8")).digest(),
        *([0] * 40), policy_version.ljust(64, b"\0"),
    )
    payload = header + b"".join(encoded_rules) + identity_bytes + resource_bytes + destination_bytes
    _require(len(payload) <= 2 * 1024 * 1024 - 96, "native policy payload is oversized")
    return payload


def _inspect_payload(payload: bytes) -> tuple[int, int, int, int, int, int, int, int, int]:
    _require(isinstance(payload, bytes) and len(payload) >= _HEADER_SIZE,
             "native payload is invalid")
    fields = struct.unpack_from(_HEADER_FORMAT, payload)
    schema, floor, sequence, epoch, issued, expires, rules, permits, identities, resources, destinations, mode = fields[:12]
    expected = (_HEADER_SIZE + rules * _RULE_SIZE + permits * 196 +
                identities * 32 + (resources + destinations) * _CLASSIFICATION_SIZE)
    _require(schema == 2 and floor == 2 and sequence > 0 and epoch > 0 and
             issued < expires and expires - issued <= 86400 and
             rules <= 4096 and permits == 0 and identities <= 256 and
             resources <= 1024 and destinations <= 1024 and mode in (1, 2) and
             expected == len(payload) and all(value == 0 for value in fields[14:54]),
             "native payload header is invalid")
    return sequence, epoch, issued, expires, rules, identities, resources, destinations, mode


def render_routing_signing_bytes(*, source_envelope: Mapping[str, Any],
        binding_envelope: Mapping[str, Any], native_envelope: bytes, public_key_x963: bytes,
        trusted_public_keys: Mapping[str, bytes], expected_tenant_id: str, expected_device_id: str,
        destination_host_suffixes: list[str], minimum_delivery_sequence: int,
        minimum_policy_epoch: int, now: datetime | None = None) -> bytes:
    from .macos_routing import routing_scope_signing_bytes
    payload = render_native_payload(source_envelope=source_envelope, binding_envelope=binding_envelope,
        trusted_public_keys=trusted_public_keys, expected_tenant_id=expected_tenant_id,
        expected_device_id=expected_device_id, minimum_delivery_sequence=minimum_delivery_sequence,
        minimum_policy_epoch=minimum_policy_epoch, now=now)
    _require(isinstance(native_envelope, bytes) and len(native_envelope) >= 16, "native envelope invalid")
    schema, length, signature_length, reserved = struct.unpack_from("<IIII", native_envelope)
    _require(schema == 2 and reserved == 0 and length == len(payload) and
        native_envelope[16:16 + length] == payload and len(native_envelope) == 16 + length + signature_length,
        "routing/native policy binding mismatch")
    _require(assemble_native_envelope(payload, native_envelope[16 + length:], public_key_x963) == native_envelope,
        "routing/native signature mismatch")
    policy = source_envelope["policy"]
    bindings = binding_envelope["bindings"]
    network_identities: set[str] = set()
    for rule in policy["rules"]:
        if set(rule["match"]["primitives"]) & {"network_connect", "network_quic", "network_localhost"}:
            _require(bool(rule["match"].get("binary_identities")), "routing network rule is unscoped")
            network_identities.update(rule["match"]["binary_identities"])
    applications = sorted({row["signing_id"] for row in bindings["identities"] if row["source_identity"] in network_identities})
    return routing_scope_signing_bytes({
        "schema": "hawk.macos-routing-scope", "version": 1,
        "source_policy_sha256": bindings["source_policy_sha256"],
        "native_policy_sha256": hashlib.sha256(native_envelope).hexdigest(),
        **{field: bindings[field] for field in ("tenant_id", "device_id", "policy_version", "policy_epoch",
            "delivery_sequence", "mode", "issued_at", "expires_at")},
        "routing_transport": "direct_transparent_relay", "application_signing_identifiers": applications,
        "destination_host_suffixes": destination_host_suffixes, "semantic_inspection_required": False,
    })


def _public_key(public_key_x963: bytes) -> ec.EllipticCurvePublicKey:
    _require(isinstance(public_key_x963, bytes) and len(public_key_x963) == 65
             and public_key_x963[0] == 4, "native public key is invalid")
    try:
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_x963)
    except ValueError as exc:
        raise ValueError("native public key is invalid") from exc
    return key


def assemble_native_envelope(payload: bytes, detached_signature: bytes,
                             public_key_x963: bytes) -> bytes:
    """Verify a purpose-scoped external ES256 signature and frame wire v2."""
    _inspect_payload(payload)
    key = _public_key(public_key_x963)
    _require(isinstance(detached_signature, bytes), "native signature is invalid")
    signature = detached_signature
    if len(signature) == 64:
        signature = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                         int.from_bytes(signature[32:], "big"))
    _require(8 <= len(signature) <= 80, "native signature length is invalid")
    try:
        key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("native signature is invalid") from exc
    envelope = struct.pack("<IIII", 2, len(payload), len(signature), 0) + payload + signature
    _require(len(envelope) <= 2 * 1024 * 1024, "native envelope is oversized")
    return envelope


def build_managed_config(envelope: bytes, public_key_x963: bytes,
                         team_id: str) -> dict[str, Any]:
    """Return exact host plist fields from the same verified wire envelope."""
    _require(isinstance(envelope, bytes) and len(envelope) >= 16 + _HEADER_SIZE,
             "native envelope is invalid")
    schema, length, signature_length, reserved = struct.unpack_from("<IIII", envelope)
    _require(schema == 2 and reserved == 0 and 16 + length + signature_length == len(envelope),
             "native envelope framing is invalid")
    payload = envelope[16:16 + length]
    signature = envelope[16 + length:]
    _require(assemble_native_envelope(payload, signature, public_key_x963) == envelope,
             "native envelope signature is invalid")
    _require(isinstance(team_id, str) and re.fullmatch(r"[A-Z0-9]{10}", team_id) is not None,
             "managed Team ID is invalid")
    _, epoch, issued, expires, _, _, _, _, mode = _inspect_payload(payload)
    version = struct.unpack_from(_HEADER_FORMAT, payload)[-1].split(b"\0", 1)[0].decode("utf-8")
    _require(bool(version), "native policy version is invalid")
    return {
        "HawkPolicyEnvelope": envelope,
        "HawkPolicySigningPublicKeyX963": public_key_x963,
        "HawkTeamIdentifier": team_id,
        "HawkHostBundleIdentifier": HOST_BUNDLE_ID,
        "HawkEndpointSecurityBundleIdentifier": EXTENSION_BUNDLE_IDS[0],
        "HawkContentFilterBundleIdentifier": EXTENSION_BUNDLE_IDS[1],
        "HawkRoutingBundleIdentifier": EXTENSION_BUNDLE_IDS[2],
        "HawkPolicyEpoch": epoch, "HawkPolicyVersion": version,
        "HawkPolicyMode": "enforce" if mode == 2 else "monitor",
        "HawkPolicyIssuedAtUnixSeconds": issued,
        "HawkPolicyExpiresAtUnixSeconds": expires,
    }


def verify_managed_routing_authority(config: Mapping[str, Any], *, trusted_public_keys: Mapping[str, bytes],
        tenant_id: str, device_id: str, now: datetime | None = None) -> dict:
    from .macos_routing import verify_routing_scope, ROUTING_SCOPE_DOMAIN
    source = json.loads(config["HawkSourcePolicyEnvelopeJSON"])
    binding = json.loads(config["HawkNativeBindingEnvelopeJSON"])
    envelope = json.loads(config["HawkRoutingScopeEnvelopeJSON"])
    scope = verify_routing_scope(envelope, trusted_public_keys=trusted_public_keys,
        expected_key_id=source["key_id"], now=now)
    signing = render_routing_signing_bytes(source_envelope=source, binding_envelope=binding,
        native_envelope=config["HawkPolicyEnvelope"], public_key_x963=config["HawkPolicySigningPublicKeyX963"],
        trusted_public_keys=trusted_public_keys, expected_tenant_id=tenant_id, expected_device_id=device_id,
        destination_host_suffixes=scope["destination_host_suffixes"], minimum_delivery_sequence=0,
        minimum_policy_epoch=0, now=now)
    _require(signing == ROUTING_SCOPE_DOMAIN + base64.b64decode(envelope["payload"], validate=True),
        "managed routing authority cross-binding mismatch")
    return scope
