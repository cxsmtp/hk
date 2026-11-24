from __future__ import annotations

import base64
import copy
import hashlib
import struct
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hawk_endpoint_agent.endpoint_floor.local_policy import canonical_policy_bytes
from hawk_endpoint_agent.endpoint_floor.policy_compiler import EndpointPolicyCompiler
from hawk_endpoint_agent.macos_native import macos_code_identity_reference
from hawk_endpoint_agent.macos_policy_compiler import (
    assemble_native_envelope,
    binding_signing_bytes,
    build_managed_config,
    render_native_payload,
)


NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)
SOURCE_PRIVATE = Ed25519PrivateKey.from_private_bytes(b"\x31" * 32)
SOURCE_PUBLIC = SOURCE_PRIVATE.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw,
)


def _policy(*, policy_epoch: int = 7, rules: list[dict] | None = None) -> dict:
    return EndpointPolicyCompiler().compile(
        {"rules": rules if rules is not None else [{
            "rule_id": "block-secret", "priority": 10,
            "match": {"primitives": ["file_read"],
                      "resource_classifications": ["restricted"],
                      "binary_identities": ["ABCDEFGHIJ:ai.hawk.claude"]},
            "action": "block",
        }]},
        tenant_id="tenant-1", device_id="device-1", policy_version="policy-7",
        policy_epoch=policy_epoch, rollback_version=None,
        issued_at="2026-09-27T09:55:00Z", expires_at="2026-09-27T10:05:00Z",
        platform_capability_requirements=[],
    )


def _source_envelope(policy: dict) -> dict:
    return {
        "key_id": "tenant-policy-1", "algorithm": "Ed25519", "policy": policy,
        "signature": base64.b64encode(SOURCE_PRIVATE.sign(canonical_policy_bytes(policy))).decode(),
    }


def _bindings(policy: dict) -> dict:
    cdhash = bytes(range(20))
    return {
        "schema": "hawk.macos-native-bindings", "version": 1,
        "source_policy_sha256": hashlib.sha256(canonical_policy_bytes(policy)).hexdigest(),
        "tenant_id": policy["tenant_id"], "device_id": policy["device_id"],
        "policy_version": policy["policy_version"], "policy_epoch": policy["policy_epoch"],
        "issued_at": policy["issued_at"], "expires_at": policy["expires_at"],
        "mode": "enforce", "delivery_sequence": 9,
        "identities": [{
            "source_identity": "ABCDEFGHIJ:ai.hawk.claude",
            "team_id": "ABCDEFGHIJ", "signing_id": "ai.hawk.claude",
            "cdhash": cdhash.hex(), "platform_binary": False,
            "identity_sha256": macos_code_identity_reference(
                "ABCDEFGHIJ", "ai.hawk.claude", cdhash, False),
        }],
        "resource_classifications": [{
            "classification": "restricted", "mask": 1,
            "reference_sha256": "a1" * 32,
        }],
        "destination_classifications": [],
    }


def _binding_envelope(bindings: dict) -> dict:
    return {
        "schema": "hawk.macos-native-bindings-envelope", "version": 1,
        "key_id": "tenant-policy-1", "algorithm": "Ed25519", "bindings": bindings,
        "signature": base64.b64encode(SOURCE_PRIVATE.sign(binding_signing_bytes(bindings))).decode(),
    }


def _render(policy: dict | None = None, bindings: dict | None = None, *,
            minimum_delivery_sequence: int = 8, minimum_policy_epoch: int = 7,
            binding_envelope: dict | None = None) -> bytes:
    policy = policy or _policy()
    bindings = bindings or _bindings(policy)
    return render_native_payload(
        source_envelope=_source_envelope(policy),
        binding_envelope=binding_envelope if binding_envelope is not None else _binding_envelope(bindings),
        trusted_public_keys={"tenant-policy-1": SOURCE_PUBLIC},
        expected_tenant_id="tenant-1", expected_device_id="device-1",
        minimum_delivery_sequence=minimum_delivery_sequence,
        minimum_policy_epoch=minimum_policy_epoch, now=NOW,
    )


def test_signed_projection_is_deterministic_and_native_header_is_bounded() -> None:
    policy = _policy()
    assert policy["supported_predicates"] == [
        "ai_assets", "application_assets", "binary_identities", "business_purposes",
        "destination_classifications", "primitives", "resource_classifications", "users",
    ]
    assert policy["classification_rules"] == ["restricted"]
    assert policy["policy_sequence"] == policy["policy_epoch"] == 7
    payload = _render(policy)
    assert payload == _render()
    header = struct.unpack_from("<IIQQQQIIIIII", payload)
    assert header[:6] == (2, 2, 9, 7, int(NOW.timestamp()) - 300, int(NOW.timestamp()) + 300)
    assert header[6:] == (1, 0, 1, 1, 0, 2)
    assert len(payload) == 352 + 128 + 32 + 36


def test_delivery_sequence_is_independent_of_source_policy_sequence() -> None:
    policy = _policy(policy_epoch=41)
    assert policy["policy_sequence"] == policy["policy_epoch"] == 41
    bindings = _bindings(policy)
    bindings["delivery_sequence"] = 3
    payload = _render(policy, bindings, minimum_delivery_sequence=2, minimum_policy_epoch=41)
    assert struct.unpack_from("<IIQQ", payload) == (2, 2, 3, 41)
    with pytest.raises(ValueError, match="native policy rollback"):
        _render(policy, bindings, minimum_delivery_sequence=3, minimum_policy_epoch=41)
    with pytest.raises(ValueError, match="native policy rollback"):
        _render(policy, bindings, minimum_delivery_sequence=2, minimum_policy_epoch=42)


def test_canonical_destination_metadata_projects_with_exact_bindings() -> None:
    rules = copy.deepcopy(_policy()["rules"])
    rules[0]["match"]["primitives"] = ["network_connect"]
    rules[0]["match"]["destination_classifications"] = ["external"]
    policy = _policy(rules=rules)
    assert policy["classification_rules"] == ["restricted"]
    assert policy["destination_rules"] == ["external"]
    bindings = _bindings(policy)
    bindings["destination_classifications"] = [{
        "classification": "external", "mask": 2, "reference_sha256": "b1" * 32,
    }]
    assert struct.unpack_from("<IIQQQQIIIIII", _render(policy, bindings))[6:] == (1, 0, 1, 1, 1, 2)


@pytest.mark.parametrize("field", ["supported_predicates", "classification_rules", "destination_rules"])
@pytest.mark.parametrize("mutation", ["missing", "extra", "duplicate"])
def test_canonical_metadata_must_exactly_match_compiler_aggregates(field: str, mutation: str) -> None:
    rules = copy.deepcopy(_policy()["rules"])
    rules[0]["match"]["destination_classifications"] = ["external"]
    policy = _policy(rules=rules)
    if mutation == "missing":
        policy[field].pop()
    elif mutation == "extra":
        policy[field].append("unexpected")
    else:
        policy[field].append(policy[field][0])
    with pytest.raises(ValueError, match=f"source {field}"):
        _render(policy)


@pytest.mark.parametrize("field", [
    "business_purpose_references", "exception_references", "omitted_predicates",
    "required_remote_context", "platform_capability_requirements", "user_group_scope",
])
def test_unsupported_source_authority_remains_rejected(field: str) -> None:
    policy = _policy()
    policy[field] = {"users": ["user-1"], "groups": []} if field == "user_group_scope" else ["unsupported"]
    with pytest.raises(ValueError, match="not projectable"):
        _render(policy)


@pytest.mark.parametrize("field", ["binary_identities", "resource_classifications", "destination_classifications"])
@pytest.mark.parametrize("action", ["allow", "allow_with_evidence", "block"])
def test_explicit_empty_native_scope_is_never_projected_as_wildcard(field: str, action: str) -> None:
    rules = copy.deepcopy(_policy()["rules"])
    rules[0]["action"] = action
    rules[0]["match"][field] = []
    policy = _policy(rules=rules)
    assert policy["rules"][0]["match"][field] == []
    with pytest.raises(ValueError, match="native rule scope is empty"):
        _render(policy)


@pytest.mark.parametrize("field", ["schema", "version", "key_id", "algorithm", "bindings", "signature"])
@pytest.mark.parametrize("mutation", ["missing", "wrong_type"])
def test_binding_envelope_requires_exact_typed_fields(field: str, mutation: str) -> None:
    envelope = _binding_envelope(_bindings(_policy()))
    if mutation == "missing":
        del envelope[field]
    else:
        envelope[field] = True if field == "version" else 1
    with pytest.raises(ValueError, match="binding envelope"):
        _render(binding_envelope=envelope)


@pytest.mark.parametrize("mutation", ["extra", "schema", "version"])
def test_binding_envelope_rejects_extra_or_unknown_schema_version(mutation: str) -> None:
    envelope = _binding_envelope(_bindings(_policy()))
    envelope[mutation] = "unexpected" if mutation != "version" else 2
    with pytest.raises(ValueError, match="binding envelope"):
        _render(binding_envelope=envelope)


@pytest.mark.parametrize("mutation", [
    "bad_policy_signature", "bad_binding_signature", "binding_digest", "binding_device",
    "binding_mode", "old_sequence", "old_epoch", "extra_classification",
    "missing_identity", "unscoped_block", "unsupported_action", "unsupported_predicate",
])
def test_projection_rejects_unauthorized_or_unsupported_input(mutation: str) -> None:
    policy = _policy()
    bindings = _bindings(policy)
    if mutation == "binding_digest":
        bindings["source_policy_sha256"] = "0" * 64
    elif mutation == "binding_device":
        bindings["device_id"] = "other-device"
    elif mutation == "old_sequence":
        bindings["delivery_sequence"] = 8
    elif mutation == "old_epoch":
        bindings["policy_epoch"] = 6
    elif mutation == "extra_classification":
        bindings["resource_classifications"].append({
            "classification": "extra", "mask": 2, "reference_sha256": "a2" * 32})
    elif mutation == "missing_identity":
        bindings["identities"] = []
    elif mutation == "unscoped_block":
        policy["rules"][0]["match"].pop("binary_identities")
        bindings = _bindings(policy)
    elif mutation == "unsupported_action":
        policy["rules"][0]["action"] = "require_remote_decision"
        bindings = _bindings(policy)
    elif mutation == "unsupported_predicate":
        policy["rules"][0]["match"]["users"] = ["user-1"]
        bindings = _bindings(policy)
    source = _source_envelope(policy)
    binding = _binding_envelope(bindings)
    if mutation == "binding_mode":
        binding["bindings"]["mode"] = "unsafe"
    if mutation == "bad_policy_signature":
        source["signature"] = base64.b64encode(bytes(64)).decode()
    if mutation == "bad_binding_signature":
        binding["signature"] = base64.b64encode(bytes(64)).decode()
    with pytest.raises(ValueError):
        render_native_payload(
            source_envelope=source, binding_envelope=binding,
            trusted_public_keys={"tenant-policy-1": SOURCE_PUBLIC},
            expected_tenant_id="tenant-1", expected_device_id="device-1",
            minimum_delivery_sequence=8, minimum_policy_epoch=7, now=NOW,
        )


def test_detached_p256_assembly_and_managed_config_bind_same_envelope() -> None:
    payload = _render()
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    envelope = assemble_native_envelope(payload, signature, public)
    assert envelope[:16] == struct.pack("<IIII", 2, len(payload), len(signature), 0)
    managed = build_managed_config(envelope, public, "ABCDEFGHIJ")
    assert managed["HawkPolicyEnvelope"] == envelope
    assert managed["HawkTeamIdentifier"] == "ABCDEFGHIJ"
    with pytest.raises(ValueError):
        assemble_native_envelope(payload + b"\0", signature, public)
    with pytest.raises(ValueError):
        assemble_native_envelope(payload, signature[:-1] + b"\0", public)


def _routing_fixture():
    from hawk_endpoint_agent.macos_policy_compiler import render_routing_signing_bytes
    rules = copy.deepcopy(_policy()["rules"])
    rules[0]["match"]["primitives"] = ["network_connect", "network_quic"]
    policy = _policy(rules=rules)
    bindings = _bindings(policy)
    native_key = ec.generate_private_key(ec.SECP256R1())
    public = native_key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    payload = _render(policy, bindings)
    native = assemble_native_envelope(payload, native_key.sign(payload, ec.ECDSA(hashes.SHA256())), public)
    arguments = dict(source_envelope=_source_envelope(policy), binding_envelope=_binding_envelope(bindings),
        native_envelope=native, public_key_x963=public, trusted_public_keys={"tenant-policy-1": SOURCE_PUBLIC},
        expected_tenant_id="tenant-1", expected_device_id="device-1", destination_host_suffixes=["api.example.com"],
        minimum_delivery_sequence=8, minimum_policy_epoch=7, now=NOW)
    signing = render_routing_signing_bytes(**arguments)
    envelope = {"schema": "hawk.macos-routing-scope-envelope", "version": 1,
        "key_id": "tenant-policy-1", "algorithm": "Ed25519",
        "payload": base64.b64encode(signing.split(b"\0", 1)[1]).decode(),
        "signature": base64.b64encode(SOURCE_PRIVATE.sign(signing)).decode()}
    return arguments, envelope, native_key


def test_routing_scope_real_compiler_signature_and_native_binding() -> None:
    from hawk_endpoint_agent.macos_routing import verify_routing_scope
    arguments, envelope, _ = _routing_fixture()
    payload = verify_routing_scope(envelope, trusted_public_keys=arguments["trusted_public_keys"],
        expected_key_id="tenant-policy-1", now=NOW)
    assert payload["native_policy_sha256"] == hashlib.sha256(arguments["native_envelope"]).hexdigest()
    assert payload["source_policy_sha256"] == hashlib.sha256(canonical_policy_bytes(arguments["source_envelope"]["policy"])).hexdigest()
    assert payload["application_signing_identifiers"] == ["ai.hawk.claude"]
    assert payload["routing_transport"] == "direct_transparent_relay"
    assert payload["semantic_inspection_required"] is False


@pytest.mark.parametrize("field,value", [
    ("schema", "other"), ("version", True), ("mode", "unsafe"),
    ("semantic_inspection_required", True), ("routing_transport", "gateway"),
    ("destination_host_suffixes", ["*.example.com"]), ("destination_host_suffixes", ["127.0.0.1"]),
    ("destination_host_suffixes", ["EXAMPLE.COM"]), ("destination_host_suffixes", ["api.example.com", "api.example.com"]),
    ("destination_host_suffixes", ["https://example.com"]), ("destination_host_suffixes", []),
    ("application_signing_identifiers", ["bad app"]), ("policy_epoch", True),
])
def test_routing_scope_rejects_noncanonical_authority(field, value) -> None:
    import json
    from hawk_endpoint_agent.macos_routing import verify_routing_scope
    arguments, envelope, _ = _routing_fixture()
    payload = json.loads(base64.b64decode(envelope["payload"]))
    payload[field] = value
    raw = canonical_policy_bytes(payload)
    envelope["payload"] = base64.b64encode(raw).decode()
    envelope["signature"] = base64.b64encode(SOURCE_PRIVATE.sign(b"hawk.macos-routing-scope.v1\0" + raw)).decode()
    with pytest.raises(ValueError):
        verify_routing_scope(envelope, trusted_public_keys=arguments["trusted_public_keys"],
            expected_key_id="tenant-policy-1", now=NOW)


@pytest.mark.parametrize("mutation", ["key", "signature", "extra", "native", "applications"])
def test_routing_scope_rejects_unsigned_or_unbound_inputs(mutation) -> None:
    from hawk_endpoint_agent.macos_policy_compiler import render_routing_signing_bytes
    from hawk_endpoint_agent.macos_routing import verify_routing_scope
    arguments, envelope, _ = _routing_fixture()
    if mutation in {"native", "applications"}:
        if mutation == "native":
            arguments["native_envelope"] += b"\0"
        else:
            arguments["source_envelope"]["policy"]["rules"][0]["match"].pop("binary_identities")
        with pytest.raises(ValueError):
            render_routing_signing_bytes(**arguments)
    else:
        if mutation == "key":
            envelope["key_id"] = "other"
        elif mutation == "signature":
            envelope["signature"] = base64.b64encode(bytes(64)).decode()
        else:
            envelope["extra"] = True
        with pytest.raises(ValueError):
            verify_routing_scope(envelope, trusted_public_keys=arguments["trusted_public_keys"],
                expected_key_id="tenant-policy-1", now=NOW)
