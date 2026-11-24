from __future__ import annotations

import base64
import copy
import json
import struct
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from hawk_endpoint_agent.auth.device_key import EphemeralDeviceKeyProvider
from hawk_endpoint_agent.macos_routing import (
    MacRoutingReceiptIssuer,
    ManagedRoutingScope,
    RoutingReceiptError,
    create_broker_key_authorization,
)


def _issuer() -> MacRoutingReceiptIssuer:
    provider = EphemeralDeviceKeyProvider()
    identity = provider.ensure_key("endpoint-test")
    trust_root = ec.generate_private_key(ec.SECP256R1())
    broker_public_key = serialization.load_pem_public_key(
        identity.public_key_pem.encode("ascii")
    )
    broker_public_key_x963 = broker_public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    authorization = create_broker_key_authorization(
        broker_public_key_x963=broker_public_key_x963,
        issued_at_unix_seconds=1_999_999_900,
        expires_at_unix_seconds=2_002_591_900,
        key_epoch=3,
        nonce=b"3" * 16,
    )
    return MacRoutingReceiptIssuer(
        provider=provider,
        identity=identity,
        broker_key_authorization=authorization,
        broker_key_authorization_signature_der=trust_root.sign(
            authorization, ec.ECDSA(hashes.SHA256())
        ),
        trust_root_public_key_x963=trust_root.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ),
        clock=lambda: 2_000_000_000.0,
        nonce_source=lambda size: b"Z" * size,
        require_hardware_backed=False,
    )


def test_issue_binds_scope_epoch_expiry_and_hardware_identity_key() -> None:
    issued = _issuer().issue(
        application_signing_identifiers=[
            "com.example.helper",
            "com.example.ai",
            "com.example.ai",
        ],
        destination_host_suffixes=["MODELS.EXAMPLE.COM.", "api.example.com"],
        policy_epoch=41,
        semantic_inspection_required=True,
        lifetime_seconds=120,
    )

    configuration = issued.provider_configuration
    assert configuration["managedRoutingEnabled"] is True
    assert configuration["functionalRelayEnabled"] is True
    assert configuration["sourceAppSigningIdentifiers"] == [
        "com.example.ai",
        "com.example.helper",
    ]
    assert configuration["destinationHostSuffixes"] == [
        "api.example.com",
        "models.example.com",
    ]
    assert configuration["policyEpoch"] == 41
    assert configuration["semanticInspectionRequired"] is True
    assert "bankReadinessReceipt" not in configuration
    assert "HawkRoutingTrustRootPublicKeyX963Base64" not in configuration

    receipt = base64.b64decode(configuration["HawkRoutingReceipt"], validate=True)
    signature = base64.b64decode(
        configuration["HawkRoutingReceiptSignatureDER"], validate=True
    )
    public_key_x963 = base64.b64decode(
        configuration["HawkRoutingReceiptPublicKeyX963"], validate=True
    )
    key_authorization = base64.b64decode(
        configuration["HawkRoutingBrokerKeyAuthorization"], validate=True
    )
    key_authorization_signature = base64.b64decode(
        configuration["HawkRoutingBrokerKeyAuthorizationSignatureDER"],
        validate=True,
    )
    assert len(receipt) == 84
    assert receipt[:8] == b"HAWKRR01"
    version, issued_at, expires_at, epoch = struct.unpack(">IQQQ", receipt[8:36])
    assert (version, issued_at, expires_at, epoch) == (
        1,
        2_000_000_000,
        2_000_000_120,
        41,
    )
    assert receipt[36:68] == issued.scope.canonical_digest()
    assert issued.scope.canonical_digest().hex() == (
        "7d3246e9bc27218bff22b03ca980f694c35f7d6e06000a7b"
        "391a5af0c3634258"
    )
    assert receipt[68:] == b"Z" * 16
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_x963
    )
    public_key.verify(signature, receipt, ec.ECDSA(hashes.SHA256()))
    assert len(key_authorization) == 84
    assert key_authorization[:8] == b"HAWKRK01"
    assert key_authorization_signature


def test_scope_normalization_is_strict_and_digest_is_materially_bound() -> None:
    scope = ManagedRoutingScope.create(
        application_signing_identifiers=["com.example.ai"],
        destination_host_suffixes=["api.example.com"],
        policy_epoch=7,
        semantic_inspection_required=False,
    )
    changed = ManagedRoutingScope.create(
        application_signing_identifiers=["com.example.ai"],
        destination_host_suffixes=["api.example.com"],
        policy_epoch=7,
        semantic_inspection_required=True,
    )

    assert scope.canonical_digest() != changed.canonical_digest()
    for bad_destination in ("", ".example.com", "exa mple.com", "é.example"):
        with pytest.raises(RoutingReceiptError):
            ManagedRoutingScope.create(
                application_signing_identifiers=["com.example.ai"],
                destination_host_suffixes=[bad_destination],
                policy_epoch=7,
                semantic_inspection_required=False,
            )


def test_issuer_refuses_long_lived_or_non_hardware_production_receipts() -> None:
    provider = EphemeralDeviceKeyProvider()
    identity = provider.ensure_key("endpoint-test")
    with pytest.raises(RoutingReceiptError, match="hardware-backed"):
        MacRoutingReceiptIssuer(
            provider=provider,
            identity=identity,
            broker_key_authorization=b"invalid",
            broker_key_authorization_signature_der=b"invalid",
            trust_root_public_key_x963=b"invalid",
        )

    issuer = _issuer()
    with pytest.raises(RoutingReceiptError, match="lifetime"):
        issuer.issue(
            application_signing_identifiers=["com.example.ai"],
            destination_host_suffixes=["api.example.com"],
            policy_epoch=1,
            semantic_inspection_required=True,
            lifetime_seconds=901,
        )


def test_issuer_refuses_public_identity_mismatch() -> None:
    signing_provider = EphemeralDeviceKeyProvider()
    other_provider = EphemeralDeviceKeyProvider()
    other_identity = other_provider.ensure_key("other")
    trust_root = ec.generate_private_key(ec.SECP256R1())
    other_public_key = serialization.load_pem_public_key(
        other_identity.public_key_pem.encode("ascii")
    )
    other_public_key_x963 = other_public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    authorization = create_broker_key_authorization(
        broker_public_key_x963=other_public_key_x963,
        issued_at_unix_seconds=1_999_999_900,
        expires_at_unix_seconds=2_002_591_900,
        key_epoch=3,
        nonce=b"3" * 16,
    )

    with pytest.raises(RoutingReceiptError, match="identity mismatch"):
        MacRoutingReceiptIssuer(
            provider=signing_provider,
            identity=other_identity,
            broker_key_authorization=authorization,
            broker_key_authorization_signature_der=trust_root.sign(
                authorization, ec.ECDSA(hashes.SHA256())
            ),
            trust_root_public_key_x963=trust_root.public_key().public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            ),
            require_hardware_backed=False,
        )


def test_receipt_cannot_outlive_root_signed_broker_key_authorization() -> None:
    provider = EphemeralDeviceKeyProvider()
    identity = provider.ensure_key("endpoint-test")
    trust_root = ec.generate_private_key(ec.SECP256R1())
    public_key = serialization.load_pem_public_key(
        identity.public_key_pem.encode("ascii")
    )
    public_key_x963 = public_key.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    authorization = create_broker_key_authorization(
        broker_public_key_x963=public_key_x963,
        issued_at_unix_seconds=1_999_999_900,
        expires_at_unix_seconds=2_000_000_030,
        key_epoch=3,
        nonce=b"3" * 16,
    )
    issuer = MacRoutingReceiptIssuer(
        provider=provider,
        identity=identity,
        broker_key_authorization=authorization,
        broker_key_authorization_signature_der=trust_root.sign(
            authorization, ec.ECDSA(hashes.SHA256())
        ),
        trust_root_public_key_x963=trust_root.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        ),
        clock=lambda: 2_000_000_000.0,
        nonce_source=lambda size: b"Z" * size,
        require_hardware_backed=False,
    )

    with pytest.raises(RoutingReceiptError, match="authorization expires"):
        issuer.issue(
            application_signing_identifiers=["com.example.ai"],
            destination_host_suffixes=["api.example.com"],
            policy_epoch=1,
            semantic_inspection_required=False,
            lifetime_seconds=120,
        )


def _authorized_provider_configuration():
    from test_macos_policy_compiler import _routing_fixture, NOW
    from hawk_endpoint_agent.macos_routing import issue_authorized_routing_configuration, verify_routing_scope
    arguments, envelope, trust_root = _routing_fixture()
    scope = verify_routing_scope(envelope, trusted_public_keys=arguments["trusted_public_keys"],
        expected_key_id="tenant-policy-1", now=NOW)
    provider = EphemeralDeviceKeyProvider()
    identity = replace(provider.ensure_key("device-1"), hardware_backed=True)
    key = serialization.load_pem_public_key(identity.public_key_pem.encode()).public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    authorization = create_broker_key_authorization(broker_public_key_x963=key,
        issued_at_unix_seconds=int(NOW.timestamp()) - 100,
        expires_at_unix_seconds=int(NOW.timestamp()) + 90, key_epoch=1, nonce=b"a" * 16)
    issuer = MacRoutingReceiptIssuer(provider=provider, identity=identity,
        broker_key_authorization=authorization,
        broker_key_authorization_signature_der=trust_root.sign(authorization, ec.ECDSA(hashes.SHA256())),
        trust_root_public_key_x963=arguments["public_key_x963"], clock=lambda: NOW.timestamp(),
        require_hardware_backed=True)
    config = issue_authorized_routing_configuration(issuer, scope, now_unix_seconds=int(NOW.timestamp()))
    return config, scope, arguments["public_key_x963"], int(NOW.timestamp())


def test_authorized_provider_configuration_python_and_swift_verifiers(tmp_path: Path) -> None:
    from hawk_endpoint_agent.macos_routing import verify_routing_provider_configuration
    configuration, scope, root, now = _authorized_provider_configuration()
    assert verify_routing_provider_configuration(configuration, scope=scope,
        trust_root_public_key_x963=root, now_unix_seconds=now) == now + 90
    source = Path(__file__).resolve().parents[1] / "native/macos/network-extension/HawkRoutingReadinessReceipt.swift"
    harness = tmp_path / "main.swift"
    harness.write_text('''import Foundation
let raw = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
let c = try JSONSerialization.jsonObject(with: raw) as! [String: Any]
func data(_ key: String) -> Data { Data(base64Encoded: c[key] as! String)! }
let scope = try HawkManagedRoutingScopeMaterial(applicationSigningIdentifiers: c["sourceAppSigningIdentifiers"] as! [String], destinationHostSuffixes: c["destinationHostSuffixes"] as! [String], policyEpoch: (c["policyEpoch"] as! NSNumber).uint64Value, semanticInspectionRequired: false)
let now = UInt64(CommandLine.arguments[3])!
let valid = HawkRoutingBrokerAuthorizationVerifier.verify(authorization: data("HawkRoutingBrokerKeyAuthorization"), signatureDER: data("HawkRoutingBrokerKeyAuthorizationSignatureDER"), trustRootPublicKeyX963: Data(base64Encoded: CommandLine.arguments[2])!, brokerPublicKeyX963: data("HawkRoutingReceiptPublicKeyX963"), nowUnixSeconds: now) && HawkRoutingReceiptVerifier.verify(receipt: data("HawkRoutingReceipt"), signatureDER: data("HawkRoutingReceiptSignatureDER"), publicKeyX963: data("HawkRoutingReceiptPublicKeyX963"), scope: scope, nowUnixSeconds: now)
assert(valid == (CommandLine.arguments[4] == "valid"))
''')
    executable = tmp_path / "receipt-test"
    compiled = subprocess.run(["/usr/bin/xcrun", "swiftc", "-module-cache-path", str(tmp_path / "module-cache"),
        str(source), str(harness), "-o", str(executable)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    for mutation in ("valid", "destination", "signature", "authorization", "expired"):
        changed = copy.deepcopy(configuration)
        if mutation == "destination":
            changed["destinationHostSuffixes"] = ["other.example.com"]
        elif mutation in {"signature", "authorization"}:
            field = "HawkRoutingReceiptSignatureDER" if mutation == "signature" else "HawkRoutingBrokerKeyAuthorizationSignatureDER"
            changed[field] = base64.b64encode(bytes(70)).decode()
        check_now = now + 91 if mutation == "expired" else now
        path = tmp_path / (mutation + ".json")
        path.write_text(json.dumps(changed))
        run = subprocess.run([str(executable), str(path), base64.b64encode(root).decode(), str(check_now), mutation], capture_output=True)
        assert run.returncode == 0, run.stderr
        if mutation != "valid":
            with pytest.raises(ValueError):
                verify_routing_provider_configuration(changed, scope=scope,
                    trust_root_public_key_x963=root, now_unix_seconds=check_now)
