from __future__ import annotations

import json
import hashlib
import base64
import struct
import subprocess
import time
import plistlib
from dataclasses import replace
from datetime import datetime
from pathlib import Path
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hawk_endpoint_agent.macos_native import (
    MacOSNativeFloorManager,
    MacOSNativeStatus,
    verify_macos_target_acceptance,
    macos_code_identity_reference,
    macos_destination_reference,
    macos_path_reference,
)


def _signed_acceptance(now: int) -> tuple[dict, bytes]:
    private = Ed25519PrivateKey.from_private_bytes(b"\x49" * 32)
    public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    payload = {
        "schema": "hawk.macos-endpoint-control-acceptance", "version": 1,
        "tenant_id": "tenant-1", "device_id": "device-1",
        "policy_digest": "a" * 64, "policy_epoch": 7,
        "component_set_digest": "b" * 64, "team_id": "ABCDEFGHIJ",
        "bundle_ids": ["ai.hawk.endpoint.host", "ai.hawk.endpoint.endpoint-security",
                       "ai.hawk.endpoint.content-filter", "ai.hawk.endpoint.managed-routing"],
        "os_build": "25A100", "tested_at_unix_seconds": now - 5,
        "issued_at_unix_seconds": now - 5, "expires_at_unix_seconds": now + 200,
        "monitor_observations": {name: True for name in (
            "file", "process", "child", "grandchild", "domain", "direct_ip",
            "quic", "localhost")},
        "enforce_results": {name: True for name in (
            "file_allow", "file_deny", "process_allow", "process_deny_nonexecution",
            "child_deny_nonexecution", "grandchild_deny_nonexecution",
            "domain_deny_nontransfer", "direct_ip_deny_nontransfer",
            "quic_deny_nontransfer", "localhost_deny_nontransfer")},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return ({"key_id": "managed-target-1", "algorithm": "Ed25519", "payload": payload,
             "signature": base64.b64encode(private.sign(canonical)).decode()}, public)


def test_target_acceptance_is_signed_fresh_device_and_artifact_bound() -> None:
    now = int(time.time())
    envelope, public = _signed_acceptance(now)
    expected = dict(trusted_public_keys={"managed-target-1": public},
                    tenant_id="tenant-1", device_id="device-1",
                    policy_digest="a" * 64, policy_epoch=7,
                    component_set_digest="b" * 64, team_id="ABCDEFGHIJ",
                    os_build="25A100", now_unix_seconds=now)
    result = verify_macos_target_acceptance(envelope, **expected)
    assert result["monitor_verified"] is True
    assert result["enforce_verified"] is True
    assert result["network_child_attribution_verified"] is True
    for field, value in (("device_id", "other"), ("team_id", "ZZZZZZZZZZ"),
                         ("component_set_digest", "c" * 64),
                         ("os_build", "other"), ("policy_epoch", 6),
                         ("expires_at_unix_seconds", now - 1)):
        changed = json.loads(json.dumps(envelope))
        changed["payload"][field] = value
        with pytest.raises(ValueError):
            verify_macos_target_acceptance(changed, **expected)
    missing = json.loads(json.dumps(envelope))
    missing["payload"]["enforce_results"].pop("quic_deny_nontransfer")
    with pytest.raises(ValueError):
        verify_macos_target_acceptance(missing, **expected)
    private = Ed25519PrivateKey.from_private_bytes(b"\x49" * 32)
    incomplete = json.loads(json.dumps(envelope))
    incomplete["payload"]["enforce_results"]["quic_deny_nontransfer"] = False
    incomplete["signature"] = base64.b64encode(private.sign(json.dumps(
        incomplete["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode())).decode()
    assert verify_macos_target_acceptance(incomplete, **expected)["enforce_verified"] is False
    incomplete["payload"]["monitor_observations"]["grandchild"] = False
    incomplete["signature"] = base64.b64encode(private.sign(json.dumps(
        incomplete["payload"], sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode())).decode()
    assert verify_macos_target_acceptance(incomplete, **expected)["monitor_verified"] is False


@pytest.mark.parametrize("mode,expected", [
    ("monitor", "Monitoring"), ("enforce", "Protected"),
])
def test_verified_acceptance_promotes_only_current_matching_native_status(
    tmp_path: Path, monkeypatch, mode: str, expected: str,
) -> None:
    now = int(time.time())
    envelope, public = _signed_acceptance(now)
    manager = MacOSNativeFloorManager(
        policy_path=str(tmp_path / "policy.bin"),
        config_path=str(tmp_path / "config.plist"),
        host_app_path=str(tmp_path / "Hawk Endpoint.app"),
        acceptance_path=str(tmp_path / "acceptance.json"),
        acceptance_public_keys={"managed-target-1": public},
        tenant_id="tenant-1", device_id="device-1",
    )
    monkeypatch.setattr(manager, "_read_protected_file", lambda path, maximum:
                        json.dumps(envelope).encode())
    monkeypatch.setattr(manager, "_os_build", lambda: "25A100")
    status = MacOSNativeStatus(
        mode=mode, policy_current=True, policy_signed=True,
        policy_digest="a" * 64, policy_epoch=7, policy_version="policy-7",
        issued_at_unix_seconds=now - 5, expires_at_unix_seconds=now + 300,
        team_id="ABCDEFGHIJ", file_control="verified", process_control="verified",
        network_control="active_unverified", healthy=True, reason_codes=[],
    )
    manager._apply_acceptance(status, "b" * 64)
    manager._last_status = status
    assert status.network_control == "verified"
    assert status.network_child_attribution_verified is True
    assert manager.posture()["display_state"] == expected
    receipt = manager.runtime_receipt_payload(tenant_id="tenant-1", device_id="device-1")
    authority = receipt["native_authority"]
    assert authority["artifact_sha256"] == "b" * 64
    assert authority["target_acceptance_verified"] is (mode == "enforce")
    assert int(datetime.fromisoformat(receipt["expires_at"].replace("Z", "+00:00")).timestamp()) <= now + 200
    status.acceptance_expires_at_unix_seconds = now - 1
    assert manager.posture()["display_state"] == "Needs attention"


def test_macos_hash_helpers_are_deterministic_and_exact() -> None:
    assert macos_path_reference("/tmp/work/.env") == macos_path_reference("/tmp/work/./.env")
    assert macos_path_reference("/tmp/work/.env") != macos_path_reference("/tmp/other/.env")
    assert macos_destination_reference("Example.com.", 443, "tcp", "ipv4") == macos_destination_reference("example.com", 443, 6, 2)
    assert macos_code_identity_reference("TEAM", "ai.hawk.claude", bytes(range(20)), False) != macos_code_identity_reference("TEAM", "ai.hawk.shell", bytes(range(20)), False)


def test_native_host_response_requires_exact_policy_digest_and_real_invocation(
    tmp_path: Path, monkeypatch,
) -> None:
    policy = tmp_path / "policy.bin"
    raw = b"synthetic-signed-envelope"
    policy.write_bytes(raw)
    app = tmp_path / "Hawk Endpoint.app"
    manager = MacOSNativeFloorManager(
        policy_path=str(policy), config_path=str(tmp_path / "managed.plist"),
        host_app_path=str(app),
    )
    invoked: list[list[str]] = []

    def fake_run(args, **kwargs):
        invoked.append(args)
        return subprocess.CompletedProcess(args, 0, json.dumps({
            "schema": "hawk.macos-native-status", "mode": "enforce",
            "policy_signed": True, "policy_current": True, "healthy": True,
            "policy_digest": None,
        }).encode(), b"")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(manager, "_read_policy", lambda: (raw, hashlib.sha256(raw).hexdigest()))
    monkeypatch.setattr(manager, "_read_config", lambda: {
        "HawkPolicyEnvelope": raw,
        "HawkTeamIdentifier": "ABCDEFGHIJ",
        "HawkHostBundleIdentifier": "ai.hawk.endpoint.host",
        "HawkEndpointSecurityBundleIdentifier": "ai.hawk.endpoint.endpoint-security",
        "HawkContentFilterBundleIdentifier": "ai.hawk.endpoint.content-filter",
        "HawkRoutingBundleIdentifier": "ai.hawk.endpoint.managed-routing",
        "HawkPolicyEpoch": 1,
        "HawkPolicyVersion": "test",
        "HawkPolicyMode": "enforce",
        "HawkPolicyIssuedAtUnixSeconds": 1,
        "HawkPolicyExpiresAtUnixSeconds": 4_000_000_000,
    }, raising=False)
    monkeypatch.setattr(manager, "_verify_host_signature", lambda team: None, raising=False)
    try:
        manager.read_status()
    except ValueError as exc:
        assert "digest" in str(exc)
    else:
        raise AssertionError("missing digest was accepted")
    assert invoked == [[str(app / "Contents" / "MacOS" / "HawkEndpointHost"), "status"]]


def test_native_manager_retains_needs_attention_on_missing_managed_policy(tmp_path: Path) -> None:
    manager = MacOSNativeFloorManager(
        policy_path=str(tmp_path / "missing-policy.bin"),
        config_path=str(tmp_path / "managed.plist"),
        host_app_path=str(tmp_path / "Hawk Endpoint.app"),
    )
    status = manager.reconcile(mode="monitor")
    assert status.mode == "disarmed"
    assert status.policy_current is False
    assert status.healthy is False
    assert "FileNotFoundError" in status.reason_codes


def test_native_manager_status_schema_is_bounded(tmp_path: Path) -> None:
    policy = tmp_path / "policy.bin"
    policy.write_bytes(b"signed-policy")
    manager = MacOSNativeFloorManager(
        policy_path=str(policy),
        config_path=str(tmp_path / "managed.plist"),
        host_app_path=str(tmp_path / "Hawk Endpoint.app"),
    )
    status = manager.reconcile(mode="enforce")
    assert status.policy_digest is None
    assert status.mode == "disarmed"
    assert json.dumps(status.reason_codes).startswith("[")


@pytest.mark.parametrize("field,replacement", [
    ("team_id", "ZZZZZZZZZZ"),
    ("host_bundle_id", "ai.hawk.endpoint.other"),
    ("content_filter_bundle_id", "ai.hawk.endpoint.other"),
    ("mode", "monitor"),
    ("expires_at_unix_seconds", 2),
    ("policy_digest", None),
])
def test_native_status_rejects_mismatched_identity_mode_time_or_digest(
    tmp_path: Path, monkeypatch, field: str, replacement: object,
) -> None:
    raw = b"signed-policy-envelope"
    now = int(time.time())
    digest = hashlib.sha256(raw).hexdigest()
    config = {
        "HawkPolicyEnvelope": raw,
        "HawkTeamIdentifier": "ABCDEFGHIJ",
        "HawkHostBundleIdentifier": "ai.hawk.endpoint.host",
        "HawkEndpointSecurityBundleIdentifier": "ai.hawk.endpoint.endpoint-security",
        "HawkContentFilterBundleIdentifier": "ai.hawk.endpoint.content-filter",
        "HawkRoutingBundleIdentifier": "ai.hawk.endpoint.managed-routing",
        "HawkPolicyEpoch": 4, "HawkPolicyVersion": "four",
        "HawkPolicyMode": "enforce",
        "HawkPolicyIssuedAtUnixSeconds": now - 10,
        "HawkPolicyExpiresAtUnixSeconds": now + 100,
    }
    response = {
        "schema": "hawk.macos-native-status", "mode": "enforce",
        "policy_signed": True, "policy_current": True, "healthy": True,
        "policy_digest": digest, "policy_epoch": 4, "policy_version": "four",
        "issued_at_unix_seconds": now - 10,
        "expires_at_unix_seconds": now + 100,
        "team_id": "ABCDEFGHIJ",
        "host_bundle_id": "ai.hawk.endpoint.host",
        "endpoint_security_bundle_id": "ai.hawk.endpoint.endpoint-security",
        "content_filter_bundle_id": "ai.hawk.endpoint.content-filter",
        "routing_bundle_id": "ai.hawk.endpoint.managed-routing",
        "file_control": "verified", "process_control": "verified",
        "network_control": "active_unverified", "reason_codes": [],
    }
    response[field] = replacement
    manager = MacOSNativeFloorManager(
        policy_path=str(tmp_path / "policy.bin"),
        config_path=str(tmp_path / "managed.plist"),
        host_app_path=str(tmp_path / "Hawk Endpoint.app"),
    )
    monkeypatch.setattr(manager, "_read_policy", lambda: (raw, digest))
    monkeypatch.setattr(manager, "_read_config", lambda: config)
    monkeypatch.setattr(manager, "_verify_host_signature", lambda team: None)
    monkeypatch.setattr(manager, "_invoke", lambda command: response)
    with pytest.raises(ValueError):
        manager.read_status()


def test_native_status_requires_verified_host_signer(tmp_path: Path, monkeypatch) -> None:
    manager = MacOSNativeFloorManager(
        policy_path=str(tmp_path / "policy.bin"),
        config_path=str(tmp_path / "managed.plist"),
        host_app_path=str(tmp_path / "Hawk Endpoint.app"),
    )
    raw = b"signed-policy-envelope"
    monkeypatch.setattr(manager, "_read_policy", lambda: (raw, hashlib.sha256(raw).hexdigest()))
    monkeypatch.setattr(manager, "_read_config", lambda: {
        "HawkPolicyEnvelope": raw,
        "HawkTeamIdentifier": "ABCDEFGHIJ",
        "HawkHostBundleIdentifier": "ai.hawk.endpoint.host",
        "HawkEndpointSecurityBundleIdentifier": "ai.hawk.endpoint.endpoint-security",
        "HawkContentFilterBundleIdentifier": "ai.hawk.endpoint.content-filter",
        "HawkRoutingBundleIdentifier": "ai.hawk.endpoint.managed-routing",
    })
    monkeypatch.setattr(manager, "_verify_host_signature", lambda team: (_ for _ in ()).throw(ValueError("signer mismatch")))
    monkeypatch.setattr(manager, "_invoke", lambda command: (_ for _ in ()).throw(AssertionError("unsigned host invoked")))
    with pytest.raises(ValueError, match="signer mismatch"):
        manager.read_status()


def test_reconcile_rejects_signed_mode_mismatch_before_host_invocation(
    tmp_path: Path, monkeypatch,
) -> None:
    now = int(time.time())
    payload = struct.pack(
        "<IIQQQQIIIIII32s32s40I64s", 2, 2, 10, 7,
        now - 10, now + 100, 0, 0, 0, 0, 0, 1,
        bytes(32), bytes(32), *([0] * 40), b"test\0".ljust(64, b"\0"),
    )
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    signature = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    raw = struct.pack("<IIII", 2, len(payload), len(signature), 0) + payload + signature
    manager = MacOSNativeFloorManager(
        policy_path=str(tmp_path / "policy.bin"),
        config_path=str(tmp_path / "managed.plist"),
        host_app_path=str(tmp_path / "Hawk Endpoint.app"),
    )
    monkeypatch.setattr(manager, "_read_policy", lambda: (raw, hashlib.sha256(raw).hexdigest()))
    monkeypatch.setattr(manager, "_read_config", lambda: {
        "HawkPolicyEnvelope": raw, "HawkPolicySigningPublicKeyX963": public,
        "HawkTeamIdentifier": "ABCDEFGHIJ",
        "HawkHostBundleIdentifier": "ai.hawk.endpoint.host",
        "HawkEndpointSecurityBundleIdentifier": "ai.hawk.endpoint.endpoint-security",
        "HawkContentFilterBundleIdentifier": "ai.hawk.endpoint.content-filter",
        "HawkRoutingBundleIdentifier": "ai.hawk.endpoint.managed-routing",
        "HawkPolicyMode": "monitor", "HawkPolicyEpoch": 7,
        "HawkPolicyVersion": "test", "HawkPolicyIssuedAtUnixSeconds": now - 10,
        "HawkPolicyExpiresAtUnixSeconds": now + 100,
    })
    monkeypatch.setattr(manager, "_verify_host_signature", lambda team: None)
    calls: list[str] = []
    monkeypatch.setattr(manager, "_invoke", lambda command: calls.append(command))
    result = manager.reconcile(mode="enforce")
    assert calls == []
    assert result.healthy is False
    assert "ValueError" in result.reason_codes


def _managed_routing_fixture():
    from test_macos_policy_compiler import _routing_fixture, NOW
    from hawk_endpoint_agent.auth.device_key import EphemeralDeviceKeyProvider
    from hawk_endpoint_agent.macos_policy_compiler import build_managed_config
    from hawk_endpoint_agent.macos_routing import create_broker_key_authorization, MacRoutingReceiptIssuer, issue_authorized_routing_configuration, verify_routing_scope
    arguments, routing, root = _routing_fixture()
    class HardwareFixture(EphemeralDeviceKeyProvider):
        def ensure_key(self, endpoint_id):
            return replace(super().ensure_key(endpoint_id), hardware_backed=True)
    provider = HardwareFixture()
    identity = provider.ensure_key("device-1")
    public = serialization.load_pem_public_key(identity.public_key_pem.encode()).public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    now = int(NOW.timestamp())
    authorization = create_broker_key_authorization(broker_public_key_x963=public,
        issued_at_unix_seconds=now - 10, expires_at_unix_seconds=now + 300, key_epoch=1, nonce=b"a" * 16)
    signature = root.sign(authorization, ec.ECDSA(hashes.SHA256()))
    config = build_managed_config(arguments["native_envelope"], arguments["public_key_x963"], "ABCDEFGHIJ")
    config.update({"HawkSourcePolicyEnvelopeJSON": json.dumps(arguments["source_envelope"]).encode(),
        "HawkNativeBindingEnvelopeJSON": json.dumps(arguments["binding_envelope"]).encode(),
        "HawkRoutingScopeEnvelopeJSON": json.dumps(routing).encode(),
        "HawkRoutingBrokerKeyAuthorization": authorization, "HawkRoutingBrokerKeyAuthorizationSignatureDER": signature,
        "HawkRoutingReceiptPublicKeyX963": public, "HawkRoutingTrustRootPublicKeyX963": arguments["public_key_x963"]})
    scope = verify_routing_scope(routing, trusted_public_keys=arguments["trusted_public_keys"], expected_key_id="tenant-policy-1", now=NOW)
    issuer = MacRoutingReceiptIssuer(provider=provider, identity=identity, broker_key_authorization=authorization,
        broker_key_authorization_signature_der=signature, trust_root_public_key_x963=arguments["public_key_x963"], clock=lambda: now)
    dynamic = issue_authorized_routing_configuration(issuer, scope, now_unix_seconds=now)
    anchor = {"security_profile": "bank", "deployment_mode": "managed_machine", "macos_native_enforcement_enabled": True,
        "tenant_id": "tenant-1", "endpoint_id": "device-1", "endpoint_floor_policy_public_keys": {
            key: base64.b64encode(value).decode() for key, value in arguments["trusted_public_keys"].items()}}
    return config, dynamic, anchor, provider, now


def test_atomic_managed_apply_uses_one_snapshot_and_renews_only_at_margin(tmp_path: Path, monkeypatch) -> None:
    config, dynamic, anchor, provider, now = _managed_routing_fixture()
    observed = [now]
    monkeypatch.setattr(time, "time", lambda: observed[0])
    manager = MacOSNativeFloorManager(policy_path=str(tmp_path / "policy.bin"), config_path=str(tmp_path / "managed.plist"),
        host_app_path=str(tmp_path / "Hawk.app"), tenant_id="tenant-1", device_id="device-1",
        policy_public_keys={key: base64.b64decode(value) for key, value in anchor["endpoint_floor_policy_public_keys"].items()},
        routing_provider=provider)
    raw = config["HawkPolicyEnvelope"]
    reads = []
    monkeypatch.setattr(manager, "_read_policy", lambda: (reads.append("policy") or raw, hashlib.sha256(raw).hexdigest()))
    monkeypatch.setattr(manager, "_read_config", lambda: reads.append("config") or config)
    monkeypatch.setattr(manager, "_verify_host_signature", lambda team: "a" * 64)
    monkeypatch.setattr(manager, "_routing_trust_root", lambda: config["HawkRoutingTrustRootPublicKeyX963"])
    calls = []
    def invoke(command, request=None):
        calls.append((command, request))
        if request:
            sent = plistlib.loads(request)
            assert sent["expected_policy_sha256"] == hashlib.sha256(raw).hexdigest()
            assert plistlib.loads(sent["managed_configuration_data"])["HawkPolicyEnvelope"] == raw
            assert sent["routing_provider_configuration"]["sourceAppSigningIdentifiers"] == ["ai.hawk.claude"]
            # Files can change after the snapshot; request bytes remain the original authority.
            (tmp_path / "managed.plist").write_bytes(b"replaced-after-read")
        return {"schema": "hawk.macos-native-status", "mode": "enforce", "policy_signed": True,
            "policy_current": True, "healthy": True, "policy_digest": hashlib.sha256(raw).hexdigest(),
            "policy_epoch": 7, "policy_version": "policy-7", "team_id": "ABCDEFGHIJ",
            "issued_at_unix_seconds": now - 300, "expires_at_unix_seconds": now + 300,
            "host_bundle_id": "ai.hawk.endpoint.host", "endpoint_security_bundle_id": "ai.hawk.endpoint.endpoint-security",
            "content_filter_bundle_id": "ai.hawk.endpoint.content-filter", "routing_bundle_id": "ai.hawk.endpoint.managed-routing",
            "file_control": "verified", "process_control": "verified", "network_control": "active_unverified", "reason_codes": []}
    monkeypatch.setattr(manager, "_invoke", invoke)
    assert manager.reconcile(mode="enforce").healthy
    assert reads == ["policy", "config"]
    observed[0] += 20
    assert manager.reconcile(mode="enforce").healthy
    observed[0] += 71
    assert manager.reconcile(mode="enforce").healthy
    assert [command for command, _ in calls] == ["apply-managed-enforce-policy", "status", "apply-managed-enforce-policy"]
    observed[0] = now + 301
    assert manager.reconcile(mode="enforce").healthy is False
    assert manager.posture()["display_state"] == "Needs attention"


def test_bank_native_anchor_requires_fixed_path_and_rejects_identity_overrides(tmp_path: Path, monkeypatch) -> None:
    from hawk_endpoint_agent.config import load_config
    config = tmp_path / "endpoint-agent.json"
    config.write_text(json.dumps({"security_profile": "bank", "deployment_mode": "managed_machine",
        "macos_native_enforcement_enabled": True, "os_type": "darwin"}))
    with pytest.raises(ValueError, match="fixed.*agent.config"):
        load_config(config)
    fixed = Path("/Library/Application Support/Hawk/EndpointAgent/endpoint-agent.json")
    monkeypatch.setattr(MacOSNativeFloorManager, "_read_protected_file", lambda path, maximum: config.read_bytes())
    for field in ("TENANT_ID", "ENDPOINT_ID", "DEPLOYMENT_MODE", "SECURITY_PROFILE"):
        monkeypatch.setenv("HAWK_AGENT_" + field, "hostile")
        with pytest.raises(ValueError, match="identity overrides"):
            load_config(fixed)
        monkeypatch.delenv("HAWK_AGENT_" + field)
