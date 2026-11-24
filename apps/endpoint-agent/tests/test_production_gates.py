from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hawk_endpoint_agent.attestation import (
    AttestationExpectations,
    BANK_READINESS_SCHEMA,
    MDM_ENDPOINT_TRUST_PIN_SCHEMA,
    evaluate_bank_readiness,
    verify_remote_attestation,
    validate_macos_release_evidence_v2,
)
from hawk_endpoint_agent.macos_native import macos_component_set_digest


ROOT = Path(__file__).resolve().parents[1]
NETWORK_EXTENSION = ROOT / "native" / "macos" / "network-extension"
BUILD_SCRIPT = ROOT / "scripts" / "build_bank_macos.sh"
NOTARIZE_SCRIPT = ROOT / "scripts" / "notarize_bank_macos.sh"
EDR_SCRIPT = ROOT / "scripts" / "validate_edr_coexistence.sh"

NOW = datetime(2026, 8, 7, 12, 0, tzinfo=UTC)
DEVICE_KEY_SHA256 = "a" * 64
RECEIPT_KEY_SHA256 = "b" * 64
REMOTE_VERIFIER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x11" * 32)
READINESS_SIGNER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x22" * 32)
EDR_CERTIFIER_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)


def test_v2_release_evidence_requires_exact_component_and_notary_binding() -> None:
    identifiers = ["ai.hawk.endpoint.host", "ai.hawk.endpoint.endpoint-security",
                   "ai.hawk.endpoint.content-filter", "ai.hawk.endpoint.managed-routing"]
    entitlement = ["com.apple.developer.system-extension.install",
                   "com.apple.developer.endpoint-security.client",
                   "com.apple.developer.networking.networkextension",
                   "com.apple.developer.networking.networkextension"]
    records = [{"bundle_id": identifier, "version": "1.2.3", "bundle_version": "9",
                "team_id": "ABCDEFGHIJ", "sha256": f"{index + 1:02x}" * 32,
                "entitlement": entitlement[index], "provisioning_profile": identifier,
                "hardened_runtime": True}
               for index, identifier in enumerate(identifiers)]
    digest_records = [{key: row[key] for key in
                       ("bundle_id", "version", "bundle_version", "sha256")}
                      for row in records]
    build = {
        "schema": "hawk.bank-macos-build-evidence", "version": 2,
        "artifact": {"name": "Hawk Endpoint.app", "sha256": records[0]["sha256"],
                     "binary_version": "1.2.3"},
        "signature": {"team_id": "ABCDEFGHIJ", "publisher": "Developer ID Application: Hawk",
                      "hardened_runtime": True},
        "components": sorted(records, key=lambda row: row["bundle_id"]),
        "component_set_digest": macos_component_set_digest(digest_records),
        "verified_at": "2026-08-07T11:59:00Z",
    }
    notary = {
        "schema": "hawk.bank-macos-notarization-evidence", "version": 2,
        "team_id": "ABCDEFGHIJ",
        "build_evidence_sha256": hashlib.sha256(_canonical_bytes(build)).hexdigest(),
        "component_evidence_sha256": hashlib.sha256(_canonical_bytes(build["components"])).hexdigest(),
        "submitted_package_sha256": "a" * 64, "stapled_package_sha256": "b" * 64,
        "status": "accepted", "submission_id": "apple-submission-1",
        "staple_status": "valid", "verified_at": "2026-08-07T12:00:00Z",
    }
    accepted = validate_macos_release_evidence_v2(build, notary, now=NOW)
    assert accepted["component_set_digest"] == build["component_set_digest"]
    for section, field, replacement in (
        ("build", "component_set_digest", "0" * 64),
        ("build", "components", build["components"][:-1]),
        ("notary", "component_evidence_sha256", "0" * 64),
        ("notary", "team_id", "ZZZZZZZZZZ"),
    ):
        changed_build, changed_notary = copy.deepcopy(build), copy.deepcopy(notary)
        (changed_build if section == "build" else changed_notary)[field] = replacement
        with pytest.raises(ValueError):
            validate_macos_release_evidence_v2(changed_build, changed_notary, now=NOW)
    with pytest.raises(ValueError):
        validate_macos_release_evidence_v2({**build, "version": 1}, notary, now=NOW)


def _public_key_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _sign_remote_attestation(evidence: dict[str, object]) -> dict[str, object]:
    unsigned = copy.deepcopy(evidence)
    unsigned["verification"].pop("receipt_signature")
    evidence["verification"]["receipt_signature"] = base64.b64encode(
        REMOTE_VERIFIER_PRIVATE_KEY.sign(_canonical_bytes(unsigned))
    ).decode("ascii")
    return evidence


def _sign_edr_certification(evidence: dict[str, object]) -> dict[str, object]:
    unsigned = copy.deepcopy(evidence)
    unsigned["certification"].pop("signature")
    evidence["certification"]["signature"] = base64.b64encode(
        EDR_CERTIFIER_PRIVATE_KEY.sign(_canonical_bytes(unsigned))
    ).decode("ascii")
    return evidence


def _sign_readiness(evidence: dict[str, object]) -> dict[str, object]:
    unsigned_evidence = copy.deepcopy(evidence)
    envelope = unsigned_evidence.pop("envelope")
    envelope.pop("signature")
    signed_payload = {"evidence": unsigned_evidence, "envelope": envelope}
    evidence["envelope"]["signature"] = base64.b64encode(
        READINESS_SIGNER_PRIVATE_KEY.sign(_canonical_bytes(signed_payload))
    ).decode("ascii")
    return evidence


def _expectations() -> AttestationExpectations:
    return AttestationExpectations(
        issuer="https://attest.hawk.example",
        audience="hawk-bank-macos",
        nonce="nonce-0123456789abcdef",
        device_id="device-001",
        endpoint_public_key_sha256=DEVICE_KEY_SHA256,
        trusted_verifier_public_keys={
            "hawk-attestation-prod": _public_key_bytes(REMOTE_VERIFIER_PRIVATE_KEY)
        },
        trusted_readiness_signer_public_keys={
            "bank-mdm-readiness-prod": _public_key_bytes(READINESS_SIGNER_PRIVATE_KEY)
        },
        trusted_edr_certifier_public_keys={
            "bank-edr-lab-prod": _public_key_bytes(EDR_CERTIFIER_PRIVATE_KEY)
        },
        now=NOW,
    )


def _remote_attestation() -> dict[str, object]:
    evidence = {
        "schema": "hawk.remote-hardware-attestation",
        "version": 1,
        "format": "apple-managed-device-attestation-v1",
        "status": "verified",
        "issuer": "https://attest.hawk.example",
        "audience": "hawk-bank-macos",
        "nonce": "nonce-0123456789abcdef",
        "device_id": "device-001",
        "key_binding": {
            "key_id": "secure-enclave-key-001",
            "public_key_sha256": DEVICE_KEY_SHA256,
        },
        "issued_at": "2026-08-07T11:58:00Z",
        "expires_at": "2026-08-07T12:03:00Z",
        "verification": {
            "status": "verified",
            "method": "remote-cryptographic-verifier",
            "verifier_id": "hawk-attestation-prod",
            "verified_at": "2026-08-07T11:59:00Z",
            "assertion_sha256": "c" * 64,
            "receipt_signature": "",
        },
    }
    return _sign_remote_attestation(evidence)


def _ready_evidence() -> dict[str, object]:
    evidence = {
        "schema": "hawk.bank-macos-readiness",
        "version": 1,
        "managed_routing_enabled": True,
        "functional_relay": {
            "schema": "hawk.network-extension-relay-evidence",
            "version": 1,
            "status": "verified",
            "provider_type": "transparent-proxy",
            "relay_implemented": True,
            "artifact_sha256": "d" * 64,
            "binary_version": "1.4.0",
            "tcp_scenario_result": "pass",
            "udp_scenario_result": "pass",
            "failure_recovery_result": "pass",
            "rollback_result": "pass",
            "validated_at": "2026-08-07T11:54:00Z",
        },
        "local_broker_authentication": {
            "schema": "hawk.local-broker-authentication-evidence",
            "version": 1,
            "status": "verified",
            "implementation": "signed-response-and-receipt-verification",
            "artifact_sha256": "d" * 64,
            "binary_version": "1.4.0",
            "endpoint_public_key_sha256": DEVICE_KEY_SHA256,
            "session_receipt_verifier_public_key_sha256": RECEIPT_KEY_SHA256,
            "client_version": "hawk-endpoint-client/1.0.0",
            "same_uid_result": "pass",
            "response_signature_result": "pass",
            "session_receipt_result": "pass",
            "replay_resistance_result": "pass",
            "validated_at": "2026-08-07T11:54:30Z",
        },
        "build": {
            "schema": "hawk.bank-macos-build-evidence",
            "version": 1,
            "artifact": {
                "name": "HawkEndpoint.app",
                "sha256": "d" * 64,
                "binary_version": "1.4.0",
            },
            "entitlement": {
                "status": "verified",
                "source": "apple-codesign",
                "network_extension_type": "transparent-proxy",
            },
            "signature": {
                "status": "verified",
                "identity_type": "developer-id-application",
                "publisher": "Developer ID Application: Hawk Bank Security (TEAM123456)",
                "team_id": "TEAM123456",
                "hardened_runtime": True,
            },
            "verified_at": "2026-08-07T11:45:00Z",
        },
        "mdm": {
            "schema": "hawk.mdm-managed-routing-evidence",
            "version": 1,
            "status": "verified",
            "managed": True,
            "routing_authorization": "authorized",
            "installation_status": "installed",
            "configuration_profile_id": "com.bank.hawk.routing",
            "system_extension_bundle_id": "com.hawk.endpoint.network-extension",
            "team_id": "TEAM123456",
            "issued_at": "2026-08-07T11:40:00Z",
            "expires_at": "2026-08-08T11:40:00Z",
        },
        "notarization": {
            "schema": "hawk.bank-macos-notarization-evidence",
            "version": 1,
            "artifact_sha256": "d" * 64,
            "build_evidence_sha256": "",
            "submission_artifact_sha256": "e" * 64,
            "status": "accepted",
            "submission_id": "notary-submission-001",
            "staple_status": "valid",
            "verified_at": "2026-08-07T11:50:00Z",
        },
        "attestation": _remote_attestation(),
        "edr": {
            "schema": "hawk.edr-coexistence-evidence",
            "version": 1,
            "status": "verified",
            "vendor": "Representative EDR Vendor",
            "product": "Endpoint Security",
            "product_version": "12.4.1",
            "test_scenario": "install, activate, enforce, update, rollback, uninstall",
            "result": "pass",
            "certification_claimed": True,
            "hawk_binary": {
                "name": "HawkEndpoint.app",
                "sha256": "d" * 64,
                "signed_publisher": "Developer ID Application: Hawk Bank Security (TEAM123456)",
                "team_identifier": "TEAM123456",
                "binary_version": "1.4.0",
                "signature_verified": True,
                "hardened_runtime": True,
            },
            "build_evidence_sha256": "",
            "certification": {
                "status": "verified",
                "algorithm": "Ed25519",
                "certifier_id": "bank-edr-lab-prod",
                "verified_at": "2026-08-07T11:56:00Z",
                "signature": "",
            },
            "verified_at": "2026-08-07T11:55:00Z",
        },
        "ipc_trust_pin": {
            "schema": "hawk.mdm-endpoint-trust-pin",
            "version": 1,
            "status": "installed",
            "managed": True,
            "management_source": "mdm",
            "configuration_profile_id": "com.bank.hawk.endpoint-trust",
            "device_id": "device-001",
            "endpoint_public_key_sha256": DEVICE_KEY_SHA256,
            "session_receipt_verifier_public_key_sha256": RECEIPT_KEY_SHA256,
            "issued_at": "2026-08-07T11:40:00Z",
            "expires_at": "2026-08-08T11:40:00Z",
        },
        "envelope": {
            "algorithm": "Ed25519",
            "signer_id": "bank-mdm-readiness-prod",
            "signed_at": "2026-08-07T11:59:30Z",
            "signature": "",
        },
    }
    evidence["edr"]["build_evidence_sha256"] = hashlib.sha256(
        _canonical_bytes(evidence["build"])
    ).hexdigest()
    evidence["notarization"]["build_evidence_sha256"] = hashlib.sha256(
        _canonical_bytes(evidence["build"])
    ).hexdigest()
    _sign_edr_certification(evidence["edr"])
    return _sign_readiness(evidence)


def test_managed_routing_defaults_off_and_source_is_not_runtime_readiness() -> None:
    contract = json.loads((NETWORK_EXTENSION / "build-contract.json").read_text())

    assert contract["schema"] == "hawk.macos-network-extension-build-contract"
    assert contract["version"] == 2
    assert contract["managed_routing_default_enabled"] is False
    assert contract["source_ready_is_runtime_ready"] is False
    assert contract["functional_relay_implemented"] is True
    assert contract["local_broker_cryptographic_authentication_implemented"] is True
    assert contract["runtime_evidence_required"] == [
        "signed_network_extension_entitlement",
        "mdm_routing_authorization",
        "mdm_installation",
        "hardened_developer_id_signature",
        "accepted_notarization",
        "valid_staple",
        "remote_hardware_attestation",
        "edr_coexistence",
        "mdm_managed_ipc_trust_pin",
        "functional_tcp_udp_relay_validation",
        "local_broker_cryptographic_authentication",
        "signed_artifact",
        "target_os_acceptance",
    ]


def test_remote_attestation_accepts_only_bound_external_verification() -> None:
    result = verify_remote_attestation(_remote_attestation(), _expectations())

    assert result.accepted is True
    assert result.failures == ()
    assert result.external_verification_accepted is True
    assert result.cryptographic_verification_performed is False
    assert result.verifier_receipt_signature_verified is True


@pytest.mark.parametrize(
    ("mutation", "failure"),
    [
        (lambda value: value.update(schema="unknown"), "schema"),
        (lambda value: value.update(version=2), "version"),
        (lambda value: value.update(format="unknown-format"), "format"),
        (lambda value: value.update(format=[]), "format"),
        (lambda value: value.update(status="pending"), "status"),
        (lambda value: value.update(issuer="https://attacker.example"), "issuer"),
        (lambda value: value.update(audience="another-service"), "audience"),
        (lambda value: value.update(nonce="replayed-nonce"), "nonce"),
        (lambda value: value.update(device_id="device-002"), "device_id"),
        (
            lambda value: value["key_binding"].update(public_key_sha256="e" * 64),
            "key_binding.public_key_sha256",
        ),
        (lambda value: value.update(issued_at="2026-08-07T12:01:00Z"), "issued_at"),
        (lambda value: value.update(expires_at="2026-08-07T11:59:00Z"), "expires_at"),
        (
            lambda value: value["verification"].update(status="unverified"),
            "verification.status",
        ),
        (
            lambda value: value["verification"].update(verifier_id="unknown-verifier"),
            "verification.verifier_id",
        ),
        (
            lambda value: value["verification"].update(receipt_signature="invalid"),
            "receipt_signature",
        ),
        (lambda value: value.update(unexpected=True), "unknown fields"),
    ],
)
def test_remote_attestation_fails_closed_for_invalid_evidence(mutation, failure: str) -> None:
    evidence = _remote_attestation()
    mutation(evidence)

    result = verify_remote_attestation(evidence, _expectations())

    assert result.accepted is False
    assert any(failure in item for item in result.failures)
    assert result.cryptographic_verification_performed is False
    assert result.verifier_receipt_signature_verified is False


def test_malformed_signer_identifiers_fail_closed_instead_of_raising() -> None:
    attestation = _remote_attestation()
    attestation["verification"]["verifier_id"] = []
    attestation_result = verify_remote_attestation(attestation, _expectations())

    readiness = _ready_evidence()
    readiness["envelope"]["signer_id"] = []
    readiness_result = evaluate_bank_readiness(readiness, _expectations())

    edr_readiness = _ready_evidence()
    edr_readiness["edr"]["certification"]["certifier_id"] = []
    _sign_edr_certification(edr_readiness["edr"])
    _sign_readiness(edr_readiness)
    edr_result = evaluate_bank_readiness(edr_readiness, _expectations())

    assert attestation_result.accepted is False
    assert readiness_result.ready is False
    assert edr_result.gates["edr_coexistence"] is False


def test_bank_readiness_requires_every_external_gate() -> None:
    result = evaluate_bank_readiness(
        {
            "schema": "hawk.bank-macos-readiness",
            "version": 1,
            "managed_routing_enabled": False,
        },
        _expectations(),
    )

    assert result.ready is False
    assert BANK_READINESS_SCHEMA == "hawk.bank-macos-readiness"
    assert MDM_ENDPOINT_TRUST_PIN_SCHEMA == "hawk.mdm-endpoint-trust-pin"
    assert set(result.gates) == {
        "managed_routing_opt_in",
        "signed_readiness_envelope",
        "functional_network_relay",
        "local_broker_cryptographically_authenticated",
        "signed_network_extension_entitlement",
        "mdm_routing_authorized",
        "mdm_network_extension_installed",
        "hardened_developer_id_signature",
        "notarization_accepted",
        "staple_valid",
        "remote_hardware_attestation",
        "edr_coexistence",
        "managed_ipc_trust_pin",
    }
    assert not any(result.gates.values())


def test_bank_readiness_accepts_complete_bound_external_evidence() -> None:
    result = evaluate_bank_readiness(_ready_evidence(), _expectations())

    assert result.ready is True
    assert all(result.gates.values())
    assert result.failures == ()


def test_unsigned_readiness_bundle_cannot_assert_any_external_gate() -> None:
    evidence = _ready_evidence()
    evidence["envelope"]["signature"] = ""

    result = evaluate_bank_readiness(evidence, _expectations())

    assert result.ready is False
    assert not any(result.gates.values())


def test_complete_external_evidence_cannot_replace_functional_relay_proof() -> None:
    evidence = _ready_evidence()
    evidence["functional_relay"] = None
    _sign_readiness(evidence)

    result = evaluate_bank_readiness(evidence, _expectations())

    assert result.ready is False
    assert result.gates["signed_readiness_envelope"] is True
    assert result.gates["functional_network_relay"] is False
    assert all(
        passed
        for gate, passed in result.gates.items()
        if gate != "functional_network_relay"
    )


def test_managed_pin_alone_cannot_authenticate_local_broker_responses() -> None:
    evidence = _ready_evidence()
    evidence["local_broker_authentication"] = None
    _sign_readiness(evidence)

    result = evaluate_bank_readiness(evidence, _expectations())

    assert result.ready is False
    assert result.gates["managed_ipc_trust_pin"] is True
    assert result.gates["local_broker_cryptographically_authenticated"] is False


@pytest.mark.parametrize(
    ("mutation", "gate"),
    [
        (
            lambda value: value["build"]["entitlement"].update(status="claimed"),
            "signed_network_extension_entitlement",
        ),
        (
            lambda value: value["functional_relay"].update(
                artifact_sha256="f" * 64
            ),
            "functional_network_relay",
        ),
        (
            lambda value: value["local_broker_authentication"].update(
                session_receipt_verifier_public_key_sha256="f" * 64
            ),
            "local_broker_cryptographically_authenticated",
        ),
        (
            lambda value: value["build"]["signature"].update(hardened_runtime=False),
            "hardened_developer_id_signature",
        ),
        (
            lambda value: value["mdm"].update(routing_authorization="pending"),
            "mdm_routing_authorized",
        ),
        (
            lambda value: value["mdm"].update(installation_status="pending"),
            "mdm_network_extension_installed",
        ),
        (
            lambda value: value["notarization"].update(status="in_progress"),
            "notarization_accepted",
        ),
        (
            lambda value: value["notarization"].update(staple_status="missing"),
            "staple_valid",
        ),
        (
            lambda value: value["attestation"].update(status="pending"),
            "remote_hardware_attestation",
        ),
        (lambda value: value["edr"].update(result="fail"), "edr_coexistence"),
        (
            lambda value: value["ipc_trust_pin"].update(managed=False),
            "managed_ipc_trust_pin",
        ),
        (
            lambda value: value["ipc_trust_pin"].update(
                endpoint_public_key_sha256="f" * 64
            ),
            "managed_ipc_trust_pin",
        ),
    ],
)
def test_bank_readiness_fails_when_a_gate_is_not_proven(mutation, gate: str) -> None:
    evidence = _ready_evidence()
    mutation(evidence)
    _sign_readiness(evidence)

    result = evaluate_bank_readiness(evidence, _expectations())

    assert result.ready is False
    assert result.gates["signed_readiness_envelope"] is True
    assert result.gates[gate] is False


def test_bank_readiness_requires_managed_session_receipt_verifier_pin() -> None:
    evidence = _ready_evidence()
    evidence["ipc_trust_pin"].pop("session_receipt_verifier_public_key_sha256")
    _sign_readiness(evidence)

    result = evaluate_bank_readiness(evidence, _expectations())

    assert result.ready is False
    assert result.gates["managed_ipc_trust_pin"] is False


def test_bank_readiness_rejects_malformed_build_verification_time() -> None:
    evidence = _ready_evidence()
    evidence["build"]["verified_at"] = "not-a-timestamp"
    _sign_readiness(evidence)

    result = evaluate_bank_readiness(evidence, _expectations())

    assert result.gates["signed_readiness_envelope"] is True
    assert result.gates["signed_network_extension_entitlement"] is False
    assert result.gates["hardened_developer_id_signature"] is False


def _run_script(script: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(script), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_bank_build_and_notarization_scripts_require_real_inputs(tmp_path: Path) -> None:
    build = _run_script(BUILD_SCRIPT)
    notarize = _run_script(NOTARIZE_SCRIPT)

    assert build.returncode != 0
    assert "required" in build.stderr.lower()
    assert notarize.returncode != 0
    assert "required" in notarize.stderr.lower()
    assert not list(tmp_path.iterdir())


def test_production_scripts_validate_apple_outputs_instead_of_claiming_them() -> None:
    build = BUILD_SCRIPT.read_text()
    notarize = NOTARIZE_SCRIPT.read_text()

    assert "xcodebuild" in build
    assert 'run(["/usr/bin/codesign", "--verify", "--strict", str(bundle)])' in build
    assert "Developer ID Application" in build
    assert "runtime" in build
    assert "networkextension" in build
    assert "notarytool submit" in notarize
    assert "stapler staple" in notarize
    assert "stapler validate" in notarize
    assert 'pkgutil --check-signature "$ARTIFACT"' in notarize
    assert '"Accepted"' in notarize
    submitted_hash = '"submitted_package_sha256": hashlib.sha256(pathlib.Path(sys.argv[2]).read_bytes()).hexdigest()'
    stapled_hash = '"stapled_package_sha256": hashlib.sha256(package.read_bytes()).hexdigest()'
    assert notarize.index(submitted_hash) < notarize.index("notarytool submit")
    assert notarize.index("stapler validate") < notarize.index(stapled_hash)
    assert '"schema": "hawk.bank-macos-notarization-evidence", "version": 2' in notarize
    assert '"build_evidence_sha256"' in notarize
    assert '"component_evidence_sha256"' in notarize
    assert 'built app is outside the requested archive' in build
    assert 'detail = run(["/usr/bin/codesign", "-dv", "--verbose=4", str(bundle)])' in build
    assert '"schema": "hawk.bank-macos-build-evidence", "version": 2' in build
    assert '"components": sorted(records, key=lambda row: row["bundle_id"])' in build
    assert "embedded.provisionprofile" in build
    assert 'run(["/usr/bin/security", "cms", "-D", "-i", str(profile_path)])' in build


def test_network_extension_scopes_tcp_and_udp_by_remote_destination() -> None:
    source = (NETWORK_EXTENSION / "HawkTransparentProxyProvider.swift").read_text()

    assert "import Network" in source
    assert "NEAppProxyUDPFlowHandling" in source
    assert "func handleNewUDPFlow" in source
    assert "initialRemoteFlowEndpoint remoteEndpoint" in source
    assert "udpFlow.localEndpoint" not in source
    assert "NWConnection(to:" in source
    assert "maximumLength: 64 * 1024" in source
    assert "readData" in source
    assert "writeDatagrams" in source
    assert "readDatagrams" in source
    assert "receiveMessage" in source
    assert "return false" in source
    assert "scope.contains" in source


def test_network_extension_source_typechecks_with_the_macos_sdk(tmp_path: Path) -> None:
    environment = os.environ.copy()
    environment["CLANG_MODULE_CACHE_PATH"] = str(tmp_path / "clang-module-cache")
    completed = subprocess.run(
        [
            "xcrun",
            "swiftc",
            "-typecheck",
            "-module-cache-path",
            str(tmp_path / "swift-module-cache"),
            str(NETWORK_EXTENSION / "HawkRoutingReadinessReceipt.swift"),
            str(NETWORK_EXTENSION / "HawkTransparentProxyProvider.swift"),
        ],
        text=True,
        capture_output=True,
        check=False,
        env=environment,
    )

    if "SDK is not supported by the compiler" in completed.stderr:
        pytest.skip("installed macOS SDK and Swift compiler versions do not match")
    assert completed.returncode == 0, completed.stderr


def _write_build_evidence(path: Path) -> dict[str, object]:
    build_evidence = copy.deepcopy(_ready_evidence()["build"])
    path.write_text(json.dumps(build_evidence), encoding="utf-8")
    return build_evidence


def test_edr_validation_requires_all_fields_and_explicit_pass(tmp_path: Path) -> None:
    build_evidence_path = tmp_path / "build-evidence.json"
    _write_build_evidence(build_evidence_path)
    output = tmp_path / "edr-evidence.json"

    missing = _run_script(
        EDR_SCRIPT,
        "--vendor",
        "Vendor",
        "--product",
        "Product",
        "--version",
        "1.0",
        "--test-scenario",
        "coexistence",
        "--result",
        "pass",
        "--evidence-out",
        str(output),
    )
    failed = _run_script(
        EDR_SCRIPT,
        "--vendor",
        "Vendor",
        "--product",
        "Product",
        "--version",
        "1.0",
        "--test-scenario",
        "coexistence",
        "--result",
        "fail",
        "--build-evidence",
        str(build_evidence_path),
        "--evidence-out",
        str(output),
    )

    assert missing.returncode != 0
    assert "build-evidence" in missing.stderr
    assert failed.returncode != 0
    assert "explicit pass" in failed.stderr.lower()
    assert not output.exists()


def test_edr_validation_writes_and_self_validates_bounded_evidence(tmp_path: Path) -> None:
    build_evidence_path = tmp_path / "build-evidence.json"
    build_evidence = _write_build_evidence(build_evidence_path)
    output = tmp_path / "edr-evidence.json"

    completed = _run_script(
        EDR_SCRIPT,
        "--vendor",
        "Representative EDR Vendor",
        "--product",
        "Endpoint Security",
        "--version",
        "12.4.1",
        "--test-scenario",
        "install, activate, enforce, update, rollback, uninstall",
        "--result",
        "pass",
        "--build-evidence",
        str(build_evidence_path),
        "--evidence-out",
        str(output),
    )

    assert completed.returncode == 0, completed.stderr
    assert output.stat().st_size <= 4096
    artifact = json.loads(output.read_text())
    assert artifact == {
        "schema": "hawk.edr-coexistence-evidence",
        "version": 1,
        "status": "recorded",
        "vendor": "Representative EDR Vendor",
        "product": "Endpoint Security",
        "product_version": "12.4.1",
        "test_scenario": "install, activate, enforce, update, rollback, uninstall",
        "result": "pass",
        "certification_claimed": False,
        "hawk_binary": {
            "name": "HawkEndpoint.app",
            "sha256": "d" * 64,
            "signed_publisher": "Developer ID Application: Hawk Bank Security (TEAM123456)",
            "team_identifier": "TEAM123456",
            "binary_version": "1.4.0",
            "signature_verified": True,
            "hardened_runtime": True,
        },
        "build_evidence_sha256": hashlib.sha256(
            _canonical_bytes(build_evidence)
        ).hexdigest(),
        "recorded_at": artifact["recorded_at"],
    }
    datetime.fromisoformat(artifact["recorded_at"].replace("Z", "+00:00"))
    assert build_evidence["signature"]["status"] == "verified"

    readiness = _ready_evidence()
    readiness["edr"] = artifact
    _sign_readiness(readiness)
    result = evaluate_bank_readiness(readiness, _expectations())
    assert result.ready is False
    assert result.gates["edr_coexistence"] is False


def test_edr_validation_rejects_unverified_publisher_or_binary_version(
    tmp_path: Path,
) -> None:
    build_evidence_path = tmp_path / "build-evidence.json"
    build_evidence = _write_build_evidence(build_evidence_path)
    build_evidence["signature"]["status"] = "claimed"
    build_evidence["artifact"]["binary_version"] = ""
    build_evidence_path.write_text(json.dumps(build_evidence), encoding="utf-8")
    output = tmp_path / "edr-evidence.json"

    completed = _run_script(
        EDR_SCRIPT,
        "--vendor",
        "Vendor",
        "--product",
        "Product",
        "--version",
        "1.0",
        "--test-scenario",
        "coexistence",
        "--result",
        "pass",
        "--build-evidence",
        str(build_evidence_path),
        "--evidence-out",
        str(output),
    )

    assert completed.returncode != 0
    assert "signed publisher" in completed.stderr.lower()
    assert not output.exists()
