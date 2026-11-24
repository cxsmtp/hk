from __future__ import annotations

import json
import re
import subprocess
import plistlib
import base64
import copy
import hashlib
from pathlib import Path

from hawk_endpoint_agent.macos_native import macos_code_identity_reference


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native"
MACOS = NATIVE / "macos"
SHARED = NATIVE / "shared"
CLANG = Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin/clang"
)
SDK = Path(
    "/Applications/Xcode.app/Contents/Developer/Platforms/"
    "MacOSX.platform/Developer/SDKs/MacOSX.sdk"
)


def test_atomic_host_request_rejects_mode_digest_keys_and_stale_routing_before_delivery(tmp_path: Path) -> None:
    from test_macos_managed_runtime import _managed_routing_fixture
    configuration, provider, anchor, _, now = _managed_routing_fixture()
    request = {"schema": "hawk.macos-managed-apply-request", "version": 1,
        "expected_policy_sha256": hashlib.sha256(configuration["HawkPolicyEnvelope"]).hexdigest(),
        "managed_configuration_data": plistlib.dumps(configuration, fmt=plistlib.FMT_BINARY),
        "routing_provider_configuration": provider}
    harness = tmp_path / "main.swift"
    harness.write_text('''import Foundation
let input = try Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[1]))
let anchor = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: CommandLine.arguments[2]))) as! [String: Any]
let root = Data(base64Encoded: CommandLine.arguments[3])!
var delivered = 0
do {
    let request = try HawkManagedApplyRequest.parse(input, command: CommandLine.arguments[4], anchor: anchor, trustRoot: root, now: UInt64(CommandLine.arguments[5])!)
    assert(request.configuration.policyEnvelope.count > 0)
    delivered += 1
} catch {}
assert(delivered == Int(CommandLine.arguments[6])!)
''')
    executable = tmp_path / "host-apply-test"
    paths = [MACOS / "host/HawkManagedConfiguration.swift", MACOS / "host/HawkManagedApplyRequest.swift",
        MACOS / "host/HawkManagedRoutingAuthority.swift", MACOS / "network-extension/HawkRoutingReadinessReceipt.swift"]
    compiled = subprocess.run(["/usr/bin/xcrun", "swiftc", "-module-cache-path", str(tmp_path / "module-cache"),
        *map(str, paths), str(harness), "-o", str(executable)], capture_output=True, text=True)
    assert compiled.returncode == 0, compiled.stderr
    for mutation in ("valid", "mode", "digest", "request_key", "config_key", "provider_key", "suffix", "anchor_key", "anchor_device", "expired", "trailing"):
        changed = copy.deepcopy(request)
        trust = copy.deepcopy(anchor)
        if mutation == "digest":
            changed["expected_policy_sha256"] = "0" * 64
        elif mutation == "request_key":
            changed["endpoint_floor_policy_public_keys"] = anchor["endpoint_floor_policy_public_keys"]
        elif mutation == "config_key":
            config = copy.deepcopy(configuration)
            config["endpoint_floor_policy_public_keys"] = anchor["endpoint_floor_policy_public_keys"]
            changed["managed_configuration_data"] = plistlib.dumps(config, fmt=plistlib.FMT_BINARY)
        elif mutation == "provider_key":
            changed["routing_provider_configuration"]["endpoint_floor_policy_public_keys"] = anchor["endpoint_floor_policy_public_keys"]
        elif mutation == "suffix":
            changed["routing_provider_configuration"]["destinationHostSuffixes"] = ["other.example.com"]
        elif mutation == "anchor_key":
            trust["endpoint_floor_policy_public_keys"] = {"tenant-policy-1": base64.b64encode(bytes(32)).decode()}
        elif mutation == "anchor_device":
            trust["endpoint_id"] = "other"
        path = tmp_path / (mutation + ".plist")
        path.write_bytes(plistlib.dumps(changed, fmt=plistlib.FMT_BINARY) + (b"\0" if mutation == "trailing" else b""))
        anchor_path = tmp_path / "anchor.json"
        anchor_path.write_text(json.dumps(trust))
        executed = subprocess.run([str(executable), str(path), str(anchor_path),
            base64.b64encode(configuration["HawkRoutingTrustRootPublicKeyX963"]).decode(),
            "apply-managed-monitor-policy" if mutation == "mode" else "apply-managed-enforce-policy",
            str(now + 121 if mutation == "expired" else now), "1" if mutation == "valid" else "0"], capture_output=True)
        assert executed.returncode == 0, (mutation, executed.stderr)


def test_code_identity_python_and_native_tuple_match(tmp_path: Path) -> None:
    harness = tmp_path / "identity.m"
    binary = tmp_path / "identity"
    harness.write_text(r'''
#include "HawkMacCodeIdentity.h"
#include <stdio.h>
#include <stdint.h>
int main(void) {
    uint8_t cdhash[20];
    uint8_t digest[32];
    for (unsigned index = 0; index < 20; ++index) cdhash[index] = (uint8_t)index;
    if (!HawkMacCodeIdentityFromComponents((const uint8_t *)"TEAM", 4,
        (const uint8_t *)"ai.hawk.test", 12, cdhash, false, digest)) return 1;
    for (unsigned index = 0; index < 32; ++index) printf("%02x", digest[index]);
    return 0;
}
''', encoding="utf-8")
    compile_result = subprocess.run([
        str(CLANG), "-Wall", "-Wextra", "-Werror", "-isysroot", str(SDK),
        "-I", str(MACOS / "shared"), str(harness),
        str(MACOS / "shared" / "HawkMacCodeIdentity.m"),
        str(SHARED / "HawkBoundedSHA256.c"), "-framework", "Security",
        "-framework", "Foundation", "-lbsm", "-o", str(binary),
    ], capture_output=True, text=True, check=False)
    assert compile_result.returncode == 0, compile_result.stderr
    executed = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    assert executed.returncode == 0, executed.stderr
    assert executed.stdout == macos_code_identity_reference(
        "TEAM", "ai.hawk.test", bytes(range(20)), False)


def test_content_filter_is_the_authoritative_local_network_gate() -> None:
    provider = (
        MACOS / "content-filter" / "HawkNetworkFilterDataProvider.swift"
    ).read_text(encoding="utf-8")
    bridge = (MACOS / "shared" / "HawkMacNetworkBridge.c").read_text(
        encoding="utf-8"
    )
    contract = json.loads(
        (MACOS / "content-filter" / "build-contract.json").read_text(
            encoding="utf-8"
        )
    )

    assert "sourceProcessAuditToken" in provider
    assert "sourceApplicationAuditToken" in provider
    assert "socketFlow?.socketProtocol" in provider
    assert "socketFlow?.socketFamily" in provider
    assert "return .drop()" in provider
    assert "HawkEvaluateCurrentFloorRequest" in bridge
    assert "HawkNormalizeDestinationHost" in bridge
    assert "HAWK_FLOOR_NETWORK_QUIC" in bridge
    assert "HAWK_FLOOR_NETWORK_LOCALHOST" in bridge
    assert contract["network_floor_owns_blocking"] is True
    assert contract["semantic_proxy_is_authoritative_for_deny"] is False
    assert contract["direct_quic_bypass_allowed"] is False
    assert contract["verification_status"] == "unverified"


def test_content_filter_unresolved_pre_evaluator_flows_allow(tmp_path: Path) -> None:
    source = MACOS / "content-filter/HawkNetworkFilterDataProvider.swift"
    text = source.read_text(encoding="utf-8")
    handler = text.split("override func handleNewFlow", 1)[1]
    assert "HawkNetworkFlowContext.from(" in handler
    assert "else {" in handler and "return .allow()" in handler.split("switch decisionEngine", 1)[0]
    harness = tmp_path / "preflight.swift"
    harness.write_text(r'''
import Foundation
import Network

@main
struct Harness {
    static func main() {
        let token = Data(repeating: 0x41, count: 32)
        let endpoint = NWEndpoint.hostPort(host: .name("api.example.com", nil), port: .https)
        func context(_ socket: Bool, _ process: Data?, _ application: Data?,
                     _ destination: NWEndpoint?) -> HawkNetworkFlowContext? {
            HawkNetworkFlowContext.from(
                isSocketFlow: socket, sourceProcessAuditToken: process,
                sourceApplicationAuditToken: application, endpoint: destination,
                protocolNumber: 6, socketFamily: 2)
        }
        assert(context(false, token, token, endpoint) == nil)
        assert(context(true, nil, token, endpoint) == nil)
        assert(context(true, Data(), token, endpoint) == nil)
        assert(context(true, token, nil, endpoint) == nil)
        assert(context(true, token, Data(), endpoint) == nil)
        assert(context(true, token, token, nil) == nil)
        let accepted = context(true, token, token, endpoint)
        assert(accepted?.destinationPort == 443)
        assert(accepted?.destinationHost == Data("api.example.com".utf8))
    }
}
''', encoding="utf-8")
    stubs = tmp_path / "bridge-stubs.c"
    stub_object = tmp_path / "bridge-stubs.o"
    stubs.write_text(r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
int32_t HawkEvaluateNetworkFlow(const uint8_t *process, intptr_t process_length,
    const uint8_t *application, intptr_t application_length,
    const uint8_t *destination, intptr_t destination_length,
    uint16_t port, int32_t protocol, int32_t family) {
    (void)process; (void)process_length; (void)application; (void)application_length;
    (void)destination; (void)destination_length; (void)port; (void)protocol; (void)family;
    return 1;
}
bool HawkMacVerifyAndInstallPolicyEnvelope(const uint8_t *envelope, intptr_t envelope_length,
    const uint8_t *key, intptr_t key_length, bool peer, uint64_t monotonic, uint64_t utc) {
    (void)envelope; (void)envelope_length; (void)key; (void)key_length;
    (void)peer; (void)monotonic; (void)utc;
    return true;
}
''', encoding="utf-8")
    compile_stub = subprocess.run([str(CLANG), "-c", str(stubs), "-o", str(stub_object)],
                                  capture_output=True, text=True, check=False)
    assert compile_stub.returncode == 0, compile_stub.stderr
    binary = tmp_path / "preflight"
    swift = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"
    compiled = subprocess.run([
        swift, "-target", "arm64-apple-macos15.0", "-sdk", str(SDK),
        "-module-cache-path", str(tmp_path / "module-cache"),
        str(source), str(harness), str(stub_object), "-o", str(binary),
    ], capture_output=True, text=True, check=False)
    assert compiled.returncode == 0, compiled.stderr
    run = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr


def test_transparent_proxy_requires_scope_bound_signed_routing_receipt(
    tmp_path: Path,
) -> None:
    receipt_source = (
        MACOS / "network-extension" / "HawkRoutingReadinessReceipt.swift"
    )
    provider = (
        MACOS / "network-extension" / "HawkTransparentProxyProvider.swift"
    ).read_text(encoding="utf-8")
    project = (
        MACOS / "HawkEndpointFloor.xcodeproj" / "project.pbxproj"
    ).read_text(encoding="utf-8")
    info = (MACOS / "network-extension" / "Info.plist").read_text(
        encoding="utf-8"
    )
    contract = json.loads(
        (MACOS / "network-extension" / "build-contract.json").read_text(
            encoding="utf-8"
        )
    )

    assert receipt_source.is_file()
    receipt = receipt_source.read_text(encoding="utf-8")
    assert "P256.Signing.PublicKey" in receipt
    assert "scopeDigest" in receipt
    assert "maximumLifetimeSeconds" in receipt
    assert "issuedAtUnixSeconds" in receipt
    assert "expiresAtUnixSeconds" in receipt
    assert "nonce" in receipt
    assert "HawkRoutingReceipt" in provider
    assert "HawkRoutingReceiptSignatureDER" in provider
    assert "HawkRoutingReceiptPublicKeyX963" in provider
    assert "HawkRoutingBrokerKeyAuthorization" in provider
    assert "HawkRoutingBrokerKeyAuthorizationSignatureDER" in provider
    assert "HawkRoutingTrustRootPublicKeyX963Base64" in provider
    assert "Bundle.main.object" in provider
    assert "verifiedReceipt" in provider
    assert "expiresAtUnixSeconds" in provider
    assert "scheduleRoutingAuthorizationExpiry" in provider
    assert "expireRoutingAuthorization" in provider
    assert "semanticInspectionUnavailable" in provider
    assert "normalizeDestinationSuffix(destinationHost)" in provider
    assert re.search(
        r"verifiedReceipt\.expiresAtUnixSeconds\s*<=\s*"
        r"verifiedAuthorization\.expiresAtUnixSeconds",
        provider,
    )
    assert "bankReadinessReceipt" not in provider
    assert "HawkRoutingTrustRootPublicKeyX963Base64" in info
    assert "HawkRoutingReadinessReceipt.swift in Sources" in project
    assert contract["local_broker_cryptographic_authentication_implemented"] is True
    assert contract["semantic_inspection_implemented"] is False
    assert contract["semantic_inspection_required_action"] == "fail_closed"
    assert contract["routing_receipt_scope_binding"] == [
        "application_signing_identifiers",
        "destination_host_suffixes",
        "policy_epoch",
        "semantic_inspection_required",
    ]
    assert contract["routing_trust_anchor"] == "signed_bundle_policy_root"

    harness = tmp_path / "HawkRoutingReceiptHarness.swift"
    binary = tmp_path / "hawk-routing-receipt-harness"
    harness.write_text(
        r'''
import CryptoKit
import Foundation

@main
struct Harness {
    static func main() throws {
        let privateKey = P256.Signing.PrivateKey()
        let trustRoot = P256.Signing.PrivateKey()
        let now: UInt64 = 2_000_000_000
        let scope = try HawkManagedRoutingScopeMaterial(
            applicationSigningIdentifiers: ["com.example.ai", "com.example.helper"],
            destinationHostSuffixes: ["api.example.com", "models.example.com"],
            policyEpoch: 41,
            semanticInspectionRequired: true
        )
        let normalizedDestination = try HawkManagedRoutingScopeMaterial
            .normalizeDestinationSuffix("API.Example.com.")
        assert(normalizedDestination == "api.example.com")
        let receipt = try HawkRoutingReadinessReceipt(
            issuedAtUnixSeconds: now - 2,
            expiresAtUnixSeconds: now + 120,
            policyEpoch: 41,
            scopeDigest: scope.canonicalDigest(),
            nonce: Data(repeating: 0x5a, count: 16)
        ).serialized()
        assert(scope.canonicalDigest().map { String(format: "%02x", $0) }.joined() ==
            "7d3246e9bc27218bff22b03ca980f694c35f7d6e06000a7b391a5af0c3634258")
        let signature = try privateKey.signature(for: receipt).derRepresentation
        let publicKey = privateKey.publicKey.x963Representation
        let keyAuthorization = try HawkRoutingBrokerKeyAuthorization(
            issuedAtUnixSeconds: now - 2,
            expiresAtUnixSeconds: now + 3_600,
            keyEpoch: 3,
            brokerPublicKeyDigest: Data(SHA256.hash(data: publicKey)),
            nonce: Data(repeating: 0x33, count: 16)
        ).serialized()
        let keyAuthorizationSignature = try trustRoot.signature(
            for: keyAuthorization
        ).derRepresentation
        let trustRootPublicKey = trustRoot.publicKey.x963Representation

        assert(HawkRoutingBrokerAuthorizationVerifier.verify(
            authorization: keyAuthorization,
            signatureDER: keyAuthorizationSignature,
            trustRootPublicKeyX963: trustRootPublicKey,
            brokerPublicKeyX963: publicKey,
            nowUnixSeconds: now
        ))
        assert(HawkRoutingBrokerAuthorizationVerifier.verifiedAuthorization(
            authorization: keyAuthorization,
            signatureDER: keyAuthorizationSignature,
            trustRootPublicKeyX963: trustRootPublicKey,
            brokerPublicKeyX963: publicKey,
            nowUnixSeconds: now
        )?.keyEpoch == 3)
        assert(!HawkRoutingBrokerAuthorizationVerifier.verify(
            authorization: keyAuthorization,
            signatureDER: keyAuthorizationSignature,
            trustRootPublicKeyX963: P256.Signing.PrivateKey().publicKey.x963Representation,
            brokerPublicKeyX963: publicKey,
            nowUnixSeconds: now
        ))
        assert(!HawkRoutingBrokerAuthorizationVerifier.verify(
            authorization: keyAuthorization,
            signatureDER: keyAuthorizationSignature,
            trustRootPublicKeyX963: trustRootPublicKey,
            brokerPublicKeyX963: publicKey,
            nowUnixSeconds: now + 3_601
        ))

        assert(HawkRoutingReceiptVerifier.verify(
            receipt: receipt,
            signatureDER: signature,
            publicKeyX963: publicKey,
            scope: scope,
            nowUnixSeconds: now
        ))
        assert(HawkRoutingReceiptVerifier.verifiedReceipt(
            receipt: receipt,
            signatureDER: signature,
            publicKeyX963: publicKey,
            scope: scope,
            nowUnixSeconds: now
        )?.expiresAtUnixSeconds == now + 120)

        let changedScope = try HawkManagedRoutingScopeMaterial(
            applicationSigningIdentifiers: ["com.example.ai"],
            destinationHostSuffixes: ["evil.example"],
            policyEpoch: 41,
            semanticInspectionRequired: true
        )
        assert(!HawkRoutingReceiptVerifier.verify(
            receipt: receipt,
            signatureDER: signature,
            publicKeyX963: publicKey,
            scope: changedScope,
            nowUnixSeconds: now
        ))
        assert(!HawkRoutingReceiptVerifier.verify(
            receipt: receipt,
            signatureDER: signature,
            publicKeyX963: publicKey,
            scope: scope,
            nowUnixSeconds: now + 121
        ))

        var tampered = receipt
        tampered[tampered.index(before: tampered.endIndex)] ^= 0x01
        assert(!HawkRoutingReceiptVerifier.verify(
            receipt: tampered,
            signatureDER: signature,
            publicKeyX963: publicKey,
            scope: scope,
            nowUnixSeconds: now
        ))
        assert(!HawkRoutingReceiptVerifier.verify(
            receipt: receipt,
            signatureDER: signature,
            publicKeyX963: P256.Signing.PrivateKey().publicKey.x963Representation,
            scope: scope,
            nowUnixSeconds: now
        ))
    }
}
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            "/Applications/Xcode.app/Contents/Developer/Toolchains/"
            "XcodeDefault.xctoolchain/usr/bin/swiftc",
            str(receipt_source),
            str(harness),
            "-sdk",
            str(SDK),
            "-target",
            "arm64-apple-macos15.0",
            "-module-cache-path",
            str(tmp_path / "swift-module-cache"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    executed = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert executed.returncode == 0, executed.stderr


def test_macos_network_bridge_normalizes_destination_and_blocks_alternate_routes(
    tmp_path: Path,
) -> None:
    if not CLANG.is_file() or not SDK.is_dir():
        raise AssertionError("reviewed Xcode clang/SDK is missing")
    harness = tmp_path / "hawk_mac_network_harness.c"
    binary = tmp_path / "hawk_mac_network_harness"
    harness.write_text(
        r'''
#include "HawkMacNetworkBridge.h"
#include "HawkMacPolicyBridge.h"
#include <assert.h>
#include <bsm/libbsm.h>
#include <netinet/in.h>
#include <string.h>

static void fill(uint8_t *value, uint8_t byte) {
    memset(value, byte, HAWK_FLOOR_HASH_BYTES);
}

bool HawkMacCodeIdentityFromAuditToken(const uint8_t *token, size_t length,
                                        uint8_t digest[HAWK_FLOOR_HASH_BYTES]) {
    if (length != sizeof(audit_token_t) || token[0] != 2) return false;
    fill(digest, 8);
    return true;
}

int main(void) {
    HawkFloorPolicySnapshot snapshot;
    HawkMacPolicyAdmission admission;
    HawkFloorRule rules[2];
    memset(&snapshot, 0, sizeof(snapshot));
    memset(&admission, 0, sizeof(admission));
    memset(rules, 0, sizeof(rules));
    uint8_t process[sizeof(audit_token_t)] = {1};
    uint8_t application[sizeof(audit_token_t)] = {2};
    const uint8_t localhost[] = "127.0.0.1";
    assert(HawkEvaluateNetworkFlow(process, sizeof(process), application, sizeof(application),
        localhost, sizeof(localhost) - 1, 11434, IPPROTO_TCP, AF_INET) == HAWK_MAC_NETWORK_VERDICT_ALLOW);
    snapshot.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    snapshot.signatureVerified = true;
    snapshot.configurationIntegrityValid = true;
    snapshot.policyEpoch = 9;
    snapshot.expiresAtMonotonicNs = UINT64_MAX;
    memcpy(snapshot.policyVersion, "network-9", 10);
    fill(snapshot.tenantHash, 1);
    fill(snapshot.deviceHash, 2);
    for (unsigned index = 0; index < HAWK_FLOOR_PRIMITIVE_COUNT; ++index) {
        snapshot.defaultActionByPrimitive[index] = HAWK_FLOOR_ACTION_ALLOW;
    }
    snapshot.ruleCount = 2;
    snapshot.rules = rules;
    rules[0].primitiveMask = 1ULL << HAWK_FLOOR_NETWORK_LOCALHOST;
    rules[1].primitiveMask = 1ULL << HAWK_FLOOR_NETWORK_QUIC;
    for (unsigned index = 0; index < 2; ++index) {
        rules[index].action = HAWK_FLOOR_ACTION_BLOCK;
        rules[index].bindBinaryIdentity = true;
        fill(rules[index].binaryIdentityHash, 8);
    }

    admission.schemaVersion = HAWK_MAC_POLICY_ADMISSION_SCHEMA_VERSION;
    admission.authenticatedPeer = true;
    admission.signatureVerified = true;
    admission.signerPinVerified = true;
    admission.configurationIntegrityValid = true;
        admission.deliverySequence = 1;
        admission.receivedAtMonotonicNs = 1;
        admission.receivedAtUnixSeconds = 1000;
        admission.mode = HAWK_MAC_ENFORCEMENT_ENFORCE;
    admission.governedIdentityCount = 1;
    fill(admission.governedIdentities[0], 8);
    fill(admission.bundleDigest, 3);
    assert(HawkMacInstallPolicySnapshot(&snapshot, &admission));

    const uint8_t allowedHost[] = "EXAMPLE.COM.";
    assert(HawkEvaluateNetworkFlow(
        process, sizeof(process), application, sizeof(application),
        allowedHost, sizeof(allowedHost) - 1, 443, IPPROTO_TCP, AF_INET
    ) == HAWK_MAC_NETWORK_VERDICT_ALLOW);

    assert(HawkEvaluateNetworkFlow(
        process, sizeof(process), application, sizeof(application),
        localhost, sizeof(localhost) - 1, 11434, IPPROTO_TCP, AF_INET
    ) == HAWK_MAC_NETWORK_VERDICT_BLOCK);
    application[0] = 3;
    assert(HawkEvaluateNetworkFlow(
        process, sizeof(process), application, sizeof(application),
        localhost, sizeof(localhost) - 1, 11434, IPPROTO_TCP, AF_INET
    ) == HAWK_MAC_NETWORK_VERDICT_ALLOW);
    application[0] = 2;

    const uint8_t quicHost[] = "example.com";
    assert(HawkEvaluateNetworkFlow(
        process, sizeof(process), application, sizeof(application),
        quicHost, sizeof(quicHost) - 1, 443, IPPROTO_UDP, AF_INET6
    ) == HAWK_MAC_NETWORK_VERDICT_BLOCK);

    const uint8_t malformed[] = {'e', 'x', 0, 'a'};
    assert(HawkEvaluateNetworkFlow(
        process, sizeof(process), application, sizeof(application),
        malformed, sizeof(malformed), 443, IPPROTO_TCP, AF_INET
    ) == HAWK_MAC_NETWORK_VERDICT_BLOCK);
    return 0;
}
''',
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            str(CLANG),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DHAWK_MAC_POLICY_TESTING=1",
            "-isysroot",
            str(SDK),
            "-I",
            str(SHARED),
            "-I",
            str(MACOS / "shared"),
            str(harness),
            str(SHARED / "HawkBoundedSHA256.c"),
            str(SHARED / "HawkFloorDecisionEngine.c"),
            str(MACOS / "shared" / "HawkMacPolicyBridge.c"),
            str(MACOS / "shared" / "HawkMacNetworkBridge.c"),
            "-lbsm",
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    executed = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    assert executed.returncode == 0, executed.stderr
