from __future__ import annotations

import subprocess
from pathlib import Path


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


def test_macos_snapshot_bridge_is_bounded_authenticated_and_fail_closed() -> None:
    header = (MACOS / "shared" / "HawkMacPolicyBridge.h").read_text(encoding="utf-8")
    source = (MACOS / "shared" / "HawkMacPolicyBridge.c").read_text(encoding="utf-8")

    required = {
        "HawkMacInstallPolicySnapshot",
        "HawkEvaluateCurrentFloorRequest",
        "HawkCurrentSignedPolicySnapshot",
        "HawkMacCopyPolicyHealth",
        "authenticatedPeer",
        "signatureVerified",
        "signerPinVerified",
        "deliverySequence",
        "policyEpoch",
        "configurationIntegrityValid",
        "HAWK_FLOOR_MAX_RULES",
        "HAWK_FLOOR_MAX_PERMITS",
        "HawkAttachBrokeredPermit",
    }
    assert all(token in header or token in source for token in required)
    assert "os_unfair_lock" in source
    assert "memcpy" in source
    assert not any(
        token in source
        for token in (
            "malloc(",
            "calloc(",
            "realloc(",
            "URLSession",
            "http://",
            "https://",
            "system(",
            "popen(",
            "dlopen(",
        )
    )


def test_macos_bridge_compiled_harness_proves_snapshot_rollback_and_permit_semantics(
    tmp_path: Path,
) -> None:
    if not CLANG.is_file() or not SDK.is_dir():
        raise AssertionError("reviewed Xcode clang/SDK is missing")
    harness = tmp_path / "hawk_mac_bridge_harness.c"
    binary = tmp_path / "hawk_mac_bridge_harness"
    harness.write_text(
        r'''
#include "HawkMacPolicyBridge.h"
#include <assert.h>
#include <string.h>

static void fill(uint8_t *value, uint8_t byte) {
    memset(value, byte, HAWK_FLOOR_HASH_BYTES);
}

static HawkMacPolicyAdmission admission(uint64_t sequence, uint64_t now) {
    HawkMacPolicyAdmission value;
    memset(&value, 0, sizeof(value));
    value.schemaVersion = HAWK_MAC_POLICY_ADMISSION_SCHEMA_VERSION;
    value.authenticatedPeer = true;
    value.signatureVerified = true;
    value.signerPinVerified = true;
    value.configurationIntegrityValid = true;
        value.deliverySequence = sequence;
        value.receivedAtMonotonicNs = now;
        value.receivedAtUnixSeconds = 1000;
        value.mode = HAWK_MAC_ENFORCEMENT_ENFORCE;
        value.governedIdentityCount = 1;
        fill(value.governedIdentities[0], 8);
    fill(value.bundleDigest, 9);
    return value;
}

int main(void) {
    HawkFloorRule rule;
    HawkFloorPermit permit;
    HawkFloorPolicySnapshot snapshot;
    HawkFloorRequest request;
    memset(&rule, 0, sizeof(rule));
    memset(&permit, 0, sizeof(permit));
    memset(&snapshot, 0, sizeof(snapshot));
    memset(&request, 0, sizeof(request));

    snapshot.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    snapshot.signatureVerified = true;
    snapshot.configurationIntegrityValid = true;
    snapshot.policyEpoch = 7;
    snapshot.expiresAtMonotonicNs = 5000;
    snapshot.ruleCount = 1;
    snapshot.rules = &rule;
    snapshot.permitCount = 1;
    snapshot.permits = &permit;
    memcpy(snapshot.policyVersion, "policy-7", 9);
    fill(snapshot.tenantHash, 1);
    fill(snapshot.deviceHash, 2);
    for (unsigned i = 0; i < HAWK_FLOOR_PRIMITIVE_COUNT; ++i) {
        snapshot.defaultActionByPrimitive[i] = HAWK_FLOOR_ACTION_BLOCK;
    }
    rule.primitiveMask = 1ULL << HAWK_FLOOR_FILE_READ;
    rule.action = HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT;
    rule.bindBinaryIdentity = true;
    fill(rule.binaryIdentityHash, 8);
    permit.integrityVerified = true;
    permit.primitive = HAWK_FLOOR_FILE_READ;
    permit.requestedRights = 1;
    permit.policyEpoch = 7;
    permit.expiresAtMonotonicNs = 3000;
    permit.maximumUses = 1;
    fill(permit.processInstanceHash, 3);
    fill(permit.stableResourceIdentityHash, 4);
    fill(permit.canonicalActionHash, 5);
    fill(permit.permitDigest, 6);

    HawkMacPolicyAdmission first = admission(10, 100);
    /* An unrestricted default cannot acquire machine-wide deny authority. */
    assert(!HawkMacInstallPolicySnapshot(&snapshot, &first));
    for (unsigned i = 0; i < HAWK_FLOOR_PRIMITIVE_COUNT; ++i) {
        snapshot.defaultActionByPrimitive[i] = HAWK_FLOOR_ACTION_ALLOW;
    }
    assert(HawkMacInstallPolicySnapshot(&snapshot, &first));

    /* The active copy is immutable even if delivery memory changes. */
    rule.action = HAWK_FLOOR_ACTION_BLOCK;
    memset(&snapshot, 0, sizeof(snapshot));

    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request.primitive = HAWK_FLOOR_FILE_READ;
    request.policyEpoch = 7;
    request.requestedRights = 1;
    request.deadlineMonotonicNs = 4000;
    fill(request.tenantHash, 1);
    fill(request.deviceHash, 2);
    fill(request.processInstanceHash, 3);
    fill(request.binaryIdentityHash, 8);
    fill(request.stableResourceIdentityHash, 4);
    fill(request.canonicalActionHash, 5);
    fill(request.permitDigest, 6);
    fill(request.binaryIdentityHash, 77);
    HawkFloorDecision ungoverned = HawkEvaluateCurrentFloorRequest(&request, 200);
    assert(ungoverned.action == HAWK_FLOOR_ACTION_ALLOW);
    fill(request.binaryIdentityHash, 8);
    /* The local broker owns permit selection; the application supplies no token. */
    HawkFloorDecision permitted = HawkEvaluateCurrentFloorRequest(&request, 200);
    assert(permitted.action == HAWK_FLOOR_ACTION_ALLOW);
    assert(permitted.permitConsumed);
    HawkFloorDecision permitReplay = HawkEvaluateCurrentFloorRequest(&request, 201);
    assert(permitReplay.action == HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT);
    assert(!permitReplay.permitConsumed);

    /* Delivery sequence and policy epoch rollback are rejected. */
    HawkFloorPolicySnapshot rollback = *HawkCurrentSignedPolicySnapshot();
    HawkMacPolicyAdmission replay = admission(10, 201);
    assert(!HawkMacInstallPolicySnapshot(&rollback, &replay));
    replay.deliverySequence = 11;
    rollback.policyEpoch = 6;
    assert(!HawkMacInstallPolicySnapshot(&rollback, &replay));

    /* An unauthenticated or unsigned delivery can never replace policy. */
    rollback.policyEpoch = 8;
    replay.authenticatedPeer = false;
    assert(!HawkMacInstallPolicySnapshot(&rollback, &replay));
    replay.authenticatedPeer = true;
    replay.signatureVerified = false;
    assert(!HawkMacInstallPolicySnapshot(&rollback, &replay));

    HawkMacPolicyHealth health;
    assert(HawkMacCopyPolicyHealth(&health));
    assert(health.active);
    assert(health.policyEpoch == 7);
    assert(health.deliverySequence == 10);
    assert(health.rejectedDeliveryCount == 5);
    assert(health.signatureVerified);
    assert(health.authenticatedPeer);
    assert(health.signerPinVerified);

    HawkMacClearPolicySnapshotForTesting();
    HawkFloorDecision absent = HawkEvaluateCurrentFloorRequest(&request, 202);
    assert(absent.action == HAWK_FLOOR_ACTION_ALLOW);
    assert(!absent.policyAccepted);
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
            str(SHARED / "HawkFloorDecisionEngine.c"),
            str(MACOS / "shared" / "HawkMacPolicyBridge.c"),
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


def test_macos_endpoint_and_network_clients_use_the_shared_bridge() -> None:
    endpoint = (MACOS / "endpoint-security" / "HawkEndpointSecurityClient.c").read_text(
        encoding="utf-8"
    )
    network = (MACOS / "content-filter" / "HawkNetworkFilterDataProvider.swift").read_text(
        encoding="utf-8"
    )
    bridge = (MACOS / "shared" / "HawkMacNetworkBridge.c").read_text(encoding="utf-8")

    assert "extern const HawkFloorPolicySnapshot" not in endpoint
    assert "extern bool HawkBuildRequestFromESMessage" not in endpoint
    assert "HawkEvaluateCurrentFloorRequest" in endpoint
    assert "HAWK_FLOOR_FILE_TRUNCATE" in endpoint
    assert "HawkEvaluateNetworkFlow" in network
    assert "sourceProcessAuditToken" in network
    assert "switch rawVerdict" in network
    assert "Until it" not in network
    assert "HawkEvaluateCurrentFloorRequest" in bridge
    assert "HAWK_FLOOR_NETWORK_QUIC" in bridge
    assert "HAWK_FLOOR_NETWORK_LOCALHOST" in bridge
