from __future__ import annotations

import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / "native" / "shared"
CLANG = Path(
    "/Applications/Xcode.app/Contents/Developer/Toolchains/"
    "XcodeDefault.xctoolchain/usr/bin/clang"
)


def test_shared_abi_contains_complete_taxonomy_epoch_rights_and_permit_bindings() -> None:
    header = (NATIVE / "HawkFloorDecisionEngine.h").read_text(encoding="utf-8")
    required = {
        "HAWK_FLOOR_FILE_TRUNCATE",
        "HAWK_FLOOR_FILE_MOVE",
        "HAWK_FLOOR_FILE_EXECUTE",
        "HAWK_FLOOR_FILE_MEMORY_MAP",
        "HAWK_FLOOR_FILE_METADATA_CHANGE",
        "HAWK_FLOOR_PROCESS_SCRIPT_LAUNCH",
        "HAWK_FLOOR_PROCESS_INTERPRETER_LAUNCH",
        "HAWK_FLOOR_NETWORK_ACCEPT",
        "HAWK_FLOOR_NETWORK_REDIRECT",
        "HAWK_FLOOR_NETWORK_DNS",
        "HAWK_FLOOR_NETWORK_QUIC",
        "HAWK_FLOOR_NETWORK_UNIX_SOCKET",
        "HAWK_FLOOR_NETWORK_NAMED_PIPE",
        "HAWK_FLOOR_INTERNAL_TRANSFER",
        "HAWK_FLOOR_LOCAL_AGENT_CONNECTION",
        "HAWK_FLOOR_LOCAL_MODEL_CONNECTION",
        "HAWK_FLOOR_UNKNOWN_LOCAL_SERVICE",
        "policyEpoch",
        "requestedRights",
        "stableResourceIdentityHash",
        "canonicalActionHash",
        "permitDigest",
        "processInstanceHash",
        "HawkFloorPermit",
        "permitConsumed",
        "permitMismatch",
    }
    assert required.issubset(set(header.replace(";", " ").split()) | {token for token in required if token in header})
    assert "HAWK_FLOOR_PRIMITIVE_COUNT" in header
    assert "HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT" in header
    assert "HAWK_FLOOR_ACTION_REQUIRE_REMOTE_DECISION" in header
    assert "HAWK_FLOOR_ACTION_REQUIRE_USER_RETRY_AFTER_APPROVAL" in header
    assert "HAWK_FLOOR_ACTION_ALLOW_WITH_EVIDENCE" in header


def test_shared_evaluator_has_no_callback_escape_hatches() -> None:
    source = (NATIVE / "HawkFloorDecisionEngine.c").read_text(encoding="utf-8")
    forbidden = (
        "malloc(",
        "calloc(",
        "realloc(",
        "fopen(",
        "open(",
        "system(",
        "popen(",
        "dlopen(",
        "curl",
        "URLSession",
        "WinHttp",
        "CreateProcess",
    )
    assert not any(token in source for token in forbidden)
    assert "HAWK_FLOOR_MAX_PERMITS" in source
    assert "HawkAtomicConsumeBounded" in source


def test_shared_c_harness_proves_atomic_single_use_mismatch_epoch_and_deadline(tmp_path) -> None:
    if not CLANG.is_file():
        raise AssertionError(f"reviewed direct clang binary is missing: {CLANG}")
    harness = tmp_path / "hawk_floor_harness.c"
    binary = tmp_path / "hawk_floor_harness"
    harness.write_text(
        r'''
#include "HawkFloorDecisionEngine.h"
#include <assert.h>
#include <string.h>

static void fill(uint8_t *value, uint8_t byte) {
    memset(value, byte, HAWK_FLOOR_HASH_BYTES);
}

int main(void) {
    _Static_assert(HAWK_FLOOR_PRIMITIVE_COUNT <= 64, "mask must remain bounded");
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
    snapshot.policyEpoch = 8;
    snapshot.expiresAtMonotonicNs = 1000;
    snapshot.ruleCount = 1;
    snapshot.rules = &rule;
    snapshot.permitCount = 1;
    snapshot.permits = &permit;
    memcpy(snapshot.policyVersion, "policy-8", 9);
    fill(snapshot.tenantHash, 1);
    fill(snapshot.deviceHash, 2);
    for (unsigned i = 0; i < HAWK_FLOOR_PRIMITIVE_COUNT; ++i) {
        snapshot.defaultActionByPrimitive[i] = HAWK_FLOOR_ACTION_BLOCK;
    }

    rule.primitiveMask = 1ULL << HAWK_FLOOR_FILE_READ;
    rule.action = HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT;

    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request.primitive = HAWK_FLOOR_FILE_READ;
    request.policyEpoch = 8;
    request.deadlineMonotonicNs = 900;
    request.requestedRights = 1;
    fill(request.tenantHash, 1);
    fill(request.deviceHash, 2);
    fill(request.processInstanceHash, 3);
    fill(request.binaryIdentityHash, 4);
    fill(request.stableResourceIdentityHash, 5);
    fill(request.canonicalActionHash, 6);
    fill(request.permitDigest, 7);

    HawkFloorDecision required = HawkFloorEvaluate(&snapshot, &request, 10);
    assert(required.action == HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT);
    assert(!required.permitConsumed);

    permit.integrityVerified = true;
    permit.primitive = HAWK_FLOOR_FILE_READ;
    permit.requestedRights = 1;
    permit.policyEpoch = 8;
    permit.expiresAtMonotonicNs = 800;
    permit.maximumUses = 1;
    fill(permit.processInstanceHash, 3);
    fill(permit.stableResourceIdentityHash, 5);
    fill(permit.canonicalActionHash, 6);
    fill(permit.permitDigest, 7);
    request.permitPresent = true;

    HawkFloorDecision allowed = HawkFloorEvaluate(&snapshot, &request, 11);
    assert(allowed.action == HAWK_FLOOR_ACTION_ALLOW);
    assert(allowed.permitConsumed);
    assert(!allowed.permitMismatch);

    HawkFloorDecision replay = HawkFloorEvaluate(&snapshot, &request, 12);
    assert(replay.action == HAWK_FLOOR_ACTION_BLOCK);
    assert(replay.permitMismatch);

    permit.consumedUses = 0;
    fill(request.stableResourceIdentityHash, 9);
    HawkFloorDecision mismatch = HawkFloorEvaluate(&snapshot, &request, 13);
    assert(mismatch.action == HAWK_FLOOR_ACTION_BLOCK);
    assert(mismatch.permitMismatch);

    request.permitPresent = false;
    fill(request.stableResourceIdentityHash, 5);
    request.policyEpoch = 7;
    assert(!HawkFloorEvaluate(&snapshot, &request, 14).policyAccepted);
    request.policyEpoch = 8;
    assert(HawkFloorEvaluate(&snapshot, &request, 901).deadlineExceeded);

    request.schemaVersion = 999;
    assert(HawkFloorEvaluate(&snapshot, &request, 20).action == HAWK_FLOOR_ACTION_BLOCK);
    request.schemaVersion = HAWK_FLOOR_SCHEMA_VERSION;
    request.primitive = (HawkFloorPrimitive)HAWK_FLOOR_PRIMITIVE_COUNT;
    assert(HawkFloorEvaluate(&snapshot, &request, 20).action == HAWK_FLOOR_ACTION_BLOCK);
    request.primitive = HAWK_FLOOR_FILE_READ;
    snapshot.ruleCount = HAWK_FLOOR_MAX_RULES + 1;
    assert(HawkFloorEvaluate(&snapshot, &request, 20).action == HAWK_FLOOR_ACTION_BLOCK);
    snapshot.ruleCount = 1;
    rule.action = (HawkFloorAction)999;
    assert(!HawkFloorEvaluate(&snapshot, &request, 20).policyAccepted);
    rule.action = HAWK_FLOOR_ACTION_REQUIRE_PREAUTHORIZED_PERMIT;

    /* Deterministic malformed-enum/version/deadline exercise: no allocation,
       parser, Unicode interpretation, or pointer arithmetic is exposed. */
    for (unsigned i = 0; i < 10000; ++i) {
        request.schemaVersion = (i % 11 == 0) ? 999 : HAWK_FLOOR_SCHEMA_VERSION;
        request.primitive = (HawkFloorPrimitive)(i % (HAWK_FLOOR_PRIMITIVE_COUNT + 7));
        request.policyEpoch = (i % 13 == 0) ? 7 : 8;
        (void)HawkFloorEvaluate(&snapshot, &request, 20 + i);
    }
    return 0;
}
''',
        encoding="utf-8",
    )
    compile_result = subprocess.run(
        [
            str(CLANG),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-isysroot",
            "/Applications/Xcode.app/Contents/Developer/Platforms/"
            "MacOSX.platform/Developer/SDKs/MacOSX.sdk",
            "-I",
            str(NATIVE),
            str(harness),
            str(NATIVE / "HawkFloorDecisionEngine.c"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert compile_result.returncode == 0, compile_result.stderr
    run_result = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    assert run_result.returncode == 0, run_result.stderr
