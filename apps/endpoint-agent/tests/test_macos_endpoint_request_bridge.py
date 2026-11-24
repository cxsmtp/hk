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


def test_bounded_sha256_matches_known_vector(tmp_path: Path) -> None:
    harness = tmp_path / "sha256_harness.c"
    binary = tmp_path / "sha256_harness"
    harness.write_text(
        r'''
#include "HawkBoundedSHA256.h"
#include <assert.h>
#include <stdint.h>
#include <string.h>

int main(void) {
    static const uint8_t expected[HAWK_SHA256_DIGEST_BYTES] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t digest[HAWK_SHA256_DIGEST_BYTES];
    HawkSHA256Context context;
    HawkSHA256Initialize(&context);
    assert(HawkSHA256Update(&context, "a", 1));
    assert(HawkSHA256Update(&context, "bc", 2));
    HawkSHA256Finalize(&context, digest);
    assert(memcmp(digest, expected, sizeof(expected)) == 0);
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
            "-isysroot",
            str(SDK),
            "-I",
            str(SHARED),
            str(harness),
            str(SHARED / "HawkBoundedSHA256.c"),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    run = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr


def test_endpoint_request_bridge_uses_process_instance_and_stable_file_identity() -> None:
    source = (MACOS / "endpoint-security" / "HawkMacEndpointRequest.c").read_text(
        encoding="utf-8"
    )
    identity = (MACOS / "shared" / "HawkMacCodeIdentity.m").read_text(encoding="utf-8")
    required = (
        "audit_token_to_pidversion",
        "audit_token",
        "start_time",
        "responsible_audit_token",
        "st_dev",
        "st_ino",
        "path_truncated",
        "HawkMacCopyPolicyBinding",
        "message->deadline",
        "canonicalActionHash",
    )
    assert all(token in source for token in required)
    assert all(token in identity for token in ("cdhash", "signing_id", "team_id"))
    assert "HawkMacCodeIdentityFromESProcess" in source
    assert "hawk.macos.binary-identity.v1" not in source
    assert "message->process->audit_token.val[5]" not in source
    assert not any(token in source for token in ("malloc(", "realpath(", "open(", "stat("))


def test_lineage_admission_does_not_evict_governed_roots(tmp_path: Path) -> None:
    harness = tmp_path / "lineage.c"
    binary = tmp_path / "lineage"
    harness.write_text(r'''
#include "HawkMacProcessLineage.h"
#include <assert.h>
#include <string.h>

static audit_token_t token(unsigned pid, unsigned version) {
    audit_token_t value = {{0}};
    value.val[5] = pid;
    value.val[7] = version;
    return value;
}

int main(void) {
    uint8_t root[32], other[32], out[32];
    uint8_t unknown[32] = {0};
    HawkMacProcessLineageHealth health;
    memset(root, 8, sizeof(root));
    memset(other, 9, sizeof(other));
    HawkMacProcessLineageClear();
    assert(HawkMacProcessLineageCopyHealth(&health));
    assert(health.occupancy == 0 && health.recordFailureCount == 0);
    // An explicitly governed Claude target seeds a root without a parent row.
    assert(HawkMacProcessLineageRecordExec(token(1, 1), token(20, 1),
        unknown, root, true, true));
    assert(HawkMacProcessLineageLookup(token(20, 1), out));
    assert(memcmp(out, root, 32) == 0);
    // Claude -> shell -> interpreter keeps the Claude authority.
    assert(HawkMacProcessLineageRecordExec(token(20, 1), token(21, 1),
        root, other, false, true));
    assert(HawkMacProcessLineageLookup(token(21, 1), out));
    assert(memcmp(out, root, 32) == 0);
    assert(HawkMacProcessLineageRecordExec(token(21, 1), token(22, 1),
        root, other, false, true));
    assert(HawkMacProcessLineageLookup(token(22, 1), out));
    assert(memcmp(out, root, 32) == 0);
    assert(!HawkMacProcessLineageLookup(token(22, 2), out));
    HawkMacProcessLineageClear();
    assert(!HawkMacProcessLineageLookup(token(20, 1), out));
    assert(!HawkMacProcessLineageLookup(token(22, 1), out));
    assert(!HawkMacProcessLineageRecordExec(token(1, 1), token(2, 1),
        root, other, false, false));
    assert(!HawkMacProcessLineageLookup(token(2, 1), out));
    assert(HawkMacProcessLineageRecordExec(token(1, 1), token(2, 1),
        root, other, false, true));
    assert(HawkMacProcessLineageLookup(token(2, 1), out));
    assert(memcmp(out, root, 32) == 0);
    assert(!HawkMacProcessLineageLookup(token(2, 2), out));
    assert(HawkMacProcessLineageRecordExec(token(2, 1), token(3, 1),
        root, other, true, true));
    assert(HawkMacProcessLineageLookup(token(3, 1), out));
    assert(memcmp(out, other, 32) == 0);
    HawkMacProcessLineageClear();
    for (unsigned index = 0; index < HAWK_MAC_PROCESS_LINEAGE_CAPACITY; ++index)
        assert(HawkMacProcessLineageRecordExec(token(1, 1), token(index + 10, 1),
            root, other, false, true));
    assert(HawkMacProcessLineageCopyHealth(&health));
    assert(health.occupancy == HAWK_MAC_PROCESS_LINEAGE_CAPACITY);
    assert(health.recordFailureCount == 0);
    assert(!HawkMacProcessLineageRecordExec(token(1, 1), token(999, 1),
        root, other, false, true));
    assert(HawkMacProcessLineageCopyHealth(&health));
    assert(health.occupancy == HAWK_MAC_PROCESS_LINEAGE_CAPACITY);
    assert(health.recordFailureCount == 1);
    assert(!HawkMacProcessLineageRecordExec(token(1, 1), token(1000, 1),
        root, other, false, false));
    assert(HawkMacProcessLineageCopyHealth(&health));
    assert(health.recordFailureCount == 1);
    assert(HawkMacProcessLineageLookup(token(10, 1), out));
    assert(memcmp(out, root, 32) == 0);
    HawkMacProcessLineageRemove(token(10, 1));
    assert(HawkMacProcessLineageCopyHealth(&health));
    assert(health.occupancy == HAWK_MAC_PROCESS_LINEAGE_CAPACITY - 1);
    assert(HawkMacProcessLineageRecordExec(token(1, 1), token(999, 1),
        root, other, false, true));
    HawkMacProcessLineageClear();
    assert(HawkMacProcessLineageCopyHealth(&health));
    assert(health.occupancy == 0 && health.recordFailureCount == 0);
    return 0;
}
''', encoding="utf-8")
    compile_result = subprocess.run([
        str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-isysroot", str(SDK), "-I", str(MACOS / "endpoint-security"),
        str(harness), str(MACOS / "endpoint-security" / "HawkMacProcessLineage.c"),
        "-lbsm", "-o", str(binary),
    ], capture_output=True, text=True, check=False)
    assert compile_result.returncode == 0, compile_result.stderr
    executed = subprocess.run([str(binary)], capture_output=True, text=True, check=False)
    assert executed.returncode == 0, executed.stderr


def test_endpoint_security_sources_compile_with_reviewed_sdk(tmp_path: Path) -> None:
    objects = [tmp_path / "client.o", tmp_path / "request.o"]
    sources = [
        MACOS / "endpoint-security" / "HawkEndpointSecurityClient.c",
        MACOS / "endpoint-security" / "HawkMacEndpointRequest.c",
    ]
    for source, target in zip(sources, objects, strict=True):
        result = subprocess.run(
            [
                str(CLANG),
                "-std=c11",
                "-fblocks",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-isysroot",
                str(SDK),
                "-I",
                str(SHARED),
                "-I",
                str(MACOS / "shared"),
                "-I",
                str(MACOS / "endpoint-security"),
                "-c",
                str(source),
                "-o",
                str(target),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
