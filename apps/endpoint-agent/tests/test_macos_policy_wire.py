from __future__ import annotations

import struct
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from hawk_endpoint_agent.macos_policy_compiler import assemble_native_envelope
from test_macos_policy_compiler import NOW, _render


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


def _wire_payload() -> bytes:
    defaults = [0] * 40
    return struct.pack(
        "<IIQQQQIIIIII32s32s40I64s",
        2,
        2,
        44,
        9,
        999,
        1100,
        0,
        0,
        0,
        0,
        0,
        2,
        b"\x11" * 32,
        b"\x22" * 32,
        *defaults,
        b"policy-9\0".ljust(64, b"\0"),
    )


def test_signed_policy_wire_rejects_tamper_replay_and_unauthenticated_peer(
    tmp_path: Path,
) -> None:
    private = ec.generate_private_key(ec.SECP256R1())
    public = private.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    )
    payload = _wire_payload()
    signature = private.sign(payload, ec.ECDSA(hashes.SHA256()))
    envelope = struct.pack("<IIII", 2, len(payload), len(signature), 0) + payload + signature
    envelope_path = tmp_path / "policy.bin"
    key_path = tmp_path / "policy-key.x963"
    envelope_path.write_bytes(envelope)
    key_path.write_bytes(public)

    harness = tmp_path / "wire_harness.c"
    binary = tmp_path / "wire_harness"
    harness.write_text(
        r'''
#include "HawkMacPolicyWire.h"
#include "HawkMacPolicyBridge.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned char *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    assert(fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file);
    assert(size > 0);
    rewind(file);
    unsigned char *value = malloc((size_t)size);
    assert(value != NULL);
    assert(fread(value, 1, (size_t)size, file) == (size_t)size);
    fclose(file);
    *length = (size_t)size;
    return value;
}

int main(int argc, char **argv) {
    assert(argc == 3);
    size_t envelope_length = 0;
    size_t key_length = 0;
    unsigned char *envelope = read_file(argv[1], &envelope_length);
    unsigned char *key = read_file(argv[2], &key_length);
    assert(!HawkMacVerifyAndInstallPolicyEnvelope(
        envelope, envelope_length, key, key_length, false, 100, 1000
    ));
    assert(HawkMacVerifyAndInstallPolicyEnvelope(
        envelope, envelope_length, key, key_length, true, 100, 1000
    ));
    assert(!HawkMacVerifyAndInstallPolicyEnvelope(
        envelope, envelope_length, key, key_length, true, 101, 1000
    ));

    HawkMacPolicyHealth health;
    assert(HawkMacCopyPolicyHealth(&health));
    assert(health.active);
    assert(health.deliverySequence == 44);
    assert(health.policyEpoch == 9);
    assert(health.issuedAtUnixSeconds == 999);
    assert(health.expiresAtUnixSeconds == 1100);
    assert(health.signatureVerified);
    assert(health.authenticatedPeer);

    envelope[sizeof(HawkMacPolicyEnvelopeHeader) + 8] ^= 1;
    assert(!HawkMacVerifyAndInstallPolicyEnvelope(
        envelope, envelope_length, key, key_length, true, 102, 1000
    ));
    free(envelope);
    free(key);
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
            "-I",
            str(MACOS / "shared"),
            str(harness),
            str(SHARED / "HawkFloorDecisionEngine.c"),
            str(SHARED / "HawkBoundedSHA256.c"),
            str(MACOS / "shared" / "HawkMacPolicyBridge.c"),
            str(MACOS / "shared" / "HawkMacPolicyWire.c"),
            "-framework",
            "Security",
            "-framework",
            "CoreFoundation",
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    run = subprocess.run(
        [str(binary), str(envelope_path), str(key_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, run.stderr


def test_compiler_payload_installs_in_native_wire_verifier(tmp_path: Path) -> None:
    payload = _render()
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint,
    )
    envelope = assemble_native_envelope(
        payload, key.sign(payload, ec.ECDSA(hashes.SHA256())), public,
    )
    (tmp_path / "envelope.bin").write_bytes(envelope)
    (tmp_path / "key.bin").write_bytes(public)
    harness = tmp_path / "compiler_wire.c"
    harness.write_text(r'''
#include "HawkMacPolicyWire.h"
#include "HawkMacPolicyBridge.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned char *read_file(const char *path, size_t *length) {
    FILE *file = fopen(path, "rb"); assert(file);
    assert(fseek(file, 0, SEEK_END) == 0);
    long size = ftell(file); assert(size > 0); rewind(file);
    unsigned char *data = malloc((size_t)size); assert(data);
    assert(fread(data, 1, (size_t)size, file) == (size_t)size);
    fclose(file); *length = (size_t)size; return data;
}
int main(int argc, char **argv) {
    assert(argc == 4);
    size_t envelope_size, key_size;
    unsigned char *envelope = read_file(argv[1], &envelope_size);
    unsigned char *key = read_file(argv[2], &key_size);
    unsigned long long now = strtoull(argv[3], NULL, 10);
    assert(HawkMacVerifyAndInstallPolicyEnvelope(envelope, envelope_size,
        key, key_size, true, 1000000, now));
    HawkMacPolicyHealth health;
    assert(HawkMacCopyPolicyHealth(&health));
    assert(health.policyEpoch == 7 && health.deliverySequence == 9);
    assert(health.mode == HAWK_MAC_ENFORCEMENT_ENFORCE && health.active);
    envelope[sizeof(HawkMacPolicyEnvelopeHeader) + 8] ^= 1;
    assert(!HawkMacVerifyAndInstallPolicyEnvelope(envelope, envelope_size,
        key, key_size, true, 1000001, now));
    free(envelope); free(key); return 0;
}
''', encoding="utf-8")
    binary = tmp_path / "compiler_wire"
    result = subprocess.run([
        str(CLANG), "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-isysroot", str(SDK), "-I", str(SHARED), "-I", str(MACOS / "shared"),
        str(harness), str(SHARED / "HawkFloorDecisionEngine.c"),
        str(SHARED / "HawkBoundedSHA256.c"),
        str(MACOS / "shared/HawkMacPolicyBridge.c"),
        str(MACOS / "shared/HawkMacPolicyWire.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-o", str(binary),
    ], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
    run = subprocess.run([
        str(binary), str(tmp_path / "envelope.bin"), str(tmp_path / "key.bin"),
        str(int(NOW.timestamp())),
    ], capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stderr
