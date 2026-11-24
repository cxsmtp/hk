#!/usr/bin/env python3
"""Verify externally signed target results and stage a detached envelope."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_endpoint_agent.macos_native import verify_macos_target_acceptance  # noqa: E402
from hawk_endpoint_agent.attestation import validate_macos_release_evidence_v2  # noqa: E402


def _read(path: str, maximum: int) -> bytes:
    value = Path(path).read_bytes()
    if not 0 < len(value) <= maximum:
        raise ValueError("target acceptance input size is invalid")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    for name in ("payload", "detached-signature", "public-key", "key-id",
                 "tenant-id", "device-id", "policy-digest", "component-set-digest",
                 "team-id", "os-build", "build-evidence", "notarization-evidence", "output"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--policy-epoch", type=int, required=True)
    args = parser.parse_args()
    payload = json.loads(_read(args.payload, 16 * 1024))
    envelope = {
        "key_id": args.key_id,
        "algorithm": "Ed25519",
        "payload": payload,
        "signature": base64.b64encode(_read(args.detached_signature, 64)).decode("ascii"),
    }
    release = validate_macos_release_evidence_v2(
        json.loads(_read(args.build_evidence, 16 * 1024)),
        json.loads(_read(args.notarization_evidence, 16 * 1024)),
    )
    if (release["component_set_digest"] != args.component_set_digest or
            release["team_id"] != args.team_id):
        raise ValueError("target acceptance differs from v2 release evidence")
    verify_macos_target_acceptance(
        envelope, trusted_public_keys={args.key_id: _read(args.public_key, 32)},
        tenant_id=args.tenant_id, device_id=args.device_id,
        policy_digest=args.policy_digest, policy_epoch=args.policy_epoch,
        component_set_digest=args.component_set_digest, team_id=args.team_id,
        os_build=args.os_build,
    )
    output = Path(args.output)
    if not output.is_absolute() or output.parts[:2] in {
        ("/", "Library"), ("/", "Applications"),
    }:
        raise ValueError("output must be an absolute non-installation staging path")
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    print(json.dumps({"output_path": str(output),
                      "sha256": hashlib.sha256(encoded).hexdigest()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
