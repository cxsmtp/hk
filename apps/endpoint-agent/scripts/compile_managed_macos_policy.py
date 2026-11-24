#!/usr/bin/env python3
"""Stage verified macOS policy bytes for existing external signing authorities."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import plistlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from hawk_endpoint_agent.config import load_config  # noqa: E402
from hawk_endpoint_agent.macos_policy_compiler import (  # noqa: E402
    assemble_native_envelope, binding_signing_bytes, build_managed_config,
    render_native_payload, render_routing_signing_bytes, verify_managed_routing_authority,
)


def _read(path: str, maximum: int) -> bytes:
    value = Path(path).read_bytes()
    if not 0 < len(value) <= maximum:
        raise ValueError("staging input size is invalid")
    return value


def _json(path: str, maximum: int) -> dict:
    value = json.loads(_read(path, maximum))
    if not isinstance(value, dict):
        raise ValueError("staging JSON root must be an object")
    return value


def _stage(path: str, data: bytes) -> None:
    target = Path(path)
    if not target.is_absolute() or target.parts[:2] in {
        ("/", "Library"), ("/", "Applications"),
    }:
        raise ValueError("output must be an absolute non-installation staging path")
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _report(stage: str, path: str, data: bytes, **fields: object) -> None:
    print(json.dumps({"stage": stage, "output_path": path,
                      "sha256": hashlib.sha256(data).hexdigest(), **fields},
                     sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="stage", required=True)
    binding = commands.add_parser("binding-signing-bytes")
    binding.add_argument("--bindings", required=True)
    binding.add_argument("--output", required=True)
    render = commands.add_parser("render")
    render.add_argument("--source-envelope", required=True)
    render.add_argument("--binding-envelope", required=True)
    render.add_argument("--agent-config", required=True)
    render.add_argument("--minimum-delivery-sequence", type=int, required=True)
    render.add_argument("--minimum-policy-epoch", type=int, required=True)
    render.add_argument("--output", required=True)
    assembly = commands.add_parser("assemble")
    assembly.add_argument("--payload", required=True)
    assembly.add_argument("--detached-signature", required=True)
    assembly.add_argument("--public-key-x963", required=True)
    assembly.add_argument("--output", required=True)
    managed = commands.add_parser("managed-config")
    managed.add_argument("--envelope", required=True)
    managed.add_argument("--public-key-x963", required=True)
    managed.add_argument("--team-id", required=True)
    managed.add_argument("--output", required=True)
    routing = commands.add_parser("routing-signing-bytes")
    routing.add_argument("--destination-suffixes", required=True)
    routing.add_argument("--output", required=True)
    routing.add_argument("--envelope", required=True)
    routing.add_argument("--public-key-x963", required=True)
    for command in (routing, managed):
        command.add_argument("--source-envelope", required=True)
        command.add_argument("--binding-envelope", required=True)
        command.add_argument("--agent-config", required=True)
    managed.add_argument("--routing-envelope", required=True)
    managed.add_argument("--broker-public-key-x963", required=True)
    managed.add_argument("--broker-key-authorization", required=True)
    managed.add_argument("--broker-key-authorization-signature", required=True)
    managed.add_argument("--routing-trust-root-public-key-x963", required=True)
    args = parser.parse_args()
    if args.stage == "binding-signing-bytes":
        body = binding_signing_bytes(_json(args.bindings, 256 * 1024))
        _stage(args.output, body)
        _report(args.stage, args.output, body)
    elif args.stage == "render":
        config = load_config(Path(args.agent_config))
        keys = {name: base64.b64decode(value, validate=True)
                for name, value in config.endpoint_floor_policy_public_keys.items()}
        body = render_native_payload(
            source_envelope=_json(args.source_envelope, 2 * 1024 * 1024),
            binding_envelope=_json(args.binding_envelope, 256 * 1024),
            trusted_public_keys=keys, expected_tenant_id=config.tenant_id,
            expected_device_id=config.endpoint_id,
            minimum_delivery_sequence=args.minimum_delivery_sequence,
            minimum_policy_epoch=args.minimum_policy_epoch,
        )
        _stage(args.output, body)
        header = struct.unpack_from("<IIQQQQIIIIII", body)
        _report(args.stage, args.output, body, policy_epoch=header[3],
                delivery_sequence=header[2], issued_at_unix_seconds=header[4],
                expires_at_unix_seconds=header[5], rule_count=header[6],
                governed_identity_count=header[8], mode="enforce" if header[11] == 2 else "monitor")
    elif args.stage == "assemble":
        body = assemble_native_envelope(
            _read(args.payload, 2 * 1024 * 1024),
            _read(args.detached_signature, 80), _read(args.public_key_x963, 65),
        )
        _stage(args.output, body)
        _report(args.stage, args.output, body)
    elif args.stage == "routing-signing-bytes":
        config = load_config(Path(args.agent_config))
        body = render_routing_signing_bytes(
            source_envelope=_json(args.source_envelope, 2 * 1024 * 1024),
            binding_envelope=_json(args.binding_envelope, 256 * 1024),
            native_envelope=_read(args.envelope, 2 * 1024 * 1024),
            public_key_x963=_read(args.public_key_x963, 65),
            trusted_public_keys={name: base64.b64decode(value, validate=True)
                for name, value in config.endpoint_floor_policy_public_keys.items()},
            expected_tenant_id=config.tenant_id, expected_device_id=config.endpoint_id,
            destination_host_suffixes=json.loads(_read(args.destination_suffixes, 128 * 1024)),
            minimum_delivery_sequence=0, minimum_policy_epoch=0,
        )
        _stage(args.output, body)
        _report(args.stage, args.output, body)
    else:
        value = build_managed_config(
            _read(args.envelope, 2 * 1024 * 1024),
            _read(args.public_key_x963, 65), args.team_id,
        )
        config = load_config(Path(args.agent_config))
        value.update({
            "HawkSourcePolicyEnvelopeJSON": _read(args.source_envelope, 2 * 1024 * 1024),
            "HawkNativeBindingEnvelopeJSON": _read(args.binding_envelope, 256 * 1024),
            "HawkRoutingScopeEnvelopeJSON": _read(args.routing_envelope, 256 * 1024),
            "HawkRoutingReceiptPublicKeyX963": _read(args.broker_public_key_x963, 65),
            "HawkRoutingBrokerKeyAuthorization": _read(args.broker_key_authorization, 84),
            "HawkRoutingBrokerKeyAuthorizationSignatureDER": _read(args.broker_key_authorization_signature, 80),
            "HawkRoutingTrustRootPublicKeyX963": _read(args.routing_trust_root_public_key_x963, 65),
        })
        scope = verify_managed_routing_authority(value,
            trusted_public_keys={name: base64.b64decode(key, validate=True)
                for name, key in config.endpoint_floor_policy_public_keys.items()},
            tenant_id=config.tenant_id, device_id=config.endpoint_id)
        from hawk_endpoint_agent.macos_routing import _verify_broker_key_authorization
        import time
        _verify_broker_key_authorization(
            authorization=value["HawkRoutingBrokerKeyAuthorization"],
            signature_der=value["HawkRoutingBrokerKeyAuthorizationSignatureDER"],
            trust_root_public_key_x963=value["HawkRoutingTrustRootPublicKeyX963"],
            broker_public_key_x963=value["HawkRoutingReceiptPublicKeyX963"],
            now_unix_seconds=int(time.time()))
        body = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=True)
        if len(body) > 2_200_000:
            raise ValueError("managed configuration is oversized")
        _stage(args.output, body)
        _report(args.stage, args.output, body, policy_epoch=value["HawkPolicyEpoch"],
                policy_version=value["HawkPolicyVersion"], mode=value["HawkPolicyMode"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
