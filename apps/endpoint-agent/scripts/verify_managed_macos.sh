#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHONPATH="$SCRIPT_DIR/../src${PYTHONPATH:+:$PYTHONPATH}" python3 - "$@" <<'PY'
import argparse
import base64
import hashlib
import json
import os
import pathlib
import plistlib
import subprocess
import sys
import tempfile

from hawk_endpoint_agent.auth.device_key import build_device_key_provider
from hawk_endpoint_agent.attestation import validate_macos_release_evidence_v2
from hawk_endpoint_agent.config import load_config
from hawk_endpoint_agent.endpoint_floor.runtime import load_signed_runtime_floor_posture
from hawk_endpoint_agent.macos_native import MacOSNativeFloorManager
from hawk_endpoint_agent.macos_release import verify_macos_package

parser = argparse.ArgumentParser()
parser.add_argument("--package")
parser.add_argument("--app", default="/Applications/Hawk Endpoint.app")
parser.add_argument("--policy", default="/Library/Application Support/Hawk/EndpointAgent/endpoint-floor-policy.bin")
parser.add_argument("--config", default="/Library/Managed Preferences/ai.hawk.endpoint.host.plist")
parser.add_argument("--agent-config")
parser.add_argument("--build-evidence")
parser.add_argument("--notarization-evidence")
arguments = parser.parse_args()
reasons = []

def check(command, timeout=12):
    result = subprocess.run(command, capture_output=True, check=False, timeout=timeout)
    if result.returncode:
        raise ValueError("command failed")
    return (result.stdout + result.stderr).decode("utf-8", errors="replace")

if sys.platform != "darwin":
    reasons.append("unsupported_os")
if not arguments.package or not pathlib.Path(arguments.package).is_file():
    reasons.append("missing_package")

agent_config = None
if not arguments.agent_config or not pathlib.Path(arguments.agent_config).is_file():
    reasons.append("missing_agent_config")
else:
    try:
        agent_config = load_config(pathlib.Path(arguments.agent_config))
        metadata = pathlib.Path(arguments.agent_config).stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("agent config is not protected")
    except (OSError, ValueError):
        reasons.append("agent_config_invalid")

release = None
if not arguments.build_evidence or not arguments.notarization_evidence:
    reasons.append("missing_v2_release_evidence")
else:
    try:
        release = validate_macos_release_evidence_v2(
            json.loads(pathlib.Path(arguments.build_evidence).read_text(encoding="utf-8")),
            json.loads(pathlib.Path(arguments.notarization_evidence).read_text(encoding="utf-8")),
        )
        notarization = json.loads(pathlib.Path(arguments.notarization_evidence).read_text(encoding="utf-8"))
        if (not arguments.package or
                hashlib.sha256(pathlib.Path(arguments.package).read_bytes()).hexdigest() !=
                    notarization["stapled_package_sha256"]):
            raise ValueError("notarized package bytes differ")
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        release = None
        reasons.append("v2_release_evidence_invalid")

manager = MacOSNativeFloorManager(
    policy_path=arguments.policy, config_path=arguments.config,
    host_app_path=arguments.app,
    acceptance_path=(agent_config.macos_target_acceptance_path if agent_config else None),
    acceptance_public_keys=({name: base64.b64decode(value, validate=True)
        for name, value in agent_config.macos_target_acceptance_public_keys.items()}
        if agent_config else None),
    tenant_id=(agent_config.tenant_id if agent_config else None),
    device_id=(agent_config.endpoint_id if agent_config else None),
)
native_status = None
if sys.platform == "darwin":
    try:
        native_status = manager.read_status()
        if release is None or not arguments.package or not native_status.accepted_artifact_sha256:
            raise ValueError("package and signed target acceptance are required")
        # read_status already recomputed the installed signed component digest
        # and bound it to the verified target acceptance before setting this field.
        verify_macos_package(
            pathlib.Path(arguments.package),
            json.loads(pathlib.Path(arguments.build_evidence).read_text(encoding="utf-8")),
            notarization,
            installed_component_digest=native_status.accepted_artifact_sha256,
            accepted_component_digest=native_status.accepted_artifact_sha256,
        )
        if not native_status.policy_current or not native_status.policy_signed:
            reasons.append("native_policy_not_current")
        if not native_status.healthy:
            reasons.append("native_controls_unhealthy")
        if release is None or native_status.accepted_artifact_sha256 != release["component_set_digest"]:
            reasons.append("target_acceptance_release_binding_unverified")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        reasons.append("native_status_or_packaged_release_unverified")

display = "Needs attention"
if agent_config is not None and native_status is not None and release is not None:
    try:
        provider = build_device_key_provider(
            provider_name=agent_config.key_provider,
            security_profile=agent_config.security_profile,
            helper_path=agent_config.identity_helper_path,
            helper_sha256=agent_config.identity_helper_sha256,
            key_tag=agent_config.device_key_tag,
        )
        identity = provider.status()
        if not identity.available or not identity.hardware_backed or not identity.signed_helper:
            raise ValueError("hardware identity unavailable")
        receipt = load_signed_runtime_floor_posture(
            os_type="darwin", receipt_path=agent_config.endpoint_floor_receipt_path,
            trusted_public_keys=agent_config.endpoint_floor_receipt_public_keys,
            expected_tenant_id=agent_config.tenant_id,
            expected_device_id=agent_config.endpoint_id,
        )
        if receipt["display_state"] == "Needs attention":
            raise ValueError("receipt does not prove controls")
        if manager.posture()["display_state"] != receipt["display_state"]:
            raise ValueError("native health and receipt disagree")
        display = receipt["display_state"]
    except (OSError, ValueError, RuntimeError):
        reasons.append("signed_runtime_receipt_unverified")

if reasons:
    display = "Needs attention"
print(json.dumps({
    "schema": "hawk.macos-managed-verification", "version": 1,
    "display_state": display, "reason_codes": sorted(set(reasons)),
}, sort_keys=True))
PY
