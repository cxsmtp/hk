#!/usr/bin/env python3
"""Explicit local development monitor preparation; dry-run by default.

Run with the existing endpoint interpreter and -I -B. A reviewed, relocated
release must already be staged by the operator. No bank enrollment is reused,
no hardware key is created, and no trust or enable switch is changed.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import urllib.request
import uuid

API = "http://127.0.0.1:8002"
TENANT = "4b06af68-d0a7-4856-a998-5615639cedb5"
BASE = "ac81ace3bb1a9b2f1db0c3abc30510c2d3edc7b5"
OVERLAY = "c60396758af868a48c66723092db4a4072a76951d569f5e82f80a741ef7fc820"
HELPER_SHA256 = "20fb31ecab7dfc625fecf70b1bdf77e05bf108031068a7644105ddfb788b7730"
MANAGED_MARKER = "--hawk-managed-hook"
CODEX_EVENTS = frozenset({"SessionStart", "SessionEnd", "PreToolUse", "PermissionRequest", "PostToolUse",
    "PreCompact", "PostCompact", "UserPromptSubmit", "SubagentStart", "SubagentStop", "Stop", "Interrupt"})


class Blocked(RuntimeError):
    """Only fixed operator reason codes may reach public output."""


def fail(code):
    raise Blocked(code)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def owned(path, *, directory=False, private=False, executable=False):
    try:
        info = path.lstat()
        if path.is_symlink() or path.resolve() != path.absolute() or info.st_uid != os.getuid():
            fail("file_integrity_invalid")
        if not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            fail("file_integrity_invalid")
        mode = stat.S_IMODE(info.st_mode)
        if mode & 0o022 or (private and mode != (0o700 if directory else 0o600)):
            fail("file_integrity_invalid")
        if executable and not os.access(path, os.X_OK):
            fail("file_integrity_invalid")
    except OSError:
        fail("file_integrity_invalid")


def private_directory(path, *, private=True):
    if path.is_symlink():
        fail("file_integrity_invalid")
    if not path.exists():
        # Refuse symlink ancestors before creating an owned state directory.
        if path.resolve() != path.absolute():
            fail("file_integrity_invalid")
        path.mkdir(parents=True, mode=0o700)
    owned(path, directory=True, private=private)


def import_rollout(path):
    spec = importlib.util.spec_from_file_location("verified_local_codex_rollout", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_release(root, manifest_sha256):
    """The caller's reviewed hash is authority, never the mutable manifest alone."""
    try:
        root = Path(root).expanduser().absolute()
        owned(root, directory=True)
        manifest_path = root / "release-manifest.json"
        owned(manifest_path)
        if not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) or sha(manifest_path) != manifest_sha256:
            fail("release_integrity_invalid")
        manifest = json.loads(manifest_path.read_text())
        if (manifest.get("format_version") != 1 or manifest.get("base_sha") != BASE
                or manifest.get("source_overlay_sha256") != OVERLAY
                or manifest.get("classification") != "local_test_candidate"
                or manifest.get("production_eligible") is not False or manifest.get("release_ready") is not False):
            fail("release_integrity_invalid")
        mapping = manifest.get("files")
        if not isinstance(mapping, dict) or not mapping:
            fail("release_integrity_invalid")
        for relative, digest in mapping.items():
            path = Path(relative)
            if path.is_absolute() or ".." in path.parts or not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
                fail("release_integrity_invalid")
        actual = {}
        for path in root.rglob("*"):
            owned(path, directory=path.is_dir())
            if path.is_file() and path != manifest_path:
                actual[str(path.relative_to(root))] = sha(path)
        if actual != mapping:
            fail("release_integrity_invalid")
    except (OSError, ValueError, TypeError, Blocked):
        fail("release_integrity_invalid")
    # Import only after every staged byte and path is authenticated by the pin.
    rollout = import_rollout(root / "repo/infra/scripts/enable_latest_native_controls.py")
    runtime = rollout.validate_codex_runtime(root / "codex-runtime")
    site = runtime.site.resolve()
    for name, module in list(sys.modules.items()):
        if name == "hawk_endpoint_agent" or name.startswith("hawk_endpoint_agent."):
            file = getattr(module, "__file__", None)
            if not file or not Path(file).resolve().is_relative_to(site):
                fail("runtime_import_invalid")
    sys.path.insert(0, str(site))
    # AdminClient must use this site's vault, never a dirty checkout fallback.
    from hawk_endpoint_agent.auth import MemoryTokenVault
    from hawk_endpoint_agent.native_control.installer import NativeHookInstaller
    from hawk_endpoint_agent.auth.device_key import public_key_thumbprint
    del MemoryTokenVault
    return rollout, runtime, NativeHookInstaller, public_key_thumbprint


def validate_helper(helper):
    try:
        owned(helper, executable=True)
        if sha(helper) != HELPER_SHA256:
            fail("helper_integrity_invalid")
    except (OSError, Blocked):
        fail("helper_integrity_invalid")


def prove_hardware_key(helper, key_tag):
    """Status + randomized signing proof. Never ensure, destroy, or export a key."""
    try:
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,200}", key_tag):
            fail("hardware_proof_invalid")
        result = subprocess.run([str(helper), "status", key_tag], capture_output=True, timeout=45, check=False)
        status = json.loads(result.stdout) if result.returncode == 0 else {}
        if not all(status.get(key) is True for key in ("ok", "exists", "hardware_backed", "sealed_reference")):
            fail("hardware_proof_invalid")
        if status.get("provider") != "macos_secure_enclave":
            fail("hardware_proof_invalid")
        public_pem = status.get("public_key_pem")
        if not isinstance(public_pem, str) or not 100 <= len(public_pem) <= 2048:
            fail("hardware_proof_invalid")
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        public = serialization.load_pem_public_key(public_pem.encode())
        if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(public.curve, ec.SECP256R1):
            fail("hardware_proof_invalid")
        challenge = b"hawk-codex-local-development-key-proof-v1:" + secrets.token_bytes(32)
        signed = subprocess.run([str(helper), "sign", key_tag], input=challenge,
                                capture_output=True, timeout=45, check=False)
        proof = json.loads(signed.stdout) if signed.returncode == 0 else {}
        if proof.get("ok") is not True or not isinstance(proof.get("signature"), str):
            fail("hardware_proof_invalid")
        encoded = proof["signature"]
        signature = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        public.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        return public_pem
    except Exception:
        fail("hardware_proof_invalid")


def file_paths(home):
    state = home / ".hawk/native-control"
    return {"bank": state / "codex.json", "hooks": home / ".codex/hooks.json",
            "codex_toml": home / ".codex/config.toml", "local": state / "codex-local-test.json",
            "rollout": state / "codex-local-test.rollout.json", "identity": state / "codex-local-test.identity.json",
            "record": state / "codex-local-test.operator.json"}


def snapshots(paths):
    result = {}
    for token, path in paths.items():
        if path.is_symlink():
            fail("file_integrity_invalid")
        if not path.exists():
            result[token] = {"absent": True}
        else:
            owned(path, private=True)
            result[token] = {"sha256": sha(path), "mode": 0o600}
    return result


def http_json(url):
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.status, json.load(response)


def validate_health(status, ready, health_status, health):
    if (status != 200 or ready.get("ready") is not True or health_status != 200
            or health.get("strict_schema") is not True or health.get("schema_healthy") is not True):
        fail("strict_ready_invalid")


def validate_catalog(adapter):
    if (adapter.get("maturity") != "experimental" or adapter.get("production_eligible") is not False
            or adapter.get("adapter_version") != "1.0.0"
            or adapter.get("provider_version_range") != {"minimum": "0.154.0", "maximum": "0.154.0",
                 "exact_verified_versions": [], "compatible_versions_require_signed_runtime_validation": False}):
        # The compatibility key is optional in older clean catalog projections.
        version = adapter.get("provider_version_range", {})
        if not (adapter.get("maturity") == "experimental" and adapter.get("production_eligible") is False
                and adapter.get("adapter_version") == "1.0.0" and version.get("minimum") == "0.154.0"
                and version.get("maximum") == "0.154.0" and version.get("exact_verified_versions") == []
                and version.get("compatible_versions_require_signed_runtime_validation", False) is False):
            fail("catalog_invalid")


def preflight(args):
    if args.api_url != API:
        fail("origin_invalid")
    rollout, runtime, installer_type, thumbprint = load_release(args.release_root, args.manifest_sha256)
    validate_helper(runtime.identity)
    ready_status, ready = http_json(API + "/health/ready")
    health_status, health = http_json(API + "/health")
    validate_health(ready_status, ready, health_status, health)
    installed = rollout._command_version("codex")
    if installed.version != "0.154.0" or not installed.installed or installed.integrity != "verified":
        fail("codex_version_invalid")
    paths = file_paths(Path.home())
    before = snapshots(paths)
    if any(not before[token].get("absent") for token in ("local", "rollout", "identity", "record")):
        fail("local_state_already_exists")
    bank = json.loads(paths["bank"].read_text())
    if (bank.get("key_provider") != "macos_secure_enclave" or bank.get("security_profile") != "bank"
            or bank.get("tenant_id") != TENANT or bank.get("api_url") != API):
        fail("bank_binding_invalid")
    key_tag = bank.get("secure_enclave_key_tag")
    public_key = prove_hardware_key(runtime.identity, key_tag)
    login_path = Path(args.login_file).expanduser().absolute()
    owned(login_path, private=True)
    saved = json.loads(login_path.read_text())
    client = rollout.AdminClient(API)
    try:
        tenant = client.login(saved["email"], saved["password"])
        saved.clear()
        if tenant != TENANT:
            fail("authenticated_tenant_invalid")
        validate_catalog(client.request("GET", "/native-controls/adapters/openai.codex.native-hooks"))
        if not rollout.codex_backend_accepts_version(client, "0.154.0"):
            fail("catalog_invalid")
        listed = client.request("GET", "/control-points").get("items")
        if not isinstance(listed, list):
            fail("control_point_inventory_invalid")
        existing_ids = {str(row.get("id")) for row in listed if isinstance(row, dict)}
        if bank.get("integration_id") not in existing_ids:
            fail("bank_binding_invalid")
        bank_row = next(row for row in listed if row.get("id") == bank["integration_id"])
        if not (bank_row.get("provider") == "openai" and bank_row.get("product") == "codex"
                and bank_row.get("provider_version") == "0.154.0" and bank_row.get("adapter_version") == "1.0.0"):
            fail("bank_binding_invalid")
        if any(isinstance(row, dict) and row.get("provider") == "openai" and row.get("product") == "codex"
               and row.get("provider_version") == "0.154.0" and row.get("adapter_version") == "1.0.0"
               and row.get("id") != bank["integration_id"] for row in listed):
            fail("unowned_matching_control_point")
        installer = installer_type(provider="codex", helper_path=runtime.helper, runtime_config_path=paths["local"])
        current = json.loads(paths["hooks"].read_text()) if paths["hooks"].exists() else {}
        merge_hooks(current, installer._desired(current))  # Validate the merge without writes.
        if snapshots(paths) != before:
            fail("protected_files_changed")
        return SimpleNamespace(paths=paths, snapshots=before, bank=bank, runtime=runtime,
                               installer=installer, client=client, public_key=public_key,
                               thumbprint=thumbprint(public_key), existing_ids=existing_ids,
                               release_hash=args.manifest_sha256,
                               allowed_events=list(rollout._NATIVE_DETAILS["codex"]["events"]))
    except BaseException:
        saved.clear()
        client.close()
        raise


def managed(row):
    if not isinstance(row, dict):
        return False
    if MANAGED_MARKER in str(row.get("command") or ""):
        return True
    return any(isinstance(hook, dict) and MANAGED_MARKER in str(hook.get("command") or "")
               for hook in row.get("hooks") or [])


def merge_hooks(current, desired):
    """Replace Hawk command definitions only; keep user trust/disabled metadata."""
    result = json.loads(json.dumps(current))
    hooks = result.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        fail("hook_merge_invalid")
    for event, replacements in desired.get("hooks", {}).items():
        if event not in CODEX_EVENTS:
            if replacements != hooks.get(event):
                fail("hook_merge_invalid")
            continue
        incoming = [row for row in replacements if managed(row)]
        previous = hooks.get(event, [])
        if not isinstance(previous, list) or len(incoming) != 1:
            fail("hook_merge_invalid")
        old = [row for row in previous if managed(row)]
        if len(old) > 1:
            fail("hook_merge_invalid")
        new = json.loads(json.dumps(incoming[0]))
        if old:
            # Preserve every old metadata field, changing only the command.
            retained = json.loads(json.dumps(old[0]))
            if len(retained.get("hooks", [])) != len(new.get("hooks", [])):
                fail("hook_merge_invalid")
            for handler, replacement in zip(retained["hooks"], new["hooks"]):
                handler["command"] = replacement["command"]
            new = retained
        hooks[event] = [new] + [row for row in previous if not managed(row)]
    return result


def atomic_bytes(path, data):
    if path.is_symlink():
        fail("file_integrity_invalid")
    fd, temporary = tempfile.mkstemp(prefix=".codex-local-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, sort_keys=True, indent=2) + "\n").encode())


def report(status, *, mutated=False, integration_id=None, credential_id=None, expires_at=None):
    result = {"status": status, "classification": "development_monitor_only", "experimental": True,
            "enforced": False, "production_eligible": False, "release_ready": False,
            "mutations_performed": mutated, "integration_id": integration_id, "credential_id": credential_id,
            "hardware_key_created": False, "trust_changed": False, "model_called": False,
            "callback_executed": False, "activation_not_performed": True,
            "user_reported_hooks_disabled": True}
    if expires_at is not None:
        result["expires_at"] = expires_at
    return result


def validate_new_detail(detail, identifier):
    if (detail.get("id") != identifier or detail.get("environment") != "development"
            or detail.get("state") != "configuring" or detail.get("mode") != "discover"
            or detail.get("degradation_mode") != "monitor_only" or detail.get("authoritative") is not False
            or detail.get("real_acceptance_current") is not False or detail.get("callback_authenticated") is not False):
        fail("new_resource_posture_invalid")


def execute(prepared, *, apply=False):
    if not apply:
        return report("preflight_ready_requires_explicit_apply")
    p = prepared
    if snapshots(p.paths) != p.snapshots:
        fail("protected_files_changed")
    private_directory(p.paths["local"].parent)
    private_directory(p.paths["hooks"].parent, private=False)
    backup_root = p.paths["local"].parent / ("codex-local-test-backup-" + uuid.uuid4().hex)
    private_directory(backup_root)
    touched = ("hooks", "local", "rollout", "identity")
    backups = {}
    for token in touched:
        if not p.snapshots[token].get("absent"):
            source = p.paths[token]
            backup = backup_root / token
            atomic_bytes(backup, source.read_bytes())
            backups[token] = backup
    record = {"status": "preparing", "release_manifest_sha256": p.release_hash,
              "before": p.snapshots, "backup_hashes": {k: sha(v) for k, v in backups.items()},
              "backup_directory": backup_root.name, "integration_id": None, "credential_id": None}
    atomic_json(p.paths["record"], record)
    integration = None
    integration_attempted = False
    credential = None
    written = {}
    try:
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(days=1)).isoformat()
        record["expires_at"] = expires_at
        atomic_json(p.paths["record"], record)
        integration_attempted = True
        created = p.client.request("POST", "/native-controls/integrations", {
            "provider": "openai", "product": "codex", "model_provider": "openai", "model": "unknown",
            "method": "native_hook", "instance_key": "codex-local-test-" + uuid.uuid4().hex,
            "display_name": "Codex 0.154 — explicit local development monitor", "environment": "development",
            "deployment_family": "endpoint", "provider_version": "0.154.0", "adapter_version": "1.0.0",
            "policy_version": "local-development-monitor-v1", "policy_fresh_until": expires_at,
            "degradation_mode": "monitor_only", "trusted_workload_authority": False})
        identifier = created.get("id")
        if not isinstance(identifier, str) or not identifier or identifier in p.existing_ids:
            fail("new_resource_identity_invalid")
        integration = identifier
        record["integration_id"] = integration
        atomic_json(p.paths["record"], record)
        validate_new_detail(p.client.request("GET", "/control-points/" + integration), integration)
        credential_id = "codex-local-test-" + str(uuid.uuid4())
        if credential_id == p.bank.get("credential_id"):
            fail("new_resource_identity_invalid")
        epoch = int(now.timestamp())
        # Persist the attempted new ID before the request so uncertain responses
        # can only target that new development resource during cleanup.
        credential = credential_id
        record.update(credential_id=credential, credential_epoch=epoch)
        atomic_json(p.paths["record"], record)
        response = p.client.request("POST", "/native-controls/integrations/" + integration + "/credentials", {
            "credential_id": credential, "credential_epoch": epoch, "public_key_pem": p.public_key,
            "environment": "development", "allowed_event_types": p.allowed_events,
            "expires_at": expires_at})
        if (response.get("credential_id") != credential or response.get("credential_epoch") != epoch
                or response.get("status") != "active" or response.get("key_thumbprint") != p.thumbprint
                or response.get("signature_algorithm") != "ES256"):
            fail("new_credential_binding_invalid")
        config = {"api_url": API, "tenant_id": TENANT, "integration_id": integration,
                  "credential_id": credential, "credential_epoch": epoch, "provider": "openai", "product": "codex",
                  "provider_version": "0.154.0", "adapter_version": "1.0.0", "environment": "development",
                  "key_provider": "macos_secure_enclave", "security_profile": "development",
                  "secure_enclave_helper_path": str(p.runtime.identity),
                  "secure_enclave_key_tag": p.bank["secure_enclave_key_tag"]}
        current = json.loads(p.paths["hooks"].read_text()) if p.paths["hooks"].exists() else {}
        merged = merge_hooks(current, p.installer._desired(current))
        values = {"local": config, "rollout": {"integration_id": integration, "credential_id": credential,
            "status": "configuring", "mode": "discover", "degradation_mode": "monitor_only",
            "experimental": True, "production_eligible": False, "release_ready": False, "expires_at": expires_at},
            "identity": {"provider": "macos_secure_enclave", "existing_hardware_key_proven": True,
                         "public_key_thumbprint": p.thumbprint, "helper_sha256": HELPER_SHA256}, "hooks": merged}
        if snapshots(p.paths) != {**p.snapshots, "record": snapshots(p.paths)["record"]}:
            fail("protected_files_changed")
        for token, value in values.items():
            written[token] = hashlib.sha256((json.dumps(value, sort_keys=True, indent=2) + "\n").encode()).hexdigest()
            atomic_json(p.paths[token], value)
        validate_new_detail(p.client.request("GET", "/control-points/" + integration), integration)
        for token in ("bank", "codex_toml"):
            if snapshots(p.paths)[token] != p.snapshots[token]:
                fail("protected_files_changed")
        for token, value in values.items():
            owned(p.paths[token], private=True)
            if json.loads(p.paths[token].read_text()) != value:
                fail("written_projection_invalid")
        record.update(status="installed_activation_not_performed_pending_human_review", written_sha256=written)
        atomic_json(p.paths["record"], record)
        return report(record["status"], mutated=True, integration_id=integration, credential_id=credential,
                      expires_at=expires_at)
    except Exception:
        restored = True
        # Restore only bytes this invocation wrote; refuse concurrent human drift.
        for token, digest in written.items():
            try:
                if snapshots(p.paths)[token] == p.snapshots[token]:
                    continue
                owned(p.paths[token], private=True)
                if sha(p.paths[token]) != digest:
                    fail("rollback_drift")
                if token in backups:
                    if sha(backups[token]) != record["backup_hashes"][token]:
                        fail("rollback_backup_invalid")
                    atomic_bytes(p.paths[token], backups[token].read_bytes())
                else:
                    p.paths[token].unlink()
            except Exception:
                restored = False
        cleaned = not integration_attempted
        if integration:
            try:
                validate_new_detail(p.client.request("GET", "/control-points/" + integration), integration)
                if credential:
                    revoked = p.client.request("POST", "/native-controls/integrations/" + integration
                        + "/credentials/" + credential + "/revoke", {"reason": "owned_local_development_pretrust_rollback"})
                    if revoked.get("status") != "revoked":
                        fail("remote_cleanup_invalid")
                disabled = p.client.request("POST", "/native-controls/integrations/" + integration + "/disable")
                if disabled.get("state") != "disabled":
                    fail("remote_cleanup_invalid")
                cleaned = True
            except Exception:
                cleaned = False
        status = "rolled_back" if restored and cleaned else "remote_cleanup_required" if restored else "file_cleanup_required"
        record.update(status=status, written_sha256=written, files_restored=restored, remote_cleanup_complete=cleaned)
        atomic_json(p.paths["record"], record)
        return report(status, mutated=True, integration_id=integration, credential_id=credential)


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--release-root", type=Path, required=True)
    result.add_argument("--manifest-sha256", required=True)
    result.add_argument("--api-url", default=API)
    result.add_argument("--login-file", type=Path, default=Path.home() / "Library/Application Support/Hawk/LocalRuntime/manual-test-login.json")
    result.add_argument("--apply", action="store_true", help="Requires separately approved local trust reduction; default is dry-run.")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        print(json.dumps(report("blocked_requires_isolated_no_bytecode")))
        return 1
    prepared = None
    try:
        prepared = preflight(args)
        result = execute(prepared, apply=args.apply)
    except Exception as exc:
        # Never echo API/helper exceptions or configuration content.
        safe = {"origin_invalid", "release_integrity_invalid", "runtime_import_invalid", "helper_integrity_invalid",
                "hardware_proof_invalid", "file_integrity_invalid", "strict_ready_invalid", "codex_version_invalid",
                "catalog_invalid", "authenticated_tenant_invalid", "control_point_inventory_invalid", "bank_binding_invalid",
                "local_state_already_exists", "hook_merge_invalid", "protected_files_changed", "unowned_matching_control_point"}
        code = str(exc) if isinstance(exc, Blocked) and str(exc) in safe else "operator_preflight_or_transaction_failed"
        result = report("blocked_" + code)
    finally:
        if prepared is not None:
            prepared.client.close()
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] in {"preflight_ready_requires_explicit_apply", "installed_activation_not_performed_pending_human_review"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
