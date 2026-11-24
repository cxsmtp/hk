"""Offline tests: no real API, hardware key, hooks, or installed release."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/enable_codex_local_test.py"


def test_operator_exists():
    assert SCRIPT.is_file(), "the separate default-dry-run operator is missing"


@pytest.fixture
def op():
    spec = importlib.util.spec_from_file_location("local_test_operator", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(json.dumps(value))
    path.chmod(0o600)
    return path


@pytest.fixture
def prepared(op, tmp_path):
    paths = op.file_paths(tmp_path)
    bank = {"key_provider": "macos_secure_enclave", "security_profile": "bank",
            "secure_enclave_key_tag": "private.existing.tag", "tenant_id": op.TENANT,
            "integration_id": "bank-id", "credential_id": "bank-credential"}
    private(paths["bank"], bank)
    private(paths["hooks"], {"disableAllHooks": True, "trust": {"unchanged": True},
                            "hooks": {"PreToolUse": [{"hooks": [{"command": "user hook", "disabled": True}]}]}})
    paths["codex_toml"].write_text('[hooks]\nenabled = false\n')
    paths["codex_toml"].chmod(0o600)

    class Installer:
        def _desired(self, current):
            result = json.loads(json.dumps(current))
            result["hooks"]["PreToolUse"] = [{"hooks": [{"command": "durable --hawk-managed-hook --config local"}]}]
            return result

    class Client:
        def __init__(self):
            self.calls = []
            self.fail_credential = False
            self.fail_cleanup = False

        def request(self, method, path, body=None):
            self.calls.append((method, path, body))
            if path == "/native-controls/integrations":
                return {"id": "new-integration"}
            if path.endswith("/credentials"):
                if self.fail_credential:
                    raise RuntimeError("hostile password private.existing.tag")
                return {"credential_id": body["credential_id"], "credential_epoch": body["credential_epoch"],
                        "key_thumbprint": "proof-thumb", "status": "active", "signature_algorithm": "ES256"}
            if path.endswith("/revoke"):
                if self.fail_cleanup:
                    raise RuntimeError("private raw response")
                return {"status": "revoked"}
            if path.endswith("/disable"):
                if self.fail_cleanup:
                    raise RuntimeError("private raw response")
                return {"state": "disabled"}
            return {"id": "new-integration", "environment": "development", "state": "configuring",
                    "mode": "discover", "degradation_mode": "monitor_only", "authoritative": False,
                    "real_acceptance_current": False, "callback_authenticated": False}

    return SimpleNamespace(paths=paths, bank=bank, snapshots=op.snapshots(paths),
                           runtime=SimpleNamespace(helper=tmp_path / "durable/hook", identity=tmp_path / "identity"),
                           installer=Installer(), client=Client(), public_key="PRIVATE PUBLIC KEY",
                           thumbprint="proof-thumb", existing_ids={"bank-id"}, release_hash="a" * 64,
                           allowed_events=["before_tool", "after_tool"])


def test_dry_run_zero_file_or_resource_mutations(op, prepared):
    before = op.snapshots(prepared.paths)
    report = op.execute(prepared, apply=False)
    assert report["mutations_performed"] is False
    assert op.snapshots(prepared.paths) == before
    assert prepared.client.calls == []


def test_apply_distinct_development_resources_and_disabled_hooks_preserved(op, prepared):
    before_bank = prepared.paths["bank"].read_bytes()
    before_toml = prepared.paths["codex_toml"].read_bytes()
    report = op.execute(prepared, apply=True)
    posts = [c for c in prepared.client.calls if c[0] == "POST"]
    assert [p[1] for p in posts] == ["/native-controls/integrations", "/native-controls/integrations/new-integration/credentials"]
    assert posts[0][2]["environment"] == posts[1][2]["environment"] == "development"
    assert posts[0][2]["trusted_workload_authority"] is False
    assert posts[0][2]["degradation_mode"] == "monitor_only"
    assert posts[1][2]["public_key_pem"] == prepared.public_key
    config = json.loads(prepared.paths["local"].read_text())
    assert config["security_profile"] == "development"
    assert config["key_provider"] == "macos_secure_enclave"
    assert config["credential_id"] != prepared.bank["credential_id"]
    hooks = json.loads(prepared.paths["hooks"].read_text())
    assert hooks["disableAllHooks"] is True and hooks["trust"] == {"unchanged": True}
    assert hooks["hooks"]["PreToolUse"][1]["hooks"][0]["command"] == "user hook"
    assert prepared.paths["bank"].read_bytes() == before_bank
    assert prepared.paths["codex_toml"].read_bytes() == before_toml
    assert report["enforced"] is False and report["production_eligible"] is False
    for token in ("local", "rollout", "identity", "record", "hooks"):
        assert prepared.paths[token].stat().st_mode & 0o777 == 0o600
    assert prepared.paths["local"].parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("failure", ["credential", "file"])
def test_failure_restores_files_and_only_cleans_new_resources(op, prepared, monkeypatch, failure):
    before = op.snapshots(prepared.paths)
    if failure == "credential":
        prepared.client.fail_credential = True
    else:
        original = op.atomic_json
        def fail(path, value):
            if path == prepared.paths["identity"]:
                raise RuntimeError("raw secret")
            return original(path, value)
        monkeypatch.setattr(op, "atomic_json", fail)
    report = op.execute(prepared, apply=True)
    assert report["status"] == "rolled_back"
    for token in ("bank", "hooks", "local", "rollout", "identity", "codex_toml"):
        assert op.snapshots(prepared.paths)[token] == before[token]
    mutations = [c for c in prepared.client.calls if c[0] == "POST"]
    assert all("bank-id" not in c[1] and "bank-credential" not in c[1] for c in mutations)
    assert any(c[1].endswith("/disable") for c in mutations)
    assert not any(c[1].endswith("/monitor") or c[1].endswith("/enforce") for c in mutations)


def test_failed_remote_cleanup_is_reported_and_no_bank_mutation(op, prepared):
    prepared.client.fail_credential = prepared.client.fail_cleanup = True
    report = op.execute(prepared, apply=True)
    assert report["status"] == "remote_cleanup_required"
    assert report["enforced"] is False
    assert "private" not in json.dumps(report)


def test_merge_preserves_managed_disabled_and_trust_metadata(op):
    old = {"disableAllHooks": True, "hooks": {"PreToolUse": [
        {"enabled": False, "trust": "denied", "hooks": [{"command": "old --hawk-managed-hook", "disabled": True}]},
        {"hooks": [{"command": "unrelated"}]}]}}
    new = {"hooks": {"PreToolUse": [{"hooks": [{"command": "new --hawk-managed-hook"}]}]}}
    merged = op.merge_hooks(old, new)
    managed = merged["hooks"]["PreToolUse"][0]
    assert managed["enabled"] is False and managed["trust"] == "denied"
    assert managed["hooks"][0]["disabled"] is True
    assert merged["hooks"]["PreToolUse"][1] == old["hooks"]["PreToolUse"][1]
    assert merged["disableAllHooks"] is True


@pytest.mark.parametrize("origin", ["https://127.0.0.1:8002", "http://localhost:8002", "http://127.0.0.1:8000", "http://127.0.0.1:8002/", "http://127.0.0.1:8002@evil"])
def test_origin_rejected_before_any_other_work(op, origin, monkeypatch):
    monkeypatch.setattr(op, "load_release", lambda *a: pytest.fail("release must not be read"))
    with pytest.raises(op.Blocked, match="origin_invalid"):
        op.preflight(SimpleNamespace(api_url=origin))


@pytest.mark.parametrize("status,ready,health", [(503, {"ready": True}, {}), (200, {"ready": False}, {}),
    (200, {"ready": True}, {"strict_schema": False, "schema_healthy": True})])
def test_not_strict_ready_rejected(op, status, ready, health):
    with pytest.raises(op.Blocked, match="strict_ready_invalid"):
        op.validate_health(status, ready, 200, health)


@pytest.mark.parametrize("field,value", [("maturity", "production"), ("production_eligible", True),
    ("adapter_version", "other"), ("provider_version_range", {"minimum": "0.154.0", "maximum": "*", "exact_verified_versions": []})])
def test_catalog_authority_or_version_rejected(op, field, value):
    adapter = {"maturity": "experimental", "production_eligible": False, "adapter_version": "1.0.0",
               "provider_version_range": {"minimum": "0.154.0", "maximum": "0.154.0", "exact_verified_versions": []}}
    adapter[field] = value
    with pytest.raises(op.Blocked, match="catalog_invalid"):
        op.validate_catalog(adapter)


@pytest.mark.parametrize("mutation", ["hash", "extra", "symlink", "mode"])
def test_release_integrity_rejected_before_import(op, tmp_path, monkeypatch, mutation):
    root = tmp_path / "release"
    root.mkdir(mode=0o700)
    file = root / "safe.py"
    file.write_text("safe = True\n")
    file.chmod(0o600)
    manifest = {"format_version": 1, "base_sha": op.BASE, "source_overlay_sha256": op.OVERLAY,
                "classification": "local_test_candidate", "production_eligible": False, "release_ready": False,
                "files": {"safe.py": op.sha(file)}}
    private(root / "release-manifest.json", manifest)
    pin = op.sha(root / "release-manifest.json")
    if mutation == "hash": file.write_text("unsafe=True")
    if mutation == "extra": (root / "extra.py").write_text("unsafe")
    if mutation == "symlink": file.unlink(); file.symlink_to(root / "release-manifest.json")
    if mutation == "mode": file.chmod(0o666)
    monkeypatch.setattr(op, "import_rollout", lambda *a: pytest.fail("unverified code import"))
    with pytest.raises(op.Blocked, match="release_integrity_invalid"):
        op.load_release(root, pin)


def test_helper_hash_failure_never_invokes_key(op, tmp_path, monkeypatch):
    helper = tmp_path / "helper"
    helper.write_text("not pinned")
    helper.chmod(0o700)
    monkeypatch.setattr(op.subprocess, "run", lambda *a, **k: pytest.fail("key operation"))
    with pytest.raises(op.Blocked, match="helper_integrity_invalid"):
        op.validate_helper(helper)


@pytest.mark.parametrize("bad", ["missing", "software", "bad_signature"])
def test_hardware_proof_fail_closed_without_ensure(op, monkeypatch, bad):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    calls = []
    def run(command, **kwargs):
        calls.append(command[1])
        if command[1] == "status":
            result = {"ok": True, "exists": bad != "missing", "provider": "macos_secure_enclave",
                      "hardware_backed": bad != "software", "sealed_reference": True, "public_key_pem": pem}
        else:
            result = {"ok": True, "signature": base64.urlsafe_b64encode(b"invalid").decode()}
        return SimpleNamespace(returncode=0, stdout=json.dumps(result).encode())
    monkeypatch.setattr(op.subprocess, "run", run)
    with pytest.raises(op.Blocked, match="hardware_proof_invalid"):
        op.prove_hardware_key(Path("helper"), "private.tag")
    assert set(calls) <= {"status", "sign"}


@pytest.mark.parametrize("provider,profile", [("ephemeral", "development"), ("kms_hsm_helper", "development"), ("macos_secure_enclave", "production")])
def test_parser_has_no_provider_profile_or_bank_id_override(op, provider, profile):
    with pytest.raises(SystemExit):
        op.parser().parse_args(["--key-provider", provider, "--security-profile", profile])
    with pytest.raises(SystemExit):
        op.parser().parse_args(["--integration-id", "bank-id"])


def test_report_never_serializes_exception_or_key_material(op, prepared):
    prepared.client.fail_credential = True
    result = json.dumps(op.execute(prepared, apply=True))
    for private_value in (prepared.public_key, prepared.bank["secure_enclave_key_tag"], "password", str(prepared.paths["bank"])):
        assert private_value not in result


def test_existing_hardware_key_proof_verifies_signature_and_only_status_sign(op, monkeypatch):
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization, hashes
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    calls = []
    def run(command, **kwargs):
        calls.append(command[1])
        if command[1] == "status":
            result = {"ok": True, "exists": True, "provider": "macos_secure_enclave", "hardware_backed": True,
                      "sealed_reference": True, "public_key_pem": pem}
        else:
            result = {"ok": True, "signature": base64.urlsafe_b64encode(key.sign(kwargs["input"], ec.ECDSA(hashes.SHA256()))).decode()}
        return SimpleNamespace(returncode=0, stdout=json.dumps(result).encode())
    monkeypatch.setattr(op.subprocess, "run", run)
    assert op.prove_hardware_key(Path("helper"), "private.tag") == pem
    assert calls == ["status", "sign"]


@pytest.mark.parametrize("failure", ["ready", "catalog", "tenant", "hardware", "unowned"])
def test_preflight_failure_never_resource_mutates(op, tmp_path, monkeypatch, failure):
    paths = op.file_paths(tmp_path)
    private(paths["bank"], {"api_url": op.API, "tenant_id": op.TENANT, "integration_id": "bank-id",
                           "key_provider": "macos_secure_enclave", "security_profile": "bank", "secure_enclave_key_tag": "private.tag"})
    login = private(tmp_path / "login.json", {"email": "private", "password": "secret"})
    monkeypatch.setattr(op.Path, "home", lambda: tmp_path)
    calls = []
    class Client:
        def login(self, *args):
            return "wrong-tenant" if failure == "tenant" else op.TENANT
        def request(self, method, path, body=None):
            assert method == "GET"
            calls.append((method, path))
            if "adapters" in path:
                return {"maturity": "production" if failure == "catalog" else "experimental", "production_eligible": False,
                        "adapter_version": "1.0.0", "provider_version_range": {"minimum": "0.154.0", "maximum": "0.154.0", "exact_verified_versions": []}}
            rows = [{"id": "bank-id", "provider": "openai", "product": "codex", "provider_version": "0.154.0", "adapter_version": "1.0.0"}]
            if failure == "unowned": rows.append({**rows[0], "id": "unowned"})
            return {"items": rows}
        def close(self): pass
    rollout = SimpleNamespace(AdminClient=lambda api: Client(), _command_version=lambda name:
                              SimpleNamespace(version="0.154.0", installed=True, integrity="verified"),
                              codex_backend_accepts_version=lambda *args: True)
    monkeypatch.setattr(op, "load_release", lambda *args: (rollout, SimpleNamespace(identity=tmp_path / "helper"), None, None))
    monkeypatch.setattr(op, "validate_helper", lambda *args: None)
    monkeypatch.setattr(op, "http_json", lambda url: (200, {"ready": failure != "ready", "strict_schema": True, "schema_healthy": True}))
    def proof(*args):
        if failure == "hardware": op.fail("hardware_proof_invalid")
        return "private public"
    monkeypatch.setattr(op, "prove_hardware_key", proof)
    before = op.snapshots(paths)
    with pytest.raises(op.Blocked):
        op.preflight(SimpleNamespace(api_url=op.API, release_root=tmp_path, manifest_sha256="a" * 64, login_file=login))
    assert op.snapshots(paths) == before
    assert all(method == "GET" for method, _ in calls)


def test_manifest_hash_is_external_authority_not_mutable_manifest(op, tmp_path, monkeypatch):
    root = tmp_path / "release"
    root.mkdir(mode=0o700)
    private(root / "release-manifest.json", {"files": {}, "classification": "local_test_candidate"})
    monkeypatch.setattr(op, "import_rollout", lambda *args: pytest.fail("must not import"))
    with pytest.raises(op.Blocked, match="release_integrity_invalid"):
        op.load_release(root, "0" * 64)


def test_preexisting_symlink_or_writable_private_file_blocks(op, prepared):
    prepared.paths["hooks"].chmod(0o644)
    with pytest.raises(op.Blocked, match="file_integrity_invalid"):
        op.execute(prepared, apply=True)
    assert prepared.client.calls == []


def test_bank_id_returned_by_create_is_never_reused_or_revoked(op, prepared):
    original = prepared.client.request
    def response(method, path, body=None):
        if path == "/native-controls/integrations": return {"id": "bank-id"}
        return original(method, path, body)
    prepared.client.request = response
    result = op.execute(prepared, apply=True)
    assert result["status"] == "remote_cleanup_required"
    assert not any("bank-id" in path for _, path, _ in prepared.client.calls)


def test_real_installer_merge_moves_all_codex_commands_preserving_metadata(op, tmp_path):
    source = Path(__file__).parents[2] / "apps/endpoint-agent/src/hawk_endpoint_agent/native_control/installer.py"
    spec = importlib.util.spec_from_file_location("real_codex_installer", source)
    installer_module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = installer_module
    spec.loader.exec_module(installer_module)
    old_helper, new_helper = tmp_path / "old-helper", tmp_path / "durable/helper"
    new_helper.parent.mkdir()
    for helper in (old_helper, new_helper):
        helper.write_text("#!/bin/sh\n")
        helper.chmod(0o700)
    old = installer_module.NativeHookInstaller(provider="codex", helper_path=old_helper,
        runtime_config_path=tmp_path / "bank.json")
    new = installer_module.NativeHookInstaller(provider="codex", helper_path=new_helper,
        runtime_config_path=tmp_path / "codex-local-test.json")
    current = old._desired({"disableAllHooks": True, "trust": {"app": "unchanged"}})
    for event, rows in current["hooks"].items():
        rows[0].update(enabled=False, trust="denied", arbitrary_metadata={"keep": True})
        rows[0]["hooks"][0].update(disabled=True, trusted=False)
        rows.append({"custom": event, "hooks": [{"command": "user command", "disabled": True}]})
    current["hooks"]["UnrelatedEvent"] = [{"hooks": [{"command": "untouched"}], "trusted": False}]
    result = op.merge_hooks(current, new._desired(current))
    assert result["disableAllHooks"] is True and result["trust"] == current["trust"]
    assert len(result["hooks"]) == len(installer_module._EVENTS["codex"]) + 1
    assert result["hooks"]["UnrelatedEvent"] == current["hooks"]["UnrelatedEvent"]
    for event, rows in result["hooks"].items():
        if event == "UnrelatedEvent":
            continue
        managed = [row for row in rows if installer_module._managed(row)]
        assert len(managed) == 1
        command = managed[0]["hooks"][0]["command"]
        assert str(new_helper) in command and str(tmp_path / "codex-local-test.json") in command
        assert str(old_helper) not in command and "bank.json" not in command
        for key in ("enabled", "trust", "arbitrary_metadata"):
            assert managed[0][key] == current["hooks"][event][0][key]
        assert managed[0]["hooks"][0]["disabled"] is True
        assert managed[0]["hooks"][0]["trusted"] is False
        assert rows[1] == current["hooks"][event][1]


@pytest.mark.parametrize("rows", [[], [{"hooks": [{"command": "helper --hawk-native-control"}]}],
    [{"hooks": [{"command": "helper --hawk-managed-hook"}]}, {"hooks": [{"command": "helper --hawk-managed-hook"}]}]])
def test_merge_rejects_zero_wrong_or_multiple_managed_incoming(op, rows):
    with pytest.raises(op.Blocked, match="hook_merge_invalid"):
        op.merge_hooks({}, {"hooks": {"PreToolUse": rows}})


def test_owned_existing_codex_0755_accepted_without_chmod(op, prepared):
    prepared.paths["hooks"].parent.chmod(0o755)
    result = op.execute(prepared, apply=True)
    assert result["status"] == "installed_activation_not_performed_pending_human_review"
    assert prepared.paths["hooks"].parent.stat().st_mode & 0o777 == 0o755
    assert prepared.paths["local"].parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize("kind", ["codex_group_write", "codex_symlink", "hawk_not_private"])
def test_directory_integrity_blocks_before_api_mutation(op, prepared, tmp_path, kind):
    if kind == "codex_group_write":
        prepared.paths["hooks"].parent.chmod(0o775)
    elif kind == "codex_symlink":
        directory = prepared.paths["hooks"].parent
        target = tmp_path / "redirect"
        directory.rename(target)
        directory.symlink_to(target, target_is_directory=True)
    else:
        prepared.paths["local"].parent.chmod(0o755)
    with pytest.raises(op.Blocked, match="file_integrity_invalid"):
        op.execute(prepared, apply=True)
    assert prepared.client.calls == []


def test_one_day_expiry_identical_requests_records_report(op, prepared):
    start = datetime.now(timezone.utc)
    result = op.execute(prepared, apply=True)
    end = datetime.now(timezone.utc)
    posts = [call for call in prepared.client.calls if call[0] == "POST"]
    expiry = posts[0][2]["policy_fresh_until"]
    assert posts[1][2]["expires_at"] == expiry
    assert json.loads(prepared.paths["rollout"].read_text())["expires_at"] == expiry
    assert json.loads(prepared.paths["record"].read_text())["expires_at"] == expiry
    assert result["expires_at"] == expiry
    expires = datetime.fromisoformat(expiry)
    assert start + timedelta(days=1) <= expires <= end + timedelta(days=1)
