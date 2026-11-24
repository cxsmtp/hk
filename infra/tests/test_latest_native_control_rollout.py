from __future__ import annotations

import importlib.util
from contextlib import contextmanager
import json
import hashlib
import subprocess
import sys
import os
import pytest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infra" / "scripts" / "enable_latest_native_controls.py"


def load_rollout_module():
    spec = importlib.util.spec_from_file_location("enable_latest_native_controls", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rollout_plan_keeps_native_control_and_discovery_truth_separate() -> None:
    module = load_rollout_module()

    plan = module.build_rollout_plan(
        {
            "claude_code": module.InstalledProvider("2.1.183", True, "verified"),
            "gemini_cli": module.InstalledProvider("0.55.1", True, "verified"),
            "codex": module.InstalledProvider("0.154.0", True, "verified"),
            "cursor": module.InstalledProvider("3.17.19", True, "invalid_signature"),
            "chatgpt_desktop": module.InstalledProvider("26.715.72359", True, "verified"),
        }
    )

    assert plan["claude_code"].action == "install_native_monitor"
    assert plan["claude_code"].production_eligible is True
    assert plan["gemini_cli"].action == "install_native_monitor"
    assert plan["gemini_cli"].production_eligible is False
    assert plan["codex"].action == "install_native_monitor"
    assert plan["codex"].requires_user_trust is True
    assert plan["cursor"].action == "discovery_only"
    assert plan["cursor"].reason == "invalid_signature"
    assert plan["chatgpt_desktop"].action == "composite_discovery"
    assert plan["chatgpt_desktop"].native_hook_available is False


def test_rollout_rejects_unreviewed_versions_instead_of_silently_installing() -> None:
    module = load_rollout_module()

    plan = module.build_rollout_plan(
        {
            "claude_code": module.InstalledProvider("2.1.184", True, "verified"),
            "gemini_cli": module.InstalledProvider("0.55.2", True, "verified"),
            "codex": module.InstalledProvider("0.153.0", True, "verified"),
        }
    )

    assert plan["claude_code"].action == "discovery_only"
    assert plan["gemini_cli"].action == "discovery_only"
    assert plan["codex"].action == "discovery_only"


def test_production_env_update_enables_catalog_and_monitor_without_global_enforce() -> None:
    module = load_rollout_module()

    updated = module.update_env_text(
        "ENV=production\nNATIVE_CONTROL_GOOGLE=false\nNATIVE_CONTROL_ENFORCE=true\n",
        module.PRODUCTION_FEATURE_FLAGS,
    )

    assert "NATIVE_CONTROL_FRAMEWORK=true\n" in updated
    assert "NATIVE_CONTROL_ADAPTER_FRAMEWORK=true\n" in updated
    assert "NATIVE_CONTROL_ADAPTER_ENFORCEMENT=true\n" in updated
    assert "NATIVE_CONTROL_MONITOR=true\n" in updated
    assert "NATIVE_CONTROL_ENFORCE=false\n" in updated
    assert "NATIVE_CONTROL_ANTHROPIC=true\n" in updated
    assert "NATIVE_CONTROL_GOOGLE=true\n" in updated
    assert "NATIVE_CONTROL_OPENAI=true\n" in updated
    assert "NATIVE_CONTROL_CURSOR=true\n" in updated


def test_route_bindings_are_additive_and_exclude_non_native_chatgpt() -> None:
    module = load_rollout_module()
    existing = '{"tenant-a":{"runtime_control":{"provider":"existing","integration_instance_ids":["old"]}}}'

    encoded = module.add_route_bindings(
        existing,
        tenant_id="tenant-a",
        integrations={
            "claude_code": "claude-id",
            "gemini_cli": "gemini-id",
            "codex": "codex-id",
        },
    )
    bindings = module.json.loads(encoded)["tenant-a"]["runtime_control"]

    assert {row["provider"] for row in bindings} == {
        "existing",
        "anthropic",
        "google",
        "openai",
    }
    assert all(row.get("product") != "chatgpt_desktop" for row in bindings)


def test_rollout_script_is_secretless_and_uses_production_stack() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert ".env.production" in script
    assert "hawk_production_stack.sh" in script
    assert "getpass.getpass" in script
    assert "MemoryTokenVault" in script
    assert "macos_secure_enclave" in script
    assert "access_token" not in script[script.index("def write_state"):script.index("def install_hooks")]
    assert "refresh_token" not in script[script.index("def write_state"):script.index("def install_hooks")]
    assert "rm -rf" not in script
    assert "--dangerously-bypass-hook-trust" not in script


def test_admin_client_uses_the_in_memory_vault_without_corrupting_bearer_header(monkeypatch) -> None:
    module = load_rollout_module()
    captured = {}

    class Vault:
        @contextmanager
        def use(self):
            value = bytearray(b"short-lived-owner-token")
            try:
                yield value
            finally:
                value[:] = b"\x00" * len(value)

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return json.dumps({"ok": True}).encode()

    def fake_urlopen(request, **_kwargs):
        captured["authorization"] = request.headers["Authorization"]
        return Response()

    monkeypatch.setattr(module.urllib.request, "urlopen", fake_urlopen)
    client = module.AdminClient.__new__(module.AdminClient)
    client.base_url = "http://127.0.0.1:8000"
    client.vault = Vault()
    client.tenant_id = "tenant-1"

    assert client.request("GET", "/control-points") == {"ok": True}
    assert captured["authorization"] == "Bearer short-lived-owner-token"


def test_existing_integration_match_uses_fields_exposed_by_control_point_api() -> None:
    module = load_rollout_module()
    rows = [
        {
            "id": "integration-1",
            "display_name": "Codex 0.154.0 — governed monitor",
            "provider": "openai",
            "product": "codex",
            "provider_version": "0.154.0",
            "adapter_version": "1.0.0",
        }
    ]

    matched = module.find_existing_integration(
        rows,
        provider="openai",
        product="codex",
        provider_version="0.154.0",
        adapter_version="1.0.0",
        display_name="Codex 0.154.0 — governed monitor",
    )

    assert matched["id"] == "integration-1"


def test_deploy_stack_builds_then_starts_the_production_stack(monkeypatch) -> None:
    module = load_rollout_module()
    commands = []

    class Result:
        returncode = 0

    def fake_run(command, **_kwargs):
        commands.append(command)
        return Result()

    monkeypatch.setattr(module.subprocess, "run", fake_run)

    module.deploy_stack()

    assert commands == [
        [str(module.PRODUCTION_STACK), "build"],
        [str(module.PRODUCTION_STACK), "up"],
    ]


def test_start_stack_only_recreates_for_changed_runtime_configuration(monkeypatch) -> None:
    module = load_rollout_module()
    commands = []

    class Result:
        returncode = 0

    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command) or Result(),
    )

    module.start_stack()

    assert commands == [[str(module.PRODUCTION_STACK), "up"]]


def test_codex_only_preflight_rejects_old_live_backend_version() -> None:
    module = load_rollout_module()

    class Client:
        def request(self, method, path):
            assert method == "GET"
            assert path == "/native-controls/adapters/openai.codex.native-hooks"
            return {
                "adapter_id": "openai.codex.native-hooks",
                "adapter_version": "1.0.0",
                "event_schema_version": "codex-hooks/0.148.0",
                "provider_version_range": {"minimum": "0.148.0", "maximum": "0.148.0"},
            }

    assert module.codex_backend_accepts_version(Client(), "0.154.0") is False


def test_codex_only_enrollment_preflights_then_uses_only_codex_runtime(monkeypatch, tmp_path) -> None:
    module = load_rollout_module()
    calls = []

    class Client:
        def login(self, _email, _password):
            calls.append("login")
            return "tenant-current"

        def request(self, method, path):
            calls.append("preflight")
            return {
                "adapter_id": "openai.codex.native-hooks",
                "adapter_version": "1.0.0",
                "event_schema_version": "codex-hooks/0.154.0",
                "provider_version_range": {"minimum": "0.154.0", "maximum": "0.154.0"},
            }

        def close(self):
            calls.append("close")

    for name in ("ENDPOINT_PYTHON", "NATIVE_HELPER", "IDENTITY_HELPER"):
        path = tmp_path / name
        path.write_text("available", encoding="utf-8")
        monkeypatch.setattr(module, name, path)
    monkeypatch.setattr(module, "AdminClient", lambda _base_url: Client())
    monkeypatch.setattr("builtins.input", lambda _prompt: "owner@example.test")
    monkeypatch.setattr(module.getpass, "getpass", lambda _prompt: "password")

    def register(client, base_url, tenant_id, installed, decision, *, runtime):
        calls.append("register")
        assert tenant_id == "tenant-current"
        assert installed.version == "0.154.0"
        assert decision.action == "install_native_monitor"
        return {"status": "installed_monitor_pending_live_callback_and_user_trust"}

    monkeypatch.setattr(module, "enroll_native_controls_after_preflight", register)
    for name in ("apply_feature_flags", "deploy_stack", "start_stack"):
        monkeypatch.setattr(module, name, lambda: (_ for _ in ()).throw(AssertionError(name)))

    root = _candidate_runtime(module, tmp_path, monkeypatch)
    result = module.enroll_codex_only(
        "http://127.0.0.1:8000",
        module.InstalledProvider("0.154.0", True, "verified"),
        runtime_root=root,
    )

    assert calls == ["login", "preflight", "register", "close"]
    assert result["status"] == "installed_monitor_pending_live_callback_and_user_trust"


def _candidate_runtime(module, tmp_path, monkeypatch):
    root = tmp_path / "codex-runtime"
    site = root / "site"
    (root / "bin").mkdir(parents=True, mode=0o700)
    site.mkdir(mode=0o700)
    root.chmod(0o700)
    relative_names = (
        "hawk_endpoint_agent/__init__.py", "hawk_endpoint_agent/native_control/__init__.py",
        "hawk_endpoint_agent/native_control/hook.py", "hawk_endpoint_agent/native_control/cli.py",
        "hawk_endpoint_agent/native_control/installer.py", "hawk_endpoint_agent/auth/__init__.py",
        "hawk_endpoint_agent/auth/device_key.py",
    )
    fixture_hashes = {}
    for relative in relative_names:
        destination = site / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = f"# Synthetic standalone fixture: {relative}\n".encode()
        destination.write_bytes(content)
        fixture_hashes[relative] = hashlib.sha256(content).hexdigest()
    monkeypatch.setattr(module, "CODEX_SITE_SHA256", fixture_hashes)
    python, identity = tmp_path / "python", tmp_path / "identity"
    for path in (python, identity):
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o500)
    monkeypatch.setattr(module, "ENDPOINT_PYTHON", python)
    monkeypatch.setattr(module, "IDENTITY_HELPER", identity)
    monkeypatch.setattr(module, "IDENTITY_HELPER_SHA256", hashlib.sha256(identity.read_bytes()).hexdigest())
    helper = root / "bin/hawk-native-hook"
    helper.write_text(module.codex_runtime_wrapper(root, python))
    cli = root / "bin/hawk-native-control"
    cli.write_text(module.codex_runtime_wrapper(root, python, "cli"))
    cli.chmod(0o700)
    (root / "bootstrap.py").write_text(module.codex_runtime_bootstrap())
    helper.chmod(0o700)
    (root / "release-manifest.json").write_text('{"status":"clean_monitor_candidate"}')
    monkeypatch.setattr(module, "validate_identity_helper_signature", lambda helper: helper)
    return root


@pytest.mark.parametrize("defect", ["symlink", "mode", "source_hash", "wrapper", "identity_hash", "interpreter_mode", "missing", "extra", "dependent", "bootstrap", "cli_wrapper"])
def test_codex_candidate_integrity_rejects_before_login_or_key_creation(monkeypatch, tmp_path, defect):
    module = load_rollout_module()
    root = _candidate_runtime(module, tmp_path, monkeypatch)
    if defect == "symlink":
        link = tmp_path / "candidate-link"
        link.symlink_to(root, target_is_directory=True)
        root = link
    elif defect == "mode":
        root.chmod(0o777)
    elif defect == "source_hash":
        (root / "site/hawk_endpoint_agent/native_control/hook.py").write_text("changed")
    elif defect == "wrapper":
        (root / "bin/hawk-native-hook").write_text("#!/bin/sh\nexit 0\n")
    elif defect == "identity_hash":
        module.IDENTITY_HELPER.chmod(0o700)
        module.IDENTITY_HELPER.write_text("changed")
    elif defect == "interpreter_mode":
        module.ENDPOINT_PYTHON.chmod(0o777)
    elif defect == "missing":
        (root / "site/hawk_endpoint_agent/native_control/cli.py").unlink()
    elif defect == "extra":
        (root / "site/extra.py").write_text("unexpected")
    elif defect == "dependent":
        relative = next(name for name in module.CODEX_SITE_SHA256 if name.endswith("device_key.py"))
        (root / "site" / relative).write_text("changed")
    elif defect == "bootstrap":
        (root / "bootstrap.py").write_text("changed")
    else:
        (root / "bin/hawk-native-control").write_text("changed")
    monkeypatch.setattr(module, "AdminClient", lambda *_args: (_ for _ in ()).throw(AssertionError("login must not start")))
    with pytest.raises(RuntimeError, match="codex_runtime_"):
        module.enroll_codex_only("http://127.0.0.1:8000", module.InstalledProvider("0.154.0", True, "verified"), runtime_root=root)


def test_codex_candidate_uses_explicit_immutable_paths_and_clean_site_first(monkeypatch, tmp_path):
    module = load_rollout_module()
    root = _candidate_runtime(module, tmp_path, monkeypatch)
    runtime = module.validate_codex_runtime(root)
    monkeypatch.setenv("PYTHONPATH", "/dirty/shared/runtime")
    commands = []
    def run(command, **kwargs):
        commands.append((command, kwargs))
        return type("Result", (), {"returncode": 0, "stdout": "{}"})()
    monkeypatch.setattr(module.subprocess, "run", run)
    enrollment = {"integration_id":"synthetic", "credential_id":"synthetic", "credential_epoch":1, "provider_version":"0.154.0", "adapter_version":"1.0.0", "key_tag":"synthetic"}
    module.install_hooks("codex", enrollment, api_url="http://127.0.0.1:8000", tenant_id="synthetic", runtime=runtime)
    command, options = commands[0]
    assert command[0] == str(runtime.cli)
    assert command[command.index("--helper") + 1] == str(runtime.helper)
    assert "PYTHONPATH" not in options["env"]
    assert options["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    with pytest.raises(AttributeError):
        runtime.site = tmp_path
    calls = []
    class Client:
        def login(self, *_args):
            calls.append("login")
            return "tenant"
        def close(self):
            pass
    monkeypatch.setattr(module, "AdminClient", lambda *_args: Client())
    monkeypatch.setattr("builtins.input", lambda *_args: "synthetic@example.test")
    monkeypatch.setattr(module.getpass, "getpass", lambda *_args: "synthetic")
    monkeypatch.setattr(module, "codex_backend_accepts_version", lambda *_args: True)
    def register(*args, **kwargs):
        assert kwargs["runtime"] == runtime
        calls.append("register")
        return {"status":"candidate"}
    monkeypatch.setattr(module, "enroll_native_controls_after_preflight", register)
    module.enroll_codex_only("http://127.0.0.1:8000", module.InstalledProvider("0.154.0", True, "verified"), runtime_root=root)
    assert calls == ["login", "register"]


def test_explicit_codex_runtime_is_rejected_for_broad_apply(monkeypatch, tmp_path):
    module = load_rollout_module()
    monkeypatch.setattr(module.sys, "argv", ["rollout", "--apply", "--codex-runtime-root", str(tmp_path)])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2


def test_codex_missing_runtime_root_rejects_before_login_or_identity(monkeypatch):
    module = load_rollout_module()
    monkeypatch.setattr(module, "AdminClient", lambda *_args: (_ for _ in ()).throw(AssertionError("must not log in")))
    with pytest.raises(RuntimeError, match="codex_runtime_root_required"):
        module.enroll_codex_only("http://127.0.0.1:8000", module.InstalledProvider("0.154.0", True, "verified"))
    monkeypatch.setattr(module.sys, "argv", ["rollout", "--codex-only"])
    with pytest.raises(SystemExit) as exc:
        module.main()
    assert exc.value.code == 2


def test_isolated_bootstrap_ignores_cwd_pythonpath_and_user_site_without_import_fallback(monkeypatch, tmp_path):
    module = load_rollout_module()
    endpoint_interpreter = Path(sys.executable).resolve(strict=True)
    root = _candidate_runtime(module, tmp_path, monkeypatch)
    shadow = tmp_path / "shadow"
    (shadow / "hawk_endpoint_agent").mkdir(parents=True)
    (shadow / "hawk_endpoint_agent/__init__.py").write_text("raise RuntimeError('cwd-shadow-imported')")
    bootstrap = root / "bootstrap.py"
    environment = dict(os.environ)
    environment.update({"PYTHONPATH": str(shadow), "PYTHONUSERBASE": str(shadow), "PYTHONHOME": str(shadow)})
    result = subprocess.run([str(endpoint_interpreter), "-I", "-B", str(bootstrap), "smoke"], cwd=shadow, env=environment, capture_output=True, text=True, check=True)
    assert result.stdout.strip() == "candidate_isolated_imports_confined"
    assert not list((root / "site").rglob("__pycache__"))
    assert " -I -B " in module.codex_runtime_wrapper(root, module.ENDPOINT_PYTHON)
    assert ' hook "$@"' in module.codex_runtime_wrapper(root, module.ENDPOINT_PYTHON)
    assert ' cli "$@"' in module.codex_runtime_wrapper(root, module.ENDPOINT_PYTHON, "cli")


def test_codex_signature_rejected_before_login_or_registration(monkeypatch,tmp_path):
    module=load_rollout_module();root=_candidate_runtime(module,tmp_path,monkeypatch)
    def rejected(path):raise RuntimeError('identity_helper_unsigned')
    monkeypatch.setattr(module,'validate_identity_helper_signature',rejected,raising=False)
    monkeypatch.setattr(module,'AdminClient',lambda *a:pytest.fail('login constructed before signature check'))
    with pytest.raises(RuntimeError,match='identity_helper_unsigned'):
        module.enroll_codex_only('http://127.0.0.1:8002',module.InstalledProvider('0.154.0',True,'verified'),runtime_root=root)


def test_optional_unsigned_flag_is_only_a_distinct_future_development_plan():
    module=load_rollout_module();plan=module.local_unsigned_helper_plan()
    assert plan['install'] is False and plan['requires_explicit_future_approval'] is True
    assert plan['distinct_development_integration_credential_config_required'] is True
    assert plan['approved_registration_operator_required'] is True
    assert plan['production_eligible'] is False and plan['release_ready'] is False


@pytest.mark.parametrize('defect',['adhoc','invalid_signature','hash','symlink'])
def test_pinned_identity_signature_preflight_rejects_defects(monkeypatch,tmp_path,defect):
    module=load_rollout_module();helper=tmp_path/'identity';helper.write_bytes(b'identity');helper.chmod(0o700)
    monkeypatch.setattr(module,'IDENTITY_HELPER_SHA256',hashlib.sha256(helper.read_bytes()).hexdigest())
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command,1 if defect=='invalid_signature' else 0,'','Signature=adhoc\nTeamIdentifier=not set' if defect=='adhoc' else 'TeamIdentifier=ABCDEFGHIJ')
    monkeypatch.setattr(module.subprocess,'run',run)
    if defect=='hash':helper.write_bytes(b'changed')
    if defect=='symlink':link=tmp_path/'link';link.symlink_to(helper);helper=link
    with pytest.raises(RuntimeError,match='identity_helper_(unsigned|integrity_invalid)'):
        module.validate_identity_helper_signature(helper)
    assert all(command[0]=='/usr/bin/codesign' for command in calls)


def test_noninstall_unsigned_plan_does_not_detect_login_or_mutate(monkeypatch,capsys):
    module=load_rollout_module();monkeypatch.setattr(module.sys,'argv',['rollout','--local-test-unsigned-helper'])
    for name in ('detect_installed','AdminClient','apply_feature_flags','enroll_native_controls'):
        monkeypatch.setattr(module,name,lambda *a,**k:pytest.fail('preparation attempted side effect'))
    assert module.main()==0
    assert json.loads(capsys.readouterr().out)['install'] is False


def test_candidate_runtime_fixture_has_no_machine_release_dependency(monkeypatch,tmp_path):
    module=load_rollout_module()
    monkeypatch.setattr(Path,'home',lambda:tmp_path/'absent-home')
    root=_candidate_runtime(module,tmp_path,monkeypatch)
    assert module.validate_codex_runtime(root).root==root
    assert len(module.CODEX_SITE_SHA256)==7
