from pathlib import Path
from types import SimpleNamespace

import pytest

from hawk_endpoint_agent.native_control import cli, installer
from hawk_endpoint_agent.native_control.cli import _parser, _settings_target


def test_native_control_cli_installs_without_storing_access_tokens() -> None:
    source = Path("src/hawk_endpoint_agent/native_control/cli.py").read_text(encoding="utf-8")
    assert '"install", "uninstall"' in source
    assert "public_key_pem" in source
    assert "access_token" not in source
    assert "runtime_config_removed\": False" in source


@pytest.mark.parametrize("platform, expected", [
    ('darwin', '/Library/Application Support/ClaudeCode/managed-settings.json'),
    ('linux', '/etc/claude-code/managed-settings.json'),
    ('win32', 'C:\\Program Files\\ClaudeCode\\managed-settings.json'),
])
def test_claude_cli_exposes_user_project_local_project_and_managed_enrollment_scopes(tmp_path: Path, monkeypatch, platform: str, expected: str) -> None:
    monkeypatch.setattr(installer, "sys", SimpleNamespace(platform=platform))
    parser = _parser()
    args = parser.parse_args(
        [
            "uninstall",
            "--provider",
            "claude_code",
            "--scope",
            "managed",
        ]
    )

    assert args.scope == "managed"
    assert str(_settings_target(args)) == expected

    args.scope = "project"
    args.project_root = str(tmp_path)
    assert _settings_target(args) == tmp_path / ".claude/settings.json"

    args.scope = "local_project"
    assert _settings_target(args) == tmp_path / ".claude/settings.local.json"


def test_cli_exposes_version_bound_installed_claude_acceptance() -> None:
    args = _parser().parse_args(
        ["validate-claude", "--binary", "/opt/claude/2.1.250/claude"]
    )

    assert args.operation == "validate-claude"
    assert args.binary == "/opt/claude/2.1.250/claude"


def test_cli_exposes_version_bound_installed_codex_acceptance() -> None:
    args = _parser().parse_args(
        [
            "validate-codex",
            "--binary",
            "/opt/codex/0.154.0/codex",
            "--repository-root",
            "/opt/hawk",
            "--python-binary",
            "/opt/hawk/python",
            "--expected-version",
            "0.154.0",
            "--expected-binary-sha256",
            "a" * 64,
            "--identity-helper",
            "/opt/hawk/hawk-device-identity",
            "--key-tag",
            "com.hawk.endpoint-agent.device-key.v20261005r2",
        ]
    )

    assert args.operation == "validate-codex"
    assert args.binary == "/opt/codex/0.154.0/codex"
    assert args.repository_root == "/opt/hawk"
    assert args.python_binary == "/opt/hawk/python"
    assert args.expected_version == "0.154.0"
    assert args.expected_binary_sha256 == "a" * 64
    assert args.identity_helper == "/opt/hawk/hawk-device-identity"
    assert args.key_tag == "com.hawk.endpoint-agent.device-key.v20261005r2"


@pytest.mark.parametrize("platform, expected", [
    ('darwin', '/Library/Application Support/Cursor/hooks.json'),
    ('linux', '/etc/cursor/hooks.json'),
    ('win32', 'C:\\ProgramData\\Cursor\\hooks.json'),
])
def test_cursor_cli_exposes_enterprise_hook_path_and_exact_release_acceptance_inputs(monkeypatch, platform: str, expected: str) -> None:
    monkeypatch.setattr(installer, "sys", SimpleNamespace(platform=platform))
    parser = _parser()
    args = parser.parse_args(
        [
            "uninstall",
            "--provider",
            "cursor",
            "--scope",
            "enterprise",
        ]
    )

    assert str(_settings_target(args)) == expected
    validation = parser.parse_args(
        [
            "validate-cursor",
            "--binary",
            "/opt/cursor/2026.08.11/cursor-agent",
            "--acceptance-home",
            "/var/lib/hawk/cursor-acceptance",
            "--desktop-app",
            "/Applications/Cursor.app",
        ]
    )
    assert validation.operation == "validate-cursor"
    assert validation.binary == "/opt/cursor/2026.08.11/cursor-agent"
    assert validation.acceptance_home == "/var/lib/hawk/cursor-acceptance"
    assert validation.desktop_app == "/Applications/Cursor.app"


@pytest.mark.parametrize("platform, expected", [
    ('darwin', '/Library/Application Support/GeminiCli/settings.json'),
    ('linux', '/etc/gemini-cli/settings.json'),
    ('win32', 'C:\\ProgramData\\gemini-cli\\settings.json'),
])
def test_gemini_cli_exposes_managed_path_and_real_binary_gate(monkeypatch, platform: str, expected: str) -> None:
    monkeypatch.setattr(installer, "sys", SimpleNamespace(platform=platform))
    parser = _parser()
    args = parser.parse_args(
        ["uninstall", "--provider", "gemini_cli", "--scope", "managed"]
    )

    assert str(_settings_target(args)) == expected
    validation = parser.parse_args(
        [
            "validate-gemini", "--binary", "/opt/gemini",
            "--runtime", "/opt/hawk/node", "--real-model-none",
        ]
    )
    assert validation.operation == "validate-gemini"
    assert validation.binary == "/opt/gemini"
    assert validation.runtime == "/opt/hawk/node"
    assert validation.real_model_none is True

    managed = parser.parse_args(
        [
            "render-gemini-managed",
            "--binary", "/Library/Hawk/bin/gemini-0.54.4",
            "--settings", "/Library/Application Support/GeminiCli/settings.json",
            "--helper", "/Library/Hawk/bin/hawk-native-hook",
            "--config", "/Library/Hawk/etc/native-control.json",
            "--expected-version", "0.54.4",
            "--output", "/Library/Hawk/bin/hawk-gemini",
        ]
    )
    assert managed.operation == "render-gemini-managed"
    assert managed.expected_version == "0.54.4"
    assert managed.output == "/Library/Hawk/bin/hawk-gemini"


def test_macos_native_hook_runtime_binds_the_registered_secure_enclave_key() -> None:
    assert cli._runtime_key_binding(
        key_provider="macos_secure_enclave",
        key_reference="secure-enclave://com.hawk.endpoint-agent.native-control.gemini.v1",
    ) == {
        "secure_enclave_key_tag": "com.hawk.endpoint-agent.native-control.gemini.v1"
    }

    with pytest.raises(ValueError, match="invalid Secure Enclave key reference"):
        cli._runtime_key_binding(
            key_provider="macos_secure_enclave",
            key_reference="hsm://wrong-provider/key",
        )

    assert cli._runtime_key_binding(
        key_provider="kms_hsm_helper",
        key_reference="hsm://hawk/gemini",
    ) == {}


def test_cli_module_invokes_main_when_run_directly() -> None:
    source = Path("src/hawk_endpoint_agent/native_control/cli.py").read_text(encoding="utf-8")

    assert 'if __name__ == "__main__":' in source
    assert source.rstrip().endswith("main()")


def _signed_helper_install_arguments(tmp_path):
    return ['cli','install','--provider','codex','--settings',str(tmp_path/'hooks.json'),'--helper',str(tmp_path/'hook'),'--config',str(tmp_path/'config.json'),'--api-url','http://127.0.0.1:8002','--tenant-id','tenant','--integration-id','integration','--credential-id','credential','--provider-family','openai','--product','codex','--provider-version','0.154.0','--key-provider','macos_secure_enclave','--kms-key-reference','secure-enclave://synthetic-key','--security-profile','bank']


def test_bank_install_checks_signature_before_any_settings_or_config_write(monkeypatch,tmp_path):
    from hawk_endpoint_agent.auth.device_key import DeviceKeyError
    monkeypatch.setattr(cli.sys,'argv',_signed_helper_install_arguments(tmp_path))
    def rejected(path):raise DeviceKeyError('private-secret',code='device_key_helper_unsigned')
    monkeypatch.setattr(cli,'validate_macos_identity_helper',rejected,raising=False)
    monkeypatch.setattr(cli,'_atomic_runtime_config',lambda *a:pytest.fail('config written before signature check'))
    monkeypatch.setattr(cli,'NativeHookInstaller',lambda **k:pytest.fail('settings touched before signature check'))
    with pytest.raises(DeviceKeyError):cli.main()
    assert not (tmp_path/'config.json').exists() and not (tmp_path/'hooks.json').exists()


def test_install_exposes_explicit_canonical_secure_enclave_helper(tmp_path):
    args=_parser().parse_args(_signed_helper_install_arguments(tmp_path)[1:])
    assert args.secure_enclave_helper_path==str(Path.home()/'Library/Application Support/Hawk/EndpointAgent/runtime/bin/hawk-device-identity')


def test_bank_install_persists_validated_explicit_helper_path(monkeypatch,tmp_path,capsys):
    helper=tmp_path/'identity';helper.write_bytes(b'identity');helper.chmod(0o700)
    (tmp_path/'hook').write_bytes(b'hook');(tmp_path/'hook').chmod(0o700)
    args=_signed_helper_install_arguments(tmp_path)+['--secure-enclave-helper-path',str(helper)]
    args[args.index('--key-provider')+1]=' MACOS_SECURE_ENCLAVE '
    args[args.index('--security-profile')+1]=' BANK '
    observed=[]
    def validate(path):observed.append(path);return helper
    monkeypatch.setattr(cli,'validate_macos_identity_helper',validate)
    monkeypatch.setattr(cli.sys,'argv',args)
    cli.main();capsys.readouterr()
    import json
    config=json.loads((tmp_path/'config.json').read_text())
    assert observed==[str(helper)]
    assert config['secure_enclave_helper_path']==str(helper)
    assert config['secure_enclave_key_tag']=='synthetic-key'
    assert config['key_provider']=='macos_secure_enclave' and config['security_profile']=='bank'


@pytest.mark.parametrize('provider,profile',[('MACOS_SECURE_ENCLAVE','BANK'),(' macos_secure_enclave ',' bank '),(' MACOS_SECURE_ENCLAVE ',' BANK ')])
def test_bank_aliases_reject_unsigned_before_any_write(monkeypatch,tmp_path,provider,profile):
    from hawk_endpoint_agent.auth.device_key import DeviceKeyError
    args=_signed_helper_install_arguments(tmp_path)
    args[args.index('--key-provider')+1]=provider;args[args.index('--security-profile')+1]=profile
    monkeypatch.setattr(cli.sys,'argv',args)
    def rejected(path):raise DeviceKeyError('unsigned',code='device_key_helper_unsigned')
    monkeypatch.setattr(cli,'validate_macos_identity_helper',rejected)
    monkeypatch.setattr(cli,'_atomic_runtime_config',lambda *a:pytest.fail('config written'))
    monkeypatch.setattr(cli,'NativeHookInstaller',lambda **k:pytest.fail('settings touched'))
    with pytest.raises(DeviceKeyError):cli.main()
    assert not (tmp_path/'config.json').exists() and not (tmp_path/'hooks.json').exists()
