import io
import json
from types import SimpleNamespace

import pytest

from hawk_endpoint_agent.native_control import hook
from hawk_endpoint_agent.native_control import endpoint_broker as broker


def test_endpoint_config_requires_only_local_pin_and_provider(tmp_path):
    path = tmp_path / 'hook.json'
    path.write_text(json.dumps({'transport': 'endpoint', 'provider': 'openai',
                              'socket_path': '/tmp/agent.sock', 'endpoint_thumbprint': 'a' * 64}))
    path.chmod(0o600)
    assert hook._configuration(str(path))['transport'] == 'endpoint'


@pytest.mark.parametrize('response', [
    {}, {'ok': False}, {'ok': True, 'request_id': 'wrong', 'decision': {'decision': 'allow', 'enforced': True}},
])
def test_missing_or_uncorrelated_agent_response_rejected(monkeypatch, response):
    monkeypatch.setattr(broker, 'query_agent', lambda *a, **kw: response)
    with pytest.raises(ValueError):
        broker.query_endpoint({'socket_path': '/tmp/agent.sock', 'endpoint_thumbprint': 'a' * 64},
                              'codex', 'before_model', {'prompt': 'synthetic'})


@pytest.mark.parametrize('decision', [{}, {'decision': 'allow'}, {'decision': 'unknown', 'enforced': True}])
def test_bad_backend_decisions_rejected(decision):
    with pytest.raises(ValueError):
        broker.validate_decision(decision)


def test_allow_preserves_provider_permissions():
    for provider in ['codex', 'claude_code']:
        for event in ['before_tool', 'permission_request', 'before_model']:
            assert broker.hook_output(provider, event, {'decision': 'allow', 'enforced': True}) == {}


def test_restrictive_prompt_decisions_block():
    for provider in ['codex', 'claude_code']:
        for decision in ['block', 'redact', 'review', 'require_approval', 'require_second_approval']:
            assert broker.hook_output(provider, 'before_model', {'decision': decision, 'enforced': True})['decision'] == 'block'


def test_broker_uses_only_agent_owned_binding(monkeypatch):
    monkeypatch.setattr(hook, '_configuration', lambda path, **kw: {
        'provider': 'openai', 'tenant_id': 'tenant-a', 'api_url': 'https://hawk.test/api'})
    seen = []
    monkeypatch.setattr(hook, '_signed_callback', lambda conf, event, data: seen.append(data) or {})
    monkeypatch.setattr(hook, '_post_callback', lambda *a: {'decision': 'block', 'enforced': True})
    config = SimpleNamespace(native_hook_runtime_configs={'codex': '/agent/owned.json'},
                             tenant_id='tenant-a', api_base_url='https://hawk.test/api')
    result = broker.evaluate_native_hook(config, {'provider': 'codex', 'event': 'before_model',
        'raw': {'prompt': 'synthetic private prompt'}, 'api_url': 'https://attacker.invalid'})
    assert result['decision'] == 'block'
    assert 'synthetic private prompt' not in json.dumps(seen)
    config.tenant_id = 'tenant-b'
    with pytest.raises(ValueError):
        broker.evaluate_native_hook(config, {'provider': 'codex', 'event': 'before_model', 'raw': {}})


def test_hook_endpoint_unavailable_blocks_without_direct_fallback(tmp_path, monkeypatch, capsys):
    path = tmp_path / 'hook.json'
    path.write_text(json.dumps({'transport': 'endpoint', 'provider': 'anthropic',
                              'socket_path': '/tmp/absent.sock', 'endpoint_thumbprint': 'a' * 64}))
    path.chmod(0o600)
    monkeypatch.setattr(broker, 'query_agent', lambda *a, **kw: {'ok': False})
    monkeypatch.setattr(hook, '_post_callback', lambda *a: pytest.fail('direct fallback forbidden'))
    monkeypatch.setattr('sys.argv', ['hook', '--provider', 'claude_code', '--event', 'before_model', '--config', str(path)])
    monkeypatch.setattr('sys.stdin', SimpleNamespace(buffer=io.BytesIO(b'{"prompt":"synthetic"}')))
    hook.main()
    assert json.loads(capsys.readouterr().out)['decision'] == 'block'


def test_install_endpoint_renders_only_local_config(tmp_path, monkeypatch, capsys):
    from hawk_endpoint_agent.native_control import cli
    agent_config = tmp_path / 'agent.json'
    agent_config.write_text(json.dumps({'endpoint_id': 'endpoint-a', 'tenant_id': 'tenant-a',
        'ipc_socket_path': str(tmp_path / 'agent.sock'), 'ipc_trusted_device_thumbprint': 'a' * 64,
        'native_hook_runtime_configs': {'codex': str(tmp_path / 'registered-native.json')}}))
    agent_config.chmod(0o600)
    helper = tmp_path / 'hook'
    helper.write_text('#!/bin/sh\nexit 0\n')
    helper.chmod(0o700)
    settings = tmp_path / 'hooks.json'
    settings.write_text('{"custom":"preserved"}')
    output = tmp_path / 'client.json'
    monkeypatch.setattr(cli, '_verify_endpoint_installation', lambda config, provider: None)
    monkeypatch.setattr('sys.argv', ['control', 'install-endpoint', '--provider', 'codex',
        '--endpoint-config', str(agent_config), '--helper', str(helper), '--config', str(output),
        '--settings', str(settings)])
    cli.main()
    payload = json.loads(output.read_text())
    assert payload['transport'] == 'endpoint'
    assert set(payload) == {'transport', 'provider', 'socket_path', 'endpoint_thumbprint'}
    assert json.loads(settings.read_text())['custom'] == 'preserved'
    assert json.loads(capsys.readouterr().out)['protection_status'] == 'unverified'


@pytest.mark.parametrize('provider', ['codex', 'claude_code'])
def test_authenticated_socket_roundtrip_and_bad_pin(monkeypatch, provider):
    import tempfile
    from pathlib import Path
    from hawk_endpoint_agent.auth.device_key import EphemeralDeviceKeyProvider
    from hawk_endpoint_agent.config import AgentConfig
    from hawk_endpoint_agent.ipc.control_server import ControlSocketServer
    from hawk_endpoint_agent.local_broker_auth import LocalBrokerAuthenticator

    key = EphemeralDeviceKeyProvider()
    identity = key.ensure_key('test-endpoint')
    authenticator = LocalBrokerAuthenticator(endpoint_id='test-endpoint', provider=key, identity=identity)
    client = SimpleNamespace(local_broker_authenticator=lambda: authenticator)
    monkeypatch.setattr(hook, '_configuration', lambda *a, **kw: {
        'provider': broker.PROVIDERS[provider], 'tenant_id': 'tenant-a', 'api_url': 'https://hawk.test/api'})
    monkeypatch.setattr(hook, '_signed_callback', lambda *a: {})
    decision = {'decision': 'block', 'enforced': True}
    monkeypatch.setattr(hook, '_post_callback', lambda *a: decision)
    with tempfile.TemporaryDirectory(prefix='hawk-native-', dir='/tmp') as temp:
        cfg = AgentConfig(tenant_id='tenant-a', api_base_url='https://hawk.test/api',
                          security_profile='development', ipc_socket_path=str(Path(temp) / 'agent.sock'),
                          ipc_trusted_device_thumbprint=identity.key_thumbprint,
                          native_hook_runtime_configs={provider: '/registered.json'})
        server = ControlSocketServer(cfg, SimpleNamespace(client=client))
        server.start()
        local = {'socket_path': cfg.ipc_socket_path, 'endpoint_thumbprint': identity.key_thumbprint}
        try:
            for action in ['block', 'allow']:
                decision['decision'] = action
                assert broker.query_endpoint(local, provider, 'before_model', {'prompt': 'synthetic'})['decision'] == action
                import os
                import subprocess
                import sys
                client_config = Path(temp) / 'client.json'
                client_config.write_text(json.dumps({**local, 'transport': 'endpoint',
                                                    'provider': broker.PROVIDERS[provider]}))
                client_config.chmod(0o600)
                result = subprocess.run([sys.executable, '-m', 'hawk_endpoint_agent.native_control.hook',
                    '--provider', provider, '--event', 'before_model', '--config', str(client_config)],
                    input='{"prompt":"synthetic"}', text=True, capture_output=True, timeout=5,
                    env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')})
                assert result.returncode == 0
                output = json.loads(result.stdout)
                assert output.get('decision') == ('block' if action == 'block' else None)
            with pytest.raises(ValueError):
                broker.query_endpoint({**local, 'endpoint_thumbprint': '0' * 64}, provider, 'before_model', {})
            with pytest.raises(ValueError):
                broker.query_endpoint(local, 'unsupported', 'before_model', {})
        finally:
            server.stop()
        with pytest.raises(ValueError):
            broker.query_endpoint(local, provider, 'before_model', {})


def test_installation_refuses_unavailable_agent(monkeypatch):
    from hawk_endpoint_agent.native_control import cli
    from hawk_endpoint_agent.bridge import socket_client
    monkeypatch.setattr(broker, 'registered_runtime', lambda *a: {})
    monkeypatch.setattr(socket_client, 'query_agent', lambda *a, **kw: {'ok': False})
    config = SimpleNamespace(ipc_socket_path='/tmp/no-agent.sock',
                             ipc_trusted_device_thumbprint='a' * 64, endpoint_id='endpoint-a')
    with pytest.raises(ValueError, match='installation refused'):
        cli._verify_endpoint_installation(config, 'codex')
