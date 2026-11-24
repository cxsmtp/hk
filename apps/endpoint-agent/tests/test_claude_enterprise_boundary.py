import plistlib
import pytest
from hawk_endpoint_agent.native_control.claude_enterprise import deployment_bundle, restriction_headers

ORG = '550e8400-e29b-41d4-a716-446655440000'


def test_bundle_has_managed_login_and_no_protection_claim():
    bundle = deployment_bundle([ORG])
    profile = plistlib.loads(bundle['claude.mobileconfig'].encode())
    payload = profile['PayloadContent'][0]
    assert payload['PayloadType'] == 'com.anthropic.claudefordesktop'
    assert payload['forceLoginOrgUUID'] == ORG
    assert 'unverified' in bundle['deployment.json']
    assert ORG in bundle['claude-windows.reg']


@pytest.mark.parametrize('orgs', [[], ['bad\r\nheader: injected'], ['not-a-uuid']])
def test_invalid_orgs_rejected(orgs):
    with pytest.raises(ValueError):
        deployment_bundle(orgs)


def test_strip_all_spoofed_and_continuation_headers():
    result = restriction_headers('claude.ai', [('Anthropic-Allowed-Org-Ids', 'attacker'),
        ('anthropic-allowed-org-ids', 'second'), ('anthropic-allowed-org-ids1', 'third'),
        ('anthropic-allowed-org-ids99', 'fourth'), ('Content-Type', 'application/json')], [ORG])
    assert result == [('Content-Type', 'application/json'), ('anthropic-allowed-org-ids', ORG)]
    original = [('X-Test', 'value')]
    assert restriction_headers('claude.ai.attacker.example', original, [ORG]) == original


def test_generated_proxy_addon_overwrites_actual_header_collection():
    from types import SimpleNamespace
    namespace = {}
    exec(deployment_bundle([ORG])['claude-tenant-restriction.py'], namespace)
    class Headers:
        def __init__(self): self.pairs = [('anthropic-allowed-org-ids', 'spoof'), ('authorization', 'synthetic')]
        def items(self, multi=False): return list(self.pairs)
        def clear(self): self.pairs.clear()
        def add(self, key, value): self.pairs.append((key, value))
    headers = Headers()
    namespace['request'](SimpleNamespace(request=SimpleNamespace(host='claude.ai', scheme='https', headers=headers)))
    assert headers.pairs == [('authorization', 'synthetic'), ('anthropic-allowed-org-ids', ORG)]


def test_large_allowlist_and_renderer_cli(tmp_path, monkeypatch, capsys):
    import json
    from uuid import UUID
    from hawk_endpoint_agent.native_control import cli
    ids = [str(UUID(int=i+1)) for i in range(500)]
    headers = restriction_headers('claude.ai', [], ids)
    assert len(headers) == 10 and headers[0][1].endswith(';n=10')
    assert headers[-1][0] == 'anthropic-allowed-org-ids9'
    output = tmp_path / 'bundle'
    monkeypatch.setattr('sys.argv', ['control', 'render-claude-enterprise', '--org-id', ORG,
                                   '--output-directory', str(output)])
    cli.main()
    assert json.loads(capsys.readouterr().out)['installed'] is False
    assert plistlib.loads((output / 'claude.mobileconfig').read_bytes())['PayloadScope'] == 'System'
