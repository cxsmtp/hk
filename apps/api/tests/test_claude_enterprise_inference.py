import base64
import hashlib
import hmac
import json
import time
import pytest
from app.services.native_control.claude_enterprise_inference import verify_frame, verdict_for_frame

ORG = '550e8400-e29b-41d4-a716-446655440000'
SECRET = 'whsec_' + base64.b64encode(bytes(range(32))).decode()


def frame():
    return {'type': 'prompt', 'request_id': 'synthetic-id', 'tenant_id': ORG,
            'actor': {'type': 'user', 'id': 'synthetic-user'}, 'source': {'application': 'claude-ai'},
            'messages': [{'role': 'user', 'content': [{'type': 'text', 'text': 'synthetic'}]}]}


def signed(payload, timestamp=None):
    raw = json.dumps(payload).encode()
    ts = str(int(time.time()) if timestamp is None else timestamp)
    digest = hmac.new(bytes(range(32)), b'synthetic-id.' + ts.encode() + b'.' + raw, hashlib.sha256).digest()
    return raw, {'webhook-id': 'synthetic-id', 'webhook-timestamp': ts,
                 'webhook-signature': 'v1,' + base64.b64encode(digest).decode()}


def test_signature_and_org_bound_to_raw_body():
    raw, headers = signed(frame())
    assert verify_frame(raw, headers, [SECRET], ORG)['type'] == 'prompt'
    for body, hdr, org in [(raw+b' ', headers, ORG), (raw, {}, ORG), (raw, headers, 'other')]:
        with pytest.raises(ValueError):
            verify_frame(body, hdr, [SECRET], org)
    raw, headers = signed(frame(), int(time.time())-301)
    with pytest.raises(ValueError):
        verify_frame(raw, headers, [SECRET], ORG)


def test_policy_only_explicit_allow():
    for decision in ['block', 'redact', 'hold_for_approval', 'warn', None]:
        assert verdict_for_frame(frame(), lambda text: {'final_decision': decision})['action'] == 'deny'
    assert verdict_for_frame(frame(), lambda text: {'final_decision': 'allow'}) == {'action': 'allow'}


def test_complete_text_and_tool_material_reaches_policy():
    payload = frame()
    payload['messages'][0]['content'] += [
        {'type': 'attachment', 'text': 'attachment-sensitive'},
        {'type': 'tool_use', 'tool_name': 'refund', 'input': {'amount': 200}},
        {'type': 'tool_result', 'content': 'customer-sensitive', 'is_error': False}]
    seen = []
    verdict_for_frame(payload, lambda text: seen.append(text) or {'final_decision': 'allow'})
    assert all(value in seen[0] for value in ['attachment-sensitive', '200', 'customer-sensitive'])


def test_missing_attachment_text_and_new_content_do_not_silently_pass():
    for block in [{'type': 'attachment', 'text': None}, {'type': 'future_content', 'value': 'sensitive'}]:
        payload = frame()
        payload['messages'][0]['content'].append(block)
        assert verdict_for_frame(payload, lambda text: {'final_decision': 'allow'})['action'] == 'deny'


def test_policy_failure_denies():
    def unavailable(text):
        raise RuntimeError('secret diagnostic')
    response = verdict_for_frame(frame(), unavailable)
    assert response['action'] == 'deny'
    assert 'secret' not in json.dumps(response)


def test_receiver_authenticates_before_policy_and_replay(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from app.api.routers import claude_enterprise
    app = FastAPI()
    app.include_router(claude_enterprise.router)
    binding = {'organization_id': ORG, 'tenant_id': ORG, 'ai_system_id': ORG, 'secrets': [SECRET]}
    monkeypatch.setattr(claude_enterprise, 'load_binding', lambda key: binding)
    claimed = set()
    monkeypatch.setattr(claude_enterprise, 'claim_delivery', lambda binding, event: False if event in claimed else (claimed.add(event) or True))
    evaluations = []
    monkeypatch.setattr(claude_enterprise, 'evaluate_policy', lambda binding, frame: evaluations.append(frame) or {'action': 'allow'})
    client = TestClient(app)
    raw, headers = signed(frame())
    path = '/native-controls/claude-enterprise/test/inference'
    assert client.post(path, content=raw).json()['action'] == 'deny'
    assert not evaluations
    assert client.post(path, content=raw, headers=headers).json()['action'] == 'allow'
    assert client.post(path, content=raw, headers=headers).json()['action'] == 'deny'
    assert len(evaluations) == 1


def test_policy_bridge_uses_bound_tenant_and_records_actual_verdict(monkeypatch):
    from types import SimpleNamespace
    from app.api.routers import claude_enterprise
    from app.db import session
    from app.services import gateway_service, fail_secure_service, audit_service
    tenant = SimpleNamespace(id=ORG, is_active=True, platform_mode='enforce')
    calls, audits = [], []
    class DB:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def get(self, *args): return tenant
        def commit(self): pass
        def rollback(self): pass
    monkeypatch.setattr(session, 'SessionLocal', DB)
    monkeypatch.setattr(fail_secure_service, 'enforce_fail_secure_or_raise', lambda *a, **kw: None)
    monkeypatch.setattr(gateway_service, 'llm_intercept', lambda db, **kw: calls.append(kw) or
                        {'final_decision': 'allow', 'platform_mode': 'enforce'})
    monkeypatch.setattr(audit_service, 'write_audit_log', lambda *a, **kw: audits.append(kw))
    payload = frame()
    payload['messages'][0]['content'].append({'type': 'attachment', 'text': None})
    response = claude_enterprise.evaluate_policy({'tenant_id': ORG, 'organization_id': ORG, 'ai_system_id': ORG}, payload)
    assert response['action'] == 'deny'
    assert calls[0]['tenant_id'] == ORG and calls[0]['ai_system_id'] == ORG
    assert audits[0]['payload']['action'] == 'deny'
    assert 'synthetic' not in json.dumps(audits)
    tenant.platform_mode = 'monitor'
    assert claude_enterprise.evaluate_policy({'tenant_id': ORG}, frame())['action'] == 'deny'
    assert len(calls) == 1


def test_secret_rotation_and_body_request_id_binding():
    raw, headers = signed(frame())
    assert verify_frame(raw, headers, ['whsec_invalid', SECRET], ORG)
    payload = frame()
    payload['request_id'] = 'mismatch'
    raw, headers = signed(payload)
    with pytest.raises(ValueError):
        verify_frame(raw, headers, [SECRET], ORG)


def test_binding_is_disabled_by_default_and_secret_reference_only(tmp_path, monkeypatch):
    from app.api.routers.claude_enterprise import load_binding
    monkeypatch.delenv('HAWK_CLAUDE_ENTERPRISE_BINDINGS_FILE', raising=False)
    with pytest.raises(ValueError):
        load_binding('acme')
    path = tmp_path / 'bindings.json'
    payload = {'enabled': True, 'organization_id': ORG, 'tenant_id': ORG, 'ai_system_id': ORG,
               'secret_envs': ['HAWK_CLAUDE_HOOK_SECRET_ACME']}
    path.write_text(json.dumps({'acme': payload}))
    path.chmod(0o600)
    monkeypatch.setenv('HAWK_CLAUDE_ENTERPRISE_BINDINGS_FILE', str(path))
    monkeypatch.setenv('HAWK_CLAUDE_HOOK_SECRET_ACME', SECRET)
    assert load_binding('acme')['secrets'] == [SECRET]
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load_binding('acme')
