"""Endpoint-owned native callback routing; no caller-supplied backend credentials."""
from __future__ import annotations

import json
from pathlib import Path
import re
import secrets

from ..bridge.socket_client import query_agent

PROVIDERS = {'codex': 'openai', 'claude_code': 'anthropic'}
_DECISIONS = {'allow', 'warn', 'block', 'review', 'require_approval', 'require_second_approval', 'redact'}


def endpoint_configuration(payload: dict) -> dict:
    socket_path = str(payload.get('socket_path') or '')
    pin = str(payload.get('endpoint_thumbprint') or '')
    if payload.get('provider') not in PROVIDERS.values():
        raise ValueError('unsupported endpoint hook provider')
    if not Path(socket_path).is_absolute() or not re.fullmatch(r'[0-9a-f]{64}', pin):
        raise ValueError('endpoint hook requires absolute socket path and device pin')
    return {'transport': 'endpoint', 'provider': payload['provider'],
            'socket_path': socket_path, 'endpoint_thumbprint': pin}


def validate_decision(decision: object) -> dict:
    if (not isinstance(decision, dict) or decision.get('decision') not in _DECISIONS
            or type(decision.get('enforced')) is not bool):
        raise ValueError('invalid native policy decision')
    # Do not return arbitrary backend fields or echo event material over IPC.
    return {'decision': decision['decision'], 'enforced': decision['enforced'],
            'reason': str(decision.get('reason') or 'Hawk policy decision')[:1000]}


def query_endpoint(config: dict, provider: str, event: str, raw: dict) -> dict:
    request_id = secrets.token_hex(24)
    request = {'protocol_version': 1, 'op': 'native_hook', 'request_id': request_id,
               'provider': provider, 'event': event, 'raw': raw}
    # Leave framing headroom below the agent's default 256 KiB cap.
    if len(json.dumps(request).encode('utf-8')) > 240 * 1024:
        raise ValueError('native hook IPC input too large')
    response = query_agent(config['socket_path'], request, timeout=3.0,
                           expected_thumbprint=config['endpoint_thumbprint'])
    if response.get('ok') is not True or response.get('request_id') != request_id:
        raise ValueError('native endpoint decision unavailable or uncorrelated')
    return validate_decision(response.get('decision'))


def registered_runtime(agent_config, provider: str) -> dict:
    from .hook import _configuration
    if provider not in PROVIDERS:
        raise ValueError('unsupported native provider')
    bindings = getattr(agent_config, 'native_hook_runtime_configs', {})
    path = bindings.get(provider) if isinstance(bindings, dict) else None
    if not isinstance(path, str) or not Path(path).is_absolute():
        raise ValueError('native provider is not registered on this endpoint')
    config = _configuration(path, use_environment=False)
    if (config.get('transport') == 'endpoint' or config['provider'] != PROVIDERS[provider]
            or not agent_config.tenant_id or config['tenant_id'] != agent_config.tenant_id
            or str(config['api_url']).rstrip('/') != str(agent_config.api_base_url).rstrip('/')):
        raise ValueError('native provider endpoint binding mismatch')
    return config


def evaluate_native_hook(agent_config, request: dict) -> dict:
    from .hook import _post_callback, _signed_callback, normalize_provider_event
    from .installer import _EVENTS

    provider, event, raw = request.get('provider'), request.get('event'), request.get('raw')
    if provider not in PROVIDERS or event not in {e for _, e in _EVENTS[provider]}:
        raise ValueError('unsupported native hook')
    if not isinstance(raw, dict):
        raise ValueError('invalid native event')
    config = registered_runtime(agent_config, provider)
    normalized = normalize_provider_event(provider, event, raw)
    return validate_decision(_post_callback(config, _signed_callback(config, event, normalized)))


def hook_output(provider: str, event: str, decision: dict) -> dict:
    from .hook import provider_hook_output
    decision = validate_decision(decision)
    # A policy pass is not permission to override the app's native approval flow.
    if not decision['enforced'] or decision['decision'] == 'allow':
        return {}
    if decision['decision'] in {'review', 'require_approval', 'require_second_approval', 'redact'}:
        decision['decision'] = 'block'
    if decision['decision'] == 'warn' and event == 'permission_request':
        return {}
    return provider_hook_output(provider, event, decision)
