"""Anthropic Standard Webhooks verification and conservative input verdicts."""
import base64
import hashlib
import hmac
import json
import time

MAX_BODY = 64 * 1024 * 1024


def verify_frame(raw, headers, secrets, organization_id):
    headers = {name.lower(): value for name, value in headers.items()}
    event_id = headers.get('webhook-id', '')
    timestamp = headers.get('webhook-timestamp', '')
    signatures = headers.get('webhook-signature', '')
    if (not raw or len(raw) > MAX_BODY or not 1 <= len(event_id) <= 256
            or len(timestamp) > 16 or len(signatures) > 4096):
        raise ValueError('invalid signed frame')
    if not timestamp.isascii() or not timestamp.isdecimal() or abs(time.time() - int(timestamp)) > 300:
        raise ValueError('expired signed frame')
    material = event_id.encode() + b'.' + timestamp.encode() + b'.' + raw
    valid = False
    for secret in secrets:
        try:
            if not secret.startswith('whsec_'):
                continue
            key = base64.b64decode(secret[6:], validate=True)
            if len(key) < 16:
                continue
            expected = b'v1,' + base64.b64encode(hmac.new(key, material, hashlib.sha256).digest())
            valid |= any(hmac.compare_digest(expected, value.encode()) for value in signatures.split())
        except (ValueError, TypeError):
            continue
    if not valid:
        raise ValueError('invalid signature')
    payload = json.loads(raw)
    if (not isinstance(payload, dict) or payload.get('request_id') != event_id
            or payload.get('tenant_id') != organization_id):
        raise ValueError('invalid organization or request binding')
    return payload


def deny(reason='Hawk could not authorize this request.'):
    return {'action': 'deny', 'deny_reason': reason}


def verdict_for_frame(frame, evaluate):
    try:
        if frame.get('type') != 'prompt':
            return deny('This inference event requires a supported Hawk inspection policy.')
        messages = frame.get('messages')
        if not isinstance(messages, list) or not messages:
            return deny()
        incomplete = False
        for message in messages:
            if not isinstance(message, dict) or message.get('role') not in {'user', 'assistant'}:
                return deny()
            blocks = message.get('content')
            if not isinstance(blocks, list) or not blocks:
                return deny()
            for block in blocks:
                if not isinstance(block, dict):
                    return deny()
                kind = block.get('type')
                if kind == 'text' and not isinstance(block.get('text'), str):
                    return deny()
                if kind == 'tool_result' and (not isinstance(block.get('content'), str)
                                              or type(block.get('is_error')) is not bool):
                    return deny()
                if kind == 'attachment' and not isinstance(block.get('text'), str):
                    incomplete = True
                if kind not in {'text', 'tool_use', 'tool_result', 'attachment'}:
                    incomplete = True
        # Retain all message/block fields: no truncation or unknown-field omission.
        result = evaluate(json.dumps(messages, ensure_ascii=False, separators=(',', ':')))
        if incomplete:
            return deny('Hawk cannot fully inspect some submitted content under this policy.')
        if isinstance(result, dict) and result.get('final_decision') == 'allow':
            return {'action': 'allow'}
        return deny('Blocked by Hawk policy.')
    except Exception:
        return deny()
