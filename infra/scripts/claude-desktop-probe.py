"""Read-only transport feasibility probe, NOT a DLP protection adapter.

Run only with the documented scoped pilot options. No headers, URLs, payloads,
identifiers, or upstream responses are logged. All writes/upgrades are withheld.
"""
import json


def in_scope(host):
    return host == 'claude.ai' or host.endswith('.claude.ai')


def permit_read(method, upgrade):
    return method in {'GET', 'HEAD', 'OPTIONS'} and not upgrade


def route_category(path):
    parts = path.split('?', 1)[0].rstrip('/').split('/')
    if parts[-1] in {'completion', 'retry_completion'}:
        return 'completion'
    if 'chat_conversations' in parts:
        return 'conversation'
    if 'upload' in parts or 'uploads' in parts:
        return 'upload'
    if parts[-1] == 'organizations':
        return 'organization'
    return 'other'


class Probe:
    def requestheaders(self, flow):
        from mitmproxy import http
        # This also rejects unknown destinations if interception config drifts.
        allowed = in_scope(flow.request.host) and permit_read(
            flow.request.method, bool(flow.request.headers.get('upgrade'))
        )
        flow.metadata['hawk_probe_allowed'] = allowed
        category = route_category(flow.request.path)
        print(json.dumps({'event': 'decrypted_request', 'route': category,
                          'decision': 'read_only_pass' if allowed else 'block',
                          'protection': 'unvalidated_probe'}), flush=True)
        if not allowed:
            flow.response = http.Response.make(
                403, b'{"error":{"type":"permission_error","message":"Hawk transport probe: submissions are disabled during validation."}}',
                {'content-type': 'application/json', 'cache-control': 'no-store'},
            )

    def responseheaders(self, flow):
        if flow.metadata.get('hawk_probe_allowed'):
            flow.response.stream = True
            print(json.dumps({'event': 'upstream_response',
                              'route': route_category(flow.request.path),
                              'status': flow.response.status_code}), flush=True)

    def tls_failed_client(self, data):
        sni = data.conn.sni or ''
        scope = 'claude_root' if sni == 'claude.ai' else (
            'claude_subdomain' if in_scope(sni) else 'other')
        error = str(data.conn.error or '').lower()
        reason = 'certificate' if any(word in error for word in (
            'certificate', 'unknown ca', 'bad cert', 'trust')) else 'other'
        print(json.dumps({'event': 'client_tls_failed', 'scope': scope,
                          'reason': reason}), flush=True)

    def tls_failed_server(self, data):
        print('{"event":"upstream_tls_failed"}', flush=True)


addons = [Probe()]
