import test from 'node:test';
import assert from 'node:assert/strict';
import { HawkGatewayClient, HawkGatewayError, safeHawkReason } from '../src/hawk-client.mjs';
import { buildAuthorizePayload } from '../src/policy.mjs';

test('HTTP gateway authorization omits only endpoint-specific client_app', async () => {
  const payload = buildAuthorizePayload({
    aiSystemId: 'system', actorId: 'agent', capabilityToken: 'capability',
    mcpServerId: 'manual-terminal-lab', toolName: 'write_demo_marker',
    toolVersion: '1.0.0', toolFingerprintId: 'fingerprint',
    argumentsObject: { note: 'synthetic-marker' }, chainId: null,
    sessionId: 'session', clientApp: 'official-sdk',
  });
  assert.equal(payload.client_app, 'official-sdk');
  const originalFetch = globalThis.fetch;
  let posted;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, 'http://127.0.0.1:54321/gateway/mcp/authorize');
    posted = JSON.parse(options.body);
    return { ok: true, text: async () => JSON.stringify({ decision: 'allow' }) };
  };
  try {
    const client = new HawkGatewayClient({ apiUrl: 'http://127.0.0.1:54321', tenantId: 'tenant', accessToken: 'owner' });
    assert.deepEqual(await client.authorize(payload), { decision: 'allow' });
  } finally { globalThis.fetch = originalFetch; }
  const { client_app: ignored, ...expected } = payload;
  assert.deepEqual(posted, expected);
  assert.equal(Object.hasOwn(posted, 'client_app'), false);
  for (const key of ['ai_system_id', 'actor_id', 'capability_token', 'action', 'resource', 'tool_name', 'tool_usage_meta', 'session_id'])
    assert.ok(Object.hasOwn(posted, key), key);
});

test('HTTP errors expose only a fixed reason, bounded status, and valid correlation ID', async () => {
  const originalFetch = globalThis.fetch;
  const secret = 'private-token-and-backend-message';
  const cases = [
    [401, 'unauthenticated'], [403, 'forbidden'], [404, 'not_found'],
    [409, 'conflict'], [422, 'request_schema_invalid'], [429, 'rate_limited'],
    [500, 'internal_error'], [503, 'service_unavailable'], [418, 'http_error'],
  ];
  try {
    for (const [status, reason] of cases) {
      globalThis.fetch = async () => ({ ok: false, status, headers: { get: () => '123e4567-e89b-42d3-a456-426614174000' }, text: async () => JSON.stringify({ detail: { message: secret, reason_code: secret } }) });
      const client = new HawkGatewayClient({ apiUrl: 'http://127.0.0.1:1', tenantId: 'tenant', accessToken: secret });
      await assert.rejects(client.authorize({ client_app: 'official-sdk' }), error => {
        assert.ok(error instanceof HawkGatewayError);
        assert.deepEqual([error.httpStatus, error.reasonCode, error.correlationId], [status, reason, '123e4567-e89b-42d3-a456-426614174000']);
        assert.equal(JSON.stringify(error).includes(secret), false);
        assert.equal(error.message, 'Hawk gateway request failed');
        return true;
      });
    }
    globalThis.fetch = async () => ({ ok: false, status: 422, headers: { get: () => secret }, text: async () => '{malformed' });
    await assert.rejects(new HawkGatewayClient({ apiUrl: 'http://127.0.0.1:1', tenantId: 'tenant', accessToken: secret }).authorize({}), error => {
      assert.equal(error.reasonCode, 'request_schema_invalid');
      assert.equal(error.correlationId, null);
      return true;
    });
  } finally { globalThis.fetch = originalFetch; }
  assert.equal(safeHawkReason(403, { detail: { reason_code: 'agent_session_revoked' } }), 'agent_session_revoked');
});

test('network and timeout errors stay generic and never retain backend messages', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => { throw new Error('private network secret'); };
    await assert.rejects(new HawkGatewayClient({ apiUrl: 'http://127.0.0.1:1', tenantId: 'tenant', accessToken: 'token' }).authorize({}), error => {
      assert.equal(error.reasonCode, 'transport_error');
      assert.equal(error.httpStatus, null);
      assert.equal(JSON.stringify(error).includes('private'), false);
      return true;
    });
    globalThis.fetch = async (_url, options) => { options.signal.throwIfAborted(); throw new DOMException('private timeout', 'AbortError'); };
    await assert.rejects(new HawkGatewayClient({ apiUrl: 'http://127.0.0.1:1', tenantId: 'tenant', accessToken: 'token' }).authorize({}), HawkGatewayError);
  } finally { globalThis.fetch = originalFetch; }
});
