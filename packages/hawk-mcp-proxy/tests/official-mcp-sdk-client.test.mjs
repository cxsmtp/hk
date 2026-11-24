import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, chmodSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { McpError } from '@modelcontextprotocol/sdk/types.js';
import { classifyCallError, exactMarkerSchema, safeResult, validatePrivateConfig } from '../examples/manual-terminal/official-mcp-sdk-client.mjs';
import { READ_TOOL, handleReadOnlyRequest } from '../examples/manual-terminal/read-only-mcp-server.mjs';
import { classifyToolCall } from '../src/policy.mjs';

const schema = { type: 'object', properties: { note: { type: 'string', maxLength: 64 } }, required: ['note'], additionalProperties: false };

test('only the exact synthetic tool schema is accepted', () => {
  assert.equal(exactMarkerSchema(schema), true);
  for (const wrong of [
    { ...schema, required: [] },
    { ...schema, additionalProperties: true },
    { ...schema, properties: { note: { type: 'string', maxLength: 128 } } },
    { ...schema, properties: { ...schema.properties, path: { type: 'string' } } },
  ]) assert.equal(exactMarkerSchema(wrong), false);
});

test('private config and one synthetic note are required without exposing secrets', () => {
  const root = mkdtempSync('/private/tmp/hawk-sdk-unit-');
  const path = join(root, 'private.json');
  try {
    writeFileSync(path, JSON.stringify({ mcpServers: { hawk_lab: { command: '/usr/bin/node', args: ['proxy', '--allowed-tools', 'read_demo_marker'], env: { HAWK_ACCESS_TOKEN: 'private-token' } } } }));
    chmodSync(path, 0o600);
    const server = validatePrivateConfig(path, 'synthetic-marker');
    assert.equal(server.args.at(-1), 'read_demo_marker');
    assert.throws(() => validatePrivateConfig(path, 'secret content with spaces'), /invalid_private_input/);
    chmodSync(path, 0o644);
    assert.throws(() => validatePrivateConfig(path, 'synthetic-marker'), /private_config_permissions_invalid/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('safe output has only fixed facts and no content', () => {
  const facts = safeResult({ connected: true, advertised: true, schemaExact: true, callStatus: 'returned', isError: false });
  assert.deepEqual(Object.keys(facts), ['client', 'client_version', 'connected', 'exact_tool_advertised', 'exact_schema', 'call_status', 'is_error', 'mcp_error_code', 'reason_token']);
  assert.equal(facts.client_version, '1.29.0');
  assert.throws(() => safeResult({ connected: true, advertised: true, schemaExact: true, callStatus: 'other', isError: false }), /safe_result_invalid/);
});

test('MCP errors reveal only a bounded numeric code and fixed data-derived token', () => {
  const secret = 'private-token-and-raw-tool-contents';
  const blocked = classifyCallError(new McpError(-32001, secret, { 'ai.hawk/governance': { decision: 'block', secret } }));
  assert.deepEqual(blocked, { mcp_error_code: -32001, reason_token: 'hawk_block' });
  assert.equal(JSON.stringify(blocked).includes(secret), false);
  const unknown = classifyCallError(new McpError(-32001, secret, { unknown: secret }));
  assert.deepEqual(unknown, { mcp_error_code: -32001, reason_token: 'other' });
  assert.deepEqual(classifyCallError(new Error(secret)), { mcp_error_code: null, reason_token: 'non_mcp_error' });
});

test('synthetic read tool returns a fixed value and original write remains high risk', () => {
  assert.equal(READ_TOOL.name, 'read_demo_marker');
  assert.equal(exactMarkerSchema(READ_TOOL.inputSchema), true);
  assert.equal(classifyToolCall({ mcpServerId: 'manual-terminal-lab', toolName: READ_TOOL.name, argumentsObject: { note: 'synthetic' } }).action, 'file_read');
  assert.equal(classifyToolCall({ mcpServerId: 'manual-terminal-lab', toolName: 'write_demo_marker', argumentsObject: { note: 'synthetic' } }).action, 'file_write');
  const call = { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: READ_TOOL.name, arguments: { note: 'synthetic' } } };
  const response = handleReadOnlyRequest(call);
  assert.deepEqual(response.result, { content: [{ type: 'text', text: 'Hawk fixed synthetic read-only value' }], isError: false });
  assert.equal(handleReadOnlyRequest({ ...call, params: { name: 'write_demo_marker', arguments: { note: 'synthetic' } } }).error.code, -32602);
});
