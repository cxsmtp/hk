#!/usr/bin/env node
// One bounded synthetic MCP call through the installed official SDK. No tool content is printed.
import { readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { McpError } from '@modelcontextprotocol/sdk/types.js';

const TOOL = 'read_demo_marker';
const VERSION = '1.29.0';
const GATEWAY_REASONS = new Set(['request_schema_invalid', 'unauthenticated', 'forbidden', 'not_found', 'conflict', 'rate_limited', 'service_unavailable', 'internal_error', 'http_error', 'transport_error', 'timeout', 'response_invalid', 'agent_session_revoked', 'agent_session_expired', 'agent_session_inactive', 'agent_session_required', 'mcp_session_authority_denied', 'governance_context_blocked', 'governance_fail_secure', 'tool_fingerprint_unapproved', 'tool_metadata_drift']);

export function exactMarkerSchema(schema) {
  return schema?.type === 'object' && schema.additionalProperties === false &&
    Array.isArray(schema.required) && schema.required.length === 1 && schema.required[0] === 'note' &&
    schema.properties && Object.keys(schema.properties).length === 1 &&
    schema.properties.note?.type === 'string' && schema.properties.note.maxLength === 64;
}

export function validatePrivateConfig(path, note) {
  if (typeof path !== 'string' || !path.startsWith('/private/tmp/') ||
      typeof note !== 'string' || !/^[a-z0-9-]{1,40}$/.test(note)) throw new Error('invalid_private_input');
  const mode = statSync(path).mode & 0o777;
  if (mode !== 0o600) throw new Error('private_config_permissions_invalid');
  const data = readFileSync(path);
  if (data.length > 16384) throw new Error('private_config_oversized');
  const config = JSON.parse(data.toString('utf8'));
  const servers = config?.mcpServers;
  if (!servers || Object.keys(servers).length !== 1 || !servers.hawk_lab) throw new Error('exact_server_required');
  const server = servers.hawk_lab;
  if (typeof server.command !== 'string' || !server.command.startsWith('/') ||
      !Array.isArray(server.args) || !server.args.every(x => typeof x === 'string') ||
      !server.args.includes('--allowed-tools') ||
      server.args[server.args.indexOf('--allowed-tools') + 1] !== TOOL ||
      typeof server.env !== 'object' || !server.env) throw new Error('private_server_config_invalid');
  return server;
}

export function classifyCallError(error) {
  if (!(error instanceof McpError)) return { mcp_error_code: null, reason_token: 'non_mcp_error' };
  const code = Number.isInteger(error.code) && error.code >= -32768 && error.code <= 32767 ? error.code : null;
  const governance = error.data && typeof error.data === 'object' && !Array.isArray(error.data)
    ? error.data['ai.hawk/governance'] : null;
  const gateway = error.data && typeof error.data === 'object' && !Array.isArray(error.data)
    ? error.data['ai.hawk/error'] : null;
  if (gateway && typeof gateway === 'object' && GATEWAY_REASONS.has(gateway.reason_code))
    return { mcp_error_code: code, reason_token: `gateway_${gateway.reason_code}` };
  const decision = governance && typeof governance === 'object' ? governance.decision : null;
  const reason = decision === 'block' ? 'hawk_block' : decision === 'hold_for_approval' ? 'hawk_hold' :
    decision === 'warn' ? 'hawk_warn' : 'other';
  return { mcp_error_code: code, reason_token: reason };
}

export function safeResult({ connected, advertised, schemaExact, callStatus, isError, mcpErrorCode = null, reasonToken = 'none' }) {
  if (typeof connected !== 'boolean' || typeof advertised !== 'boolean' ||
      typeof schemaExact !== 'boolean' || !['not_called', 'returned', 'failed'].includes(callStatus) ||
      (isError !== null && typeof isError !== 'boolean') ||
      (mcpErrorCode !== null && (!Number.isInteger(mcpErrorCode) || mcpErrorCode < -32768 || mcpErrorCode > 32767)) ||
      !(['none', 'hawk_block', 'hawk_hold', 'hawk_warn', 'other', 'non_mcp_error', 'returned_error'].includes(reasonToken) || [...GATEWAY_REASONS].some(reason => reasonToken === `gateway_${reason}`))) throw new Error('safe_result_invalid');
  return { client: 'official-mcp-typescript-sdk', client_version: VERSION, connected,
    exact_tool_advertised: advertised, exact_schema: schemaExact,
    call_status: callStatus, is_error: isError, mcp_error_code: mcpErrorCode, reason_token: reasonToken };
}

async function main() {
  const [configPath, note] = process.argv.slice(2);
  const server = validatePrivateConfig(configPath, note);
  const transport = new StdioClientTransport({
    command: server.command, args: server.args,
    env: server.env, stderr: 'ignore',
  });
  const client = new Client({ name: 'hawk-isolated-official-sdk-acceptance', version: '1.0.0' });
  let connected = false;
  let advertised = false;
  let schemaExact = false;
  let callStatus = 'not_called';
  let isError = null;
  let mcpErrorCode = null;
  let reasonToken = 'none';
  try {
    await client.connect(transport);
    connected = true;
    const listed = await client.listTools();
    if (!Array.isArray(listed?.tools)) throw new Error('tool_list_invalid');
    const exact = listed.tools.filter(tool => tool?.name === TOOL);
    advertised = exact.length === 1;
    schemaExact = advertised && exactMarkerSchema(exact[0].inputSchema);
    if (!advertised || !schemaExact) throw new Error('exact_tool_schema_missing');
    try {
      const result = await client.callTool({ name: TOOL, arguments: { note } });
      if (!result || typeof result !== 'object' || (result.isError !== undefined && typeof result.isError !== 'boolean'))
        throw new Error('tool_result_invalid');
      callStatus = 'returned';
      isError = result.isError === true;
      if (isError) reasonToken = 'returned_error';
    } catch (error) {
      callStatus = 'failed';
      isError = true;
      ({ mcp_error_code: mcpErrorCode, reason_token: reasonToken } = classifyCallError(error));
    }
  } finally {
    await client.close();
  }
  return safeResult({ connected, advertised, schemaExact, callStatus, isError, mcpErrorCode, reasonToken });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    const facts = await main();
    process.stdout.write(`${JSON.stringify(facts)}\n`);
  } catch {
    process.stdout.write(`${JSON.stringify({ status: 'blocked', reason: 'official_sdk_client_failed' })}\n`);
    process.exitCode = 2;
  }
}
