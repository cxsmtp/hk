#!/usr/bin/env node
// Synthetic read-only MCP fixture. The optional lab event log records call counts only.
import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { createMcpMessageFramer, encodeMcpMessage, normalizeMcpStdioFraming } from '../../src/framing.mjs';

export const READ_TOOL = Object.freeze({
  name: 'read_demo_marker', version: '1.0.0',
  description: 'Return a fixed synthetic read-only value without reading or changing customer data.',
  inputSchema: { type: 'object', properties: { note: { type: 'string', maxLength: 64 } }, required: ['note'], additionalProperties: false },
  examples: [{ note: 'synthetic-read' }],
});
export const SERVER_ID = 'manual-terminal-lab';

export function handleReadOnlyRequest(message) {
  const id = message?.id ?? null;
  if (message?.method === 'initialize') return { jsonrpc: '2.0', id, result: { protocolVersion: '2025-06-18', capabilities: { tools: {} }, serverInfo: { name: SERVER_ID, version: '1.0.0' } } };
  if (message?.method === 'notifications/initialized') return null;
  if (message?.method === 'tools/list') return { jsonrpc: '2.0', id, result: { tools: [structuredClone(READ_TOOL)] } };
  if (message?.method === 'tools/call') {
    const args = message?.params?.arguments;
    if (message?.params?.name !== READ_TOOL.name || !args || Object.keys(args).length !== 1 || typeof args.note !== 'string' || !args.note.trim() || args.note.length > 64)
      return { jsonrpc: '2.0', id, error: { code: -32602, message: 'Invalid synthetic read parameters' } };
    return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'Hawk fixed synthetic read-only value' }], isError: false } };
  }
  return id === null ? null : { jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } };
}

export function startReadOnlyServer({ input = process.stdin, output = process.stdout, stderr = process.stderr, labDir = process.env.HAWK_MCP_LAB_DIR, stdioFraming = process.env.HAWK_MCP_STDIO_FRAMING || 'content-length' } = {}) {
  const resolved = path.resolve(String(labDir || ''));
  if (resolved !== labDir || !resolved.startsWith('/private/tmp/hawk-mcp-terminal-lab-') || resolved.includes('..')) throw new Error('Invalid private lab directory');
  const framing = normalizeMcpStdioFraming(stdioFraming);
  const framer = createMcpMessageFramer(framing);
  let queue = Promise.resolve();
  framer.onMessage(message => {
    queue = queue.then(async () => {
      if (message?.method === 'tools/call') {
        await mkdir(resolved, { recursive: true });
        await appendFile(path.join(resolved, 'child-events.ndjson'), `${JSON.stringify({ method: 'tools/call' })}\n`, 'utf8');
      }
      const response = handleReadOnlyRequest(message);
      if (response) output.write(encodeMcpMessage(response, framing));
    }).catch(() => {
      stderr.write('Synthetic read-only MCP child failed safely\n');
      if (message?.id !== undefined) output.write(encodeMcpMessage({ jsonrpc: '2.0', id: message.id, error: { code: -32000, message: 'Synthetic MCP child failed safely' } }, framing));
    });
  });
  input.on('data', chunk => { try { framer.push(chunk); } catch { stderr.write('Synthetic MCP framing failed safely\n'); } });
  input.on('end', () => { try { framer.end(); } catch { stderr.write('Synthetic MCP framing failed safely\n'); } });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === '--print-contract') process.stdout.write(`${JSON.stringify({ mcpServerId: SERVER_ID, tool: READ_TOOL })}\n`);
  else startReadOnlyServer();
}
