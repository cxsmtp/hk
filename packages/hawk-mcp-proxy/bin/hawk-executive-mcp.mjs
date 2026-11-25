#!/usr/bin/env node
import process from "node:process";

import { ExecutiveApiClient } from "../src/executive-api-client.mjs";
import { ExecutiveMcpServer } from "../src/executive-mcp-server.mjs";
import { normalizeMcpStdioFraming } from "../src/framing.mjs";

const options = parseArgs(process.argv.slice(2));

if (options.help) {
  console.error("Usage: hawk-executive-mcp [--gateway URL --tenant ID --token TOKEN] [--stdio-framing ndjson|content-length]");
  process.exit(0);
}

let framing;
try {
  framing = normalizeMcpStdioFraming(
    options["stdio-framing"] || process.env.HAWK_EXEC_MCP_STDIO_FRAMING || process.env.HAWK_MCP_STDIO_FRAMING || "ndjson",
  );
} catch {
  console.error("Invalid MCP stdio framing mode; use ndjson or content-length");
  process.exit(2);
}

try {
  const client = new ExecutiveApiClient({
    apiUrl: options.gateway || process.env.HAWK_EXEC_API_URL || process.env.HAWK_API_URL,
    tenantId: options.tenant || process.env.HAWK_EXEC_TENANT_ID || process.env.HAWK_TENANT_ID,
    accessToken: options.token || process.env.HAWK_EXEC_ACCESS_TOKEN || process.env.HAWK_ACCESS_TOKEN,
  });
  new ExecutiveMcpServer({ client, framing }).start();
} catch (error) {
  console.error(String(error?.message || error));
  process.exit(2);
}

function parseArgs(args) {
  const parsed = {};
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!arg.startsWith("--")) {
      continue;
    }
    const key = arg.slice(2);
    const next = args[i + 1];
    if (next && !next.startsWith("--")) {
      parsed[key] = next;
      i += 1;
    } else {
      parsed[key] = "true";
    }
  }
  return parsed;
}
