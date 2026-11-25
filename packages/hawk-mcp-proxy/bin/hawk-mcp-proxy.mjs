#!/usr/bin/env node
import process from "node:process";

import { HawkEndpointClient } from "../src/endpoint-client.mjs";
import { normalizeMcpStdioFraming } from "../src/framing.mjs";
import { HawkGatewayClient } from "../src/hawk-client.mjs";
import { HawkMcpProxy } from "../src/proxy.mjs";

const parsed = parseArgs(process.argv.slice(2));

if (parsed.options.help || !parsed.childCommand) {
  console.error("Usage: hawk-mcp-proxy [--endpoint-socket PATH --endpoint-device-thumbprint SHA256 | --gateway URL --tenant ID --token TOKEN] [--ai-system-id ID] [--actor-id USER] [--server-id ID] [--server-url HTTP(S)-URL] [--repository-scope github.com/owner/repository] [--client-app NAME] [--stdio-framing ndjson|content-length] [--allowed-tools comma,separated,names] [--pass-env NAME[,NAME]] -- <mcp command> [args...]");
  if (parsed.options.help) {
    process.exit(0);
  }
  process.exit(2);
}

let stdioFraming;
try {
  stdioFraming = normalizeMcpStdioFraming(
    parsed.options["stdio-framing"] || process.env.HAWK_MCP_STDIO_FRAMING || "ndjson",
  );
} catch {
  console.error("Invalid MCP stdio framing mode; use ndjson or content-length");
  process.exit(2);
}

const endpointSocket = parsed.options["endpoint-socket"] || process.env.HAWK_ENDPOINT_SOCKET;
const endpointDeviceThumbprint = String(
  parsed.options["endpoint-device-thumbprint"]
  || process.env.HAWK_ENDPOINT_DEVICE_THUMBPRINT
  || "",
).trim().toLowerCase();
if (endpointSocket && !/^[0-9a-f]{64}$/.test(endpointDeviceThumbprint)) {
  console.error("A managed endpoint device-key thumbprint is required in endpoint mode");
  process.exit(2);
}
const hawkClient = endpointSocket
  ? new HawkEndpointClient({
      socketPath: endpointSocket,
      trustedDeviceThumbprint: endpointDeviceThumbprint,
      timeoutMs: process.env.HAWK_ENDPOINT_TIMEOUT_MS,
      maxRequestBytes: process.env.HAWK_ENDPOINT_MAX_REQUEST_BYTES,
      maxResponseBytes: process.env.HAWK_ENDPOINT_MAX_RESPONSE_BYTES,
    })
  : new HawkGatewayClient({
      apiUrl: parsed.options.gateway || process.env.HAWK_API_URL,
      tenantId: parsed.options.tenant || process.env.HAWK_TENANT_ID,
      accessToken: parsed.options.token || process.env.HAWK_ACCESS_TOKEN,
    });
let proxy;
try {
  proxy = new HawkMcpProxy({
    childCommand: parsed.childCommand,
    childArgs: parsed.childArgs,
    hawkClient,
    aiSystemId: parsed.options["ai-system-id"] || process.env.HAWK_AI_SYSTEM_ID,
    actorId: parsed.options["actor-id"]
      || process.env.HAWK_ACTOR_ID
      || (endpointSocket ? undefined : "unknown"),
    capabilityToken: parsed.options["capability-token"] || process.env.HAWK_CAPABILITY_TOKEN || "mcp-client",
    mcpServerId: parsed.options["server-id"] || process.env.HAWK_MCP_SERVER_ID || "unknown-mcp-server",
    repositoryScope: parsed.options["repository-scope"] || process.env.HAWK_GITHUB_REPOSITORY_SCOPE || null,
    chainId: parsed.options["chain-id"] || process.env.HAWK_CHAIN_ID || null,
    sessionId: parsed.options["session-id"] || process.env.HAWK_SESSION_ID || null,
    clientApp: parsed.options["client-app"] || process.env.HAWK_MCP_CLIENT_APP || null,
    mcpServerUrl: parsed.options["server-url"] || process.env.HAWK_MCP_SERVER_URL || null,
    stdioFraming,
    scanDeadlineMs: process.env.HAWK_MCP_SCAN_DEADLINE_MS,
    allowedTools: parsed.options["allowed-tools"] || process.env.HAWK_MCP_ALLOWED_TOOLS || null,
    resultInspectionEnabled: process.env.HAWK_MCP_RESULT_INSPECTION_ENABLED === "true",
    resultInspectionMaxBytes: process.env.HAWK_MCP_RESULT_INSPECTION_MAX_BYTES,
    // The MCP server gets only a minimal environment (src/proxy.mjs CHILD_ENVIRONMENT_ALLOWLIST) and the variables
    // named here, such as the API key it needs. Hawk's own tokens can never be named.
    passEnv: [parsed.options["pass-env"], process.env.HAWK_MCP_PASS_ENV].filter(Boolean).join(","),
  });
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(2);
}

proxy.start();

function parseArgs(args) {
  const options = {};
  const separator = args.indexOf("--");
  const optionArgs = separator === -1 ? args : args.slice(0, separator);
  const childArgs = separator === -1 ? [] : args.slice(separator + 1);

  for (let i = 0; i < optionArgs.length; i += 1) {
    const arg = optionArgs[i];
    if (!arg.startsWith("--")) {
      continue;
    }
    const key = arg.slice(2);
    const next = optionArgs[i + 1];
    if (next && !next.startsWith("--")) {
      options[key] = next;
      i += 1;
    } else {
      options[key] = "true";
    }
  }

  return {
    options,
    childCommand: childArgs[0],
    childArgs: childArgs.slice(1),
  };
}
