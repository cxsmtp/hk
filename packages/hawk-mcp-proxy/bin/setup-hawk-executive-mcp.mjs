#!/usr/bin/env node
import { createInterface } from "node:readline/promises";
import process from "node:process";

import { writeExecutiveMcpConfigs } from "../src/executive-mcp-config.mjs";

const options = parseArgs(process.argv.slice(2));

if (options.help) {
  printUsage();
  process.exit(0);
}

try {
  if (options["insecure-local-tls"] === "true") {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  }

  const apiUrl = String(options.api || process.env.HAWK_EXEC_API_URL || "https://api.hawk.localhost:3443").replace(/\/+$/, "");
  const repoRoot = options.repo || process.env.HAWK_EXEC_REPO_ROOT || process.cwd();
  const nodePath = options.node || process.env.HAWK_EXEC_NODE_PATH || "/usr/local/bin/node";
  const tenantId = options.tenant || process.env.HAWK_EXEC_TENANT_ID;
  const accessToken = options.token || process.env.HAWK_EXEC_ACCESS_TOKEN;

  const credentials = tenantId && accessToken
    ? { tenantId, accessToken }
    : await loginForToken({ apiUrl });

  const result = writeExecutiveMcpConfigs({
    repoRoot,
    apiUrl,
    nodePath,
    tenantId: credentials.tenantId,
    accessToken: credentials.accessToken,
    framing: options.framing || "content-length",
  });

  console.log(JSON.stringify({
    status: "configured",
    server: result.serverName,
    codex_config: result.codexConfigPath,
    claude_config: result.claudeConfigPath,
    backups: result.backups,
    restart_required: ["Restart Codex Desktop", "Restart Claude Desktop"],
    test_prompts: buildTestPrompts(),
  }, null, 2));
} catch (error) {
  console.error(String(error?.message || error));
  process.exit(1);
}

async function loginForToken({ apiUrl }) {
  const terminal = createInterface({ input: process.stdin, output: process.stderr });
  try {
    const email = (await terminal.question("Hawk owner/admin email: ")).trim();
    const password = await hiddenQuestion(terminal, "Hawk password: ");
    const response = await fetch(`${apiUrl}/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const body = await response.text();
    let parsed;
    try {
      parsed = body ? JSON.parse(body) : {};
    } catch {
      parsed = { detail: body.slice(0, 1000) };
    }
    if (!response.ok) {
      throw new Error(`Login failed (${response.status}): ${stringifyDetail(parsed.detail || parsed)}`);
    }
    const tenantId = parsed.selected_tenant_id || parsed.tenants?.[0]?.id;
    const accessToken = parsed.access_token;
    if (!tenantId || !accessToken) {
      throw new Error("Login succeeded but did not return tenant/access token");
    }
    return { tenantId, accessToken };
  } finally {
    terminal.close();
  }
}

async function hiddenQuestion(terminal, prompt) {
  const originalWrite = terminal._writeToOutput?.bind(terminal);
  if (!originalWrite) {
    return terminal.question(prompt);
  }

  terminal._writeToOutput = function writeMasked(value) {
    if (terminal.stdoutMuted) {
      terminal.output.write("*");
      return;
    }
    originalWrite(value);
  };

  try {
    const pending = terminal.question(prompt);
    terminal.stdoutMuted = true;
    const answer = await pending;
    process.stderr.write("\n");
    return answer;
  } finally {
    terminal.stdoutMuted = false;
    terminal._writeToOutput = originalWrite;
  }
}

function buildTestPrompts() {
  return {
    claude_or_codex_summary:
      "Use the Hawk Executive MCP to get an executive summary for the last 30 days. Return only the summary and mention which MCP tool was used.",
    blocked_actions:
      "Use the Hawk Executive MCP to query executive metrics for blocked actions grouped by application for the last 30 days. Return the top 10 rows and mention which MCP tool was used.",
    github_visibility:
      "Use the Hawk Executive MCP to query executive metrics for github_repositories for the last 30 days. Return repositories, AI tools involved, and policy decision summary if present.",
    tokens_and_spend:
      "Use the Hawk Executive MCP to query tokens, then spend, for the last 30 days. Explain whether the values are provider-reported, estimated, or unavailable.",
    presentation:
      "Use the Hawk Executive MCP to create an executive presentation titled 'AI Governance Executive Brief' for the last 30 days. Return the generated file path and do not include raw prompts.",
  };
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

function stringifyDetail(detail) {
  if (typeof detail === "string") {
    return detail;
  }
  try {
    return JSON.stringify(detail);
  } catch {
    return "request failed";
  }
}

function printUsage() {
  console.log(`Usage:
  setup-hawk-executive-mcp [--api URL] [--repo PATH] [--tenant ID --token TOKEN]

Examples:
  node packages/hawk-mcp-proxy/bin/setup-hawk-executive-mcp.mjs --insecure-local-tls
  node packages/hawk-mcp-proxy/bin/setup-hawk-executive-mcp.mjs --tenant "$HAWK_EXEC_TENANT_ID" --token "$HAWK_EXEC_ACCESS_TOKEN"
`);
}
