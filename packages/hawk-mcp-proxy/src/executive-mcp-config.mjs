import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const DEFAULT_EXECUTIVE_MCP_NAME = "trinya-executive";
export const DEFAULT_API_URL = "https://api.hawk.localhost:3443";
export const DEFAULT_NODE_PATH = "/usr/local/bin/node";

export function buildExecutiveMcpArgs({
  repoRoot,
  apiUrl = DEFAULT_API_URL,
  tenantId,
  accessToken,
  framing = "content-length",
} = {}) {
  const root = String(repoRoot || process.cwd()).replace(/\/+$/, "");
  const tenant = required("tenantId", tenantId);
  const token = required("accessToken", accessToken);
  return [
    path.join(root, "packages/hawk-mcp-proxy/bin/trinya-executive-mcp.mjs"),
    "--gateway",
    String(apiUrl || DEFAULT_API_URL).replace(/\/+$/, ""),
    "--tenant",
    tenant,
    "--token",
    token,
    "--stdio-framing",
    framing,
  ];
}

export function buildClaudeDesktopConfig({
  existing = {},
  repoRoot,
  apiUrl,
  tenantId,
  accessToken,
  nodePath = DEFAULT_NODE_PATH,
  serverName = DEFAULT_EXECUTIVE_MCP_NAME,
  framing = "content-length",
} = {}) {
  const args = buildExecutiveMcpArgs({ repoRoot, apiUrl, tenantId, accessToken, framing });
  return {
    ...existing,
    mcpServers: {
      ...(existing?.mcpServers || {}),
      [serverName]: {
        command: nodePath,
        args,
      },
    },
  };
}

export function buildCodexTomlBlock({
  repoRoot,
  apiUrl,
  tenantId,
  accessToken,
  nodePath = DEFAULT_NODE_PATH,
  serverName = DEFAULT_EXECUTIVE_MCP_NAME,
  framing = "content-length",
} = {}) {
  const args = buildExecutiveMcpArgs({ repoRoot, apiUrl, tenantId, accessToken, framing });
  return [
    `[mcp_servers.${quoteTomlKey(serverName)}]`,
    `command = ${tomlString(nodePath)}`,
    "args = [",
    ...args.map((arg) => `  ${tomlString(arg)},`),
    "]",
    "",
  ].join("\n");
}

export function upsertCodexMcpServerBlock(configText, { serverName = DEFAULT_EXECUTIVE_MCP_NAME, block } = {}) {
  const header = `[mcp_servers.${quoteTomlKey(serverName)}]`;
  const escapedHeader = escapeRegExp(header);
  const pattern = new RegExp(`(?:^|\\n)${escapedHeader}\\n[\\s\\S]*?(?=\\n\\[|$)`);
  const normalizedBlock = String(block || "").replace(/\s+$/, "") + "\n";
  if (pattern.test(configText)) {
    return String(configText).replace(pattern, (match) => {
      const prefix = match.startsWith("\n") ? "\n" : "";
      return prefix + normalizedBlock;
    });
  }
  const trimmed = String(configText || "").replace(/\s+$/, "");
  return `${trimmed}${trimmed ? "\n\n" : ""}${normalizedBlock}`;
}

export function writeExecutiveMcpConfigs({
  codexConfigPath = path.join(os.homedir(), ".codex/config.toml"),
  claudeConfigPath = path.join(os.homedir(), "Library/Application Support/Claude/claude_desktop_config.json"),
  repoRoot,
  apiUrl,
  tenantId,
  accessToken,
  nodePath = DEFAULT_NODE_PATH,
  serverName = DEFAULT_EXECUTIVE_MCP_NAME,
  framing = "content-length",
} = {}) {
  const timestamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  const backups = [];

  const codexBlock = buildCodexTomlBlock({
    repoRoot,
    apiUrl,
    tenantId,
    accessToken,
    nodePath,
    serverName,
    framing,
  });
  const existingCodex = readOptionalText(codexConfigPath);
  if (existingCodex !== null) {
    const backup = `${codexConfigPath}.trinya-executive-${timestamp}.backup`;
    fs.copyFileSync(codexConfigPath, backup);
    backups.push(backup);
  }
  fs.mkdirSync(path.dirname(codexConfigPath), { recursive: true });
  fs.writeFileSync(
    codexConfigPath,
    upsertCodexMcpServerBlock(existingCodex || "", { serverName, block: codexBlock }),
    "utf8",
  );

  const existingClaude = readOptionalJson(claudeConfigPath) || {};
  if (fs.existsSync(claudeConfigPath)) {
    const backup = `${claudeConfigPath}.trinya-executive-${timestamp}.backup`;
    fs.copyFileSync(claudeConfigPath, backup);
    backups.push(backup);
  }
  fs.mkdirSync(path.dirname(claudeConfigPath), { recursive: true });
  fs.writeFileSync(
    claudeConfigPath,
    JSON.stringify(
      buildClaudeDesktopConfig({
        existing: existingClaude,
        repoRoot,
        apiUrl,
        tenantId,
        accessToken,
        nodePath,
        serverName,
        framing,
      }),
      null,
      2,
    ) + "\n",
    "utf8",
  );

  return {
    serverName,
    codexConfigPath,
    claudeConfigPath,
    backups,
  };
}

function readOptionalText(filePath) {
  try {
    return fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      return null;
    }
    throw error;
  }
}

function readOptionalJson(filePath) {
  const text = readOptionalText(filePath);
  if (text === null || !text.trim()) {
    return null;
  }
  return JSON.parse(text);
}

function quoteTomlKey(value) {
  return JSON.stringify(String(value || DEFAULT_EXECUTIVE_MCP_NAME));
}

function tomlString(value) {
  return JSON.stringify(String(value ?? ""));
}

function required(name, value) {
  const text = String(value || "").trim();
  if (!text) {
    throw new Error(`Executive MCP setup requires ${name}`);
  }
  return text;
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
