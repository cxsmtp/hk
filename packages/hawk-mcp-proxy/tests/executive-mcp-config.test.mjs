import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  buildClaudeDesktopConfig,
  buildCodexTomlBlock,
  upsertCodexMcpServerBlock,
  writeExecutiveMcpConfigs,
} from "../src/executive-mcp-config.mjs";

const REPO_ROOT = "/Volumes/X10 Pro/New project/repo";

test("executive MCP config preserves existing Claude servers and adds Trinya executive", () => {
  const config = buildClaudeDesktopConfig({
    existing: {
      mcpServers: {
        "existing-github": { command: "node", args: ["server.mjs"] },
      },
      preferences: { theme: "dark" },
    },
    repoRoot: REPO_ROOT,
    tenantId: "tenant-1",
    accessToken: "token-1",
  });

  assert.equal(config.preferences.theme, "dark");
  assert.equal(config.mcpServers["existing-github"].command, "node");
  assert.equal(config.mcpServers["trinya-executive"].command, "/usr/local/bin/node");
  assert.deepEqual(config.mcpServers["trinya-executive"].args.slice(-2), ["--stdio-framing", "content-length"]);
  assert.ok(config.mcpServers["trinya-executive"].args[0].endsWith("trinya-executive-mcp.mjs"));
});

test("executive MCP config upserts one Codex server block", () => {
  const block = buildCodexTomlBlock({
    repoRoot: REPO_ROOT,
    tenantId: "tenant-1",
    accessToken: "token-1",
  });
  const first = upsertCodexMcpServerBlock('model = "gpt-5"\n', { block });
  const second = upsertCodexMcpServerBlock(first, { block: block.replace("token-1", "token-2") });

  assert.equal((second.match(/\[mcp_servers\."trinya-executive"\]/g) || []).length, 1);
  assert.match(second, /token-2/);
  assert.doesNotMatch(second, /token-1/);
  assert.match(second, /model = "gpt-5"/);
  assert.match(second, /content-length/);
});

test("executive MCP setup writes Claude and Codex configs with backups", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "trinya-exec-mcp-config-"));
  const codexConfigPath = path.join(tmp, ".codex/config.toml");
  const claudeConfigPath = path.join(tmp, "Claude/claude_desktop_config.json");
  fs.mkdirSync(path.dirname(codexConfigPath), { recursive: true });
  fs.mkdirSync(path.dirname(claudeConfigPath), { recursive: true });
  fs.writeFileSync(codexConfigPath, '[mcp_servers."old"]\ncommand = "node"\n', "utf8");
  fs.writeFileSync(claudeConfigPath, JSON.stringify({ mcpServers: { old: { command: "node", args: [] } } }), "utf8");

  const result = writeExecutiveMcpConfigs({
    codexConfigPath,
    claudeConfigPath,
    repoRoot: REPO_ROOT,
    tenantId: "tenant-1",
    accessToken: "token-1",
  });

  assert.equal(result.serverName, "trinya-executive");
  assert.equal(result.backups.length, 2);
  assert.match(fs.readFileSync(codexConfigPath, "utf8"), /\[mcp_servers\."trinya-executive"\]/);
  const claude = JSON.parse(fs.readFileSync(claudeConfigPath, "utf8"));
  assert.ok(claude.mcpServers.old);
  assert.ok(claude.mcpServers["trinya-executive"]);
});
