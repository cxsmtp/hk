#!/usr/bin/env node
import path from "node:path";
import process from "node:process";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";

import {
  cleanupLabDirectory,
  runManualMcpScenario,
} from "./manual-mcp-client-core.mjs";
import { resolveLabDirectory } from "./manual-mcp-server.mjs";

export function usageText() {
  return [
    "Usage:",
    "  npm --prefix packages/hawk-mcp-proxy run manual:mcp",
    "  npm --prefix packages/hawk-mcp-proxy run manual:mcp -- --help",
    "  npm --prefix packages/hawk-mcp-proxy run manual:mcp:cleanup -- --lab-dir /private/tmp/hawk-mcp-terminal-lab-RUN_ID",
    "  node examples/manual-terminal/manual-mcp-client.mjs cleanup --lab-dir /private/tmp/hawk-mcp-terminal-lab-RUN_ID",
    "",
    "Required environment variables:",
    "  HAWK_API_URL",
    "  HAWK_TENANT_ID",
    "  HAWK_ACCESS_TOKEN",
    "  HAWK_AI_SYSTEM_ID",
  ].join("\n");
}

export function parseClientArgs(args) {
  if (!args.length) {
    return { command: "run" };
  }
  if (args.length === 1 && ["--help", "-h"].includes(args[0])) {
    return { command: "help" };
  }
  if (
    args.length === 3
    && args[0] === "cleanup"
    && args[1] === "--lab-dir"
    && args[2]
  ) {
    return { command: "cleanup", labDir: args[2] };
  }
  throw new Error(usageText());
}

export async function main({
  args = process.argv.slice(2),
  env = process.env,
  input = process.stdin,
  output = process.stdout,
} = {}) {
  const parsed = parseClientArgs(args);
  if (parsed.command === "help") {
    output.write(`${usageText()}\n`);
    return 0;
  }
  if (parsed.command === "cleanup") {
    const labDir = resolveLabDirectory(parsed.labDir);
    output.write(`Cleaning lab directory: ${labDir}\n`);
    await cleanupLabDirectory(labDir);
    output.write("Cleanup complete\n");
    return 0;
  }

  const readline = createInterface({ input, output });
  try {
    const result = await runManualMcpScenario({
      env,
      readLine: () => readline.question(""),
      stdout: output,
    });
    return result.exitCode;
  } finally {
    readline.close();
  }
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    process.exitCode = await main();
  } catch {
    process.stderr.write("Manual MCP lab failed safely\n");
    process.exitCode = 2;
  }
}
