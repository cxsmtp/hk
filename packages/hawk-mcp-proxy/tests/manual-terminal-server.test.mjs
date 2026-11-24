import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { PassThrough } from "node:stream";

import {
  encodeNdjsonMcpMessage,
  NdjsonMcpMessageFramer,
} from "../src/framing.mjs";

import {
  DEMO_TOOL_NAME,
  handleDemoRequest,
  resolveLabDirectory,
  startDemoServer,
  toolContract,
} from "../examples/manual-terminal/manual-mcp-server.mjs";

test("manual MCP child supports NDJSON for Codex", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-test-");
  const input = new PassThrough();
  const output = new PassThrough();
  const responseFramer = new NdjsonMcpMessageFramer();
  const messages = [];
  responseFramer.onMessage((message) => messages.push(message));
  output.on("data", (chunk) => responseFramer.push(chunk));

  try {
    startDemoServer({ input, output, labDir, stdioFraming: "ndjson" });
    input.write(encodeNdjsonMcpMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {},
    }));
    input.write(encodeNdjsonMcpMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
    }));

    await waitFor(() => messages.length === 2);
    assert.equal(messages[0].result.serverInfo.name, "manual-terminal-lab");
    assert.equal(messages[1].result.tools[0].name, DEMO_TOOL_NAME);
  } finally {
    input.end();
    await rm(labDir, { recursive: true });
  }
});

test("manual MCP server exposes one fixed write tool", () => {
  assert.equal(toolContract.mcpServerId, "manual-terminal-lab");
  assert.equal(toolContract.tool.name, DEMO_TOOL_NAME);
  assert.equal(toolContract.tool.version, "1.0.0");
  assert.equal(toolContract.tool.inputSchema.additionalProperties, false);
});

test("manual MCP server accepts only an explicit /private/tmp lab directory", () => {
  assert.equal(
    resolveLabDirectory("/private/tmp/hawk-mcp-terminal-lab-test"),
    "/private/tmp/hawk-mcp-terminal-lab-test",
  );
  for (const unsafe of [
    ".",
    "/tmp/not-hawk",
    "/private/tmp/hawk-mcp-terminal-lab-../escape",
  ]) {
    assert.throws(
      () => resolveLabDirectory(unsafe),
      /Invalid Hawk MCP lab directory/,
    );
  }
});

test("marker is absent after list and present only after tools/call", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-test-");
  try {
    const list = await handleDemoRequest(
      { jsonrpc: "2.0", id: 1, method: "tools/list" },
      { labDir },
    );
    assert.equal(list.result.tools.length, 1);
    await assert.rejects(stat(`${labDir}/tool-call-received.json`));
    await assert.rejects(stat(`${labDir}/marker.json`));

    const call = await handleDemoRequest({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: {
        name: DEMO_TOOL_NAME,
        arguments: { note: "CISO manual proof" },
      },
    }, { labDir });
    assert.equal(call.result.isError, false);
    assert.equal(
      JSON.parse(await readFile(`${labDir}/marker.json`, "utf8")).note,
      "CISO manual proof",
    );
  } finally {
    await rm(labDir, { recursive: true });
  }
});

test("manual MCP server rejects unsafe tool-call inputs without writing", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-test-");
  try {
    for (const params of [
      { name: "unknown_tool", arguments: { note: "CISO manual proof" } },
      { name: DEMO_TOOL_NAME, arguments: { note: "" } },
      { name: DEMO_TOOL_NAME, arguments: { note: "x".repeat(65) } },
      { name: DEMO_TOOL_NAME, arguments: { note: 7 } },
    ]) {
      const response = await handleDemoRequest(
        { jsonrpc: "2.0", id: 3, method: "tools/call", params },
        { labDir },
      );
      assert.equal(response.error.code, -32602);
    }
    await assert.rejects(stat(`${labDir}/marker.json`));
  } finally {
    await rm(labDir, { recursive: true });
  }
});

async function waitFor(predicate, timeoutMs = 250) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("Timed out waiting for manual MCP child response");
}
