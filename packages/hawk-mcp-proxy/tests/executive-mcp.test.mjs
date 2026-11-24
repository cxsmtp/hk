import assert from "node:assert/strict";
import fs from "node:fs";
import { PassThrough } from "node:stream";
import test from "node:test";

import { createMcpMessageFramer, encodeMcpMessage } from "../src/framing.mjs";
import { ExecutiveApiClient } from "../src/executive-api-client.mjs";
import { ExecutiveMcpServer } from "../src/executive-mcp-server.mjs";

test("executive MCP lists and calls tenant summary tools", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const received = [];
  const framer = createMcpMessageFramer("ndjson");
  framer.onMessage((message) => received.push(message));
  output.on("data", (chunk) => framer.push(chunk));

  const calls = [];
  const server = new ExecutiveMcpServer({
    input,
    output,
    framing: "ndjson",
    client: {
      async getSummary(args) {
        calls.push(["summary", args]);
        return { tenant_id: "tenant-1", headline: { total_ai_actions: 7 }, raw_prompt_content_included: false };
      },
      async queryMetrics(args) {
        calls.push(["query", args]);
        return { metric: args.metric, total: 2 };
      },
      async createPresentation(args) {
        calls.push(["presentation", args]);
        return { artifact_id: "artifact-1", filename: "brief.pptx", raw_prompt_content_included: false };
      },
    },
  });
  server.start();

  input.write(encodeMcpMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, "ndjson"));
  input.write(encodeMcpMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, "ndjson"));
  input.write(
    encodeMcpMessage(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "get_executive_summary", arguments: { window_days: 7 } },
      },
      "ndjson",
    ),
  );
  await new Promise((resolve) => setTimeout(resolve, 20));

  assert.equal(received[0].result.serverInfo.name, "trinya-executive-mcp");
  assert.deepEqual(
    received[1].result.tools.map((tool) => tool.name),
    ["get_executive_summary", "query_executive_metrics", "create_executive_presentation"],
  );
  assert.equal(JSON.parse(received[2].result.content[0].text).headline.total_ai_actions, 7);
  assert.deepEqual(calls, [["summary", { windowDays: 7 }]]);
});

test("executive MCP sanitizes API errors", async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const received = [];
  const framer = createMcpMessageFramer("ndjson");
  framer.onMessage((message) => received.push(message));
  output.on("data", (chunk) => framer.push(chunk));

  const server = new ExecutiveMcpServer({
    input,
    output,
    framing: "ndjson",
    client: {
      async getSummary() {
        throw new Error("token expired SECRET_SHOULD_NOT_APPEAR".repeat(100));
      },
    },
  });
  server.start();

  input.write(
    encodeMcpMessage(
      {
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: { name: "get_executive_summary", arguments: {} },
      },
      "ndjson",
    ),
  );
  await new Promise((resolve) => setTimeout(resolve, 20));

  assert.equal(received[0].error.code, -32000);
  assert.ok(received[0].error.message.length <= 1000);
});

test("executive API client writes presentation artifacts locally", async () => {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        artifact_id: "artifact-1",
        filename: "brief.pptx",
        content_base64: Buffer.from("pptx-bytes").toString("base64"),
        raw_prompt_content_included: false,
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  try {
    const client = new ExecutiveApiClient({
      apiUrl: "https://api.example.test",
      tenantId: "tenant-1",
      accessToken: "token",
    });
    const result = await client.createPresentation({ title: "Board brief", windowDays: 7 });
    assert.equal(result.content_base64, undefined);
    assert.equal(result.filename, "brief.pptx");
    assert.ok(result.local_path.endsWith("brief.pptx"));
    assert.equal(fs.readFileSync(result.local_path, "utf8"), "pptx-bytes");
  } finally {
    globalThis.fetch = previousFetch;
  }
});
