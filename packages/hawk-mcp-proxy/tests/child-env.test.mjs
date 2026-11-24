import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { NdjsonMcpMessageFramer, encodeNdjsonMcpMessage } from "../src/framing.mjs";
import { HawkMcpProxy } from "../src/proxy.mjs";

test("endpoint CLI requires an out-of-band managed device-key pin", () => {
  const result = spawnSync(process.execPath, [
    "bin/hawk-mcp-proxy.mjs",
    "--endpoint-socket", "/private/tmp/hawk-agent.sock",
    "--", process.execPath, "-e", "",
  ], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
    env: Object.fromEntries(
      Object.entries(process.env).filter(([name]) => name !== "HAWK_ENDPOINT_DEVICE_THUMBPRINT"),
    ),
  });

  assert.equal(result.status, 2);
  assert.match(result.stderr, /device-key thumbprint is required/i);
});

const SENSITIVE_ENVIRONMENT = [
  "HAWK_ACCESS_TOKEN",
  "HAWK_CAPABILITY_TOKEN",
  "HAWK_AGENT_TOKEN",
  "HAWK_AGENT_OPERATOR_TOKEN",
  "HAWK_AGENT_REFRESH_TOKEN",
  "HAWK_ENDPOINT_SOCKET",
  "HAWK_ENDPOINT_TIMEOUT_MS",
  "HAWK_ENDPOINT_MAX_REQUEST_BYTES",
  "HAWK_ENDPOINT_MAX_RESPONSE_BYTES",
  "HAWK_AGENT_ENDPOINT_ID",
  "HAWK_AGENT_TENANT_ID",
  "HAWK_AGENT_USER_ID",
  "HAWK_AGENT_USER_EMAIL",
  "HAWK_AGENT_CONFIG",
  "HAWK_AGENT_API_URL",
  "HAWK_TENANT_ID",
  "HAWK_ACTOR_ID",
  "HAWK_AI_SYSTEM_ID",
  "HAWK_CHAIN_ID",
  "HAWK_SESSION_ID",
  "HAWK_MCP_SERVER_ID",
  "HAWK_API_URL",
];

test("gateway and endpoint proxy children never inherit Hawk secrets or endpoint identity", async (t) => {
  const saved = new Map();
  for (const name of SENSITIVE_ENVIRONMENT) {
    saved.set(name, process.env[name]);
    process.env[name] = `sensitive-${name}`;
  }
  saved.set("HAWK_MCP_LAB_DIR", process.env.HAWK_MCP_LAB_DIR);
  process.env.HAWK_MCP_LAB_DIR = "/private/tmp/hawk-child-env-safe";
  t.after(() => {
    for (const [name, value] of saved) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  const directory = await mkdtemp(join(tmpdir(), "hawk-child-env-"));
  const childPath = join(directory, "child.mjs");
  await writeFile(childPath, `
    let input = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      input += chunk;
      const newline = input.indexOf("\\n");
      if (newline === -1) return;
      const request = JSON.parse(input.slice(0, newline));
      process.stdout.write(JSON.stringify({
        jsonrpc: "2.0",
        id: request.id,
        result: { env: process.env },
      }) + "\\n");
    });
  `);

  for (const transport of ["gateway", "endpoint"]) {
    await t.test(transport, async () => {
      const input = new PassThrough();
      const output = new PassThrough();
      const messages = [];
      const framer = new NdjsonMcpMessageFramer();
      framer.onMessage((message) => messages.push(message));
      output.on("data", (chunk) => framer.push(chunk));
      const proxy = new HawkMcpProxy({
        childCommand: process.execPath,
        childArgs: [childPath],
        hawkClient: { transport },
        stdioFraming: "ndjson",
        stderr: new PassThrough(),
      });
      proxy.start({ input, output });
      try {
        input.write(encodeNdjsonMcpMessage({
          jsonrpc: "2.0",
          id: 1,
          method: "initialize",
          params: {},
        }));
        const response = await waitFor(() => messages.find((message) => message.id === 1));
        for (const name of SENSITIVE_ENVIRONMENT) {
          assert.equal(response.result.env[name], undefined, `${transport}:${name}`);
        }
        assert.equal(response.result.env.HAWK_MCP_LAB_DIR, "/private/tmp/hawk-child-env-safe");
        assert.equal(response.result.env.PATH, process.env.PATH);
      } finally {
        input.destroy();
        proxy.child.kill();
        await new Promise((resolve) => proxy.child.once("exit", resolve));
      }
    });
  }
});

async function waitFor(factory, timeoutMs = 10000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    const value = factory();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error("Timed out waiting for child environment");
}
