import test from "node:test";
import assert from "node:assert/strict";
import { PassThrough } from "node:stream";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { NdjsonMcpMessageFramer, encodeNdjsonMcpMessage } from "../src/framing.mjs";
import { CHILD_ENVIRONMENT_ALLOWLIST, HawkMcpProxy, childEnvironment, normalizePassEnv } from "../src/proxy.mjs";

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

// Secrets of other kinds a developer's shell or an MCP client config commonly holds.
const UNRELATED_SECRETS = [
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GITHUB_TOKEN",
  "GITHUB_PERSONAL_ACCESS_TOKEN",
  "NPM_TOKEN",
  "DATABASE_URL",
];

test("child environment is an allowlist plus explicitly named variables", () => {
  const parent = {
    PATH: "/usr/bin",
    HOME: "/home/someone",
    LANG: "en_US.UTF-8",
    HTTPS_PROXY: "http://proxy.example:3128",
    OPENAI_API_KEY: "sk-secret",
    GITHUB_PERSONAL_ACCESS_TOKEN: "ghp-secret",
    HAWK_MCP_PASS_ENV: "GITHUB_PERSONAL_ACCESS_TOKEN",
    HAWK_ACCESS_TOKEN: "hawk-secret",
    HAWK_AGENT_ANYTHING: "agent-secret",
  };
  assert.deepEqual(childEnvironment(parent), {
    PATH: "/usr/bin",
    HOME: "/home/someone",
    LANG: "en_US.UTF-8",
    HTTPS_PROXY: "http://proxy.example:3128",
  });
  assert.deepEqual(childEnvironment(parent, normalizePassEnv("GITHUB_PERSONAL_ACCESS_TOKEN")), {
    PATH: "/usr/bin",
    HOME: "/home/someone",
    LANG: "en_US.UTF-8",
    HTTPS_PROXY: "http://proxy.example:3128",
    GITHUB_PERSONAL_ACCESS_TOKEN: "ghp-secret",
  });
  // Windows names are case-insensitive.
  assert.deepEqual(
    childEnvironment({ Path: "C:\\Windows", SystemRoot: "C:\\Windows", hawk_access_token: "x", Secret: "y" }, [], { platform: "win32" }),
    { Path: "C:\\Windows", SystemRoot: "C:\\Windows" },
  );
});

test("Hawk credentials and malformed names cannot be passed explicitly", () => {
  assert.deepEqual(normalizePassEnv(null), []);
  assert.deepEqual(normalizePassEnv(" A_KEY, B_KEY ,A_KEY,"), ["A_KEY", "B_KEY"]);
  assert.deepEqual(normalizePassEnv(["A_KEY"]), ["A_KEY"]);
  for (const name of ["HAWK_ACCESS_TOKEN", "HAWK_CAPABILITY_TOKEN", "HAWK_AGENT_TOKEN", "HAWK_AGENT_X", "HAWK_ENDPOINT_SOCKET"]) {
    assert.throws(() => normalizePassEnv(name), /never passed/, name);
  }
  for (const name of ["A-B", "1ABC", "A B", "A=B"]) {
    assert.throws(() => normalizePassEnv(name), /Invalid environment variable name/, name);
  }
  assert.throws(
    () => new HawkMcpProxy({ childCommand: "x", childArgs: [], hawkClient: {}, passEnv: "HAWK_ACCESS_TOKEN" }),
    /never passed/,
  );
});

test("proxy CLI refuses to pass a Hawk credential to the child", () => {
  const result = spawnSync(process.execPath, [
    "bin/hawk-mcp-proxy.mjs",
    "--gateway", "http://127.0.0.1:9",
    "--tenant", "tenant-1",
    "--token", "not-a-real-token",
    "--pass-env", "HAWK_ACCESS_TOKEN",
    "--", process.execPath, "-e", "",
  ], {
    cwd: new URL("..", import.meta.url),
    encoding: "utf8",
    env: { PATH: process.env.PATH },
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /never passed to an MCP server/);
});

test("gateway and endpoint proxy children never inherit Hawk secrets, endpoint identity or other secrets", async (t) => {
  const saved = new Map();
  for (const name of [...SENSITIVE_ENVIRONMENT, ...UNRELATED_SECRETS]) {
    saved.set(name, process.env[name]);
    process.env[name] = `sensitive-${name}`;
  }
  saved.set("HAWK_MCP_LAB_DIR", process.env.HAWK_MCP_LAB_DIR);
  process.env.HAWK_MCP_LAB_DIR = "/private/tmp/hawk-child-env-safe";
  saved.set("MCP_SERVER_API_KEY", process.env.MCP_SERVER_API_KEY);
  process.env.MCP_SERVER_API_KEY = "named-for-the-child";
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
        passEnv: "HAWK_MCP_LAB_DIR,MCP_SERVER_API_KEY",
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
        for (const name of [...SENSITIVE_ENVIRONMENT, ...UNRELATED_SECRETS]) {
          assert.equal(response.result.env[name], undefined, `${transport}:${name}`);
        }
        assert.equal(response.result.env.HAWK_MCP_LAB_DIR, "/private/tmp/hawk-child-env-safe");
        assert.equal(response.result.env.MCP_SERVER_API_KEY, "named-for-the-child");
        assert.equal(response.result.env.PATH, process.env.PATH);
        const allowed = new Set([...CHILD_ENVIRONMENT_ALLOWLIST, "HAWK_MCP_LAB_DIR", "MCP_SERVER_API_KEY"]);
        for (const name of Object.keys(response.result.env)) {
          // The child runtime may add a few of its own (macOS adds __CF_USER_TEXT_ENCODING).
          if (name.startsWith("__CF")) continue;
          assert.ok(allowed.has(name), `${transport}: unexpected ${name}`);
        }
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
