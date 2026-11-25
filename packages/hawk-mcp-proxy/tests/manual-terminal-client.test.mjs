import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { PassThrough } from "node:stream";

import { encodeMcpFrame, MpcMessageFramer } from "../src/framing.mjs";
import {
  parseClientArgs,
  usageText,
} from "../examples/manual-terminal/manual-mcp-client.mjs";

import {
  classifyOutcome,
  buildManualProxyArgs,
  cleanupLabDirectory,
  createFramedProxySession,
  findCorrelatedEvidence,
  redactSecrets,
  requireManualConfirmation,
  runManualMcpScenario,
} from "../examples/manual-terminal/manual-mcp-client-core.mjs";

test("manual lab explicitly preserves Content-Length proxy framing", () => {
  const args = buildManualProxyArgs({
    proxyPath: "/repo/proxy.mjs",
    serverPath: "/repo/server.mjs",
    apiUrl: "http://127.0.0.1:8000",
    tenantId: "tenant-1",
    aiSystemId: "system-1",
    actorId: "owner@example.com",
    chainId: "chain-1",
    sessionId: "session-1",
    capabilityToken: "capability-1",
  });

  assert.deepEqual(
    args.slice(args.indexOf("--stdio-framing"), args.indexOf("--stdio-framing") + 2),
    ["--stdio-framing", "content-length"],
  );
});

test("manual confirmation accepts only CALL", async () => {
  assert.equal(await requireManualConfirmation(async () => "CALL"), true);
  assert.equal(await requireManualConfirmation(async () => "yes"), false);
});

test("generic proxy block without persisted block evidence is not proven", () => {
  assert.equal(classifyOutcome({
    proxyError: "MCP tool call blocked by Hawk policy",
    markerExists: false,
    childSawCall: false,
  }), "NOT PROVEN");
});

test("matching block evidence plus non-execution proves the block", () => {
  assert.equal(classifyOutcome({
    proxyError: "MCP tool call blocked by Hawk policy",
    markerExists: false,
    childSawCall: false,
    enforcementEvent: {
      id: "evt-1",
      final_decision: "block",
      correlation_id: "corr-1",
    },
    runtimeEvent: { event_id: "runtime-1", correlation_id: "corr-1" },
  }), "BLOCK PROVEN");
});

test("execution evidence is never classified as blocked", () => {
  assert.equal(classifyOutcome({
    markerExists: true,
    childSawCall: true,
  }), "ALLOW/EXECUTION OBSERVED");
});

test("setup failure is distinct from a policy block", () => {
  assert.equal(classifyOutcome({
    setupError: "MCP tool metadata scan failed",
    markerExists: false,
    childSawCall: false,
  }), "SETUP FAILED");
});

test("evidence correlation requires actor, system, tool, decision, and start time", () => {
  const result = findCorrelatedEvidence([
    {
      id: "old",
      actor_id: "run-1",
      ai_system_id: "sys-1",
      tool_name: "write_demo_marker",
      final_decision: "block",
      timestamp: "2026-08-03T07:00:00Z",
    },
    {
      id: "match",
      actor_id: "run-1",
      ai_system_id: "sys-1",
      tool_name: "write_demo_marker",
      final_decision: "block",
      timestamp: "2026-08-03T08:00:01Z",
      correlation_id: "corr-1",
    },
  ], {
    actorId: "run-1",
    aiSystemId: "sys-1",
    startedAt: "2026-08-03T08:00:00Z",
  });
  assert.equal(result.id, "match");
});

test("evidence correlation rejects invalid timestamps and partial matches", () => {
  const result = findCorrelatedEvidence([
    {
      id: "wrong-tool",
      actor_id: "run-1",
      ai_system_id: "sys-1",
      tool_name: "other",
      final_decision: "block",
      timestamp: "2026-08-03T08:00:01Z",
    },
    {
      id: "invalid-time",
      actor_id: "run-1",
      ai_system_id: "sys-1",
      tool_name: "write_demo_marker",
      final_decision: "block",
      timestamp: "not-a-time",
    },
  ], {
    actorId: "run-1",
    aiSystemId: "sys-1",
    startedAt: "2026-08-03T08:00:00Z",
  });
  assert.equal(result, null);
});

test("evidence correlation treats Hawk timezone-naive timestamps as UTC", () => {
  const result = findCorrelatedEvidence([{
    id: "naive-utc",
    actor_id: "run-1",
    ai_system_id: "sys-1",
    tool_name: "write_demo_marker",
    final_decision: "block",
    timestamp: "2026-08-03T08:00:01.123456",
    correlation_id: "corr-naive",
  }], {
    actorId: "run-1",
    aiSystemId: "sys-1",
    startedAt: "2026-08-03T08:00:00Z",
  });

  assert.equal(result?.id, "naive-utc");
});

test("redaction removes both access and capability tokens", () => {
  assert.equal(
    redactSecrets(
      "Bearer access-secret capability-secret access-secret",
      ["access-secret", "capability-secret"],
    ),
    "Bearer [REDACTED] [REDACTED] [REDACTED]",
  );
});

test("framed proxy session writes requests and resolves matching responses", async () => {
  const child = new EventEmitter();
  child.stdin = new PassThrough();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  child.exitCode = null;
  child.killed = false;
  child.kill = () => {
    child.killed = true;
    child.exitCode = 0;
    child.emit("exit", 0);
  };

  const inbound = new MpcMessageFramer();
  inbound.onMessage((message) => {
    child.stdout.write(encodeMcpFrame({
      jsonrpc: "2.0",
      id: message.id,
      result: { echoed: message.method },
    }));
  });
  child.stdin.on("data", (chunk) => inbound.push(chunk));

  const session = createFramedProxySession(child, { timeoutMs: 200 });
  const response = await session.request({
    jsonrpc: "2.0",
    id: 11,
    method: "initialize",
  });
  assert.equal(response.result.echoed, "initialize");
  await session.close();
  assert.equal(child.killed, true);
});

test("manual scenario sends tools/call only after exact confirmation", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-client-");
  await writeFile(
    `${labDir}/child-events.ndjson`,
    `${JSON.stringify({ method: "initialize" })}\n${JSON.stringify({ method: "tools/list" })}\n`,
    "utf8",
  );
  const requests = [];
  const fakeSession = {
    async request(message) {
      requests.push(message.method);
      if (message.method === "initialize") {
        return { jsonrpc: "2.0", id: message.id, result: {} };
      }
      if (message.method === "tools/list") {
        return { jsonrpc: "2.0", id: message.id, result: { tools: [] } };
      }
      return {
        jsonrpc: "2.0",
        id: message.id,
        error: { code: -32000, message: "MCP tool call blocked by Hawk policy" },
      };
    },
    async close() {},
  };

  const result = await runManualMcpScenario({
    env: validEnv(),
    labDir,
    runId: "run-confirm",
    readLine: async () => "no",
    sessionFactory: async () => fakeSession,
    fetchImpl: async () => jsonResponse({ items: [] }),
    now: () => new Date("2026-08-03T08:00:00Z"),
    stdout: sink().stream,
  });

  assert.deepEqual(requests, ["initialize", "tools/list"]);
  assert.equal(result.outcome, "NOT PROVEN");
  assert.equal(result.exitCode, 4);
});

test("matching API evidence and absent execution artifacts proves the block", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-client-");
  await writeFile(
    `${labDir}/child-events.ndjson`,
    `${JSON.stringify({ method: "initialize" })}\n${JSON.stringify({ method: "tools/list" })}\n`,
    "utf8",
  );
  const requests = [];
  const captured = sink();
  const result = await runManualMcpScenario({
    env: validEnv(),
    labDir,
    runId: "run-proof",
    readLine: async () => "CALL",
    sessionFactory: async () => ({
      async request(message) {
        requests.push(message.method);
        if (message.method === "initialize") {
          return { jsonrpc: "2.0", id: message.id, result: {} };
        }
        if (message.method === "tools/list") {
          return { jsonrpc: "2.0", id: message.id, result: { tools: [] } };
        }
        return {
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32000, message: "MCP tool call blocked by Hawk policy" },
        };
      },
      async close() {},
    }),
    fetchImpl: async (url) => {
      if (String(url).includes("/enforcement/events")) {
        return jsonResponse({ items: [{
          id: "evt-1",
          actor_id: "manual-mcp-terminal-run-proof",
          ai_system_id: "sys-1",
          tool_name: "write_demo_marker",
          final_decision: "block",
          timestamp: "2026-08-03T08:00:01Z",
          correlation_id: "corr-1",
        }] });
      }
      return jsonResponse({ items: [{
        event_id: "runtime-1",
        correlation_id: "corr-1",
      }] });
    },
    now: () => new Date("2026-08-03T08:00:00Z"),
    stdout: captured.stream,
  });

  assert.deepEqual(requests, ["initialize", "tools/list", "tools/call"]);
  assert.equal(result.outcome, "BLOCK PROVEN");
  assert.equal(result.exitCode, 0);
  assert.match(captured.value(), /Enforcement event: evt-1/);
  assert.match(captured.value(), /Runtime event: runtime-1/);
  assert.equal(captured.value().includes("access-secret"), false);
  assert.equal(captured.value().includes("capability-secret"), false);
});

test("manual scenario polls until correlated enforcement and runtime evidence arrive", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-client-");
  let enforcementFetches = 0;
  let runtimeFetches = 0;
  let sleeps = 0;
  const result = await runManualMcpScenario({
    env: validEnv(),
    labDir,
    runId: "run-delayed-proof",
    readLine: async () => "CALL",
    sessionFactory: async () => fixedBlockingSession(),
    fetchImpl: async (url) => {
      if (String(url).includes("/enforcement/events")) {
        enforcementFetches += 1;
        return jsonResponse({ items: enforcementFetches < 3 ? [] : [{
          id: "evt-delayed",
          actor_id: "manual-mcp-terminal-run-delayed-proof",
          ai_system_id: "sys-1",
          tool_name: "write_demo_marker",
          final_decision: "block",
          timestamp: "2026-08-03T08:00:01Z",
          correlation_id: "corr-delayed",
        }] });
      }
      runtimeFetches += 1;
      return jsonResponse({ items: runtimeFetches < 2 ? [] : [{
        event_id: "runtime-delayed",
        correlation_id: "corr-delayed",
      }] });
    },
    now: () => new Date("2026-08-03T08:00:00Z"),
    sleepImpl: async () => {
      sleeps += 1;
    },
    stdout: sink().stream,
  });

  assert.equal(result.outcome, "BLOCK PROVEN");
  assert.equal(result.enforcementEvent.id, "evt-delayed");
  assert.equal(result.runtimeEvent.event_id, "runtime-delayed");
  assert.equal(enforcementFetches, 4);
  assert.equal(runtimeFetches, 2);
  assert.equal(sleeps, 3);
});

test("generic proxy block with no matching API evidence remains not proven", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-client-");
  const result = await runManualMcpScenario({
    env: validEnv(),
    labDir,
    runId: "run-no-evidence",
    readLine: async () => "CALL",
    sessionFactory: async () => fixedBlockingSession(),
    fetchImpl: async () => jsonResponse({ items: [] }),
    now: () => new Date("2026-08-03T08:00:00Z"),
    stdout: sink().stream,
  });
  assert.equal(result.outcome, "NOT PROVEN");
  assert.equal(result.exitCode, 4);
});

test("metadata scan failure is setup failed and never prompts for CALL", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-client-");
  let promptCount = 0;
  const result = await runManualMcpScenario({
    env: validEnv(),
    labDir,
    runId: "run-setup",
    readLine: async () => {
      promptCount += 1;
      return "CALL";
    },
    sessionFactory: async () => ({
      async request(message) {
        if (message.method === "initialize") {
          return { jsonrpc: "2.0", id: message.id, result: {} };
        }
        return {
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32000, message: "MCP tool metadata scan failed" },
        };
      },
      async close() {},
    }),
    fetchImpl: async () => jsonResponse({ items: [] }),
    now: () => new Date("2026-08-03T08:00:00Z"),
    stdout: sink().stream,
  });
  assert.equal(result.outcome, "SETUP FAILED");
  assert.equal(result.exitCode, 3);
  assert.equal(promptCount, 0);
});

test("cleanup removes only an explicitly scoped Hawk lab directory", async () => {
  const labDir = await mkdtemp("/private/tmp/hawk-mcp-terminal-lab-cleanup-");
  await writeFile(`${labDir}/marker.json`, "{}", "utf8");
  await cleanupLabDirectory(labDir);
  await assert.rejects(stat(labDir));
  await assert.rejects(
    cleanupLabDirectory("/private/tmp/not-hawk"),
    /Invalid Hawk MCP lab directory/,
  );
});

test("manual client CLI exposes run, cleanup, and secret-free help", () => {
  assert.deepEqual(parseClientArgs([]), { command: "run" });
  assert.deepEqual(parseClientArgs(["--help"]), { command: "help" });
  assert.deepEqual(
    parseClientArgs([
      "cleanup",
      "--lab-dir",
      "/private/tmp/hawk-mcp-terminal-lab-cleanup-example",
    ]),
    {
      command: "cleanup",
      labDir: "/private/tmp/hawk-mcp-terminal-lab-cleanup-example",
    },
  );
  assert.match(usageText(), /HAWK_ACCESS_TOKEN/);
  assert.match(usageText(), /cleanup --lab-dir/);
  assert.equal(usageText().includes("access-secret"), false);
});

test("manual client CLI rejects ambiguous arguments", () => {
  assert.throws(() => parseClientArgs(["cleanup"]), /Usage:/);
  assert.throws(() => parseClientArgs(["--unknown"]), /Usage:/);
});

test("package scripts expose the honest terminal proof path", async () => {
  const packageJson = JSON.parse(await readFile(
    new URL("../package.json", import.meta.url),
    "utf8",
  ));
  assert.equal(
    packageJson.scripts["manual:mcp"],
    "node examples/manual-terminal/manual-mcp-client.mjs",
  );
  assert.equal(
    packageJson.scripts["manual:mcp:cleanup"],
    "node examples/manual-terminal/manual-mcp-client.mjs cleanup",
  );

});

function validEnv() {
  return {
    HAWK_API_URL: "http://127.0.0.1:8000",
    HAWK_TENANT_ID: "tenant-1",
    HAWK_ACCESS_TOKEN: "access-secret",
    HAWK_AI_SYSTEM_ID: "sys-1",
    HAWK_CAPABILITY_TOKEN: "capability-secret",
  };
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function fixedBlockingSession() {
  return {
    async request(message) {
      if (message.method === "initialize") {
        return { jsonrpc: "2.0", id: message.id, result: {} };
      }
      if (message.method === "tools/list") {
        return { jsonrpc: "2.0", id: message.id, result: { tools: [] } };
      }
      return {
        jsonrpc: "2.0",
        id: message.id,
        error: { code: -32000, message: "MCP tool call blocked by Hawk policy" },
      };
    },
    async close() {},
  };
}

function sink() {
  const chunks = [];
  return {
    stream: { write: (chunk) => chunks.push(String(chunk)) },
    value: () => chunks.join(""),
  };
}
