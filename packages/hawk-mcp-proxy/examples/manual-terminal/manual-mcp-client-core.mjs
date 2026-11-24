export async function requireManualConfirmation(readLine) {
  return String(await readLine()).trim() === "CALL";
}

export function classifyOutcome(state) {
  if (state.markerExists || state.childSawCall) {
    return "ALLOW/EXECUTION OBSERVED";
  }
  if (state.setupError) {
    return "SETUP FAILED";
  }
  const event = state.enforcementEvent;
  const runtime = state.runtimeEvent;
  if (
    state.proxyError === "MCP tool call blocked by Hawk policy"
    && event?.final_decision === "block"
    && event?.correlation_id
    && runtime?.correlation_id === event.correlation_id
  ) {
    return "BLOCK PROVEN";
  }
  return "NOT PROVEN";
}

export function findCorrelatedEvidence(events, {
  actorId,
  aiSystemId,
  startedAt,
}) {
  const lowerBound = parseHawkTimestamp(startedAt);
  if (!Number.isFinite(lowerBound) || !Array.isArray(events)) {
    return null;
  }
  return events.find((event) => {
    const eventTime = parseHawkTimestamp(event?.timestamp);
    return (
      event?.actor_id === actorId
      && event?.ai_system_id === aiSystemId
      && event?.tool_name === "write_demo_marker"
      && event?.final_decision === "block"
      && Number.isFinite(eventTime)
      && eventTime >= lowerBound
    );
  }) || null;
}

function parseHawkTimestamp(value) {
  const normalized = String(value || "").trim();
  if (!normalized) {
    return Number.NaN;
  }
  const timezoneNaiveIso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/;
  return Date.parse(timezoneNaiveIso.test(normalized) ? `${normalized}Z` : normalized);
}

export function redactSecrets(value, secrets) {
  let redacted = String(value ?? "");
  for (const secret of secrets || []) {
    const normalized = String(secret || "");
    if (normalized) {
      redacted = redacted.split(normalized).join("[REDACTED]");
    }
  }
  return redacted;
}

export function createFramedProxySession(child, { timeoutMs = 8000 } = {}) {
  const pending = new Map();
  const framer = new MpcMessageFramer();
  let closed = false;

  framer.onMessage((message) => {
    const key = requestKey(message?.id);
    const request = pending.get(key);
    if (!request) {
      return;
    }
    clearTimeout(request.timer);
    pending.delete(key);
    request.resolve(message);
  });

  child.stdout.on("data", (chunk) => {
    try {
      framer.push(chunk);
    } catch {
      failPending("MCP proxy response framing failed");
    }
  });
  child.stdout.on("end", () => {
    if (!closed) {
      failPending("MCP proxy ended before responding");
    }
  });
  child.stderr.on("data", () => {});
  child.on("error", () => failPending("MCP proxy process failed"));
  child.on("exit", () => {
    if (!closed) {
      failPending("MCP proxy exited before responding");
    }
  });

  function failPending(message) {
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error(message));
    }
    pending.clear();
  }

  return {
    request(message) {
      if (closed) {
        return Promise.reject(new Error("MCP proxy session is closed"));
      }
      const key = requestKey(message?.id);
      if (key === null || pending.has(key)) {
        return Promise.reject(new Error("MCP proxy request id is invalid"));
      }
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          pending.delete(key);
          reject(new Error("MCP proxy request timed out"));
        }, timeoutMs);
        pending.set(key, { resolve, reject, timer });
        try {
          child.stdin.write(encodeMcpFrame(message));
        } catch {
          clearTimeout(timer);
          pending.delete(key);
          reject(new Error("MCP proxy request failed"));
        }
      });
    },
    async close() {
      if (closed) {
        return;
      }
      closed = true;
      failPending("MCP proxy session closed");
      if (!child.stdin.destroyed && !child.stdin.writableEnded) {
        child.stdin.end();
      }
      if (child.exitCode === null && !child.killed) {
        child.kill();
      }
    },
  };
}

export async function runManualMcpScenario({
  env = process.env,
  fetchImpl = fetch,
  labDir: requestedLabDir,
  now = () => new Date(),
  readLine,
  runId: requestedRunId,
  sessionFactory,
  sleepImpl = sleep,
  spawnImpl = spawn,
  stdout = process.stdout,
} = {}) {
  const config = readConfig(env);
  if (typeof readLine !== "function") {
    throw new Error("Manual confirmation reader is required");
  }
  const runId = normalizeRunId(requestedRunId || generateRunId(now()));
  const labDir = resolveLabDirectory(
    requestedLabDir || `/private/tmp/hawk-mcp-terminal-lab-${runId}`,
  );
  await mkdir(labDir, { recursive: true });

  const startedAt = now().toISOString();
  const actorId = `manual-mcp-terminal-${runId}`;
  const chainId = `manual-mcp-chain-${runId}`;
  const sessionId = `manual-mcp-session-${runId}`;
  const capabilityToken = `manual-mcp-non-authoritative-${runId}`;
  const createSession = sessionFactory || ((context) => spawnProxySession({
    ...context,
    spawnImpl,
  }));
  const session = await createSession({
    actorId,
    capabilityToken,
    chainId,
    config,
    env,
    labDir,
    sessionId,
  });

  writeLine(stdout, `HAWK_MCP_LAB_DIR=${labDir}`, config, capabilityToken);
  try {
    const initialize = await session.request({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "hawk-manual-terminal", version: "1.0.0" },
      },
    });
    if (initialize?.error) {
      return finish({
        capabilityToken,
        config,
        labDir,
        setupError: initialize.error.message || "MCP initialize failed",
        stdout,
      });
    }

    const tools = await session.request({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: {},
    });
    if (tools?.error) {
      return finish({
        capabilityToken,
        config,
        labDir,
        setupError: tools.error.message || "MCP tool metadata scan failed",
        stdout,
      });
    }

    writeLine(
      stdout,
      `Type CALL and press Enter to invoke ${DEMO_TOOL_NAME} through Hawk:`,
      config,
      capabilityToken,
    );
    if (!await requireManualConfirmation(readLine)) {
      return finish({ capabilityToken, config, labDir, stdout });
    }

    const call = await session.request({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: DEMO_TOOL_NAME,
        arguments: { note: "CISO manual proof" },
      },
    });
    const proxyError = String(call?.error?.message || "").trim() || null;
    const { enforcementEvent, runtimeEvent } = proxyError === BLOCK_MESSAGE
      ? await pollForBlockEvidence({
        actorId,
        config,
        fetchImpl,
        sleepImpl,
        startedAt,
      })
      : { enforcementEvent: null, runtimeEvent: null };
    return finish({
      capabilityToken,
      config,
      enforcementEvent,
      labDir,
      proxyError,
      runtimeEvent,
      stdout,
    });
  } finally {
    await session.close();
  }
}

export async function cleanupLabDirectory(rawPath) {
  const labDir = resolveLabDirectory(rawPath);
  await rm(labDir, { recursive: true });
  return labDir;
}

async function spawnProxySession({
  actorId,
  capabilityToken,
  chainId,
  config,
  env,
  labDir,
  sessionId,
  spawnImpl,
}) {
  const proxyPath = fileURLToPath(new URL("../../bin/hawk-mcp-proxy.mjs", import.meta.url));
  const serverPath = fileURLToPath(new URL("./manual-mcp-server.mjs", import.meta.url));
  const child = spawnImpl(process.execPath, buildManualProxyArgs({
    proxyPath,
    serverPath,
    apiUrl: config.apiUrl,
    tenantId: config.tenantId,
    aiSystemId: config.aiSystemId,
    actorId,
    chainId,
    sessionId,
    capabilityToken,
  }), {
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...env,
      HAWK_ACCESS_TOKEN: config.accessToken,
      HAWK_MCP_LAB_DIR: labDir,
    },
  });
  return createFramedProxySession(child);
}

export function buildManualProxyArgs({
  proxyPath,
  serverPath,
  apiUrl,
  tenantId,
  aiSystemId,
  actorId,
  chainId,
  sessionId,
  capabilityToken,
}) {
  return [
    proxyPath,
    "--gateway", apiUrl,
    "--tenant", tenantId,
    "--ai-system-id", aiSystemId,
    "--actor-id", actorId,
    "--server-id", toolContract.mcpServerId,
    "--chain-id", chainId,
    "--session-id", sessionId,
    "--capability-token", capabilityToken,
    "--stdio-framing", "content-length",
    "--",
    process.execPath,
    serverPath,
  ];
}

async function fetchEnforcementEvent({
  actorId,
  config,
  fetchImpl,
  startedAt,
}) {
  const body = await fetchEnvelope(
    `${config.apiUrl}/enforcement/events?page=1&page_size=100`,
    config,
    fetchImpl,
  );
  return findCorrelatedEvidence(body?.items, {
    actorId,
    aiSystemId: config.aiSystemId,
    startedAt,
  });
}

async function fetchRuntimeEvent({ config, correlationId, fetchImpl }) {
  const encoded = encodeURIComponent(correlationId);
  const body = await fetchEnvelope(
    `${config.apiUrl}/runtime-intelligence/events?page=1&page_size=100&correlation_id=${encoded}`,
    config,
    fetchImpl,
  );
  if (!Array.isArray(body?.items)) {
    return null;
  }
  return body.items.find((event) => event?.correlation_id === correlationId) || null;
}

async function pollForBlockEvidence({
  actorId,
  config,
  fetchImpl,
  sleepImpl,
  startedAt,
}) {
  let enforcementEvent = null;
  let runtimeEvent = null;
  for (let attempt = 0; attempt < EVIDENCE_POLL_ATTEMPTS; attempt += 1) {
    enforcementEvent = await fetchEnforcementEvent({
      actorId,
      config,
      fetchImpl,
      startedAt,
    });
    runtimeEvent = enforcementEvent?.correlation_id
      ? await fetchRuntimeEvent({
        config,
        correlationId: enforcementEvent.correlation_id,
        fetchImpl,
      })
      : null;
    if (enforcementEvent && runtimeEvent) {
      break;
    }
    if (attempt + 1 < EVIDENCE_POLL_ATTEMPTS) {
      await sleepImpl(EVIDENCE_POLL_INTERVAL_MS);
    }
  }
  return { enforcementEvent, runtimeEvent };
}

async function fetchEnvelope(url, config, fetchImpl) {
  try {
    const response = await fetchImpl(url, {
      headers: {
        "Authorization": `Bearer ${config.accessToken}`,
        "X-Tenant-ID": config.tenantId,
      },
    });
    if (!response.ok) {
      return { items: [] };
    }
    return await response.json();
  } catch {
    return { items: [] };
  }
}

async function finish({
  capabilityToken,
  config,
  enforcementEvent = null,
  labDir,
  proxyError = null,
  runtimeEvent = null,
  setupError = null,
  stdout,
}) {
  const execution = await inspectExecution(labDir);
  const outcome = classifyOutcome({
    ...execution,
    enforcementEvent,
    proxyError,
    runtimeEvent,
    setupError,
  });
  for (const line of [
    `Outcome: ${outcome}`,
    `Marker file: ${execution.markerExists ? "present" : "absent"}`,
    `Child received tools/call: ${execution.childSawCall ? "yes" : "no"}`,
    `Enforcement event: ${enforcementEvent?.id || "none"}`,
    `Runtime event: ${runtimeEvent?.event_id || "none"}`,
    `Correlation ID: ${enforcementEvent?.correlation_id || "none"}`,
  ]) {
    writeLine(stdout, line, config, capabilityToken);
  }
  if (outcome === "SETUP FAILED") {
    writeLine(
      stdout,
      "Bootstrap the exact local demo fingerprint, then run this command again.",
      config,
      capabilityToken,
    );
  }
  return {
    ...execution,
    enforcementEvent,
    exitCode: EXIT_CODES[outcome],
    labDir,
    outcome,
    proxyError,
    runtimeEvent,
    setupError,
  };
}

async function inspectExecution(labDir) {
  const markerExists = await fileExists(path.join(labDir, "marker.json"));
  const callRecordExists = await fileExists(
    path.join(labDir, "tool-call-received.json"),
  );
  let childSawCall = callRecordExists;
  try {
    const log = await readFile(path.join(labDir, "child-events.ndjson"), "utf8");
    childSawCall ||= log.split("\n").some((line) => {
      if (!line.trim()) {
        return false;
      }
      try {
        return JSON.parse(line).method === "tools/call";
      } catch {
        return true;
      }
    });
  } catch {
    // Absence of the child log is not evidence of execution.
  }
  return { childSawCall, markerExists };
}

async function fileExists(filePath) {
  try {
    await stat(filePath);
    return true;
  } catch {
    return false;
  }
}

function readConfig(env) {
  const missing = REQUIRED_ENV.filter((name) => !String(env?.[name] || "").trim());
  if (missing.length) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
  return {
    accessToken: String(env.HAWK_ACCESS_TOKEN),
    aiSystemId: String(env.HAWK_AI_SYSTEM_ID).trim(),
    apiUrl: String(env.HAWK_API_URL).trim().replace(/\/+$/, ""),
    tenantId: String(env.HAWK_TENANT_ID).trim(),
  };
}

function generateRunId(date) {
  const timestamp = date.toISOString().replace(/[-:.]/g, "").replace(/\.\d{3}Z$/, "Z");
  return `${timestamp}-${randomUUID().slice(0, 6)}`;
}

function normalizeRunId(value) {
  const normalized = String(value || "").trim();
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(normalized)) {
    throw new Error("Invalid manual MCP run identifier");
  }
  return normalized;
}

function requestKey(id) {
  if (typeof id === "string" || typeof id === "number") {
    return `${typeof id}:${id}`;
  }
  return null;
}

function writeLine(stdout, value, config, capabilityToken) {
  const safe = redactSecrets(value, [config.accessToken, capabilityToken]);
  stdout.write(`${safe}\n`);
}
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import {
  mkdir,
  readFile,
  rm,
  stat,
} from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

import {
  encodeMcpFrame,
  MpcMessageFramer,
} from "../../src/framing.mjs";
import {
  DEMO_TOOL_NAME,
  resolveLabDirectory,
  toolContract,
} from "./manual-mcp-server.mjs";

const EXIT_CODES = Object.freeze({
  "BLOCK PROVEN": 0,
  "SETUP FAILED": 3,
  "NOT PROVEN": 4,
  "ALLOW/EXECUTION OBSERVED": 5,
});
const BLOCK_MESSAGE = "MCP tool call blocked by Hawk policy";
const EVIDENCE_POLL_ATTEMPTS = 12;
const EVIDENCE_POLL_INTERVAL_MS = 250;
const REQUIRED_ENV = Object.freeze([
  "HAWK_API_URL",
  "HAWK_TENANT_ID",
  "HAWK_ACCESS_TOKEN",
  "HAWK_AI_SYSTEM_ID",
]);
