#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import {
  createMcpMessageFramer,
  encodeMcpMessage,
  normalizeMcpStdioFraming,
} from "../../src/framing.mjs";

export const toolContract = Object.freeze(JSON.parse(
  readFileSync(new URL("./tool-contract.json", import.meta.url), "utf8"),
));
export const DEMO_TOOL_NAME = toolContract.tool.name;

export function resolveLabDirectory(rawPath) {
  const resolved = path.resolve(String(rawPath || ""));
  if (
    resolved !== rawPath
    || !resolved.startsWith("/private/tmp/hawk-mcp-terminal-lab-")
    || resolved.includes("..")
  ) {
    throw new Error("Invalid Hawk MCP lab directory");
  }
  return resolved;
}

export async function handleDemoRequest(message, { labDir }) {
  const id = message?.id ?? null;
  if (message?.method === "initialize") {
    return {
      jsonrpc: "2.0",
      id,
      result: {
        protocolVersion: "2025-06-18",
        capabilities: { tools: {} },
        serverInfo: { name: toolContract.mcpServerId, version: "1.0.0" },
      },
    };
  }

  if (message?.method === "notifications/initialized") {
    return null;
  }

  if (message?.method === "tools/list") {
    return {
      jsonrpc: "2.0",
      id,
      result: { tools: [structuredClone(toolContract.tool)] },
    };
  }

  if (message?.method === "tools/call") {
    const name = message?.params?.name;
    const note = message?.params?.arguments?.note;
    if (
      name !== DEMO_TOOL_NAME
      || typeof note !== "string"
      || !note.trim()
      || note.length > 64
    ) {
      return invalidParams(id);
    }

    const resolvedLabDir = resolveLabDirectory(labDir);
    await mkdir(resolvedLabDir, { recursive: true });
    const receivedAt = new Date().toISOString();
    const record = JSON.stringify({
      tool: DEMO_TOOL_NAME,
      note,
      receivedAt,
    }, null, 2);
    await writeFile(
      path.join(resolvedLabDir, "tool-call-received.json"),
      record,
      { encoding: "utf8", flag: "wx" },
    );
    await writeFile(
      path.join(resolvedLabDir, "marker.json"),
      record,
      { encoding: "utf8", flag: "wx" },
    );
    return {
      jsonrpc: "2.0",
      id,
      result: {
        content: [{ type: "text", text: "Hawk manual MCP marker written" }],
        isError: false,
      },
    };
  }

  if (message?.method && id !== null) {
    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32601, message: "Method not found" },
    };
  }
  return null;
}

export function startDemoServer({
  input = process.stdin,
  output = process.stdout,
  stderr = process.stderr,
  labDir = process.env.HAWK_MCP_LAB_DIR,
  stdioFraming = process.env.HAWK_MCP_STDIO_FRAMING || "content-length",
} = {}) {
  const resolvedLabDir = resolveLabDirectory(labDir);
  const framingMode = normalizeMcpStdioFraming(stdioFraming);
  const framer = createMcpMessageFramer(framingMode);
  const encodeMessage = (message) => encodeMcpMessage(message, framingMode);
  let queue = Promise.resolve();

  framer.onMessage((message) => {
    queue = queue.then(async () => {
      if (typeof message?.method === "string") {
        await mkdir(resolvedLabDir, { recursive: true });
        await appendFile(
          path.join(resolvedLabDir, "child-events.ndjson"),
          `${JSON.stringify({ method: message.method, receivedAt: new Date().toISOString() })}\n`,
          "utf8",
        );
      }
      const response = await handleDemoRequest(message, { labDir: resolvedLabDir });
      if (response) {
        output.write(encodeMessage(response));
      }
    }).catch(() => {
      stderr.write("manual MCP child failed safely\n");
      if (message?.id !== undefined) {
        output.write(encodeMessage({
          jsonrpc: "2.0",
          id: message.id,
          error: { code: -32000, message: "Manual MCP child failed safely" },
        }));
      }
    });
  });

  input.on("data", (chunk) => {
    try {
      framer.push(chunk);
    } catch {
      stderr.write("manual MCP child framing failed safely\n");
    }
  });
  input.on("end", () => {
    try {
      framer.end();
    } catch {
      stderr.write("manual MCP child framing failed safely\n");
    }
  });
}

function invalidParams(id) {
  return {
    jsonrpc: "2.0",
    id,
    error: { code: -32602, message: "Invalid demo tool parameters" },
  };
}

const isMain = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  startDemoServer();
}
