import process from "node:process";

import {
  createMcpMessageFramer,
  encodeMcpMessage,
  normalizeMcpStdioFraming,
} from "./framing.mjs";

const TOOLS = Object.freeze([
  {
    name: "get_executive_summary",
    description: "Return a tenant-scoped executive AI governance summary. Raw prompt content is never included.",
    inputSchema: {
      type: "object",
      properties: {
        window_days: { type: "integer", minimum: 1, maximum: 366, default: 30 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "query_executive_metrics",
    description: "Query tenant-scoped executive metrics such as actions, blocks, top violations, providers, MCP tools, GitHub repositories, control coverage, spend, or tokens.",
    inputSchema: {
      type: "object",
      required: ["metric"],
      properties: {
        metric: {
          type: "string",
          enum: [
            "actions",
            "blocked",
            "top_violations",
            "violations_by_framework",
            "providers",
            "mcp_tools",
            "github_repositories",
            "control_coverage",
            "spend",
            "tokens",
          ],
        },
        group_by: { type: ["string", "null"], default: null },
        window_days: { type: "integer", minimum: 1, maximum: 366, default: 30 },
        limit: { type: "integer", minimum: 1, maximum: 100, default: 10 },
        include_named_users: { type: "boolean", default: false },
      },
      additionalProperties: false,
    },
  },
  {
    name: "create_executive_presentation",
    description: "Create an audited tenant-scoped PPTX executive brief from current evidence. Raw prompt content is excluded.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", minLength: 1, maxLength: 120, default: "Executive AI Governance Brief" },
        window_days: { type: "integer", minimum: 1, maximum: 366, default: 30 },
      },
      additionalProperties: false,
    },
  },
]);

export class ExecutiveMcpServer {
  constructor({ client, input = process.stdin, output = process.stdout, framing = "ndjson" } = {}) {
    this.client = client;
    this.input = input;
    this.output = output;
    this.framing = normalizeMcpStdioFraming(framing);
    this.framer = createMcpMessageFramer(this.framing);
  }

  start() {
    this.framer.onMessage((message) => {
      this.#handle(message).catch((error) => {
        this.#send({
          jsonrpc: "2.0",
          id: message?.id ?? null,
          error: {
            code: -32000,
            message: sanitizeError(error),
          },
        });
      });
    });
    this.input.on("data", (chunk) => this.framer.push(chunk));
    this.input.on("end", () => this.framer.end());
  }

  async #handle(message) {
    if (!message || message.jsonrpc !== "2.0") {
      return;
    }
    if (message.method === "initialize") {
      this.#send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: {
            name: "trinya-executive-mcp",
            version: "0.1.0",
          },
        },
      });
      return;
    }
    if (message.method === "notifications/initialized") {
      return;
    }
    if (message.method === "tools/list") {
      this.#send({ jsonrpc: "2.0", id: message.id, result: { tools: TOOLS } });
      return;
    }
    if (message.method === "tools/call") {
      const result = await this.#callTool(message.params || {});
      this.#send({
        jsonrpc: "2.0",
        id: message.id,
        result: {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        },
      });
      return;
    }
    this.#send({
      jsonrpc: "2.0",
      id: message.id,
      error: { code: -32601, message: "Method not found" },
    });
  }

  async #callTool(params) {
    const name = String(params.name || "");
    const args = params.arguments || {};
    if (name === "get_executive_summary") {
      return this.client.getSummary({ windowDays: args.window_days });
    }
    if (name === "query_executive_metrics") {
      return this.client.queryMetrics({
        metric: args.metric,
        groupBy: args.group_by,
        windowDays: args.window_days,
        limit: args.limit,
        includeNamedUsers: args.include_named_users,
      });
    }
    if (name === "create_executive_presentation") {
      return this.client.createPresentation({
        title: args.title,
        windowDays: args.window_days,
      });
    }
    throw new Error(`Unknown executive MCP tool: ${name}`);
  }

  #send(message) {
    this.output.write(encodeMcpMessage(message, this.framing));
  }
}

function sanitizeError(error) {
  return String(error?.message || error || "Executive MCP request failed").slice(0, 1000);
}
