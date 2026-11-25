import { spawn } from "node:child_process";
import process from "node:process";

import {
  createMcpMessageFramer,
  encodeMcpMessage,
  normalizeMcpStdioFraming,
} from "./framing.mjs";
import {
  buildAuthorizePayload,
  buildTransportBinding,
  buildToolScanPayload,
  matchesGitHubRepositoryScope,
  normalizeGitHubRepositoryScope,
  repositoryScopedMcpServerId,
  shouldBlockDecision,
} from "./policy.mjs";
import { applyToolResultInspection } from "./result-inspection.mjs";
import { HawkGatewayError } from "./hawk-client.mjs";
import {
  attachGovernanceMetadata,
  governanceResourceResult,
  governanceStatusForDecision,
  governanceToolMetadata,
  HAWK_GOVERNANCE_RESOURCE_URI,
} from "./governance-app.mjs";

const MAX_PENDING_REQUESTS = 1024;
const MAX_TOOLS_PER_LIST = 1024;
const MAX_TOOL_METADATA_BYTES = 256 * 1024;
const MAX_TOOL_LIST_METADATA_BYTES = 1024 * 1024;
const MAX_TOOL_LIST_GENERATION = 1_000_000;
// The installed endpoint broker signs every response with the enrolled device
// key. Keep descriptor scanning parallel enough for desktop startup while
// bounding concurrent signing lanes to avoid overwhelming that trust anchor.
const MAX_CONCURRENT_TOOL_SCANS = 2;
// Endpoint metadata scans are signed, server-persisted checks.  A normal
// least-privilege GitHub catalog contains three tools and must not fail just
// because each bounded endpoint round trip consumes part of an 8-second
// aggregate window.
export const DEFAULT_TOOL_SCAN_DEADLINE_MS = 30_000;
const DEFAULT_RESULT_INSPECTION_MAX_BYTES = 256 * 1024;
// What a child MCP server inherits from the proxy's environment by default: what a process needs to start, find
// programs, reach the network through a proxy and trust certificates (the same list as
// bin/hawk-github-pr-endpoint.mjs, plus what Windows needs to start a process). Anything else, such as an API key the
// server needs, is passed only when named with --pass-env NAME[,NAME] or HAWK_MCP_PASS_ENV=NAME[,NAME].
export const CHILD_ENVIRONMENT_ALLOWLIST = Object.freeze([
  "ALL_PROXY",
  "HOME",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_PROXY",
  "PATH",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "TERM",
  "TMPDIR",
  // Windows
  "APPDATA",
  "COMSPEC",
  "LOCALAPPDATA",
  "PATHEXT",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "USERPROFILE",
  "WINDIR",
]);
const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
// Never passed to a child, even when named with --pass-env.
const CHILD_ENVIRONMENT_DENYLIST = new Set([
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
  "HAWK_TENANT_ID",
  "HAWK_ACTOR_ID",
  "HAWK_AI_SYSTEM_ID",
  "HAWK_CHAIN_ID",
  "HAWK_SESSION_ID",
  "HAWK_MCP_SERVER_ID",
  "HAWK_API_URL",
]);
const TOOL_TRUST_STATUSES = new Set(["approved", "unknown", "changed"]);
const TOOL_POISONING_DECISIONS = new Set([
  "allow",
  "warn",
  "redact",
  "hold_for_approval",
  "block",
]);
const ALLOWED_AUTHORIZATION_DECISIONS = new Set([
  "allow",
  "warn",
  "redact",
  "block",
  "review",
  "hold_for_approval",
  "require_approval",
  "require_second_approval",
  "step_up",
]);

class ToolMetadataScanError extends Error {}
class ToolMetadataDriftError extends ToolMetadataScanError {}

const GOVERNED_REPOSITORY_SCOPE_TOOL = Object.freeze({
  name: "get_governed_repository_scope",
  version: "1.0.0",
  description: "Show the GitHub repository scope currently governed by Hawk for this MCP session.",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    properties: {},
  },
});

export class HawkMcpProxy {
  constructor({
    childCommand,
    childArgs,
    hawkClient,
    aiSystemId,
    actorId,
    capabilityToken,
    mcpServerId,
    chainId,
    sessionId,
    clientApp,
    mcpServerUrl = null,
    repositoryScope = null,
    stdioFraming = "ndjson",
    scanDeadlineMs = DEFAULT_TOOL_SCAN_DEADLINE_MS,
    allowedTools = null,
    resultInspectionEnabled = false,
    resultInspectionMaxBytes = DEFAULT_RESULT_INSPECTION_MAX_BYTES,
    passEnv = null,
    stderr = process.stderr,
  }) {
    this.childPassEnv = normalizePassEnv(passEnv);
    this.childCommand = childCommand;
    this.childArgs = childArgs;
    this.hawkClient = hawkClient;
    this.aiSystemId = aiSystemId;
    this.actorId = actorId;
    this.capabilityToken = capabilityToken || "mcp-client";
    this.repositoryScope = normalizeGitHubRepositoryScope(repositoryScope);
    if (repositoryScope !== null && repositoryScope !== undefined && !this.repositoryScope) {
      throw new Error("GitHub repository scope must be github.com/<owner>/<repository>");
    }
    this.mcpServerId = this.repositoryScope
      ? repositoryScopedMcpServerId(this.repositoryScope)
      : (mcpServerId || "unknown-mcp-server");
    this.chainId = chainId || null;
    this.sessionId = sessionId || null;
    this.clientApp = typeof clientApp === "string" && clientApp.trim()
      ? clientApp.trim().slice(0, 128)
      : null;
    this.transportBinding = buildTransportBinding({ mcpServerUrl });
    this.mcpServerUrl = this.transportBinding.destination;
    this.stdioFraming = normalizeMcpStdioFraming(stdioFraming);
    this.scanDeadlineMs = normalizePositiveInteger(
      scanDeadlineMs,
      DEFAULT_TOOL_SCAN_DEADLINE_MS,
    );
    this.allowedTools = normalizeAllowedTools(allowedTools);
    this.resultInspectionEnabled = resultInspectionEnabled === true;
    this.resultInspectionMaxBytes = normalizePositiveInteger(
      resultInspectionMaxBytes,
      DEFAULT_RESULT_INSPECTION_MAX_BYTES,
    );
    this.stderr = stderr;
    this.pendingRequests = new Map();
    this.pendingToolLists = new Map();
    this.authorizedTools = new Map();
    this.toolListGeneration = 0;
    this.toolCallCount = 0;
  }

  start({ input = process.stdin, output = process.stdout } = {}) {
    if (!this.childCommand) {
      throw new Error("MCP child command is required after --");
    }

    this.child = spawn(this.childCommand, this.childArgs, {
      stdio: ["pipe", "pipe", "pipe"],
      env: childEnvironment(process.env, this.childPassEnv),
    });
    this.output = output;
    this.childUnavailable = false;
    this.protocolFailed = false;

    this.child.stderr.on("data", (chunk) => {
      this.stderr.write(chunk);
    });

    const clientFramer = createMcpMessageFramer(this.stdioFraming);
    const serverFramer = createMcpMessageFramer(this.stdioFraming);

    input.on("data", (chunk) => {
      try {
        clientFramer.push(chunk);
      } catch {
        this.#failFraming(output, "client");
      }
    });
    input.on("end", () => {
      try {
        clientFramer.end();
      } catch {
        this.#failFraming(output, "client");
        return;
      }
      if (
        !this.protocolFailed
        && !this.child.stdin.destroyed
        && !this.child.stdin.writableEnded
      ) {
        this.child.stdin.end();
      }
    });
    this.child.stdout.on("data", (chunk) => {
      try {
        serverFramer.push(chunk);
      } catch {
        this.#failFraming(output, "child");
      }
    });
    this.child.stdout.on("end", () => {
      try {
        serverFramer.end();
      } catch {
        this.#failFraming(output, "child");
        return;
      }
      this.#cleanupChildFailure(output);
      if (this.child?.exitCode === null && !this.child.killed) {
        this.child.kill();
      }
    });

    clientFramer.onMessage((message) => {
      this.#handleClientMessage(message, output).catch(() => {
        if (hasValidRequestId(message)) {
          this.#sendError(output, message.id, "MCP proxy request failed");
        }
      });
    });

    serverFramer.onMessage((message) => {
      this.#handleServerMessage(message, output).catch(() => {
        this.#resolvePendingToolList(message, false);
        if (hasValidRequestId(message)) {
          this.#sendError(output, message.id, "MCP proxy response processing failed");
        }
      });
    });

    this.child.on("error", () => {
      this.stderr.write("hawk-mcp-proxy child process error\n");
      this.#cleanupChildFailure(output);
    });
    this.child.stdin.on("error", () => {
      this.#cleanupChildFailure(output);
    });
    this.child.on("exit", (code) => {
      this.stderr.write(`hawk-mcp-proxy child exited with code ${code}\n`);
      this.#cleanupChildFailure(output);
    });
  }

  async #handleClientMessage(message, output) {
    if (Array.isArray(message)) {
      this.#sendError(output, null, "JSON-RPC batches are not supported by the Hawk MCP proxy", -32600);
      return;
    }
    const requestId = requestIdInfo(message);
    if (message?.method && requestId.kind === "invalid") {
      this.#sendError(output, null, "Invalid JSON-RPC request id", -32600);
      return;
    }
    if (
      message?.method === "resources/read"
      && requestId.kind === "request"
      && message?.params?.uri === HAWK_GOVERNANCE_RESOURCE_URI
    ) {
      output.write(this.#encodeMessage({ jsonrpc: "2.0", id: message.id, result: governanceResourceResult() }));
      return;
    }
    if (
      message?.method === "tools/call"
      && requestId.kind === "request"
      && this.#isGovernedRepositoryScopeTool(message)
    ) {
      this.toolCallCount += 1;
      output.write(this.#encodeMessage({
        jsonrpc: "2.0",
        id: message.id,
        result: attachGovernanceMetadata(
          {
            content: [
              {
                type: "text",
                text: this.#governedRepositoryScopeText(),
              },
            ],
            structuredContent: this.#governedRepositoryScopePayload(),
          },
          governanceStatusForDecision(
            { decision: "allow", control_mode: "inline_authorized" },
            this.#governanceContext(),
          ),
        ),
      }));
      return;
    }
    if (this.childUnavailable) {
      if (requestId.kind === "request" && message?.method) {
        this.#sendError(output, message.id, "MCP child server unavailable");
      }
      return;
    }
    let governanceDecision = null;
    let governanceContext = null;
    if (message?.method === "tools/call") {
      const barriers = [...this.pendingToolLists.values()];
      if (barriers.length) {
        const listResults = await Promise.all(barriers);
        if (listResults.some((result) => result !== true)) {
          this.#sendToolCallError(output, message, "MCP tool metadata is not authorized");
          return;
        }
      }
      if (!this.sessionId) {
        this.#sendToolCallError(output, message, "MCP session authority is required");
        return;
      }
      const toolName = message.params?.name || message.params?.tool || "unknown_tool";
      const argumentsObject = message.params?.arguments || message.params?.args || {};
      const repositoryScopeMismatch = this.repositoryScope
        && !matchesGitHubRepositoryScope(argumentsObject, this.repositoryScope);
      const authorizedTool = this.authorizedTools.get(toolName);
      if (!authorizedTool) {
        this.#sendToolCallError(output, message, "MCP tool metadata is not authorized");
        return;
      }
      const authorizedGeneration = this.toolListGeneration;
      const payload = buildAuthorizePayload({
        aiSystemId: this.aiSystemId,
        actorId: this.actorId,
        capabilityToken: this.capabilityToken,
        mcpServerId: this.mcpServerId,
        toolName,
        toolVersion: authorizedTool.toolVersion,
        toolFingerprintId: authorizedTool.toolFingerprintId,
        argumentsObject,
        repositoryScope: this.repositoryScope,
        chainId: this.chainId,
        sessionId: this.sessionId,
        clientApp: this.clientApp,
        mcpServerUrl: this.mcpServerUrl,
      });
      let decision;
      try {
        decision = await this.hawkClient.authorize(payload);
      } catch (error) {
        if (error instanceof HawkGatewayError) {
          this.#sendError(output, message.id, "MCP tool authorization failed", -32001, {
            "ai.hawk/error": {
              http_status: error.httpStatus,
              reason_code: error.reasonCode,
              ...(error.correlationId ? { correlation_id: error.correlationId } : {}),
            },
          });
        } else {
          this.#sendToolCallError(output, message, "MCP tool authorization failed");
        }
        return;
      }
      if (
        authorizedGeneration !== this.toolListGeneration
        || this.authorizedTools.get(toolName) !== authorizedTool
      ) {
        this.#sendToolCallError(output, message, "MCP tool metadata is not authorized");
        return;
      }
      const normalizedDecision = String(decision?.decision || "").trim().toLowerCase();
      if (!ALLOWED_AUTHORIZATION_DECISIONS.has(normalizedDecision)) {
        this.#sendToolCallError(output, message, "MCP tool authorization failed");
        return;
      }
      this.toolCallCount += 1;
      governanceContext = this.#governanceContext();
      if (repositoryScopeMismatch) {
        this.#sendToolCallError(
          output,
          message,
          "MCP tool call blocked by Hawk policy",
          {
            ...(decision && typeof decision === "object" ? decision : {}),
            decision: "block",
            control_mode: "inline_prevented",
          },
          governanceContext,
        );
        return;
      }
      if (shouldBlockDecision(decision)) {
        this.#sendToolCallError(output, message, "MCP tool call blocked by Hawk policy", decision, governanceContext);
        return;
      }
      governanceDecision = decision;
    }

    if (requestId.kind === "request" && message?.method) {
      if (this.pendingRequests.size >= MAX_PENDING_REQUESTS) {
        this.#sendError(output, message.id, "MCP proxy has too many pending requests");
        return;
      }
      if (this.pendingRequests.has(requestId.key)) {
        this.#sendError(output, message.id, "Duplicate JSON-RPC request id", -32600);
        return;
      }
      const pending = { method: message.method, id: message.id };
      if (governanceDecision) pending.governanceDecision = governanceDecision;
      if (governanceContext) pending.governanceContext = governanceContext;
      if (message.method === "tools/list") {
        if (this.toolListGeneration >= MAX_TOOL_LIST_GENERATION) {
          if (this.pendingToolLists.size) {
            this.#sendError(output, message.id, "MCP tool metadata scan failed");
            return;
          }
          this.toolListGeneration = 0;
        }
        const previousTools = new Map(this.authorizedTools);
        this.authorizedTools.clear();
        const generation = ++this.toolListGeneration;
        const barrier = createBarrier();
        pending.generation = generation;
        pending.previousTools = previousTools;
        pending.barrier = barrier;
        this.pendingToolLists.set(requestId.key, barrier.promise);
      }
      this.pendingRequests.set(requestId.key, pending);
    }
    this.child.stdin.write(this.#encodeMessage(message));
  }

  async #handleServerMessage(message, output) {
    if (hasMethod(message)) {
      if (message.method === "notifications/tools/list_changed") {
        this.#invalidateToolAuthority();
      }
      output.write(this.#encodeMessage(message));
      return;
    }
    if (!isResponseMessage(message)) {
      return;
    }
    const responseId = requestIdInfo(message);
    const pending = this.pendingRequests.get(responseId.key);
    if (!pending || pending.responseReceived) {
      return;
    }
    pending.responseReceived = true;
    if (pending.method === "tools/call") {
      this.pendingRequests.delete(responseId.key);
      if (message.error) {
        output.write(this.#encodeMessage(message));
        return;
      }
      try {
        const inspectedMessage = applyToolResultInspection(message, {
          enabled: this.resultInspectionEnabled,
          maxBytes: this.resultInspectionMaxBytes,
        });
        const governance = governanceStatusForDecision(pending.governanceDecision, {
          ...pending.governanceContext,
        });
        output.write(this.#encodeMessage({
          ...inspectedMessage,
          result: attachGovernanceMetadata(inspectedMessage.result, governance),
        }));
      } catch {
        this.#sendError(output, message.id, "MCP tool result inspection failed");
      }
      return;
    }
    if (pending.method !== "tools/list") {
      this.pendingRequests.delete(responseId.key);
      output.write(this.#encodeMessage(message));
      return;
    }

    if (message.error) {
      if (pending.generation === this.toolListGeneration) {
        this.authorizedTools.clear();
      }
      this.#completeToolList(responseId.key, pending, false);
      this.#sendError(output, message.id, "MCP tool metadata scan failed");
      return;
    }

    const tools = message?.result?.tools;
    if (!Array.isArray(tools)) {
      this.authorizedTools.clear();
      this.#completeToolList(responseId.key, pending, false);
      this.#sendError(output, message.id, "MCP tool metadata scan failed");
      return;
    }

    try {
      const exposedTools = this.#exposedTools(tools);
      const scannedTools = await this.#scanTools(exposedTools, pending.previousTools);
      if (!this.#isCurrentToolList(responseId.key, pending)) {
        this.#terminalizeStaleToolList(output, responseId.key, pending);
        return;
      }
      this.authorizedTools = scannedTools;
      this.#completeToolList(responseId.key, pending, true);
      output.write(this.#encodeMessage({
        ...message,
        result: {
          ...message.result,
          tools: this.#exposedToolsWithLocalStatus(exposedTools)
            .map((tool) => governanceToolMetadata(tool)),
        },
      }));
    } catch (error) {
      if (!this.#isCurrentToolList(responseId.key, pending)) {
        this.#terminalizeStaleToolList(output, responseId.key, pending);
        return;
      }
      this.authorizedTools.clear();
      this.#completeToolList(responseId.key, pending, false);
      this.#sendError(
        output,
        message.id,
        error instanceof ToolMetadataDriftError
          ? "MCP tool metadata drift requires approval"
          : "MCP tool metadata scan failed",
      );
    }
  }

  async #scanTools(tools, previousTools) {
    if (tools.length > MAX_TOOLS_PER_LIST) {
      throw new ToolMetadataScanError();
    }

    const preparedTools = [];
    const toolNames = new Set();
    let totalMetadataBytes = 0;
    for (const tool of tools) {
      const scanPayload = buildToolScanPayload({
        mcpServerId: this.mcpServerId,
        tool,
        chainId: this.chainId,
        mcpServerUrl: this.mcpServerUrl,
      });
      const toolName = String(scanPayload.tool_name || "").trim();
      if (!toolName || toolName === "unknown_tool" || toolNames.has(toolName)) {
        throw new ToolMetadataScanError();
      }
      const metadataCanonical = canonicalJson(scanPayload);
      const metadataBytes = Buffer.byteLength(metadataCanonical, "utf8");
      totalMetadataBytes += metadataBytes;
      if (
        metadataBytes > MAX_TOOL_METADATA_BYTES
        || totalMetadataBytes > MAX_TOOL_LIST_METADATA_BYTES
      ) {
        throw new ToolMetadataScanError();
      }
      toolNames.add(toolName);
      preparedTools.push({ metadataCanonical, scanPayload, toolName });
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.scanDeadlineMs);
    const scanResults = new Array(preparedTools.length);
    let nextScanIndex = 0;
    let transportFailed = false;
    let sawMetadataDrift = false;
    let sawUnapprovedMetadata = false;
    const scanStartedAt = Date.now();
    let observedScanMs = 0;
    try {
      const scanWorker = async () => {
        while (!controller.signal.aborted) {
          const elapsedMs = Date.now() - scanStartedAt;
          const remainingMs = this.scanDeadlineMs - elapsedMs;
          if (observedScanMs > 0 && remainingMs <= observedScanMs) {
            return;
          }
          const index = nextScanIndex;
          nextScanIndex += 1;
          if (index >= preparedTools.length) return;
          try {
            const singleScanStartedAt = Date.now();
            scanResults[index] = await this.hawkClient.scanTool(
              preparedTools[index].scanPayload,
              { signal: controller.signal },
            );
            observedScanMs = Math.max(observedScanMs, Date.now() - singleScanStartedAt);
          } catch {
            transportFailed = true;
            controller.abort();
            return;
          }
        }
      };
      await Promise.all(
        Array.from(
          { length: Math.min(MAX_CONCURRENT_TOOL_SCANS, preparedTools.length) },
          () => scanWorker(),
        ),
      );
    } finally {
      clearTimeout(timer);
    }
    if (controller.signal.aborted || transportFailed) {
      throw new ToolMetadataScanError();
    }

    const scannedTools = new Map();
    for (let index = 0; index < preparedTools.length; index += 1) {
      const { metadataCanonical, scanPayload, toolName } = preparedTools[index];
      const scanResult = scanResults[index];
      const toolFingerprintId = String(scanResult?.tool_fingerprint_id || "").trim();
      const trustStatus = String(scanResult?.trust_status || "").trim().toLowerCase();
      const poisoningDecision = String(scanResult?.tool_poisoning_decision || "").trim().toLowerCase();
      if (
        scanResult?.status !== "completed"
        || !toolFingerprintId
        || !TOOL_TRUST_STATUSES.has(trustStatus)
        || !TOOL_POISONING_DECISIONS.has(poisoningDecision)
      ) {
        throw new ToolMetadataScanError();
      }
      if (trustStatus === "changed") {
        sawMetadataDrift = true;
        continue;
      }
      if (trustStatus !== "approved" || poisoningDecision !== "allow") {
        sawUnapprovedMetadata = true;
        continue;
      }
      const previous = previousTools.get(toolName);
      if (
        previous
        && (
          previous.toolFingerprintId !== toolFingerprintId
          || previous.metadataCanonical !== metadataCanonical
        )
      ) {
        sawMetadataDrift = true;
        continue;
      }
      scannedTools.set(toolName, {
        toolFingerprintId,
        toolVersion: scanPayload.tool_version,
        metadataCanonical,
      });
    }
    if (sawMetadataDrift) {
      throw new ToolMetadataDriftError();
    }
    if (sawUnapprovedMetadata) {
      throw new ToolMetadataScanError();
    }
    if (previousTools.size && !sameKeys(previousTools, scannedTools)) {
      throw new ToolMetadataDriftError();
    }
    return scannedTools;
  }

  #exposedTools(tools) {
    if (this.allowedTools === null) {
      return tools;
    }
    return tools.filter((tool) => this.allowedTools.has(String(tool?.name || "").trim()));
  }

  #exposedToolsWithLocalStatus(tools) {
    if (!this.repositoryScope) {
      return tools;
    }
    return [...tools, GOVERNED_REPOSITORY_SCOPE_TOOL];
  }

  #completeToolList(id, pending, succeeded) {
    this.pendingRequests.delete(id);
    this.pendingToolLists.delete(id);
    pending.barrier.resolve(succeeded);
  }

  #isCurrentToolList(id, pending) {
    return (
      !this.childUnavailable
      && pending.generation === this.toolListGeneration
      && this.pendingRequests.get(id) === pending
      && this.pendingToolLists.has(id)
    );
  }

  #terminalizeStaleToolList(output, id, pending) {
    if (
      this.childUnavailable
      || this.pendingRequests.get(id) !== pending
      || !this.pendingToolLists.has(id)
    ) {
      return;
    }
    this.#completeToolList(id, pending, false);
    this.#sendError(output, pending.id, "MCP tool metadata scan failed");
  }

  #invalidateToolAuthority() {
    this.authorizedTools.clear();
    this.toolListGeneration = this.toolListGeneration >= MAX_TOOL_LIST_GENERATION
      ? 1
      : this.toolListGeneration + 1;
  }

  #resolvePendingToolList(message, succeeded) {
    if (!isResponseMessage(message)) {
      return;
    }
    const responseId = requestIdInfo(message);
    const pending = this.pendingRequests.get(responseId.key);
    if (pending?.method === "tools/list") {
      this.#completeToolList(responseId.key, pending, succeeded);
    }
  }

  #cleanupChildFailure(output) {
    if (this.childUnavailable) {
      return;
    }
    this.childUnavailable = true;
    const pending = [...this.pendingRequests.values()];
    for (const request of pending) {
      if (request.method === "tools/list") {
        request.barrier.resolve(false);
      }
    }
    this.pendingRequests.clear();
    this.pendingToolLists.clear();
    this.authorizedTools.clear();
    this.toolListGeneration = this.toolListGeneration >= MAX_TOOL_LIST_GENERATION
      ? 1
      : this.toolListGeneration + 1;
    for (const request of pending) {
      this.#sendError(output, request.id, "MCP child server unavailable");
    }
  }

  #failFraming(output, source) {
    if (this.protocolFailed) {
      return;
    }
    this.protocolFailed = true;
    const hadPendingRequests = this.pendingRequests.size > 0;
    if (source === "client") {
      this.#sendError(output, null, "Invalid MCP client frame", -32600);
    }
    this.#cleanupChildFailure(output);
    if (source === "child" && !hadPendingRequests) {
      this.#sendError(output, null, "MCP child server unavailable");
    }
    if (this.child?.exitCode === null) {
      this.child.kill();
    }
  }

  #sendError(output, id, message, code = -32001, data = undefined) {
    output.write(this.#encodeMessage({
      jsonrpc: "2.0",
      id: id ?? null,
      error: {
        code,
        message,
        ...(data === undefined ? {} : { data }),
      },
    }));
  }

  #encodeMessage(message) {
    return encodeMcpMessage(message, this.stdioFraming);
  }

  #governanceContext() {
    return {
      sessionId: this.sessionId,
      serverId: this.mcpServerId,
      connected: true,
      clientApp: this.clientApp,
      availableToolCount: this.authorizedTools.size,
      toolCallCount: this.toolCallCount,
      tokenUsage: { total: null, provenance: "unknown" },
      costUsage: { amount: null, currency: null, provenance: "unknown", source: "unknown" },
    };
  }

  #isGovernedRepositoryScopeTool(message) {
    return String(message?.params?.name || message?.params?.tool || "").trim()
      === GOVERNED_REPOSITORY_SCOPE_TOOL.name;
  }

  #governedRepositoryScopePayload() {
    const allowedTools = this.allowedTools === null
      ? []
      : [...this.allowedTools].sort();
    return {
      repository_scope: this.repositoryScope || null,
      blocked_outside_scope: Boolean(this.repositoryScope),
      enforcement_mode: this.repositoryScope ? "enforce_selected_repository" : "unscoped",
      client_app: this.clientApp,
      mcp_server_id: this.mcpServerId,
      session_id: this.sessionId,
      available_governed_tools: allowedTools,
      guidance: this.repositoryScope
        ? `Use only ${this.repositoryScope} for GitHub MCP calls. Requests for other repositories are blocked before reaching GitHub.`
        : "No repository scope is configured for this MCP proxy instance.",
    };
  }

  #governedRepositoryScopeText() {
    const payload = this.#governedRepositoryScopePayload();
    const tools = payload.available_governed_tools.length
      ? payload.available_governed_tools.join(", ")
      : "reported by the connected MCP server";
    return [
      "Governed GitHub repository scope",
      `Allowed repository: ${payload.repository_scope || "unscoped"}`,
      `Mode: ${payload.enforcement_mode}`,
      `Blocked outside scope: ${payload.blocked_outside_scope ? "yes" : "no"}`,
      `Client app: ${payload.client_app || "unknown"}`,
      `MCP server: ${payload.mcp_server_id}`,
      `Session: ${payload.session_id || "unavailable"}`,
      `Governed tools: ${tools}`,
      payload.guidance,
    ].join("\n");
  }

  #sendToolCallError(output, request, message, decision = null, context = null) {
    if (hasValidRequestId(request)) {
      const governance = decision
        ? governanceStatusForDecision(decision, context || this.#governanceContext())
        : null;
      this.#sendError(output, request.id, message, -32001, governance ? { "ai.hawk/governance": governance } : undefined);
    }
  }
}

function createBarrier() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function neverPassedToChild(name) {
  return CHILD_ENVIRONMENT_DENYLIST.has(name)
    || name.startsWith("HAWK_AGENT_")
    || name.startsWith("HAWK_ENDPOINT_");
}

/**
 * The names a child MCP server may receive beyond CHILD_ENVIRONMENT_ALLOWLIST, from `--pass-env` or
 * HAWK_MCP_PASS_ENV: a list or comma-separated text of environment variable names. Hawk's own tokens and endpoint
 * identity can never be named.
 */
export function normalizePassEnv(value) {
  if (value === null || value === undefined || value === "") {
    return [];
  }
  const entries = Array.isArray(value) ? value : String(value).split(",");
  const names = [];
  for (const entry of entries) {
    const name = String(entry ?? "").trim();
    if (!name) continue;
    if (!ENVIRONMENT_NAME_PATTERN.test(name)) {
      throw new Error(`Invalid environment variable name for --pass-env: ${name.slice(0, 64)}`);
    }
    if (neverPassedToChild(name)) {
      throw new Error(`${name} is a Hawk credential or endpoint identity and is never passed to an MCP server`);
    }
    if (!names.includes(name)) names.push(name);
  }
  return names;
}

/**
 * The environment of the child MCP server: only CHILD_ENVIRONMENT_ALLOWLIST (what a process needs to run) and the
 * names passed explicitly. Everything else the proxy was started with (API keys, cloud credentials, tokens) stays
 * with the proxy.
 */
export function childEnvironment(environment, passEnv = [], { platform = process.platform } = {}) {
  // Windows names are case-insensitive (Path, SystemRoot).
  const fold = platform === "win32" ? (name) => name.toUpperCase() : (name) => name;
  const allowed = new Set([...CHILD_ENVIRONMENT_ALLOWLIST, ...passEnv].map(fold));
  return Object.fromEntries(
    Object.entries(environment).filter(([name, value]) => (
      allowed.has(fold(name))
      && !neverPassedToChild(fold(name))
      && typeof value === "string"
    )),
  );
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function sameKeys(left, right) {
  return left.size === right.size && [...left.keys()].every((key) => right.has(key));
}

function normalizePositiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0
    ? Math.floor(parsed)
    : fallback;
}

function normalizeAllowedTools(value) {
  if (value === null || value === undefined || value === "") {
    return null;
  }
  const items = Array.isArray(value)
    ? value
    : String(value).split(",");
  const names = items.map((item) => String(item || "").trim()).filter(Boolean);
  if (names.length === 0) {
    return null;
  }
  return new Set(names);
}

function hasValidRequestId(message) {
  return requestIdInfo(message).kind === "request";
}

function hasMethod(message) {
  return Boolean(
    message
    && typeof message === "object"
    && !Array.isArray(message)
    && Object.prototype.hasOwnProperty.call(message, "method"),
  );
}

function isResponseMessage(message) {
  if (
    !message
    || typeof message !== "object"
    || Array.isArray(message)
    || hasMethod(message)
    || requestIdInfo(message).kind !== "request"
  ) {
    return false;
  }
  const hasResult = Object.prototype.hasOwnProperty.call(message, "result");
  const hasError = Object.prototype.hasOwnProperty.call(message, "error");
  return hasResult !== hasError;
}

function requestIdInfo(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) {
    return { kind: "absent" };
  }
  if (!Object.prototype.hasOwnProperty.call(message, "id")) {
    return { kind: "absent" };
  }
  const id = message.id;
  if (typeof id === "string") {
    return { kind: "request", key: `s:${id}` };
  }
  if (typeof id === "number" && Number.isFinite(id)) {
    return { kind: "request", key: `n:${String(Object.is(id, -0) ? 0 : id)}` };
  }
  return { kind: "invalid" };
}
