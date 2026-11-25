import test from "node:test";
import assert from "node:assert/strict";

import {
  buildAuthorizePayload,
  buildTransportBinding,
  classifyToolCall,
  destinationMatchesMcpServerUrl,
  matchesGitHubRepositoryScope,
  repositoryScopedMcpServerId,
  shouldBlockDecision,
} from "../src/policy.mjs";

test("remote MCP destination binding is explicit and stdio is never implied remote coverage", () => {
  assert.deepEqual(buildTransportBinding({}), {
    transport: "stdio_child",
    destination: null,
    binding_status: "local_child",
  });
  assert.deepEqual(buildTransportBinding({ mcpServerUrl: "https://mcp.example.test/mcp/" }), {
    transport: "remote_http_declared",
    destination: "https://mcp.example.test/mcp",
    binding_status: "declared_not_routed",
  });
  assert.equal(destinationMatchesMcpServerUrl("https://mcp.example.test/mcp", "https://mcp.example.test/mcp/"), true);
  assert.equal(destinationMatchesMcpServerUrl("https://other.example.test/mcp", "https://mcp.example.test/mcp"), false);
});

test("remote binding rejects credentials and query-bearing URLs", () => {
  assert.throws(() => buildTransportBinding({ mcpServerUrl: "https://user:pass@example.test/mcp" }));
  assert.throws(() => buildTransportBinding({ mcpServerUrl: "https://example.test/mcp?token=secret" }));
});

test("classifyToolCall marks secret file reads as high-risk credential access", () => {
  const classified = classifyToolCall({
    toolName: "read_file",
    argumentsObject: { path: "/repo/.env" },
  });

  assert.equal(classified.action, "secret_access_attempt");
  assert.equal(classified.resource, "/repo/.env");
  assert.equal(classified.toolCategory, "credential");
});

test("classifyToolCall marks file write tools as write actions", () => {
  const classified = classifyToolCall({
    toolName: "write_file",
    argumentsObject: { path: "/repo/src/auth.ts" },
  });

  assert.equal(classified.action, "file_write");
  assert.equal(classified.resource, "/repo/src/auth.ts");
  assert.equal(classified.toolCategory, "write");
});

test("shouldBlockDecision blocks block and review decisions", () => {
  assert.equal(shouldBlockDecision({ decision: "block" }), true);
  assert.equal(shouldBlockDecision({ decision: "review" }), true);
  assert.equal(shouldBlockDecision({ decision: "require_approval" }), true);
  assert.equal(shouldBlockDecision({ decision: "hold_for_approval" }), true);
  assert.equal(shouldBlockDecision({ decision: "allow" }), false);
});

test("authorization binds the declared client application without interaction content", () => {
  const payload = buildAuthorizePayload({
    toolName: "read_file",
    argumentsObject: { path: "/repo/readme.md" },
    clientApp: "Codex",
  });
  assert.equal(payload.client_app, "Codex");
  assert.equal(Object.prototype.hasOwnProperty.call(payload, "prompt"), false);
});

test("authorization carries explicit MCP transport binding without claiming remote routing", () => {
  const payload = buildAuthorizePayload({
    mcpServerId: "higgsfield",
    toolName: "list_history",
    argumentsObject: {},
    mcpServerUrl: "https://mcp.higgsfield.ai/mcp/",
  });
  assert.deepEqual(payload.tool_usage_meta.transport_binding, {
    transport: "remote_http_declared",
    destination: "https://mcp.higgsfield.ai/mcp",
    binding_status: "declared_not_routed",
  });
});

test("classifyToolCall binds the approved GitHub pull-request server to its repository", () => {
  const classified = classifyToolCall({
    mcpServerId: "github-pull-requests",
    toolName: "list_pull_requests",
    argumentsObject: { owner: "github", repo: "github-mcp-server" },
  });

  assert.equal(classified.resource, "github.com/github/github-mcp-server");
  assert.equal(classified.destination, "https://github.com/github/github-mcp-server");
  assert.equal(classified.dataClassification, "public");
});

test("authorization carries public GitHub repository scope into governed MCP session context", () => {
  const payload = buildAuthorizePayload({
    mcpServerId: "github-pull-requests",
    toolName: "list_pull_requests",
    argumentsObject: { owner: "github", repo: "github-mcp-server" },
  });

  assert.equal(payload.resource, "github.com/github/github-mcp-server");
  assert.deepEqual(payload.session_context, {
    data_classification: "public",
    environment: "production",
  });
});

test("classifyToolCall does not turn malformed or unrelated arguments into a GitHub scope", () => {
  const invalidRepositoryArguments = [
    { owner: "github/other", repo: "github-mcp-server" },
    { owner: "github", repo: "../github-mcp-server" },
    { owner: "github ", repo: "github-mcp-server" },
    { owner: "https://github.com", repo: "github-mcp-server" },
    { owner: "", repo: "github-mcp-server" },
    { owner: "github", repo: "" },
    { owner: 42, repo: "github-mcp-server" },
    { owner: "github", repo: null },
  ];

  for (const argumentsObject of invalidRepositoryArguments) {
    const classified = classifyToolCall({
      mcpServerId: "github-pull-requests",
      toolName: "list_pull_requests",
      argumentsObject,
    });
    assert.equal(classified.resource, "unknown");
    assert.equal(classified.destination, null);
  }

  const unrelatedServer = classifyToolCall({
    mcpServerId: "other-server",
    toolName: "list_pull_requests",
    argumentsObject: { owner: "github", repo: "github-mcp-server" },
  });
  assert.equal(unrelatedServer.resource, "unknown");
  assert.equal(unrelatedServer.destination, null);
});

test("repository-scoped GitHub identities bind only their exact normalized repository", () => {
  const scope = "github.com/hawk-demo/governed-repo";
  const mcpServerId = repositoryScopedMcpServerId(scope);

  assert.equal(
    mcpServerId,
    "github-pull-requests--hawk-demo--governed-repo",
  );
  assert.equal(
    matchesGitHubRepositoryScope(
      { owner: "Hawk-Demo", repo: "governed-repo" },
      scope,
    ),
    true,
  );
  assert.equal(
    matchesGitHubRepositoryScope(
      { owner: "github", repo: "github-mcp-server" },
      scope,
    ),
    false,
  );

  const classified = classifyToolCall({
    mcpServerId,
    repositoryScope: scope,
    toolName: "create_pull_request",
    argumentsObject: { owner: "Hawk-Demo", repo: "governed-repo" },
  });
  assert.equal(classified.resource, "github.com/hawk-demo/governed-repo");
  assert.equal(classified.destination, "https://github.com/hawk-demo/governed-repo");
});
