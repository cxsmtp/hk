import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const stateUrl = new URL("../src/lib/policy-builder-state.ts", import.meta.url);

async function loadStateModule() {
  assert.equal(existsSync(stateUrl), true, "policy builder state module must exist");
  const source = readFileSync(stateUrl, "utf8");
  const result = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
    reportDiagnostics: true,
  });
  const errors = (result.diagnostics || []).filter(
    (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
  );
  assert.deepEqual(errors, []);
  const encoded = Buffer.from(result.outputText).toString("base64");
  return import(`data:text/javascript;base64,${encoded}`);
}

test("buildScopedRuleDraft keeps users, agents, tools, action types and operations separate", async () => {
  const { buildScopedRuleDraft } = await loadStateModule();

  const rule = buildScopedRuleDraft({
    ruleId: "  protect-write  ",
    priority: 10,
    description: "  Protect privileged writes  ",
    userIds: [" user-1 ", "user-1", "User-2"],
    agentIds: [" agent-1 ", "agent-1"],
    sourceSurfaces: [" MCP ", "mcp", "Endpoint"],
    tools: [" Filesystem.Write_File ", "filesystem.write_file"],
    actionTypes: [" Tool_Call ", "tool_call"],
    actionOperations: [" WRITE ", "write"],
    decision: "require_approval",
    reasonCode: "  privileged_write  ",
    explanation: "  Approval is required.  ",
    recommendedAction: "  Request approval.  ",
    metadata: { source: "protect" },
  });

  assert.equal(rule.rule_id, "protect-write");
  assert.equal(rule.description, "Protect privileged writes");
  assert.equal(rule.priority, 10);
  assert.deepEqual(rule.subjects, {
    user_ids: ["user-1", "User-2"],
    agent_ids: ["agent-1"],
    source_surfaces: ["mcp", "endpoint"],
  });
  assert.deepEqual(rule.resources, { tools: ["filesystem.write_file"] });
  assert.deepEqual(rule.actions, {
    types: ["tool_call"],
    operations: ["write"],
  });
  assert.deepEqual(rule.effect, {
    decision: "require_approval",
    reason_code: "privileged_write",
    explanation: "Approval is required.",
    recommended_action: "Request approval.",
    priority: 10,
  });
  assert.deepEqual(rule.metadata, { source: "protect" });
});

test("runtime-like matching requires exact selectors and preserves identifier case", async () => {
  const { buildScopedRuleDraft, matchObservedEventAgainstRule } = await loadStateModule();
  const rule = buildScopedRuleDraft({
    ruleId: "protect-write",
    userIds: ["User-1"],
    agentIds: ["agent-1"],
    sourceSurfaces: ["mcp"],
    tools: ["filesystem.write_file"],
    actionTypes: ["tool_call"],
    actionOperations: ["write"],
  });
  const matchingEvent = {
    user_id: "User-1",
    agent_id: "agent-1",
    source_surface: "MCP",
    tool_name: "FILESYSTEM.WRITE_FILE",
    action_type: "TOOL_CALL",
    operation: "WRITE",
  };

  assert.equal(matchObservedEventAgainstRule(matchingEvent, rule), "match");
  assert.equal(
    matchObservedEventAgainstRule({ ...matchingEvent, tool_name: "prefix.filesystem.write_file" }, rule),
    "no_match",
  );
  assert.equal(
    matchObservedEventAgainstRule({ ...matchingEvent, action_type: "tool_call_extended" }, rule),
    "no_match",
  );
  assert.equal(
    matchObservedEventAgainstRule({ ...matchingEvent, user_id: "user-1" }, rule),
    "no_match",
  );
  assert.equal(
    matchObservedEventAgainstRule({ ...matchingEvent, agent_id: "Agent-1" }, rule),
    "no_match",
  );
});

test("runtime-like matching returns unknown when a required event field is absent", async () => {
  const { buildScopedRuleDraft, matchObservedEventAgainstRule } = await loadStateModule();
  const rule = buildScopedRuleDraft({
    ruleId: "protect-write",
    userIds: ["user-1"],
    agentIds: ["agent-1"],
    sourceSurfaces: ["mcp"],
    tools: ["filesystem.write_file"],
    actionTypes: ["tool_call"],
    actionOperations: ["write"],
  });
  const completeEvent = {
    user_id: "user-1",
    agent_id: "agent-1",
    source_surface: "mcp",
    tool_name: "filesystem.write_file",
    action_type: "tool_call",
    operation: "write",
  };

  for (const field of ["user_id", "agent_id", "source_surface", "tool_name", "action_type", "operation"]) {
    assert.equal(
      matchObservedEventAgainstRule({ ...completeEvent, [field]: undefined }, rule),
      "unknown",
      `${field} should be required`,
    );
  }

  assert.equal(
    matchObservedEventAgainstRule(
      { ...completeEvent, operation: undefined, tool_name: "different.tool" },
      rule,
    ),
    "no_match",
    "a known mismatch is definitive even when another selector cannot be evaluated",
  );
});

test("empty and wildcard selectors do not require corresponding event fields", async () => {
  const { buildScopedRuleDraft, matchObservedEventAgainstRule } = await loadStateModule();
  const rule = buildScopedRuleDraft({
    ruleId: "all-mcp-actions",
    userIds: ["*"],
    sourceSurfaces: ["mcp"],
  });

  assert.equal(matchObservedEventAgainstRule({ source_surface: "MCP" }, rule), "match");
  assert.equal(matchObservedEventAgainstRule({ source_surface: "browser" }, rule), "no_match");
});

test("builds persisted application, domain, provider, model and MCP selectors", async () => {
  const { buildScopedRuleDraft, matchObservedEventAgainstRule } = await loadStateModule();
  const rule = buildScopedRuleDraft({
    ruleId: "customer-targets",
    applications: ["Claude Desktop"],
    domains: ["example.com"],
    providers: ["Anthropic"],
    models: ["claude-3"],
    mcpServers: ["repo-server"],
    tools: ["repo.read"],
    actionTypes: ["tool_call"],
    actionOperations: ["read"],
  });
  assert.deepEqual(rule.resources.domains, ["example.com"]);
  assert.deepEqual(rule.resources.providers, ["anthropic"]);
  assert.deepEqual(rule.resources.models, ["claude-3"]);
  assert.deepEqual(rule.condition_tree, { all: [
    { field: "application", operator: "in", value: ["Claude Desktop"] },
    { field: "mcp_server", operator: "in", value: ["repo-server"] },
  ] });
  assert.equal(matchObservedEventAgainstRule({ application: "claude desktop", domain: "sub.example.com", provider: "anthropic", model: "claude-3", mcp_server: "repo-server", tool_name: "repo.read", action_type: "tool_call", operation: "read" }, rule), "match");
  assert.equal(matchObservedEventAgainstRule({ application: "claude desktop", provider: "anthropic" }, rule), "unknown");
});
