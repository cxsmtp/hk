import assert from "node:assert/strict";
import test from "node:test";
import ts from "typescript";
import { readFileSync } from "node:fs";

async function loadMapper() {
  const source = readFileSync(new URL("../src/lib/activity-presentation.ts", import.meta.url), "utf8");
  const result = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  const encoded = Buffer.from(result.outputText).toString("base64");
  return import(`data:text/javascript;base64,${encoded}`);
}

const base = {
  event_id: "evt-1",
  tenant_id: "tenant-1",
  source_surface: "llm_gateway",
  event_type: "model_request",
  decision: "allow",
  policy_decision: "allow",
  created_at: "2026-09-27T10:00:00Z",
  timestamp: "2026-09-27T10:00:00Z",
  evidence_node_ids: [],
  risk_score: 0,
};

test("allowed requests keep decision separate from missing execution evidence", async () => {
  const { presentActivity } = await loadMapper();
  const row = presentActivity({ ...base, model: "gpt-5", provider: "OpenAI" });
  assert.equal(row.decision, "Allowed");
  assert.equal(row.outcome, "Execution not captured");
  assert.equal(row.category, "Model request");
});

test("blocked requests only claim prevention when explicit evidence says so", async () => {
  const { presentActivity } = await loadMapper();
  const row = presentActivity({ ...base, source_surface: "mcp", event_type: "tool_call", tool_name: "repo.write", policy_decision: "block", decision: "block", metadata: { prevented: true } });
  assert.equal(row.decision, "Blocked");
  assert.equal(row.outcome, "Prevented");
  assert.deepEqual(row.categories, ["Blocked", "Tool call"]);
});

test("audit fallback decision drives display, category, warning and blocked outcome consistently", async () => {
  const { presentActivity } = await loadMapper();
  const warned = presentActivity({ ...base, decision: "", policy_decision: "", event_type: "model_request", model: "gpt-5" }, { enforcement_action: "warn" });
  assert.equal(warned.decision, "Warned");
  assert.equal(warned.category, "Model request");
  assert.ok(warned.categories.includes("Warning"));
  const blocked = presentActivity({ ...base, decision: "", policy_decision: "", event_type: "tool_call", tool_name: "repo.write", control_outcome: "prevented" }, { enforcement_action: "block" });
  assert.equal(blocked.decision, "Blocked");
  assert.equal(blocked.category, "Blocked");
  assert.ok(blocked.categories.includes("Blocked"));
  assert.equal(blocked.outcome, "Prevented");
});

test("missing identity and redacted prompt stay explicit", async () => {
  const { presentActivity } = await loadMapper();
  const row = presentActivity({ ...base, user_id: null, user_email: null, metadata: { prompt_payload: { content_access_level: "REDACTED_PREVIEW", redacted_preview: "[redacted]" } } });
  assert.equal(row.actor, "Initiator unknown");
  assert.equal(row.request.contentAccess, "REDACTED_PREVIEW");
  assert.equal(row.request.preview, "[redacted]");
});

test("GitHub author and owner do not become initiator or causal links", async () => {
  const { presentActivity } = await loadMapper();
  const row = presentActivity({ ...base, source_surface: "github", event_type: "repository_action", metadata: { repository_owner: "owner", commit_author: "author", commit_sha: "abc" } });
  assert.equal(row.actor, "Initiator unknown");
  assert.deepEqual(row.related, []);
  assert.equal(row.target, "Repository action");
});

test("related activity requires stored references", async () => {
  const { presentActivity } = await loadMapper();
  const row = presentActivity({ ...base, related_event_ids: ["evt-2"], correlation_id: "corr-1", chain_id: "chain-1" });
  assert.deepEqual(row.related, ["evt-2"]);
  assert.deepEqual(row.references, { correlationId: "corr-1", chainId: "chain-1" });
});

test("audit and runtime trace enrich known identities without inventing execution", async () => {
  const { presentActivity } = await loadMapper();
  const audit = {
    action_id: "audit-1",
    runtime_event_id: "evt-1",
    action_type: "repository_action",
    ai_app: "MCP agent",
    ai_model: "gpt-5",
    correlation_id: "corr-audit",
    enforcement_action: "allow",
    prompt_payload: { content_access_level: "REDACTED_PREVIEW", redacted_preview: "[repo request]" },
  };
  const trace = {
    runtime_event: { event_id: "evt-1" },
    canonical_ai_action: { actor: { identity_id: "runtime-principal", identity_type: "agent", agent_id: "agent-1", user_id: "person@example.com" }, action: { action_type: "repository_action", operation: "pull_request.create", tool_name: "github", target_resource: "org/repo", redacted_arguments: "[redacted]" } },
    decision_receipt: { decision: "allowed", chain_id: "chain-trace" },
    execution_receipt: { downstream_objects: ["pull-request-ref"], execution_status: "not_captured" },
    explicit_git_refs: ["refs/pull/42/head"],
  };
  const row = presentActivity({ ...base, source_surface: "github", event_type: "repository_action", requesting_user: "person@example.com", agent_id: "agent-1", executing_principal: "runtime-principal", repository_owner: "org", commit_author: "author", reviewer: "reviewer", merger: "merger" }, audit, trace);
  assert.equal(row.actor, "person@example.com");
  assert.equal(row.application, "agent-1");
  assert.equal(row.identities.executingPrincipal, "runtime-principal");
  assert.equal(row.identities.owner, "org");
  assert.equal(row.identities.author, "author");
  assert.equal(row.identities.reviewer, "reviewer");
  assert.equal(row.identities.merger, "merger");
  assert.equal(row.action, "pull_request.create");
  assert.equal(row.target, "org/repo");
  assert.equal(row.outcome, "not_captured");
  assert.deepEqual(row.references, { correlationId: "corr-audit", chainId: "chain-trace", gitRefs: ["refs/pull/42/head"] });
  assert.deepEqual(row.trace.downstreamObjects, ["pull-request-ref"]);
  assert.equal(row.rawAudit, audit);
  assert.equal(row.rawTrace, trace);
});

test("nested LLM trace preserves provider, model, redacted structures, approval and execution", async () => {
  const { presentActivity } = await loadMapper();
  const argumentsValue = { prompt: "[redacted]", options: { temperature: 0.2 } };
  const resultValue = { text: "[redacted]", usage: { tokens: 12 } };
  const trace = {
    canonical_ai_action: {
      actor: { identity_id: "requester-1", agent_id: "agent-1" },
      surface: { provider: "Anthropic", model: "claude-sonnet" },
      action: { action_type: "model_request", operation: "messages.create", redacted_arguments: argumentsValue },
      approval: { status: "approved", approver: "reviewer-1" },
    },
    decision_receipt: { decision: "allowed" },
    execution_receipt: { execution_status: "completed", redacted_result: resultValue, downstream_objects: [{ type: "message", id: "msg-1" }] },
  };
  const row = presentActivity({ ...base, action_type: "model_request" }, undefined, trace);
  assert.equal(row.action, "messages.create");
  assert.equal(row.actor, "requester-1");
  assert.equal(row.identities.executingPrincipal, "Unavailable");
  assert.equal(row.evidence.provider, "Anthropic");
  assert.equal(row.evidence.model, "claude-sonnet");
  assert.deepEqual(row.evidence.redactedArguments, argumentsValue);
  assert.deepEqual(row.evidence.redactedResult, resultValue);
  assert.deepEqual(row.evidence.approval, trace.canonical_ai_action.approval);
  assert.deepEqual(row.evidence.execution, trace.execution_receipt);
  assert.deepEqual(row.trace.downstreamObjects, [{ type: "message", id: "msg-1" }]);
});

test("nested MCP and Git traces keep roles and explicit repository references separate", async () => {
  const { presentActivity } = await loadMapper();
  const trace = {
    canonical_ai_action: {
      actor: { identity_id: "requester-2", agent_id: "agent-2" },
      surface: { mcp_server_id: "github-mcp" },
      action: { action_type: "tool_call", operation: "pull_request.create", tool_name: "create_pull_request", redacted_arguments: { title: "[redacted]" } },
    },
    runtime_event: { repository: "org/repo", branch: "feature/x", commit_sha: "a1b2c3d4", pull_request_number: 42 },
    execution_receipt: { executing_principal: "service-account", execution_status: "completed", downstream_objects: [{ repository: "org/repo", pull_request_url: "https://github.com/org/repo/pull/42", id: "pr-42" }] },
  };
  const audit = { action_type: "repository_action", metadata: { repository_owner: "repo-owner", commit_author: "commit-author", reviewer: "reviewer", merger: "merger" } };
  const row = presentActivity({ ...base, source_surface: "mcp", action_type: "repository_action" }, audit, trace);
  assert.equal(row.action, "pull_request.create");
  assert.equal(row.evidence.mcpServer, "github-mcp");
  assert.equal(row.evidence.mcpTool, "create_pull_request");
  assert.equal(row.identities.requestingPerson, "requester-2");
  assert.equal(row.identities.executingPrincipal, "service-account");
  assert.equal(row.identities.owner, "repo-owner");
  assert.equal(row.identities.author, "commit-author");
  assert.equal(row.identities.reviewer, "reviewer");
  assert.equal(row.identities.merger, "merger");
  assert.ok(row.references.gitRefs.includes("Repository: org/repo"));
  assert.ok(row.references.gitRefs.includes("Branch: feature/x"));
  assert.ok(row.references.gitRefs.includes("Commit: a1b2c3d4"));
  assert.ok(row.references.gitRefs.includes("Pull request: 42"));
  assert.ok(row.references.gitRefs.includes("Pull request: https://github.com/org/repo/pull/42"));
  assert.deepEqual(row.trace.downstreamObjects, trace.execution_receipt.downstream_objects);
  assert.deepEqual(row.related, []);
});

test("browser domain is not an MCP call while explicit browser invocation is", async () => {
  const { presentActivity } = await loadMapper();
  const browser = presentActivity({ ...base, source_surface: "browser", event_type: "prompt_submitted", tool_name: null, metadata: { tool_name: "chatgpt.com", mcp_server_id: "configured-server" } });
  assert.equal(browser.evidence.mcpTool, "Unavailable");
  assert.equal(browser.evidence.mcpServer, "Unavailable");
  assert.deepEqual(browser.categories, ["Model request"]);
  const invoked = presentActivity({ ...base, source_surface: "browser", event_type: "tool_call", metadata: { tool_name: "read_file", mcp_server_id: "configured-server", tool_call_id: "call-1" } });
  assert.equal(invoked.evidence.mcpTool, "read_file");
  assert.equal(invoked.evidence.mcpServer, "configured-server");
  assert.ok(invoked.categories.includes("Tool call"));
});

test("explicit redacted tool structures and safe upload details are visible", async () => {
  const { presentActivity } = await loadMapper();
  const tool = presentActivity({ ...base, source_surface: "mcp", event_type: "tool_call", metadata: { tool_name: "read_file", redacted_arguments: { path: "[redacted]" }, redacted_result: { text: "[redacted]" } } });
  assert.deepEqual(tool.evidence.redactedArguments, { path: "[redacted]" });
  assert.deepEqual(tool.evidence.redactedResult, { text: "[redacted]" });
  const upload = presentActivity({ ...base, source_surface: "browser", event_type: "file_upload", metadata: { action_type: "file_upload", attachments: [{ mime_type: "application/pdf", size: 1024, sha256: "abc" }], attachment_count: 1 } });
  assert.ok(upload.categories.includes("Upload"));
  assert.deepEqual(upload.evidence.attachments, [{ mime_type: "application/pdf", size: 1024, sha256: "abc" }]);
  const noDetails = presentActivity({ ...base, source_surface: "browser", event_type: "browser_interaction_eval", action_type: "file_upload" });
  assert.ok(noDetails.categories.includes("Upload"));
  assert.equal(noDetails.evidence.attachmentCount, 0);
});

test("authoritative hashed prompt hides stale metadata preview and blocked is not failure", async () => {
  const { presentActivity } = await loadMapper();
  const row = presentActivity({ ...base, source_surface: "browser", event_type: "prompt_blocked", decision: "block", policy_decision: "block", metadata: { redacted_preview: "stale preview", prompt_payload: { redacted_preview: "stale preview" } } }, { prompt_payload: { content_access_level: "METADATA_ONLY", storage_mode: "hashed_only", prompt_hash: "abc" } });
  assert.equal(row.request.contentAccess, "METADATA_ONLY");
  assert.equal(row.request.preview, null);
  const unavailable = presentActivity({ ...base, metadata: { prompt_payload: { content_access_level: "REDACTED_PREVIEW", redacted_preview: "stale" } } }, { prompt_payload: { content_access_level: "CONTENT_UNAVAILABLE" } });
  assert.equal(unavailable.request.preview, null);
  assert.ok(row.categories.includes("Blocked"));
  assert.ok(!row.categories.includes("Failure"));
  const warning = presentActivity({ ...base, source_surface: "browser", event_type: "prompt_warned", decision: "warn", policy_decision: "warn" });
  assert.ok(warning.categories.includes("Warning"));
  const explicitWarning = presentActivity({ ...base, source_surface: "browser", event_type: "prompt_warned", decision: "allow" });
  assert.ok(explicitWarning.categories.includes("Warning"));
  const failed = presentActivity({ ...base, source_surface: "mcp", event_type: "tool_call", execution_status: "failed" });
  assert.ok(failed.categories.includes("Failure"));
});

test("refreshing loaded activity pages replaces stale rows and deduplicates offset overlap", async () => {
  const { mergeActivityPages } = await loadMapper();
  const old = { event_id: "old", timestamp: "2026-09-27T10:00:00Z" };
  const middle = { event_id: "middle", timestamp: "2026-09-27T11:00:00Z" };
  const newest = { event_id: "new", timestamp: "2026-09-27T12:00:00Z" };
  assert.deepEqual(mergeActivityPages([{ items: [middle] }, { items: [old] }]).map((row) => row.event_id), ["middle", "old"]);
  assert.deepEqual(mergeActivityPages([{ items: [newest, middle] }, { items: [middle, old] }]).map((row) => row.event_id), ["new", "middle", "old"]);
});
