import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  buildAuthorizePayload,
  buildGitHubChangeContext,
  classifyToolCall,
  repositoryScopedMcpServerId,
} from "../src/policy.mjs";

const SCOPE = "github.com/acme/app";
const SERVER = repositoryScopedMcpServerId(SCOPE);

test("GitHub repository mutations are classified as governed repository actions with change context", () => {
  const payload = buildAuthorizePayload({
    mcpServerId: SERVER,
    repositoryScope: SCOPE,
    toolName: "push_files",
    argumentsObject: {
      owner: "acme",
      repo: "app",
      branch: "feature/agent",
      message: "update",
      files: [
        { path: "src/b.js", content: "export const b = 2;\n" },
        { path: "./src//a.js", content: "export const a = 1;\n" },
      ],
    },
    approvalBindingId: "1b0f6a52-7f0e-4d7e-9c55-2a1f3b4c5d6e",
  });
  assert.equal(payload.action, "REPOSITORY_PUSH");
  assert.equal(payload.resource, "github.com/acme/app");
  const context = payload.tool_usage_meta.github_change_context;
  assert.equal(context.repository_action, "REPOSITORY_PUSH");
  assert.equal(context.branch, "feature/agent");
  assert.deepEqual(context.paths, ["src/a.js", "src/b.js"]);
  assert.equal(context.files_changed, 2);
  assert.equal(context.invalid_paths, 0);
  assert.equal(
    context.bytes_changed,
    Buffer.byteLength("export const b = 2;\n") + Buffer.byteLength("export const a = 1;\n"),
  );
  assert.match(context.content_sha256, /^[0-9a-f]{64}$/);
  assert.equal(context.approval_binding_id, "1b0f6a52-7f0e-4d7e-9c55-2a1f3b4c5d6e");
  assert.equal(Object.prototype.hasOwnProperty.call(context, "content"), false);
  assert.equal(Object.prototype.hasOwnProperty.call(context, "files"), false);
});

test("GitHub change fingerprint matches the gateway's canonical content fingerprint", () => {
  const context = buildGitHubChangeContext("REPOSITORY_PUSH", {
    files: [{ path: "b.txt", content: "two" }, { path: "a.txt", content: "one" }],
  });
  const expected = createHash("sha256");
  for (const [path, content] of [["a.txt", "one"], ["b.txt", "two"]]) {
    expected.update(JSON.stringify([path, createHash("sha256").update(content).digest("hex")]));
    expected.update("\n");
  }
  assert.equal(context.content_sha256, expected.digest("hex"));
});

test("GitHub branch, pull request, merge and fork tools map to their repository actions", () => {
  const cases = [
    ["create_branch", { owner: "acme", repo: "app", branch: "feature/x", from_branch: "main" }, "REPOSITORY_BRANCH_CREATE"],
    ["create_pull_request", { owner: "acme", repo: "app", head: "feature/x", base: "main", title: "t" }, "REPOSITORY_PULL_REQUEST_CREATE"],
    ["merge_pull_request", { owner: "acme", repo: "app", pullNumber: 3 }, "REPOSITORY_PULL_REQUEST_MERGE"],
    ["fork_repository", { owner: "acme", repo: "app" }, "REPOSITORY_FORK"],
  ];
  for (const [toolName, argumentsObject, action] of cases) {
    assert.equal(classifyToolCall({ mcpServerId: SERVER, repositoryScope: SCOPE, toolName, argumentsObject }).action, action);
  }
  const pullRequest = buildAuthorizePayload({
    mcpServerId: SERVER,
    repositoryScope: SCOPE,
    toolName: "create_pull_request",
    argumentsObject: cases[1][1],
  });
  assert.equal(pullRequest.tool_usage_meta.github_change_context.branch, "feature/x");
  assert.equal(pullRequest.tool_usage_meta.github_change_context.base_branch, "main");
});

test("GitHub change context reports unusable paths and drops malformed approval references", () => {
  const payload = buildAuthorizePayload({
    mcpServerId: "github-pull-requests",
    toolName: "create_or_update_file",
    argumentsObject: { owner: "acme", repo: "app", path: "", content: "x", branch: "feature/y" },
    approvalBindingId: "bad id; drop",
  });
  const context = payload.tool_usage_meta.github_change_context;
  assert.equal(context.invalid_paths, 1);
  assert.equal(Object.prototype.hasOwnProperty.call(context, "approval_binding_id"), false);
});

test("GitHub reads keep their read classification and secret-bearing writes stay credential attempts", () => {
  const read = classifyToolCall({
    mcpServerId: "github-pull-requests",
    toolName: "list_pull_requests",
    argumentsObject: { owner: "acme", repo: "app" },
  });
  assert.equal(read.action, "file_read");
  assert.equal(read.githubChangeContext, undefined);
  const secret = classifyToolCall({
    mcpServerId: "github-pull-requests",
    toolName: "create_or_update_file",
    argumentsObject: { owner: "acme", repo: "app", path: "config.js", content: "const api_key = 'x';" },
  });
  assert.equal(secret.action, "secret_access_attempt");
});

test("non-GitHub servers keep the generic write classification", () => {
  const classified = classifyToolCall({
    mcpServerId: "other-server",
    toolName: "create_or_update_file",
    argumentsObject: { owner: "acme", repo: "app", path: "a.txt", content: "x" },
  });
  assert.equal(classified.action, "file_write");
});
