import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInNewContext } from "node:vm";

const page = readFileSync(new URL("../src/app/control-coverage/source-control/github-repository-boundary/page.tsx", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/lib/api.ts", import.meta.url), "utf8");
const types = readFileSync(new URL("../src/lib/types.ts", import.meta.url), "utf8");
const policyWorkspace = readFileSync(new URL("../src/components/lifecycle/policy-pack-platform-workspace.tsx", import.meta.url), "utf8");

test("local operation controls require current private governance and an exact active binding", () => {
  const expression = page.match(/const localRepositoryControlsReady = (Boolean\([\s\S]*?\n  \));/)?.[1];
  assert.ok(expression);
  const repository = { id: "repo", governance_version: 3, evidence_state: "CONFIRMED", visibility: "PRIVATE", lifecycle_state: "ACTIVE", governance_state: "APPROVED", policy_current: true };
  const detail = { repository, runtime_bindings: { items: [{ repository_id: "repo", scope: "EXACT_FOLDER", state: "ACTIVE" }] } };
  const ready = (changes = {}) => runInNewContext(expression, { selectedRepository: repository, runtimeControlDetail: detail, runtimeBindingsLoading: false, runtimeBindingWorking: false, ...changes });
  assert.equal(ready(), true);
  assert.equal(ready({ runtimeBindingsLoading: true }), false);
  assert.equal(ready({ selectedRepository: null }), false);
  for (const change of [{ governance_version: 4 }, { visibility: "PUBLIC" }, { evidence_state: "INFERRED" }, { lifecycle_state: "DELETED" }, { governance_state: "UNAPPROVED" }, { policy_current: false }]) {
    assert.equal(ready({ runtimeControlDetail: { ...detail, repository: { ...repository, ...change } } }), false);
  }
  for (const change of [{ state: "OBSERVED" }, { state: "REVOKED" }, { scope: "ALL_WORKTREES" }, { repository_id: "other" }]) {
    assert.equal(ready({ runtimeControlDetail: { ...detail, runtime_bindings: { items: [{ ...detail.runtime_bindings.items[0], ...change }] } } }), false);
  }
  assert.match(page, /disabled=\{!localRepositoryControlsReady \|\| operationControlsWorking\}/);
});

test("workspace activation submits only the signed observation and current governance version", () => {
  assert.match(api, /bindGitHubRepositoryRuntime: \(repositoryId: string, payload: \{ observation_id: string; expected_governance_version: number \}\)/);
  assert.match(page, /Bind signed workspace/);
  assert.match(page, /row\.state === "OBSERVED" && row\.scope === "EXACT_FOLDER" && row\.repository_id === null/);
  assert.match(page, /observation_id: selectedRuntimeObservation, expected_governance_version: runtimeControlDetail\.repository\.governance_version/);
  assert.match(page, /Allow removes this repository block; other rules still apply/);
  const bindingType = types.slice(types.indexOf("export type GitHubRepositoryRuntimeBinding ="), types.indexOf("export type GitHubRepositoryAccessRelationship ="));
  assert.match(bindingType, /repository_id: string \| null/);
  assert.match(bindingType, /scope: "EXACT_FOLDER";/);
  assert.doesNotMatch(bindingType, /ALL_WORKTREES/);
});

test("GitHub setup follows connect, repositories, draft controls, and observed activity", () => {
  const headings = ["Connect GitHub</CardTitle>", "Choose repositories</CardTitle>", "Define controls</CardTitle>", "Recent activity</CardTitle>"];
  const locations = headings.map((heading) => page.indexOf(heading));
  assert.ok(locations.every((location) => location >= 0));
  assert.ok(locations.every((location, index) => index === 0 || location > locations[index - 1]));
  assert.match(page, /<details[^>]*>[\s\S]*Connection details and test tools/);
  assert.doesNotMatch(page, /github\.com\/company\/approved-demo-repo|github\.com\/github\/github-mcp-server/);
});

test("draft controls require a repository, tool, action, and surface", () => {
  const expression = page.match(/const canReviewControls = (Boolean\([^;]+\));/)?.[1];
  assert.ok(expression);
  const canReview = (repo, tools, operations, surfaces) => runInNewContext(expression, {
    selectedRepository: repo,
    selectedAITools: tools,
    selectedOperations: operations,
    selectedSurfaces: surfaces,
  });
  assert.equal(canReview(null, ["codex"], ["REPOSITORY_READ"], ["runtime"]), false);
  assert.equal(canReview({ id: "repo" }, [], ["REPOSITORY_READ"], ["runtime"]), false);
  assert.equal(canReview({ id: "repo" }, ["codex"], [], ["runtime"]), false);
  assert.equal(canReview({ id: "repo" }, ["codex"], ["REPOSITORY_READ"], []), false);
  assert.equal(canReview({ id: "repo" }, ["codex"], ["REPOSITORY_READ"], ["runtime"]), true);
  assert.match(page, /<Button type="button" disabled=\{!canReviewControls\}/);
  assert.match(page, /Review and apply controls/);
  const choice = page.match(/selectedOperations\.includes\(action\.value\) \? ("[^"]+") : ("[^"]+")/)?.[0];
  assert.ok(choice);
  assert.equal(runInNewContext(choice, { selectedOperations: ["REPOSITORY_READ"], action: { value: "REPOSITORY_READ" } }), "Allow after approval");
  assert.equal(runInNewContext(choice, { selectedOperations: [], action: { value: "REPOSITORY_READ" } }), "Not allowed by this draft");
});

test("repository access experience exposes inventory and four accessible modes", () => {
  for (const label of ["Accounts", "Repositories", "People & teams", "AI Connections", "Authoritative inventory", "Direct access", "Team access", "Evidence and freshness"]) {
    assert.match(page, new RegExp(label));
  }
  assert.match(page, /aria-label="GitHub repository inventory modes"/);
  assert.match(page, /role="tablist"/);
  assert.match(page, /repository_inventory/);
  assert.doesNotMatch(page, /productivity score/i);
});

test("web client exposes bounded GitHub repository query routes", () => {
  for (const route of ["githubRepositoryOrganizations", "githubRepositories", "githubRepositoryDetail", "githubRepositoryDevelopers", "githubRepositoryAIConnections"]) {
    assert.match(api, new RegExp(route));
  }
  assert.match(types, /repository_inventory/);
});

test("repository inventory modes use backend routes and render fetched rows with honest empty and error states", () => {
  for (const route of [
    "/control-coverage/source-control/github-repositories/organizations",
    "/control-coverage/source-control/github-repositories/repositories",
    "/control-coverage/source-control/github-repositories/developers",
    "/control-coverage/source-control/github-repositories/ai-connections",
  ]) assert.ok(api.includes(route));
  for (const marker of ["inventoryRows", "api.githubRepositoryOrganizations", "api.githubRepositories", "api.githubRepositoryDevelopers", "api.githubRepositoryAIConnections", "No inventory rows are available", "Could not load this inventory mode", "Show more"]) assert.match(page, new RegExp(marker));
});

test("AI connection and repository detail request contract exposes the governed relationship fields", () => {
  const mockedAIConnection = {
    client_name: "Codex", provider: "openai", model: "gpt-5", agent_id: "agent-1",
    mcp_server_id: "mcp-1", tool_name: "create_pull_request", source_surface: "RUNTIME",
    confidence: "OBSERVED", evidence_refs: ["evidence-1"], last_seen_at: "2026-09-13T00:00:00Z",
  };
  for (const field of Object.keys(mockedAIConnection)) assert.match(page, new RegExp(field));
  for (const marker of ["Repository detail", "role=\"dialog\"", "loadRepositoryDetail", "Loading repository relationships", "Could not load repository detail"]) assert.match(page, new RegExp(marker));
});

test("repository detail is typed, read-only, and keyboard accessible", () => {
  for (const marker of ["GitHubRepositoryDetail", "GitHubRepositoryAccessRelationship", "GitHubRepositoryAIConnection", "GitHubRepositoryInventoryPage<T", "aria-modal=\"true\"", "repositoryDetailCloseRef", "repositoryDetailReturnFocusRef", "event.key === \"Escape\"", "Long values are truncated visually", "updateGitHubRepositoryGovernance"]) {
    assert.match(`${page}\n${api}\n${types}`, new RegExp(marker));
  }
  assert.doesNotMatch(types, /GitHubRepositoryInventoryPage = \{\s*items: Array<Record/);
  assert.match(page, /repositoryDetail\.access_relationships\.items/);
  assert.match(page, /repositoryDetail\.ai_connections\.items/);
});

test("repository detail renders the complete bounded access and AI relationship fields", () => {
  for (const marker of [
    "repositoryDetail.repository.host", "repositoryDetail.repository.repository_id", "repositoryDetail.repository.read_posture",
    "repositoryDetail.repository.policy_mapping_ref", "repositoryDetail.repository.approved_scope_ref",
    "row.mapped_user_id", "row.mapped_group_id", "row.external_principal_id", "row.principal_type", "row.access_path", "row.permission", "row.source_team_id", "row.evidence_state", "row.valid_until",
    "row.client_name", "row.ai_system_id", "row.provider", "row.model", "row.agent_id", "row.mcp_server_id", "row.tool_name", "row.source_surface", "row.relationship_state", "row.confidence", "row.evidence_refs", "row.action_count", "row.last_seen_at",
    "repositoryDetail.access_relationships.next_cursor", "repositoryDetail.ai_connections.next_cursor",
  ]) assert.match(page, new RegExp(marker.replaceAll(".", "\\.")));
  assert.match(types, /valid_until: string \| null/);
});

test("connection and inventory preserve manual GitHub App capabilities", () => {
  for (const marker of ["githubSourceConnections", "createGitHubSourceConnection", "validateGitHubSourceConnection", "api.githubRepositoryOrganizations", "api.githubRepositories", "api.githubRepositoryDevelopers", "api.githubRepositoryAIConnections", "Run inventory scan", "connectionError", "GitHub connection status is unavailable", "Account type", "Organization account", "Personal account", "GitHub App ID", "GitHub installation ID", "GitHub App private key", "selected_repository_scope: \"SELECTED\""]) assert.match(page, new RegExp(marker));
  assert.match(page, /setPrivateKey\(""\)/);
  assert.match(page, /role="tablist"/);
  for (const label of ["Repositories", "Accounts", "People & teams", "AI Connections"]) assert.match(page, new RegExp(label.replaceAll("&", "&amp;|&")));
  assert.match(page, /No inventory rows are available/);
  assert.match(page, /Could not load this inventory mode/);
});

test("control draft preserves every action and exact Policy Pack handoff", () => {
  for (const action of ["REPOSITORY_READ", "REPOSITORY_PULL", "REPOSITORY_BRANCH_CREATE", "REPOSITORY_FILE_WRITE", "REPOSITORY_PULL_REQUEST_CREATE", "REPOSITORY_PUSH", "REPOSITORY_MERGE", "REPOSITORY_PULL_REQUEST_APPROVE"]) assert.ok(page.includes(`["${action}"`));
  for (const marker of ["approved_repositories: [selectedRepository.full_name]", "repository_account_class", "personal_repository_deny_posture", "approved_ai_tools: selectedAITools", "allowed_repository_actions: selectedOperations", "resource_classes: [\"github_repository\"]", "application: selectedAITools.join", "surface: selectedSurfaces.join", "user: people", "group: groups", "parameters: JSON.stringify(parameters)"]) assert.ok(page.includes(marker), `missing handoff field ${marker}`);
  assert.match(page, /window.location.href = policyRolloutHref/);
  assert.match(policyWorkspace, /github-repository-control/);
  for (const field of ["setApplication", "setSurface", "setUser", "setGroup", "setParameters"]) assert.match(policyWorkspace, new RegExp(field));
  assert.match(page, /These choices are a draft/);
});

test("personal repositories retain explicit deny modes and source truth", () => {
  for (const marker of ["BLOCK_CHANGES", "BLOCK_ALL", "Apply protection", "updateGitHubRepositoryGovernance", "decision: \"UNAPPROVED\"", "expected_governance_version", "metadata inventory remains visible", "healthy governed MCP/runtime route", "healthy enrolled endpoint control point"]) assert.match(page, new RegExp(marker));
  assert.match(page, /Selection never approves this repository/);
});

test("activity and advanced evidence separate real results from unavailable states", () => {
  assert.match(page, /data.unauthorized_attempts.map/);
  assert.match(page, /observedAICalls.map/);
  assert.match(page, /No unauthorized attempts are available/);
  assert.match(page, /No AI tool calls are available/);
  assert.match(page, /Activity is unavailable/);
  assert.match(page, /sourceReady \? state : \"NOT_VERIFIED\"/);
  assert.match(page, /AI tool coverage for this repository/);
  assert.match(page, /repositoryPathStatus = sourceReady && selectedRepository \? \"UNKNOWN\" : \"NOT_VERIFIED\"/);
  assert.match(page, /Evidence and freshness/);
  assert.match(page, /Last selected repository evidence/);
  assert.match(page, /Missing or stale evidence stays unknown/);
  assert.match(page, /<owner>\/<other-repository>/);
  assert.match(page, /These are example prompts/);
});

test("recent AI activity never falls back to a planned decision", () => {
  assert.match(page, /const observedAICalls = projectedAIClients;/);
  assert.doesNotMatch(page, /observedAICalls\s*=\s*[^;]*projectedLatestDecision/);
});

test("personal protection shows repository-specific verification and test entry", () => {
  const personal = page.slice(page.indexOf('id="personal-repository-protection"'), page.indexOf('AI tools to allow after approval'));
  assert.match(personal, /MCP gateway \/ runtime[\s\S]*StateBadge value=\{repositoryPathStatus\}/);
  assert.match(personal, /Endpoint CLI \/ IDE[\s\S]*StateBadge value=\{repositoryPathStatus\}/);
  const examples = page.slice(page.indexOf('>Test this control<'), page.indexOf('>Access relationships<') > page.indexOf('>Test this control<') ? page.indexOf('>Access relationships<') : undefined);
  assert.match(examples, /href="\/validate"/);
});
