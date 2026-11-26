const SECRET_RESOURCE_PATTERN = /(^|[/\\])(\.env|\.npmrc|\.pypirc|id_rsa|id_ed25519|private[-_]?key|credentials?\.json|secrets?\.)/i;
import { createHash } from "node:crypto";

const SECRET_ARG_PATTERN = /(api[_-]?key|secret|token|password|private[_-]?key|connection[_-]?string)/i;
const WRITE_TOOL_PATTERN = /(write|create|update|delete|remove|move|rename|patch|edit|apply|commit|push|deploy|trigger)/i;
const EXEC_TOOL_PATTERN = /(shell|terminal|exec|command|run|process|script)/i;
const READ_TOOL_PATTERN = /(read|get|fetch|list|search|query|summari[sz]e)/i;
const GITHUB_PULL_REQUESTS_SERVER = "github-pull-requests";
const GITHUB_SCOPE_PATTERN = /^github\.com\/([A-Za-z0-9][A-Za-z0-9._-]*)\/([A-Za-z0-9][A-Za-z0-9._-]*)$/i;
// GitHub MCP server tools that change a repository, mapped to the governed
// repository actions the Hawk gateway decides on (default deny, branch, path,
// size, secret and approval rules). Reads keep their generic classification.
const GITHUB_REPOSITORY_ACTIONS = new Map([
  ["create_branch", "REPOSITORY_BRANCH_CREATE"],
  ["create_or_update_file", "REPOSITORY_PUSH"],
  ["push_files", "REPOSITORY_PUSH"],
  ["delete_file", "REPOSITORY_PUSH"],
  ["create_pull_request", "REPOSITORY_PULL_REQUEST_CREATE"],
  ["update_pull_request", "REPOSITORY_PULL_REQUEST_UPDATE"],
  ["update_pull_request_branch", "REPOSITORY_PULL_REQUEST_UPDATE"],
  ["add_comment_to_pending_review", "REPOSITORY_PULL_REQUEST_COMMENT"],
  ["add_reply_to_pull_request_comment", "REPOSITORY_PULL_REQUEST_COMMENT"],
  ["pull_request_review_write", "REPOSITORY_PULL_REQUEST_APPROVE"],
  ["merge_pull_request", "REPOSITORY_PULL_REQUEST_MERGE"],
  ["enable_pr_auto_merge", "REPOSITORY_PULL_REQUEST_MERGE"],
  ["fork_repository", "REPOSITORY_FORK"],
  ["delete_repository", "REPOSITORY_DELETE"],
]);
const MAX_CHANGE_PATHS = 1000;
const SAFE_APPROVAL_BINDING_ID = /^[A-Za-z0-9_.:-]{1,64}$/;

export function normalizeMcpServerUrl(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  let parsed;
  try { parsed = new URL(value.trim()); } catch { return null; }
  if (!["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password || parsed.search || parsed.hash) return null;
  parsed.pathname = parsed.pathname.replace(/\/{2,}/g, "/").replace(/\/$/, "") || "/";
  return parsed.toString();
}

export function buildTransportBinding({ mcpServerUrl = null } = {}) {
  const normalized = normalizeMcpServerUrl(mcpServerUrl);
  if (mcpServerUrl !== null && mcpServerUrl !== undefined && !normalized) {
    throw new Error("MCP server URL must be an absolute HTTP(S) URL without credentials, query, or fragment");
  }
  return normalized
    ? { transport: "remote_http_declared", destination: normalized, binding_status: "declared_not_routed" }
    : { transport: "stdio_child", destination: null, binding_status: "local_child" };
}

export function destinationMatchesMcpServerUrl(destination, mcpServerUrl) {
  const normalizedDestination = normalizeMcpServerUrl(destination);
  const normalizedServer = normalizeMcpServerUrl(mcpServerUrl);
  return Boolean(normalizedDestination && normalizedServer && normalizedDestination === normalizedServer);
}

export function normalizeGitHubRepositoryScope(value) {
  if (typeof value !== "string" || value.trim() !== value) {
    return null;
  }
  const match = GITHUB_SCOPE_PATTERN.exec(value);
  if (!match) {
    return null;
  }
  return `github.com/${match[1].toLowerCase()}/${match[2].toLowerCase()}`;
}

export function repositoryScopedMcpServerId(repositoryScope) {
  const normalizedScope = normalizeGitHubRepositoryScope(repositoryScope);
  if (!normalizedScope) {
    throw new Error("A GitHub repository scope must be github.com/<owner>/<repository>");
  }
  const [, owner, repository] = normalizedScope.split("/");
  const readableId = `${GITHUB_PULL_REQUESTS_SERVER}--${owner}--${repository}`;
  if (readableId.length <= 128) {
    return readableId;
  }
  return `${GITHUB_PULL_REQUESTS_SERVER}--${createHash("sha256").update(normalizedScope).digest("hex").slice(0, 32)}`;
}

export function matchesGitHubRepositoryScope(argumentsObject, repositoryScope) {
  const normalizedScope = normalizeGitHubRepositoryScope(repositoryScope);
  if (!normalizedScope || !argumentsObject || typeof argumentsObject !== "object") {
    return false;
  }
  const owner = argumentsObject.owner;
  const repository = argumentsObject.repo;
  if (!isSafeGitHubIdentifier(owner) || !isSafeGitHubIdentifier(repository)) {
    return false;
  }
  return normalizedScope === `github.com/${owner.toLowerCase()}/${repository.toLowerCase()}`;
}

export function classifyToolCall({ mcpServerId, repositoryScope = null, toolName, argumentsObject = {} }) {
  const normalizedTool = String(toolName || "unknown_tool");
  const githubRepository = githubRepositoryIdentity(mcpServerId, argumentsObject, repositoryScope);
  const resource = githubRepository?.resource || extractResource(argumentsObject);
  const destination = githubRepository?.destination || extractDestination(argumentsObject);
  const dataClassification = githubRepository?.dataClassification || null;
  const serializedArgs = safeJson(argumentsObject);

  if (SECRET_RESOURCE_PATTERN.test(resource) || SECRET_ARG_PATTERN.test(serializedArgs)) {
    return {
      action: "secret_access_attempt",
      resource,
      destination,
      dataClassification,
      toolCategory: "credential",
      actionRisk: "critical",
    };
  }

  const repositoryAction = githubRepository ? GITHUB_REPOSITORY_ACTIONS.get(normalizedTool) : undefined;
  if (repositoryAction) {
    return {
      action: repositoryAction,
      resource,
      destination,
      dataClassification,
      toolCategory: "write",
      actionRisk: "high",
      githubChangeContext: buildGitHubChangeContext(repositoryAction, argumentsObject),
    };
  }

  if (EXEC_TOOL_PATTERN.test(normalizedTool)) {
    return {
      action: "terminal_command",
      resource,
      destination,
      dataClassification,
      toolCategory: "execute",
      actionRisk: "critical",
    };
  }

  if (WRITE_TOOL_PATTERN.test(normalizedTool)) {
    return {
      action: "file_write",
      resource,
      destination,
      dataClassification,
      toolCategory: "write",
      actionRisk: "high",
    };
  }

  if (READ_TOOL_PATTERN.test(normalizedTool)) {
    return {
      action: "file_read",
      resource,
      destination,
      dataClassification,
      toolCategory: "read",
      actionRisk: "low",
    };
  }

  return {
    action: "mcp_tool_call",
    resource,
    destination,
    dataClassification,
    toolCategory: "unknown",
    actionRisk: "medium",
  };
}

export function shouldBlockDecision(decisionPayload) {
  const decision = String(decisionPayload?.decision || "").toLowerCase();
  return ["block", "review", "hold_for_approval", "require_approval", "require_second_approval", "step_up"].includes(decision);
}

export function buildAuthorizePayload({
  aiSystemId,
  actorId,
  capabilityToken,
  mcpServerId,
  toolName,
  toolVersion,
  toolFingerprintId,
  argumentsObject,
  repositoryScope = null,
  chainId,
  sessionId,
  clientApp,
  mcpServerUrl = null,
  approvalBindingId = null,
}) {
  const classification = classifyToolCall({
    mcpServerId,
    repositoryScope,
    toolName,
    argumentsObject,
  });
  return {
    ai_system_id: aiSystemId,
    actor_id: actorId,
    capability_token: capabilityToken,
    action: classification.action,
    resource: classification.resource,
    chain_depth: 1,
    provider: "mcp",
    tool_name: toolName,
    tool_category: classification.toolCategory,
    api_endpoint: classification.destination,
    tool_usage_meta: {
      mcp_server_id: mcpServerId,
      tool_version: toolVersion,
      tool_fingerprint_id: toolFingerprintId,
      parameters: argumentsObject,
      target_resource: classification.resource,
      data_destination: classification.destination,
      arguments_summary: summarizeArguments(argumentsObject),
      action_risk: classification.actionRisk,
      transport_binding: buildTransportBinding({ mcpServerUrl }),
      ...(classification.githubChangeContext
        ? {
            github_change_context: {
              ...classification.githubChangeContext,
              ...(typeof approvalBindingId === "string" && SAFE_APPROVAL_BINDING_ID.test(approvalBindingId)
                ? { approval_binding_id: approvalBindingId }
                : {}),
            },
          }
        : {}),
    },
    chain_id: chainId || null,
    session_id: sessionId || null,
    ...(classification.dataClassification
      ? {
          session_context: {
            data_classification: classification.dataClassification,
            environment: "production",
          },
        }
      : {}),
    client_app: typeof clientApp === "string" && clientApp.trim()
      ? clientApp.trim().slice(0, 128)
      : null,
  };
}

export function buildToolScanPayload({
  mcpServerId,
  tool,
  chainId,
  mcpServerUrl = null,
}) {
  return {
    mcp_server_id: mcpServerId,
    tool_name: tool?.name || "unknown_tool",
    tool_version: tool?.version || tool?.annotations?.version || "unknown",
    description: tool?.description || "",
    schema: tool?.inputSchema || tool?.schema || {},
    examples: tool?.examples || [],
    manifest: {
      ...(tool || {}),
      ...(mcpServerUrl ? { hawk_transport_binding: buildTransportBinding({ mcpServerUrl }) } : {}),
    },
    chain_id: chainId || null,
  };
}

function normalizeChangePath(value) {
  if (typeof value !== "string") return null;
  const parts = value.trim().replace(/\\/g, "/").split("/").filter((part) => part !== "" && part !== ".");
  return parts.length ? parts.join("/") : null;
}

/**
 * Change facts the gateway needs before a GitHub repository mutation: target
 * and base branch, touched paths, file and byte counts, and a content
 * fingerprint. File contents are not copied here (the gateway scans the
 * arguments it receives itself); declared counts can only tighten a decision.
 */
export function buildGitHubChangeContext(repositoryAction, args) {
  const input = args && typeof args === "object" ? args : {};
  const pairs = [];
  const paths = new Set();
  let invalidPaths = 0;
  const addPath = (rawPath, content) => {
    const path = normalizeChangePath(rawPath);
    if (!path) {
      invalidPaths += 1;
      return;
    }
    paths.add(path);
    if (typeof content === "string") pairs.push([path, content]);
  };
  if (Object.prototype.hasOwnProperty.call(input, "path")) addPath(input.path, input.content);
  if (Array.isArray(input.files)) {
    for (const file of input.files.slice(0, MAX_CHANGE_PATHS + 1)) {
      if (file && typeof file === "object") addPath(file.path, file.content);
      else invalidPaths += 1;
    }
  }
  const bytesChanged = pairs.reduce((total, [, content]) => total + Buffer.byteLength(content, "utf8"), 0);
  let contentSha256 = null;
  if (pairs.length) {
    const digest = createHash("sha256");
    for (const [path, content] of [...pairs].sort((left, right) => (left[0] < right[0] ? -1 : left[0] > right[0] ? 1 : left[1] < right[1] ? -1 : left[1] > right[1] ? 1 : 0))) {
      digest.update(JSON.stringify([path, createHash("sha256").update(content, "utf8").digest("hex")]));
      digest.update("\n");
    }
    contentSha256 = digest.digest("hex");
  }
  const text = (value) => (typeof value === "string" && value.trim() ? value.trim().slice(0, 255) : null);
  return {
    repository_action: repositoryAction,
    branch: text(input.branch) || text(input.head),
    base_branch: text(input.base) || text(input.from_branch),
    paths: [...paths].sort().slice(0, MAX_CHANGE_PATHS),
    files_changed: paths.size,
    bytes_changed: bytesChanged,
    invalid_paths: invalidPaths,
    content_sha256: contentSha256,
  };
}

function extractResource(args) {
  if (!args || typeof args !== "object") {
    return "unknown";
  }
  for (const key of ["path", "file", "file_path", "repo_path", "resource", "url", "uri", "target", "command"]) {
    const value = args[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return "unknown";
}

function extractDestination(args) {
  if (!args || typeof args !== "object") {
    return null;
  }
  for (const key of ["url", "uri", "endpoint", "destination", "webhook", "callback_url"]) {
    const value = args[key];
    if (typeof value === "string" && /^https?:\/\//i.test(value.trim())) {
      return value.trim();
    }
  }
  return null;
}

function githubRepositoryIdentity(mcpServerId, args, repositoryScope) {
  const normalizedScope = normalizeGitHubRepositoryScope(repositoryScope);
  const isUnscopedGitHub = !normalizedScope && mcpServerId === GITHUB_PULL_REQUESTS_SERVER;
  const isScopedGitHub = normalizedScope
    && mcpServerId === repositoryScopedMcpServerId(normalizedScope);
  if ((!isUnscopedGitHub && !isScopedGitHub) || !args || typeof args !== "object") {
    return null;
  }

  const owner = args.owner;
  const repo = args.repo;
  if (!isSafeGitHubIdentifier(owner) || !isSafeGitHubIdentifier(repo)) {
    return null;
  }

  const repository = `github.com/${owner.toLowerCase()}/${repo.toLowerCase()}`;
  return {
    resource: repository,
    destination: `https://${repository}`,
    dataClassification: "public",
  };
}

function isSafeGitHubIdentifier(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(value);
}

function summarizeArguments(args) {
  if (!args || typeof args !== "object") {
    return {};
  }
  const summary = {};
  for (const [key, value] of Object.entries(args)) {
    if (SECRET_ARG_PATTERN.test(key)) {
      summary[key] = "[REDACTED]";
    } else if (typeof value === "string") {
      summary[key] = value.length > 180 ? `${value.slice(0, 180)}...` : value;
    } else if (typeof value === "number" || typeof value === "boolean" || value === null) {
      summary[key] = value;
    } else {
      summary[key] = `[${Array.isArray(value) ? "array" : "object"}]`;
    }
  }
  return summary;
}

function safeJson(value) {
  try {
    return JSON.stringify(value || {});
  } catch {
    return "";
  }
}
