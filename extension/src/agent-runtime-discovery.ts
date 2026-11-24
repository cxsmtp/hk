import { isHawkControlPlaneSurface } from "./platform-surface";

export type AgentRuntimeProfile = {
  agent_id: string;
  agent_name: string;
  model_name?: string;
  runtime_provider?: string;
  tools: string[];
  actions: string[];
  privileges: string[];
  environment: string;
};

type AgentRuntimeInput = {
  domain: string;
  url?: string | null;
  title?: string | null;
  bodyText?: string | null;
};

const AGENT_KEYWORDS = [
  "agent",
  "agent os",
  "agent-os",
  "tools & mcp",
  "mcp tools",
  "command center",
  "automation",
  "orchestrator",
];

const TOOL_HINTS: Array<{ hint: string; value: string }> = [
  { hint: "web search", value: "web.search" },
  { hint: "tavily", value: "web.search" },
  { hint: "gmail", value: "gmail.draft" },
  { hint: "email", value: "gmail.draft" },
  { hint: "mcp tools", value: "mcp.tools" },
  { hint: "tools & mcp", value: "mcp.tools" },
  { hint: "github", value: "github.repo" },
  { hint: "slack", value: "slack.message" },
];

const ACTION_HINTS: Array<{ hint: string; value: string }> = [
  { hint: "run research", value: "research.company" },
  { hint: "search the web", value: "research.company" },
  { hint: "draft email", value: "draft.email" },
  { hint: "write and summarize emails", value: "draft.email" },
  { hint: "save drafts", value: "save.gmail_draft" },
  { hint: "save draft", value: "save.gmail_draft" },
  { hint: "execute tasks", value: "task.execute" },
  { hint: "run task", value: "task.execute" },
];

function normalize(value: string | null | undefined): string {
  return String(value || "").trim().toLowerCase();
}

function toWordSlug(value: string): string {
  const normalized = normalize(value).replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return normalized || "local-agent-runtime";
}

function isLocalDomain(domain: string): boolean {
  const normalized = normalize(domain);
  if (!normalized) return false;
  if (normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1") return true;
  return (
    normalized.endsWith(".localhost")
    || normalized.endsWith(".local")
    || normalized.endsWith(".internal")
    || normalized.endsWith(".corp")
    || normalized.endsWith(".lan")
  );
}

function hasAnyHint(text: string, hints: string[]): boolean {
  const normalized = normalize(text);
  return hints.some((hint) => normalized.includes(hint));
}

function collectMappedHints(text: string, hints: Array<{ hint: string; value: string }>): string[] {
  const normalized = normalize(text);
  const found: string[] = [];
  for (const item of hints) {
    if (normalized.includes(item.hint) && !found.includes(item.value)) {
      found.push(item.value);
    }
  }
  return found;
}

function detectModelName(text: string): string | undefined {
  const normalized = normalize(text);
  const tagged = normalized.match(/\b([a-z0-9][a-z0-9._-]*:\d+(?:\.\d+)?[bm])\b/i);
  if (tagged?.[1]) return tagged[1].toLowerCase();

  const family = normalized.match(
    /\b((?:qwen|llama|mistral|mixtral|gemma|phi|deepseek|gpt|claude|grok)[a-z0-9._:-]*)\b/i
  );
  if (family?.[1]) return family[1].toLowerCase();
  return undefined;
}

function detectRuntimeProvider(text: string): string | undefined {
  const normalized = normalize(text);
  if (normalized.includes("ollama")) return "ollama";
  if (normalized.includes("open-webui") || normalized.includes("open webui")) return "open-webui";
  if (normalized.includes("lm studio")) return "lm-studio";
  if (normalized.includes("vllm")) return "vllm";
  if (normalized.includes("local llm")) return "local-llm";
  return undefined;
}

function detectAgentName(domain: string, title: string, text: string): string {
  const normalizedTitle = normalize(title);
  const normalizedText = normalize(text);
  if (normalizedTitle.includes("agent os") || normalizedText.includes("agent os")) return "agent-os";

  const candidate = normalizedTitle.match(/\b([a-z0-9][a-z0-9._-]{1,30})\b/);
  if (candidate?.[1] && candidate[1] !== "localhost") {
    return toWordSlug(candidate[1]);
  }

  if (isLocalDomain(domain)) return "local-agent-runtime";
  return toWordSlug(domain);
}

function hash32(input: string, seed: number): number {
  let hash = seed >>> 0;
  for (let index = 0; index < input.length; index += 1) {
    hash ^= input.charCodeAt(index);
    hash = Math.imul(hash, 0x45d9f3b) >>> 0;
    hash = (hash ^ (hash >>> 16)) >>> 0;
  }
  return hash >>> 0;
}

function deterministicAgentId(seed: string): string {
  const p1 = hash32(seed, 0x811c9dc5).toString(16).padStart(8, "0");
  const p2 = hash32(seed, 0x9e3779b1).toString(16).padStart(8, "0");
  const p3 = hash32(seed, 0xc2b2ae35).toString(16).padStart(8, "0");
  const p4 = hash32(seed, 0x27d4eb2f).toString(16).padStart(8, "0");
  return `agt-${(p1 + p2 + p3 + p4).slice(0, 32)}`;
}

function derivePrivileges(tools: string[], actions: string[]): string[] {
  const privilegeSet = new Set<string>();
  if (tools.includes("web.search") || actions.includes("research.company")) {
    privilegeSet.add("network.web_access");
  }
  if (tools.includes("mcp.tools")) {
    privilegeSet.add("mcp.tool.invoke");
  }
  if (tools.includes("gmail.draft") || actions.includes("draft.email") || actions.includes("save.gmail_draft")) {
    privilegeSet.add("email.gmail_draft_write");
  }
  if (actions.includes("task.execute")) {
    privilegeSet.add("workflow.task_execute");
  }
  return [...privilegeSet];
}

export function detectAgentRuntimeProfile(input: AgentRuntimeInput): AgentRuntimeProfile | null {
  const domain = normalize(input.domain);
  if (isHawkControlPlaneSurface(input)) return null;

  const title = String(input.title || "");
  const bodyText = String(input.bodyText || "");
  const combined = [domain, input.url || "", title, bodyText].join("\n");

  const localDomain = isLocalDomain(domain);
  const hasAgentSignals = hasAnyHint(combined, AGENT_KEYWORDS);
  const modelName = detectModelName(combined);
  const runtimeProvider = detectRuntimeProvider(combined);
  const tools = collectMappedHints(combined, TOOL_HINTS);
  const actions = collectMappedHints(combined, ACTION_HINTS);
  const privileges = derivePrivileges(tools, actions);

  let confidence = 0;
  if (localDomain) confidence += 1;
  if (hasAgentSignals) confidence += 1;
  if (modelName) confidence += 1;
  if (runtimeProvider) confidence += 1;
  if (tools.length || actions.length) confidence += 1;

  if (confidence < 2) return null;

  const agentName = detectAgentName(domain, title, combined);
  const agentSeed = [domain, normalize(input.url), agentName, modelName || "", tools.join(","), actions.join(",")].join("|");

  return {
    agent_id: deterministicAgentId(agentSeed),
    agent_name: agentName,
    model_name: modelName,
    runtime_provider: runtimeProvider,
    tools,
    actions,
    privileges,
    environment: localDomain ? "local_browser_runtime" : "browser_runtime",
  };
}
