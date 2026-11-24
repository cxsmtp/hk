import { isHawkControlPlaneSurface } from "./platform-surface";

export type DiscoveryHint =
  | "known_ai_domain"
  | "policy_managed_domain"
  | "agentic_keyword"
  | "local_agent_runtime";

export type DiscoveryTarget = {
  domain: string;
  url?: string | null;
  title?: string | null;
};

export type DiscoveryEligibility = {
  eligible: boolean;
  hint: DiscoveryHint | null;
};

const DEFAULT_AI_DOMAIN_HINTS = [
  "openai",
  "chatgpt",
  "anthropic",
  "claude",
  "gemini",
  "copilot",
  "perplexity",
  "poe",
  "mistral",
  "cohere",
  "huggingface",
  "grok",
  "deepseek",
  "you.com",
  "phind",
];

const AGENTIC_KEYWORD_HINTS = [
  "agent",
  "agent-os",
  "agent_os",
  "mcp",
  "langchain",
  "langgraph",
  "crewai",
  "autogen",
  "workflow agent",
  "automation agent",
  "tool orchestration",
  "copilot studio",
];

const LOCAL_AGENT_RUNTIME_HINTS = [
  "agent",
  "mcp",
  "prompt",
  "workflow",
];

const LOCAL_MODEL_RUNTIME_HINTS = [
  "llm",
  "ollama",
  "qwen",
  "llama",
  "mistral",
  "open-webui",
  "open webui",
  "lm studio",
  "vllm",
  "model runner",
  "local model",
  "chat completions",
  "inference",
  "copilot",
  "automation",
  "orchestrator",
];

const LOCAL_MODEL_RUNTIME_PORTS = new Set([
  "11434",
  "1234",
  "3000",
  "3001",
  "8080",
  "7860",
]);

export function normalizeDomain(raw: string): string {
  const value = String(raw || "").trim().toLowerCase();
  if (!value) return "";
  const candidate = value.includes("://") ? value : `https://${value}`;
  try {
    const parsed = new URL(candidate);
    return parsed.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return value.replace(/^www\./, "");
  }
}

export function domainFromUrl(url: string | undefined): string {
  if (!url || (!url.startsWith("http://") && !url.startsWith("https://"))) return "";
  return normalizeDomain(url);
}

export function domainMatches(candidate: string, expected: string): boolean {
  const c = normalizeDomain(candidate);
  const e = normalizeDomain(expected);
  if (!c || !e) return false;
  return c === e || c.endsWith(`.${e}`);
}

export function isPolicyManagedDomain(domain: string, managedDomains: string[]): boolean {
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;
  return managedDomains.some((value) => domainMatches(normalized, value) || domainMatches(value, normalized));
}

export function isLikelyAiDomain(
  domain: string,
  scopedDomains: Set<string>,
  aiHints: string[] = DEFAULT_AI_DOMAIN_HINTS
): boolean {
  const normalized = normalizeDomain(domain);
  if (!normalized) return false;
  if (scopedDomains.has(normalized)) return true;
  if (normalized.endsWith(".ai")) return true;
  return aiHints.some((hint) => normalized.includes(String(hint || "").toLowerCase()));
}

function isLocalLikeDomain(domain: string): boolean {
  const normalized = normalizeDomain(domain);
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

function containsHint(haystack: string, hints: string[]): boolean {
  const value = haystack.toLowerCase();
  return hints.some((hint) => value.includes(String(hint || "").toLowerCase()));
}

function getUrlHostAndPort(rawUrl: string | null | undefined): { host: string; port: string } {
  const value = String(rawUrl || "").trim();
  if (!value) return { host: "", port: "" };
  try {
    const parsed = new URL(value);
    return {
      host: normalizeDomain(parsed.hostname),
      port: String(parsed.port || "").trim(),
    };
  } catch {
    return { host: "", port: "" };
  }
}

function hasLocalModelRuntimeSignal(target: DiscoveryTarget): boolean {
  const combined = [target.domain, target.url || "", target.title || ""].join(" ").toLowerCase();
  if (containsHint(combined, LOCAL_AGENT_RUNTIME_HINTS) || containsHint(combined, LOCAL_MODEL_RUNTIME_HINTS)) {
    return true;
  }
  const { host, port } = getUrlHostAndPort(target.url);
  if (!host || !isLocalLikeDomain(host) || !port) return false;
  return LOCAL_MODEL_RUNTIME_PORTS.has(port);
}

export function classifyDiscoveryEligibility(
  target: DiscoveryTarget,
  options: {
    policyManagedDomains: string[];
    scopedDomains: Set<string>;
    aiHints?: string[];
  }
): DiscoveryEligibility {
  const policyManagedDomains = options.policyManagedDomains;
  const scopedDomains = options.scopedDomains;
  const aiHints = options.aiHints ?? DEFAULT_AI_DOMAIN_HINTS;
  const domain = normalizeDomain(target.domain);
  if (!domain) return { eligible: false, hint: null };
  if (isHawkControlPlaneSurface(target)) return { eligible: false, hint: null };

  if (isPolicyManagedDomain(domain, policyManagedDomains)) {
    return { eligible: true, hint: "policy_managed_domain" };
  }

  if (isLikelyAiDomain(domain, scopedDomains, aiHints)) {
    return { eligible: true, hint: "known_ai_domain" };
  }

  const combined = [domain, target.url || "", target.title || ""].join(" ").toLowerCase();
  if (containsHint(combined, AGENTIC_KEYWORD_HINTS)) {
    return { eligible: true, hint: "agentic_keyword" };
  }

  if (isLocalLikeDomain(domain) && hasLocalModelRuntimeSignal(target)) {
    return { eligible: true, hint: "local_agent_runtime" };
  }

  return { eligible: false, hint: null };
}
