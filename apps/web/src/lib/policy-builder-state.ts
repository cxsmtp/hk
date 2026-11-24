import type { PolicyScopedRule } from "@/lib/types";

export type PolicyRuleMatch = "match" | "no_match" | "unknown";

export type PolicyRuleDraftInput = {
  ruleId: string;
  enabled?: boolean;
  priority?: number;
  description?: string;
  userIds?: string[];
  agentIds?: string[];
  sourceSurfaces?: string[];
  tools?: string[];
  actionTypes?: string[];
  actionOperations?: string[];
  applications?: string[];
  domains?: string[];
  providers?: string[];
  models?: string[];
  mcpServers?: string[];
  decision?: NonNullable<PolicyScopedRule["effect"]>["decision"];
  reasonCode?: string;
  explanation?: string;
  recommendedAction?: string;
  metadata?: Record<string, unknown>;
};

export type PolicyMatchEvent = {
  user_id?: string | null;
  agent_id?: string | null;
  source_surface?: string | null;
  tool_name?: string | null;
  action_type?: string | null;
  operation?: string | null;
  application?: string | null;
  domain?: string | null;
  url?: string | null;
  provider?: string | null;
  model?: string | null;
  mcp_server?: string | null;
};

function uniqueStrings(values: string[] | undefined, lowercase = false): string[] {
  const normalized = (values || [])
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => lowercase ? value.toLowerCase() : value);
  return [...new Set(normalized)];
}

function domainName(value: string | null | undefined): string {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw) return "";
  try {
    return new URL(raw.includes("://") ? raw : `https://${raw}`).hostname.replace(/^www\./, "");
  } catch {
    return raw.split("/")[0].replace(/^www\./, "");
  }
}

function matchDomain(values: string[] | undefined, candidate: string | null | undefined): PolicyRuleMatch {
  const selectors = uniqueStrings(values).map(domainName).filter(Boolean);
  if (!selectors.length || selectors.includes("*")) return "match";
  const current = domainName(candidate);
  if (!current) return "unknown";
  return selectors.some((selector) => current === selector || current.endsWith(`.${selector}`)) ? "match" : "no_match";
}

export function buildScopedRuleDraft(input: PolicyRuleDraftInput): PolicyScopedRule {
  const priority = Number.isFinite(input.priority) ? Number(input.priority) : 100;
  const applications = uniqueStrings(input.applications);
  const mcpServers = uniqueStrings(input.mcpServers);
  const domains = uniqueStrings(input.domains, true).map(domainName).filter(Boolean);
  const providers = uniqueStrings(input.providers, true);
  const models = uniqueStrings(input.models, true);
  const conditionAtoms = [
    applications.length ? { field: "application", operator: "in" as const, value: applications } : null,
    mcpServers.length ? { field: "mcp_server", operator: "in" as const, value: mcpServers } : null,
  ].filter((atom): atom is { field: string; operator: "in"; value: string[] } => Boolean(atom));
  return {
    rule_id: input.ruleId.trim() || "scoped_rule_1",
    enabled: input.enabled !== false,
    priority,
    description: input.description?.trim() || undefined,
    subjects: {
      user_ids: uniqueStrings(input.userIds),
      agent_ids: uniqueStrings(input.agentIds),
      source_surfaces: uniqueStrings(input.sourceSurfaces, true),
    },
    resources: {
      tools: uniqueStrings(input.tools, true),
      ...(domains.length ? { domains } : {}),
      ...(providers.length ? { providers } : {}),
      ...(models.length ? { models } : {}),
    },
    actions: {
      types: uniqueStrings(input.actionTypes, true),
      operations: uniqueStrings(input.actionOperations, true),
    },
    effect: {
      decision: input.decision || "warn",
      reason_code: input.reasonCode?.trim() || undefined,
      explanation: input.explanation?.trim() || undefined,
      recommended_action: input.recommendedAction?.trim() || undefined,
      priority,
    },
    ...(conditionAtoms.length ? { condition_tree: { all: conditionAtoms } } : {}),
    metadata: { ...(input.metadata || {}) },
  };
}

function matchSelector(
  values: string[] | undefined,
  candidate: string | null | undefined,
  caseInsensitive: boolean,
): PolicyRuleMatch {
  const selectors = uniqueStrings(values, caseInsensitive);
  if (!selectors.length || selectors.includes("*")) return "match";

  const rawCandidate = String(candidate || "").trim();
  if (!rawCandidate) return "unknown";
  const normalizedCandidate = caseInsensitive ? rawCandidate.toLowerCase() : rawCandidate;
  return selectors.includes(normalizedCandidate) ? "match" : "no_match";
}

export function matchObservedEventAgainstRule(
  event: PolicyMatchEvent,
  rule: PolicyScopedRule,
): PolicyRuleMatch {
  const checks: PolicyRuleMatch[] = [
    matchSelector(rule.subjects?.user_ids, event.user_id, false),
    matchSelector(rule.subjects?.agent_ids, event.agent_id, false),
    matchSelector(rule.subjects?.source_surfaces, event.source_surface, true),
    matchSelector(rule.resources?.tools, event.tool_name, true),
    matchSelector(rule.actions?.types, event.action_type, true),
    matchSelector(rule.actions?.operations, event.operation, true),
  ];

  checks.push(
    matchSelector(rule.resources?.providers, event.provider, true),
    matchSelector(rule.resources?.models, event.model, true),
    matchSelector(
      rule.condition_tree && "all" in rule.condition_tree
        ? rule.condition_tree.all.filter((atom): atom is { field: string; operator: "in"; value: string[] } => "field" in atom && atom.operator === "in" && Array.isArray(atom.value) && atom.field === "application").flatMap((atom) => atom.value)
        : undefined,
      event.application,
      true,
    ),
    matchSelector(
      rule.condition_tree && "all" in rule.condition_tree
        ? rule.condition_tree.all.filter((atom): atom is { field: string; operator: "in"; value: string[] } => "field" in atom && atom.operator === "in" && Array.isArray(atom.value) && atom.field === "mcp_server").flatMap((atom) => atom.value)
        : undefined,
      event.mcp_server,
      true,
    ),
    matchDomain(rule.resources?.domains, event.domain || event.url),
  );

  if (checks.includes("no_match")) return "no_match";
  if (checks.includes("unknown")) return "unknown";
  return "match";
}
