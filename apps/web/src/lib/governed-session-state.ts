export type GovernanceState =
  | "governed"
  | "monitor_only"
  | "partially_governed"
  | "unknown"
  | "disconnected";

export type GovernanceProof = {
  controlMode?: string | null;
  identityResolved?: boolean | null;
  policyAttached?: boolean | null;
  policyCurrent?: boolean | null;
  heartbeatFresh?: boolean | null;
  evidencePresent?: boolean | null;
};

export type GovernancePresentation = {
  state: GovernanceState;
  label: "Governed" | "Monitor only" | "Partially governed" | "Unknown" | "Disconnected";
  explanation: string;
};

export type TokenUsage = {
  input: number | null;
  output: number | null;
  cached: number | null;
  total: number | null;
  provenance: "exact" | "estimated" | "unknown";
};

export type CostUsage = {
  amount: number | null;
  currency: string | null;
  provenance: "exact" | "estimated" | "unknown";
  source:
    | "provider_billed"
    | "provider_reported"
    | "customer_rate_card"
    | "client_estimate"
    | "calculated_estimate"
    | "mixed"
    | "unknown";
};

const INLINE_MODES = new Set(["inline_authorized", "inline_allowed", "inline_prevented", "warned", "scoped"]);
const MONITOR_MODES = new Set([
  "detected_only",
  "telemetry_only",
  "shadow_would_block",
  "monitor_would_allow",
  "monitor_would_warn",
  "monitor_would_review",
  "monitor_would_block",
]);

function normalized(value: unknown): string {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function deriveGovernanceState(proof: GovernanceProof): GovernancePresentation {
  if (proof.heartbeatFresh === false) {
    return {
      state: "disconnected",
      label: "Disconnected",
      explanation: "The controlling surface has no fresh heartbeat. Hawk cannot assert live governance.",
    };
  }

  if (proof.identityResolved !== true) {
    return {
      state: "unknown",
      label: "Unknown",
      explanation: "The acting user, agent, or service identity is not resolved.",
    };
  }

  const mode = normalized(proof.controlMode);
  if (MONITOR_MODES.has(mode)) {
    return {
      state: "monitor_only",
      label: "Monitor only",
      explanation: "Hawk observed the action but did not authorize it before execution.",
    };
  }

  if (!INLINE_MODES.has(mode)) {
    return {
      state: "unknown",
      label: "Unknown",
      explanation: "Hawk has no verified inline control mode for this session.",
    };
  }

  if (proof.policyAttached !== true || proof.policyCurrent !== true || proof.evidencePresent !== true) {
    return {
      state: "partially_governed",
      label: "Partially governed",
      explanation: "Hawk was inline, but current policy or decision evidence is incomplete.",
    };
  }

  return {
    state: "governed",
    label: "Governed",
    explanation: "Identity, inline policy, heartbeat, decision and evidence are verified.",
  };
}

function finiteUsage(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function estimatedTokensFromChars(value: unknown): number | null {
  const chars = finiteUsage(value);
  if (chars === null || chars === 0) return null;
  return Math.max(1, Math.ceil(chars / 4));
}

function textLength(value: unknown): number | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed.length : null;
}

function currencyCode(value: unknown, fallback: string | null = null): string | null {
  const candidate = typeof value === "string" ? value.trim().toUpperCase() : "";
  if (/^[A-Z]{3}$/.test(candidate)) return candidate;
  return fallback;
}

function costSource(value: unknown): CostUsage["source"] {
  const candidate = normalized(value);
  return ["provider_billed", "provider_reported", "customer_rate_card", "client_estimate", "calculated_estimate"]
    .includes(candidate) ? candidate as CostUsage["source"] : "unknown";
}

function record(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

export function deriveTokenUsage(metadata: Record<string, unknown> | null | undefined): TokenUsage {
  const source = record(metadata);
  const usage = record(source.usage);
  const exactInput = finiteUsage(source.prompt_tokens ?? source.input_tokens ?? usage.prompt_tokens ?? usage.input_tokens);
  const exactOutput = finiteUsage(source.completion_tokens ?? source.output_tokens ?? usage.completion_tokens ?? usage.output_tokens);
  const exactCached = finiteUsage(source.cached_tokens ?? usage.cached_tokens ?? record(usage.input_tokens_details).cached_tokens);
  const exactTotal = finiteUsage(source.total_tokens ?? usage.total_tokens);
  const hasExact = exactInput !== null || exactOutput !== null || exactCached !== null || exactTotal !== null;

  if (hasExact) {
    return {
      input: exactInput,
      output: exactOutput,
      cached: exactCached,
      total: exactTotal ?? ((exactInput ?? 0) + (exactOutput ?? 0)),
      provenance: "exact",
    };
  }

  const estimatedInput = finiteUsage(source.estimated_prompt_tokens ?? source.estimated_input_tokens);
  const estimatedOutput = finiteUsage(source.estimated_completion_tokens ?? source.estimated_output_tokens);
  const estimatedCached = finiteUsage(source.estimated_cached_tokens);
  const estimatedTotal = finiteUsage(source.estimated_total_tokens);
  const hasEstimate = estimatedInput !== null || estimatedOutput !== null || estimatedCached !== null || estimatedTotal !== null;

  if (hasEstimate) {
    return {
      input: estimatedInput,
      output: estimatedOutput,
      cached: estimatedCached,
      total: estimatedTotal ?? ((estimatedInput ?? 0) + (estimatedOutput ?? 0)),
      provenance: "estimated",
    };
  }

  const inputChars = finiteUsage(
    source.prompt_chars
    ?? source.input_chars
    ?? source.request_chars
    ?? source.prompt_character_count
    ?? usage.prompt_chars
    ?? usage.input_chars
    ?? usage.request_chars,
  ) ?? textLength(
    source.prompt_preview_redacted
    ?? source.redacted_prompt
    ?? source.original_intent
    ?? source.input_context_summary
    ?? usage.prompt_preview_redacted
    ?? usage.redacted_prompt,
  );
  const outputChars = finiteUsage(
    source.output_chars
    ?? source.response_chars
    ?? source.completion_chars
    ?? source.output_character_count
    ?? usage.output_chars
    ?? usage.response_chars
    ?? usage.completion_chars,
  ) ?? textLength(
    source.output_text_preview_redacted
    ?? source.response_preview_redacted
    ?? source.completion_preview_redacted
    ?? usage.output_text_preview_redacted
    ?? usage.response_preview_redacted,
  );
  const inferredInput = estimatedTokensFromChars(inputChars);
  const inferredOutput = estimatedTokensFromChars(outputChars);
  if (inferredInput !== null || inferredOutput !== null) {
    return {
      input: inferredInput,
      output: inferredOutput,
      cached: null,
      total: (inferredInput ?? 0) + (inferredOutput ?? 0),
      provenance: "estimated",
    };
  }

  return { input: null, output: null, cached: null, total: null, provenance: "unknown" };
}

export function deriveCostUsage(metadata: Record<string, unknown> | null | undefined): CostUsage {
  const source = record(metadata);
  const usage = record(source.usage);
  const nested = Object.keys(record(usage.cost)).length ? record(usage.cost) : record(source.cost);
  const nestedSource = costSource(nested.source ?? source.cost_source ?? usage.cost_source ?? source.cost_type ?? usage.cost_type);
  const namedCandidates: Array<[unknown, CostUsage["source"], string | null]> = [
    [source.provider_billed_cost_usd ?? usage.provider_billed_cost_usd ?? source.billed_cost_usd, "provider_billed", "USD"],
    [source.provider_reported_cost_usd ?? usage.provider_reported_cost_usd ?? source.reported_cost_usd, "provider_reported", "USD"],
    [source.customer_rate_card_cost_usd ?? usage.customer_rate_card_cost_usd ?? source.rate_card_cost_usd, "customer_rate_card", "USD"],
    [source.client_estimated_cost_usd ?? usage.client_estimated_cost_usd, "client_estimate", "USD"],
    [source.estimated_cost_usd ?? usage.estimated_cost_usd, "calculated_estimate", "USD"],
  ];
  const nestedAmount = finiteUsage(nested.amount);
  let amount = nestedSource === "unknown" ? null : nestedAmount;
  let resolvedSource = amount === null ? "unknown" as CostUsage["source"] : nestedSource;
  let currency = amount === null ? null : currencyCode(nested.currency);

  if (amount === null) {
    for (const [candidate, candidateSource, candidateCurrency] of namedCandidates) {
      const parsed = finiteUsage(candidate);
      if (parsed !== null) {
        amount = parsed;
        resolvedSource = candidateSource;
        currency = candidateCurrency;
        break;
      }
    }
  }

  if (amount !== null && currency !== null) {
    const providerExact = ["provider_billed", "provider_reported"].includes(resolvedSource)
      && source.cost_usage_verified === true;
    return {
      amount,
      currency,
      provenance: providerExact ? "exact" : "estimated",
      source: resolvedSource,
    };
  }

  const rateCard = record(source.rate_card ?? usage.rate_card);
  const reference = typeof rateCard.reference === "string" ? rateCard.reference.trim() : "";
  const inputRate = finiteUsage(rateCard.input_usd_per_million);
  const outputRate = finiteUsage(rateCard.output_usd_per_million);
  const tokens = deriveTokenUsage(source);
  if (reference && inputRate !== null && outputRate !== null && (tokens.input !== null || tokens.output !== null)) {
    return {
      amount: ((tokens.input ?? 0) * inputRate + (tokens.output ?? 0) * outputRate) / 1_000_000,
      currency: "USD",
      provenance: "estimated",
      source: "customer_rate_card",
    };
  }

  return { amount: null, currency: null, provenance: "unknown", source: "unknown" };
}

export function sessionKeyForEvent(event: {
  event_id: string;
  correlation_id?: string | null;
  chain_id?: string | null;
  context_id?: string | null;
  user_email?: string | null;
  user_id?: string | null;
  agent_id?: string | null;
  application?: string | null;
  ai_surface?: string | null;
  source_surface?: string | null;
  api_endpoint?: string | null;
  metadata?: Record<string, unknown> | null;
}): string {
  const metadata = record(event.metadata);
  const sessionId = String(metadata.session_id ?? metadata.sessionId ?? "").trim();
  if (sessionId) return `session:${sessionId}`;
  const conversationId = String(
    metadata.conversation_id
    ?? metadata.conversationId
    ?? metadata.thread_id
    ?? metadata.threadId
    ?? event.context_id
    ?? event.chain_id
    ?? "",
  ).trim();
  if (conversationId) return `conversation:${conversationId}`;
  const correlationId = String(event.correlation_id || "").trim();
  if (correlationId) return `correlation:${correlationId}`;
  const endpoint = String(
    event.api_endpoint
    ?? metadata.url
    ?? metadata.page_url
    ?? metadata.pageUrl
    ?? metadata.tab_url
    ?? metadata.target_url
    ?? "",
  ).trim();
  const actor = String(event.user_email || event.user_id || event.agent_id || metadata.actor_id || "unknown-actor").trim().toLowerCase();
  const application = String(event.application || event.ai_surface || event.source_surface || metadata.application || metadata.provider || "unknown-app").trim().toLowerCase();
  if (endpoint) {
    try {
      const url = new URL(endpoint);
      const stablePath = url.pathname.split("/").slice(0, 3).join("/");
      return `observed:${actor}:${application}:${url.hostname}${stablePath}`;
    } catch {
      return `observed:${actor}:${application}:${endpoint.slice(0, 160)}`;
    }
  }
  return `event:${event.event_id}`;
}

export function governanceProofFromEvent(event: {
  identity_type?: string | null;
  user_id?: string | null;
  agent_id?: string | null;
  policy_id?: string | null;
  evidence_node_ids?: string[];
  control_triggered?: string[];
  metadata?: Record<string, unknown> | null;
}): GovernanceProof {
  const metadata = record(event.metadata);
  const evidence = Array.isArray(event.evidence_node_ids) && event.evidence_node_ids.length > 0;
  const mode = String(metadata.control_mode ?? metadata.controlMode ?? metadata.enforcement_mode ?? "");
  const identityResolved = Boolean(event.user_id || event.agent_id || metadata.actor_id || metadata.identity_id);
  const policyAttached = Boolean(event.policy_id || metadata.policy_id || metadata.policy_version_id || event.control_triggered?.length);
  const policyCurrentValue = metadata.policy_current ?? metadata.policyCurrent;
  const heartbeatValue = metadata.heartbeat_fresh ?? metadata.heartbeatFresh;
  return {
    controlMode: mode,
    identityResolved,
    policyAttached,
    policyCurrent: typeof policyCurrentValue === "boolean" ? policyCurrentValue : policyAttached,
    heartbeatFresh: typeof heartbeatValue === "boolean" ? heartbeatValue : true,
    evidencePresent: evidence || Boolean(metadata.evidence_ref || metadata.evidence_bundle_id),
  };
}
