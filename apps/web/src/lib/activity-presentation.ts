export type ActivityCategory = "Model request" | "Tool call" | "Repository action" | "Device action" | "Upload" | "Warning" | "Failure" | "Blocked" | "Activity";

export type ActivityRecord = {
  id: string;
  when: string;
  actor: string;
  application: string;
  action: string;
  target: string;
  decision: "Allowed" | "Warned" | "Approval required" | "Blocked" | "Unknown";
  outcome: string;
  category: ActivityCategory;
  categories: ActivityCategory[];
  source: string;
  request: {
    contentAccess: string;
    preview: string | null;
  };
  capture: string;
  retention: string;
  related: string[];
  references: { correlationId?: string; chainId?: string; gitRefs?: string[] };
  identities: {
    requestingPerson: string;
    appAgent: string;
    executingPrincipal: string;
    owner: string;
    author: string;
    reviewer: string;
    merger: string;
  };
  trace: {
    action: string;
    target: string;
    decision: string;
    execution: string;
    downstreamObjects: unknown[];
    unavailable: boolean;
  };
  evidence: {
    provider: string;
    model: string;
    mcpServer: string;
    mcpTool: string;
    attachments: unknown[];
    attachmentCount: number;
    redactedArguments: unknown | null;
    redactedResult: unknown | null;
    approval: unknown | null;
    execution: unknown | null;
  };
  rawEvent: unknown;
  rawAudit: unknown;
  rawTrace: unknown;
};

type ActivityEvent = Record<string, unknown>;

export function mergeActivityPages<T extends { event_id: string; timestamp?: string; created_at?: string }>(pages: Array<{ items: T[] }>): T[] {
  const byId = new Map<string, T>();
  for (const page of pages) for (const event of page.items || []) byId.set(event.event_id, event);
  const when = (event: T) => {
    const parsed = Date.parse(event.timestamp || event.created_at || "");
    return Number.isFinite(parsed) ? parsed : 0;
  };
  return [...byId.values()].sort((a, b) => when(b) - when(a) || b.event_id.localeCompare(a.event_id));
}

function text(value: unknown): string {
  return typeof value === "string" && value.trim() ? value.trim() : "";
}

function metadataOf(event: ActivityEvent): ActivityEvent {
  return event.metadata && typeof event.metadata === "object" ? event.metadata as ActivityEvent : {};
}

function firstText(...values: unknown[]): string {
  for (const value of values) {
    const found = text(value);
    if (found) return found;
  }
  return "";
}

function decisionOf(event: ActivityEvent): ActivityRecord["decision"] {
  const raw = firstText(event.policy_decision, event.policyDecision, event.decision).toLowerCase();
  if (["allow", "allowed", "permit", "permitted"].includes(raw)) return "Allowed";
  if (["warn", "warning"].includes(raw)) return "Warned";
  if (["require_approval", "hold_for_approval", "approval_required"].includes(raw)) return "Approval required";
  if (["block", "blocked", "deny", "denied", "prevent", "prevented"].includes(raw)) return "Blocked";
  return "Unknown";
}

function effectiveDecisionOf(event: ActivityEvent, audit: ActivityEvent): ActivityRecord["decision"] {
  const runtimeDecision = decisionOf(event);
  if (runtimeDecision !== "Unknown") return runtimeDecision;
  return decisionOf({
    policy_decision: firstText(audit.policy_decision, audit.enforcement_action),
    decision: firstText(audit.decision, audit.policy_triggered),
  });
}

function executionEvidence(event: ActivityEvent): unknown {
  const metadata = metadataOf(event);
  return event.execution_status ?? event.executionStatus ?? event.result_status ?? event.resultStatus
    ?? event.execution_receipt ?? event.executionReceipt ?? event.result ?? metadata.execution_status
    ?? metadata.execution_receipt ?? metadata.result_status ?? metadata.result ?? null;
}

function outcomeOf(event: ActivityEvent, decision: ActivityRecord["decision"]): string {
  const explicit = executionEvidence(event);
  if (typeof explicit === "string" && explicit.trim()) return explicit.trim();
  if (explicit && typeof explicit === "object") {
    const value = firstText((explicit as ActivityEvent).status, (explicit as ActivityEvent).outcome, (explicit as ActivityEvent).decision);
    if (value) return value;
    if ((explicit as ActivityEvent).prevented === true) return "Prevented";
  }
  const metadata = metadataOf(event);
  if (metadata.prevented === true || event.prevented === true) return "Prevented";
  if (decision === "Blocked" && firstText(event.control_outcome, metadata.control_outcome).toLowerCase() === "prevented") return "Prevented";
  return "Execution not captured";
}

function activityKinds(event: ActivityEvent): string[] {
  const metadata = metadataOf(event);
  return [event.event_type, event.action_type, metadata.event_type, metadata.action_type, metadata.action_class]
    .map((value) => text(value).toLowerCase())
    .filter(Boolean);
}

function isModelRequest(event: ActivityEvent): boolean {
  const metadata = metadataOf(event);
  const kinds = activityKinds(event);
  const contraryKind = kinds.some((kind) => /upload|attachment|tool|domain|navigation|context_invalidated/.test(kind))
    || isUpload(event)
    || invokedTool(event);
  if (contraryKind) return false;
  const hasModelContext = Boolean(
    text(event.model)
    || text(event.model_name)
    || text(metadata.model)
    || text(metadata.model_name)
    || event.prompt_payload
    || event.prompt_access
    || event.prompt_id
    || metadata.prompt_payload
    || metadata.prompt_access
    || metadata.prompt_id,
  );
  const hasPromptOrModelKind = kinds.some((kind) => /(^|_)(prompt|model)(_|$)/.test(kind));
  const legacyModelOnly = hasModelContext && !kinds.length;
  return hasModelContext || hasPromptOrModelKind || legacyModelOnly;
}

function categoryOf(event: ActivityEvent, decision: ActivityRecord["decision"]): ActivityCategory {
  const source = firstText(event.source_surface, event.source, event.ai_surface).toLowerCase();
  const kind = firstText(event.event_type, event.action_type, event.tool_name).toLowerCase();
  if (decision === "Blocked") return "Blocked";
  if (isUpload(event)) return "Upload";
  if (source.includes("github") || source.includes("repository") || kind.includes("repository") || kind.includes("commit") || kind.includes("pull_request")) return "Repository action";
  if (source.includes("endpoint") || source.includes("device") || kind.includes("device")) return "Device action";
  if (invokedTool(event)) return "Tool call";
  if (isModelRequest(event)) return "Model request";
  return "Activity";
}

function activityTypesOf(event: ActivityEvent): ActivityCategory[] {
  const source = firstText(event.source_surface, event.source, event.ai_surface).toLowerCase();
  const kind = firstText(event.event_type, event.action_type, event.tool_name).toLowerCase();
  const categories: ActivityCategory[] = [];
  if (source.includes("github") || source.includes("repository") || kind.includes("repository") || kind.includes("commit") || kind.includes("pull_request")) categories.push("Repository action");
  if (source.includes("endpoint") || source.includes("device") || kind.includes("device")) categories.push("Device action");
  if (invokedTool(event)) categories.push("Tool call");
  if (isModelRequest(event)) categories.push("Model request");
  if (isUpload(event)) categories.push("Upload");
  return categories.length ? categories : ["Activity"];
}

function invokedTool(event: ActivityEvent, canonicalAction: ActivityEvent = {}): boolean {
  const metadata = metadataOf(event);
  const kinds = [canonicalAction.action_type, event.event_type, event.action_type, metadata.event_type, metadata.action_type].map((value) => text(value).toLowerCase());
  return Boolean(event.tool_call_id || metadata.tool_call_id || event.function_call_id || metadata.function_call_id || event.tool_invoked === true || metadata.tool_invoked === true)
    || kinds.some((kind) => /(^|_)tool_call($|_(allowed|blocked|denied|requested|completed|failed|detected)$)/.test(kind));
}

function isUpload(event: ActivityEvent): boolean {
  const metadata = metadataOf(event);
  const kind = [event.event_type, event.action_type, metadata.event_type, metadata.action_type].map(text).join(" ").toLowerCase();
  return kind.includes("upload") || kind.includes("attachment") || Number(metadata.attachment_count || 0) > 0;
}

function isWarning(event: ActivityEvent, decision: ActivityRecord["decision"]): boolean {
  const metadata = metadataOf(event);
  const kind = [event.event_type, event.action_type, metadata.event_type, metadata.action_type, metadata.action_taken].map(text).join(" ").toLowerCase();
  return decision === "Warned" || kind.includes("warn");
}

function isFailure(event: ActivityEvent, trace: ActivityEvent): boolean {
  const metadata = metadataOf(event);
  const receipt = objectOf(trace.execution_receipt);
  const status = firstText(receipt.execution_status, receipt.status, event.execution_status, metadata.execution_status, metadata.status).toLowerCase();
  const kind = [event.event_type, event.action_type, metadata.event_type, metadata.action_type].map(text).join(" ").toLowerCase();
  return ["failed", "failure", "error", "degraded", "unhealthy", "tampered"].includes(status)
    || /(^|_)failed(_|$)/.test(kind) || /(^|_)error(_|$)/.test(kind);
}

function safeAttachments(metadata: ActivityEvent): ActivityEvent[] {
  if (!Array.isArray(metadata.attachments)) return [];
  return metadata.attachments.slice(0, 100).map((item) => {
    const record = objectOf(item);
    const safe: ActivityEvent = {};
    const mime = text(record.mime_type);
    if (mime.includes("/")) safe.mime_type = mime;
    if (typeof record.size === "number" && Number.isFinite(record.size) && record.size >= 0) safe.size = record.size;
    for (const key of ["id", "file_id", "sha256", "content_hash"]) if (text(record[key])) safe[key] = text(record[key]);
    return safe;
  });
}

function promptOf(event: ActivityEvent): { contentAccess: string; preview: string | null } {
  const metadata = metadataOf(event);
  const payload = [event.prompt_access, event.promptAccess, event.prompt_payload, metadata.prompt_access, metadata.prompt_payload]
    .find((value) => value && typeof value === "object") as ActivityEvent | undefined;
  const contentAccess = firstText(payload?.content_access_level, payload?.contentAccessLevel, event.content_access_level, metadata.content_access_level) || "CONTENT_UNAVAILABLE";
  const preview = text(payload?.redacted_preview ?? payload?.redactedPreview ?? event.redacted_preview ?? metadata.redacted_preview);
  return { contentAccess, preview: contentAccess === "REDACTED_PREVIEW" ? preview || null : null };
}

function targetOf(event: ActivityEvent, category: ActivityCategory): string {
  const metadata = metadataOf(event);
  return firstText(event.target, event.target_resource, event.api_endpoint, event.repository, event.domain, event.tool_name, metadata.target, metadata.target_resource, metadata.repository, metadata.domain)
    || (category === "Repository action" ? "Repository action" : category === "Tool call" ? "Tool call" : "Target unavailable");
}

function objectOf(value: unknown): ActivityEvent {
  return value && typeof value === "object" && !Array.isArray(value) ? value as ActivityEvent : {};
}

function knownStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (typeof item === "string" && item.trim()) return [item.trim()];
    const record = objectOf(item);
    const label = firstText(record.id, record.ref, record.reference, record.url, record.path, record.name, record.type);
    return label ? [label] : [];
  });
}

function traceOf(value: unknown): ActivityEvent {
  return objectOf(value);
}

function presentValue(value: unknown): unknown | null {
  return value === undefined || value === null || value === "" ? null : value;
}

function explicitGitRefs(...records: ActivityEvent[]): string[] {
  const refs: string[] = [];
  for (const record of records) {
    for (const [label, keys] of [
      ["Repository", ["repository", "repository_full_name", "repository_name", "repo_full_name", "repo"]],
      ["Branch", ["branch", "branch_name", "ref_name"]],
      ["Commit", ["commit_sha", "commit_hash", "commit_id"]],
      ["Pull request", ["pull_request_url", "pull_request_ref", "pull_request_number", "pr_url", "pr_number"]],
    ] as const) {
      const value = firstText(...keys.map((key) => {
        const candidate = record[key];
        return (key === "pull_request_number" || key === "pr_number") && typeof candidate === "number" ? String(candidate) : candidate;
      }));
      if (value) refs.push(`${label}: ${value}`);
    }
    refs.push(...knownStrings(record.git_refs), ...knownStrings(record.explicit_git_refs));
  }
  return [...new Set(refs)];
}

export function presentActivity(event: ActivityEvent, audit?: unknown, trace?: unknown): ActivityRecord {
  const metadata = metadataOf(event);
  const auditRecord = objectOf(audit);
  const traceRecord = traceOf(trace);
  const canonical = objectOf(traceRecord.canonical_ai_action || traceRecord.ai_action);
  const canonicalActor = objectOf(canonical.actor);
  const canonicalAction = objectOf(canonical.action);
  const canonicalSurface = objectOf(canonical.surface);
  const executionReceipt = objectOf(traceRecord.execution_receipt);
  const decisionReceipt = objectOf(traceRecord.decision_receipt);
  const auditMetadata = objectOf(auditRecord.metadata);
  const traceEvent = objectOf(traceRecord.runtime_event);
  const traceMetadata = objectOf(traceEvent.metadata);
  const downstreamObjects = Array.isArray(executionReceipt.downstream_objects) ? executionReceipt.downstream_objects : [];
  const prompt = objectOf(auditRecord.prompt_payload !== undefined ? auditRecord.prompt_payload : event.prompt_payload || metadata.prompt_payload);
  const decision = effectiveDecisionOf(event, auditRecord);
  const category = categoryOf(event, decision);
  const categories = activityTypesOf(event);
  const request = {
    contentAccess: firstText(prompt.content_access_level, prompt.contentAccessLevel) || promptOf(event).contentAccess,
    preview: null as string | null,
  };
  request.preview = request.contentAccess === "REDACTED_PREVIEW" && firstText(prompt.storage_mode).toLowerCase() !== "hashed_only"
    ? text(prompt.redacted_preview ?? prompt.redactedPreview) || (auditRecord.prompt_payload !== undefined ? null : promptOf(event).preview)
    : null;
  const identities = {
    requestingPerson: firstText(event.requesting_user, event.requesting_person, event.user_email, event.user_id, canonicalActor.user_id, canonicalActor.acting_on_behalf_of, canonicalActor.identity_id) || "Initiator unknown",
    appAgent: firstText(event.agent_id, event.application, canonicalActor.agent_id, auditRecord.ai_app, metadata.application) || "Unavailable",
    executingPrincipal: firstText(event.executing_principal, event.execution_principal, executionReceipt.executing_principal, executionReceipt.execution_principal) || "Unavailable",
    owner: firstText(event.repository_owner, metadata.repository_owner, auditMetadata.repository_owner, traceEvent.repository_owner) || "Unavailable",
    author: firstText(event.commit_author, metadata.commit_author, auditMetadata.commit_author, traceEvent.commit_author) || "Unavailable",
    reviewer: firstText(event.reviewer, metadata.reviewer, auditMetadata.reviewer, traceEvent.reviewer) || "Unavailable",
    merger: firstText(event.merger, metadata.merger, auditMetadata.merger, traceEvent.merger) || "Unavailable",
  };
  const actor = identities.requestingPerson;
  const application = identities.appAgent === "Unavailable" ? "Application unavailable" : identities.appAgent;
  const action = firstText(canonicalAction.operation, event.operation, auditRecord.operation, canonicalAction.action_type, event.action_type, auditRecord.action_type, canonicalAction.tool_name, event.tool_name) || "Action unavailable";
  const related = [...knownStrings(event.related_event_ids), ...knownStrings(auditRecord.related_event_ids)];
  const references: ActivityRecord["references"] = {};
  const correlationId = firstText(event.correlation_id, auditRecord.correlation_id, metadata.correlation_id);
  const chainId = firstText(event.chain_id, traceRecord.chain_id, decisionReceipt.chain_id, metadata.chain_id);
  const gitRefs = explicitGitRefs(event, metadata, auditRecord, auditMetadata, traceEvent, traceMetadata, traceRecord, canonicalAction, executionReceipt, ...downstreamObjects.map(objectOf));
  if (correlationId) references.correlationId = correlationId;
  if (chainId) references.chainId = chainId;
  if (gitRefs.length) references.gitRefs = [...new Set(gitRefs)];
  const traceAction = firstText(canonicalAction.operation, traceRecord.operation, action);
  const traceTarget = firstText(canonicalAction.target_resource, canonicalAction.data_destination, traceRecord.target_resource) || targetOf(event, category);
  const traceDecision = firstText(decisionReceipt.decision, traceRecord.decision, traceRecord.decision_explanation) || decision;
  const execution = firstText(executionReceipt.execution_status, executionReceipt.status, executionReceipt.outcome);
  const hasToolInvocation = invokedTool(event, canonicalAction);
  return {
    id: firstText(event.event_id, event.id) || "unknown-event",
    when: firstText(event.timestamp, event.created_at) || "Unknown time",
    actor: actor || "Initiator unknown",
    application,
    action: traceAction,
    target: traceTarget,
    decision,
    outcome: execution || outcomeOf(event, decision),
    category,
    categories: [
      ...(decision === "Blocked" ? ["Blocked" as const] : []),
      ...(isWarning(event, decision) ? ["Warning" as const] : []),
      ...(isFailure(event, traceRecord) ? ["Failure" as const] : []),
      ...categories,
    ],
    source: firstText(event.source_surface, event.source) || "Source unavailable",
    request,
    capture: request.contentAccess === "CONTENT_UNAVAILABLE" ? "Unavailable" : request.contentAccess,
    retention: firstText(event.retention, metadata.retention) || "Unavailable",
    related,
    references,
    identities,
    trace: {
      action: traceAction,
      target: traceTarget,
      decision: traceDecision,
      execution: execution || "Execution not captured",
      downstreamObjects,
      unavailable: !trace,
    },
    evidence: {
      provider: firstText(event.provider, event.model_provider, metadata.provider, metadata.model_provider, auditRecord.ai_provider, auditMetadata.provider, auditMetadata.model_provider, traceEvent.provider, traceMetadata.provider, traceMetadata.model_provider, canonicalSurface.provider, canonicalSurface.model_provider, canonicalSurface.ai_provider) || "Unavailable",
      model: firstText(event.model, event.model_name, metadata.model_name, auditRecord.ai_model, auditMetadata.model, auditMetadata.model_name, traceEvent.model, traceMetadata.model_name, canonicalSurface.model, canonicalSurface.model_name, canonicalSurface.ai_model) || "Unavailable",
      mcpServer: hasToolInvocation ? firstText(event.mcp_server_id, metadata.mcp_server_id, auditMetadata.mcp_server_id, traceEvent.mcp_server_id, traceMetadata.mcp_server_id, canonicalSurface.mcp_server_id) || "Unavailable" : "Unavailable",
      mcpTool: hasToolInvocation ? firstText(canonicalAction.tool_name, event.tool_name, metadata.tool_name, auditMetadata.tool_name, traceEvent.tool_name, traceMetadata.tool_name) || "Unavailable" : "Unavailable",
      attachments: safeAttachments(metadata),
      attachmentCount: Number(metadata.attachment_count || 0),
      redactedArguments: presentValue(canonicalAction.redacted_arguments ?? traceRecord.redacted_arguments ?? traceMetadata.redacted_arguments ?? metadata.redacted_arguments ?? auditMetadata.redacted_arguments ?? event.redacted_arguments),
      redactedResult: presentValue(executionReceipt.redacted_result ?? traceRecord.redacted_result ?? traceMetadata.redacted_result ?? metadata.redacted_result ?? auditMetadata.redacted_result ?? event.redacted_result),
      approval: presentValue(canonical.approval ?? (decisionReceipt.approval_binding_status ? { status: decisionReceipt.approval_binding_status, approved_by: decisionReceipt.approved_by ?? null } : null)),
      execution: presentValue(traceRecord.execution_receipt ?? event.execution_receipt ?? event.execution_status),
    },
    rawEvent: event,
    rawAudit: audit ?? null,
    rawTrace: trace ?? null,
  };
}

export function activitySearchText(record: ActivityRecord): string {
  return [record.actor, record.application, record.action, record.target, record.source, record.when, record.references.correlationId, record.references.chainId, ...(record.references.gitRefs || []), ...record.related]
    .filter(Boolean).join(" ").toLowerCase();
}
