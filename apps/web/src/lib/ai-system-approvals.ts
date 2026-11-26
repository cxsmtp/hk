/**
 * Settings → AI system approvals: the shapes of app/api/routers/ai_system_approvals.py and what the page works out
 * from them. No imports, so tests/ai-system-approvals.test.mjs loads it as it is.
 *
 * The policy says, for each risk tier, how many different people approve an AI system, whether the person who asked
 * may be one of them (only when one approval is needed), which roles approve, and the scopes an approver may choose:
 * blanket (until revoked), one-time (used up by the first governed use) or time-bound (ends at a set time).
 */

export type ApprovalScope = "blanket" | "one_time" | "time_bound";
export type ApprovalTier = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "RESTRICTED";

export type TierRule = {
  min_approvers: number;
  allow_self_approval: boolean;
  approver_roles: string[];
  allowed_scopes: ApprovalScope[];
  default_scope: ApprovalScope;
  default_duration_hours: number;
  max_duration_hours: number;
};

export type ApprovalPolicy = { tiers: Record<ApprovalTier, TierRule>; request_ttl_hours: number };

export type ApprovalPolicyView = {
  policy: ApprovalPolicy;
  defaults: ApprovalPolicy;
  tiers: ApprovalTier[];
  not_approvable_tiers: string[];
  unknown_tier_reads_as: ApprovalTier;
  scopes: ApprovalScope[];
  roles: string[];
  revision: number;
  updated_at: string | null;
  updated_by: string | null;
  may_manage: boolean;
};

export type ApprovalEntry = { user_id: string; role: string; at: string; reason?: string };

export type ApprovalRequestView = {
  id: string;
  ai_system_id: string;
  ai_system_name: string | null;
  risk_tier: string | null;
  tier: ApprovalTier | null;
  status: "pending" | "approved" | "denied" | "expired";
  requested_by: string | null;
  requested_at: string | null;
  reason: string;
  scope: ApprovalScope;
  duration_hours: number | null;
  renewal: boolean;
  target_status: string;
  approvals: ApprovalEntry[];
  approvals_needed: number;
  allow_self_approval: boolean;
  approver_roles: string[];
  allowed_scopes: ApprovalScope[];
  max_duration_hours: number | null;
  scope_fixed: boolean;
  expires_at: string | null;
  decided_by: string | null;
  decided_at: string | null;
  denied_reason: string | null;
  may_approve: boolean;
  may_deny: boolean;
};

export type ApprovalGrantView = {
  id: string;
  ai_system_id: string;
  ai_system_name: string | null;
  approval_request_id: string | null;
  scope: ApprovalScope;
  state: "ACTIVE" | "CONSUMED" | "EXPIRED" | "REVOKED" | "SUPERSEDED";
  risk_tier: string;
  origin: "workflow" | "upgrade";
  requested_by: string | null;
  approver_user_ids: string[];
  expires_at: string | null;
  lapsed: boolean;
  created_at: string | null;
  ended_at: string | null;
  ended_by: string | null;
  end_reason: string | null;
};

export type ApprovalDecision = { decision: "approve" | "deny"; scope?: ApprovalScope; duration_hours?: number; reason?: string };

export const TIER_ORDER: ApprovalTier[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED"];
export const SCOPE_ORDER: ApprovalScope[] = ["blanket", "one_time", "time_bound"];
export const SCOPE_LABELS: Record<ApprovalScope, string> = { blanket: "Blanket", one_time: "One-time", time_bound: "Time-bound" };
export const SCOPE_HINTS: Record<ApprovalScope, string> = {
  blanket: "stands until someone revokes it",
  one_time: "used up by the first request through the gateway",
  time_bound: "ends on its own at a set time",
};
export const TIER_LABELS: Record<ApprovalTier, string> = { LOW: "Low", MEDIUM: "Medium", HIGH: "High", CRITICAL: "Critical", RESTRICTED: "Restricted" };

/** Hours as people say them: "24 hours", "7 days", "90 days", "1 year". */
export function hoursLabel(hours: number | null | undefined): string {
  const h = Math.floor(Number(hours || 0));
  if (h <= 0) return "";
  if (h === 8760) return "1 year";
  if (h % 24 === 0 && h >= 48) return `${h / 24} days`;
  return h === 1 ? "1 hour" : `${h} hours`;
}

/** One line for a tier's rule: "2 approvers, not the requester · Time-bound only (7 days, up to 30 days)". */
export function ruleSummary(rule: TierRule): string {
  const who =
    rule.min_approvers === 1
      ? rule.allow_self_approval
        ? "1 approver, who may be the requester"
        : "1 approver, not the requester"
      : `${rule.min_approvers} approvers, none of them the requester`;
  const scopes = rule.allowed_scopes.map((scope) => SCOPE_LABELS[scope]);
  const scopeText = scopes.length === 1 ? `${scopes[0]} only` : `${scopes.join(", ")} (default ${SCOPE_LABELS[rule.default_scope].toLowerCase()})`;
  const time = rule.allowed_scopes.includes("time_bound")
    ? ` · time-bound ${hoursLabel(rule.default_duration_hours)} by default, up to ${hoursLabel(rule.max_duration_hours)}`
    : "";
  return `${who} · ${scopeText}${time}`;
}

/** What the API would refuse in a tier's rule, said the same way, so the page says it before saving. */
export function ruleProblems(rule: TierRule, roles?: readonly string[]): string[] {
  const out: string[] = [];
  if (!Number.isInteger(rule.min_approvers) || rule.min_approvers < 1 || rule.min_approvers > 5) out.push("Approvers must be between 1 and 5.");
  if (rule.allow_self_approval && rule.min_approvers > 1) out.push("The requester may approve their own request only when one approval is needed.");
  if (!rule.approver_roles.length) out.push("Name at least one role that may approve.");
  if (roles) for (const role of rule.approver_roles) if (!roles.includes(role)) out.push(`There is no role ${role}.`);
  if (!rule.allowed_scopes.length) out.push("Allow at least one approval scope.");
  else if (!rule.allowed_scopes.includes(rule.default_scope)) out.push("The default scope must be one of the allowed scopes.");
  if (!Number.isInteger(rule.max_duration_hours) || rule.max_duration_hours < 1 || rule.max_duration_hours > 8760) out.push("The longest time-bound approval is 1 to 8760 hours.");
  else if (!Number.isInteger(rule.default_duration_hours) || rule.default_duration_hours < 1 || rule.default_duration_hours > rule.max_duration_hours)
    out.push("The default time-bound approval must be at least 1 hour and no longer than the longest.");
  return out;
}

/** A rule changed by the form, kept whole: more than one approver turns self-approval off; the default scope follows
 * the allowed ones. */
export function withRuleChange(rule: TierRule, patch: Partial<TierRule>): TierRule {
  const next: TierRule = { ...rule, ...patch };
  if (next.min_approvers > 1) next.allow_self_approval = false;
  next.allowed_scopes = SCOPE_ORDER.filter((scope) => next.allowed_scopes.includes(scope));
  if (next.allowed_scopes.length && !next.allowed_scopes.includes(next.default_scope)) next.default_scope = next.allowed_scopes[0];
  return next;
}

/** The body of PUT /settings/ai-system-approvals: every tier, as the form holds it. */
export function policyPayload(policy: ApprovalPolicy): ApprovalPolicy {
  const tiers = {} as Record<ApprovalTier, TierRule>;
  for (const tier of TIER_ORDER) {
    const rule = policy.tiers[tier];
    tiers[tier] = {
      min_approvers: rule.min_approvers,
      allow_self_approval: rule.min_approvers === 1 && rule.allow_self_approval,
      approver_roles: [...rule.approver_roles],
      allowed_scopes: SCOPE_ORDER.filter((scope) => rule.allowed_scopes.includes(scope)),
      default_scope: rule.default_scope,
      default_duration_hours: rule.default_duration_hours,
      max_duration_hours: rule.max_duration_hours,
    };
  }
  return { tiers, request_ttl_hours: policy.request_ttl_hours };
}

/** Whether the form differs from what is saved. */
export function policyChanged(saved: ApprovalPolicy, form: ApprovalPolicy): boolean {
  return JSON.stringify(policyPayload(saved)) !== JSON.stringify(policyPayload(form));
}

/** "1 of 2 approvals" and who still may decide. */
export function progressLabel(request: Pick<ApprovalRequestView, "approvals" | "approvals_needed">): string {
  return `${request.approvals.length} of ${request.approvals_needed} approval${request.approvals_needed === 1 ? "" : "s"}`;
}

/** A standing approval in one line: "Blanket", "One-time, not used yet", "Time-bound until 3 Dec 2026, 14:00 UTC". */
export function grantLine(grant: Pick<ApprovalGrantView, "scope" | "state" | "expires_at" | "origin" | "lapsed">): string {
  const base = SCOPE_LABELS[grant.scope];
  const carried = grant.origin === "upgrade" ? " (approved before the workflow; carried over)" : "";
  if (grant.state !== "ACTIVE") return `${base}, ${grant.state.toLowerCase()}${carried}`;
  if (grant.scope === "one_time") return `${base}, not used yet${carried}`;
  if (grant.scope === "time_bound" && grant.expires_at) {
    const at = new Date(grant.expires_at);
    const when = Number.isFinite(at.getTime())
      ? `${at.toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" })}, ${at.toISOString().slice(11, 16)} UTC`
      : grant.expires_at;
    return `${base} ${grant.lapsed ? "ended" : "until"} ${when}${carried}`;
  }
  return `${base}${carried}`;
}

/** The message in an API refusal: `error`, or `detail` as text or as { message }. */
export function refusalMessage(text: string, fallback = "Something went wrong."): string {
  const raw = String(text || "").trim();
  if (!raw) return fallback;
  try {
    const body = JSON.parse(raw) as { error?: unknown; detail?: unknown };
    if (typeof body.error === "string" && body.error) return body.error;
    if (typeof body.detail === "string" && body.detail) return body.detail;
    if (body.detail && typeof body.detail === "object" && typeof (body.detail as { message?: unknown }).message === "string") return (body.detail as { message: string }).message;
    return fallback;
  } catch {
    return raw;
  }
}
