"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowRight, Eye, RefreshCw, ShieldCheck, UsersRound, X } from "lucide-react";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { getSession } from "@/lib/auth";
import {
  canSubmitVisibilityRecovery,
  isVisibilityRecoveryReasonValid,
  isVisibilityRecoveryRole,
  loadUserVisibilityData,
  submitVisibilityRecovery,
} from "./user-visibility-recovery";
import type {
  ListEnvelope,
  UserVisibilityAction,
  UserVisibilityAIUsage,
  UserVisibilityDirectorySummary,
  UserVisibilityDepartment,
  UserVisibilityExperienceSection,
  UserVisibilityGroup,
  UserVisibilityGroupDetail,
  UserVisibilityOrganization,
  UserVisibilityPolicyStack,
  UserVisibilityPrompt,
  UserVisibilityUser,
} from "@/lib/types";

type WorkspaceView = "users" | "departments" | "organization" | "actions" | "groups";
type RevealPurpose = "security_investigation" | "audit" | "incident_response" | "privacy_review";
type User360Tab = "overview" | "usage" | "accounts" | "prompts" | "actions" | "policies" | "controls" | "lineage" | "maturity";

type User360Overview = {
  user: {
    user_id: string;
    display_name?: string | null;
    email?: string | null;
    department?: string | null;
    role?: string | null;
    status?: string | null;
    deployment_surfaces?: string[];
    last_ai_activity?: string | null;
  };
  ai_usage: UserVisibilityAIUsage;
  group_refs: string[];
  maturity_stage?: string;
  evidence_quality?: string;
};

type User360Controls = {
  evidence_quality?: string;
  receipt_refs?: Array<Record<string, string | null | undefined>>;
  control_states?: string[];
};

type User360Lineage = {
  recent_action_refs?: Array<Record<string, string | null | undefined>>;
};

type UserAccountTenantContext = {
  context_id: string;
  application: string;
  provider: string;
  product: string;
  models: string[];
  clients: string[];
  display_category: "COMPANY_ENTERPRISE" | "PARTNER_EXTERNAL_ENTERPRISE" | "PERSONAL" | "ANONYMOUS" | "UNKNOWN";
  account_class: string;
  provider_tenant: { selected_organisation_id?: string | null; selected_workspace_id?: string | null; selected_tenant_id?: string | null; verification: string };
  subscription_class?: string | null;
  licence_state?: string | null;
  assurance_level: string;
  verification_status: string;
  verification_method: string;
  relationship_state: string;
  surfaces: string[];
  last_seen?: string | null;
  activity_count: number;
  current: boolean;
  limitations: string[];
};

type UserAccountTenantSection = { summary: Record<string, number>; items: UserAccountTenantContext[]; truncated: boolean; limit: number; limitations: string[] };

type ActionFilterDraft = {
  department: string;
  application: string;
  provider: string;
  model: string;
  agent: string;
  tool: string;
  resource: string;
  target: string;
  destination: string;
  data_class: string;
  side_effect: string;
  decision: string;
  control_state: string;
};

type DirectoryFilterDraft = {
  department: string;
  status: string;
  role: string;
  group_id: string;
  application: string;
  account_class: string;
  provider: string;
  model: string;
  last_activity_after: string;
};

const VIEWS: Array<{ id: WorkspaceView; label: string; note: string }> = [
  { id: "users", label: "Users", note: "Identity and AI use" },
  { id: "departments", label: "Departments", note: "Scoped aggregates" },
  { id: "organization", label: "Organization", note: "Estate activity" },
  { id: "actions", label: "Action Explorer", note: "Decision and evidence" },
  { id: "groups", label: "Groups", note: "Policy-pack context" },
];

const USER_360_TABS: Array<{ id: User360Tab; label: string; requiresActionDetail?: boolean }> = [
  { id: "overview", label: "Overview" },
  { id: "usage", label: "AI usage" },
  { id: "accounts", label: "AI Accounts & Tenants" },
  { id: "prompts", label: "Prompts & requests", requiresActionDetail: true },
  { id: "actions", label: "AI actions", requiresActionDetail: true },
  { id: "policies", label: "Policies & Policy Packs" },
  { id: "controls", label: "Controls & evidence", requiresActionDetail: true },
  { id: "lineage", label: "Activity Lineage", requiresActionDetail: true },
  { id: "maturity", label: "Maturity & trends" },
];

const DIRECTORY_SORT_OPTIONS: Array<{ value: "last_activity" | "display_name" | "department" | "action_count"; label: string }> = [
  { value: "last_activity", label: "Last AI activity" },
  { value: "display_name", label: "Name" },
  { value: "department", label: "Department" },
  { value: "action_count", label: "Recorded actions" },
];

const EMPTY_ACTION_FILTERS: ActionFilterDraft = {
  department: "",
  application: "",
  provider: "",
  model: "",
  agent: "",
  tool: "",
  resource: "",
  target: "",
  destination: "",
  data_class: "",
  side_effect: "",
  decision: "",
  control_state: "",
};

const EMPTY_DIRECTORY_FILTERS: DirectoryFilterDraft = {
  department: "",
  status: "",
  role: "",
  group_id: "",
  application: "",
  account_class: "",
  provider: "",
  model: "",
  last_activity_after: "",
};

const DIRECTORY_FILTER_FIELDS: Array<{ key: keyof DirectoryFilterDraft; label: string; type?: "datetime-local" }> = [
  { key: "department", label: "Department" },
  { key: "status", label: "Status" },
  { key: "role", label: "Role" },
  { key: "group_id", label: "Group ID" },
  { key: "application", label: "Application" },
  { key: "account_class", label: "Account class" },
  { key: "provider", label: "Provider" },
  { key: "model", label: "Model" },
  { key: "last_activity_after", label: "Activity after", type: "datetime-local" },
];

const REVEAL_PURPOSES: Array<{ value: RevealPurpose; label: string }> = [
  { value: "security_investigation", label: "Security investigation" },
  { value: "audit", label: "Audit" },
  { value: "incident_response", label: "Incident response" },
  { value: "privacy_review", label: "Privacy review" },
];
const ACTION_EXPLORER_REFRESH_MS = 1_000;

function humanize(value?: string | null, fallback = "Unknown"): string {
  const normalized = String(value || "").trim();
  if (!normalized) return fallback;
  return normalized.replace(/_/g, " ");
}

function formatDate(value?: string | null): string {
  if (!value) return "No recorded activity";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleString();
}

function decisionTone(value?: string | null): string {
  const decision = String(value || "").toLowerCase();
  if (["blocked", "block", "denied", "deny"].includes(decision)) return "border-rose-400/25 bg-rose-400/10 text-rose-200";
  if (["held", "warned", "warning", "modified", "require_approval"].includes(decision)) return "border-amber-400/25 bg-amber-400/10 text-amber-200";
  if (["allowed", "allow"].includes(decision)) return "border-emerald-400/25 bg-emerald-400/10 text-emerald-200";
  return "border-slate-500/35 bg-slate-500/10 text-slate-300";
}

function contentTone(level?: string | null): string {
  if (level === "REDACTED_PREVIEW") return "border-sky-400/25 bg-sky-400/10 text-sky-200";
  if (level === "CONTENT_UNAVAILABLE") return "border-slate-500/35 bg-slate-500/10 text-slate-300";
  return "border-amber-400/25 bg-amber-400/10 text-amber-200";
}

function promptSummary(prompt?: UserVisibilityPrompt | null): string {
  if (!prompt) return "CONTENT_UNAVAILABLE — no prompt source was attached to this action.";
  if (prompt.content_access_level === "REDACTED_PREVIEW") return prompt.redacted_preview || "Redacted preview unavailable.";
  if (prompt.content_access_level === "CONTENT_UNAVAILABLE") return "CONTENT_UNAVAILABLE — source text was not captured.";
  return `${prompt.content_access_level} — structured metadata only.`;
}

function errorMessage(error: unknown): string {
  const value = error instanceof Error ? error.message : "Unknown request failure";
  if (value.includes("visibility_capability_required")) return "Your role does not currently have this visibility capability.";
  if (value.includes("visibility_department_scope_denied")) return "This view is outside your approved department scope.";
  if (value.includes("visibility_content_retention_disabled")) return "Privileged content reveal is disabled by the tenant retention policy.";
  return value;
}

function DefinitionList({ values }: { values: Array<{ label: string; value?: string | number | null }> }) {
  return (
    <dl className="grid gap-x-5 gap-y-3 sm:grid-cols-2">
      {values.map((item) => (
        <div key={item.label} className="border-l border-[#263149] pl-3">
          <dt className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">{item.label}</dt>
          <dd className="mt-1 break-words text-sm text-slate-200">{item.value === null || item.value === undefined || item.value === "" ? "Unknown" : String(item.value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function CountTile({ label, value, note }: { label: string; value: string | number; note: string }) {
  return (
    <div className="relative overflow-hidden rounded-lg border border-[#263149] bg-[#111722] px-4 py-3">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
      <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold tracking-[-0.03em] text-slate-100">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{note}</p>
    </div>
  );
}

function CompactPanel({ title, value, note }: { title: string; value: string; note: string }) {
  return <div className="rounded-md border border-[#263149] bg-[#101622] p-3"><p className="font-mono text-[9px] uppercase tracking-[0.12em] text-slate-500">{title}</p><p className="mt-1 truncate text-sm font-medium text-slate-200" title={value}>{value}</p><p className="mt-1 text-xs leading-4 text-slate-500">{note}</p></div>;
}

function User360SectionContent({
  section,
  data,
  onInspectAction,
}: {
  section: User360Tab;
  data: unknown;
  onInspectAction: (action: UserVisibilityAction) => void;
}) {
  if (section === "overview") {
    const overview = data as User360Overview;
    return <div className="grid gap-3 sm:grid-cols-2"><CompactPanel title="Identity & groups" value={`${overview.group_refs?.length ?? 0} visible group reference(s)`} note={`Department: ${overview.user.department || "Unknown"}`} /><CompactPanel title="AI activity" value={`${overview.ai_usage.action_count} recorded action(s)`} note={`${overview.ai_usage.prompt_request_count} prompt/request record(s)`} /><CompactPanel title="Surfaces" value={(overview.user.deployment_surfaces || []).join(", ") || "Unknown"} note="Unavailable is not treated as covered" /><CompactPanel title="Maturity" value={humanize(overview.maturity_stage, "Unknown")} note={`Evidence: ${humanize(overview.evidence_quality, "Unknown")}`} /></div>;
  }
  if (section === "usage") {
    const usage = data as UserVisibilityAIUsage;
    return <div className="grid gap-3 sm:grid-cols-2"><CompactPanel title="Applications" value={usage.applications.join(", ") || "Unknown"} note="Observed use, not an approval list" /><CompactPanel title="Account types" value={usage.account_classes.join(", ") || "Unknown"} note="Account classification is source-backed" /><CompactPanel title="Providers & models" value={[...usage.providers, ...usage.models].join(", ") || "Unknown"} note="Only observed source fields are shown" /><CompactPanel title="Agents & tools" value={[...usage.agents, ...usage.tools].join(", ") || "Unknown"} note="No tool trust status is inferred here" /></div>;
  }
  if (section === "accounts") {
    const accounts = data as UserAccountTenantSection;
    if (!accounts.items.length) return <p className="rounded-md border border-dashed border-[#33405a] p-4 text-sm text-slate-500">No AI account or provider-tenant evidence is linked to this user in the selected scope.</p>;
    return <div className="space-y-3"><div className="grid gap-2 sm:grid-cols-2"><CompactPanel title="Company / enterprise tenant" value={String(accounts.summary.current_company_enterprise || 0)} note="Current verified provider membership" /><CompactPanel title="Partner / external enterprise" value={String(accounts.summary.partner_external_enterprise || 0)} note="Not the customer’s own provider tenant" /><CompactPanel title="Personal" value={String(accounts.summary.personal || 0)} note="Source-classified personal accounts" /><CompactPanel title="Anonymous" value={String(accounts.summary.anonymous || 0)} note="Source-classified anonymous contexts" /><CompactPanel title="Unknown" value={String(accounts.summary.unknown || 0)} note="Insufficient or unmatched evidence" /></div>{accounts.items.map((account) => <details key={account.context_id} className="rounded-md border border-[#263149] bg-[#101622] p-3"><summary className="cursor-pointer list-none text-sm font-medium text-slate-100">{account.application || account.product || "Unknown application"} · {humanize(account.display_category)}</summary><div className="mt-3 space-y-3"><div className="flex flex-wrap gap-2"><Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[9px] uppercase text-slate-300">{humanize(account.display_category)}</Badge><Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[9px] uppercase text-slate-400">{account.current ? "Current" : humanize(account.relationship_state)}</Badge></div><DefinitionList values={[{ label: "Application", value: account.application }, { label: "Provider", value: account.provider }, { label: "Product", value: account.product }, { label: "Detailed account class", value: humanize(account.account_class) }, { label: "Provider tenant", value: account.provider_tenant.selected_tenant_id }, { label: "Organization", value: account.provider_tenant.selected_organisation_id }, { label: "Workspace", value: account.provider_tenant.selected_workspace_id }, { label: "Subscription", value: account.subscription_class }, { label: "License", value: account.licence_state }, { label: "Verification", value: humanize(account.provider_tenant.verification) }, { label: "Assurance", value: account.assurance_level }, { label: "Relationship", value: humanize(account.relationship_state) }, { label: "Surfaces", value: account.surfaces.map((item) => humanize(item)).join(", ") }, { label: "Models", value: account.models.join(", ") }, { label: "Clients", value: account.clients.join(", ") }, { label: "Last activity", value: formatDate(account.last_seen) }, { label: "Observed activity", value: account.activity_count }]} />{account.limitations.length ? <p className="text-xs text-slate-500">Limitations: {account.limitations.map((item) => humanize(item)).join(", ")}</p> : null}</div></details>)}{accounts.truncated ? <p className="text-xs text-slate-500">Only the first {accounts.limit} bounded account contexts are shown.</p> : null}<p className="text-xs text-slate-500">{accounts.limitations.map((item) => humanize(item)).join(" · ")}</p></div>;
  }
  if (section === "prompts" || section === "actions") {
    const page = data as ListEnvelope<UserVisibilityAction>;
    return <div className="space-y-2">{(page.items || []).map((action) => <ActionMini key={action.action_id} action={action} onInspect={() => onInspectAction(action)} />)}{!page.items?.length ? <p className="rounded-md border border-dashed border-[#33405a] p-4 text-sm text-slate-500">No {section === "prompts" ? "prompt or request" : "action"} records are available in this bounded view.</p> : null}<p className="text-xs text-slate-500">Page {page.page} of bounded source-backed results ({page.total} total).</p></div>;
  }
  if (section === "policies") {
    const stack = data as UserVisibilityPolicyStack;
    return <div className="space-y-3"><div className="rounded-md border border-[#263149] bg-[#0d131d] p-3"><p className="text-sm font-semibold text-slate-100">Policy stack</p><p className="mt-1 text-sm text-slate-400">Final decision: <span className="text-slate-200">{humanize(stack.final?.decision, "No matching policy")}</span></p><p className="mt-2 text-xs leading-5 text-slate-500"><span className="font-medium text-slate-300">Why this policy applies:</span> {stack.explanation || "No final rule matched the available request context."}</p></div>{stack.entries.length ? stack.entries.map((entry) => <div key={entry.assignment_id} className="rounded-md border border-[#263149] bg-[#101622] p-3"><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-medium text-slate-100">{entry.assignment_key}</p><Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[9px] uppercase text-slate-300">{entry.assignment_kind}</Badge><Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[9px] uppercase text-slate-400">{entry.pack_instance_state || "unknown"}</Badge></div><p className="mt-1 text-xs text-slate-400">{entry.source_pack || "Unknown source pack"}{entry.source_pack_version ? ` · ${entry.source_pack_version}` : ""} · {entry.scope_explanation}</p><p className="mt-1 text-xs text-slate-500">{entry.requires_action_context ? "Additional action selectors must match before this policy is effective." : "No additional action selector is required for this assignment scope."}</p>{entry.selected_surfaces?.length ? <p className="mt-1 text-xs text-slate-500">Surfaces: {entry.selected_surfaces.join(", ")}</p> : null}</div>) : <p className="rounded-md border border-dashed border-[#33405a] p-4 text-sm text-slate-500">No effective Policy Pack assignment is available for this user context.</p>}</div>;
  }
  if (section === "controls") {
    const controls = data as User360Controls;
    return <DefinitionList values={[{ label: "Evidence quality", value: humanize(controls.evidence_quality, "Unknown") }, { label: "Control states", value: (controls.control_states || []).map((item) => humanize(item)).join(", ") || "Unknown" }, { label: "Receipt references", value: controls.receipt_refs?.length ?? 0 }, { label: "Coverage", value: "Open Control Coverage for authoritative surface detail" }]} />;
  }
  if (section === "lineage") {
    const lineage = data as User360Lineage;
    return <div className="space-y-3"><p className="text-sm text-slate-400">{lineage.recent_action_refs?.length ?? 0} bounded Activity Lineage reference(s) are available for this user.</p><Link href="/runtime-intelligence/activity-map" className="text-sm font-medium text-cyan-200 hover:text-cyan-100">Open Investigation &amp; AI Activity Lineage <ArrowRight className="inline h-3.5 w-3.5" /></Link></div>;
  }
  const maturity = data as { stage?: string; state?: string; maturity_link?: string };
  return <div className="space-y-3"><DefinitionList values={[{ label: "Maturity stage", value: humanize(maturity.stage, "Unknown") }, { label: "Source state", value: humanize(maturity.state, "Unknown") }]} /><Link href={maturity.maturity_link || "/maturity"} className="text-sm font-medium text-cyan-200 hover:text-cyan-100">Open Maturity Curve <ArrowRight className="inline h-3.5 w-3.5" /></Link></div>;
}

export function UserVisibilityWorkspace() {
  const searchParams = useSearchParams();
  const [view, setView] = useState<WorkspaceView>("users");
  const [userSearch, setUserSearch] = useState("");
  const [appliedUserSearch, setAppliedUserSearch] = useState("");
  const [directoryFilters, setDirectoryFilters] = useState<DirectoryFilterDraft>(EMPTY_DIRECTORY_FILTERS);
  const [appliedDirectoryFilters, setAppliedDirectoryFilters] = useState<DirectoryFilterDraft>(EMPTY_DIRECTORY_FILTERS);
  const [users, setUsers] = useState<ListEnvelope<UserVisibilityUser> | null>(null);
  const [directorySummary, setDirectorySummary] = useState<UserVisibilityDirectorySummary | null>(null);
  const [directoryPage, setDirectoryPage] = useState(1);
  const [directorySort, setDirectorySort] = useState<"last_activity" | "display_name" | "department" | "action_count">("last_activity");
  const [directorySortDirection, setDirectorySortDirection] = useState<"asc" | "desc">("desc");
  const [departments, setDepartments] = useState<ListEnvelope<UserVisibilityDepartment> | null>(null);
  const [organization, setOrganization] = useState<UserVisibilityOrganization | null>(null);
  const [actions, setActions] = useState<ListEnvelope<UserVisibilityAction> | null>(null);
  const [groups, setGroups] = useState<ListEnvelope<UserVisibilityGroup> | null>(null);
  const [selectedGroup, setSelectedGroup] = useState<UserVisibilityGroupDetail | null>(null);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [selectedUserTab, setSelectedUserTab] = useState<User360Tab>("overview");
  const [userSections, setUserSections] = useState<Partial<Record<User360Tab, UserVisibilityExperienceSection<unknown>>>>({});
  const [selectedAction, setSelectedAction] = useState<UserVisibilityAction | null>(null);
  const [followLatestAction, setFollowLatestAction] = useState(true);
  const [lastActionRefreshAt, setLastActionRefreshAt] = useState<string>("");
  const [filters, setFilters] = useState<ActionFilterDraft>(EMPTY_ACTION_FILTERS);
  const [loading, setLoading] = useState("");
  const [error, setError] = useState("");
  const [visibilityCapabilityRequired, setVisibilityCapabilityRequired] = useState(false);
  const [visibilityReason, setVisibilityReason] = useState("");
  const [revealOpen, setRevealOpen] = useState(false);
  const [revealPurpose, setRevealPurpose] = useState<RevealPurpose>("security_investigation");
  const [revealReason, setRevealReason] = useState("");
  const [revealedContent, setRevealedContent] = useState<string | null>(null);
  const [openedUserQuery, setOpenedUserQuery] = useState("");
  const actionRequestSeq = useRef(0);
  const requestedUserId = searchParams.get("user_id")?.trim() || "";

  const refreshUserVisibility = useCallback(async () => {
    setLoading("users");
    setError("");
    const outcome = await loadUserVisibilityData({
      loadUsers: () => api.userVisibilityUsers({ q: appliedUserSearch || undefined, ...appliedDirectoryFilters, sort_by: directorySort, sort_direction: directorySortDirection, page: directoryPage, page_size: 25 }),
      loadDirectorySummary: () => api.userVisibilityDirectorySummary(),
    });
    if (outcome.users.status === "fulfilled") setUsers(outcome.users.value);
    if (outcome.directorySummary.status === "fulfilled") setDirectorySummary(outcome.directorySummary.value);
    if (outcome.allSucceeded) {
      setVisibilityCapabilityRequired(false);
    } else if (outcome.capabilityRequired) {
      setVisibilityCapabilityRequired(true);
    }
    if (outcome.firstError) {
      setError(errorMessage(outcome.firstError));
    }
    setLoading("");
  }, [appliedDirectoryFilters, appliedUserSearch, directoryPage, directorySort, directorySortDirection]);

  const loadDepartments = useCallback(async () => {
    setLoading("departments");
    setError("");
    try {
      setDepartments(await api.userVisibilityDepartments({ page: 1, page_size: 50 }));
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading("");
    }
  }, []);

  const loadOrganization = useCallback(async () => {
    setLoading("organization");
    setError("");
    try {
      setOrganization(await api.userVisibilityOrganization());
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading("");
    }
  }, []);

  const loadActions = useCallback(async (requestedFilters = filters) => {
    const requestSeq = actionRequestSeq.current + 1;
    actionRequestSeq.current = requestSeq;
    setLoading("actions");
    setError("");
    try {
      const nextActions = await api.userVisibilityActions({ ...requestedFilters, page: 1, page_size: 50 });
      if (requestSeq !== actionRequestSeq.current) return;
      setActions(nextActions);
      setLastActionRefreshAt(new Date().toISOString());
      setSelectedAction((current) => {
        const newestAction = nextActions.items[0] || null;
        if (followLatestAction) return newestAction;
        if (!current) return newestAction;
        return nextActions.items.find((action) => action.action_id === current.action_id) || newestAction;
      });
    } catch (requestError) {
      if (requestSeq !== actionRequestSeq.current) return;
      setError(errorMessage(requestError));
    } finally {
      if (requestSeq === actionRequestSeq.current) setLoading("");
    }
  }, [filters, followLatestAction]);

  const loadGroups = useCallback(async () => {
    setLoading("groups");
    setError("");
    try {
      setGroups(await api.userVisibilityGroups({ page: 1, page_size: 50 }));
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading("");
    }
  }, []);

  useEffect(() => {
    if (view === "users") {
      void refreshUserVisibility();
      return;
    }
    if (view === "departments" && departments === null) void loadDepartments();
    if (view === "organization" && organization === null) void loadOrganization();
    if (view === "actions" && actions === null) void loadActions();
    if (view === "groups" && groups === null) void loadGroups();
  }, [actions, departments, groups, loadActions, loadDepartments, loadGroups, loadOrganization, organization, refreshUserVisibility, view]);

  useEffect(() => {
    if (view !== "actions") return undefined;
    const timer = window.setInterval(() => {
      void loadActions(filters);
    }, ACTION_EXPLORER_REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [filters, loadActions, view]);

  const loadUserSection = useCallback(async (userId: string, section: User360Tab, force = false) => {
    if (!force && userSections[section]) return;
    setLoading("user-section");
    setError("");
    try {
      const response: UserVisibilityExperienceSection<unknown> = section === "policies"
        ? { section, data: await api.userVisibilityPolicyStack(userId) }
        : await api.userVisibilityUserExperience(userId, section, { page: 1, page_size: 25 });
      setUserSections((current) => ({ ...current, [section]: response }));
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading("");
    }
  }, [userSections]);

  const selectUser = useCallback(async (userId: string) => {
    setSelectedUserId(userId);
    setSelectedUserTab("overview");
    setUserSections({});
    await loadUserSection(userId, "overview", true);
  }, [loadUserSection]);

  useEffect(() => {
    if (!requestedUserId || openedUserQuery === requestedUserId) return;
    setOpenedUserQuery(requestedUserId);
    setView("users");
    void selectUser(requestedUserId);
  }, [openedUserQuery, requestedUserId, selectUser]);

  const selectGroup = useCallback(async (groupId: string) => {
    setLoading("group-detail");
    setError("");
    try {
      setSelectedGroup(await api.userVisibilityGroup(groupId));
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading("");
    }
  }, []);

  const actionSummary = useMemo(() => {
    const items = actions?.items || [];
    return {
      total: actions?.total || 0,
      blocked: items.filter((action) => ["blocked", "block", "denied", "deny"].includes(String(action.decision || "").toLowerCase())).length,
      unknownEvidence: items.filter((action) => !action.evidence_quality || action.evidence_quality === "unknown").length,
    };
  }, [actions]);

  const selectedOverview = userSections.overview?.data as User360Overview | undefined;
  const selectedSection = userSections[selectedUserTab];

  const submitUserSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAppliedUserSearch(userSearch.trim());
    setAppliedDirectoryFilters(directoryFilters);
    setDirectoryPage(1);
  };

  const submitActionFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFollowLatestAction(true);
    void loadActions(filters);
  };

  const enableDemoVisibility = async () => {
    const session = getSession();
    if (!isVisibilityRecoveryRole(session)) {
      setError("Only an owner or administrator can enable this scoped visibility.");
      return;
    }
    if (!isVisibilityRecoveryReasonValid(visibilityReason)) {
      setError("Provide an audit reason between 3 and 1000 characters before enabling visibility.");
      return;
    }

    setLoading("visibility-grant");
    setError("");
    const submission = await submitVisibilityRecovery({
      session,
      reason: visibilityReason,
      createGrant: api.createUserVisibilityAccessGrant,
    });
    if (!submission.ok) {
      setError(errorMessage(submission.error));
      setLoading("");
      return;
    }
    await refreshUserVisibility();
  };

  const openReveal = (action: UserVisibilityAction) => {
    setSelectedAction(action);
    setRevealReason("");
    setRevealedContent(null);
    setRevealOpen(true);
  };

  const closeReveal = () => {
    setRevealOpen(false);
    setRevealedContent(null);
    setRevealReason("");
  };

  const consumeReveal = async () => {
    if (!selectedAction || revealReason.trim().length < 3) {
      setError("Provide an investigation reason of at least three characters before requesting a reveal.");
      return;
    }
    setLoading("reveal");
    setError("");
    try {
      const grant = await api.requestUserVisibilityPromptReveal(selectedAction.action_id, {
        purpose: revealPurpose,
        reason: revealReason.trim(),
      });
      const response = await api.consumeUserVisibilityPromptReveal(grant.grant_id);
      setRevealedContent(response.content);
    } catch (requestError) {
      setError(errorMessage(requestError));
    } finally {
      setLoading("");
    }
  };

  const refreshCurrent = () => {
    if (view === "users") {
      void refreshUserVisibility();
    }
    if (view === "departments") void loadDepartments();
    if (view === "organization") void loadOrganization();
    if (view === "actions") void loadActions();
    if (view === "groups") void loadGroups();
  };

  const currentRole = String(getSession()?.userRole || "").trim().toLowerCase();
  const visibilityRecoveryVisible = view === "users" && visibilityCapabilityRequired && ["owner", "admin"].includes(currentRole);
  const visibilityReasonIsValid = canSubmitVisibilityRecovery({ session: getSession(), reason: visibilityReason, isSubmitting: loading === "visibility-grant" });

  return (
    <section className="space-y-5" aria-label="User visibility workspace">
      <div className="relative overflow-hidden rounded-xl border border-[#2a3a55] bg-[radial-gradient(circle_at_88%_-10%,rgba(34,211,238,0.17),transparent_34%),linear-gradient(135deg,#111827_0%,#0f1622_52%,#141722_100%)] p-5 shadow-[0_24px_70px_rgba(0,0,0,0.24)] sm:p-6">
        <div className="absolute inset-y-0 left-0 w-1 bg-gradient-to-b from-cyan-300 via-cyan-500/50 to-transparent" />
        <div className="relative flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-3xl">
            <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-cyan-200">Identity · action · evidence</p>
            <h2 className="mt-2 text-2xl font-semibold tracking-[-0.03em] text-slate-100">User visibility without productivity surveillance.</h2>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">This workspace projects existing activity, Policy Packs, and lineage records. Unknown evidence stays unknown; prompt content stays safe by default.</p>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={refreshCurrent} disabled={Boolean(loading)}>
            <RefreshCw className="mr-2 h-3.5 w-3.5" /> Refresh view
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap gap-2 border-b border-[#263149] pb-3" role="tablist" aria-label="User visibility views">
        {VIEWS.map((item) => {
          const active = view === item.id;
          return (
            <button
              key={item.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setView(item.id)}
              className={`shrink-0 rounded-md border px-3 py-2 text-left transition-colors ${active ? "border-cyan-300/40 bg-cyan-300/10 text-cyan-100" : "border-transparent text-slate-400 hover:border-[#33405a] hover:bg-white/[0.03] hover:text-slate-200"}`}
            >
              <span className="block text-sm font-semibold">{item.label}</span>
              <span className="block font-mono text-[9px] uppercase tracking-[0.12em] opacity-70">{item.note}</span>
            </button>
          );
        })}
      </div>

      {error ? (
        <div role="alert" className="flex items-start justify-between gap-3 rounded-lg border border-rose-400/25 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">
          <span>{error}</span>
          <button type="button" onClick={() => setError("")} aria-label="Dismiss visibility error" className="text-rose-200 hover:text-white"><X className="h-4 w-4" /></button>
        </div>
      ) : null}

      {visibilityRecoveryVisible ? (
        <Card className="border-amber-300/25 bg-amber-300/[0.06]">
          <CardHeader className="gap-2 border-b border-amber-300/15 p-5">
            <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-amber-200">Owner or administrator action</p>
            <CardTitle className="text-lg">Enable demo visibility</CardTitle>
            <p className="text-sm leading-6 text-slate-300">Create a tenant-scoped, audited grant for aggregates, user metadata, and action details. This does not reveal raw prompt content or grant privacy, group, or policy management access.</p>
          </CardHeader>
          <CardContent className="space-y-3 p-5">
            <label className="block text-sm font-medium text-slate-200" htmlFor="visibility-recovery-reason">Audit reason</label>
            <textarea
              id="visibility-recovery-reason"
              value={visibilityReason}
              onChange={(event) => setVisibilityReason(event.target.value)}
              minLength={3}
              maxLength={1000}
              rows={3}
              placeholder="Why is this visibility needed for the current review?"
              className="w-full rounded-md border border-[#2a3348] bg-[#0d131d] px-3 py-2 text-sm text-slate-100 placeholder:text-slate-500 focus:border-cyan-300 focus:outline-none"
            />
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs text-slate-400">The reason is recorded in the tenant audit trail.</p>
              <Button type="button" onClick={() => void enableDemoVisibility()} disabled={loading === "visibility-grant" || !visibilityReasonIsValid}>
                {loading === "visibility-grant" ? "Enabling visibility…" : "Enable demo visibility"}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {view === "users" ? (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <CountTile label="Total known users" value={directorySummary?.known_user_count ?? "—"} note="Visible in your approved scope" />
            <CountTile label="Active with AI" value={directorySummary?.active_ai_user_count ?? "—"} note="Observed source activity" />
            <CountTile label="Personal AI accounts" value={directorySummary?.personal_account_user_count ?? "—"} note="Account classification where observed" />
            <CountTile label="Policy coverage needs review" value={directorySummary?.policy_gap_user_count ?? "Unknown"} note="No coverage gap is inferred without source evidence" />
          </div>
          <p className="text-xs text-slate-500">This directory lists named people from the existing User Registry. Service and workload identities remain in Agent Identity &amp; AI IAM until a source-backed identity-type projection is available.</p>
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(380px,0.76fr)]">
            <Card>
              <CardHeader className="gap-3 border-b border-[#263149] p-5">
                <div className="flex items-center justify-between gap-3"><div><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Directory</p><CardTitle className="mt-1 text-lg">People with observed AI activity</CardTitle></div><Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[10px] text-slate-300">{users?.total ?? "—"} scoped</Badge></div>
                <form onSubmit={submitUserSearch} className="flex gap-2"><Input value={userSearch} onChange={(event) => setUserSearch(event.target.value)} placeholder="Search name, email, or department" aria-label="Search users" /><Button type="submit" variant="outline" size="sm" disabled={loading === "users"}>Search</Button></form>
                <div className="grid gap-2 sm:grid-cols-2"><label className="text-xs text-slate-400">Sort users<select value={directorySort} onChange={(event) => { setDirectorySort(event.target.value as typeof directorySort); setDirectoryPage(1); }} className="mt-1 h-9 w-full rounded-md border border-[#2a3348] bg-[#0d131d] px-2 text-sm text-slate-100">{DIRECTORY_SORT_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select></label><label className="text-xs text-slate-400">Direction<select value={directorySortDirection} onChange={(event) => { setDirectorySortDirection(event.target.value as typeof directorySortDirection); setDirectoryPage(1); }} className="mt-1 h-9 w-full rounded-md border border-[#2a3348] bg-[#0d131d] px-2 text-sm text-slate-100"><option value="desc">Newest / highest first</option><option value="asc">Oldest / lowest first</option></select></label></div>
                <details className="rounded-md border border-[#263149] bg-[#0d131d] px-3 py-2"><summary className="cursor-pointer text-xs font-medium text-slate-300">Directory filters</summary><div className="mt-3 grid gap-2 sm:grid-cols-2">{DIRECTORY_FILTER_FIELDS.map((field) => <Input key={field.key} type={field.type || "text"} value={directoryFilters[field.key]} onChange={(event) => setDirectoryFilters((current) => ({ ...current, [field.key]: event.target.value }))} placeholder={field.label} aria-label={`Directory filter ${field.label}`} />)}</div><div className="mt-2 flex items-center justify-between gap-3"><p className="text-[11px] text-slate-500">Coverage and maturity stay unknown until source evidence exists; they are not treated as a filterable truth state.</p><Button type="button" variant="ghost" size="sm" onClick={() => { setDirectoryFilters(EMPTY_DIRECTORY_FILTERS); setAppliedDirectoryFilters(EMPTY_DIRECTORY_FILTERS); setDirectoryPage(1); }}>Reset</Button></div></details>
              </CardHeader>
              <CardContent className="p-0">
                {loading === "users" && !users ? <p className="p-5 text-sm text-slate-500">Loading scoped directory…</p> : null}
                {!loading && users?.items.length === 0 ? <p className="p-5 text-sm text-slate-500">No directory records match this scoped search.</p> : null}
                <div className="divide-y divide-[#202b3d]">{(users?.items || []).map((user) => <button key={user.user_id} type="button" onClick={() => void selectUser(user.user_id)} className="group flex w-full items-center gap-4 px-5 py-4 text-left hover:bg-cyan-300/[0.035]"><span className="grid h-9 w-9 shrink-0 place-items-center rounded-md border border-cyan-300/20 bg-cyan-300/10 font-semibold text-cyan-100">{(user.display_name || user.email || "?").slice(0, 1).toUpperCase()}</span><span className="min-w-0 flex-1"><span className="flex flex-wrap items-center gap-2"><span className="truncate font-medium text-slate-100">{user.display_name || user.email || "Unknown user"}</span><Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[9px] uppercase text-slate-400">{user.department || "No department"}</Badge></span><span className="mt-1 block truncate text-xs text-slate-500">{user.email || "No email"} · {user.role || "Unknown role"} · {user.ai_usage.action_count} actions</span><span className="mt-1 block truncate text-[11px] text-slate-600">{user.ai_usage.applications.join(", ") || "No observed application"} · {user.ai_usage.account_classes.join(", ") || "Unknown account class"}</span></span><ArrowRight className="h-4 w-4 shrink-0 text-slate-600 transition-transform group-hover:translate-x-0.5 group-hover:text-cyan-200" /></button>)}</div>
                <div className="flex items-center justify-between gap-3 border-t border-[#263149] px-5 py-3"><p className="text-xs text-slate-500">Page {users?.page ?? directoryPage} · {users?.total ?? 0} scoped user(s)</p><div className="flex gap-2"><Button type="button" variant="ghost" size="sm" disabled={directoryPage <= 1 || loading === "users"} onClick={() => setDirectoryPage((value) => Math.max(1, value - 1))}>Previous</Button><Button type="button" variant="ghost" size="sm" disabled={!users || directoryPage * (users.page_size || 25) >= users.total || loading === "users"} onClick={() => setDirectoryPage((value) => value + 1)}>Next</Button></div></div>
              </CardContent>
            </Card>

            <Card className="min-h-[500px]">
              <CardHeader className="border-b border-[#263149] p-5"><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">User 360</p><CardTitle className="mt-1 text-lg">{selectedOverview?.user.display_name || "Select a user"}</CardTitle><p className="text-sm text-slate-500">Tabs request only the selected safe source projection. Full prompt content remains outside this view.</p></CardHeader>
              <CardContent className="space-y-5 p-5">
                {!selectedUserId ? <div className="grid min-h-[270px] place-items-center rounded-lg border border-dashed border-[#33405a] p-8 text-center"><UsersRound className="h-7 w-7 text-cyan-300/70" /><p className="mt-3 text-sm text-slate-400">Choose a directory row to inspect its approved visibility scope.</p></div> : null}
                {selectedUserId && !selectedOverview && loading === "user-section" ? <p className="text-sm text-slate-500">Loading User 360 overview…</p> : null}
                {selectedUserId && selectedOverview ? <><DefinitionList values={[{ label: "Department", value: selectedOverview.user.department }, { label: "Role", value: selectedOverview.user.role }, { label: "Last AI activity", value: formatDate(selectedOverview.user.last_ai_activity) }, { label: "Groups", value: selectedOverview.group_refs.length }]} /><div className="flex gap-2 overflow-x-auto border-b border-[#263149] pb-2" role="tablist" aria-label="User 360 sections">{USER_360_TABS.map((tab) => <button key={tab.id} type="button" role="tab" aria-selected={selectedUserTab === tab.id} onClick={() => { setSelectedUserTab(tab.id); void loadUserSection(selectedUserId, tab.id); }} className={`shrink-0 rounded-md px-2.5 py-1.5 text-xs ${selectedUserTab === tab.id ? "bg-cyan-300/10 text-cyan-100" : "text-slate-400 hover:bg-white/[0.03] hover:text-slate-200"}`}>{tab.label}</button>)}</div><div aria-live="polite">{loading === "user-section" && !selectedSection ? <p className="text-sm text-slate-500">Loading {USER_360_TABS.find((tab) => tab.id === selectedUserTab)?.label}…</p> : null}{selectedSection ? <User360SectionContent section={selectedUserTab} data={selectedSection.data} onInspectAction={(action) => { setFollowLatestAction(false); setSelectedAction(action); setView("actions"); }} /> : null}</div><div className="flex flex-wrap gap-3 text-xs"><Link href="/policies" className="font-medium text-cyan-200 hover:text-cyan-100">Open Policies &amp; Policy Packs <ArrowRight className="inline h-3 w-3" /></Link><Link href="/validation/coverage" className="font-medium text-cyan-200 hover:text-cyan-100">Open Control Coverage <ArrowRight className="inline h-3 w-3" /></Link><Link href="/ai-ecosystem" className="font-medium text-cyan-200 hover:text-cyan-100">Open AI Ecosystem <ArrowRight className="inline h-3 w-3" /></Link></div></> : null}
              </CardContent>
            </Card>
          </div>
        </div>
      ) : null}

      {view === "departments" ? (
        <Card>
          <CardHeader className="border-b border-[#263149] p-5"><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Scoped aggregate</p><CardTitle className="mt-1">Departments</CardTitle></CardHeader>
          <CardContent className="p-0">
            {!departments && loading === "departments" ? <p className="p-5 text-sm text-slate-500">Loading department aggregates…</p> : null}
            <div className="grid gap-px bg-[#263149] md:grid-cols-2 xl:grid-cols-3">
              {(departments?.items || []).map((department) => <DepartmentCard key={department.department} department={department} />)}
            </div>
            {departments?.items.length === 0 ? <p className="p-5 text-sm text-slate-500">No department data is available in your current scope.</p> : null}
          </CardContent>
        </Card>
      ) : null}

      {view === "organization" ? (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-3">
            <CountTile label="Scoped users" value={organization?.user_count ?? "—"} note="Current approved visibility scope" />
            <CountTile label="Recorded actions" value={organization?.action_count ?? "—"} note={`${organization?.lookback_hours ?? 0}-hour window`} />
            <CountTile label="Evidence quality" value={humanize(organization?.evidence_quality, "Unknown evidence")} note="Missing evidence is not a healthy signal" />
          </div>
          <Card>
            <CardHeader className="border-b border-[#263149] p-5"><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Observed applications</p><CardTitle className="mt-1">Organization activity</CardTitle></CardHeader>
            <CardContent className="p-5">
              {loading === "organization" && !organization ? <p className="text-sm text-slate-500">Loading organization aggregate…</p> : null}
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{(organization?.applications || []).map((app) => <div key={app.name} className="rounded-lg border border-[#263149] bg-[#101622] p-4"><p className="truncate text-sm font-semibold text-slate-100">{app.name}</p><p className="mt-2 font-mono text-xl text-cyan-200">{app.count}</p><p className="text-xs text-slate-500">recorded actions</p></div>)}</div>
              {organization && organization.applications.length === 0 ? <p className="text-sm text-slate-500">No observed applications in this time window.</p> : null}
            </CardContent>
          </Card>
        </div>
      ) : null}

      {view === "actions" ? (
        <div className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-3">
            <CountTile label="Matched actions" value={actionSummary.total} note="Server-side, time-bounded query" />
            <CountTile label="Blocked" value={actionSummary.blocked} note="Only this result page" />
            <CountTile label="Unknown evidence" value={actionSummary.unknownEvidence} note="No assurance is inferred" />
          </div>
          <Card>
              <CardHeader className="border-b border-[#263149] p-5">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Consequence path</p>
                    <CardTitle className="mt-1">Action Explorer</CardTitle>
                    <p className="text-sm text-slate-500">Filter the canonical action projections. Live prompt projections refresh every second; prompt metadata never turns into a content search.</p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge className={followLatestAction ? "border-emerald-400/35 bg-emerald-400/10 text-emerald-200" : "border-amber-400/35 bg-amber-400/10 text-amber-200"}>{followLatestAction ? "Live-following newest" : "Pinned action"}</Badge>
                    <Button type="button" variant="ghost" size="sm" onClick={() => { setFollowLatestAction(true); if (actions?.items?.[0]) setSelectedAction(actions.items[0]); }}>
                      <RefreshCw className="mr-1 h-3 w-3" /> Follow latest
                    </Button>
                  </div>
                </div>
                <p className="mt-2 text-xs text-slate-500">{lastActionRefreshAt ? `Last refreshed ${formatDate(lastActionRefreshAt)}` : "Waiting for the first live refresh."}</p>
              </CardHeader>
            <CardContent className="p-5">
              <form onSubmit={submitActionFilters} className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                {Object.entries(filters).map(([key, value]) => <Input key={key} value={value} onChange={(event) => setFilters((current) => ({ ...current, [key]: event.target.value }))} placeholder={humanize(key)} aria-label={`Filter ${humanize(key)}`} />)}
                <div className="flex gap-2"><Button type="submit" variant="outline" size="sm" disabled={loading === "actions"}>Apply filters</Button><Button type="button" variant="ghost" size="sm" onClick={() => { setFilters(EMPTY_ACTION_FILTERS); setFollowLatestAction(true); void loadActions(EMPTY_ACTION_FILTERS); }}>Clear</Button></div>
              </form>
            </CardContent>
          </Card>
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(330px,0.62fr)]">
            <Card>
              <CardContent className="p-0">
                {loading === "actions" && !actions ? <p className="p-5 text-sm text-slate-500">Loading actions…</p> : null}
                <div className="divide-y divide-[#202b3d]">
                  {(actions?.items || []).map((action) => <ActionMini key={action.action_id} action={action} selected={selectedAction?.action_id === action.action_id} onInspect={() => { setFollowLatestAction(false); setSelectedAction(action); }} />)}
                </div>
                {actions?.items.length === 0 ? <p className="p-5 text-sm text-slate-500">No actions match these safe, server-side filters.</p> : null}
              </CardContent>
            </Card>
            <ActionDetail action={selectedAction} onReveal={() => selectedAction && openReveal(selectedAction)} />
          </div>
        </div>
      ) : null}

      {view === "groups" ? (
        <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_minmax(340px,0.65fr)]">
          <Card>
            <CardHeader className="border-b border-[#263149] p-5"><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Existing policy-pack groups</p><CardTitle className="mt-1">Groups and assignment context</CardTitle><p className="text-sm text-slate-500">SCIM and dynamic sources remain source-managed. Static membership changes are available only to authorized administrators through the existing Policy Pack model.</p></CardHeader>
            <CardContent className="p-0">
              {loading === "groups" && !groups ? <p className="p-5 text-sm text-slate-500">Loading scoped groups…</p> : null}
              <div className="divide-y divide-[#202b3d]">{(groups?.items || []).map((group) => <GroupRow key={group.group_id} group={group} onInspect={() => void selectGroup(group.group_id)} />)}</div>
              {groups?.items.length === 0 ? <p className="p-5 text-sm text-slate-500">No visible group records are available.</p> : null}
            </CardContent>
          </Card>
          <GroupDetail group={selectedGroup} loading={loading === "group-detail"} />
        </div>
      ) : null}

      {revealOpen && selectedAction ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-[#05070c]/80 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Privileged prompt reveal">
          <div className="w-full max-w-xl overflow-hidden rounded-xl border border-cyan-300/25 bg-[#101722] shadow-2xl">
            <div className="flex items-start justify-between border-b border-[#263149] p-5"><div><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Audited, one-time path</p><h3 className="mt-1 text-lg font-semibold text-slate-100">Request privileged content reveal</h3></div><Button type="button" variant="ghost" size="sm" onClick={closeReveal} aria-label="Close privileged prompt reveal"><X className="h-4 w-4" /></Button></div>
            <div className="space-y-4 p-5">
              <p className="text-sm leading-6 text-slate-400">Reveal redacted content is safe in the standard view. Retained source content requires the tenant retention setting, a visibility capability, a stated purpose, and a single-use five-minute grant.</p>
              <DefinitionList values={[{ label: "Action", value: selectedAction.action_id }, { label: "Content level", value: selectedAction.prompt_payload?.content_access_level }, { label: "Decision", value: selectedAction.decision }]} />
              {!revealedContent ? <>
                <label className="block text-sm font-medium text-slate-300">Purpose<select value={revealPurpose} onChange={(event) => setRevealPurpose(event.target.value as RevealPurpose)} className="mt-1 h-10 w-full rounded-md border border-[#2a3348] bg-[#0d131d] px-3 text-sm text-slate-100">{REVEAL_PURPOSES.map((purpose) => <option key={purpose.value} value={purpose.value}>{purpose.label}</option>)}</select></label>
                <label className="block text-sm font-medium text-slate-300">Reason<textarea value={revealReason} onChange={(event) => setRevealReason(event.target.value)} rows={3} maxLength={1000} className="mt-1 w-full resize-y rounded-md border border-[#2a3348] bg-[#0d131d] px-3 py-2 text-sm text-slate-100" placeholder="Case, audit, or incident reference" /></label>
                <Button type="button" onClick={() => void consumeReveal()} disabled={loading === "reveal"}><Eye className="mr-2 h-4 w-4" />{loading === "reveal" ? "Requesting…" : "Request audited reveal"}</Button>
              </> : <><div className="rounded-lg border border-amber-400/25 bg-amber-400/10 p-3 text-xs leading-5 text-amber-100">Displayed only in this open dialog after single-use grant consumption. It is not placed into search, export, or URL state.</div><pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-lg border border-[#263149] bg-[#090d14] p-4 text-sm leading-6 text-slate-100">{revealedContent}</pre><Button type="button" variant="outline" onClick={closeReveal}>Close and clear</Button></>}
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}

function ActionMini({ action, onInspect, selected = false }: { action: UserVisibilityAction; onInspect: () => void; selected?: boolean }) {
  const prompt = action.prompt_payload;
  const preview = prompt?.content_access_level === "REDACTED_PREVIEW" ? prompt.redacted_preview : "";
  return (
    <button type="button" onClick={onInspect} className={`w-full px-5 py-4 text-left transition-colors ${selected ? "bg-cyan-300/[0.07]" : "hover:bg-white/[0.025]"}`}>
      <div className="flex flex-wrap items-center justify-between gap-2"><span className="font-medium text-slate-100">{humanize(action.action_class, "Unknown action")}</span><Badge className={`rounded-sm border font-mono text-[9px] uppercase ${decisionTone(action.decision)}`}>{humanize(action.decision)}</Badge></div>
      {preview ? <p className="mt-2 line-clamp-2 rounded-md border border-sky-300/15 bg-sky-300/[0.06] px-2 py-1.5 text-xs leading-5 text-sky-100">Prompt: {preview}</p> : null}
      <p className="mt-1 truncate text-xs text-slate-400">{action.application || "Unknown application"} · {action.tool || "No tool"} · {action.destination || "No destination"}</p>
      <p className="mt-1 text-xs text-slate-600">{formatDate(action.timestamp)} · {action.action_id}</p>
    </button>
  );
}

function ActionDetail({ action, onReveal }: { action: UserVisibilityAction | null; onReveal: () => void }) {
  if (!action) return <Card className="min-h-[300px]"><CardContent className="grid min-h-[300px] place-items-center p-8 text-center"><ShieldCheck className="h-7 w-7 text-cyan-300/70" /><p className="mt-3 text-sm text-slate-400">Select an action to inspect the approved decision, execution, evidence, and prompt projection.</p></CardContent></Card>;
  const prompt = action.prompt_payload;
  return (
    <Card>
      <CardHeader className="border-b border-[#263149] p-5"><div className="flex flex-wrap items-center justify-between gap-2"><div><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Action detail</p><CardTitle className="mt-1 text-lg">{humanize(action.action_class)}</CardTitle></div><Badge className={`rounded-sm border font-mono text-[9px] uppercase ${decisionTone(action.decision)}`}>{humanize(action.decision)}</Badge></div></CardHeader>
      <CardContent className="space-y-5 p-5">
        <DefinitionList values={[
          { label: "Application", value: action.application }, { label: "Provider / model", value: [action.provider, action.model].filter(Boolean).join(" / ") },
          { label: "Agent / tool", value: [action.agent, action.tool].filter(Boolean).join(" / ") }, { label: "Destination", value: action.destination },
          { label: "Resource / target", value: [action.resource, action.target].filter(Boolean).join(" / ") }, { label: "Execution", value: action.execution_result },
          { label: "Approval", value: action.approval }, { label: "Control point", value: action.control_point },
        ]} />
        <div className="rounded-lg border border-[#263149] bg-[#0d131d] p-4"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-semibold text-slate-100">Prompt and request metadata</p><Badge className={`rounded-sm border font-mono text-[9px] uppercase ${contentTone(prompt?.content_access_level)}`}>{prompt?.content_access_level || "CONTENT_UNAVAILABLE"}</Badge></div><p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-400">{promptSummary(prompt)}</p><p className="mt-2 text-xs text-slate-500">Classification: {(prompt?.data_classifications || []).join(", ") || "Unknown"}</p>{prompt?.content_access_level === "REDACTED_PREVIEW" ? <Button type="button" variant="outline" size="sm" className="mt-3" onClick={onReveal}><Eye className="mr-2 h-3.5 w-3.5" />Request audited reveal</Button> : null}</div>
        <div className="rounded-lg border border-[#263149] p-4"><p className="text-sm font-semibold text-slate-100">Evidence and lineage</p><p className="mt-2 text-sm text-slate-400">Evidence quality: <span className="text-slate-200">{action.evidence_quality || "Unknown evidence"}</span> · Integrity: <span className="text-slate-200">{action.integrity || "Unknown"}</span> · Drift: <span className="text-slate-200">{action.drift || "Unknown"}</span></p><p className="mt-2 break-all font-mono text-[10px] leading-5 text-slate-500">Receipt {action.receipt_refs.evidence_node_id || "unavailable"} · Lineage {action.lineage_refs.correlation_id || "unavailable"}</p></div>
      </CardContent>
    </Card>
  );
}

function DepartmentCard({ department }: { department: UserVisibilityDepartment }) {
  return <div className="bg-[#13161f] p-5"><p className="text-sm font-semibold text-slate-100">{department.department}</p><div className="mt-4 flex gap-6"><span><strong className="block text-xl text-cyan-200">{department.user_count}</strong><span className="text-xs text-slate-500">users</span></span><span><strong className="block text-xl text-slate-100">{department.action_count}</strong><span className="text-xs text-slate-500">actions</span></span></div><p className="mt-3 text-xs text-slate-500">Last activity: {formatDate(department.last_ai_activity)}</p></div>;
}

function GroupRow({ group, onInspect }: { group: UserVisibilityGroup; onInspect: () => void }) {
  return <div className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-center sm:justify-between"><div><div className="flex flex-wrap items-center gap-2"><p className="font-medium text-slate-100">{group.name}</p><Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[9px] uppercase text-slate-400">{group.group_type}</Badge></div><p className="mt-1 text-xs text-slate-500">{group.member_count} visible members · {group.policy_pack_assignments.length} Policy Pack assignment(s) · {group.source_ref || "Source unavailable"}</p></div><div className="flex items-center gap-2"><Button type="button" variant="outline" size="sm" onClick={onInspect}>Inspect</Button><Link href="/policies" className="text-sm font-medium text-cyan-200 hover:text-cyan-100">Policy Packs <ArrowRight className="inline h-3.5 w-3.5" /></Link></div></div>;
}

function GroupDetail({ group, loading }: { group: UserVisibilityGroupDetail | null; loading: boolean }) {
  if (!group) return <Card className="min-h-[300px]"><CardContent className="grid min-h-[300px] place-items-center p-8 text-center"><UsersRound className="h-7 w-7 text-cyan-300/70" /><p className="mt-3 text-sm text-slate-400">{loading ? "Loading group detail…" : "Inspect a group to view its current members, source, rule, assignments, and audit history."}</p></CardContent></Card>;
  const memberPreview = group.member_ids.slice(0, 20);
  return <Card>
    <CardHeader className="border-b border-[#263149] p-5"><p className="font-mono text-[10px] uppercase tracking-[0.15em] text-cyan-200">Group detail</p><CardTitle className="mt-1 text-lg">{group.name}</CardTitle><p className="text-sm text-slate-500">{group.group_type} · {group.source_ref || "Source unavailable"}</p></CardHeader>
    <CardContent className="space-y-5 p-5">
      <div><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">Current members</p><p className="mt-2 break-all text-sm text-slate-200">{memberPreview.join(", ") || "No visible members"}</p><p className="mt-1 text-xs text-slate-500">{group.member_count} visible member(s); page {group.member_page} is intentionally bounded.</p></div>
      <div><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">Membership rules</p><pre className="mt-2 max-h-28 overflow-auto rounded-md border border-[#263149] bg-[#0d131d] p-3 text-xs text-slate-400">{JSON.stringify(group.membership_rule, null, 2)}</pre></div>
      <div><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">Nested groups</p><p className="mt-2 break-all text-sm text-slate-200">{group.nested_group_ids.join(", ") || "No nested groups"}</p></div>
      <div><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">Policy Packs</p><p className="mt-2 text-sm text-slate-200">{group.policy_pack_assignments.map((assignment) => assignment.assignment_key).join(", ") || "No active assignment references"}</p></div>
      <div><p className="font-mono text-[10px] uppercase tracking-[0.14em] text-slate-500">Audit history</p><div className="mt-2 space-y-2">{group.audit_refs.length ? group.audit_refs.map((audit) => <div key={audit.audit_log_id} className="rounded-md border border-[#263149] bg-[#0d131d] p-3"><p className="text-xs text-slate-200">{humanize(audit.action)}</p><p className="mt-1 text-[10px] text-slate-500">{formatDate(audit.created_at)} · actor {audit.actor_user_id || "unavailable"}</p></div>) : <p className="text-sm text-slate-500">No audit references are available for this group.</p>}</div></div>
    </CardContent>
  </Card>;
}
