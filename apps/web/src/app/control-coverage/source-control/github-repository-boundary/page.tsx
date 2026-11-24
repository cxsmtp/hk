"use client";

import Link from "next/link";
import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  AlertTriangle,
  ArrowRight,
  Check,
  Eye,
  GitBranch,
  Github,
  KeyRound,
  LockKeyhole,
  RefreshCw,
  Search,
  UsersRound,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type {
  EnterpriseDeveloperAIControl,
  GitHubRepositoryDetail,
  GitHubRepositoryInventoryPage,
  GitHubRepositoryProjection,
  GitHubRepositoryRuntimeBinding,
  GitHubPersonalRepositoryDenyPosture,
  HMAIRSourceConnection,
  HMAIRSourceConnectionInput,
} from "@/lib/types";

const statusClass: Record<string, string> = {
  APPROVED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  CONFIRMED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  VERIFIED: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  READY: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  COVERED_CURRENT: "border-emerald-400/30 bg-emerald-400/10 text-emerald-100",
  PARTIAL: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  PARTIALLY_COVERED: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  STALE: "border-amber-400/30 bg-amber-400/10 text-amber-100",
  OBSERVED: "border-cyan-400/30 bg-cyan-400/10 text-cyan-100",
  CONNECTED_UNVERIFIED: "border-cyan-400/30 bg-cyan-400/10 text-cyan-100",
  CONFIGURED_UNVALIDATED: "border-blue-400/30 bg-blue-400/10 text-blue-100",
  UNKNOWN: "border-slate-400/30 bg-slate-400/10 text-slate-100",
  UNVERIFIED: "border-slate-400/30 bg-slate-400/10 text-slate-100",
  DISCONNECTED: "border-slate-400/30 bg-slate-400/10 text-slate-200",
  UNSUPPORTED: "border-red-400/30 bg-red-400/10 text-red-100",
  REGRESSED: "border-red-400/30 bg-red-400/10 text-red-100",
  BLOCK: "border-red-400/30 bg-red-400/10 text-red-100",
};

const AI_TOOLS = [
  ["codex", "Codex"],
  ["claude", "Claude"],
  ["cursor", "Cursor"],
  ["gemini", "Gemini"],
  ["chatgpt", "ChatGPT / OpenAI agents"],
  ["github_copilot", "GitHub Copilot"],
  ["other_ai_agent", "Other AI agent"],
] as const;

const REPOSITORY_ACTIONS = [
  ["REPOSITORY_READ", "Read"],
  ["REPOSITORY_PULL", "Pull"],
  ["REPOSITORY_BRANCH_CREATE", "Branch"],
  ["REPOSITORY_FILE_WRITE", "Write file"],
  ["REPOSITORY_PULL_REQUEST_CREATE", "Create PR"],
  ["REPOSITORY_PUSH", "Push"],
  ["REPOSITORY_MERGE", "Merge"],
  ["REPOSITORY_PULL_REQUEST_APPROVE", "Approve PR"],
] as const;

const granularRepositoryActions = REPOSITORY_ACTIONS.map(([value, label]) => ({
  value,
  label,
  risk: value === "REPOSITORY_READ" ? "read-only" : value === "REPOSITORY_MERGE" || value === "REPOSITORY_PULL_REQUEST_APPROVE" ? "high-impact" : "change",
}));

const DEPLOYMENT_SURFACES = [
  ["runtime", "MCP gateway / runtime"],
  ["endpoint", "Endpoint CLI / IDE"],
  ["browser", "Browser / web"],
  ["saas_api", "Provider-native SaaS/API"],
] as const;

type RepositoryInventoryMode = "organizations" | "repositories" | "developers" | "ai-connections";
type GitHubAccountScopeKind = "ORGANIZATION" | "PERSONAL";

function StateBadge({ value }: { value?: string | number | null }) {
  const text = String(value ?? "UNKNOWN").toUpperCase();
  return (
    <Badge className={statusClass[text] || "border-white/10 bg-white/5 text-slate-200"}>
      {text.replaceAll("_", " ")}
    </Badge>
  );
}

function MetricCard({ label, value, hint }: { label: string; value: unknown; hint: string }) {
  return (
    <Card className="border-white/10 bg-[#101721]/80">
      <CardContent className="p-4">
        <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</p>
        <p className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-white">{String(value ?? "—")}</p>
        <p className="mt-1 text-xs leading-5 text-slate-500">{hint}</p>
      </CardContent>
    </Card>
  );
}

function ChoiceChip({ checked, label, onChange }: { checked: boolean; label: string; onChange: () => void }) {
  return (
    <button
      type="button"
      aria-pressed={checked}
      onClick={onChange}
      className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-left text-xs transition ${checked ? "border-orange-300/40 bg-orange-400/10 text-orange-100" : "border-white/10 bg-white/[0.025] text-slate-300 hover:border-white/20"}`}
    >
      <span className={`grid h-4 w-4 place-items-center rounded border ${checked ? "border-orange-300 bg-orange-400 text-black" : "border-slate-600"}`}>
        {checked ? <Check className="h-3 w-3" aria-hidden="true" /> : null}
      </span>
      {label}
    </button>
  );
}

function detailValue(value: unknown): string {
  return value === null || value === undefined || value === "" ? "Unknown" : String(value);
}

function inventoryAccountScope(row: Record<string, unknown>): string {
  if (typeof row.account_scope_kind === "string") return row.account_scope_kind;
  const capabilities = row.capabilities;
  if (capabilities && typeof capabilities === "object" && "account_scope_kind" in capabilities) {
    const scope = (capabilities as Record<string, unknown>).account_scope_kind;
    if (typeof scope === "string") return scope;
  }
  return "UNKNOWN";
}

function friendlyConnectionState(connection: HMAIRSourceConnection | null): string {
  if (!connection) return "Not connected";
  if (connection.capability.state === "ready") return "Connected and ready";
  if (connection.capability.state === "partial") return "Connected with gaps";
  if (connection.capability.state === "permission_denied") return "Permissions required";
  if (connection.capability.state === "failed") return "Connection needs attention";
  return "Connected, validation required";
}

function toggleChoice(current: string[], value: string): string[] {
  return current.includes(value) ? current.filter((item) => item !== value) : [...current, value];
}

export default function GitHubRepositoryBoundaryPage() {
  const [data, setData] = useState<EnterpriseDeveloperAIControl | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [sourceConnections, setSourceConnections] = useState<HMAIRSourceConnection[]>([]);
  const [sourceConnection, setSourceConnection] = useState<HMAIRSourceConnection | null>(null);
  const [connectionLoading, setConnectionLoading] = useState(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [connectionFormOpen, setConnectionFormOpen] = useState(false);
  const [connectionWorking, setConnectionWorking] = useState(false);
  const [accountScopeKind, setAccountScopeKind] = useState<GitHubAccountScopeKind>("ORGANIZATION");
  const [accountLogin, setAccountLogin] = useState("");
  const [appId, setAppId] = useState("");
  const [installationId, setInstallationId] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [repositoryInventoryMode, setRepositoryInventoryMode] = useState<RepositoryInventoryMode>("repositories");
  const [inventoryRows, setInventoryRows] = useState<Array<Record<string, unknown>>>([]);
  const [inventoryCursor, setInventoryCursor] = useState<string | null>(null);
  const [inventoryError, setInventoryError] = useState<string | null>(null);
  const [inventoryLoading, setInventoryLoading] = useState(false);
  const [inventoryFilter, setInventoryFilter] = useState("");
  const [selectedRepository, setSelectedRepository] = useState<GitHubRepositoryProjection | null>(null);
  const [selectedAITools, setSelectedAITools] = useState<string[]>(["codex", "claude"]);
  const [selectedOperations, setSelectedOperations] = useState<string[]>(["REPOSITORY_READ"]);
  const [operationControls, setOperationControls] = useState<Record<"READ" | "EDIT" | "COMMIT" | "PULL" | "PUSH", "ALLOW" | "BLOCK">>({ READ: "BLOCK", EDIT: "BLOCK", COMMIT: "BLOCK", PULL: "BLOCK", PUSH: "BLOCK" });
  const [operationControlsWorking, setOperationControlsWorking] = useState(false);
  const [runtimeControlDetail, setRuntimeControlDetail] = useState<GitHubRepositoryDetail | null>(null);
  const [runtimeObservations, setRuntimeObservations] = useState<GitHubRepositoryRuntimeBinding[]>([]);
  const [runtimeIntegrationLabels, setRuntimeIntegrationLabels] = useState<Record<string, string>>({});
  const [selectedRuntimeObservation, setSelectedRuntimeObservation] = useState("");
  const [runtimeBindingsLoading, setRuntimeBindingsLoading] = useState(false);
  const [runtimeBindingWorking, setRuntimeBindingWorking] = useState(false);
  const [runtimeBindingError, setRuntimeBindingError] = useState<string | null>(null);
  const runtimeRequestSequence = useRef(0);
  const [selectedSurfaces, setSelectedSurfaces] = useState<string[]>(["runtime", "endpoint"]);
  const [people, setPeople] = useState("");
  const [groups, setGroups] = useState("");
  const [personalRepositoryDenyPosture, setPersonalRepositoryDenyPosture] = useState<GitHubPersonalRepositoryDenyPosture>("BLOCK_ALL");
  const [personalProtectionWorking, setPersonalProtectionWorking] = useState(false);
  const [repositoryDetail, setRepositoryDetail] = useState<GitHubRepositoryDetail | null>(null);
  const [repositoryDetailLoading, setRepositoryDetailLoading] = useState(false);
  const [repositoryDetailError, setRepositoryDetailError] = useState<string | null>(null);
  const repositoryDetailCloseRef = useRef<HTMLButtonElement | null>(null);
  const repositoryDetailReturnFocusRef = useRef<HTMLElement | null>(null);

  const refreshSummary = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.enterpriseDeveloperAIControl());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not load GitHub controls.");
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshConnection = useCallback(async () => {
    setConnectionLoading(true);
    try {
      const response = await api.githubSourceConnections();
      setConnectionError(null);
      const githubConnections = response.items.filter((item) => item.provider_key === "hmair_github_cloud" || item.provider_key === "hmair_github_ghes");
      setSourceConnections(githubConnections);
      setSourceConnection((current) => githubConnections.find((item) => item.connection_id === current?.connection_id) || githubConnections[0] || null);
    } catch {
      setConnectionError("GitHub connection status is unavailable. Retry to check connected accounts.");
    } finally {
      setConnectionLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshSummary();
    void refreshConnection();
  }, [refreshConnection, refreshSummary]);

  useEffect(() => {
    if (selectedRepository?.operation_controls) setOperationControls(selectedRepository.operation_controls);
  }, [selectedRepository]);

  const loadRepositoryInventory = useCallback(async (append = false, requestedCursor?: string | null) => {
    setInventoryLoading(true);
    setInventoryError(null);
    try {
      const cursor = requestedCursor ?? (append ? inventoryCursor : null);
      const request = repositoryInventoryMode === "organizations"
        ? api.githubRepositoryOrganizations(50, cursor || undefined)
        : repositoryInventoryMode === "repositories"
          ? api.githubRepositories(50, cursor || undefined)
          : repositoryInventoryMode === "developers"
            ? api.githubRepositoryDevelopers(50, cursor || undefined)
            : api.githubRepositoryAIConnections(50, cursor || undefined);
      const page = await request as GitHubRepositoryInventoryPage;
      setInventoryRows((current) => append ? [...current, ...page.items] : page.items);
      setInventoryCursor(page.next_cursor);
    } catch (err) {
      setInventoryError(err instanceof Error ? err.message : "Could not load this inventory mode");
      if (!append) setInventoryRows([]);
    } finally {
      setInventoryLoading(false);
    }
  }, [inventoryCursor, repositoryInventoryMode]);

  useEffect(() => {
    void loadRepositoryInventory(false, null);
  }, [loadRepositoryInventory]);

  const closeRepositoryDetail = useCallback(() => {
    setRepositoryDetail(null);
    setRepositoryDetailError(null);
    repositoryDetailReturnFocusRef.current?.focus();
  }, []);

  const loadRepositoryDetail = async (repositoryId: string, selectForPolicy = false) => {
    repositoryDetailReturnFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    setRepositoryDetailLoading(true);
    setRepositoryDetailError(null);
    setRepositoryDetail(null);
    try {
      const detail = await api.githubRepositoryDetail(repositoryId);
      setRepositoryDetail(detail);
      if (selectForPolicy) {
        setSelectedRepository(detail.repository);
        if (detail.repository.deny_posture) setPersonalRepositoryDenyPosture(detail.repository.deny_posture);
      }
    } catch (err) {
      setRepositoryDetailError(err instanceof Error ? err.message : "Could not load repository detail");
    } finally {
      setRepositoryDetailLoading(false);
    }
  };

  useEffect(() => {
    if (!repositoryDetail && !repositoryDetailError) return;
    repositoryDetailCloseRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeRepositoryDetail();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [closeRepositoryDetail, repositoryDetail, repositoryDetailError]);

  async function connectGitHub(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (![accountLogin, appId, installationId, privateKey, authorizationReference].every((value) => value.trim())) {
      toast.error("Complete every GitHub App connection field.");
      return;
    }
    setConnectionWorking(true);
    const input: HMAIRSourceConnectionInput = {
      provider_key: "hmair_github_cloud",
      display_name: `${accountLogin.trim()}-github-inventory`,
      target_identifier: accountLogin.trim(),
      environment: "production",
      authorization_reference: authorizationReference.trim(),
      requested_capabilities: ["repository_inventory"],
      include_entra_account_evidence: false,
      metadata: {
        account_scope_kind: accountScopeKind,
        account_login: accountLogin.trim(),
        selected_repository_scope: "SELECTED",
        ...(accountScopeKind === "ORGANIZATION" ? { organization_login: accountLogin.trim() } : {}),
      },
      credentials: {
        app_id: appId.trim(),
        installation_id: installationId.trim(),
        private_key_pem: privateKey.trim(),
      },
    };
    try {
      const created = await api.createGitHubSourceConnection(input);
      setPrivateKey("");
      setSourceConnection(created);
      setSourceConnections((current) => [created, ...current.filter((item) => item.connection_id !== created.connection_id)]);
      setConnectionFormOpen(false);
      toast.success("GitHub connection saved. Validating its granted scope now.");
      try {
        const validated = await api.validateGitHubSourceConnection(created.connection_id);
        setSourceConnection(validated);
        setSourceConnections((current) => current.map((item) => item.connection_id === validated.connection_id ? validated : item));
        toast.success("GitHub connection validation completed.");
      } catch (validationError) {
        toast.error(validationError instanceof Error ? validationError.message : "The connection was saved but could not be validated.");
      }
      await refreshSummary();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "GitHub connection could not be saved.");
    } finally {
      setConnectionWorking(false);
    }
  }

  async function validateConnection() {
    if (!sourceConnection) return;
    setConnectionWorking(true);
    try {
      const validated = await api.validateGitHubSourceConnection(sourceConnection.connection_id);
      setSourceConnection(validated);
      setSourceConnections((current) => current.map((item) => item.connection_id === validated.connection_id ? validated : item));
      toast.success("GitHub permissions and source scope were checked.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "GitHub connection validation failed.");
    } finally {
      setConnectionWorking(false);
    }
  }

  async function applyPersonalProtection() {
    if (!selectedRepository || selectedRepository.account_scope_kind !== "PERSONAL") return;
    setPersonalProtectionWorking(true);
    try {
      const updated = await api.updateGitHubRepositoryGovernance(selectedRepository.id, {
        decision: "UNAPPROVED",
        expected_governance_version: selectedRepository.governance_version,
        assignment_id: null,
        deny_posture: personalRepositoryDenyPosture,
      });
      setSelectedRepository(updated);
      setRepositoryDetail((current) => current && current.repository.id === updated.id ? { ...current, repository: updated } : current);
      setInventoryRows((current) => current.map((row) => row.id === updated.id ? updated : row));
      toast.success(personalRepositoryDenyPosture === "BLOCK_ALL" ? "All governed AI access is blocked for this personal repository." : "Repository changes are blocked; governed reads remain available.");
      await refreshSummary();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Personal repository protection could not be applied.");
    } finally {
      setPersonalProtectionWorking(false);
    }
  }

  const localRepositoryControlsReady = Boolean(
    selectedRepository && runtimeControlDetail && !runtimeBindingsLoading && !runtimeBindingWorking &&
    runtimeControlDetail.repository.id === selectedRepository.id &&
    runtimeControlDetail.repository.governance_version === selectedRepository.governance_version &&
    runtimeControlDetail.repository.evidence_state === "CONFIRMED" &&
    runtimeControlDetail.repository.visibility === "PRIVATE" &&
    runtimeControlDetail.repository.lifecycle_state === "ACTIVE" &&
    runtimeControlDetail.repository.governance_state === "APPROVED" &&
    runtimeControlDetail.repository.policy_current &&
    runtimeControlDetail.runtime_bindings.items.some((row) => row.repository_id === selectedRepository.id && row.scope === "EXACT_FOLDER" && row.state === "ACTIVE")
  );
  const localRepositoryGovernanceReady = Boolean(
    selectedRepository && runtimeControlDetail && !runtimeBindingsLoading && !runtimeBindingWorking &&
    runtimeControlDetail.repository.id === selectedRepository.id &&
    runtimeControlDetail.repository.governance_version === selectedRepository.governance_version &&
    runtimeControlDetail.repository.evidence_state === "CONFIRMED" &&
    runtimeControlDetail.repository.visibility === "PRIVATE" &&
    runtimeControlDetail.repository.lifecycle_state === "ACTIVE" &&
    runtimeControlDetail.repository.governance_state === "APPROVED" && runtimeControlDetail.repository.policy_current
  );
  const eligibleRuntimeObservations = runtimeObservations.filter((row) => row.state === "OBSERVED" && row.scope === "EXACT_FOLDER" && row.repository_id === null);

  const refreshRuntimeControls = useCallback(async (repositoryId: string) => {
    const sequence = ++runtimeRequestSequence.current;
    setRuntimeBindingsLoading(true);
    setRuntimeBindingError(null);
    try {
      const [detail, observations, points] = await Promise.all([
        api.githubRepositoryDetail(repositoryId), api.githubRepositoryRuntimeBindings(), api.nativeControlPoints(),
      ]);
      if (sequence !== runtimeRequestSequence.current) return;
      setRuntimeControlDetail(detail);
      setRuntimeObservations(observations.items);
      setRuntimeIntegrationLabels(Object.fromEntries(points.items.map((point) => [point.id, point.display_name])));
      setSelectedRuntimeObservation("");
      setOperationControls(detail.repository.operation_controls);
      setSelectedRepository((current) => current?.id === repositoryId ? detail.repository : current);
      setRepositoryDetail((current) => current?.repository.id === repositoryId ? detail : current);
    } catch (err) {
      if (sequence !== runtimeRequestSequence.current) return;
      setRuntimeControlDetail(null);
      setRuntimeObservations([]);
      setRuntimeBindingError(err instanceof Error ? err.message : "Signed workspaces could not be loaded.");
    } finally {
      if (sequence === runtimeRequestSequence.current) setRuntimeBindingsLoading(false);
    }
  }, []);

  useEffect(() => {
    setRuntimeControlDetail(null);
    setRuntimeObservations([]);
    setSelectedRuntimeObservation("");
    if (selectedRepository?.id) void refreshRuntimeControls(selectedRepository.id);
    return () => { runtimeRequestSequence.current += 1; };
  }, [selectedRepository?.id, refreshRuntimeControls]);

  async function bindRuntimeObservation() {
    if (!selectedRepository || !runtimeControlDetail || !localRepositoryGovernanceReady ||
        !eligibleRuntimeObservations.some((row) => row.id === selectedRuntimeObservation)) return;
    setRuntimeBindingWorking(true);
    setRuntimeBindingError(null);
    try {
      await api.bindGitHubRepositoryRuntime(selectedRepository.id, { observation_id: selectedRuntimeObservation, expected_governance_version: runtimeControlDetail.repository.governance_version });
      await refreshRuntimeControls(selectedRepository.id);
      toast.success("Signed workspace bound to this repository.");
    } catch (err) {
      await refreshRuntimeControls(selectedRepository.id);
      setRuntimeBindingError(err instanceof Error ? err.message : "Workspace binding could not be saved.");
    } finally {
      setRuntimeBindingWorking(false);
    }
  }

  async function saveOperationControls() {
    if (!selectedRepository || !localRepositoryControlsReady) return;
    setOperationControlsWorking(true);
    try {
      const updated = await api.updateGitHubRepositoryOperationControls(selectedRepository.id, { controls: operationControls, expected_governance_version: selectedRepository.governance_version });
      setSelectedRepository(updated);
      setInventoryRows((current) => current.map((row) => row.id === updated.id ? updated : row));
      setRepositoryDetail((current) => current && current.repository.id === updated.id ? { ...current, repository: updated } : current);
      await refreshRuntimeControls(selectedRepository.id);
      toast.success("Local repository controls saved.");
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Repository controls could not be saved.");
    } finally {
      setOperationControlsWorking(false);
    }
  }

  const repositoryInventory = data?.repository_inventory ?? {
    organizations: 0,
    repositories: 0,
    access_relations: 0,
    direct_access: 0,
    team_inherited_access: 0,
    unknown_access: 0,
    ai_connections: 0,
    authoritative_denominator_available: false,
    blind_spots: ["No completed GitHub inventory receipt is available for this tenant."],
  };
  const developerAISetup = data?.developer_ai_setup;
  const projectedAIClients = developerAISetup?.ai_clients ?? [];
  const displayedInventoryRows = inventoryRows.filter((row) => JSON.stringify(row).toLowerCase().includes(inventoryFilter.trim().toLowerCase()));
  const policyRolloutHref = useMemo(() => {
    if (!selectedRepository) return "/policies#policy-packs";
    const parameters = {
      approved_repositories: [selectedRepository.full_name],
      repository_account_class: selectedRepository.account_scope_kind.toLowerCase(),
      personal_repository_deny_posture: selectedRepository.account_scope_kind === "PERSONAL" ? personalRepositoryDenyPosture : null,
      approved_ai_tools: selectedAITools,
      allowed_repository_actions: selectedOperations,
      resource_classes: ["github_repository"],
    };
    const query = new URLSearchParams({
      source: "github-repository-control",
      application: selectedAITools.join(","),
      surface: selectedSurfaces.join(","),
      user: people,
      group: groups,
      parameters: JSON.stringify(parameters),
    });
    return `/policies?${query.toString()}#policy-packs`;
  }, [groups, people, personalRepositoryDenyPosture, selectedAITools, selectedOperations, selectedRepository, selectedSurfaces]);

  const runtimeCoverage = data?.control_coverage.find((item) => item.capability.includes("Runtime/MCP"))?.state || "UNKNOWN";
  const endpointCoverage = data?.control_coverage.find((item) => item.capability.includes("Endpoint Git"))?.state || "UNKNOWN";
  const browserCoverage = data?.control_coverage.find((item) => item.capability.includes("Browser/web"))?.state || "UNKNOWN";
  const sourceReady = sourceConnection?.capability.state === "ready" || sourceConnection?.capability.state === "partial";
  const selectedRepositoryName = selectedRepository?.full_name || "<owner>/<selected-repository>";
  const blockedRepositoryName = "<owner>/<other-repository>";
  const repositoryPathStatus = sourceReady && selectedRepository ? "UNKNOWN" : "NOT_VERIFIED";
  const repositoryDetailMatchesSelection = Boolean(
    repositoryDetail && selectedRepository && repositoryDetail.repository.id === selectedRepository.id,
  );
  const selectedHumanAccessRows = repositoryDetailMatchesSelection && repositoryDetail ? repositoryDetail.access_relationships.items : [];
  const selectedAIAccessRows = repositoryDetailMatchesSelection && repositoryDetail ? repositoryDetail.ai_connections.items : [];
  const selectedActionControls = granularRepositoryActions.map((action) => ({
    ...action,
    selected: selectedOperations.includes(action.value),
    decision: selectedOperations.includes(action.value) ? "Allow after approval" : "Not allowed by this draft",
  }));
  const humanAndAIRepoGraphRows = [
    ...selectedHumanAccessRows.map((row) => ({
      actor: detailValue(row.mapped_user_id || row.external_principal_id),
      actorType: detailValue(row.principal_type),
      relationship: `${detailValue(row.access_path)} · ${detailValue(row.permission)}`,
      evidence: detailValue(row.evidence_state),
    })),
    ...selectedAIAccessRows.map((row) => ({
      actor: detailValue(row.client_name || row.ai_system_id),
      actorType: "AI",
      relationship: `${detailValue(row.provider)} · ${detailValue(row.model)} · ${detailValue(row.tool_name)}`,
      evidence: detailValue(row.confidence),
    })),
  ];
  const clientControlRows = [
    ["Claude Code", "Use in Claude Code", repositoryPathStatus, "A governed MCP route can enforce a repository policy after approval and validation."],
    ["Codex Desktop", "Use in Codex Desktop", repositoryPathStatus, "Repository protection requires an approved policy and a validated governed route."],
    ["Codex CLI", "Use in Codex CLI", repositoryPathStatus, "CLI requests need a configured governed MCP route."],
    ["CLI / IDE", "Use from CLI / IDE", repositoryPathStatus, "Local Git controls require an enrolled managed device and an approved policy."],
  ] as const;
  const observedAICalls = projectedAIClients;
  const canReviewControls = Boolean(selectedRepository && selectedAITools.length && selectedOperations.length && selectedSurfaces.length);

  return (
    <AppShell>
      <div className="min-h-screen bg-[#090d13] text-slate-100">
        <section className="border-b border-white/10 bg-[radial-gradient(circle_at_top_left,rgba(251,146,60,0.14),transparent_34%),linear-gradient(135deg,#0d1118,#101827_60%,#080b10)] px-6 py-8 lg:px-8">
          <div className="mx-auto max-w-[1180px]">
            <p className="text-[11px] font-semibold uppercase tracking-[0.22em] text-orange-300">GitHub controls</p>
            <h1 className="mt-2 text-3xl font-semibold tracking-tight text-white">GitHub access &amp; AI controls</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-300">Connect GitHub, choose a repository, and prepare who and what can access it. Review and approval happen before controls become active.</p>
            <div className="mt-4 flex flex-wrap gap-2 text-xs text-slate-400"><span className="rounded-full border border-white/10 px-3 py-1">1 Connect</span><span className="rounded-full border border-white/10 px-3 py-1">2 Repositories</span><span className="rounded-full border border-white/10 px-3 py-1">3 Controls</span><span className="rounded-full border border-white/10 px-3 py-1">4 Activity</span></div>
          </div>
        </section>
        <section className="mx-auto max-w-[1180px] space-y-5 px-6 py-6 lg:px-8">
          <Card className="overflow-hidden border-white/10 bg-[#101721]/80">
            <CardHeader className="border-b border-white/10 bg-[linear-gradient(120deg,rgba(56,189,248,0.08),transparent_55%)]">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <CardTitle className="flex items-center gap-2 text-white"><Github className="h-5 w-5 text-cyan-300" /> Connect GitHub</CardTitle>
                  <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Add a GitHub App installed on the repositories you choose. This connection reads inventory metadata; it does not copy repository contents.</p>
                </div>
                <div className="flex items-center gap-2">
                  <StateBadge value={connectionError ? "UNKNOWN" : sourceConnection?.capability.state || "DISCONNECTED"} />
                  <Button type="button" onClick={() => setConnectionFormOpen((open) => !open)} className="bg-cyan-300 text-slate-950 hover:bg-cyan-200">{sourceConnections.length ? "Add GitHub account" : "Connect GitHub"}</Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4 p-5">
              {connectionError ? <p role="alert" className="rounded-xl border border-amber-300/20 bg-amber-300/[0.06] p-3 text-sm text-amber-100">{connectionError} <Button type="button" variant="outline" size="sm" onClick={() => void refreshConnection()}>Retry</Button></p> : null}
              {connectionLoading ? <p className="text-sm text-slate-400">Checking GitHub connections…</p> : null}
              {sourceConnections.length ? <div className="space-y-2"><p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-500">GitHub accounts</p>{sourceConnections.map((connection) => <button key={connection.connection_id} type="button" onClick={() => setSourceConnection(connection)} className={`flex w-full flex-wrap items-center justify-between gap-3 rounded-xl border p-4 text-left ${sourceConnection?.connection_id === connection.connection_id ? "border-cyan-300/35 bg-cyan-300/[0.05]" : "border-white/10 bg-white/[0.025]"}`}><span><span className="flex items-center gap-2 font-medium text-white">{connection.display_name}<StateBadge value={connection.account_scope_kind} /></span><span className="mt-1 block text-xs text-slate-500">{connection.target.target_type.replaceAll("_", " ")} · {connection.collector.health.replaceAll("_", " ")} · {connection.capability.allowed_capabilities.length} validated capabilities</span></span><StateBadge value={connection.capability.state} /></button>)}</div> : null}
              {sourceConnection ? <div className="flex flex-wrap justify-end gap-2"><Button type="button" variant="outline" disabled={connectionWorking} onClick={() => void validateConnection()}><RefreshCw className="mr-2 h-4 w-4" />Validate selected account</Button><Button asChild variant="outline"><Link href="/discovery/scans">Run inventory scan</Link></Button></div> : null}

              {connectionFormOpen ? (
                <form onSubmit={connectGitHub} className="grid gap-4 rounded-2xl border border-cyan-300/20 bg-cyan-300/[0.035] p-5">
                  <div className="flex items-start gap-3"><KeyRound className="mt-0.5 h-5 w-5 text-cyan-300" /><div><p className="font-medium text-white">GitHub App connection</p><p className="mt-1 text-xs leading-5 text-slate-400">Install the app on selected repositories in the account you control. Organization accounts may provide member and team evidence; personal accounts never imply organization membership. The private key is write-only and is never returned to the browser.</p></div></div>
                  <fieldset><legend className="mb-2 text-xs font-medium text-slate-300">Account type</legend><div className="grid gap-2 sm:grid-cols-2"><button type="button" aria-pressed={accountScopeKind === "ORGANIZATION"} onClick={() => setAccountScopeKind("ORGANIZATION")} className={`rounded-xl border p-3 text-left ${accountScopeKind === "ORGANIZATION" ? "border-cyan-300/40 bg-cyan-300/10" : "border-white/10"}`}><span className="block text-sm font-medium text-white">Organization account</span><span className="mt-1 block text-xs text-slate-500">Inventory selected company repositories and permitted member/team access.</span></button><button type="button" aria-pressed={accountScopeKind === "PERSONAL"} onClick={() => setAccountScopeKind("PERSONAL")} className={`rounded-xl border p-3 text-left ${accountScopeKind === "PERSONAL" ? "border-orange-300/40 bg-orange-300/10" : "border-white/10"}`}><span className="block text-sm font-medium text-white">Personal account</span><span className="mt-1 block text-xs text-slate-500">Inventory selected test repositories and keep them unapproved by default.</span></button></div></fieldset>
                  <div className="grid gap-3 md:grid-cols-2">
                    <label className="space-y-2 text-xs text-slate-400">GitHub organization or account name<Input value={accountLogin} onChange={(event) => setAccountLogin(event.target.value)} placeholder={accountScopeKind === "PERSONAL" ? "your-login" : "company-name"} autoComplete="off" /></label>
                    <label className="space-y-2 text-xs text-slate-400">Approval or change reference<Input value={authorizationReference} onChange={(event) => setAuthorizationReference(event.target.value)} placeholder="change-ticket-1234" autoComplete="off" /></label>
                    <label className="space-y-2 text-xs text-slate-400">GitHub App ID<Input value={appId} onChange={(event) => setAppId(event.target.value)} placeholder="123456" autoComplete="off" /></label>
                    <label className="space-y-2 text-xs text-slate-400">GitHub installation ID<Input value={installationId} onChange={(event) => setInstallationId(event.target.value)} placeholder="78901234" autoComplete="off" /></label>
                  </div>
                  <label className="space-y-2 text-xs text-slate-400">GitHub App private key (kept write-only)<textarea value={privateKey} onChange={(event) => setPrivateKey(event.target.value)} rows={5} placeholder="-----BEGIN RSA PRIVATE KEY-----" autoComplete="off" className="w-full rounded-md border border-[#1e2433] bg-[#0e1018] px-3 py-2 font-mono text-xs text-slate-100 outline-none focus:ring-2 focus:ring-cyan-300" /></label>
                  <div className="flex flex-wrap justify-between gap-3"><a href="https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app" target="_blank" rel="noreferrer" className="text-xs text-cyan-300 hover:underline">Review GitHub App permissions</a><div className="flex gap-2"><Button type="button" variant="ghost" onClick={() => setConnectionFormOpen(false)}>Cancel</Button><Button type="submit" disabled={connectionWorking}>{connectionWorking ? "Connecting…" : "Save and validate"}</Button></div></div>
                </form>
              ) : null}
            </CardContent>
          </Card>

          <Card id="repo-picker" className="border-white/10 bg-[#101721]/80">
            <CardHeader>
              <div className="flex flex-wrap items-start justify-between gap-4"><div><CardTitle className="flex items-center gap-2 text-white"><GitBranch className="h-5 w-5 text-orange-300" /> Choose repositories</CardTitle><p className="mt-2 text-sm text-slate-400">Select a repository from the GitHub inventory to prepare a control draft. Selection does not approve access.</p></div><Button type="button" variant="outline" disabled={inventoryLoading} onClick={() => void loadRepositoryInventory(false, null)}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button></div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div role="tablist" aria-label="GitHub repository inventory modes" className="flex flex-wrap gap-2">
                {(["repositories", "organizations", "developers", "ai-connections"] as RepositoryInventoryMode[]).map((mode) => {
                  const label = mode === "ai-connections" ? "AI Connections" : mode === "developers" ? "People & teams" : mode === "organizations" ? "Accounts" : "Repositories";
                  return <button key={mode} type="button" role="tab" aria-selected={repositoryInventoryMode === mode} onClick={() => setRepositoryInventoryMode(mode)} className={`rounded-lg border px-3 py-2 text-xs ${repositoryInventoryMode === mode ? "border-cyan-300/40 bg-cyan-300/10 text-cyan-100" : "border-white/10 text-slate-400"}`}>{label}</button>;
                })}
              </div>
              <div className="relative max-w-xl"><Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" /><Input id="repository-inventory-filter" aria-label="Filter current GitHub inventory" value={inventoryFilter} onChange={(event) => setInventoryFilter(event.target.value)} placeholder="Search repositories, people, teams, tools or models" className="pl-9" /></div>
              {inventoryLoading ? <p className="text-sm text-slate-400">Loading current inventory evidence…</p> : null}
              {inventoryError ? <p className="rounded-xl border border-red-400/20 bg-red-400/10 p-3 text-sm text-red-100">Could not load this inventory mode. Existing controls remain unchanged.</p> : null}
              {!inventoryLoading && !inventoryError && displayedInventoryRows.length === 0 ? <div className="rounded-2xl border border-dashed border-white/15 bg-white/[0.02] p-8 text-center"><Github className="mx-auto h-8 w-8 text-slate-600" /><p className="mt-3 font-medium text-white">No inventory rows are available</p><p className="mx-auto mt-2 max-w-xl text-sm leading-6 text-slate-500">{inventoryFilter.trim() ? "No rows match this search." : sourceReady ? "Validate the source and run an inventory scan. Repositories appear after GitHub returns a completed inventory." : "Connect GitHub, then run an inventory scan to see repositories."}</p></div> : null}
              {displayedInventoryRows.length ? <div className="overflow-x-auto rounded-xl border border-white/10"><table className="w-full min-w-[940px] text-left text-xs"><thead className="bg-white/[0.025] text-[10px] uppercase tracking-[0.16em] text-slate-500"><tr>{repositoryInventoryMode === "ai-connections" ? <><th className="px-4 py-3">AI tool / application</th><th className="px-4 py-3">Provider / model</th><th className="px-4 py-3">Agent / MCP / tool</th><th className="px-4 py-3">Surface</th><th className="px-4 py-3">Evidence</th></> : <><th className="px-4 py-3">Name</th><th className="px-4 py-3">Account / access state</th><th className="px-4 py-3">Evidence</th><th className="px-4 py-3">Action</th></>}</tr></thead><tbody>{displayedInventoryRows.map((row, index) => repositoryInventoryMode === "ai-connections" ? <tr key={String(row.id || index)} className="border-t border-white/5"><td className="px-4 py-3 text-white">{String(row.client_name || row.ai_system_id || "Unknown AI tool")}</td><td className="px-4 py-3 text-slate-300">{String(row.provider || "Unknown provider")} · {String(row.model || "Unknown model")}</td><td className="px-4 py-3 text-slate-300">{String(row.agent_id || "Unknown agent")} · {String(row.mcp_server_id || "No MCP evidence")} · {String(row.tool_name || "Unknown tool")}</td><td className="px-4 py-3">{String(row.source_surface || "Unknown")}</td><td className="px-4 py-3"><StateBadge value={String(row.confidence || "UNKNOWN")} /></td></tr> : <tr key={String(row.id || index)} className={`border-t border-white/5 ${selectedRepository?.id === row.id ? "bg-orange-400/[0.06]" : ""}`}><td className="px-4 py-3 font-medium text-white">{String(row.full_name || row.login || row.external_principal_id || "Unknown")}</td><td className="px-4 py-3 text-slate-300"><span className="flex flex-wrap items-center gap-2"><StateBadge value={inventoryAccountScope(row)} /><span>{String(row.governance_state || row.permission || row.access_path || row.sync_state || "Unknown")}</span></span></td><td className="px-4 py-3"><StateBadge value={String(row.evidence_state || "UNKNOWN")} /></td><td className="px-4 py-3">{repositoryInventoryMode === "repositories" ? <div className="flex gap-2"><Button type="button" size="sm" onClick={() => row.id && void loadRepositoryDetail(String(row.id), true)}>Select repository</Button><Button type="button" size="sm" variant="outline" onClick={() => row.id && void loadRepositoryDetail(String(row.id))}><Eye className="mr-1 h-3.5 w-3.5" />Details</Button></div> : "—"}</td></tr>)}</tbody></table></div> : null}
              {inventoryCursor ? <Button type="button" variant="outline" disabled={inventoryLoading} onClick={() => void loadRepositoryInventory(true)}>Show more</Button> : null}
            </CardContent>
          </Card>

          <Card className={`border-white/10 bg-[#101721]/80 ${selectedRepository ? "ring-1 ring-orange-300/20" : ""}`}>
            <CardHeader><div className="flex flex-wrap items-start justify-between gap-3"><div><CardTitle className="flex items-center gap-2 text-white"><LockKeyhole className="h-5 w-5 text-orange-300" /> Define controls</CardTitle><p className="mt-2 text-sm text-slate-400">Choose who and what this draft covers. Review and approval happen in Policies.</p></div>{selectedRepository ? <StateBadge value={selectedRepository.governance_state} /> : null}</div></CardHeader>
            <CardContent className="space-y-5">
              {!selectedRepository ? <div className="rounded-2xl border border-dashed border-white/15 p-8 text-center text-sm text-slate-400">Choose a source-backed repository above to configure its controls.</div> : <>
                <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-orange-300/20 bg-orange-300/[0.045] p-4"><div><p className="text-xs uppercase tracking-[0.16em] text-orange-200">Selected repository</p><p className="mt-1 text-lg font-semibold text-white">{selectedRepository.full_name}</p><div className="mt-2 flex flex-wrap items-center gap-2"><StateBadge value={selectedRepository.account_scope_kind} /><StateBadge value={selectedRepository.deny_posture || selectedRepository.governance_state} /><span className="text-xs text-slate-400">{selectedRepository.visibility.toLowerCase()} · default branch {selectedRepository.default_branch || "unknown"} · evidence {selectedRepository.evidence_state.toLowerCase()}</span></div></div><Button type="button" variant="ghost" onClick={() => setSelectedRepository(null)}><X className="mr-2 h-4 w-4" />Clear</Button></div>

                <section aria-labelledby="local-repository-controls" className="space-y-3 rounded-2xl border border-cyan-300/20 bg-cyan-300/[0.04] p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 id="local-repository-controls" className="text-sm font-medium text-white">Local repository controls</h3><p className="mt-1 text-xs text-slate-400">Signed hooks control one exact workspace. Allow removes this repository block; other rules still apply.</p></div><Button type="button" disabled={!selectedRepository || runtimeBindingsLoading || runtimeBindingWorking || operationControlsWorking} variant="ghost" onClick={() => selectedRepository && void refreshRuntimeControls(selectedRepository.id)}>Refresh workspaces</Button></div>
                  {runtimeBindingError ? <p role="alert" className="text-xs text-red-300">{runtimeBindingError}</p> : null}
                  {runtimeBindingsLoading ? <p className="text-xs text-slate-400">Checking signed workspaces and current governance…</p> : localRepositoryControlsReady ? <p className="text-xs text-emerald-200">Active exact-folder workspace verified.</p> : <p className="text-xs text-amber-200">Controls require current approved private-repository governance and an active signed workspace.</p>}
                  <div className="flex flex-wrap items-end gap-3"><label className="min-w-0 flex-1 text-xs text-slate-400">Signed workspace observation<select aria-label="Signed workspace observation" value={selectedRuntimeObservation} onChange={(event) => setSelectedRuntimeObservation(event.target.value)} disabled={!localRepositoryGovernanceReady || runtimeBindingWorking} className="mt-1 w-full rounded-lg border border-white/10 bg-[#101721] px-3 py-2 text-slate-100"><option value="">Choose a signed observation</option>{eligibleRuntimeObservations.map((row) => <option key={row.id} value={row.id}>{runtimeIntegrationLabels[row.native_integration_id] || "Native integration"} · {row.canonical_root_sha256.slice(0, 12)}… · exact folder</option>)}</select></label><Button type="button" disabled={!localRepositoryGovernanceReady || !selectedRuntimeObservation || runtimeBindingWorking} onClick={() => void bindRuntimeObservation()}>{runtimeBindingWorking ? "Binding…" : "Bind signed workspace"}</Button></div>
                  {!runtimeBindingsLoading && !eligibleRuntimeObservations.length ? <p className="text-xs text-slate-500">Run a repository action through a configured native hook to create a signed observation.</p> : null}
                  <div className="grid gap-2 sm:grid-cols-5">{([['READ','Read'],['EDIT','Edit'],['COMMIT','Commit'],['PULL','Pull'],['PUSH','Push']] as const).map(([value, label]) => <button key={value} type="button" disabled={!localRepositoryControlsReady || operationControlsWorking} aria-pressed={operationControls[value] === "ALLOW"} onClick={() => setOperationControls((current) => ({ ...current, [value]: current[value] === "ALLOW" ? "BLOCK" : "ALLOW" }))} className={`rounded-xl border p-3 text-left text-xs disabled:cursor-not-allowed disabled:opacity-40 ${operationControls[value] === "ALLOW" ? "border-emerald-300/40 bg-emerald-300/10" : "border-red-300/30 bg-red-300/[0.05]"}`}><span className="block font-medium text-white">{label}</span><span className="mt-1 text-slate-400">{operationControls[value]}</span></button>)}</div>
                  <Button type="button" disabled={!localRepositoryControlsReady || operationControlsWorking} onClick={() => void saveOperationControls()} className="bg-cyan-300 text-slate-950 hover:bg-cyan-200">{operationControlsWorking ? "Saving…" : "Apply"}</Button>
                  <p className="text-[11px] text-slate-500">Workspace identities are retained as hashes. MCP and provider-hosted paths keep their existing policy controls.</p>
                </section>
                {selectedRepository.account_scope_kind === "PERSONAL" ? <section aria-labelledby="personal-repository-protection" className="space-y-5 rounded-2xl border border-red-300/20 bg-red-400/[0.035] p-5">
                  <div className="flex flex-wrap items-start justify-between gap-4"><div><h3 id="personal-repository-protection" className="text-lg font-semibold text-white">Personal repository protection</h3><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Selection never approves this repository. Its metadata inventory remains visible to authorized administrators so the account and control state can be audited.</p></div><StateBadge value={selectedRepository.deny_posture || "REVIEW_REQUIRED"} /></div>
                  <fieldset><legend className="mb-3 text-sm font-medium text-white">Choose the governed AI restriction</legend><div className="grid gap-3 lg:grid-cols-2">
                    <button type="button" aria-pressed={personalRepositoryDenyPosture === "BLOCK_CHANGES"} onClick={() => setPersonalRepositoryDenyPosture("BLOCK_CHANGES")} className={`rounded-2xl border p-4 text-left transition ${personalRepositoryDenyPosture === "BLOCK_CHANGES" ? "border-orange-300/50 bg-orange-300/10" : "border-white/10 bg-white/[0.025]"}`}><span className="font-medium text-white">Block changes</span><span className="mt-2 block text-xs leading-5 text-slate-400">Allow governed metadata reads, clone, fetch and pull. Block branch, push, pull request, review and merge operations.</span></button>
                    <button type="button" aria-pressed={personalRepositoryDenyPosture === "BLOCK_ALL"} onClick={() => setPersonalRepositoryDenyPosture("BLOCK_ALL")} className={`rounded-2xl border p-4 text-left transition ${personalRepositoryDenyPosture === "BLOCK_ALL" ? "border-red-300/50 bg-red-300/10" : "border-white/10 bg-white/[0.025]"}`}><span className="font-medium text-white">Block all AI access</span><span className="mt-2 block text-xs leading-5 text-slate-400">Keep metadata inventory visible to administrators, but block governed reads, clone, fetch and pull, and every repository change.</span></button>
                  </div></fieldset>
                  <div className="grid gap-3 md:grid-cols-2">
                    <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-sm font-medium text-white">MCP gateway / runtime</p><div className="mt-2"><StateBadge value={repositoryPathStatus} /></div><p className="mt-2 text-xs leading-5 text-slate-500">Pre-execution blocking requires a healthy governed MCP/runtime route. Otherwise this surface remains visibly unavailable or partial.</p></div>
                    <div className="rounded-xl border border-white/10 bg-white/[0.025] p-4"><p className="text-sm font-medium text-white">Endpoint CLI / IDE</p><div className="mt-2"><StateBadge value={repositoryPathStatus} /></div><p className="mt-2 text-xs leading-5 text-slate-500">Git command blocking requires a healthy enrolled endpoint control point. Inventory status alone never implies enforcement.</p></div>
                  </div>
                  <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-white/10 bg-black/10 p-4"><div><p className="font-medium text-white">Apply fail-closed protection</p><p className="mt-1 max-w-3xl text-xs leading-5 text-slate-400">This records an explicit unapproved state and the selected read posture. It does not delete or hide the repository inventory.</p></div><Button type="button" disabled={personalProtectionWorking} onClick={() => void applyPersonalProtection()} className="bg-red-300 text-slate-950 hover:bg-red-200">{personalProtectionWorking ? "Applying…" : "Apply protection"}</Button></div>
                </section> : <>
                <div className="grid gap-5 xl:grid-cols-2">
                  <fieldset><legend className="mb-3 text-sm font-medium text-white">AI tools to allow after approval</legend><div className="flex flex-wrap gap-2">{AI_TOOLS.map(([value, label]) => <ChoiceChip key={value} checked={selectedAITools.includes(value)} label={label} onChange={() => setSelectedAITools((current) => toggleChoice(current, value))} />)}</div></fieldset>
                  <fieldset><legend className="mb-3 text-sm font-medium text-white">Repository actions to allow after approval</legend><div className="grid gap-2 sm:grid-cols-2">{selectedActionControls.map((action) => <button key={action.value} type="button" aria-pressed={action.selected} onClick={() => setSelectedOperations((current) => toggleChoice(current, action.value))} className={`rounded-xl border p-3 text-left text-xs ${action.selected ? "border-orange-300/40 bg-orange-400/10" : "border-white/10 bg-white/[0.025]"}`}><span className="block font-medium text-white">{action.label}</span><span className="mt-1 block text-slate-400">{action.decision}</span></button>)}</div></fieldset>
                  <fieldset><legend className="mb-3 flex items-center gap-2 text-sm font-medium text-white"><UsersRound className="h-4 w-4 text-cyan-300" /> People and groups</legend><div className="grid gap-3 sm:grid-cols-2"><label className="space-y-2 text-xs text-slate-400">Users (comma-separated)<Input value={people} onChange={(event) => setPeople(event.target.value)} placeholder="alice@company.com" /></label><label className="space-y-2 text-xs text-slate-400">Groups (comma-separated)<Input value={groups} onChange={(event) => setGroups(event.target.value)} placeholder="engineering, platform" /></label></div></fieldset>
                  <fieldset><legend className="mb-3 text-sm font-medium text-white">Where controls should apply</legend><div className="flex flex-wrap gap-2">{DEPLOYMENT_SURFACES.map(([value, label]) => <ChoiceChip key={value} checked={selectedSurfaces.includes(value)} label={label} onChange={() => setSelectedSurfaces((current) => toggleChoice(current, value))} />)}</div></fieldset>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-orange-300/20 bg-orange-300/[0.05] p-4"><p className="max-w-2xl text-sm text-slate-300">These choices are a draft. Review them in Policies before any approved control can become active.</p><Button type="button" disabled={!canReviewControls} onClick={() => { window.location.href = policyRolloutHref; }} className="bg-orange-400 text-slate-950 hover:bg-orange-300">Review and apply controls <ArrowRight className="ml-2 h-4 w-4" /></Button></div>
                </>}
              </>}
            </CardContent>
          </Card>

          <Card className="border-white/10 bg-[#101721]/80">
            <CardHeader><CardTitle className="flex items-center gap-2 text-white"><AlertTriangle className="h-5 w-5 text-amber-300" /> Recent activity</CardTitle><p className="mt-2 text-sm text-slate-400">Actual repository decisions and AI tool calls appear here when evidence is received.</p></CardHeader>
            <CardContent className="space-y-4">
              {loading ? <p className="text-sm text-slate-400">Loading activity…</p> : error ? <p role="alert" className="text-sm text-amber-100">Activity is unavailable. Retry the page to check current evidence.</p> : data ? <>
                <div><h3 className="text-sm font-medium text-white">Unauthorized repository attempts</h3>{data.unauthorized_attempts.length ? <div className="mt-2 space-y-2">{data.unauthorized_attempts.map((row, index) => <div key={index} className="rounded-xl border border-white/10 p-3 text-sm"><div className="flex items-center justify-between gap-3"><span className="text-white">{String(row.repository || "Unknown repository")}</span><StateBadge value={String(row.decision || "UNKNOWN")} /></div><p className="mt-1 text-xs text-slate-500">{String(row.operation || "Unknown action")} · {String(row.tool || "Unknown tool")} · {String(row.surface || "Unknown surface")}</p></div>)}</div> : <p className="mt-2 text-sm text-slate-400">No unauthorized attempts are available in the current evidence window.</p>}</div>
                <div><h3 className="text-sm font-medium text-white">AI tool calls</h3>{observedAICalls.length ? <div className="mt-2 space-y-2">{observedAICalls.map((row, index) => <div key={index} className="rounded-xl border border-white/10 p-3 text-sm"><div className="flex items-center justify-between gap-3"><span className="text-white">{detailValue(row.ai_client)} · {detailValue(row.action)}</span><StateBadge value={row.policy_decision} /></div><p className="mt-1 text-xs text-slate-500">{detailValue(row.provider)} / {detailValue(row.model)} · {detailValue(row.tool_call)} · Evidence: {row.evidence_refs.length ? row.evidence_refs.join(", ") : "Unavailable"}</p></div>)}</div> : <p className="mt-2 text-sm text-slate-400">No AI tool calls are available in the current evidence window.</p>}</div>
              </> : <p className="text-sm text-slate-400">Activity is unavailable.</p>}
            </CardContent>
          </Card>
          <details className="rounded-2xl border border-white/10 bg-[#101721]/70 p-5">
            <summary className="cursor-pointer text-sm font-semibold text-slate-200">Connection details and test tools</summary>
            <div className="mt-5 space-y-6 text-sm text-slate-400">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <MetricCard label="Connection" value={connectionError ? "Unavailable" : connectionLoading ? "Checking" : friendlyConnectionState(sourceConnection)} hint="GitHub source status" />
                <MetricCard label="Accounts" value={data ? repositoryInventory.organizations : "Unavailable"} hint="Reported by inventory" />
                <MetricCard label="Repositories" value={data ? repositoryInventory.repositories : "Unavailable"} hint="Reported by inventory" />
                <MetricCard label="Authoritative inventory" value={data ? repositoryInventory.authoritative_denominator_available ? "Available" : "Unavailable" : "Unavailable"} hint="Requires a completed source receipt" />
                <MetricCard label="Direct access" value={data ? repositoryInventory.direct_access : "Unavailable"} hint="Person to repository" />
                <MetricCard label="Team access" value={data ? repositoryInventory.team_inherited_access : "Unavailable"} hint="Access through GitHub teams" />
              </div>
              <div><h3 className="font-medium text-white">Evidence and freshness</h3><p className="mt-1">Last selected repository evidence: {detailValue(selectedRepository?.last_verified_at || selectedRepository?.last_seen_at)}</p><ul className="mt-2 space-y-1">{repositoryInventory.blind_spots.map((blindSpot) => <li key={blindSpot}>• {blindSpot.replaceAll("_", " ")}</li>)}</ul><p className="mt-2">Missing or stale evidence stays unknown. GitHub inventory, governed runtime calls and endpoint controls prove different things.</p></div>
              <div><h3 className="font-medium text-white">General control path status</h3><p className="mt-1 text-xs">This reports available control paths, not protection for a selected repository.</p><div className="mt-2 grid gap-3 md:grid-cols-3">{[["MCP gateway / runtime", runtimeCoverage], ["Endpoint CLI / IDE", endpointCoverage], ["Browser / web", browserCoverage]].map(([label, state]) => <div key={label} className="rounded-xl border border-white/10 p-3"><p className="font-medium text-white">{label}</p><div className="mt-2"><StateBadge value={sourceReady ? state : "NOT_VERIFIED"} /></div></div>)}</div></div>
              <div><h3 className="font-medium text-white">AI tool coverage for this repository</h3><div className="mt-2 grid gap-2 sm:grid-cols-2">{clientControlRows.map(([name, , state, description]) => <div key={name} className="rounded-xl border border-white/10 p-3"><div className="flex items-center justify-between gap-2"><span className="font-medium text-white">{name}</span><StateBadge value={state} /></div><p className="mt-2 text-xs">{description}</p></div>)}</div><p className="mt-2 text-xs">Unsupported paths stay visible. An installed client alone does not prove enforcement.</p></div>
              <div><h3 className="font-medium text-white">Access relationships</h3><p className="mt-1">Human or AI actor → repository → action → decision. Open Details on a repository for source-backed users, teams, providers, models, tools and evidence. {humanAndAIRepoGraphRows.length ? `${humanAndAIRepoGraphRows.length} relationships are loaded for the selected repository.` : "No selected repository relationships are loaded."}</p></div>
              <div><h3 className="font-medium text-white">Test this control</h3><p className="mt-1">These are example prompts. Run them only after the policy is approved, then check the actual result and evidence.</p><div className="mt-3 grid gap-3 lg:grid-cols-2"><div className="rounded-xl border border-emerald-300/20 p-3"><p className="font-medium text-white">Selected repository example</p><code className="mt-2 block whitespace-pre-wrap break-words text-xs">Use the governed GitHub MCP server to list open pull requests for {selectedRepositoryName}. Return the result or the exact policy error.</code></div><div className="rounded-xl border border-red-300/20 p-3"><p className="font-medium text-white">Other repository example</p><code className="mt-2 block whitespace-pre-wrap break-words text-xs">Use the governed GitHub MCP server to list open pull requests for {blockedRepositoryName}. Return the result or the exact policy error.</code></div></div><p className="mt-2 text-xs">Replace angle-bracket names with real repositories. A draft choice is not an observed allow or block decision.</p><Link href="/validate" className="mt-3 inline-flex text-xs font-medium text-cyan-300 hover:underline">Open control tests <ArrowRight className="ml-1 h-3.5 w-3.5" /></Link></div>
            </div>
          </details>
          {(repositoryDetailLoading || repositoryDetailError || repositoryDetail) ? <aside role="dialog" aria-modal="true" aria-labelledby="repository-detail-heading" className="fixed inset-y-0 right-0 z-50 w-full max-w-2xl overflow-y-auto border-l border-white/10 bg-[#0b111a] p-6 shadow-2xl"><div className="flex items-center justify-between gap-3"><h2 id="repository-detail-heading" className="text-lg font-semibold text-white">Repository detail</h2><Button ref={repositoryDetailCloseRef} type="button" variant="outline" onClick={closeRepositoryDetail}>Close</Button></div>{repositoryDetailLoading ? <p className="mt-5 text-slate-400">Loading repository relationships…</p> : null}{repositoryDetailError ? <p className="mt-5 rounded-xl border border-red-400/20 bg-red-400/10 p-3 text-red-100">Could not load repository detail. Existing controls remain unchanged.</p> : null}{repositoryDetail ? <>
            <div className="mt-5 rounded-2xl border border-white/10 bg-white/[0.025] p-4"><p className="font-semibold text-white">{repositoryDetail.repository.full_name}</p><p className="mt-1 text-xs text-slate-500">{repositoryDetail.repository.host} · {repositoryDetail.repository.visibility} · {repositoryDetail.repository.lifecycle_state}</p><div className="mt-3 flex flex-wrap gap-2"><StateBadge value={repositoryDetail.repository.account_scope_kind} /><StateBadge value={repositoryDetail.repository.governance_state} /><StateBadge value={repositoryDetail.repository.deny_posture || repositoryDetail.repository.evidence_state} /></div></div>
            <div className="mt-5 grid gap-4 lg:grid-cols-2"><div><p className="font-medium text-white">Users and access</p>{repositoryDetail.access_relationships.items.length ? repositoryDetail.access_relationships.items.map((row) => <div key={row.id} className="mt-2 rounded-xl border border-white/10 p-3 text-xs text-slate-300"><p className="font-medium text-white">{detailValue(row.mapped_user_id || row.external_principal_id)}</p><p className="mt-1">{detailValue(row.principal_type)} · {detailValue(row.access_path)} · {detailValue(row.permission)}</p><p className="mt-1 text-slate-500">Group: {detailValue(row.mapped_group_id || row.source_team_id)} · Evidence: {detailValue(row.evidence_state)} · Valid until: {detailValue(row.valid_until)}</p></div>) : <p className="mt-2 text-sm text-slate-500">No source-backed access relationships are available.</p>}{repositoryDetail.access_relationships.next_cursor ? <p className="mt-2 text-xs text-slate-500">More access relationships exist outside this bounded page.</p> : null}</div>
              <div><p className="font-medium text-white">AI connections</p>{repositoryDetail.ai_connections.items.length ? repositoryDetail.ai_connections.items.map((row) => <div key={row.id} className="mt-2 rounded-xl border border-white/10 p-3 text-xs text-slate-300"><p className="font-medium text-white">{detailValue(row.client_name || row.ai_system_id)}</p><p className="mt-1">Provider / model: {detailValue(row.provider)} · {detailValue(row.model)}</p><p className="mt-1">Agent: {detailValue(row.agent_id)} · MCP: {detailValue(row.mcp_server_id)} · Tool: {detailValue(row.tool_name)}</p><p className="mt-1 text-slate-500">Surface: {detailValue(row.source_surface)} · Relationship: {detailValue(row.relationship_state)} · Confidence: {detailValue(row.confidence)} · Evidence: {detailValue(row.evidence_refs.join(", "))} · Actions: {detailValue(row.action_count)} · Last seen: {detailValue(row.last_seen_at)}</p></div>) : <p className="mt-2 text-sm text-slate-500">No source-backed AI relationship is available.</p>}{repositoryDetail.ai_connections.next_cursor ? <p className="mt-2 text-xs text-slate-500">More AI connections exist outside this bounded page.</p> : null}</div></div>
            <details className="mt-5 rounded-xl border border-white/10 p-4 text-xs"><summary className="cursor-pointer font-medium text-slate-300">Audit evidence</summary><dl className="mt-3 grid gap-2 sm:grid-cols-2">{[["Account class", repositoryDetail.repository.account_scope_kind], ["Personal repository posture", repositoryDetail.repository.deny_posture], ["Immutable GitHub ID", repositoryDetail.repository.repository_id], ["GitHub node ID", repositoryDetail.repository.node_id], ["Governance version", repositoryDetail.repository.governance_version], ["Read posture", repositoryDetail.repository.read_posture], ["Policy version", repositoryDetail.repository.policy_mapping_ref], ["Policy assignment", repositoryDetail.repository.approved_scope_ref], ["First seen", repositoryDetail.repository.first_seen_at], ["Last seen", repositoryDetail.repository.last_seen_at], ["Last verified", repositoryDetail.repository.last_verified_at]].map(([label, value]) => <div key={String(label)}><dt className="text-slate-500">{String(label)}</dt><dd className="truncate text-slate-100" title={detailValue(value)}>{detailValue(value)}</dd></div>)}</dl><p className="mt-3 text-slate-500">Long values are truncated visually; focus or hover to inspect evidence metadata. No repository content, secret or prompt body is shown.</p></details>
          </> : null}</aside> : null}
        </section>
      </div>
    </AppShell>
  );
}
