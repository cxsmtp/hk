"use client";

import Link from "next/link";
import {
  AlertTriangle,
  CircleDot,
  Database,
  ExternalLink,
  Fingerprint,
  KeyRound,
  Mail,
  Plus,
  Radar,
  RefreshCw,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type {
  Connector,
  ConnectorCoverageState,
  ConnectorEvaluation,
  ConnectorProviderCatalogItem,
} from "@/lib/types";
import {
  canLinkVerifiedEvidence,
  deriveGmailBrowserPresentation,
  selectMatchingEvaluation,
} from "@/lib/connector-control-room-state";
import {
  deriveConnectorCapabilities,
  deriveConnectorReadiness,
  normalizeConnectorCategory,
} from "@/lib/connector-catalog";
import { cn } from "@/lib/utils";

type ConnectorControlRoomProps = {
  connectors: Connector[];
  providers: ConnectorProviderCatalogItem[];
  selectedConnectorId: string | null;
  evaluation: ConnectorEvaluation | null;
  evaluating: boolean;
  evaluationError: string | null;
  onSelect: (connectorId: string) => void;
  onEvaluate: (connectorId: string) => Promise<void>;
  onConfigureProvider?: (provider: ConnectorProviderCatalogItem) => void;
  setupPanel: React.ReactNode;
  connectionGuide?: React.ReactNode;
  loadState?: "loading" | "loaded" | "error";
  loadError?: string | null;
};

const COVERAGE_TONE: Record<ConnectorCoverageState, string> = {
  covered: "border-emerald-400/25 bg-emerald-400/[0.08] text-emerald-200",
  not_covered: "border-rose-400/25 bg-rose-400/[0.08] text-rose-200",
  unknown: "border-amber-400/25 bg-amber-400/[0.08] text-amber-200",
};

function formatDate(value?: string | null): string {
  if (!value) return "No observation";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

function sentenceCase(value?: string | null): string {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function friendlyProviderName(provider?: ConnectorProviderCatalogItem | null, providerKey?: string): string {
  const key = String(providerKey || provider?.provider_key || "").toLowerCase();
  const known: Record<string, string> = {
    hmair_microsoft365_copilot: "Microsoft 365 Copilot",
    hmair_github_cloud: "GitHub Cloud",
    hmair_github_ghes: "GitHub Enterprise Server",
    microsoft_365: "Microsoft 365",
    azure_openai: "Azure OpenAI",
    openai_enterprise: "OpenAI Enterprise",
    google_workspace: "Google Workspace",
  };
  if (known[key]) return known[key];
  const display = provider?.display_name?.trim();
  if (display && !/^[A-Z0-9_ -]+$/.test(display)) return display;
  return sentenceCase(key || display || "Integration");
}

function providerConnectionLabel(provider: ConnectorProviderCatalogItem): string {
  if (provider.is_stub) return "Planned";
  if (!provider.supports_live_pull) return "Setup limited";
  return "Ready to connect";
}

function customerConnectorCategory(category?: string | null, providerKey?: string | null): string {
  const normalized = normalizeConnectorCategory(category, providerKey);
  return normalized === "SDK and application bindings" ? "Application connections" : normalized;
}

function coverageLabel(value?: ConnectorCoverageState): string {
  if (value === "covered") return "Covered";
  if (value === "not_covered") return "Not Covered";
  return "Unknown";
}

function connectorStatus(connector: Connector): {
  label: string;
  tone: string;
} {
  if (!connector.enabled) {
    return { label: "Disabled", tone: "border-slate-500/30 bg-slate-500/10 text-slate-300" };
  }
  if (connector.is_stub) {
    return { label: "Stub", tone: "border-violet-400/25 bg-violet-400/10 text-violet-200" };
  }
  if (connector.status.toLowerCase() === "revoked") {
    return { label: "Revoked", tone: "border-rose-400/25 bg-rose-400/10 text-rose-200" };
  }
  if (connector.last_pull_status.toLowerCase() === "error") {
    return { label: "Degraded", tone: "border-amber-400/25 bg-amber-400/10 text-amber-200" };
  }
  return { label: sentenceCase(connector.status || "active"), tone: "border-emerald-400/25 bg-emerald-400/10 text-emerald-200" };
}

function connectorCoverageLabel(connector: Connector): string {
  if (connector.is_stub) return "Not Covered";
  if ((connector.provider_key || connector.connector_type).toLowerCase() === "gmail") return "Monitor-only";
  return "Unknown";
}

function ConnectorFleet({
  connectors,
  providers,
  selectedConnectorId,
  onSelect,
  onConfigureProvider,
}: Pick<ConnectorControlRoomProps, "connectors" | "providers" | "selectedConnectorId" | "onSelect" | "onConfigureProvider">) {
  const [categoryFilter, setCategoryFilter] = useState("All categories");
  const configuredProviders = new Set(
    connectors.map((connector) => (connector.provider_key || connector.connector_type).toLowerCase()),
  );
  const available = providers.filter((provider) => !configuredProviders.has(provider.provider_key.toLowerCase()));
  const providerByKey = useMemo(
    () => new Map(providers.map((provider) => [provider.provider_key.toLowerCase(), provider])),
    [providers],
  );
  const categories = useMemo(
    () => [
      "All categories",
      ...Array.from(new Set(providers.map((provider) => customerConnectorCategory(provider.category, provider.provider_key)))).sort(),
    ],
    [providers],
  );
  const filteredConnectors = connectors.filter((connector) => {
    if (categoryFilter === "All categories") return true;
    const providerKey = (connector.provider_key || connector.connector_type).toLowerCase();
    const provider = providerByKey.get(providerKey);
    return customerConnectorCategory(provider?.category, providerKey) === categoryFilter;
  });
  const implementedAvailable = available.filter((provider) => !provider.is_stub);
  const plannedAvailable = available.filter((provider) => provider.is_stub);
  const filteredAvailable = implementedAvailable.filter((provider) => (
    categoryFilter === "All categories"
    || customerConnectorCategory(provider.category, provider.provider_key) === categoryFilter
  ));
  const filteredPlanned = plannedAvailable.filter((provider) => (
    categoryFilter === "All categories"
    || customerConnectorCategory(provider.category, provider.provider_key) === categoryFilter
  ));

  return (
    <section aria-labelledby="connector-fleet-title" className="border-b border-[#263047] bg-[#0c111a]/90 p-4 md:p-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-cyan-300">Connected source status · observation only</div>
          <h2 id="connector-fleet-title" className="mt-2 text-lg font-semibold text-slate-100">Connected sources</h2>
          <p className="mt-1 text-xs text-slate-500">Connected means Hawk can collect from the source. Control requires separate inline-control evidence.</p>
        </div>
        <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">
          {connectors.length} connected · {available.length} available integrations
        </div>
      </div>

      <div className="mt-4 flex flex-wrap gap-2 pb-1" aria-label="Connector categories">
        {categories.map((category) => (
          <button
            key={category}
            type="button"
            aria-pressed={categoryFilter === category}
            onClick={() => setCategoryFilter(category)}
            className={cn(
              "shrink-0 border px-3 py-2 text-[10px] font-semibold uppercase tracking-[0.08em] transition",
              categoryFilter === category
                ? "border-orange-400/35 bg-orange-400/10 text-orange-200"
                : "border-[#30394d] bg-[#0d121b] text-slate-500 hover:border-[#46516a] hover:text-slate-300",
            )}
          >
            {category}
          </button>
        ))}
      </div>

      {filteredConnectors.length ? (
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {filteredConnectors.map((connector) => {
            const state = connectorStatus(connector);
            const selected = connector.id === selectedConnectorId;
            const providerKey = (connector.provider_key || connector.connector_type).toLowerCase();
            const provider = providerByKey.get(providerKey);
            const category = customerConnectorCategory(provider?.category, providerKey);
            const capabilities = provider ? deriveConnectorCapabilities(provider) : null;
            return (
              <button
                type="button"
                key={connector.id}
                aria-pressed={selected}
                onClick={() => onSelect(connector.id)}
                className={cn(
                  "group relative overflow-hidden border bg-[#111722] p-4 text-left transition duration-200",
                  selected
                    ? "border-brand-400/70 shadow-[inset_3px_0_0_#fb923c,0_12px_32px_rgba(0,0,0,.22)]"
                    : "border-[#293348] hover:-translate-y-0.5 hover:border-[#45516a]",
                )}
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <Mail className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />
                      <span className="truncate text-sm font-semibold text-slate-100">{connector.name}</span>
                    </div>
                    <div className="mt-1 pl-6 font-mono text-[10px] uppercase tracking-[0.12em] text-slate-500">
                      {friendlyProviderName(provider, providerKey)} · {category}
                    </div>
                  </div>
                  <Badge className={cn("shrink-0 rounded-sm font-mono text-[9px] uppercase", state.tone)}>{state.label}</Badge>
                </div>
                <div className="mt-4 grid grid-cols-2 gap-x-3 gap-y-2 border-t border-[#273045] pt-3 text-[11px]">
                  <div>
                    <div className="text-slate-600">Last pull</div>
                    <div className="mt-1 truncate text-slate-300">{formatDate(connector.last_run_at)}</div>
                  </div>
                  <div>
                    <div className="text-slate-600">Signals</div>
                    <div className="mt-1 font-mono text-slate-200">{connector.last_signal_count ?? 0}</div>
                  </div>
                  <div>
                    <div className="text-slate-600">Credential</div>
                    <div className="mt-1 text-slate-300">{connector.has_secrets ? "Present" : "Missing"}</div>
                  </div>
                  <div>
                    <div className="text-slate-600">Coverage</div>
                    <div className="mt-1 text-amber-200">{connectorCoverageLabel(connector)}</div>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-1.5 border-t border-[#273045] pt-3">
                  <span className={cn("border px-2 py-1 font-mono text-[9px] uppercase", capabilities?.discover ? "border-cyan-400/20 bg-cyan-400/[0.06] text-cyan-200" : "border-slate-600/30 text-slate-600")}>Discover</span>
                  <span className="border border-slate-600/30 px-2 py-1 font-mono text-[9px] uppercase text-slate-600" title="Provider collectors do not authorize pre-action requests">Authorize</span>
                  <span className={cn("border px-2 py-1 font-mono text-[9px] uppercase", capabilities?.prove ? "border-emerald-400/20 bg-emerald-400/[0.06] text-emerald-200" : "border-slate-600/30 text-slate-600")}>Prove</span>
                  <span className="ml-auto border border-[#343e53] px-2 py-1 font-mono text-[9px] uppercase text-slate-500">{selected ? "Manage connection" : "Inspect connection"}</span>
                </div>
              </button>
            );
          })}
        </div>
      ) : (
        <div className="mt-4 border border-dashed border-[#33405a] bg-[#0e141f] p-6 text-sm text-slate-400">
          {connectors.length
            ? "No configured connector matches this category."
            : "No connector is configured. Add one below to begin collecting provider evidence."}
        </div>
      )}

      {filteredAvailable.length ? (
        <details className="mt-5 border-t border-[#283247] pt-4">
          <summary className="cursor-pointer list-none text-xs font-semibold text-slate-300">Available source catalog · {filteredAvailable.length}</summary>
          <div className="pt-3">
          <div className="flex flex-wrap items-end justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-200">Available integrations</h3>
              <p className="mt-1 text-[11px] text-slate-600">Implemented adapters that have never been configured for this tenant.</p>
            </div>
            <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-slate-600">Never configured</span>
          </div>
          <div className="mt-3 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
            {filteredAvailable.map((provider) => {
              const readiness = deriveConnectorReadiness(provider);
              const capabilities = deriveConnectorCapabilities(provider);
              return (
                <article key={provider.provider_key} className="border border-dashed border-[#30394d] bg-[#0d121b] p-3">
                  <div className="flex items-start justify-between gap-2">
                    <div>
                      <p className="text-xs font-semibold text-slate-300">{provider.display_name}</p>
                      <p className="mt-1 text-[9px] uppercase tracking-[0.1em] text-slate-600">{customerConnectorCategory(provider.category, provider.provider_key)}</p>
                    </div>
                    <Badge className="rounded-sm border-[#3a455c] bg-transparent font-mono text-[9px] uppercase text-slate-500">{providerConnectionLabel(provider)}</Badge>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    <span className={cn("border px-2 py-1 text-[9px]", capabilities.discover ? "border-cyan-400/20 text-cyan-200" : "border-slate-600/30 text-slate-600")}>Discover</span>
                    <span className="border border-slate-600/30 px-2 py-1 text-[9px] text-slate-600">Authorize</span>
                    <span className={cn("border px-2 py-1 text-[9px]", capabilities.prove ? "border-emerald-400/20 text-emerald-200" : "border-slate-600/30 text-slate-600")}>Prove</span>
                  </div>
                  <p className="mt-3 text-[10px] leading-4 text-slate-600">{readiness.assertion}</p>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    className="mt-3 w-full"
                    aria-label={`Connect ${friendlyProviderName(provider)}`}
                    onClick={() => onConfigureProvider?.(provider)}
                  >
                    Connect {friendlyProviderName(provider)}
                  </Button>
                </article>
              );
            })}
          </div>
          </div>
        </details>
      ) : null}

      {filteredPlanned.length ? (
        <details className="mt-5 border border-[#30394d] bg-[#0d121b]">
          <summary className="cursor-pointer list-none px-4 py-3 text-xs font-semibold text-slate-400 marker:hidden">Planned / unsupported · {filteredPlanned.length}</summary>
          <div className="grid gap-2 border-t border-[#30394d] p-3 md:grid-cols-2 xl:grid-cols-3">
            {filteredPlanned.map((provider) => (
              <div key={provider.provider_key} className="border border-dashed border-[#30394d] p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-medium text-slate-400">{provider.display_name}</span>
                  <span className="font-mono text-[9px] uppercase text-violet-300">Planned</span>
                </div>
                <p className="mt-2 text-[10px] leading-4 text-slate-600">{provider.stub_reason || "Unsupported today."}</p>
                <p className="mt-2 text-[10px] font-semibold text-amber-200">Does not contribute to Control Coverage.</p>
              </div>
            ))}
          </div>
        </details>
      ) : null}
    </section>
  );
}

function CoverageAssertion({
  icon: Icon,
  label,
  value,
}: {
  icon: typeof Radar;
  label: string;
  value?: ConnectorCoverageState;
}) {
  const normalized = value || "unknown";
  return (
    <div className="border-l border-[#313b50] pl-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.1em] text-slate-500">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        {label}
      </div>
      <div className={cn("mt-2 inline-flex border px-2 py-1 text-[10px] font-semibold", COVERAGE_TONE[normalized])}>
        {coverageLabel(normalized)}
      </div>
    </div>
  );
}

function CoveragePath({
  eyebrow,
  title,
  description,
  mode,
  discovery,
  authorization,
  prove,
  tone,
}: {
  eyebrow: string;
  title: string;
  description: string;
  mode: string;
  discovery?: ConnectorCoverageState;
  authorization?: ConnectorCoverageState;
  prove?: ConnectorCoverageState;
  tone: "amber" | "mint";
}) {
  return (
    <article className="relative overflow-hidden border border-[#293348] bg-[#0e141e] p-4">
      <div className={cn("absolute inset-y-0 left-0 w-0.5", tone === "mint" ? "bg-emerald-300" : "bg-amber-300")} />
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-slate-600">{eyebrow}</div>
          <h4 className="mt-1 text-sm font-semibold text-slate-100">{title}</h4>
          <p className="mt-1 max-w-xl text-[11px] leading-5 text-slate-500">{description}</p>
        </div>
        <Badge className={cn("rounded-sm font-mono text-[9px] uppercase", tone === "mint" ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-200" : "border-amber-400/25 bg-amber-400/10 text-amber-200")}>
          {mode}
        </Badge>
      </div>
      <div className="mt-4 grid grid-cols-3 gap-2 border-t border-[#252e40] pt-4">
        <CoverageAssertion icon={Radar} label="Discover" value={discovery} />
        <CoverageAssertion icon={KeyRound} label="Authorize" value={authorization} />
        <CoverageAssertion icon={ScrollText} label="Prove" value={prove} />
      </div>
    </article>
  );
}

function EvaluationProgress() {
  const stages = ["Requested", "Collecting", "Normalizing", "Evidence persisted"];
  return (
    <div role="status" aria-live="polite" className="border border-brand-400/25 bg-brand-400/[0.06] p-3">
      <div className="flex items-center gap-2 text-xs font-semibold text-brand-200">
        <RefreshCw className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />
        Evaluating
      </div>
      <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
        {stages.map((stage, index) => (
          <div key={stage} className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider text-slate-500">
            <span className={cn("h-1.5 w-1.5 rounded-full", index === 0 ? "animate-pulse bg-brand-300" : "bg-slate-700")} />
            {stage}
          </div>
        ))}
      </div>
    </div>
  );
}

function EvidenceLink({
  evidenceId,
  integrityStatus,
  label = "Open in Auditor",
}: {
  evidenceId?: string | null;
  integrityStatus?: string | null;
  label?: string;
}) {
  if (!canLinkVerifiedEvidence(evidenceId, integrityStatus)) {
    return <span className="text-[11px] text-slate-600">No verified evidence link</span>;
  }
  return (
    <Link
      href={`/auditor?evidence_id=${encodeURIComponent(evidenceId)}`}
      className="inline-flex items-center gap-1.5 text-[11px] font-semibold text-cyan-300 hover:text-cyan-200"
    >
      {label}
      <ExternalLink className="h-3 w-3" aria-hidden="true" />
    </Link>
  );
}

function ConnectorProofWorkspace({
  connector,
  evaluation,
  evaluating,
  evaluationError,
  onEvaluate,
}: {
  connector: Connector;
  evaluation: ConnectorEvaluation | null;
  evaluating: boolean;
  evaluationError: string | null;
  onEvaluate: (connectorId: string) => Promise<void>;
}) {
  const selectedEvaluation = selectMatchingEvaluation(connector.id, evaluation);
  const connectorProof = selectedEvaluation?.connector_path.prove || "unknown";
  const browserProof = selectedEvaluation?.browser_path.prove || "unknown";
  const action = selectedEvaluation?.latest_browser_action;
  const browserPresentation = deriveGmailBrowserPresentation(action?.control_mode);
  const hasExplicitInlineAction = browserPresentation.isInline;
  const hasTelemetryOnlyAction = browserPresentation.isTelemetryOnly;
  const isBlocked = browserPresentation.isBlocked;
  const actionEvidenceId = action?.evidence_node_ids?.[0];
  const rootEvidenceId = selectedEvaluation?.evidence.root_id || selectedEvaluation?.latest_pull?.evidence_root_id;
  const signalCount = selectedEvaluation?.latest_pull?.normalized_signal_count ?? connector.last_signal_count ?? 0;
  const providerKey = (connector.provider_key || connector.connector_type).toLowerCase();
  const isGmail = providerKey === "gmail";
  const providerLabel = isGmail ? "Gmail API" : sentenceCase(providerKey);
  const normalizedCategories = Array.from(new Set(
    (selectedEvaluation?.evidence.items || []).map((item) => item.signal_type).filter(Boolean),
  )).slice(0, 6);
  const browserMode = browserPresentation.mode;
  const browserAuthorization = hasExplicitInlineAction
    ? selectedEvaluation?.browser_path.authorization
    : "unknown";

  return (
    <section aria-labelledby="proof-workspace-title" className="grid min-w-0 gap-5 p-4 md:p-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(330px,.65fr)]">
      <div className="min-w-0 space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-[#283247] pb-4">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-brand-300">Selected proof workspace</div>
            <h2 id="proof-workspace-title" className="mt-2 text-2xl font-semibold tracking-tight text-slate-50">{connector.name}</h2>
            <p className="mt-1 text-sm text-slate-500">
              {connector.provider_key || connector.connector_type} · Last evidence-backed result {formatDate(selectedEvaluation?.latest_pull?.created_at || connector.last_run_at)}
            </p>
          </div>
          <Button onClick={() => onEvaluate(connector.id)} disabled={evaluating || !connector.enabled || connector.is_stub}>
            <RefreshCw className={cn("mr-2 h-4 w-4", evaluating && "animate-spin")} aria-hidden="true" />
            Run live evaluation
          </Button>
        </div>

        {evaluationError ? (
          <div role="alert" className="flex items-start gap-3 border border-rose-400/30 bg-rose-400/[0.07] p-3 text-sm text-rose-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-300" aria-hidden="true" />
            <div>
              <div className="font-semibold">Latest evaluation failed</div>
              <p className="mt-1 text-xs leading-5 text-rose-200/75">{evaluationError}</p>
              {selectedEvaluation ? <p className="mt-1 text-[10px] text-slate-500">The prior verified result remains visible below.</p> : null}
            </div>
          </div>
        ) : null}

        {selectedEvaluation?.latest_pull?.error ? (
          <div role="alert" className="flex items-start gap-3 border border-amber-400/30 bg-amber-400/[0.07] p-3 text-sm text-amber-100">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" aria-hidden="true" />
            <div>
              <div className="font-semibold">Persisted connector pull error</div>
              <p className="mt-1 text-xs leading-5 text-amber-200/75">{selectedEvaluation.latest_pull.error}</p>
            </div>
          </div>
        ) : null}

        {evaluating ? <EvaluationProgress /> : null}

        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {[
            [CircleDot, "Pull state", sentenceCase(selectedEvaluation?.latest_pull?.status || connector.last_pull_status || "unknown")],
            [Database, "Normalized signals", String(signalCount)],
            [Fingerprint, "Evidence integrity", sentenceCase(selectedEvaluation?.evidence.integrity_status || "unknown")],
            [ShieldCheck, "Credential", connector.has_secrets ? "Present" : "Missing"],
          ].map(([Icon, label, value]) => {
            const Glyph = Icon as typeof CircleDot;
            return (
              <div key={String(label)} className="border border-[#293348] bg-[#101620] p-3">
                <div className="flex items-center gap-2 text-[10px] uppercase tracking-[0.1em] text-slate-600">
                  <Glyph className="h-3.5 w-3.5 text-slate-500" aria-hidden="true" />
                  {String(label)}
                </div>
                <div className="mt-2 truncate font-mono text-sm text-slate-200">{String(value)}</div>
              </div>
            );
          })}
        </div>

        <div className="flex flex-wrap items-center gap-2 border border-[#293348] bg-[#0e141e] px-3 py-2.5">
          <span className="text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-600">Source categories</span>
          {normalizedCategories.length ? normalizedCategories.map((category) => (
            <span key={category} className="border border-cyan-400/20 bg-cyan-400/[0.06] px-2 py-1 font-mono text-[9px] text-cyan-200">
              {category}
            </span>
          )) : <span className="text-[11px] text-amber-200">Unknown</span>}
        </div>

        <div>
          <div className="mb-3 flex items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-100">Governance paths</h3>
              <p className="mt-1 text-[11px] text-slate-500">Connector observation and browser enforcement are asserted independently.</p>
            </div>
            <EvidenceLink evidenceId={rootEvidenceId} integrityStatus={selectedEvaluation?.evidence.integrity_status} />
          </div>
          <div className="space-y-3">
            <CoveragePath
              eyebrow="Provider telemetry path"
              title={`${providerLabel} connector`}
              description={isGmail
                ? "Read-only provider collection. It can discover metadata and prove persisted observations after the action; it cannot authorize a send."
                : "Provider collection coverage is based only on persisted pull and evidence records; no pre-action authority is inferred."}
              mode={isGmail ? "Monitor-only" : sentenceCase(selectedEvaluation?.connector_path.mode || "Unknown")}
              discovery={selectedEvaluation?.connector_path.discovery}
              authorization={selectedEvaluation?.connector_path.authorization || "not_covered"}
              prove={connectorProof}
              tone="amber"
            />
            <CoveragePath
              eyebrow="Pre-action browser path"
              title={isGmail ? "Managed Chrome control" : "Browser control path"}
              description={isGmail
                ? "Coverage exists only for an observed mail.google.com action intercepted by the managed Hawk extension before submission."
                : "Browser authorization is Unknown until a canonical provider domain and an explicit persisted inline decision are observed."}
              mode={browserMode}
              discovery={selectedEvaluation?.browser_path.discovery}
              authorization={browserAuthorization}
              prove={browserProof}
              tone={hasExplicitInlineAction ? "mint" : "amber"}
            />
          </div>
        </div>

        <details className="border border-[#293348] bg-[#0e141d]">
          <summary className="cursor-pointer list-none px-4 py-3 text-xs font-semibold text-slate-300 marker:hidden">
            Coverage boundaries
          </summary>
          <div className="border-t border-[#293348] px-4 py-3">
            <ul className="space-y-2 text-[11px] leading-5 text-slate-500">
              {(selectedEvaluation?.limitations || [
                "Connector telemetry does not authorize actions before execution.",
                "Unmanaged browsers, Gmail mobile and desktop clients, and direct Gmail API actions remain outside this browser-inline path.",
              ]).map((limitation) => (
                <li key={limitation} className="flex gap-2">
                  <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-amber-300" />
                  {limitation}
                </li>
              ))}
            </ul>
          </div>
        </details>
      </div>

      <aside className="min-w-0 border border-[#293348] bg-[#0c121b]">
        <div className="border-b border-[#293348] p-4">
          <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan-300">Latest action evaluation</div>
          <h3 className="mt-2 text-base font-semibold text-slate-100">Evidence timeline</h3>
        </div>

        <div className="space-y-0 p-4">
          <article className="relative border-l border-[#364158] pb-6 pl-5">
            <span className="absolute -left-1.5 top-0 h-3 w-3 rounded-full border-2 border-[#0c121b] bg-amber-300" />
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <div className="text-xs font-semibold text-slate-200">Connector pull</div>
                <div className="mt-1 font-mono text-[9px] text-slate-600">{formatDate(selectedEvaluation?.latest_pull?.created_at)}</div>
              </div>
              <Badge className="rounded-sm border-amber-400/25 bg-amber-400/10 font-mono text-[9px] uppercase text-amber-200">
                {sentenceCase(selectedEvaluation?.latest_pull?.status || "Unknown")}
              </Badge>
            </div>
            <dl className="mt-3 space-y-2 text-[11px]">
              <div className="flex justify-between gap-3"><dt className="text-slate-600">Signals</dt><dd className="font-mono text-slate-300">{signalCount}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-slate-600">Correlation</dt><dd className="max-w-[190px] truncate font-mono text-slate-400">{selectedEvaluation?.latest_pull?.correlation_id || "Unknown"}</dd></div>
              <div className="flex justify-between gap-3"><dt className="text-slate-600">Evidence root</dt><dd className="max-w-[190px] truncate font-mono text-slate-400">{rootEvidenceId || "Unknown"}</dd></div>
            </dl>
            <div className="mt-3"><EvidenceLink evidenceId={rootEvidenceId} integrityStatus={selectedEvaluation?.evidence.integrity_status} label="Inspect connector proof" /></div>
          </article>

          <article className="relative border-l border-[#364158] pl-5">
            <span className={cn("absolute -left-1.5 top-0 h-3 w-3 rounded-full border-2 border-[#0c121b]", isBlocked ? "bg-rose-400" : hasExplicitInlineAction ? "bg-emerald-300" : hasTelemetryOnlyAction ? "bg-amber-300" : "bg-slate-600")} />
            {action && hasExplicitInlineAction ? (
              <>
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="text-xs font-semibold text-slate-200">Managed Chrome action</div>
                    <div className="mt-1 font-mono text-[9px] text-slate-600">{formatDate(action.created_at)}</div>
                  </div>
                  <Badge className={cn("rounded-sm font-mono text-[9px] uppercase", isBlocked ? "border-rose-400/30 bg-rose-400/10 text-rose-200" : "border-emerald-400/25 bg-emerald-400/10 text-emerald-200")}>
                    {isBlocked ? "Pre-Action Blocked" : action.decision_badge || sentenceCase(action.decision)}
                  </Badge>
                </div>
                <dl className="mt-3 space-y-2 text-[11px]">
                  <div className="flex justify-between gap-3"><dt className="text-slate-600">Control mode</dt><dd className="font-mono text-slate-300">{action.control_mode}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-slate-600">Action</dt><dd className="text-right text-slate-300">{action.action_type || "Unknown"}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-slate-600">Policy reason</dt><dd className="max-w-[190px] text-right text-slate-300">{action.reason || "Unknown"}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-slate-600">Source</dt><dd className="text-right text-slate-300">{action.source || "browser"} · {action.domain || action.application || "Unknown"}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-slate-600">User</dt><dd className="max-w-[190px] truncate text-right text-slate-300">{action.user || "Unknown"}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-slate-600">Integrity</dt><dd className="text-right text-slate-300">{sentenceCase(action.evidence_integrity_status)}</dd></div>
                  <div className="flex justify-between gap-3"><dt className="text-slate-600">Correlation</dt><dd className="max-w-[190px] truncate font-mono text-slate-400">{action.correlation_id || "Unknown"}</dd></div>
                </dl>
                <div className="mt-3">
                  <EvidenceLink
                    evidenceId={actionEvidenceId}
                    integrityStatus={action.evidence_integrity_status}
                    label="Inspect browser proof"
                  />
                </div>
              </>
            ) : (
              <div className="border border-dashed border-[#303a4f] bg-[#0e141e] p-4">
                <ShieldAlert className="h-5 w-5 text-amber-300" aria-hidden="true" />
                <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                  <div className="text-xs font-semibold text-slate-200">No inline Gmail action observed</div>
                  {action ? (
                    <Badge className={cn(
                      "rounded-sm font-mono text-[9px] uppercase",
                      hasTelemetryOnlyAction
                        ? "border-amber-400/25 bg-amber-400/10 text-amber-200"
                        : "border-slate-500/30 bg-slate-500/10 text-slate-300",
                    )}>
                      {hasTelemetryOnlyAction ? "Telemetry-only" : "Unknown"}
                    </Badge>
                  ) : null}
                </div>
                <p className="mt-2 text-[11px] leading-5 text-slate-500">
                  Managed Chrome authorization remains Unknown until Hawk receives an explicit persisted pre-action decision.
                </p>
                {action ? (
                  <>
                    <dl className="mt-3 space-y-2 border-t border-[#293348] pt-3 text-[11px]">
                      <div className="flex justify-between gap-3"><dt className="text-slate-600">Observed mode</dt><dd className={cn("font-mono", hasTelemetryOnlyAction ? "text-amber-200" : "text-slate-300")}>{action.control_mode}</dd></div>
                      <div className="flex justify-between gap-3"><dt className="text-slate-600">Action</dt><dd className="text-right text-slate-300">{action.action_type || "Unknown"}</dd></div>
                      <div className="flex justify-between gap-3"><dt className="text-slate-600">Observed</dt><dd className="font-mono text-right text-slate-400">{formatDate(action.created_at)}</dd></div>
                    </dl>
                    <div className="mt-3">
                      <EvidenceLink
                        evidenceId={actionEvidenceId}
                        integrityStatus={action.evidence_integrity_status}
                        label="Inspect telemetry evidence"
                      />
                    </div>
                  </>
                ) : null}
              </div>
            )}
          </article>
        </div>
      </aside>
    </section>
  );
}

export function ConnectorControlRoom(props: ConnectorControlRoomProps) {
  const selectedConnector = props.connectors.find((connector) => connector.id === props.selectedConnectorId) || null;
  const [setupOpen, setSetupOpen] = useState(false);
  const setupRef = useRef<HTMLDetailsElement | null>(null);

  const connectionGuide = <>{props.connectionGuide ? (
    <details className="border-b border-[#293348] bg-[#0b1018]">
      <summary className="cursor-pointer list-none px-4 py-4 text-sm font-semibold text-slate-200 marker:hidden md:px-6">
        Connection setup guide
      </summary>
      <div className="border-t border-[#293348] p-4 md:p-6">{props.connectionGuide}</div>
    </details>
  ) : null}</>;

  function configureProvider(provider: ConnectorProviderCatalogItem) {
    props.onConfigureProvider?.(provider);
    setSetupOpen(true);
    window.requestAnimationFrame(() => setupRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  return (
    <div
      className="overflow-hidden rounded-xl border border-[#2a3348] bg-[#0a0f17] shadow-[0_22px_80px_rgba(0,0,0,.28)]"
      style={{
        backgroundImage: "linear-gradient(rgba(64,78,105,.07) 1px, transparent 1px), linear-gradient(90deg, rgba(64,78,105,.07) 1px, transparent 1px)",
        backgroundSize: "30px 30px",
      }}
    >
      <header className="relative overflow-hidden border-b border-[#293348] bg-[#101620]/95 px-4 py-5 md:px-6">
        <div className="absolute inset-y-0 left-0 w-1 bg-gradient-to-b from-brand-300 via-amber-400 to-cyan-300" />
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.24em] text-brand-300">Integrations · observation · control evidence</div>
            <h1 className="mt-2 text-2xl font-semibold tracking-tight text-slate-50">Integrations</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              See what each integration can observe and what Hawk can control. Connected does not imply controlled.
            </p>
            <div className="mt-3 flex flex-wrap gap-2 text-[10px] uppercase tracking-[0.12em] text-slate-500"><span className="rounded-full border border-cyan-400/20 px-2 py-1">What Hawk can observe</span><span className="rounded-full border border-orange-400/20 px-2 py-1">What Hawk can control</span></div>
          </div>
          <div className="flex items-center gap-2 border border-[#2b354a] bg-[#0b1018] px-3 py-2">
            <ShieldCheck className="h-4 w-4 text-emerald-300" aria-hidden="true" />
            <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-400">Evidence-backed status</span>
          </div>
        </div>
      </header>

      {props.loadState === "loading" ? <div className="border-b border-[#293348] px-4 py-5 text-sm text-slate-400 md:px-6" role="status">Loading integration status…</div> : null}
      {props.loadState === "error" ? <div className="border-b border-amber-400/20 bg-amber-400/[0.06] px-4 py-4 text-sm text-amber-100 md:px-6"><p className="font-semibold">Integration status unavailable</p><p className="mt-1 text-xs text-amber-100/70">{props.loadError || "Retry to load connected sources."}</p></div> : null}

      {props.loadState !== "error" ? <ConnectorFleet
        connectors={props.connectors}
        providers={props.providers}
        selectedConnectorId={props.selectedConnectorId}
        onSelect={props.onSelect}
        onConfigureProvider={configureProvider}
      /> : null}

      {connectionGuide}

      {selectedConnector ? (
        <ConnectorProofWorkspace
          connector={selectedConnector}
          evaluation={props.evaluation}
          evaluating={props.evaluating}
          evaluationError={props.evaluationError}
          onEvaluate={props.onEvaluate}
        />
      ) : (
        <div className="grid min-h-64 place-items-center p-8 text-center">
          <div>
            <ShieldCheck className="mx-auto h-7 w-7 text-slate-600" aria-hidden="true" />
            <h2 className="mt-3 text-sm font-semibold text-slate-300">Select a connector to inspect its proof path</h2>
            <p className="mt-2 text-xs text-slate-600">Nothing is marked covered until persisted evidence supports it.</p>
          </div>
        </div>
      )}

      <details ref={setupRef} open={setupOpen} onToggle={(event) => setSetupOpen(event.currentTarget.open)} className="group border-t border-[#293348] bg-[#0d121b]">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-4 marker:hidden md:px-6">
          <span className="flex items-center gap-2 text-sm font-semibold text-slate-200">
            <Plus className="h-4 w-4 text-brand-300 transition group-open:rotate-45" aria-hidden="true" />
            Add connector
          </span>
          <span className="text-[11px] text-slate-600">Credentials are write-only and never shown here.</span>
        </summary>
        <div className="border-t border-[#293348] p-4 md:p-6">{props.setupPanel}</div>
      </details>
    </div>
  );
}
