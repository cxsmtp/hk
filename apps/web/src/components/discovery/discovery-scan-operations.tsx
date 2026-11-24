"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { Activity, Check, ChevronDown, ChevronRight, CircleAlert, Laptop, Play, RefreshCw, RotateCcw, ScanSearch, ShieldCheck, Square } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { DeepScanCoverage, DeepScanPreflight, DeepScanPreflightRequest, DiscoveryScanDiagnostics, DiscoveryScanEstimate, DiscoveryScanProgress, DiscoveryScanResults, EndpointMetadataInventoryRun, HmairCollectorSummary, HmairDiscoveryScan, HmairTargetSummary } from "@/lib/types";
import { DiscoveryDemoReadiness } from "./discovery-demo-readiness";
import { ShadowAIAssessment } from "./shadow-ai-assessment";
import { DiscoveryEmpty, DiscoveryWorkspaceFrame, formatDiscoveryLabel, formatDiscoveryTime, TruthBadge } from "./discovery-workspace-frame";

const STAGES = ["Scope", "Sources", "Permissions", "Safety", "Estimate", "Progress", "Results", "Review", "Ownership", "Monitor"];

const _DISCOVERY_SURFACES = [
  {
    name: "Browser",
    summary: "AI web apps, prompts/actions where the managed extension can see them, and account hints.",
    status: "Connected only when the trusted extension ID has a fresh heartbeat.",
    lastEvidence: "Extension heartbeat and browser prompt/action event time.",
    action: "Connect source or test browser capture",
    limitation: "Provider-native verified model, usage, and spend require provider/admin signals.",
  },
  {
    name: "Endpoint",
    summary: "Installed AI apps, local coding clients, process/network metadata, and enrolled-device inventory.",
    status: "Requires enrolled Mac or Windows endpoint identity.",
    lastEvidence: "Signed endpoint heartbeat and metadata inventory receipt.",
    action: "Enroll endpoint or run inventory",
    limitation: "Command enforcement remains monitor-only until policy freshness and signed command receipts are current.",
  },
  {
    name: "MCP & agents",
    summary: "Governed MCP servers, tools, tool calls, AI agent identity, action outcome, and policy decision.",
    status: "Requires MCP gateway session or runtime connector.",
    lastEvidence: "MCP tool-list, allow/block receipt, and runtime invocation timestamp.",
    action: "Generate MCP config",
    limitation: "Ungoverned local tools remain unknown until routed through the gateway or runtime source.",
  },
  {
    name: "GitHub repositories",
    summary: "Repository access, approved repo scope, AI client using the repo, and read/write/PR decisions.",
    status: "Requires GitHub App or governed MCP repository session.",
    lastEvidence: "Repository inventory receipt, selected-repo approval, or MCP GitHub decision.",
    action: "Connect GitHub or approve one repo",
    limitation: "Personal repositories stay blocked unless explicitly approved for the scoped demo.",
  },
  {
    name: "SaaS apps",
    summary: "Enterprise SaaS AI surfaces and app-level activity when a customer-owned connector is present.",
    status: "Unavailable until a SaaS connector is authorized.",
    lastEvidence: "Connector health and last ingestion completion.",
    action: "Connect source",
    limitation: "No SaaS absence claim is made without an authoritative denominator.",
  },
  {
    name: "Identity / SCIM",
    summary: "Users, groups, departments, managers, service accounts, and assignment denominators.",
    status: "Unavailable until IdP or SCIM source is connected.",
    lastEvidence: "Directory sync completion and group membership snapshot.",
    action: "Connect source",
    limitation: "User and department coverage may remain unknown without SCIM/IdP authority.",
  },
  {
    name: "Cloud",
    summary: "Cloud AI services, model endpoints, service principals, workload identities, and billing projects.",
    status: "Unavailable until cloud source is authorized.",
    lastEvidence: "Cloud inventory or billing export snapshot.",
    action: "Connect source",
    limitation: "Provider-native verified cloud usage needs customer-owned cloud admin access.",
  },
  {
    name: "M365 / Teams",
    summary: "Teams meeting AI, note-takers, Copilot/Graph signals, and tenant collaboration context.",
    status: "Unavailable until Microsoft Graph consent is provided.",
    lastEvidence: "Graph connector health and authorized Teams test event.",
    action: "Connect source",
    limitation: "Meeting note-taker blocking requires live tenant policy and Teams evidence.",
  },
];

const DEFAULT_DISCOVERY_BLIND_SPOTS = [
  "SaaS apps without a customer-owned connector",
  "Cloud projects without billing or inventory export",
  "Identity / SCIM membership without an IdP source",
  "Provider-native verified usage, model, and spend without admin APIs",
  "Ungoverned MCP, local agent, and desktop activity outside connected control paths",
];

function ToggleRow({ checked, onChange, title, detail, disabled }: { checked: boolean; onChange: (value: boolean) => void; title: string; detail: string; disabled?: boolean }) {
  return <label className={`flex cursor-pointer items-start gap-3 rounded-xl border p-3 transition ${checked ? "border-cyan-300/20 bg-cyan-300/[0.04]" : "border-white/[0.06] bg-white/[0.02]"} ${disabled ? "cursor-not-allowed opacity-50" : ""}`}><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} disabled={disabled} className="mt-0.5 accent-cyan-400"/><span><span className="block text-xs font-medium text-slate-200">{title}</span><span className="mt-1 block text-[10px] leading-4 text-slate-500">{detail}</span></span></label>;
}

function parseExclusions(value: string): string[] {
  return [...new Set(value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean))].slice(0, 256);
}

export function DiscoveryScanOperations() {
  const [scans, setScans] = useState<HmairDiscoveryScan[]>([]);
  const [targets, setTargets] = useState<HmairTargetSummary[]>([]);
  const [collectors, setCollectors] = useState<HmairCollectorSummary[]>([]);
  const [selectedTargets, setSelectedTargets] = useState<string[]>([]);
  const [selectedCollectors, setSelectedCollectors] = useState<string[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<string>("");
  const [estimate, setEstimate] = useState<DiscoveryScanEstimate | null>(null);
  const [progress, setProgress] = useState<DiscoveryScanProgress | null>(null);
  const [results, setResults] = useState<DiscoveryScanResults | null>(null);
  const [diagnostics, setDiagnostics] = useState<DiscoveryScanDiagnostics | null>(null);
  const [deepScanPreflight, setDeepScanPreflight] = useState<DeepScanPreflight | null>(null);
  const [deepScanCoverage, setDeepScanCoverage] = useState<DeepScanCoverage | null>(null);
  const [deepScanAuthorizationReference, setDeepScanAuthorizationReference] = useState("");
  const deepScanRequestedMode: "partial" = "partial";
  const [metadataInventoryRuns, setMetadataInventoryRuns] = useState<EndpointMetadataInventoryRun[]>([]);
  const [metadataInventoryError, setMetadataInventoryError] = useState<string | null>(null);
  const [safetyProfile, setSafetyProfile] = useState<"read_only" | "metadata_only">("read_only");
  const [dryRun, setDryRun] = useState(false);
  const [exclusionsInput, setExclusionsInput] = useState("raw_content\ncredentials\nsource_files\ndatabase_records");
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const inventoryRequest = api.listEndpointMetadataInventoryRuns().then((payload) => {
        setMetadataInventoryError(null);
        return payload;
      }).catch((error) => {
        setMetadataInventoryError(error instanceof Error ? error.message : "Endpoint inventory is not enabled for this tenant.");
        return { items: [] as EndpointMetadataInventoryRun[] };
      });
      const [scanPayload, targetPayload, collectorPayload, inventoryPayload] = await Promise.all([
        api.listHmairScans({ limit: 100 }),
        api.listHmairTargets(),
        api.listHmairCollectors(),
        inventoryRequest,
      ]);
      setScans(scanPayload.items || []);
      setTargets(targetPayload.items || []);
      setCollectors(collectorPayload.items || []);
      setMetadataInventoryRuns(inventoryPayload.items || []);
      setSelectedTargets((current) => current.length ? current : (targetPayload.items || []).filter((item) => item.active_scan_allowed).map((item) => item.target_id));
      setSelectedCollectors((current) => current.length ? current : (collectorPayload.items || []).filter((item) => item.enabled).map((item) => item.collector_id));
      setSelectedScanId((current) => current || scanPayload.items?.[0]?.scan_id || "");
    } catch (error) {
      setScans([]); setTargets([]); setCollectors([]); setMetadataInventoryRuns([]);
      toast.error(error instanceof Error ? error.message : "Unable to load scan operations");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!selectedScanId) { setProgress(null); setResults(null); setDiagnostics(null); setDeepScanCoverage(null); return; }
    let cancelled = false;
    Promise.all([
      api.getHmairScanProgress(selectedScanId).catch(() => null),
      api.getHmairScanResults(selectedScanId).catch(() => null),
      api.getHmairScanDiagnostics(selectedScanId).catch(() => null),
      api.getHmairDeepScanCoverage(selectedScanId).catch(() => null),
    ]).then(([progressPayload, resultPayload, diagnosticPayload, deepScanCoveragePayload]) => {
      if (!cancelled) { setProgress(progressPayload); setResults(resultPayload); setDiagnostics(diagnosticPayload); setDeepScanCoverage(deepScanCoveragePayload); }
    });
    return () => { cancelled = true; };
  }, [selectedScanId, scans]);

  useEffect(() => {
    setDeepScanPreflight(null);
  }, [selectedTargets, selectedCollectors, deepScanAuthorizationReference]);

  const selectedScan = scans.find((scan) => scan.scan_id === selectedScanId) || null;
  const canEstimate = selectedTargets.length > 0 && selectedCollectors.length > 0;
  const deepScanPreflightRequest: DeepScanPreflightRequest = {
    target_ids: selectedTargets,
    collector_ids: selectedCollectors,
    required_target_ids: selectedTargets,
    time_window_minutes: 30,
    customer_authorization_reference: deepScanAuthorizationReference.trim(),
    requested_mode: deepScanRequestedMode,
  };
  const canPreflightDeepScan = canEstimate && deepScanAuthorizationReference.trim().length > 0;
  const canLaunchDeepScan = Boolean(
    deepScanPreflight && deepScanPreflight.ready_assignment_count > 0,
  );
  const exhaustive = results?.exhaustive_claim_permitted === true;
  const activeCount = scans.filter((scan) => ["queued", "running", "partially_complete"].includes(scan.status)).length;
  const latestMetadataInventory = metadataInventoryRuns[0] || null;
  const sourceReadyCount = new Set(targets.filter((target) => target.active_scan_allowed).map((target) => target.target_type)).size;
  const collectorReadyCount = collectors.filter((collector) => collector.enabled).length;
  const latestEvidenceAt = selectedScan?.completed_at || selectedScan?.started_at || null;
  const scanPrimaryLabel = canPreflightDeepScan ? "Run AI Discovery" : canEstimate ? "Add authorization and run" : "Connect source first";
  const scanPrimaryHelp = canEstimate
    ? "This starts with a readiness check and only scans the selected connected sources."
    : "Connect or enroll at least one source before running a scan.";
  const simpleSourceCards = [
    {
      name: "Browser",
      state: targets.some((target) => target.target_type === "browser_tenant") ? "Ready to scan" : "Connect source",
      detail: "Web AI prompts/actions where the managed extension can see them.",
      href: "/ai-tools-usage?tab=accounts",
    },
    {
      name: "Endpoint",
      state: latestMetadataInventory || targets.some((target) => target.target_type === "endpoint_group") ? "Ready to scan" : "Enroll endpoint",
      detail: "Installed AI apps, desktop clients, process/network metadata, and signed device heartbeat.",
      href: "/surface-coverage",
    },
    {
      name: "MCP & agents",
      state: targets.some((target) => target.target_type === "mcp_environment" || target.target_type === "runtime_environment") ? "Ready to scan" : "Connect gateway",
      detail: "Governed tools, MCP calls, AI agents, runtime actions, and policy decisions.",
      href: "/ai-tools-usage?tab=mcp",
    },
    {
      name: "GitHub / SaaS / Cloud",
      state: targets.some((target) => ["github_org", "github_repository", "saas_tenant", "cloud_account"].includes(target.target_type)) ? "Ready to scan" : "Connect source",
      detail: "Repository inventory, SaaS apps, cloud AI services, identities, and admin denominators.",
      href: "/integrations",
    },
  ];
  const discoveryFindingCards = [
    ["AI users / identities", results?.breadth.active_users ?? "—", "Human, service, or workload identities observed in the selected evidence window."],
    ["Shadow AI", results?.breadth.shadow_ai ?? "—", "AI use inferred from connected browser, endpoint, runtime, or SaaS sources."],
    ["Models", results?.breadth.models ?? "—", "Models observed from client, gateway, runtime, or provider-native verified signals."],
    ["Agents & runtimes", results ? results.breadth.agents + results.breadth.runtimes : "—", "Agents, runtime workloads, and execution paths linked to the scan."],
    ["MCP & tools", results?.breadth.mcp ?? "—", "MCP servers/tools and governed tool calls observed through connected paths."],
    ["GitHub repositories", results?.breadth.developer_ai ?? "—", "Developer-AI and repository-control evidence from GitHub or MCP sources."],
    ["SaaS AI", results?.breadth.saas_ai ?? "—", "SaaS AI activity from authorized SaaS connectors only."],
    ["Unknown AI", results?.breadth.unknown_candidates ?? "—", "Investigation candidates where evidence exists but identity or authority is unresolved."],
  ];
  const discoveryBlindSpots = (results?.breadth.blind_spots.length ? results.breadth.blind_spots.map(formatDiscoveryLabel) : DEFAULT_DISCOVERY_BLIND_SPOTS);

  const toggle = (value: string, selected: string[], setter: (value: string[]) => void) => setter(selected.includes(value) ? selected.filter((item) => item !== value) : [...selected, value]);

  async function runEstimate() {
    if (!canEstimate) return;
    setWorking(true);
    try {
      setEstimate(await api.estimateHmairScan({ target_ids: selectedTargets, collector_ids: selectedCollectors }));
      toast.success("Read-only scan estimate is ready");
    } catch (error) { setEstimate(null); toast.error(error instanceof Error ? error.message : "Estimate failed"); }
    finally { setWorking(false); }
  }

  async function launchScan() {
    if (!canEstimate || !estimate) return;
    setWorking(true);
    try {
      const scan = await api.createHmairScan({
        name: `AI Estate Scan ${new Date().toISOString().slice(0, 16)}`,
        scan_type: "targeted",
        scope: { mode: "selected_registered_targets", continuous_monitoring: false, exclusions: parseExclusions(exclusionsInput) },
        target_ids: selectedTargets,
        collector_ids: selectedCollectors,
        safety_profile: safetyProfile,
        dry_run: dryRun,
      }, crypto.randomUUID());
      setSelectedScanId(scan.scan_id);
      toast.success("AI estate scan accepted");
      await load();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Scan launch failed"); }
    finally { setWorking(false); }
  }

  async function preflightDeepScan() {
    if (!canPreflightDeepScan) return;
    setWorking(true);
    try {
      const preflight = await api.preflightHmairDeepScan(deepScanPreflightRequest);
      setDeepScanPreflight(preflight);
      toast.success("Deep Scan preflight completed for the selected sources");
    } catch (error) {
      setDeepScanPreflight(null);
      toast.error(error instanceof Error ? error.message : "Deep Scan preflight failed");
    } finally { setWorking(false); }
  }

  async function launchDeepScan() {
    if (!deepScanPreflight || !canLaunchDeepScan) return;
    setWorking(true);
    try {
      const launched = await api.launchHmairDeepScan({
        name: `Production Deep Scan ${new Date().toISOString().slice(0, 16)}`,
        preflight: deepScanPreflightRequest,
        preflight_digest: deepScanPreflight.preflight_digest,
        dry_run: false,
      }, crypto.randomUUID());
      setSelectedScanId(launched.scan.scan_id);
      setDeepScanCoverage(null);
      toast.success("Bounded production Deep Scan accepted");
      await load();
    } catch (error) { toast.error(error instanceof Error ? error.message : "Deep Scan launch failed"); }
    finally { setWorking(false); }
  }

  async function cancelSelected() {
    if (!selectedScan) return;
    setWorking(true);
    try { await api.cancelHmairScan(selectedScan.scan_id); toast.success("Scan cancellation recorded"); await load(); }
    catch (error) { toast.error(error instanceof Error ? error.message : "Cancellation failed"); }
    finally { setWorking(false); }
  }

  async function rescanSelected() {
    if (!selectedScan) return;
    setWorking(true);
    try { const scan = await api.rescanHmairScan(selectedScan.scan_id, crypto.randomUUID()); setSelectedScanId(scan.scan_id); toast.success("Bounded rescan accepted"); await load(); }
    catch (error) { toast.error(error instanceof Error ? error.message : "Rescan failed"); }
    finally { setWorking(false); }
  }

  async function requestEndpointMetadataInventory() {
    setWorking(true);
    try {
      const run = await api.createEndpointMetadataInventoryRun(
        { endpoint_ids: null, expires_in_minutes: 60 },
        crypto.randomUUID(),
      );
      setMetadataInventoryRuns((current) => [run, ...current.filter((item) => item.id !== run.id)].slice(0, 20));
      setMetadataInventoryError(null);
      toast.success(`Metadata inventory requested for ${run.endpoint_denominator} eligible enrolled endpoints`);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Endpoint metadata inventory request failed");
    } finally { setWorking(false); }
  }

  return (
    <DiscoveryWorkspaceFrame eyebrow="Active discovery" title="AI Discovery" description="Run a bounded AI estate scan, see what was found, and understand which sources still need connection." actions={<Button size="sm" variant="outline" onClick={load} disabled={loading || working} className="border-white/10 bg-white/[0.03] text-slate-200 hover:bg-white/[0.07]"><RefreshCw className={`mr-2 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh</Button>}>
      <section className="overflow-hidden rounded-3xl border border-cyan-300/15 bg-[radial-gradient(circle_at_12%_0%,rgba(34,211,238,0.16),transparent_32%),radial-gradient(circle_at_100%_20%,rgba(251,146,60,0.12),transparent_30%),#0b121c] p-5 shadow-2xl shadow-black/25">
        <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
          <div className="max-w-4xl">
            <p className="font-mono text-[10px] uppercase tracking-[0.24em] text-cyan-200/75">Discovery Command Center</p>
            <h2 className="mt-2 text-2xl font-semibold tracking-[-0.04em] text-white">Start here: run an AI discovery scan.</h2>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">This page now shows the customer journey first: connected sources, one scan action, latest results, and clear gaps. Full-enterprise coverage is not proven until every authorized source has current evidence. Internal target IDs, collector details, preflight proof, and diagnostics stay available in Advanced details.</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Button size="sm" onClick={preflightDeepScan} disabled={!canPreflightDeepScan || working} className="bg-orange-500 text-slate-950 hover:bg-orange-400"><ScanSearch className="mr-2 h-3.5 w-3.5" /> {scanPrimaryLabel}</Button>
              <Button size="sm" variant="outline" onClick={runEstimate} disabled={!canEstimate || working} className="border-cyan-300/20 bg-cyan-300/[0.05] text-cyan-100 hover:bg-cyan-300/10">Check readiness</Button>
              <Link href="/integrations" className="inline-flex h-8 items-center rounded-md border border-white/10 bg-white/[0.03] px-3 text-xs font-medium text-slate-200 hover:bg-white/[0.07]">Connect source</Link>
            </div>
            <p className="mt-2 text-[11px] leading-5 text-slate-500">{scanPrimaryHelp}</p>
          </div>
          <div className="grid min-w-[260px] gap-2 rounded-2xl border border-white/[0.07] bg-black/20 p-3">
            <div className="flex items-center justify-between gap-3"><span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Mode</span><TruthBadge value="monitor-only" /></div>
            <div className="flex items-center justify-between gap-3"><span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Sources ready</span><span className="font-mono text-sm text-white">{sourceReadyCount}</span></div>
            <div className="flex items-center justify-between gap-3"><span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Collectors ready</span><span className="font-mono text-sm text-white">{collectorReadyCount}</span></div>
            <div className="flex items-center justify-between gap-3"><span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Last evidence</span><span className="text-right font-mono text-[10px] text-slate-400">{formatDiscoveryTime(latestEvidenceAt)}</span></div>
          </div>
        </div>

        <div className="mt-6 grid gap-4 xl:grid-cols-[0.95fr_1.05fr]">
          <div className="rounded-2xl border border-white/[0.07] bg-white/[0.025] p-4">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
              <div><p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan-200/70">Sources</p><p className="mt-1 text-xs text-slate-500">Pick a source to connect or test. Green claims require real evidence.</p></div>
              <TruthBadge value={exhaustive ? "complete selected scope" : "partial selected scope"} />
            </div>
            <div className="mt-4 grid gap-3">
              {simpleSourceCards.map((surface) => <Link key={surface.name} href={surface.href} className="group rounded-xl border border-white/[0.06] bg-[#09111b]/80 p-3 transition hover:border-cyan-300/20 hover:bg-cyan-300/[0.04]">
                <div className="flex items-start justify-between gap-3"><div><h3 className="text-sm font-semibold text-white">{surface.name}</h3><p className="mt-1 text-[11px] leading-5 text-slate-400">{surface.detail}</p></div><span className={`rounded-full border px-2 py-1 font-mono text-[8px] uppercase ${surface.state.includes("Ready") ? "border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-100" : "border-amber-300/20 bg-amber-300/[0.06] text-amber-100"}`}>{surface.state}</span></div>
              </Link>)}
            </div>
          </div>

          <div className="space-y-4">
            <div className="rounded-2xl border border-emerald-300/15 bg-emerald-300/[0.035] p-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-emerald-100/75">Latest scan result</p>
              <p className="mt-1 text-[11px] leading-5 text-slate-500">{results ? "Evidence-backed findings from the selected scan only." : "Run or select a scan to populate evidence-backed findings."}</p>
              <div className="mt-3 grid gap-2 sm:grid-cols-2 xl:grid-cols-1">
                {discoveryFindingCards.map(([label, value, detail]) => <div key={String(label)} className="rounded-xl border border-white/[0.06] bg-black/15 p-3"><div className="flex items-center justify-between gap-3"><p className="text-[11px] font-medium text-slate-200">{label}</p><p className="font-mono text-lg text-white">{value}</p></div><p className="mt-1 text-[10px] leading-4 text-slate-500">{detail}</p></div>)}
              </div>
            </div>
            <div className="rounded-2xl border border-amber-300/15 bg-amber-300/[0.035] p-4">
              <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-amber-100/75">Still not visible</p>
              <p className="mt-1 text-[11px] leading-5 text-slate-500">These are explicit blind spots, not absence claims. Connect the listed sources before claiming coverage.</p>
              <div className="mt-3 space-y-2">{discoveryBlindSpots.map((item) => <p key={item} className="rounded-lg border border-white/[0.05] bg-black/10 p-2 text-[10px] leading-4 text-slate-400">• {item}</p>)}</div>
            </div>
          </div>
        </div>
      </section>

      <ShadowAIAssessment />

      <button type="button" onClick={() => setShowAdvanced((value) => !value)} className="mt-4 flex w-full items-center justify-between rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4 text-left text-sm font-semibold text-slate-100 transition hover:border-cyan-300/20 hover:bg-cyan-300/[0.035]">
        <span>{showAdvanced ? "Hide advanced scan settings" : "Advanced scan settings and diagnostics"}</span>
        {showAdvanced ? <ChevronDown className="h-4 w-4 text-slate-400" /> : <ChevronRight className="h-4 w-4 text-slate-400" />}
      </button>

      {showAdvanced ? <>

      <div className="overflow-x-auto rounded-2xl border border-white/[0.07] bg-[#0d151e] p-3"><div className="flex min-w-[760px] items-center">{STAGES.map((stage, index) => <div key={stage} className="flex flex-1 items-center"><div className="min-w-0 text-center"><span className={`mx-auto grid h-7 w-7 place-items-center rounded-full border font-mono text-[9px] ${index < 5 ? "border-cyan-300/30 bg-cyan-300/10 text-cyan-100" : "border-white/10 bg-white/[0.03] text-slate-500"}`}>{index < 5 ? <Check className="h-3 w-3" /> : index + 1}</span><p className="mt-1 font-mono text-[7px] uppercase tracking-wider text-slate-500">{stage}</p></div>{index < STAGES.length - 1 ? <div className="mx-1 h-px flex-1 bg-gradient-to-r from-cyan-300/25 to-white/[0.06]" /> : null}</div>)}</div></div>

      <section className="mt-4 overflow-hidden rounded-2xl border border-cyan-300/15 bg-[radial-gradient(circle_at_92%_0%,rgba(34,211,238,0.12),transparent_35%),#0d151e] p-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 gap-3">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-cyan-300/20 bg-cyan-300/[0.08] text-cyan-100"><Laptop className="h-4 w-4" /></div>
            <div>
              <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-cyan-200/70">Endpoint foundation · macOS + Windows</p>
              <h2 className="mt-1 text-sm font-semibold text-white">Enrolled endpoint metadata inventory</h2>
              <p className="mt-1 max-w-3xl text-[11px] leading-5 text-slate-400">This is not an organization-wide deep scan. It asks each active, enrolled endpoint with discovery scope to submit one privacy-bounded metadata snapshot through its authenticated policy refresh.</p>
            </div>
          </div>
          <Button size="sm" onClick={requestEndpointMetadataInventory} disabled={working || Boolean(metadataInventoryError)} className="shrink-0 bg-cyan-300 text-slate-950 hover:bg-cyan-200"><Play className="mr-2 h-3.5 w-3.5" /> Request metadata inventory</Button>
        </div>
        <div className="mt-4 grid gap-3 lg:grid-cols-[0.85fr_1.15fr]">
          <div className="grid grid-cols-3 gap-2 rounded-xl border border-white/[0.06] bg-black/10 p-3">
            <div><p className="font-mono text-lg text-white">{latestMetadataInventory?.endpoint_denominator ?? "—"}</p><p className="font-mono text-[8px] uppercase text-slate-600">Eligible enrolled</p></div>
            <div><p className="font-mono text-lg text-emerald-200">{latestMetadataInventory?.completed_count ?? "—"}</p><p className="font-mono text-[8px] uppercase text-slate-600">Completed</p></div>
            <div><TruthBadge value={latestMetadataInventory?.status || "not requested"} /><p className="mt-2 font-mono text-[8px] uppercase text-slate-600">Latest request</p></div>
          </div>
          <div className="rounded-xl border border-amber-300/15 bg-amber-300/[0.03] p-3">
            <p className="font-mono text-[9px] uppercase tracking-[0.16em] text-amber-100/80">Declared blind spots</p>
            <p className="mt-1 text-[11px] leading-5 text-slate-400">This workflow does not discover browser activity, MCP/runtime behavior, in-app AI actions, SaaS, cloud, identity, repositories, network, or databases. It does not collect prompts, credentials, cookies, browser history, account identifiers, or raw local content.</p>
            {latestMetadataInventory ? <p className="mt-2 font-mono text-[9px] text-slate-600">Expires {formatDiscoveryTime(latestMetadataInventory.expires_at)} · pending {latestMetadataInventory.pending_count} · delivered {latestMetadataInventory.delivered_count} · failed {latestMetadataInventory.failed_count}</p> : null}
            {metadataInventoryError ? <p className="mt-2 text-[10px] leading-4 text-amber-100/80">Endpoint inventory is unavailable here: {metadataInventoryError}</p> : null}
          </div>
        </div>
      </section>

      <DiscoveryDemoReadiness
        targets={targets}
        collectors={collectors}
        latestInventoryRun={latestMetadataInventory}
        coverage={deepScanCoverage}
      />

      <section className="mt-4 overflow-hidden rounded-2xl border border-violet-300/20 bg-[radial-gradient(circle_at_0%_0%,rgba(167,139,250,0.13),transparent_34%),#0d151e] p-4">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 gap-3">
            <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-violet-300/25 bg-violet-300/[0.08] text-violet-100"><ShieldCheck className="h-4 w-4" /></div>
            <div>
              <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-violet-200/75">Production control · preflight first</p>
              <h2 className="mt-1 text-sm font-semibold text-white">Production Deep Scan</h2>
              <p className="mt-1 max-w-4xl text-[11px] leading-5 text-slate-400">Use the selected registered targets and collectors below. A connected adapter is not coverage. This release produces a bounded result for selected sources only; Hawk cannot claim organization-wide coverage until every authorized surface has reconciled completion evidence.</p>
            </div>
          </div>
          <TruthBadge value="bounded partial" />
        </div>
        <div className="mt-4 grid gap-3 lg:grid-cols-[1fr_1fr_0.8fr]">
          <label className="rounded-xl border border-white/[0.07] bg-black/10 p-3">
            <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Customer authorization reference</span>
            <input value={deepScanAuthorizationReference} onChange={(event) => setDeepScanAuthorizationReference(event.target.value)} maxLength={128} placeholder="Approved change or consent reference" aria-label="Customer authorization reference" className="mt-2 h-9 w-full rounded-lg border border-white/10 bg-[#081019] px-2.5 text-xs text-slate-200 outline-none placeholder:text-slate-600 focus:border-violet-300/40" />
            <span className="mt-2 block text-[10px] leading-4 text-slate-500">An opaque audit reference only; no secret or customer content is returned by the service.</span>
          </label>
          <div className="rounded-xl border border-white/[0.07] bg-black/10 p-3">
            <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Result boundary</span>
            <p className="mt-2 text-xs font-medium text-slate-200">Bounded partial scan</p>
            <span className="mt-2 block text-[10px] leading-4 text-slate-500">Organization-wide verification is unavailable until every authorized surface has a current per-unit completion protocol and an approved enterprise scope-closure manifest.</span>
          </div>
          <div className="flex flex-col justify-between rounded-xl border border-violet-300/15 bg-violet-300/[0.03] p-3">
            <p className="text-[11px] leading-5 text-slate-400">Read-only. No endpoint shell, browser profile, prompt, cookie, credential, raw tool input, or raw source content is collected.</p>
            <Button size="sm" onClick={preflightDeepScan} disabled={!canPreflightDeepScan || working} className="mt-3 bg-violet-300 text-slate-950 hover:bg-violet-200"><Activity className="mr-2 h-3.5 w-3.5" /> Run Deep Scan preflight</Button>
          </div>
        </div>
        {!canEstimate ? <p className="mt-3 text-[10px] text-amber-100/80">Select one or more active targets and enabled collectors in the bounded scan configuration before requesting Deep Scan preflight.</p> : null}
        {canEstimate && !deepScanAuthorizationReference.trim() ? <p className="mt-3 text-[10px] text-amber-100/80">Provide the customer authorization reference before requesting a production Deep Scan preflight.</p> : null}
        {deepScanPreflight ? <div className="mt-4 rounded-xl border border-white/[0.07] bg-black/10 p-3">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-violet-200/80">Frozen preflight candidate</p><p className="mt-1 text-xs text-slate-200">{deepScanPreflight.ready_assignment_count} ready source {deepScanPreflight.ready_assignment_count === 1 ? "pair" : "pairs"} · bounded partial result only</p></div><Button size="sm" onClick={launchDeepScan} disabled={!canLaunchDeepScan || working} className="bg-violet-300 text-slate-950 hover:bg-violet-200"><Play className="mr-2 h-3.5 w-3.5" /> Start bounded Deep Scan</Button></div>
          <div className="mt-3 grid gap-2 xl:grid-cols-2">{deepScanPreflight.sources.map((source) => <div key={`${source.target_id}-${source.collector_id}`} className="rounded-lg border border-white/[0.06] bg-white/[0.02] p-2.5"><div className="flex items-start justify-between gap-3"><div><p className="text-[11px] font-medium text-slate-200">{formatDiscoveryLabel(source.target_type)}</p><p className="mt-1 font-mono text-[9px] text-slate-600">{source.target_id} · {source.collector_id}</p></div><TruthBadge value={source.readiness} /></div><div className="mt-2 grid grid-cols-2 gap-2 text-[10px] text-slate-500"><span>Mode: {formatDiscoveryLabel(source.observation_mode)}</span><span>Expected: {source.expected_count ?? "unknown"}</span><span>Last success: {formatDiscoveryTime(source.last_success_at)}</span><span>{source.required ? "Required source" : "Optional source"}</span></div>{source.limitations.length ? <p className="mt-2 text-[10px] leading-4 text-amber-100/75">{source.limitations.map(formatDiscoveryLabel).join(" · ")}</p> : null}</div>)}</div>
          {deepScanPreflight.required_gaps.length ? <div className="mt-3 rounded-lg border border-amber-300/15 bg-amber-300/[0.03] p-2 text-[10px] leading-4 text-amber-100/85"><strong>Required source gaps:</strong> {deepScanPreflight.required_gaps.map(formatDiscoveryLabel).join(" · ")}. Not connected sources remain gaps; they are never treated as no AI activity.</div> : null}
        </div> : null}
        {deepScanCoverage ? <div className="mt-4 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.025] p-3"><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-cyan-100/80">Selected Deep Scan source coverage</p><div className="mt-2 grid gap-2 xl:grid-cols-2">{deepScanCoverage.sources.map((source) => <div key={`${source.target_id}-${source.collector_id}`} className="rounded-lg border border-white/[0.06] bg-black/10 p-2.5"><div className="flex items-center justify-between gap-2"><p className="text-[11px] text-slate-200">{formatDiscoveryLabel(source.target_type)}</p><TruthBadge value={source.coverage_state} /></div><p className="mt-1 font-mono text-[9px] text-slate-600">Observed {source.observed_count} / {source.expected_count ?? "unknown"} · {formatDiscoveryLabel(source.readiness)}</p>{source.reason ? <p className="mt-1 text-[10px] text-amber-100/75">{formatDiscoveryLabel(source.reason)}</p> : null}</div>)}</div></div> : null}
        <p className="mt-4 text-[10px] leading-4 text-slate-600">Not connected means Hawk has no authorized, current evidence path for that source. It does not mean the organization has no AI use there.</p>
      </section>

      <div className="mt-4 grid gap-4 2xl:grid-cols-[1.1fr_0.9fr]">
        <section className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4">
          <div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold text-white">Configure a bounded scan</h2><p className="mt-1 text-[11px] text-slate-500">Only registered targets and enabled collectors can be selected.</p></div><ScanSearch className="h-4 w-4 text-cyan-300" /></div>
          <div className="mt-4 grid gap-4 lg:grid-cols-2"><div><p className="mb-2 font-mono text-[9px] uppercase tracking-[0.16em] text-slate-600">Scope · targets</p><div className="space-y-2">{targets.map((target) => <ToggleRow key={target.target_id} checked={selectedTargets.includes(target.target_id)} onChange={() => toggle(target.target_id, selectedTargets, setSelectedTargets)} disabled={!target.active_scan_allowed} title={target.identifier} detail={`${formatDiscoveryLabel(target.target_type)} · ${formatDiscoveryLabel(target.environment)} · ${target.active_scan_allowed ? "active scan allowed" : "monitor only"}`} />)}{!targets.length && <DiscoveryEmpty title="No registered targets" detail="Add a tenant target before estimating a scan." />}</div></div><div><p className="mb-2 font-mono text-[9px] uppercase tracking-[0.16em] text-slate-600">Sources · collectors</p><div className="space-y-2">{collectors.map((collector) => <ToggleRow key={collector.collector_id} checked={selectedCollectors.includes(collector.collector_id)} onChange={() => toggle(collector.collector_id, selectedCollectors, setSelectedCollectors)} disabled={!collector.enabled} title={formatDiscoveryLabel(collector.collector_type)} detail={`v${collector.version} · ${formatDiscoveryLabel(collector.health)} · ${collector.enabled ? "enabled" : "default-off or unavailable"}`} />)}{!collectors.length && <DiscoveryEmpty title="No registered collectors" detail="Collectors are default-off until explicitly configured." />}</div></div></div>
          <div className="mt-4 grid gap-3 rounded-xl border border-emerald-300/10 bg-emerald-300/[0.025] p-3 md:grid-cols-[0.8fr_1.2fr]">
            <div>
              <label className="font-mono text-[9px] uppercase tracking-[0.16em] text-emerald-200/70" htmlFor="hmair-safety-profile">Safety profile</label>
              <select id="hmair-safety-profile" value={safetyProfile} onChange={(event) => setSafetyProfile(event.target.value as "read_only" | "metadata_only")} className="mt-2 h-9 w-full rounded-lg border border-white/10 bg-[#081019] px-2.5 text-xs text-slate-200 outline-none">
                <option value="read_only">Read only</option>
                <option value="metadata_only">Metadata only</option>
              </select>
              <label className="mt-3 flex items-start gap-2 text-[11px] text-slate-300"><input type="checkbox" checked={dryRun} onChange={(event) => setDryRun(event.target.checked)} className="mt-0.5 accent-cyan-400"/><span><strong>Dry run</strong><span className="mt-0.5 block text-[10px] text-slate-500">Validate scope and permissions without collecting observations.</span></span></label>
            </div>
            <label><span className="font-mono text-[9px] uppercase tracking-[0.16em] text-emerald-200/70">Exclusions</span><textarea value={exclusionsInput} onChange={(event) => setExclusionsInput(event.target.value)} maxLength={4096} rows={4} aria-label="Scan exclusions" className="mt-2 w-full resize-y rounded-lg border border-white/10 bg-[#081019] p-2.5 text-xs text-slate-200 outline-none"/><span className="mt-1 block text-[10px] leading-4 text-slate-500">One category per line. Exclusions only narrow the selected targets and are included in the audit-bound scan request.</span></label>
            <p className="text-[11px] leading-5 text-slate-400 md:col-span-2">Read-only or metadata-only collection. No prompts, credentials, cookies, browser history, arbitrary source, raw tool arguments, or customer data are requested by this workflow.</p>
          </div>
          <div className="mt-4 flex flex-wrap gap-2"><Button size="sm" variant="outline" disabled={!canEstimate || working} onClick={runEstimate} className="border-cyan-300/20 bg-cyan-300/[0.05] text-cyan-100 hover:bg-cyan-300/10"><Activity className="mr-2 h-3.5 w-3.5" /> Estimate impact</Button><Button size="sm" disabled={!estimate || working} onClick={launchScan} className="bg-cyan-300 text-slate-950 hover:bg-cyan-200"><Play className="mr-2 h-3.5 w-3.5" /> Run AI Estate Scan</Button></div>
          {estimate ? <div className="mt-4 grid gap-3 rounded-xl border border-white/[0.06] bg-black/10 p-3 sm:grid-cols-4"><div><p className="font-mono text-xl text-white">{estimate.eligible_assignment_count}</p><p className="font-mono text-[8px] uppercase text-slate-600">Eligible pairs</p></div><div><p className="font-mono text-xl text-amber-200">{estimate.unsupported_pairs.length}</p><p className="font-mono text-[8px] uppercase text-slate-600">Unsupported</p></div><div><p className="font-mono text-xl text-rose-200">{estimate.permission_gaps.length}</p><p className="font-mono text-[8px] uppercase text-slate-600">Permission gaps</p></div><div><TruthBadge value={estimate.exhaustive_claim_permitted ? "exhaustive" : "partial"} /><p className="mt-1 font-mono text-[8px] uppercase text-slate-600">Estimate claim</p></div><div className="sm:col-span-4">{estimate.limitations.map((item) => <p key={item} className="text-[10px] leading-4 text-amber-100/70">• {item}</p>)}</div></div> : null}
        </section>

        <section className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4">
          <div className="flex items-center justify-between"><div><h2 className="text-sm font-semibold text-white">Scan control room</h2><p className="mt-1 text-[11px] text-slate-500">{scans.length} scans · {activeCount} active</p></div>{selectedScan ? <TruthBadge value={selectedScan.status} /> : null}</div>
          <select value={selectedScanId} onChange={(event) => setSelectedScanId(event.target.value)} className="mt-4 h-10 w-full rounded-xl border border-white/10 bg-[#081019] px-3 text-xs text-slate-300 outline-none" aria-label="Selected discovery scan"><option value="">Select a scan</option>{scans.map((scan) => <option key={scan.scan_id} value={scan.scan_id}>{scan.name} · {formatDiscoveryLabel(scan.status)}</option>)}</select>
          {!selectedScan ? <div className="mt-4"><DiscoveryEmpty title="No scan selected" detail="Run or select a scan to inspect evidence-backed progress and results." /></div> : <div className="mt-4 space-y-3">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">{[["Assignments", progress?.assignments_total ?? "—"], ["Completion", progress ? `${Math.round(progress.completion_percent)}%` : "—"], ["Observations", progress?.observations_count ?? selectedScan.observations_count], ["Assets", progress?.assets_linked ?? results?.asset_ids.length ?? "—"]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-2 text-center"><p className="font-mono text-lg text-white">{value}</p><p className="font-mono text-[7px] uppercase text-slate-600">{label}</p></div>)}</div>
            {progress ? <div><div className="h-2 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full rounded-full bg-gradient-to-r from-cyan-400 to-emerald-400" style={{ width: `${Math.max(0, Math.min(100, progress.completion_percent))}%` }} /></div><div className="mt-2 flex flex-wrap gap-1.5">{Object.entries(progress.assignments_by_state).map(([state, count]) => <span key={state} className="rounded-full border border-white/[0.07] px-2 py-1 font-mono text-[8px] uppercase text-slate-500">{formatDiscoveryLabel(state)} {count}</span>)}</div></div> : null}
            <div className={`rounded-xl border p-3 ${exhaustive ? "border-emerald-300/15 bg-emerald-300/[0.03]" : "border-amber-300/15 bg-amber-300/[0.03]"}`}><p className="font-mono text-[9px] uppercase tracking-[0.15em] text-slate-500">Result truth</p><p className="mt-1 text-xs text-slate-300">{results ? (exhaustive ? "Selected registered scope permits an exhaustive result claim." : "Results are partial; an enterprise-wide claim is prohibited.") : "Result proof has not been produced yet."}</p>{results ? <div className="mt-2 space-y-1 text-[10px] text-slate-500"><p>Confidence: {formatDiscoveryLabel(results.completion_confidence)}</p><p>Unresolved assets: {results.assets_unresolved}</p><p>Unknown sources: {results.unknown_sources.length ? results.unknown_sources.join(" · ") : "None reported in selected scope"}</p><p>Unsupported sources: {results.unsupported_sources.length ? results.unsupported_sources.join(" · ") : "None reported in selected scope"}</p></div> : null}</div>
            {results ? <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3"><div className="flex items-center justify-between gap-3"><div><p className="font-mono text-[9px] uppercase tracking-[0.15em] text-cyan-200/70">Result breadth</p><p className="mt-1 text-[10px] text-slate-500">Counts apply only to assets linked to this scan.</p></div><TruthBadge value={results.breadth.control_coverage_state} /></div>{results.result_truncated ? <p className="mt-2 rounded-lg border border-amber-300/10 bg-amber-300/[0.025] p-2 text-[10px] leading-4 text-amber-100/70">This result reached the server safety limit. Refine the scan scope to review every linked asset.</p> : null}<div className="mt-3 grid grid-cols-3 gap-2">{[["Users / identities", results.breadth.active_users], ["Shadow AI", results.breadth.shadow_ai], ["Models", results.breadth.models], ["Agents", results.breadth.agents], ["MCP", results.breadth.mcp], ["Developer AI", results.breadth.developer_ai], ["SaaS AI", results.breadth.saas_ai], ["AI-enabled data", results.breadth.ai_enabled_data], ["Runtimes", results.breadth.runtimes], ["Unknown candidates", results.breadth.unknown_candidates], ["Control Coverage", formatDiscoveryLabel(results.breadth.control_coverage_state)]].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-white/[0.05] bg-black/10 p-2"><p className="font-mono text-sm text-white">{value}</p><p className="mt-1 text-[8px] uppercase text-slate-600">{label}</p></div>)}</div><div className="mt-3 rounded-lg border border-amber-300/10 bg-amber-300/[0.025] p-2"><p className="font-mono text-[8px] uppercase text-amber-100/70">Blind spots</p><p className="mt-1 text-[10px] leading-4 text-slate-500">{results.breadth.blind_spots.length ? results.breadth.blind_spots.map(formatDiscoveryLabel).join(" · ") : "No additional blind spot was reported inside the selected scope; this is not an enterprise-wide no-gap claim."}</p></div></div> : null}
            {diagnostics ? <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3"><div className="flex items-center justify-between gap-2"><div><p className="font-mono text-[9px] uppercase tracking-[0.15em] text-violet-200/70">Collector diagnostics</p><p className="mt-1 text-[10px] text-slate-500">Health, permissions, exclusions, and unsupported paths for assigned sources.</p></div><span className="font-mono text-[9px] text-slate-500">{diagnostics.healthy_sources} healthy · {diagnostics.degraded_sources} degraded</span></div><div className="mt-2 space-y-2">{diagnostics.sources.map((source) => <div key={source.assignment_id} className="rounded-lg border border-white/[0.05] bg-black/10 p-2"><div className="flex items-center justify-between gap-2"><span className="text-[10px] text-slate-300">{formatDiscoveryLabel(source.target_type)} · {formatDiscoveryLabel(source.collector_type)}</span><TruthBadge value={source.supported ? source.collector_health : "unsupported"} /></div><p className="mt-1 text-[9px] text-slate-600">{formatDiscoveryLabel(source.assignment_status)} · {source.observations_count} observations · permission gaps {source.permission_gaps.length}</p>{source.target_exclusions.length ? <p className="mt-1 text-[9px] text-amber-100/65">Exclusions: {source.target_exclusions.map(formatDiscoveryLabel).join(" · ")}</p> : null}{source.limitations.length ? <p className="mt-1 text-[9px] text-slate-500">Limits: {source.limitations.map(formatDiscoveryLabel).join(" · ")}</p> : null}</div>)}</div>{diagnostics.limitations.map((item) => <p key={item} className="mt-2 text-[9px] text-slate-600">• {item}</p>)}</div> : null}
            {(progress?.warnings.length || progress?.errors.length || selectedScan.warnings.length || selectedScan.errors.length) ? <div className="rounded-xl border border-rose-300/10 bg-rose-300/[0.025] p-3"><p className="flex items-center gap-1.5 font-mono text-[9px] uppercase text-rose-200/70"><CircleAlert className="h-3 w-3" /> Partial failure evidence</p>{[...(progress?.warnings || []), ...(progress?.errors || []), ...selectedScan.warnings, ...selectedScan.errors].map((item, index) => <p key={`${index}-${item}`} className="mt-1 text-[10px] leading-4 text-slate-400">• {item}</p>)}</div> : null}
            <p className="font-mono text-[9px] text-slate-600">Started {formatDiscoveryTime(selectedScan.started_at)} · completed {formatDiscoveryTime(selectedScan.completed_at)}</p>
            <div className="flex flex-wrap gap-2"><Button size="sm" variant="outline" onClick={rescanSelected} disabled={working} className="border-white/10 bg-white/[0.02] text-slate-200"><RotateCcw className="mr-2 h-3.5 w-3.5" /> Rescan</Button>{["queued", "running", "partially_complete"].includes(selectedScan.status) ? <Button size="sm" variant="outline" onClick={cancelSelected} disabled={working} className="border-rose-300/15 bg-rose-300/[0.03] text-rose-200"><Square className="mr-2 h-3.5 w-3.5" /> Cancel</Button> : null}<Link href="/discovery/assets" className="inline-flex h-8 items-center rounded-md border border-white/10 bg-white/[0.02] px-3 text-xs text-slate-200">Review assets</Link><Link href="/discovery/unknown" className="inline-flex h-8 items-center rounded-md border border-white/10 bg-white/[0.02] px-3 text-xs text-slate-200">Resolve Unknown AI</Link><Link href="/discovery/findings" className="inline-flex h-8 items-center rounded-md border border-white/10 bg-white/[0.02] px-3 text-xs text-slate-200">Review findings</Link></div>
          </div>}
        </section>
      </div>
      </> : null}
    </DiscoveryWorkspaceFrame>
  );
}
