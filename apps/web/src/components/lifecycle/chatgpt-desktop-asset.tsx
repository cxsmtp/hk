"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AppWindow,
  ChevronDown,
  CircleHelp,
  Cloud,
  Code2,
  Eye,
  FileKey2,
  Fingerprint,
  Globe2,
  Layers3,
  LoaderCircle,
  MessageSquareText,
  Network,
  RefreshCw,
  Route,
  ShieldAlert,
  ShieldCheck,
  Workflow,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type {
  ChatGPTCompositeCapability,
  ChatGPTCompositeVerification,
  ChatGPTDesktopAction,
  ChatGPTDesktopCompositeAsset,
  ChatGPTDesktopControlPlan,
} from "@/lib/types";
import { cn } from "@/lib/utils";

const STATE_LABEL: Record<ChatGPTCompositeVerification, string> = {
  verified: "Verified",
  partial: "Partial",
  experimental: "Experimental",
  unverified: "Unverified",
  unavailable: "Unavailable",
  unknown: "Unknown",
};

const ACTIONS: Array<{ value: ChatGPTDesktopAction; label: string }> = [
  { value: "built_in_browser_navigation", label: "Built-in browser · navigate" },
  { value: "built_in_browser_upload", label: "Built-in browser · upload" },
  { value: "built_in_browser_download", label: "Built-in browser · download" },
  { value: "chat_file_upload", label: "Chat · file upload" },
  { value: "work_local_file_read", label: "Work local · file read" },
  { value: "work_cloud_action", label: "Work cloud · action" },
  { value: "app_action", label: "Enterprise app · action" },
  { value: "custom_mcp_write", label: "Custom MCP · write" },
  { value: "codex_local_shell", label: "Codex local · shell" },
  { value: "codex_remote_action", label: "Codex remote · action" },
];

const CAPABILITY_GROUPS = [
  {
    label: "Chat",
    capabilities: ["chat_network", "chat_file_upload"],
  },
  {
    label: "Work",
    capabilities: ["work_local_file_read", "work_local_file_write", "work_desktop_app", "work_cloud"],
  },
  {
    label: "Built-in Browser",
    capabilities: [
      "built_in_browser_network",
      "built_in_browser_destination",
      "built_in_browser_http_semantics",
      "built_in_browser_dom",
      "built_in_browser_upload",
      "built_in_browser_download",
    ],
  },
  {
    label: "Apps & MCP",
    capabilities: ["app_access", "app_action", "app_approval", "custom_mcp"],
  },
  {
    label: "Proof & identity",
    capabilities: ["compliance_visibility", "codex_local", "codex_remote", "account_identity"],
  },
] as const;

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function stateTone(state: ChatGPTCompositeVerification): string {
  if (state === "verified") return "border-emerald-300/25 bg-emerald-300/[0.08] text-emerald-200";
  if (state === "partial") return "border-cyan-300/25 bg-cyan-300/[0.07] text-cyan-200";
  if (state === "experimental") return "border-sky-300/25 bg-sky-300/[0.07] text-sky-200";
  if (state === "unverified") return "border-amber-300/25 bg-amber-300/[0.07] text-amber-200";
  if (state === "unavailable") return "border-rose-300/20 bg-rose-300/[0.055] text-rose-200/80";
  return "border-slate-600/40 bg-slate-500/[0.05] text-slate-400";
}

function StatePill({ state }: { state: ChatGPTCompositeVerification }) {
  return (
    <span className={cn("inline-flex rounded-full border px-2 py-1 font-mono text-[9px] font-semibold uppercase tracking-[0.13em]", stateTone(state))}>
      {STATE_LABEL[state]}
    </span>
  );
}

function statusFromFloor(value?: { verification?: string; health?: string; status?: string }): ChatGPTCompositeVerification {
  if (!value) return "unknown";
  if (value.verification === "verified" && value.health === "healthy" && ["inline", "inline_bound"].includes(value.status || "")) return "verified";
  if (value.status === "unavailable") return "unavailable";
  if (value.verification === "experimental") return "experimental";
  if (value.verification === "unverified") return "unverified";
  return "unknown";
}

function CapabilityStrip({ capabilities }: { capabilities: ChatGPTCompositeCapability[] }) {
  return (
    <div className="grid grid-cols-10 gap-1" aria-label="Twenty independent capability states">
      {capabilities.map((row) => (
        <div
          key={row.capability}
          title={`${humanize(row.capability)} · ${STATE_LABEL[row.verification]}`}
          className={cn(
            "h-2 rounded-full border transition duration-300 hover:scale-y-150",
            row.verification === "verified" && "border-emerald-300/30 bg-emerald-300/80 shadow-[0_0_10px_rgba(110,231,183,.2)]",
            row.verification === "partial" && "border-cyan-300/30 bg-cyan-300/70",
            row.verification === "experimental" && "border-sky-300/25 bg-sky-300/60",
            row.verification === "unverified" && "border-amber-300/25 bg-amber-300/50",
            row.verification === "unavailable" && "border-rose-300/20 bg-rose-300/35",
            row.verification === "unknown" && "border-slate-700 bg-slate-700/60",
          )}
        />
      ))}
    </div>
  );
}

function BoundaryCard({
  icon: Icon,
  label,
  note,
  state,
}: {
  icon: typeof Globe2;
  label: string;
  note: string;
  state: ChatGPTCompositeVerification;
}) {
  return (
    <div className="group relative overflow-hidden rounded-2xl border border-white/[0.06] bg-black/20 p-3.5 transition hover:border-white/[0.11] hover:bg-white/[0.025]">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-orange-300/20 to-transparent opacity-0 transition group-hover:opacity-100" />
      <div className="flex items-start justify-between gap-3">
        <div className="grid h-8 w-8 place-items-center rounded-xl border border-white/[0.07] bg-white/[0.025]">
          <Icon className="h-3.5 w-3.5 text-orange-200/80" />
        </div>
        <StatePill state={state} />
      </div>
      <p className="mt-3 text-xs font-semibold text-slate-100">{label}</p>
      <p className="mt-1.5 text-[10px] leading-4 text-slate-600">{note}</p>
    </div>
  );
}

function PlanResult({ plan }: { plan: ChatGPTDesktopControlPlan }) {
  const unsatisfied = plan.selection.unsatisfied_mandatory_floors;
  return (
    <div className="mt-4 grid gap-3 lg:grid-cols-[1.05fr_.95fr]">
      <div className="rounded-2xl border border-white/[0.065] bg-[#090d12] p-4">
        <div className="flex items-center justify-between gap-3">
          <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Mandatory enforcement floors</p>
          <StatePill state={unsatisfied.length ? "unverified" : "verified"} />
        </div>
        <div className="mt-4 space-y-2">
          {plan.requirements.mandatory_enforcement_floors.length ? plan.requirements.mandatory_enforcement_floors.map((floor, index) => {
            const missing = unsatisfied.includes(floor.floor_id);
            return (
              <div key={floor.floor_id} className="flex items-center gap-3">
                <span className={cn("grid h-6 w-6 place-items-center rounded-full border font-mono text-[9px]", missing ? "border-amber-300/25 text-amber-200" : "border-emerald-300/25 text-emerald-200")}>{String(index + 1).padStart(2, "0")}</span>
                <div className="min-w-0 flex-1"><p className="truncate text-xs font-medium text-slate-200">{humanize(floor.floor_id)}</p><p className="text-[10px] text-slate-600">{humanize(floor.capability)} · ≤ {floor.maximum_latency_ms} ms</p></div>
                <span className={cn("font-mono text-[9px] uppercase", missing ? "text-amber-300" : "text-emerald-300")}>{missing ? "unresolved" : "selected"}</span>
              </div>
            );
          }) : <p className="text-xs leading-5 text-slate-500">No local Endpoint Floor applies to this cloud-only or unresolved action.</p>}
        </div>
      </div>
      <div className="rounded-2xl border border-white/[0.065] bg-[#090d12] p-4">
        <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Why this action is controlled</p>
        <p className="mt-3 text-sm leading-6 text-slate-200">{plan.why_controlled.why_selected}</p>
        <div className="mt-4 flex flex-wrap gap-1.5">
          {[plan.why_controlled.file, plan.why_controlled.process, plan.why_controlled.network, plan.why_controlled.semantic_proxy]
            .filter((value) => value && value !== "not_required")
            .map((value) => <span key={value} className="rounded-lg border border-white/[0.06] bg-white/[0.025] px-2 py-1 font-mono text-[9px] uppercase text-slate-400">{humanize(value)}</span>)}
        </div>
      </div>
    </div>
  );
}

function CompositeAssetCard({ asset, onRefresh }: { asset: ChatGPTDesktopCompositeAsset; onRefresh: () => void }) {
  const [expanded, setExpanded] = useState(false);
  const [action, setAction] = useState<ChatGPTDesktopAction>("built_in_browser_upload");
  const [plan, setPlan] = useState<ChatGPTDesktopControlPlan | null>(null);
  const [planLoading, setPlanLoading] = useState(false);
  const [planError, setPlanError] = useState<string | null>(null);
  const capabilities = useMemo(() => new Map(asset.capabilities.map((row) => [row.capability, row])), [asset.capabilities]);
  const capabilityState = (name: string): ChatGPTCompositeVerification => capabilities.get(name)?.verification || "unknown";
  const floor = asset.endpoint_floor.controls;
  const coverage = asset.control_coverage;

  async function resolvePlan() {
    setPlanLoading(true);
    setPlanError(null);
    try {
      setPlan(await api.chatGPTDesktopControlPlan(asset.endpoint_id, action));
    } catch (reason: unknown) {
      setPlan(null);
      setPlanError(reason instanceof Error ? reason.message : "Action plan is unavailable");
    } finally {
      setPlanLoading(false);
    }
  }

  return (
    <article className="relative overflow-hidden rounded-[26px] border border-white/[0.075] bg-[#0b0f14] shadow-[0_28px_90px_rgba(0,0,0,.22)]">
      <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-orange-400/[0.045] blur-3xl" />
      <div className="border-b border-white/[0.06] p-5 lg:p-6">
        <div className="flex flex-col gap-5 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex items-start gap-4">
            <div className="relative grid h-12 w-12 shrink-0 place-items-center overflow-hidden rounded-[17px] border border-orange-300/20 bg-orange-300/[0.07]">
              <MessageSquareText className="h-5 w-5 text-orange-200" />
              <span className="absolute bottom-1 right-1 h-1.5 w-1.5 rounded-full bg-orange-300 shadow-[0_0_8px_rgba(253,186,116,.8)]" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <p className="font-mono text-[9px] uppercase tracking-[0.2em] text-orange-300/65">AI Asset Intelligence · Composite</p>
                <span className="rounded-full border border-white/[0.07] px-2 py-0.5 font-mono text-[8px] uppercase text-slate-600">evidence projected</span>
              </div>
              <h2 className="mt-1.5 text-xl font-semibold tracking-[-0.02em] text-white">ChatGPT Desktop</h2>
              <p className="mt-1 text-[11px] text-slate-500">
                {asset.installation.version || "Version unknown"} · {asset.installation.bundle_id || "Bundle unknown"} · {asset.endpoint_id}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className={cn("rounded-full border px-2.5 py-1 text-[10px]", asset.installation.signature_verified ? "border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200" : "border-amber-300/20 bg-amber-300/[0.06] text-amber-200")}>
              {asset.installation.signature_verified ? "Signed identity" : "Signature unverified"}
            </span>
            <span className="rounded-full border border-rose-300/20 bg-rose-300/[0.05] px-2.5 py-1 text-[10px] text-rose-200/80">
              {asset.native_hook_available ? "App-wide hook observed" : "No app-wide hook"}
            </span>
            <button type="button" onClick={onRefresh} className="grid h-8 w-8 place-items-center rounded-full border border-white/[0.07] text-slate-500 transition hover:border-white/[0.14] hover:text-slate-200" aria-label="Refresh ChatGPT asset"><RefreshCw className="h-3.5 w-3.5" /></button>
          </div>
        </div>

        <div className="mt-6 grid gap-5 lg:grid-cols-[11rem_minmax(0,1fr)]">
          <div className="flex items-center gap-4 lg:block">
            <div className="relative grid h-28 w-28 shrink-0 place-items-center rounded-full" style={{ background: `conic-gradient(#f59e0b ${coverage.verified_percent}%, rgba(255,255,255,.055) 0)` }}>
              <div className="grid h-[5.7rem] w-[5.7rem] place-items-center rounded-full border border-white/[0.06] bg-[#0b0f14] text-center">
                <div><p className="font-mono text-2xl text-white">{coverage.verified_dimensions}<span className="text-xs text-slate-600">/{coverage.total_dimensions}</span></p><p className="mt-0.5 text-[8px] uppercase tracking-[0.16em] text-slate-600">Verified</p></div>
              </div>
            </div>
            <div className="lg:mt-3"><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Control Coverage</p><p className="mt-1 text-[10px] leading-4 text-slate-600">Independent dimensions. No weighted marketing score.</p></div>
          </div>
          <div>
            <CapabilityStrip capabilities={asset.capabilities} />
            <div className="mt-4 grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
              <div><p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Account</p><p className="mt-1 text-xs font-medium capitalize text-slate-200">{asset.account.context}</p><p className="mt-0.5 text-[9px] text-slate-600">{asset.account.authoritative ? "Authoritative" : "Evidence missing"}</p></div>
              <div><p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Modes</p><p className="mt-1 text-xs font-medium text-slate-200">{asset.modes_observed.length ? asset.modes_observed.map(humanize).join(" · ") : "Unknown"}</p><p className="mt-0.5 text-[9px] capitalize text-slate-600">{humanize(asset.runtime_location)}</p></div>
              <div><p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Endpoint Floor</p><p className="mt-1 text-xs font-medium capitalize text-slate-200">{asset.endpoint_floor.health}</p><p className="mt-0.5 text-[9px] text-slate-600">Policy {asset.endpoint_floor.local_policy.freshness}</p></div>
              <div><p className="text-[9px] uppercase tracking-[0.14em] text-slate-600">Built-in Browser</p><p className="mt-1 text-xs font-medium text-slate-200">{asset.built_in_browser.observed ? "Observed" : "Not observed"}</p><p className="mt-0.5 text-[9px] text-slate-600">Chrome coverage: {asset.built_in_browser.inherits_chrome_extension_coverage ? "Inherited" : "Not inherited"}</p></div>
            </div>
            <p className="mt-4 border-t border-white/[0.05] pt-3 font-mono text-[8px] uppercase tracking-[0.12em] text-slate-700">{coverage.inflation_guard}</p>
          </div>
        </div>
      </div>

      <div className="p-5 lg:p-6">
        <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <BoundaryCard icon={FileKey2} label="File" note="Local read + write consequences" state={statusFromFloor(floor.file_control)} />
          <BoundaryCard icon={Workflow} label="Process" note="Child process and local execution" state={statusFromFloor(floor.process_control)} />
          <BoundaryCard icon={Network} label="Network" note="Destination and transfer boundary" state={statusFromFloor(floor.network_control)} />
          <BoundaryCard icon={Globe2} label="HTTP semantics" note="Legitimate proxy only; DOM separate" state={capabilityState("built_in_browser_http_semantics")} />
          <BoundaryCard icon={Route} label="Custom MCP" note="Exact Hawk-governed tool path" state={capabilityState("custom_mcp")} />
          <BoundaryCard icon={Cloud} label="Cloud Work" note="Never inherits local Endpoint authority" state={capabilityState("work_cloud")} />
        </div>

        <div className="mt-5 grid gap-3 lg:grid-cols-3">
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.018] p-4">
            <div className="flex items-center gap-2"><AppWindow className="h-3.5 w-3.5 text-orange-200/70" /><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Apps</p></div>
            <div className="mt-3 flex items-center justify-between"><span className="text-xs text-slate-300">Access / Action / Approval</span><StatePill state={capabilityState("app_action")} /></div>
            <p className="mt-2 text-[10px] leading-4 text-slate-600">Provider deny is monotonic. One app never lends capability to another.</p>
          </div>
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.018] p-4">
            <div className="flex items-center gap-2"><Eye className="h-3.5 w-3.5 text-orange-200/70" /><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Compliance</p></div>
            <div className="mt-3 flex items-center justify-between"><span className="text-xs text-slate-300">Post-action Evidence</span><StatePill state={capabilityState("compliance_visibility")} /></div>
            <p className="mt-2 text-[10px] leading-4 text-slate-600">Reconciliation only. Compliance never becomes inline authorization.</p>
          </div>
          <div className="rounded-2xl border border-white/[0.06] bg-white/[0.018] p-4">
            <div className="flex items-center gap-2"><Code2 className="h-3.5 w-3.5 text-orange-200/70" /><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Codex</p></div>
            <div className="mt-3 flex items-center justify-between"><span className="text-xs text-slate-300">Local / Remote</span><StatePill state={capabilityState("codex_local")} /></div>
            <p className="mt-2 text-[10px] leading-4 text-slate-600">Work/Codex lifecycle hooks are separate and require their own current evidence. Remote execution is a separate runtime.</p>
          </div>
        </div>

        <button type="button" onClick={() => setExpanded((current) => !current)} className="mt-5 flex w-full items-center justify-between rounded-2xl border border-white/[0.06] bg-black/15 px-4 py-3 text-left transition hover:border-white/[0.11]">
          <span><span className="text-xs font-semibold text-slate-200">Inspect 20 capability dimensions</span><span className="ml-2 text-[10px] text-slate-600">Evidence, roles and blind spots</span></span>
          <ChevronDown className={cn("h-4 w-4 text-slate-600 transition", expanded && "rotate-180")} />
        </button>

        {expanded ? (
          <div className="mt-4 space-y-5">
            {CAPABILITY_GROUPS.map((group) => (
              <section key={group.label}>
                <p className="mb-2 text-[9px] font-semibold uppercase tracking-[0.18em] text-slate-600">{group.label}</p>
                <div className="grid gap-px overflow-hidden rounded-2xl border border-white/[0.06] bg-white/[0.06] md:grid-cols-2">
                  {group.capabilities.map((name) => {
                    const row = capabilities.get(name);
                    if (!row) return null;
                    return (
                      <div key={name} className="bg-[#0a0e13] p-3.5">
                        <div className="flex items-start justify-between gap-3"><div><p className="text-xs font-medium text-slate-200">{humanize(name)}</p><p className="mt-1 font-mono text-[8px] uppercase tracking-[0.12em] text-slate-700">{humanize(row.control_role)} · {humanize(row.level)}</p></div><StatePill state={row.verification} /></div>
                        {row.blind_spots.length ? <p className="mt-3 text-[10px] leading-4 text-slate-600">{row.blind_spots.map(humanize).join(" · ")}</p> : null}
                      </div>
                    );
                  })}
                </div>
              </section>
            ))}

            <section className="rounded-[22px] border border-orange-300/10 bg-orange-300/[0.025] p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                <div><div className="flex items-center gap-2"><Layers3 className="h-4 w-4 text-orange-200/70" /><p className="text-xs font-semibold text-slate-100">Why this action is controlled</p></div><p className="mt-1.5 text-[10px] text-slate-600">Resolve the current mandatory floors and semantic path from server evidence. Read-only.</p></div>
                <div className="flex gap-2">
                  <select value={action} onChange={(event) => setAction(event.target.value as ChatGPTDesktopAction)} className="h-9 min-w-0 rounded-xl border border-white/[0.08] bg-[#090d12] px-3 text-[11px] text-slate-300 outline-none sm:min-w-60">
                    {ACTIONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                  <Button size="sm" variant="outline" onClick={() => void resolvePlan()} disabled={planLoading}>{planLoading ? <LoaderCircle className="mr-2 h-3.5 w-3.5 animate-spin" /> : <Fingerprint className="mr-2 h-3.5 w-3.5" />}Resolve</Button>
                </div>
              </div>
              {planError ? <p className="mt-3 text-xs text-rose-300">{planError}</p> : null}
              {plan ? <PlanResult plan={plan} /> : null}
            </section>

            <div className="grid gap-3 lg:grid-cols-2">
              <section className="rounded-2xl border border-white/[0.06] bg-white/[0.018] p-4">
                <div className="flex items-center gap-2"><ShieldAlert className="h-3.5 w-3.5 text-amber-200/70" /><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Blind spots</p></div>
                <div className="mt-3 space-y-2">{asset.blind_spots.length ? asset.blind_spots.map((item) => <p key={item} className="flex gap-2 text-[10px] leading-4 text-slate-500"><span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-amber-300/60" />{humanize(item)}</p>) : <p className="text-[10px] text-slate-600">No blind spot recorded in the loaded evidence window.</p>}</div>
              </section>
              <section className="rounded-2xl border border-white/[0.06] bg-white/[0.018] p-4">
                <div className="flex items-center gap-2"><ShieldCheck className="h-3.5 w-3.5 text-emerald-200/70" /><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">Evidence</p></div>
                <p className="mt-3 text-xs text-slate-300">{asset.evidence_refs.length} bounded references · {asset.compliance_reconciliation.items.length} reconciliation rows</p>
                <p className="mt-2 text-[10px] leading-4 text-slate-600">Last observed {new Date(asset.last_observed_at).toLocaleString()} · process {asset.process.process_id || "unknown"}</p>
                <div className="mt-3 flex flex-wrap gap-1">{asset.evidence_refs.slice(0, 8).map((ref) => <span key={ref} className="rounded-md border border-white/[0.05] px-1.5 py-1 font-mono text-[8px] text-slate-700">{ref}</span>)}</div>
              </section>
            </div>
          </div>
        ) : null}
      </div>
    </article>
  );
}

export function ChatGPTDesktopAsset() {
  const [assets, setAssets] = useState<ChatGPTDesktopCompositeAsset[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [emptyMessage, setEmptyMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const response = await api.chatGPTDesktopAssets();
      setAssets(response.items || []);
      setEmptyMessage(response.empty_state?.message || null);
      setError(null);
    } catch (reason: unknown) {
      setAssets([]);
      setError(reason instanceof Error ? reason.message : "ChatGPT Desktop evidence is unavailable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (loading) {
    return <div className="grid min-h-48 place-items-center rounded-[26px] border border-white/[0.06] bg-[#0b0f14]"><div className="flex items-center gap-2 text-xs text-slate-600"><LoaderCircle className="h-4 w-4 animate-spin" />Projecting ChatGPT composite evidence…</div></div>;
  }
  if (error) {
    return <div className="flex items-center justify-between gap-4 rounded-[22px] border border-amber-300/15 bg-amber-300/[0.04] p-4"><div className="flex items-center gap-3"><CircleHelp className="h-4 w-4 text-amber-200/70" /><div><p className="text-xs font-medium text-amber-100">ChatGPT composite evidence unavailable</p><p className="mt-1 text-[10px] text-amber-200/50">{error}</p></div></div><Button size="sm" variant="outline" onClick={() => void load()}>Retry</Button></div>;
  }
  if (!assets.length) {
    return <div className="relative overflow-hidden rounded-[24px] border border-dashed border-white/[0.08] bg-[#0b0f14] p-7"><div className="absolute right-0 top-0 h-32 w-32 rounded-full bg-orange-300/[0.04] blur-3xl" /><div className="flex items-start gap-4"><div className="grid h-10 w-10 place-items-center rounded-2xl border border-white/[0.07] bg-white/[0.02]"><AppWindow className="h-4 w-4 text-slate-600" /></div><div><p className="text-sm font-semibold text-slate-200">ChatGPT Desktop not observed</p><p className="mt-1 max-w-xl text-[11px] leading-5 text-slate-600">{emptyMessage || "No supported signed-app observation exists for this tenant. Hawk will not synthesize an asset or infer an account from process or network names."}</p><Button className="mt-4" size="sm" variant="outline" onClick={() => void load()}>Refresh evidence</Button></div></div></div>;
  }
  return <div className="space-y-4">{assets.map((asset) => <CompositeAssetCard key={asset.asset_id} asset={asset} onRefresh={() => void load()} />)}</div>;
}
