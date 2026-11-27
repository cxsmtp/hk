"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowUpRight, CircleHelp, Eye, RefreshCw, ShieldCheck, Unplug } from "lucide-react";

import { WorkspaceHeader } from "@/components/lifecycle/workspace-header";
import { WorkspaceLinks } from "@/components/lifecycle/workspace-links";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { ControlCoverageSummary, DeploymentCoverageSummary, DeploymentCoverageSurface, EndpointEnforcementFloorSummary, EndpointHealthSummary, EndpointReenrollmentAuthorization, PilotHealthState } from "@/lib/types";
import { cn } from "@/lib/utils";

function surfaceState(surface: DeploymentCoverageSurface): "Protected" | "Partially protected" | "Monitor only" | "Outside control" | "Unknown" {
  if (surface.observed_event_count < 0 || surface.policy_enforced_count < 0 || surface.policy_enforced_count > surface.observed_event_count) return "Unknown";
  if (surface.observed_event_count === 0) return surface.covered ? "Unknown" : "Outside control";
  if (surface.policy_enforced_count === surface.observed_event_count) return "Protected";
  if (surface.policy_enforced_count > 0) return "Partially protected";
  return "Monitor only";
}

const STATE_STYLE = {
  Protected: { icon: ShieldCheck, className: "border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-300" },
  "Partially protected": { icon: ShieldCheck, className: "border-amber-400/20 bg-amber-400/[0.07] text-amber-300" },
  "Monitor only": { icon: Eye, className: "border-sky-400/20 bg-sky-400/[0.07] text-sky-300" },
  "Outside control": { icon: Unplug, className: "border-rose-400/20 bg-rose-400/[0.07] text-rose-300" },
  Unknown: { icon: CircleHelp, className: "border-slate-400/20 bg-slate-400/[0.07] text-slate-400" },
} as const;

const ENDPOINT_FLOOR_CONTROLS = [
  { key: "file_control", label: "File control", description: "Open, write, rename and delete" },
  { key: "process_control", label: "Process control", description: "Exec and child creation" },
  { key: "network_control", label: "Network control", description: "Connect and transfer boundary" },
  { key: "semantic_proxy", label: "Semantic proxy", description: "HTTP and AI-action context" },
] as const;

export const DEPLOYMENT_METHODS = [
  { key: "browser", label: "Browser Extension", observe: "Prompts and responses in managed browsers", control: "Block or warn before a browser prompt is sent", href: "/surface-coverage#browser-extension" },
  { key: "mcp", label: "MCP Gateway", observe: "Programs using MCP servers and tools", control: "Allow, require approval, or block routed tool calls", href: "/surface-coverage#mcp-gateway" },
  { key: "llm_gateway", label: "LLM Gateway", observe: "Apps sending model requests through the gateway", control: "Check prompts and responses before provider calls", href: "/surface-coverage#llm-gateway" },
  { key: "endpoint", label: "Endpoint Agent", observe: "Files and programs on enrolled devices", control: "Apply file, process, and network controls when receipts are current", href: "/surface-coverage#endpoint-agent" },
] as const;

function readableState(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function floorControlStyle(status: string, verification: string, health: string): string {
  if (["inline", "inline_bound"].includes(status) && verification === "verified" && health === "healthy") {
    return "border-emerald-400/25 bg-emerald-400/[0.07] text-emerald-300";
  }
  if (status === "not_covered" || status === "unavailable" || health === "unhealthy") {
    return "border-rose-400/20 bg-rose-400/[0.06] text-rose-300";
  }
  if (status === "observe" || health === "degraded") {
    return "border-amber-400/20 bg-amber-400/[0.06] text-amber-300";
  }
  return "border-slate-400/15 bg-slate-400/[0.045] text-slate-400";
}

export function DeployWorkspace() {
  const [deployment, setDeployment] = useState<DeploymentCoverageSummary | null>(null);
  const [coverage, setCoverage] = useState<ControlCoverageSummary | null>(null);
  // Control Coverage is off unless the server enables it (GET /system/features): its figures then say so.
  const [coverageEnabled, setCoverageEnabled] = useState(true);
  const coverageValue = (value: string | number | null | undefined): string | number => (!coverageEnabled ? "Not enabled" : value ?? "Unknown");
  const [health, setHealth] = useState<PilotHealthState | null>(null);
  const [endpointFloorStatus, setEndpointFloorStatus] = useState<EndpointEnforcementFloorSummary | null>(null);
  const [endpointHealth, setEndpointHealth] = useState<EndpointHealthSummary | null>(null);
  const [reenrollmentBundle, setReenrollmentBundle] = useState<EndpointReenrollmentAuthorization | null>(null);
  const [reenrollingEndpoint, setReenrollingEndpoint] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [endpointHealthState, setEndpointHealthState] = useState<"loading" | "loaded" | "error">("loading");
  const [endpointFloorState, setEndpointFloorState] = useState<"loading" | "loaded" | "error">("loading");

  async function load() {
    setLoading(true);
    try {
      const coverageOn = await api.systemFeatures().then((f) => f.control_coverage !== false, () => true);
      setCoverageEnabled(coverageOn);
      const [deploymentResult, coverageResult, healthResult, endpointFloorResult, endpointHealthResult] = await Promise.allSettled([
        api.deploymentCoverage(),
        coverageOn ? api.controlCoverage(30) : Promise.resolve(null),
        api.pilotHealth(),
        api.getEndpointFloorStatus(),
        api.getEndpointHealth(),
      ]);
      if (deploymentResult.status === "fulfilled") setDeployment(deploymentResult.value);
      if (coverageResult.status === "fulfilled" && coverageResult.value) setCoverage(coverageResult.value);
      if (healthResult.status === "fulfilled") setHealth(healthResult.value);
      if (endpointFloorResult.status === "fulfilled") setEndpointFloorStatus(endpointFloorResult.value);
      setEndpointFloorState(endpointFloorResult.status === "fulfilled" ? "loaded" : "error");
      setEndpointHealthState(endpointHealthResult.status === "fulfilled" ? "loaded" : "error");
      if (endpointHealthResult.status === "fulfilled") setEndpointHealth(endpointHealthResult.value);
      const unavailable = [
        deploymentResult.status === "rejected" ? "deployment telemetry" : null,
        coverageResult.status === "rejected" ? "Control Coverage" : null,
        healthResult.status === "rejected" ? "platform health" : null,
        endpointFloorResult.status === "rejected" ? "endpoint enforcement evidence" : null,
        endpointHealthResult.status === "rejected" ? "endpoint identity health" : null,
      ].filter(Boolean);
      setError(unavailable.length ? `${unavailable.join(", ")} unavailable. Available deployment evidence remains visible.` : null);
    } catch { setError("Deployment data is unavailable. Hawk is not inferring protection from missing telemetry."); }
    finally { setLoading(false); }
  }
  useEffect(() => { void load(); }, []);

  function methodStatus(key: string): string {
    const surface = deployment?.surfaces.find((item) => `${item.surface} ${item.label}`.toLowerCase().includes(key));
    if (!surface) return "Unknown";
    if (surface.observed_event_count === 0) return surface.last_seen_at ? "No activity observed" : "Unknown";
    if (surface.policy_enforced_count === surface.observed_event_count) return "Controlled";
    if (surface.policy_enforced_count > 0) return "Partially controlled";
    return "Observed";
  }

  async function createReenrollmentBundle(endpointId: string) {
    setReenrollingEndpoint(endpointId);
    setReenrollmentBundle(null);
    try {
      const issued = await api.createEndpointReenrollmentAuthorization(endpointId);
      setReenrollmentBundle(issued);
      await load();
    } catch {
      setError("Endpoint re-enrollment could not be authorized. Existing controls remain unchanged.");
    } finally {
      setReenrollingEndpoint(null);
    }
  }

  return (
    <div className="space-y-5">
      <WorkspaceHeader eyebrow="Deployments" title="Connect the four control methods" description="Set up Browser Extension, MCP Gateway, LLM Gateway, or Endpoint Agent, then review the evidence each connection returns." actions={<Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("mr-2 h-4 w-4", loading && "animate-spin")} />Refresh evidence</Button>} />
      {error ? <div className="rounded-2xl border border-amber-400/20 bg-amber-400/[0.06] px-4 py-3 text-sm text-amber-200">{error}</div> : null}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4" aria-label="Deployment methods">
        {DEPLOYMENT_METHODS.map((method) => <article key={method.key} className="rounded-[20px] border border-white/[0.07] bg-[#0c1016] p-4"><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-semibold text-slate-100">{method.label}</p><p className="mt-1 text-[11px] text-slate-500">{method.observe}</p></div><span className={cn("rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.1em]", methodStatus(method.key) === "Controlled" ? "border-emerald-400/20 text-emerald-300" : methodStatus(method.key) === "Unknown" ? "border-slate-400/20 text-slate-500" : "border-orange-400/20 text-orange-200")}>{loading ? "Loading" : methodStatus(method.key)}</span></div><p className="mt-3 text-[11px] leading-5 text-slate-600">{method.control}. Missing evidence stays Unknown.</p><Link href={method.href} className="mt-3 inline-flex items-center text-[11px] font-semibold text-orange-200 hover:text-orange-100">View setup and evidence <ArrowUpRight className="ml-1 h-3 w-3" /></Link></article>)}
      </section>
      <details className="group rounded-[24px] border border-white/[0.08] bg-[#0b0f15]">
        <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-200">Technical deployment diagnostics</summary>
        <section className="overflow-hidden border-t border-white/[0.08]">
        <div className="border-b border-white/[0.06] bg-[radial-gradient(circle_at_top_left,rgba(45,212,191,0.10),transparent_35%)] px-5 py-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyan-300/75">Endpoint identity & health</p>
              <h2 className="mt-2 text-lg font-semibold text-white">Signed device status</h2>
              <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">Shows enrolled endpoint identity, token auto-renewal, signed heartbeat freshness, local policy freshness, and command enforcement acceptance. Missing evidence stays visible.</p>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5 lg:min-w-[620px]">
              {[
                ["Devices", endpointHealthState === "error" ? "Unavailable" : endpointHealth?.summary.total ?? 0],
                ["Active", endpointHealthState === "error" ? "Unavailable" : endpointHealth?.summary.active ?? 0],
                ["Fresh heartbeat", endpointHealthState === "error" ? "Unavailable" : endpointHealth?.summary.fresh_signed_heartbeat ?? 0],
                ["Command accepted", endpointHealthState === "error" ? "Unavailable" : endpointHealth?.summary.command_enforcement_accepted ?? 0],
                ["Needs re-enroll", endpointHealthState === "error" ? "Unavailable" : endpointHealth?.summary.needs_reenrollment ?? 0],
              ].map(([label, value]) => (
                <div key={label} className="rounded-2xl border border-white/[0.07] bg-black/20 p-3">
                  <p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-600">{label}</p>
                  <p className="mt-2 text-xl font-semibold text-white">{loading ? "—" : value}</p>
                </div>
              ))}
            </div>
          </div>
          {reenrollmentBundle ? (
            <div className="mt-4 rounded-2xl border border-cyan-400/20 bg-cyan-400/[0.055] p-4">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <p className="text-sm font-semibold text-cyan-100">One-click re-enroll bundle created</p>
                  <p className="mt-1 text-xs text-cyan-100/65">Expires {new Date(reenrollmentBundle.expires_at).toLocaleString()}. Paste this bundle into the endpoint agent enrollment flow; it is shown once for operator handoff.</p>
                </div>
                <span className="rounded-full border border-cyan-300/20 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-cyan-100">{reenrollmentBundle.endpoint_id}</span>
              </div>
              <pre className="mt-3 max-h-48 overflow-auto rounded-xl border border-white/[0.08] bg-black/35 p-3 text-[10px] leading-5 text-cyan-50/80">{JSON.stringify(reenrollmentBundle, null, 2)}</pre>
            </div>
          ) : null}
          {endpointHealthState === "error" ? <div className="mt-4 rounded-[20px] border border-amber-400/15 bg-amber-400/[0.04] px-5 py-8 text-center"><p className="text-sm font-medium text-amber-200">Endpoint identity health unavailable</p><p className="mt-2 text-xs text-slate-600">The health source did not respond. Hawk is not inferring enrollment or heartbeat status.</p></div> : null}
          <div className="mt-4 grid gap-3">
            {(endpointHealth?.devices || []).map((device) => (
              <article key={device.identity_id} className="rounded-[20px] border border-white/[0.07] bg-black/20 p-4">
                <div className="flex flex-col gap-3 xl:flex-row xl:items-start xl:justify-between">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="font-semibold text-slate-100">{device.endpoint_id}</h3>
                      <span className={cn("rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em]", device.status === "active" ? "border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-300" : "border-rose-400/20 bg-rose-400/[0.07] text-rose-300")}>{readableState(device.status)}</span>
                      <span className="rounded-full border border-white/[0.08] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em] text-slate-500">{readableState(device.key_provider)}</span>
                    </div>
                    <p className="mt-1 text-[10px] text-slate-600">Thumbprint {device.key_thumbprint.slice(0, 16)}… · {device.scopes.length} scopes</p>
                  </div>
                  <Button variant="outline" size="sm" onClick={() => void createReenrollmentBundle(device.endpoint_id)} disabled={reenrollingEndpoint === device.endpoint_id}>
                    {reenrollingEndpoint === device.endpoint_id ? "Creating…" : "One-click re-enroll"}
                  </Button>
                </div>
                <div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
                  {[
                    ["Auto-renew identity", readableState(device.auto_renewal.state), device.last_authenticated_at ? `Last token ${new Date(device.last_authenticated_at).toLocaleString()}` : "No token exchange observed"],
                    ["Signed heartbeat", readableState(device.signed_heartbeat.freshness), device.signed_heartbeat.last_seen_at ? `Last heartbeat ${new Date(device.signed_heartbeat.last_seen_at).toLocaleString()}` : "No signed heartbeat"],
                    ["Policy freshness", `${readableState(device.policy_freshness.status)} · ${readableState(device.policy_freshness.freshness)}`, device.policy_freshness.signature_verified ? `Signed ${device.policy_freshness.policy_version || "policy"}` : "Policy signature not proved"],
                    ["Command enforcement acceptance", readableState(device.command_enforcement_acceptance.state), device.command_enforcement_acceptance.minimum_floor_satisfied ? "File/process/network floor accepted" : "Minimum floor not accepted"],
                  ].map(([label, value, helper]) => (
                    <div key={label} className="rounded-2xl border border-white/[0.055] bg-white/[0.018] p-3">
                      <p className="text-[9px] font-semibold uppercase tracking-[0.13em] text-slate-600">{label}</p>
                      <p className="mt-2 text-sm font-semibold text-slate-100">{value}</p>
                      <p className="mt-1 text-[10px] leading-4 text-slate-600">{helper}</p>
                    </div>
                  ))}
                </div>
                {device.command_enforcement_acceptance.blind_spots.length ? (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {device.command_enforcement_acceptance.blind_spots.map((spot) => (
                      <span key={spot} className="rounded-full border border-amber-400/15 bg-amber-400/[0.045] px-2 py-1 text-[9px] text-amber-200/75">{readableState(spot)}</span>
                    ))}
                  </div>
                ) : null}
              </article>
            ))}
            {endpointHealthState === "loaded" && !loading && !endpointHealth?.devices.length ? (
              <div className="rounded-[20px] border border-dashed border-white/[0.09] bg-white/[0.012] px-5 py-8 text-center">
                <p className="text-sm font-medium text-slate-400">No endpoint identity is enrolled for this tenant.</p>
                <p className="mt-2 text-xs text-slate-600">Create an enrollment authorization before claiming endpoint coverage.</p>
              </div>
            ) : null}
          </div>
        </div>
        <div className="flex flex-col gap-3 border-b border-white/[0.06] bg-[radial-gradient(circle_at_top_right,rgba(249,115,22,0.11),transparent_38%)] px-5 py-5 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-orange-300/75">Endpoint enforcement floor</p>
            <h2 className="mt-2 text-lg font-semibold text-white">OS consequence boundaries</h2>
            <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">Minimum floor requires current runtime evidence for file, process and network authorization plus a fresh, signed local policy. The semantic proxy is reported separately.</p>
          </div>
          <span className="w-fit rounded-full border border-white/[0.08] bg-black/20 px-3 py-1.5 text-xs text-slate-400">
            {loading ? "Loading receipts" : endpointFloorState === "error" ? "Unavailable" : `${endpointFloorStatus?.summary.total ?? 0} endpoint receipt${endpointFloorStatus?.summary.total === 1 ? "" : "s"}`}
          </span>
        </div>
        <div className="space-y-4 p-5">
          {(endpointFloorStatus?.endpoints || []).map((endpoint) => (
            <article key={endpoint.endpoint_id} className="rounded-[20px] border border-white/[0.07] bg-white/[0.018] p-4">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="font-semibold text-slate-100">{endpoint.hostname}</h3>
                    <span className="rounded-full border border-white/[0.08] px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.13em] text-slate-500">{endpoint.os_type}</span>
                  </div>
                  <p className="mt-1 text-[10px] text-slate-600">{endpoint.endpoint_id} · last receipt {new Date(endpoint.last_seen_at).toLocaleString()}</p>
                </div>
                <span className={cn("w-fit rounded-full border px-3 py-1.5 text-[10px] font-semibold uppercase tracking-[0.12em]", endpoint.minimum_floor_satisfied ? "border-emerald-400/25 bg-emerald-400/[0.08] text-emerald-300" : "border-slate-400/15 bg-slate-400/[0.05] text-slate-400")}>
                  Minimum floor · {endpoint.minimum_floor_satisfied ? "verified active" : "not proved"}
                </span>
              </div>
              <div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-4">
                {ENDPOINT_FLOOR_CONTROLS.map((item) => {
                  const control = endpoint.controls[item.key];
                  return (
                    <div key={item.key} className="rounded-2xl border border-white/[0.055] bg-black/15 p-3.5">
                      <div className="flex items-start justify-between gap-2">
                        <div><p className="text-xs font-semibold text-slate-200">{item.label}</p><p className="mt-1 text-[9px] text-slate-600">{item.description}</p></div>
                        <span className={cn("rounded-full border px-2 py-1 text-[9px] font-semibold", floorControlStyle(control.status, control.verification, control.health))}>{readableState(control.status)}</span>
                      </div>
                      <div className="mt-4 flex items-center justify-between border-t border-white/[0.05] pt-2.5 text-[9px] text-slate-600">
                        <span>{readableState(control.verification)} · {readableState(control.health)}</span>
                        <span>{control.evidence_refs.length} evidence</span>
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="mt-3 grid gap-2 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)]">
                <div className="rounded-2xl border border-white/[0.055] bg-black/15 p-3.5">
                  <div className="flex items-center justify-between gap-3"><p className="text-xs font-semibold text-slate-200">Local policy</p><span className={cn("rounded-full border px-2 py-1 text-[9px] font-semibold", endpoint.local_policy.status === "active" && endpoint.local_policy.freshness === "fresh" && endpoint.local_policy.signature_verified ? "border-emerald-400/25 bg-emerald-400/[0.07] text-emerald-300" : "border-slate-400/15 bg-slate-400/[0.045] text-slate-400")}>{readableState(endpoint.local_policy.status)}</span></div>
                  <div className="mt-3 grid grid-cols-2 gap-2 text-[9px]"><div><p className="text-slate-600">Freshness</p><p className="mt-1 text-slate-300">{readableState(endpoint.local_policy.freshness)}</p></div><div><p className="text-slate-600">Signature</p><p className="mt-1 text-slate-300">{endpoint.local_policy.signature_verified ? "Verified" : "Not proved"}</p></div><div><p className="text-slate-600">Version</p><p className="mt-1 truncate text-slate-300">{endpoint.local_policy.policy_version || "Unknown"}</p></div><div><p className="text-slate-600">Evidence</p><p className="mt-1 text-slate-300">{endpoint.local_policy.evidence_refs.length} references</p></div></div>
                </div>
                <div className="rounded-2xl border border-white/[0.055] bg-black/15 p-3.5">
                  <div className="flex items-center justify-between gap-3"><p className="text-xs font-semibold text-slate-200">Blind spots</p><span className="text-[9px] text-slate-600">{endpoint.evidence_refs.length} total evidence references</span></div>
                  {endpoint.blind_spots.length ? <div className="mt-3 flex flex-wrap gap-1.5">{endpoint.blind_spots.map((spot) => <span key={spot} className="rounded-full border border-amber-400/15 bg-amber-400/[0.045] px-2 py-1 text-[9px] text-amber-200/75">{readableState(spot)}</span>)}</div> : <p className="mt-3 text-[10px] text-slate-600">No reported blind spots. This does not imply controls beyond the verified receipts above.</p>}
                  {endpoint.reason_codes.length ? <p className="mt-3 line-clamp-2 text-[9px] leading-4 text-slate-600">{endpoint.reason_codes.map(readableState).join(" · ")}</p> : null}
                </div>
              </div>
            </article>
          ))}
          {endpointFloorState === "error" ? <div className="rounded-[20px] border border-amber-400/15 bg-amber-400/[0.04] px-5 py-10 text-center"><p className="text-sm font-medium text-amber-200">Endpoint enforcement floor unavailable</p><p className="mt-2 text-xs text-slate-600">The floor source did not respond. No receipt or heartbeat count is inferred.</p></div> : !loading && !endpointFloorStatus?.endpoints.length ? <div className="rounded-[20px] border border-dashed border-white/[0.09] bg-white/[0.012] px-5 py-10 text-center"><p className="text-sm font-medium text-slate-400">Runtime evidence missing</p><p className="mt-2 text-xs text-slate-600">No authenticated endpoint floor heartbeat is available.</p></div> : null}
        </div>
        <section className="grid gap-3 border-t border-white/[0.08] px-5 py-5 sm:grid-cols-2 xl:grid-cols-5">
          {[
            ["Conservative score", coverageValue(coverage?.headline.score === null || coverage?.headline.score === undefined ? null : `${Math.round(coverage.headline.score)}%`)],
            ["Protected", coverageValue(coverage?.surface_summary.protected)],
            ["Monitor only", coverageValue(coverage?.surface_summary.monitor_only)],
            ["Outside control", coverageValue(coverage?.surface_summary.outside_control)],
            ["Unknown", coverageValue(coverage?.surface_summary.unknown)],
          ].map(([label, value]) => <div key={label} className="rounded-[20px] border border-white/[0.07] bg-[#0c1016] p-4"><p className="text-[10px] font-semibold uppercase tracking-[0.15em] text-slate-500">{label}</p><p className="mt-3 text-2xl font-semibold text-white">{loading ? "—" : value}</p></div>)}
        </section>
        <section className="border-t border-white/[0.08] bg-[#0c1016] p-5">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-orange-300/70">Deployment surfaces</p><h2 className="mt-2 text-lg font-semibold text-white">Observed control posture</h2><p className="mt-1 text-xs text-slate-500">Protected requires policy evidence for every observed event. Mixed evidence is Partially protected; observation alone is Monitor only.</p></div><span className={cn("rounded-full border px-3 py-1.5 text-xs font-semibold", health?.overall_status === "ok" ? "border-emerald-400/20 bg-emerald-400/[0.07] text-emerald-300" : "border-amber-400/20 bg-amber-400/[0.07] text-amber-300")}>{health ? `Platform ${health.overall_status.replace(/_/g, " ")}` : "Health unknown"}</span></div>
          <div className="mt-5 overflow-x-auto"><table className="w-full min-w-[720px] text-left"><thead><tr className="border-b border-white/[0.06] text-[9px] uppercase tracking-[0.15em] text-slate-600"><th className="px-3 py-3 font-semibold">Surface</th><th className="px-3 py-3 font-semibold">Status</th><th className="px-3 py-3 font-semibold">Observed events</th><th className="px-3 py-3 font-semibold">Policy enforcement</th><th className="px-3 py-3 font-semibold">Last seen</th></tr></thead><tbody>{(deployment?.surfaces || []).map((surface) => { const state = surfaceState(surface); const StateIcon = STATE_STYLE[state].icon; return <tr key={surface.surface} className="border-b border-white/[0.045] text-sm"><td className="px-3 py-4"><p className="font-medium text-slate-200">{surface.label}</p><p className="mt-1 text-[10px] text-slate-600">{surface.surface}</p></td><td className="px-3 py-4"><span className={cn("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-semibold", STATE_STYLE[state].className)}><StateIcon className="h-3 w-3" />{state}</span></td><td className="px-3 py-4 text-slate-400">{surface.observed_event_count.toLocaleString()}</td><td className="px-3 py-4 text-slate-400">{surface.policy_enforced_count.toLocaleString()}</td><td className="px-3 py-4 text-xs text-slate-600">{surface.last_seen_at ? new Date(surface.last_seen_at).toLocaleString() : "Unknown"}</td></tr>; })}</tbody></table>{!loading && !deployment?.surfaces.length ? <p className="py-12 text-center text-sm text-slate-600">No deployment-surface telemetry is available.</p> : null}</div>
        </section>
        </section>
      </details>
      {coverageEnabled ? <section className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-5"><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Blind spots</p><div className="mt-3 space-y-2">{(coverage?.blind_spots || []).slice(0, 6).map((spot) => <div key={spot.blind_spot_id} className="rounded-2xl border border-white/[0.055] bg-white/[0.018] p-3.5"><p className="text-sm font-medium capitalize text-slate-200">{spot.kind.replaceAll("_", " ")}</p><p className="mt-1 text-xs leading-5 text-slate-600">Path {spot.path_id} · {spot.dimensions.join(", ") || "dimension unknown"} · {spot.evidence_refs.length} evidence references</p></div>)}{!coverage?.blind_spots.length ? <p className="rounded-2xl border border-dashed border-white/[0.08] p-6 text-center text-sm text-slate-600">No verified blind-spot records are available.</p> : null}</div></div>
        <div className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-5"><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">Highest-impact deployment</p><div className="mt-3 space-y-2">{(coverage?.deployment_improvements || []).slice(0, 6).map((item) => <Link key={item.deployment_type} href="/surface-coverage" className="group flex items-center justify-between gap-3 rounded-2xl border border-white/[0.055] bg-white/[0.018] p-3.5 transition hover:border-orange-400/20"><div><p className="text-sm font-medium text-slate-200">{item.deployment_type}</p><p className="mt-1 text-xs text-slate-600">{item.addressable_assertion_count} assertions · {item.impacted_path_count} paths</p></div><ArrowUpRight className="h-4 w-4 text-slate-600 group-hover:text-orange-300" /></Link>)}{!coverage?.deployment_improvements.length ? <p className="rounded-2xl border border-dashed border-white/[0.08] p-6 text-center text-sm text-slate-600">No evidence-backed deployment recommendation is available.</p> : null}</div></div>
      </section> : null}
      <WorkspaceLinks links={[
        { href: "/surface-coverage", label: "Surface coverage", description: "Inspect every deployment family and prerequisite." },
        { href: "/integrations", label: "Connectors", description: "Configure and evaluate enterprise integrations." },
        { href: "/validation/coverage", label: "Control Coverage", description: "Drill into assertion and path-native coverage." },
      ]} />
    </div>
  );
}
