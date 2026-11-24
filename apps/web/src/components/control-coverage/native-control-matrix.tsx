"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Check,
  CircleDot,
  Cpu,
  Fingerprint,
  Gauge,
  GitBranch,
  KeyRound,
  LoaderCircle,
  PlayCircle,
  Power,
  RefreshCw,
  Route,
  Search,
  Settings2,
  ShieldCheck,
  ShieldQuestion,
  X,
  Zap,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type {
  NativeCapabilityClaim,
  NativeCapabilityLevel,
  NativeCapabilityMatrix,
  NativeControlPoint,
  NativeControlPointHealth,
  NativeControlSelection,
  NativeProviderManifest,
  NativeVerificationStatus,
} from "@/lib/types";


const MATRIX_DIMENSIONS = [
  ["prompt_control", "Prompt"],
  ["response_control", "Response"],
  ["model_request_control", "Model request"],
  ["model_response_control", "Model response"],
  ["tool_control", "Tool"],
  ["function_tool_control", "Function tool"],
  ["function_tool_parameter_binding", "Function parameters"],
  ["function_tool_target_binding", "Function target"],
  ["mcp_control", "MCP"],
  ["local_mcp_control", "Local MCP"],
  ["hosted_mcp_control", "Hosted MCP"],
  ["direct_api_control", "Direct API"],
  ["command_control", "Command"],
  ["file_read_control", "File read"],
  ["file_write_control", "File write"],
  ["network_control", "Network"],
  ["approval_control", "Approval"],
  ["provider_permission_context", "Provider permission"],
  ["hawk_approval_binding", "Hawk approval binding"],
  ["approval_correlation", "Approval correlation"],
  ["parameter_binding", "Parameter binding"],
  ["target_binding", "Target binding"],
  ["destination_binding", "Destination"],
  ["post_execution_visibility", "Post-action visibility"],
  ["tool_failure_visibility", "Tool failure visibility"],
  ["execution_correlation", "Execution correlation"],
  ["post_execution_verification", "Execution proof"],
  ["config_change_visibility", "Config change visibility"],
  ["config_integrity", "Config integrity"],
  ["background_execution_visibility", "Background visibility"],
  ["persistent_side_effect_visibility", "Side-effect visibility"],
  ["persistent_side_effect_control", "Persistent side effect"],
  ["containment", "Containment"],
  ["bypass_detection", "Bypass"],
] as const;

const LEVEL_RANK: Record<NativeCapabilityLevel, number> = {
  inline_bound: 5,
  inline: 4,
  external: 3,
  observe: 2,
  unavailable: 1,
  unknown: 0,
};

function humanize(value: string): string {
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function verificationTone(status: NativeVerificationStatus): string {
  if (status === "verified") return "border-emerald-300/30 bg-emerald-300/10 text-emerald-100";
  if (status === "experimental") return "border-sky-300/30 bg-sky-300/10 text-sky-100";
  if (status === "broken" || status === "removed") return "border-rose-300/30 bg-rose-300/10 text-rose-100";
  return "border-amber-300/30 bg-amber-300/10 text-amber-100";
}

function healthTone(status: string): string {
  if (status === "healthy") return "border-emerald-300/35 bg-emerald-300/10 text-emerald-100";
  if (status === "degraded") return "border-amber-300/35 bg-amber-300/10 text-amber-100";
  if (status === "tampered" || status === "unhealthy") return "border-rose-300/35 bg-rose-300/10 text-rose-100";
  return "border-slate-500/40 bg-slate-500/10 text-slate-300";
}

function capabilityTone(claim?: NativeCapabilityClaim): string {
  if (!claim || claim.verification_status !== "verified") return "border-slate-700 bg-slate-900/70 text-slate-600";
  if (claim.level === "inline_bound") return "border-emerald-300/45 bg-emerald-300/15 text-emerald-50";
  if (claim.level === "inline") return "border-cyan-300/40 bg-cyan-300/12 text-cyan-50";
  if (claim.level === "external") return "border-violet-300/35 bg-violet-300/10 text-violet-100";
  if (claim.level === "observe") return "border-sky-300/30 bg-sky-300/10 text-sky-100";
  if (claim.level === "unavailable") return "border-rose-300/25 bg-rose-300/[0.06] text-rose-200/70";
  return "border-amber-300/25 bg-amber-300/[0.06] text-amber-200/70";
}

function capabilityLabel(claim?: NativeCapabilityClaim): string {
  if (!claim) return "Unknown";
  if (claim.verification_status === "unverified") return "Unverified";
  if (claim.verification_status !== "verified") return humanize(claim.verification_status);
  if (claim.level === "unknown") return "Unknown";
  return humanize(claim.level);
}

function MatrixCell({ claim }: { claim?: NativeCapabilityClaim }) {
  const verified = claim?.verification_status === "verified";
  return (
    <div
      className={`group relative grid min-h-14 place-items-center border px-2 py-2 text-center transition hover:-translate-y-0.5 ${capabilityTone(claim)}`}
      title={`${capabilityLabel(claim)}${claim?.evidence_refs?.length ? ` · ${claim.evidence_refs.join(" · ")}` : ""}`}
    >
      <span className="font-mono text-[9px] font-semibold uppercase tracking-[0.12em]">
        {capabilityLabel(claim)}
      </span>
      <span className={`absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full ${verified ? "bg-emerald-300 shadow-[0_0_8px_rgba(110,231,183,.8)]" : "bg-slate-700"}`} />
    </div>
  );
}

type CompatibilityFactState = "yes" | "no" | "unknown";

function CompatibilityFact({
  label,
  state,
}: {
  label: string;
  state: CompatibilityFactState;
}) {
  const tone = state === "yes"
    ? "border-emerald-300/25 bg-emerald-300/[0.07] text-emerald-100"
    : state === "no"
      ? "border-rose-300/20 bg-rose-300/[0.05] text-rose-100"
      : "border-amber-300/20 bg-amber-300/[0.05] text-amber-100";
  const value = state === "yes" ? "Yes" : state === "no" ? "No" : "Unknown";
  return (
    <div className={`border px-2 py-2 ${tone}`}>
      <div className="font-mono text-[8px] uppercase tracking-[0.12em] opacity-60">{label}</div>
      <div className="mt-1 text-[10px] font-semibold">{value}</div>
    </div>
  );
}

type HealthFactState = "pass" | "fail" | "unknown";

function healthFactState(value: boolean | undefined): HealthFactState {
  if (value === true) return "pass";
  if (value === false) return "fail";
  return "unknown";
}

function HealthFactRow({
  icon: Icon,
  label,
  state,
  detail,
}: {
  icon: typeof Fingerprint;
  label: string;
  state: HealthFactState;
  detail?: string;
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-[#222c3d] pb-2.5 last:border-0 last:pb-0">
      <span className="flex min-w-0 items-center gap-2 text-xs text-slate-400">
        <Icon className="h-3.5 w-3.5 shrink-0" />
        <span className="min-w-0">
          {label}
          {detail ? <span className="mt-0.5 block text-[10px] leading-4 text-slate-600">{detail}</span> : null}
        </span>
      </span>
      {state === "pass" ? (
        <Check className="h-4 w-4 shrink-0 text-emerald-300" />
      ) : state === "fail" ? (
        <X className="h-4 w-4 shrink-0 text-rose-300" />
      ) : (
        <span className="shrink-0 text-[10px] text-slate-600">Unknown</span>
      )}
    </div>
  );
}

function configuredFactState(point: NativeControlPoint | null): CompatibilityFactState {
  if (!point) return "no";
  if (point.state === "configuring") return "no";
  if (point.state === "disabled") return "unknown";
  if (["validating", "monitoring", "enforcing", "degraded"].includes(point.state)) {
    return point.configuration_integrity_valid ? "yes" : "no";
  }
  return "unknown";
}

function healthyFactState(point: NativeControlPoint | null): CompatibilityFactState {
  if (!point || point.health_state === "unknown") return "unknown";
  if (point.health_state === "healthy") return "yes";
  if ([
    "degraded",
    "unhealthy",
    "tampered",
    "version_mismatch",
    "policy_stale",
    "not_installed",
  ].includes(point.health_state)) return "no";
  return "unknown";
}

function ControlPointCard({
  point,
  selected,
  onSelect,
}: {
  point: NativeControlPoint;
  selected: boolean;
  onSelect: () => void;
}) {
  const verifiedClaims = Object.values(point.capabilities).filter((claim) => claim.verification_status === "verified");
  const inlineClaims = verifiedClaims.filter((claim) => LEVEL_RANK[claim.level] >= LEVEL_RANK.inline).length;
  return (
    <button
      type="button"
      onClick={onSelect}
      className={`relative min-w-[250px] flex-1 overflow-hidden border p-4 text-left transition ${selected ? "border-cyan-300/60 bg-cyan-300/[0.08] shadow-[0_0_30px_rgba(34,211,238,.08)]" : "border-[#2a3448] bg-[#0d131d] hover:border-[#43516d]"}`}
    >
      <span className={`absolute inset-y-0 left-0 w-0.5 ${point.authoritative ? "bg-emerald-300" : point.mode === "monitor" ? "bg-sky-300" : "bg-amber-300"}`} />
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-slate-500">{point.provider} · {point.environment}</div>
          <div className="mt-1 text-sm font-semibold text-slate-100">{point.display_name}</div>
        </div>
        <Badge className={healthTone(point.health_state)}>{humanize(point.health_state)}</Badge>
      </div>
      <div className="mt-4 flex items-end justify-between">
        <div>
          <div className="font-mono text-2xl text-slate-100">{inlineClaims}</div>
          <div className="text-[10px] text-slate-500">inline dimensions</div>
        </div>
        <div className="text-right">
          <div className={`font-mono text-[10px] uppercase ${point.authoritative ? "text-emerald-200" : "text-amber-200"}`}>
            {point.authoritative ? "authoritative" : `${point.mode} · not current`}
          </div>
          <div className="mt-1 text-[10px] text-slate-600">{humanize(point.method)}</div>
        </div>
      </div>
    </button>
  );
}

export function NativeControlMatrix() {
  const [matrix, setMatrix] = useState<NativeCapabilityMatrix | null>(null);
  const [points, setPoints] = useState<NativeControlPoint[]>([]);
  const [selectedPointId, setSelectedPointId] = useState<string | null>(null);
  const [health, setHealth] = useState<NativeControlPointHealth | null>(null);
  const [providerFilter, setProviderFilter] = useState("all");
  const [actionId, setActionId] = useState("");
  const [selection, setSelection] = useState<NativeControlSelection | null>(null);
  const [selectionError, setSelectionError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [mutation, setMutation] = useState<"configure" | "validate" | "monitor" | "enforce" | "disable" | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [mutationMessage, setMutationMessage] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [matrixPayload, pointsPayload] = await Promise.all([
        api.nativeControlProviders(),
        api.nativeControlPoints(),
      ]);
      setMatrix(matrixPayload);
      setPoints(pointsPayload.items);
      setSelectedPointId((current) => current ?? pointsPayload.items[0]?.id ?? null);
      setError(null);
    } catch (reason: unknown) {
      setError(reason instanceof Error ? reason.message : "Native control framework unavailable");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const loadHealth = useCallback(async (controlPointId: string | null) => {
    if (!controlPointId) {
      setHealth(null);
      return;
    }
    try {
      setHealth(await api.nativeControlPointHealth(controlPointId));
    } catch {
      setHealth(null);
    }
  }, []);

  useEffect(() => {
    let active = true;
    if (!selectedPointId) {
      setHealth(null);
      return () => { active = false; };
    }
    api.nativeControlPointHealth(selectedPointId)
      .then((payload) => { if (active) setHealth(payload); })
      .catch(() => { if (active) setHealth(null); });
    return () => { active = false; };
  }, [selectedPointId]);

  const providers = useMemo(
    () => Array.from(new Set(matrix?.providers.map((manifest) => manifest.provider) ?? [])).sort(),
    [matrix],
  );
  const manifests = useMemo(
    () => (matrix?.providers ?? []).filter((manifest) => providerFilter === "all" || manifest.provider === providerFilter),
    [matrix, providerFilter],
  );
  const compatibilityRows = useMemo<Array<{
    manifest: NativeProviderManifest;
    point: NativeControlPoint | null;
  }>>(
    () => manifests.flatMap<{
      manifest: NativeProviderManifest;
      point: NativeControlPoint | null;
    }>((manifest) => {
      const matchingPoints = points.filter((point) => (
        point.provider === manifest.provider
        && point.product === manifest.product
        && point.method === manifest.method
      ));
      return matchingPoints.length
        ? matchingPoints.map((point) => ({ manifest, point }))
        : [{ manifest, point: null }];
    }),
    [manifests, points],
  );
  const selectedPoint = points.find((point) => point.id === selectedPointId) ?? null;
  const primaryControlPoint = selection?.primary_control_point
    ? points.find((point) => point.id === selection.primary_control_point)
    : null;

  async function inspectSelection() {
    const normalized = actionId.trim();
    if (!normalized) return;
    try {
      const payload = await api.nativeControlSelection(normalized);
      setSelection(payload);
      setSelectionError(null);
    } catch (reason: unknown) {
      setSelection(null);
      setSelectionError(reason instanceof Error ? reason.message : "Selection evidence not found");
    }
  }

  async function mutateControlPoint(action: "configure" | "validate" | "monitor" | "enforce" | "disable") {
    if (!selectedPoint) return;
    if (action === "enforce" && !window.confirm(`Enable inline enforcement for ${selectedPoint.display_name}? Hawk will refuse if any readiness evidence is missing.`)) return;
    if (action === "disable" && !window.confirm(`Disable ${selectedPoint.display_name}? It will immediately stop contributing active coverage.`)) return;
    setMutation(action);
    setMutationError(null);
    setMutationMessage(null);
    try {
      if (action === "configure") await api.configureNativeControlPoint(selectedPoint.id);
      if (action === "validate") {
        const result = await api.validateNativeControlPoint(selectedPoint.id);
        setMutationMessage(result.result === "passed" ? "Provider validation accepted; enforce readiness still depends on live health, route binding and rollout gates." : `Validation needs attention: ${result.reason_codes.map(humanize).join(" · ")}`);
      }
      if (action === "monitor") await api.monitorNativeControlPoint(selectedPoint.id);
      if (action === "enforce") await api.enforceNativeControlPoint(selectedPoint.id);
      if (action === "disable") await api.disableNativeControlPoint(selectedPoint.id);
      if (action !== "validate") setMutationMessage(`${humanize(action)} completed and confirmed by Hawk.`);
      await load();
      await loadHealth(selectedPoint.id);
    } catch (reason: unknown) {
      setMutationError(reason instanceof Error ? reason.message : `${humanize(action)} failed`);
      await loadHealth(selectedPoint.id);
    } finally {
      setMutation(null);
    }
  }

  if (loading && !matrix) {
    return (
      <section className="overflow-hidden border border-[#2a3448] bg-[#090e15]">
        <div className="h-1 animate-pulse bg-cyan-300/70" />
        <div className="grid animate-pulse gap-4 p-6 lg:grid-cols-[1fr_320px]">
          <div className="h-80 bg-[#121925]" /><div className="h-80 bg-[#121925]" />
        </div>
      </section>
    );
  }

  if (error && !matrix) {
    return (
      <section className="border border-amber-300/25 bg-[#10151e] p-6">
        <div className="flex items-start gap-3">
          <ShieldQuestion className="mt-0.5 h-5 w-5 text-amber-200" />
          <div>
            <h2 className="text-base font-semibold text-slate-100">Native Control truth is unavailable</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Hawk is not substituting configured integrations for verified protection. Enable and migrate the Native Control Framework to populate this matrix.
            </p>
            <Button className="mt-4" size="sm" variant="outline" onClick={() => void load()}>Retry</Button>
          </div>
        </div>
      </section>
    );
  }

  if (!matrix) return null;
  const verifiedCount = matrix.providers.filter((manifest) => manifest.effective_for_selection === true).length;
  const enforcingCount = points.filter((point) => point.authoritative).length;
  const acceptedProviderProof = health?.real_acceptance_current === true;
  const liveCallbackObserved = health?.callback_health === "authenticated_recently";
  const liveEvidenceFlowing = health?.evidence_flowing === true;
  const validationCurrent = health?.validation_current === true || acceptedProviderProof;

  return (
    <section className="relative overflow-hidden border border-[#2d394f] bg-[#080d14] text-slate-100">
      <div className="absolute inset-0 opacity-40" style={{ backgroundImage: "linear-gradient(rgba(103,232,249,.045) 1px, transparent 1px),linear-gradient(90deg,rgba(103,232,249,.045) 1px,transparent 1px)", backgroundSize: "24px 24px" }} />
      <div className="relative border-b border-[#273247] bg-gradient-to-r from-cyan-300/[0.08] via-transparent to-emerald-300/[0.05] px-5 py-5 md:px-7">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.24em] text-cyan-200">
              <Route className="h-3.5 w-3.5" /> Trusted control routing
            </div>
            <h2 className="mt-2 text-2xl font-semibold tracking-tight">Control Capability Matrix</h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              What every control point can actually see, bind, stop and prove. Verification and health—not installation—determine selection.
            </p>
          </div>
          <div className="grid grid-cols-3 gap-px overflow-hidden border border-[#2a3549] bg-[#2a3549]">
            {[
              ["Verified", verifiedCount, ShieldCheck],
              ["Enforcing", enforcingCount, Zap],
              ["Unknown", matrix.providers.filter((row) => row.verification_status === "unverified").length, ShieldQuestion],
            ].map(([label, value, Icon]) => {
              const Glyph = Icon as typeof ShieldCheck;
              return (
                <div key={String(label)} className="min-w-[92px] bg-[#0d131d] px-3 py-2.5">
                  <Glyph className="h-3.5 w-3.5 text-cyan-200" />
                  <div className="mt-2 font-mono text-xl">{String(value)}</div>
                  <div className="text-[9px] uppercase tracking-wider text-slate-600">{String(label)}</div>
                </div>
              );
            })}
          </div>
        </div>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-[#273247] pt-3">
          <span className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-600">{matrix.matrix_version}</span>
          <Button size="sm" variant="ghost" onClick={() => void load()} disabled={loading}>
            <RefreshCw className={`mr-2 h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />Refresh truth
          </Button>
        </div>
      </div>

      <div className="relative p-5 md:p-7">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-500">Active control points</div>
            <div className="mt-1 text-xs text-slate-600">Select one to inspect its trust state.</div>
          </div>
          <span className="font-mono text-xs text-cyan-200">{points.length} configured · {enforcingCount} authoritative</span>
        </div>
        {points.length ? (
          <div className="mt-3 flex gap-3 overflow-x-auto pb-2">
            {points.map((point) => (
              <ControlPointCard
                key={point.id}
                point={point}
                selected={point.id === selectedPointId}
                onSelect={() => setSelectedPointId(point.id)}
              />
            ))}
          </div>
        ) : (
          <div className="mt-3 border border-dashed border-[#334057] bg-[#0c121b] px-5 py-6 text-sm text-slate-500">
            No tenant control point is configured. Provider capability rows below remain reference truth and do not count as coverage.
          </div>
        )}

        <div className="mt-6 grid gap-5 2xl:grid-cols-[minmax(0,1fr)_360px]">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
              <button type="button" onClick={() => setProviderFilter("all")} className={`border px-3 py-1.5 font-mono text-[9px] uppercase tracking-wider ${providerFilter === "all" ? "border-cyan-300/50 bg-cyan-300/10 text-cyan-100" : "border-[#2b364a] text-slate-500"}`}>All providers</button>
              {providers.map((provider) => (
                <button key={provider} type="button" onClick={() => setProviderFilter(provider)} className={`border px-3 py-1.5 font-mono text-[9px] uppercase tracking-wider ${providerFilter === provider ? "border-cyan-300/50 bg-cyan-300/10 text-cyan-100" : "border-[#2b364a] text-slate-500 hover:text-slate-300"}`}>{provider}</button>
                ))}
              </div>

              <div className="mt-3 overflow-hidden border border-[#2b364a] bg-[#0b111a]">
                <div className="flex items-start justify-between gap-4 border-b border-[#273247] bg-gradient-to-r from-cyan-300/[0.06] to-transparent px-4 py-3">
                  <div>
                    <div className="font-mono text-[9px] uppercase tracking-[0.2em] text-cyan-200">Provider Compatibility</div>
                    <p className="mt-1 text-[11px] leading-5 text-slate-500">
                      Catalog support and tenant deployment proof are separate. Missing installation evidence remains Unknown.
                    </p>
                  </div>
                  <span className="shrink-0 font-mono text-[9px] uppercase tracking-wider text-slate-600">{compatibilityRows.length} routes</span>
                </div>
                <div className="flex gap-3 overflow-x-auto p-3">
                  {compatibilityRows.map(({ manifest, point }) => (
                    <div key={`compat:${manifest.manifest_id}:${point?.id ?? "catalog"}`} className="min-w-[350px] border border-[#273247] bg-[#090f17] p-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="text-xs font-semibold text-slate-100">{humanize(manifest.provider)} · {humanize(manifest.product)}</div>
                          <div className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">{humanize(manifest.method)}</div>
                          <div className="mt-1 font-mono text-[8px] text-slate-700">
                            {point ? `${point.environment} · ${point.deployment_family} · ${point.id}` : "Catalog only · no tenant route"}
                          </div>
                        </div>
                        <Badge className={verificationTone(manifest.verification_status)}>{humanize(manifest.verification_status)}</Badge>
                      </div>
                      <div className="mt-3 grid grid-cols-5 gap-1">
                        <CompatibilityFact label="Installed" state="unknown" />
                        <CompatibilityFact label="Configured" state={configuredFactState(point)} />
                        <CompatibilityFact label="Healthy" state={healthyFactState(point)} />
                        <CompatibilityFact label="Validated" state={point ? (point.validation_current ? "yes" : "no") : "unknown"} />
                        <CompatibilityFact label="Enforced" state={point ? (point.authoritative ? "yes" : "no") : "unknown"} />
                      </div>
                      <div className="mt-3 flex items-center justify-between gap-3 border-t border-[#202a3b] pt-2 font-mono text-[8px] text-slate-600">
                        <span>{manifest.supported_versions.length ? manifest.supported_versions.join(" · ") : "Version Unknown"}</span>
                        <span>{manifest.effective_for_selection ? "Selectable" : "Not selectable"}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-3 overflow-x-auto border border-[#2b364a]">
              <table className="w-full min-w-[2640px] border-collapse text-left">
                <thead>
                  <tr className="border-b border-[#2b364a] bg-[#101722]">
                    <th className="sticky left-0 z-10 w-56 bg-[#101722] px-4 py-3 font-mono text-[9px] uppercase tracking-[0.18em] text-slate-500">Provider · method</th>
                    {MATRIX_DIMENSIONS.map(([, label]) => <th key={label} className="w-28 px-2 py-3 text-center font-mono text-[9px] uppercase tracking-wider text-slate-500">{label}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {manifests.map((manifest) => (
                    <tr key={manifest.manifest_id} className="border-b border-[#202a3b] last:border-0">
                      <td className="sticky left-0 z-10 bg-[#0b111a] px-4 py-3">
                        <div className="flex items-center gap-2">
                          <CircleDot className={`h-3.5 w-3.5 ${manifest.verification_status === "verified" ? "text-emerald-300" : "text-amber-300"}`} />
                          <span className="text-xs font-semibold text-slate-200">{humanize(manifest.provider)} · {humanize(manifest.product)}</span>
                        </div>
                        <div className="mt-1.5 flex items-center justify-between gap-2">
                          <span className="font-mono text-[9px] text-slate-600">{humanize(manifest.method)}</span>
                          <Badge className={verificationTone(manifest.verification_status)}>{manifest.verification_status === "verified" ? "Verified" : manifest.verification_status === "unverified" ? "Unverified" : humanize(manifest.verification_status)}</Badge>
                        </div>
                      </td>
                      {MATRIX_DIMENSIONS.map(([dimension]) => <td key={dimension} className="bg-[#090f17] p-1.5"><MatrixCell claim={manifest.capability_matrix[dimension]} /></td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-2 flex flex-wrap gap-3 font-mono text-[9px] uppercase text-slate-600">
              <span className="text-emerald-200">Inline bound</span><span className="text-cyan-200">Inline</span><span className="text-violet-200">External</span><span className="text-sky-200">Observe</span><span className="text-amber-200">Unknown</span><span className="text-rose-200">Unavailable</span>
            </div>
          </div>

          <aside className="space-y-4">
            <div className="border border-[#2b364a] bg-[#0c121b] p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="flex items-center gap-2"><Gauge className="h-4 w-4 text-cyan-200" /><h3 className="text-sm font-semibold">Control-point health</h3></div>
                {selectedPoint ? <Badge className={healthTone(selectedPoint.health_state)}>{humanize(selectedPoint.health_state)}</Badge> : null}
              </div>
              {selectedPoint ? (
                <div className="mt-4 space-y-3">
                  <div>
                    <div className="text-base font-semibold text-slate-100">{selectedPoint.display_name}</div>
                    <div className="mt-1 font-mono text-[9px] uppercase tracking-wider text-slate-600">{selectedPoint.provider} · {selectedPoint.product} · {selectedPoint.method}</div>
                  </div>
                  <div className="border border-[#2a3549] bg-[#090f17] p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div>
                        <div className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Admin lifecycle</div>
                        <div className="mt-1 text-xs text-slate-300">{humanize(selectedPoint.state)} · {humanize(selectedPoint.mode)}</div>
                      </div>
                      {mutation ? <LoaderCircle className="h-4 w-4 animate-spin text-cyan-200" /> : null}
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-2">
                      <Button size="sm" variant="outline" disabled={mutation !== null || !["disabled", "degraded"].includes(selectedPoint.state)} onClick={() => void mutateControlPoint("configure")}><Settings2 className="mr-1.5 h-3.5 w-3.5" />Configure</Button>
                      <Button size="sm" variant="outline" disabled={mutation !== null || !["endpoint_runtime", "native_hook"].includes(selectedPoint.method) || selectedPoint.state === "disabled"} onClick={() => void mutateControlPoint("validate")}><PlayCircle className="mr-1.5 h-3.5 w-3.5" />Validate</Button>
                      <Button size="sm" variant="outline" disabled={mutation !== null || !["validating", "degraded", "enforcing"].includes(selectedPoint.state)} onClick={() => void mutateControlPoint("monitor")}><Activity className="mr-1.5 h-3.5 w-3.5" />Monitor</Button>
                      <Button size="sm" disabled={mutation !== null || selectedPoint.state !== "monitoring"} onClick={() => void mutateControlPoint("enforce")}><Zap className="mr-1.5 h-3.5 w-3.5" />Enforce</Button>
                      <Button size="sm" variant="outline" className="col-span-2 border-rose-300/25 text-rose-100 hover:bg-rose-300/10" disabled={mutation !== null || selectedPoint.state === "disabled"} onClick={() => void mutateControlPoint("disable")}><Power className="mr-1.5 h-3.5 w-3.5" />Disable</Button>
                    </div>
                    {selectedPoint.method !== "endpoint_runtime" && selectedPoint.method !== "native_hook" ? <p className="mt-2 text-[10px] leading-4 text-slate-600">This control method requires its signed workload validation flow; Hawk will not synthesize provider proof.</p> : null}
                    {mutationMessage ? <p className="mt-2 text-[10px] leading-4 text-emerald-200">{mutationMessage}</p> : null}
                    {mutationError ? <p className="mt-2 text-[10px] leading-4 text-rose-200">{mutationError}</p> : null}
                  </div>
                  <div className="space-y-2">
                    <HealthFactRow icon={Fingerprint} label="Configuration integrity" state={healthFactState(health?.configuration_integrity_valid)} />
                    <HealthFactRow icon={Cpu} label="Provider version" state={healthFactState(health?.provider_version_compatible)} />
                    <HealthFactRow icon={Cpu} label="Adapter version" state={healthFactState(health?.adapter_version_compatible)} />
                    <HealthFactRow
                      icon={ShieldCheck}
                      label="Accepted provider proof"
                      state={healthFactState(acceptedProviderProof)}
                      detail="Real binary / signed route acceptance. This is separate from a currently open live session."
                    />
                    <HealthFactRow
                      icon={KeyRound}
                      label="Live signed callback observed"
                      state={healthFactState(liveCallbackObserved)}
                      detail={acceptedProviderProof && !liveCallbackObserved ? "Accepted proof exists, but no fresh live callback is bound to the active credential right now." : undefined}
                    />
                    <HealthFactRow
                      icon={Activity}
                      label="Live evidence flowing"
                      state={healthFactState(liveEvidenceFlowing)}
                      detail={acceptedProviderProof && !liveEvidenceFlowing ? "Accepted validation evidence exists; live telemetry is not currently fresh enough for enforce readiness." : undefined}
                    />
                    <HealthFactRow icon={Activity} label="Policy freshness" state={healthFactState(health?.policy_fresh)} />
                    <HealthFactRow icon={ShieldCheck} label="Validation current" state={healthFactState(validationCurrent)} />
                    <HealthFactRow icon={Route} label="Route binding current" state={healthFactState(health?.route_binding_current)} />
                    <HealthFactRow
                      icon={Zap}
                      label="Enforcement feature enabled"
                      state={healthFactState(health?.enforcement_feature_active)}
                      detail={health?.enforcement_feature_active === false ? "Provider proof can be accepted while tenant rollout or provider enforcement flags still prevent enforce mode." : undefined}
                    />
                    <HealthFactRow
                      icon={ShieldCheck}
                      label="Active for enforcement"
                      state={healthFactState(health?.active_for_enforcement)}
                      detail="Requires accepted proof, fresh callback/evidence, current policy, route binding and enabled rollout gates."
                    />
                    <HealthFactRow icon={ShieldCheck} label="Verified active profile" state={healthFactState(health ? health.profile_active && health.profile_verification === "verified" : undefined)} />
                  </div>
                  {selectedPoint.provider === "anthropic" && selectedPoint.product === "claude_code" ? (
                    <div className="border border-[#2a3549] bg-[#090f17] p-3">
                      <div className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">Claude lifecycle truth</div>
                      <div className="mt-2 grid gap-px bg-[#273247]">
                        {[
                          ["PreToolUse", "Hawk authorizes before execution"],
                          ["PermissionRequest", "Provider context; reuses the exact Hawk decision"],
                          ["PostToolUse / Failure", "Provider-reported evidence; never prevention"],
                          ["ConfigChange", "Secondary integrity signal; fingerprint stays authoritative"],
                        ].map(([event, meaning]) => (
                          <div key={event} className="grid grid-cols-[118px_1fr] gap-3 bg-[#0a1018] px-2.5 py-2">
                            <span className="font-mono text-[9px] text-cyan-200">{event}</span>
                            <span className="text-[10px] leading-4 text-slate-400">{meaning}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  <div className="grid grid-cols-2 gap-px bg-[#273247]">
                    {[
                      ["Authorization", selectedPoint.capabilities.tool_control],
                      ["Parameter binding", selectedPoint.capabilities.parameter_binding],
                      ["Provider permission", selectedPoint.capabilities.provider_permission_context],
                      ["Hawk approval binding", selectedPoint.capabilities.hawk_approval_binding],
                      ["Approval correlation", selectedPoint.capabilities.approval_correlation],
                      ["Tool failure visibility", selectedPoint.capabilities.tool_failure_visibility],
                      ["Execution correlation", selectedPoint.capabilities.execution_correlation],
                      ["Config change visibility", selectedPoint.capabilities.config_change_visibility],
                      ["Execution proof", selectedPoint.capabilities.post_execution_verification],
                    ].map(([label, claim]) => (
                      <div key={String(label)} className="bg-[#0a1018] p-2.5">
                        <div className="font-mono text-[9px] text-slate-600">{String(label)}</div>
                        <div className="mt-1 text-[10px] font-semibold text-slate-300">{capabilityLabel(claim as NativeCapabilityClaim | undefined)}</div>
                      </div>
                    ))}
                  </div>
                  <div className="space-y-1.5 border-t border-[#273247] pt-3 font-mono text-[9px] text-slate-500">
                    <div className="flex justify-between gap-3"><span>Last action</span><span className="max-w-[190px] truncate text-slate-300">{health?.last_action_id ?? "Unknown"}</span></div>
                    <div className="flex justify-between gap-3"><span>Last selector outcome</span><span className="text-slate-300">{health?.last_selection_reason ? humanize(health.last_selection_reason) : "Unknown"}</span></div>
                    <div className="flex justify-between gap-3"><span>Current assurance</span><span className="text-slate-300">{health?.current_assurance != null ? `A${health.current_assurance}` : "Unknown"}</span></div>
                    <div className="flex justify-between gap-3"><span>Expected latency</span><span className="text-slate-300">{health?.expected_latency_ms != null ? `${health.expected_latency_ms} ms` : "Unknown"}</span></div>
                    <div className="flex justify-between gap-3"><span>Observed p95 latency</span><span className="text-slate-300">{health?.observed_latency_ms != null ? `${health.observed_latency_ms} ms` : "Unknown"}</span></div>
                  </div>
                </div>
              ) : <p className="mt-4 text-xs leading-5 text-slate-600">Select a configured point to inspect its current recorded health evidence.</p>}
            </div>

            <div className="border border-rose-300/20 bg-rose-300/[0.035] p-4">
              <div className="flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-rose-200" /><h3 className="text-sm font-semibold">Known blind spots</h3></div>
              {selectedPoint?.known_blind_spots.length ? (
                <ul className="mt-3 space-y-2">
                  {selectedPoint.known_blind_spots.map((spot) => <li key={spot} className="border-l border-rose-300/30 pl-3 text-xs leading-5 text-slate-400">{spot}</li>)}
                </ul>
              ) : <p className="mt-3 text-xs leading-5 text-slate-600">No verified blind-spot evidence is attached to the selected point. This does not mean none exist.</p>}
            </div>

            <div className="border border-cyan-300/20 bg-cyan-300/[0.035] p-4">
              <div className="flex items-center gap-2"><GitBranch className="h-4 w-4 text-cyan-200" /><h3 className="text-sm font-semibold">Why this control point?</h3></div>
              <p className="mt-2 text-xs leading-5 text-slate-500">Enter an AI Action ID to replay the deterministic selection explanation.</p>
              <div className="mt-3 flex gap-2">
                <Input value={actionId} onChange={(event) => setActionId(event.target.value)} placeholder="action-id" className="h-9 font-mono text-xs" />
                <Button size="sm" onClick={() => void inspectSelection()} aria-label="Inspect control selection"><Search className="h-3.5 w-3.5" /></Button>
              </div>
              {selectionError ? <p className="mt-3 text-xs leading-5 text-amber-200">{selectionError}</p> : null}
              {selection ? (
                <div className="mt-4 space-y-3">
                  <div className={`flex items-center gap-2 border p-3 ${selection.primary_control_point ? "border-emerald-300/20 bg-emerald-300/[0.06]" : "border-amber-300/25 bg-amber-300/[0.06]"}`}>
                    {selection.primary_control_point ? <ShieldCheck className="h-4 w-4 text-emerald-200" /> : <ShieldQuestion className="h-4 w-4 text-amber-200" />}
                    <div><div className={`text-[10px] uppercase tracking-wider ${selection.primary_control_point ? "text-emerald-200" : "text-amber-200"}`}>{selection.primary_control_point ? "Primary" : "Unsatisfied"}</div><div className="mt-0.5 text-xs text-slate-200">{primaryControlPoint?.display_name ?? selection.primary_control_point ?? "No verified control point satisfied this action"}</div></div>
                  </div>
                  <div className="flex flex-wrap gap-1.5">{selection.satisfied_capabilities.map((item) => <span key={item} className="border border-emerald-300/20 bg-emerald-300/[0.05] px-2 py-1 text-[9px] text-emerald-100">{humanize(item)}</span>)}</div>
                  {selection.rejected_candidates.map((candidate) => (
                    <div key={candidate.control_point_id} className="border-l border-rose-300/30 pl-3">
                      <div className="font-mono text-[9px] text-slate-600">Rejected · {candidate.control_point_id}</div>
                      <div className="mt-1 text-[10px] leading-4 text-rose-100/80">{candidate.reason_codes.map(humanize).join(" · ")}</div>
                    </div>
                  ))}
                  <div className="flex items-center justify-between border-t border-[#273247] pt-3 font-mono text-[9px] text-slate-600"><span>A{selection.assurance_level}</span><span>{selection.selector_version}</span></div>
                </div>
              ) : null}
              {!selection && !selectionError ? <div className="mt-4 flex items-center gap-2 text-[10px] text-slate-600"><ArrowRight className="h-3.5 w-3.5" />Selection evidence includes every rejected candidate.</div> : null}
            </div>
          </aside>
        </div>
      </div>
    </section>
  );
}
