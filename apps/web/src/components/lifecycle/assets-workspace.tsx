"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { ArrowRight, Bot, Boxes, KeyRound, RefreshCw, Search, UserRoundCheck } from "lucide-react";

import { WorkspaceHeader } from "@/components/lifecycle/workspace-header";
import { WorkspaceLinks } from "@/components/lifecycle/workspace-links";
import { ChatGPTDesktopAsset } from "@/components/lifecycle/chatgpt-desktop-asset";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { AIIAMIdentityProfile, AISystem, ControlCoveragePath } from "@/lib/types";
import { cn } from "@/lib/utils";

function scoreTone(score: number): string {
  if (score >= 75) return "text-rose-300";
  if (score >= 45) return "text-amber-300";
  return "text-emerald-300";
}

function firstOrUnknown(values: string[]): string {
  return values.length ? values.slice(0, 4).join(", ") : "Unknown — no verified data";
}

type SourceState = "loading" | "ready" | "stale" | "unavailable";

function sourceValue(state: SourceState, count: number): string {
  if (state === "loading") return "—";
  if (state === "unavailable") return "Unavailable";
  if (state === "stale") return count ? `${count.toLocaleString()} · stale` : "Stale";
  return count.toLocaleString();
}

function sourceLabel(state: SourceState): string {
  if (state === "loading") return "Loading source";
  if (state === "unavailable") return "Unavailable";
  if (state === "stale") return "Stale source";
  return "Source ready";
}

export function AssetsWorkspace() {
  const [systems, setSystems] = useState<AISystem[]>([]);
  const [identities, setIdentities] = useState<AIIAMIdentityProfile[]>([]);
  const [paths, setPaths] = useState<ControlCoveragePath[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [systemState, setSystemState] = useState<SourceState>("loading");
  const [identityState, setIdentityState] = useState<SourceState>("loading");
  const [pathState, setPathState] = useState<SourceState>("loading");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [systemResult, identityResult, pathResult] = await Promise.allSettled([
        api.listAISystems(),
        api.listAIIAMIdentities({ page: 1, page_size: 100, lookback_hours: 168 }),
        api.controlCoveragePaths("page=1&page_size=100"),
      ]);
      if (systemResult.status === "fulfilled") {
        setSystems(systemResult.value.items || []);
        setSystemState("ready");
      } else {
        setSystemState(systems.length ? "stale" : "unavailable");
      }
      if (identityResult.status === "fulfilled") {
        setIdentities(identityResult.value.items || []);
        setSelectedId((current) => current || identityResult.value.items?.[0]?.identity_id || "");
        setIdentityState("ready");
      } else {
        setIdentityState(identities.length ? "stale" : "unavailable");
      }
      if (pathResult.status === "fulfilled") {
        setPaths(pathResult.value.items || []);
        setPathState("ready");
      } else {
        setPathState(paths.length ? "stale" : "unavailable");
      }
      const unavailable = [
        systemResult.status === "rejected" ? "AI systems" : null,
        identityResult.status === "rejected" ? "AI identities" : null,
        pathResult.status === "rejected" ? "Control Coverage paths" : null,
      ].filter(Boolean);
      setError(unavailable.length ? `${unavailable.join(", ")} unavailable. Available inventory remains visible.` : null);
    } catch {
      setSystemState(systems.length ? "stale" : "unavailable");
      setIdentityState(identities.length ? "stale" : "unavailable");
      setPathState(paths.length ? "stale" : "unavailable");
      setError("Asset inventory is unavailable. Hawk is not presenting synthetic assets.");
    } finally {
      setLoading(false);
    }
  }, [systems.length, identities.length, paths.length]);

  useEffect(() => { void load(); }, [load]);

  const visible = useMemo(() => identities.filter((identity) => {
    if (!query.trim()) return true;
    const term = query.toLowerCase();
    return `${identity.identity_id} ${identity.type} ${identity.owner || ""} ${identity.model || ""} ${identity.environment.join(" ")}`.toLowerCase().includes(term);
  }), [identities, query]);
  const selected = identities.find((identity) => identity.identity_id === selectedId) || visible[0] || null;
  const identityPaths = selected ? paths.filter((path) => path.identity_ref === selected.identity_id || path.identity_ref.includes(selected.identity_id)) : [];
  const uncovered = identityPaths.flatMap((path) => path.assertions).filter((assertion) => assertion.state === "not_covered" || assertion.state === "unknown");
  const recommendedPolicy = selected?.controls.missed_controls[0] || uncovered[0]?.explanation || "No evidence-backed policy recommendation available";

  return (
    <div className="space-y-5">
      <WorkspaceHeader
        eyebrow="Assets"
        title="Know every AI system, identity, and access path"
        description="Review AI systems, identities, owners, and access paths with source-backed evidence."
        actions={<Button variant="outline" onClick={() => void load()} disabled={loading}><RefreshCw className={cn("mr-2 h-4 w-4", loading && "animate-spin")} />Refresh inventory</Button>}
      />

      {error ? <div className="rounded-2xl border border-amber-400/20 bg-amber-400/[0.06] px-4 py-3 text-sm text-amber-200">{error}</div> : null}

      <section className="grid gap-4 xl:grid-cols-[23rem_minmax(0,1fr)]">
        <div className="overflow-hidden rounded-[22px] border border-white/[0.07] bg-[#0c1016]">
          <div className="border-b border-white/[0.06] p-3">
            <div className="mb-3"><h2 className="text-sm font-semibold text-white">Searchable inventory</h2><p className="mt-1 text-xs text-slate-500">Find identities, owners, models, and access context.</p></div>
            <label className="relative block">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-600" />
              <input aria-label="Search identities, owners, and models" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search identities, owners, or models" className="h-10 w-full rounded-xl border border-white/[0.07] bg-black/20 pl-10 pr-3 text-sm text-slate-200 outline-none placeholder:text-slate-600 focus:border-orange-400/30" />
            </label>
          </div>
          <div className="max-h-[44rem] overflow-y-auto p-2">
            {!loading && identityState === "unavailable" ? <p className="p-8 text-center text-sm text-slate-500">Identity source unavailable. No empty inventory is being inferred.</p> : null}
            {!loading && identityState !== "unavailable" && !visible.length ? <p className="p-8 text-center text-sm text-slate-600">No known identities match this view.</p> : null}
            {visible.map((identity) => (
              <button key={identity.identity_id} type="button" onClick={() => setSelectedId(identity.identity_id)} className={cn("mb-1 w-full rounded-2xl border p-3 text-left transition", selected?.identity_id === identity.identity_id ? "border-orange-400/20 bg-orange-400/[0.055]" : "border-transparent hover:border-white/[0.06] hover:bg-white/[0.025]")}>
                <div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-100">{identity.identity_id}</p><p className="mt-1 truncate text-[11px] capitalize text-slate-500">{identity.type} · {identity.owner || "owner unknown"}{identityState === "stale" ? " · stale" : ""}</p></div><span className={cn("text-sm font-semibold", scoreTone(identity.risk_score))}>{Math.round(identity.risk_score)}</span></div>
              </button>
            ))}
          </div>
        </div>

        <div className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-5">
          {selected ? (
            <div>
              <div className="flex flex-col gap-4 border-b border-white/[0.06] pb-5 sm:flex-row sm:items-start sm:justify-between">
                <div><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-orange-300/70">Selected identity</p><h2 className="mt-2 text-xl font-semibold text-white">{selected.identity_id}</h2><p className="mt-1 text-xs capitalize text-slate-500">{selected.type} · {selected.status} · {selected.environment.join(", ") || "environment unknown"}{identityState === "stale" ? " · stale source" : ""}</p></div>
                <Button asChild variant="outline" size="sm"><Link href={`/ai-iam?identity_id=${encodeURIComponent(selected.identity_id)}`}>Open full identity <ArrowRight className="ml-2 h-3.5 w-3.5" /></Link></Button>
              </div>

              <div className="mt-5 grid gap-3 md:grid-cols-2">
                {[
                  { step: "01", title: "Owner", value: selected.owner || "Unknown — ownership not attested", note: "Accountable owner for this identity" },
                  { step: "02", title: "Delegated authority", value: firstOrUnknown(selected.permissions.actions), note: `${selected.token_control.active_token_count} active credential references` },
                  { step: "03", title: "Tools & data", value: firstOrUnknown([...selected.permissions.tools, ...selected.permissions.data]), note: `${selected.permissions.tools.length} tools · ${selected.permissions.data.length} data scopes` },
                  { step: "04", title: "Risky path", value: pathState === "unavailable" ? "Unavailable — path source did not respond" : identityPaths.length ? `${identityPaths.length} observed path${identityPaths.length === 1 ? "" : "s"}${pathState === "stale" ? " · stale" : ""}` : "Unknown — no path evidence", note: uncovered.length ? `${uncovered.length} uncovered or unknown assertions` : pathState === "stale" ? "Retained from a stale source" : "No uncovered assertion in the loaded window" },
                  { step: "05", title: "Recommended policy", value: recommendedPolicy, note: "Derived from missed controls and path assertions" },
                  { step: "06", title: "Evidence", value: identityPaths.length ? `${identityPaths.flatMap((path) => path.assertions).flatMap((assertion) => assertion.evidence_refs).length} evidence references` : "Unknown — no linked evidence", note: `Updated ${selected.updated_at ? new Date(selected.updated_at).toLocaleString() : "time unknown"}` },
                ].map((item) => (
                  <div key={item.step} className="rounded-2xl border border-white/[0.055] bg-white/[0.018] p-4">
                    <div className="flex items-center gap-2"><span className="font-mono text-[10px] text-orange-300/60">{item.step}</span><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">{item.title}</p></div>
                    <p className="mt-3 text-sm font-medium leading-6 text-slate-200">{item.value}</p><p className="mt-2 text-[11px] leading-5 text-slate-600">{item.note}</p>
                  </div>
                ))}
              </div>
            </div>
          ) : <div className="grid min-h-[30rem] place-items-center text-sm text-slate-600">Select an identity to inspect its authority path.</div>}
        </div>
      </section>

      <details className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-4">
        <summary className="cursor-pointer text-sm font-semibold text-white">Inventory metrics and ChatGPT Desktop evidence</summary>
        <div className="mt-4 space-y-5">
          <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {[
              { label: "AI systems", value: sourceValue(systemState, systems.length), state: systemState, icon: Boxes },
              { label: "Known identities", value: sourceValue(identityState, identities.length), state: identityState, icon: UserRoundCheck },
              { label: "Agent identities", value: sourceValue(identityState, identities.filter((item) => item.type === "agent").length), state: identityState, icon: Bot },
              { label: "Verified paths", value: sourceValue(pathState, paths.length), state: pathState, icon: KeyRound },
            ].map((item) => {
              const Icon = item.icon;
              return <div key={item.label} className="rounded-[20px] border border-white/[0.07] bg-black/20 p-4"><div className="flex items-center justify-between"><p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{item.label}</p><Icon className="h-4 w-4 text-orange-300/70" /></div><p className="mt-3 text-2xl font-semibold text-white">{item.value}</p><p className="mt-1 text-[10px] uppercase tracking-[0.12em] text-slate-600">{sourceLabel(item.state)}</p></div>;
            })}
          </section>
          <ChatGPTDesktopAsset />
        </div>
      </details>

      <WorkspaceLinks links={[
        { href: "/ai-footprint", label: "AI footprint", description: "Review systems, applications and discovered providers." },
        { href: "/ai-iam", label: "AI IAM", description: "Manage identity posture, tokens, authority and kill switches." },
        { href: "/discovery/overview", label: "Discovery", description: "Inspect observed applications, findings and collection health." },
      ]} />
    </div>
  );
}
