"use client";

import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { ControlCoverageAssertion, ControlCoveragePath, ControlCoveragePathList } from "@/lib/types";

const DIMENSIONS = ["", "discovery", "identity", "authorization", "evidence", "deployment", "runtime", "bypass"];
const STATES = ["", "covered", "not_covered", "unknown"];
const IDENTITY_TYPES = ["", "user", "agent", "service_identity", "unknown"];

function stateClass(state: ControlCoverageAssertion["state"]): string {
  if (state === "covered") return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
  if (state === "not_covered") return "border-rose-400/30 bg-rose-400/10 text-rose-200";
  if (state === "unknown") return "border-amber-400/30 bg-amber-400/10 text-amber-200";
  return "border-slate-400/20 bg-slate-400/10 text-slate-300";
}

function stateLabel(state: string): string {
  if (state === "not_covered") return "Not Covered";
  if (state === "covered") return "Covered";
  if (state === "unknown") return "Unknown";
  return "Not Applicable";
}

function PathNode({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 flex-1 border border-[#2a3348] bg-[#111722] px-3 py-2.5">
      <div className="font-mono text-[9px] uppercase tracking-[0.18em] text-slate-600">{label}</div>
      <div className="mt-1 truncate text-xs font-medium text-slate-200" title={value}>{value}</div>
    </div>
  );
}

function PathRow({ path }: { path: ControlCoveragePath }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <article className="border border-[#293247] bg-[#0e131c]">
      <button
        type="button"
        className="w-full p-4 text-left hover:bg-white/[0.02]"
        onClick={() => setExpanded((value) => !value)}
        aria-expanded={expanded}
      >
        {/* approved path: asset → identity → runtime → deployment surface → destination/tool */}
        <div className="grid items-stretch gap-1.5 md:grid-cols-[1fr_auto_1fr_auto_1fr_auto_1fr_auto_1fr]">
          <PathNode label="asset" value={path.asset_ref} />
          <span className="hidden self-center text-slate-600 md:block">→</span>
          <PathNode label={`identity · ${path.identity_type}`} value={path.identity_ref} />
          <span className="hidden self-center text-slate-600 md:block">→</span>
          <PathNode label="runtime" value={path.runtime_ref} />
          <span className="hidden self-center text-slate-600 md:block">→</span>
          <PathNode label="deployment surface" value={path.deployment_surface_ref} />
          <span className="hidden self-center text-slate-600 md:block">→</span>
          <PathNode label="destination/tool" value={path.destination_ref} />
        </div>
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-500">
          <span className="font-mono">{path.path_key.slice(0, 16)}…</span>
          <span>{path.assertions.length} dimension assertions · last seen {new Date(path.last_seen_at).toLocaleString()}</span>
        </div>
      </button>

      {expanded ? (
        <div className="grid gap-2 border-t border-[#293247] bg-[#0b1018] p-4 lg:grid-cols-2">
          {path.assertions.map((assertion) => (
            <div key={assertion.assertion_id} className="border border-[#252e42] bg-[#121823] p-3">
              <div className="flex items-center justify-between gap-3">
                <span className="text-xs font-semibold capitalize text-slate-200">{assertion.dimension}</span>
                <span className={`rounded-sm border px-2 py-1 font-mono text-[9px] uppercase tracking-wider ${stateClass(assertion.state)}`}>
                  {stateLabel(assertion.state)}
                </span>
              </div>
              <p className="mt-2 text-xs leading-5 text-slate-400">{assertion.explanation}</p>
              <div className="mt-2 font-mono text-[10px] text-slate-600">{assertion.reason_code}</div>
              {assertion.evidence_refs.length ? (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {assertion.evidence_refs.map((reference) => (
                    <span key={reference} className="max-w-full truncate rounded-sm bg-cyan-400/[0.07] px-2 py-1 font-mono text-[9px] text-cyan-200/80" title={reference}>
                      {reference}
                    </span>
                  ))}
                </div>
              ) : (
                <div className="mt-3 text-[10px] text-slate-600">No supporting evidence reference</div>
              )}
            </div>
          ))}
        </div>
      ) : null}
    </article>
  );
}

export function PathExplorer() {
  const [dimension, setDimension] = useState("");
  const [state, setState] = useState("");
  const [identityType, setIdentityType] = useState("");
  const [identityRef, setIdentityRef] = useState("");
  const [assetRef, setAssetRef] = useState("");
  const [appliedQuery, setAppliedQuery] = useState("page=1&page_size=20");
  const [data, setData] = useState<ControlCoveragePathList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    api.controlCoveragePaths(appliedQuery)
      .then((payload) => {
        if (cancelled) return;
        setData(payload);
        setError(null);
      })
      .catch((reason: unknown) => {
        if (cancelled) return;
        setError(reason instanceof Error ? reason.message : "Path query unavailable");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  }, [appliedQuery]);

  const activeFilters = useMemo(
    () => [dimension, state, identityType, identityRef.trim(), assetRef.trim()].filter(Boolean).length,
    [assetRef, dimension, identityRef, identityType, state],
  );

  function applyFilters() {
    const query = new URLSearchParams({ page: "1", page_size: "20" });
    if (dimension) query.set("dimension", dimension);
    if (state) query.set("state", state);
    if (identityType) query.set("identity_type", identityType);
    if (identityRef.trim()) query.set("identity_ref", identityRef.trim());
    if (assetRef.trim()) query.set("asset_ref", assetRef.trim());
    setAppliedQuery(query.toString());
  }

  return (
    <section className="rounded-xl border border-[#293247] bg-[#10141e] p-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-cyan-300">Path-native evidence</div>
          <h3 className="mt-1 text-lg font-semibold text-slate-100">Governable path explorer</h3>
          <p className="mt-1 text-xs text-slate-500">Each row is one unique observed path—not an asset or user counted again.</p>
        </div>
        <span className="font-mono text-xs text-slate-400">{loading ? "querying…" : `${data?.total ?? 0} paths`}</span>
      </div>

      <div className="mt-4 grid gap-2 border-y border-[#273045] py-4 md:grid-cols-2 xl:grid-cols-5">
        <select aria-label="Coverage dimension" value={dimension} onChange={(event) => setDimension(event.target.value)} className="h-10 border border-[#2a3348] bg-[#0d121b] px-3 text-xs text-slate-300">
          {DIMENSIONS.map((value) => <option key={value || "all"} value={value}>{value || "All dimensions"}</option>)}
        </select>
        <select aria-label="Coverage state" value={state} onChange={(event) => setState(event.target.value)} className="h-10 border border-[#2a3348] bg-[#0d121b] px-3 text-xs text-slate-300">
          {STATES.map((value) => <option key={value || "all"} value={value}>{value ? stateLabel(value) : "All states"}</option>)}
        </select>
        <select aria-label="Identity type" value={identityType} onChange={(event) => setIdentityType(event.target.value)} className="h-10 border border-[#2a3348] bg-[#0d121b] px-3 text-xs capitalize text-slate-300">
          {IDENTITY_TYPES.map((value) => <option key={value || "all"} value={value}>{value ? value.replaceAll("_", " ") : "All identity types"}</option>)}
        </select>
        <Input aria-label="Identity reference" value={identityRef} onChange={(event) => setIdentityRef(event.target.value)} placeholder="user / agent / service identity" className="rounded-none bg-[#0d121b] text-xs" />
        <Input aria-label="Asset reference" value={assetRef} onChange={(event) => setAssetRef(event.target.value)} placeholder="asset reference" className="rounded-none bg-[#0d121b] text-xs" />
        <div className="flex items-center gap-2 xl:col-span-5">
          <Button size="sm" onClick={applyFilters}>Apply server filters</Button>
          <span className="text-[11px] text-slate-500">{activeFilters} active</span>
        </div>
      </div>

      {error ? (
        <div className="mt-4 border border-amber-400/25 bg-amber-400/[0.07] p-4 text-sm text-amber-100">Path evidence unavailable: {error}</div>
      ) : null}
      {!error && loading ? <div className="mt-4 h-28 animate-pulse bg-[#151b27]" /> : null}
      {!error && !loading && data?.items.length ? (
        <div className="mt-4 space-y-2">{data.items.map((path) => <PathRow key={path.path_id} path={path} />)}</div>
      ) : null}
      {!error && !loading && !data?.items.length ? (
        <div className="mt-4 border border-dashed border-[#30394d] bg-[#0d1119] p-6 text-sm text-slate-400">No observed paths match these filters.</div>
      ) : null}
    </section>
  );
}
