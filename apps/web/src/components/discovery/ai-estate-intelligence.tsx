"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Bot,
  Boxes,
  CircleAlert,
  CloudCog,
  Database,
  Fingerprint,
  Network,
  Radar,
  RefreshCw,
  ScanSearch,
  Search,
  ShieldCheck,
  Sparkles,
  UserRoundSearch,
} from "lucide-react";
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type {
  DiscoveryAssetSummary,
  DiscoveryCollectorHealth,
  DiscoveryCoverageProjection,
  DiscoveryEcosystem,
  DiscoveryEstateSummary,
  DiscoveryIntelligenceFinding,
  UnknownAIItem,
} from "@/lib/types";


const RESOLUTION_COLORS = {
  confirmed: "#34d399",
  probable: "#fbbf24",
  ambiguous: "#fb7185",
};

const SURFACE_ICONS: Record<string, typeof Radar> = {
  agent: Bot,
  agent_framework: Bot,
  model: Sparkles,
  model_endpoint: Sparkles,
  vector_database: Database,
  knowledge_base: Database,
  mcp_server: Network,
  mcp_client: Network,
  mcp_tool: Network,
  ai_saas: CloudCog,
};

function formatLabel(value: string | null | undefined): string {
  return String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function timeAgo(value: string): string {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return "Unknown time";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function signalTone(value: string): string {
  if (["confirmed", "verified", "active", "healthy"].includes(value)) {
    return "border-emerald-400/25 bg-emerald-400/10 text-emerald-200";
  }
  if (["probable", "occasional", "warning", "stale"].includes(value)) {
    return "border-amber-400/25 bg-amber-400/10 text-amber-200";
  }
  if (["ambiguous", "unknown", "degraded", "offline"].includes(value)) {
    return "border-rose-400/25 bg-rose-400/10 text-rose-200";
  }
  return "border-slate-400/20 bg-slate-400/10 text-slate-200";
}

function MetricTile({
  label,
  value,
  note,
  icon: Icon,
  tone,
}: {
  label: string;
  value: number | string;
  note: string;
  icon: typeof Radar;
  tone: string;
}) {
  return (
    <div className="group relative overflow-hidden rounded-[22px] border border-white/[0.07] bg-[#101821]/90 p-4 shadow-[0_16px_55px_rgba(0,0,0,0.28)] transition hover:-translate-y-0.5 hover:border-white/15">
      <div className={`absolute -right-6 -top-8 h-24 w-24 rounded-full blur-3xl ${tone}`} />
      <div className="relative flex items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.22em] text-slate-500">{label}</p>
          <p className="mt-2 font-mono text-3xl font-semibold tracking-tight text-white">{value}</p>
          <p className="mt-1 text-xs leading-5 text-slate-400">{note}</p>
        </div>
        <div className="rounded-2xl border border-white/10 bg-white/[0.04] p-2.5 text-slate-300">
          <Icon className="h-4 w-4" />
        </div>
      </div>
    </div>
  );
}

function ResolutionDonut({ summary }: { summary: DiscoveryEstateSummary }) {
  const data = [
    { name: "Confirmed", value: summary.confirmed_assets, color: RESOLUTION_COLORS.confirmed },
    { name: "Probable", value: summary.probable_assets, color: RESOLUTION_COLORS.probable },
    { name: "Ambiguous", value: summary.ambiguous_assets, color: RESOLUTION_COLORS.ambiguous },
  ];
  const hasData = data.some((item) => item.value > 0);
  const chart = hasData ? data : [{ name: "No assets", value: 1, color: "#263240" }];
  return (
    <div className="relative h-56" role="img" aria-label="Asset resolution distribution">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={chart} dataKey="value" nameKey="name" innerRadius={62} outerRadius={88} paddingAngle={hasData ? 4 : 0} stroke="none">
            {chart.map((item) => <Cell key={item.name} fill={item.color} />)}
          </Pie>
          <Tooltip
            contentStyle={{ background: "#0a1119", border: "1px solid #273445", borderRadius: 12, fontSize: 11 }}
            itemStyle={{ color: "#e2e8f0" }}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 grid place-items-center text-center">
        <div>
          <p className="font-mono text-4xl font-semibold text-white">{summary.assets_total}</p>
          <p className="font-mono text-[9px] uppercase tracking-[0.22em] text-slate-500">Known assets</p>
        </div>
      </div>
    </div>
  );
}

function EvidenceRiver({ assets, findings }: { assets: DiscoveryAssetSummary[]; findings: DiscoveryIntelligenceFinding[] }) {
  const signals = [
    ...assets.slice(0, 6).map((asset) => ({
      id: `asset-${asset.asset_id}`,
      label: asset.canonical_name,
      detail: `${formatLabel(asset.usage_state)} · ${formatLabel(asset.resolution_state)}`,
      state: asset.resolution_state,
      href: `/discovery/assets/${encodeURIComponent(asset.asset_id)}`,
    })),
    ...findings.slice(0, 4).map((finding) => ({
      id: `finding-${finding.finding_id}`,
      label: formatLabel(finding.finding_type),
      detail: `${formatLabel(finding.severity)} finding · ${finding.occurrence_count}×`,
      state: finding.severity === "high" || finding.severity === "critical" ? "ambiguous" : "probable",
      href: `/discovery/assets/${encodeURIComponent(finding.asset_id)}`,
    })),
  ];
  if (!signals.length) {
    return <p className="py-10 text-center text-sm text-slate-500">No observation or finding has entered the evidence river yet.</p>;
  }
  const doubled = [...signals, ...signals];
  return (
    <div className="estate-river relative overflow-hidden py-3">
      <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-16 bg-gradient-to-r from-[#0b1219] to-transparent" />
      <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-16 bg-gradient-to-l from-[#0b1219] to-transparent" />
      <div className="estate-river-track flex w-max gap-3">
        {doubled.map((signal, index) => (
          <Link
            key={`${signal.id}-${index}`}
            href={signal.href}
            className="group flex min-w-[235px] items-center gap-3 rounded-2xl border border-white/[0.07] bg-white/[0.035] px-3 py-2.5 transition hover:border-cyan-300/30 hover:bg-cyan-300/[0.06]"
          >
            <span className={`relative h-2.5 w-2.5 rounded-full ${signal.state === "confirmed" ? "bg-emerald-400" : signal.state === "probable" ? "bg-amber-400" : "bg-rose-400"}`}>
              <span className="absolute inset-0 animate-ping rounded-full bg-current opacity-40" />
            </span>
            <span className="min-w-0">
              <span className="block truncate text-xs font-medium text-slate-100">{signal.label}</span>
              <span className="block truncate font-mono text-[9px] uppercase tracking-wider text-slate-500">{signal.detail}</span>
            </span>
            <ArrowUpRight className="ml-auto h-3.5 w-3.5 text-slate-600 transition group-hover:text-cyan-300" />
          </Link>
        ))}
      </div>
    </div>
  );
}

function UnknownEvidenceCard({ item }: { item: UnknownAIItem }) {
  return (
    <Link
      href="/discovery/unknown"
      className="group flex items-center gap-3 border-b border-white/[0.055] px-5 py-4 transition last:border-0 hover:bg-amber-300/[0.035]"
    >
      <span className="grid h-10 w-10 shrink-0 place-items-center rounded-2xl border border-amber-300/15 bg-amber-300/[0.07] font-mono text-[10px] text-amber-100">
        {Math.round(item.confidence * 100)}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-slate-100">{item.label}</span>
        <span className="mt-1 block truncate font-mono text-[9px] uppercase tracking-wider text-slate-600">
          {formatLabel(item.probable_type)} · {formatLabel(item.verification_state)} · {timeAgo(item.last_seen_at)}
        </span>
        <span className="mt-1 block text-xs leading-5 text-slate-500">
          Observed but not promoted to a canonical asset until owner, account, provider and evidence bindings are resolved.
        </span>
      </span>
      <ArrowUpRight className="h-4 w-4 shrink-0 text-slate-600 transition group-hover:text-amber-200" />
    </Link>
  );
}

function DiscoveryCoverageLens({ coverage }: { coverage: DiscoveryCoverageProjection | null }) {
  if (!coverage) {
    return (
      <section className="mt-5 rounded-[24px] border border-amber-300/12 bg-amber-300/[0.025] p-5">
        <p className="font-mono text-[9px] uppercase tracking-[0.23em] text-amber-200">Discovery Control Coverage unavailable</p>
        <p className="mt-2 text-xs leading-5 text-slate-500">No discovery coverage projection was returned. Scores remain withheld.</p>
      </section>
    );
  }
  const dimensions = ["discovery", "identity", "usage", "reachability"]
    .map((name) => coverage.dimensions[name])
    .filter(Boolean);
  return (
    <section className="mt-5 rounded-[24px] border border-white/[0.07] bg-[#0b1219]/90 p-5">
      <div className="flex flex-col gap-3 border-b border-white/[0.06] pb-4 md:flex-row md:items-start md:justify-between">
        <div>
          <p className="font-mono text-[9px] uppercase tracking-[0.23em] text-cyan-300">Discovery Control Coverage</p>
          <h2 className="mt-1 text-lg font-semibold text-white">Measured inputs, never a marketing score</h2>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-500">{coverage.denominator.explanation}</p>
        </div>
        <span className={`rounded-full border px-3 py-1 font-mono text-[9px] uppercase tracking-[0.16em] ${signalTone(coverage.denominator.status)}`}>Denominator · {formatLabel(coverage.denominator.status)}</span>
      </div>
      <div className="mt-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {dimensions.map((dimension) => {
          const total = dimension.covered_count + dimension.not_covered_count + dimension.unknown_count;
          const coveredRatio = total ? Math.round(100 * dimension.covered_count / total) : 0;
          return (
            <div key={dimension.name} className="rounded-2xl border border-white/[0.06] bg-white/[0.025] p-4" title={dimension.methodology}>
              <div className="flex items-start justify-between gap-2"><div><p className="font-mono text-[9px] uppercase tracking-[0.16em] text-slate-500">{formatLabel(dimension.name)}</p><p className="mt-2 font-mono text-2xl text-white">{dimension.score === null ? "—" : `${dimension.score}%`}</p></div><span className={`rounded-full border px-2 py-1 font-mono text-[8px] uppercase ${dimension.score === null ? "border-amber-300/20 bg-amber-300/[0.05] text-amber-200" : "border-emerald-300/20 bg-emerald-300/[0.05] text-emerald-200"}`}>{dimension.score === null ? "withheld" : "measured"}</span></div>
              <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full rounded-full bg-emerald-400" style={{ width: `${coveredRatio}%` }} /></div>
              <div className="mt-3 grid grid-cols-3 gap-1 text-center"><div><p className="font-mono text-sm text-emerald-200">{dimension.covered_count}</p><p className="font-mono text-[7px] uppercase text-slate-600">Covered</p></div><div><p className="font-mono text-sm text-rose-200">{dimension.not_covered_count}</p><p className="font-mono text-[7px] uppercase text-slate-600">Uncovered</p></div><div><p className="font-mono text-sm text-amber-200">{dimension.unknown_count}</p><p className="font-mono text-[7px] uppercase text-slate-600">Unknown</p></div></div>
              <p className="mt-3 line-clamp-2 text-[9px] leading-4 text-slate-600">{dimension.score_withheld_reason ? formatLabel(dimension.score_withheld_reason) : dimension.methodology}</p>
            </div>
          );
        })}
      </div>
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-300/10 bg-amber-300/[0.025] px-3 py-2 text-[10px] text-amber-100/70"><span>Known assets {coverage.denominator.known_assets} · unresolved hypotheses {coverage.denominator.unresolved_hypotheses} · inaccessible sources {coverage.denominator.inaccessible_sources}</span><span className="font-mono uppercase">{coverage.methodology_version}</span></div>
    </section>
  );
}

export function AIEstateIntelligence() {
  const [summary, setSummary] = useState<DiscoveryEstateSummary | null>(null);
  const [assets, setAssets] = useState<DiscoveryAssetSummary[]>([]);
  const [ecosystems, setEcosystems] = useState<DiscoveryEcosystem[]>([]);
  const [unknowns, setUnknowns] = useState<UnknownAIItem[]>([]);
  const [findings, setFindings] = useState<DiscoveryIntelligenceFinding[]>([]);
  const [collectors, setCollectors] = useState<DiscoveryCollectorHealth[]>([]);
  const [coverage, setCoverage] = useState<DiscoveryCoverageProjection | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "stale" | "unavailable">("loading");
  const [failedSources, setFailedSources] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [truthFilter, setTruthFilter] = useState("all");

  async function load() {
    setLoading(true);
    setLoadState((current) => current === "ready" || current === "stale" ? "stale" : "loading");
    const results = await Promise.allSettled([
      api.getDiscoveryEstate(),
      api.listDiscoveryAssets({ page_size: 200 }),
      api.listDiscoveryEcosystems({ page_size: 100 }),
      api.listUnknownAI({ page_size: 100 }),
      api.listDiscoveryIntelligenceFindings({ page_size: 100 }),
      api.listDiscoveryCollectorHealth(),
      api.getDiscoveryCoverage(),
    ]);
    const [estateResult, assetsResult, ecosystemResult, unknownResult, findingsResult, collectorResult, coverageResult] = results;
    if (estateResult.status === "fulfilled") setSummary(estateResult.value);
    if (assetsResult.status === "fulfilled") setAssets(assetsResult.value.items || []);
    if (ecosystemResult.status === "fulfilled") setEcosystems(ecosystemResult.value.items || []);
    if (unknownResult.status === "fulfilled") setUnknowns(unknownResult.value.items || []);
    if (findingsResult.status === "fulfilled") setFindings(findingsResult.value.items || []);
    if (collectorResult.status === "fulfilled") setCollectors(collectorResult.value || []);
    if (coverageResult.status === "fulfilled") setCoverage(coverageResult.value);
    const sourceNames = ["estate inventory", "asset inventory", "ecosystem relationships", "unknown AI queue", "intelligence findings", "collector health", "coverage methodology"];
    const failures = results.flatMap((item, index) => item.status === "rejected" ? [sourceNames[index]] : []);
    setFailedSources(failures);
    if (failures.length) {
      setLoadState(summary || assets.length || unknowns.length ? "stale" : "unavailable");
      toast.error(`Unavailable discovery sources: ${failures.join(", ")}. Existing evidence remains visible.`);
    } else {
      setLoadState("ready");
    }
    setLoading(false);
  }

  useEffect(() => {
    load().catch((error) => {
      toast.error(error instanceof Error ? error.message : "Discovery intelligence failed to load");
      setLoadState("unavailable");
      setLoading(false);
    });
  // The loader intentionally runs once for this client workspace; refresh uses the same function.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const visibleAssets = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    return assets.filter((asset) => {
      if (truthFilter !== "all" && asset.resolution_state !== truthFilter) return false;
      if (!normalized) return true;
      return [asset.canonical_name, asset.provider, asset.product, asset.asset_type, asset.environment]
        .some((value) => String(value || "").toLowerCase().includes(normalized));
    });
  }, [assets, query, truthFilter]);

  const fallbackSummary: DiscoveryEstateSummary = summary || {
    assets_total: 0,
    confirmed_assets: 0,
    probable_assets: 0,
    ambiguous_assets: 0,
    active_assets: 0,
    shadow_assets: 0,
    personal_assets: 0,
    unowned_assets: 0,
    open_findings: 0,
    providers: 0,
    environments: 0,
    unknown_denominator: true,
    denominator_explanation: "No authoritative estate denominator has been loaded.",
    generated_at: new Date().toISOString(),
  };
  const observedEvidenceTotal = fallbackSummary.assets_total + unknowns.length;

  return (
    <div className="relative overflow-hidden rounded-[30px] border border-white/[0.07] bg-[#080e14] text-slate-100 shadow-[0_28px_90px_rgba(2,8,16,0.38)]">
      <div className="pointer-events-none absolute inset-0 opacity-[0.28] [background-image:linear-gradient(rgba(125,211,252,0.035)_1px,transparent_1px),linear-gradient(90deg,rgba(125,211,252,0.035)_1px,transparent_1px)] [background-size:28px_28px]" />
      <div className="pointer-events-none absolute -left-20 -top-32 h-96 w-96 rounded-full bg-cyan-400/[0.07] blur-[110px]" />
      <div className="pointer-events-none absolute -right-24 top-32 h-80 w-80 rounded-full bg-orange-400/[0.08] blur-[110px]" />

      <div className="relative p-5 md:p-7 xl:p-9">
        <header className="flex flex-col gap-6 border-b border-white/[0.07] pb-7 xl:flex-row xl:items-end xl:justify-between">
          <div className="max-w-3xl">
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <span className="rounded-full border border-cyan-300/20 bg-cyan-300/[0.08] px-3 py-1 font-mono text-[9px] uppercase tracking-[0.25em] text-cyan-200">AI Estate Intelligence</span>
              <span className="flex items-center gap-1.5 rounded-full border border-slate-300/20 bg-slate-300/[0.07] px-3 py-1 font-mono text-[9px] uppercase tracking-[0.2em] text-slate-300">
                {loadState === "loading" ? "Loading" : loadState === "ready" ? "Current snapshot" : loadState === "stale" ? "Stale snapshot" : "Unavailable"}
              </span>
            </div>
            <h1 className="max-w-2xl font-serif text-4xl leading-[0.98] tracking-[-0.035em] text-white md:text-5xl">
              AI estate inventory
            </h1>
            <p className="mt-4 max-w-2xl text-sm leading-6 text-slate-400">
              Review observed assets and unresolved AI evidence. Source coverage and resolution details are available below.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" className="border-white/10 bg-white/[0.035] text-slate-200 hover:bg-white/[0.08]" onClick={() => load()} disabled={loading}>
              <RefreshCw className={`mr-2 h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh evidence
            </Button>
            <Button asChild className="bg-orange-400 text-slate-950 hover:bg-orange-300">
              <Link href="/discovery/scans"><ScanSearch className="mr-2 h-4 w-4" /> Run AI estate scan</Link>
            </Button>
          </div>
        </header>

        {failedSources.length ? <div role="status" className="mt-5 rounded-xl border border-amber-300/15 bg-amber-300/[0.04] px-4 py-3 text-xs leading-5 text-amber-100/80">Unavailable sources: {failedSources.join(", ")}. Existing inventory remains visible; missing sources are not treated as zero.</div> : null}
        <div className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
          <MetricTile label="AI inventory" value={loadState === "loading" ? "Loading" : loadState === "unavailable" ? "Unknown" : observedEvidenceTotal} note="Canonical assets plus unresolved observed signals" icon={Boxes} tone="bg-cyan-400/20" />
          <MetricTile label="Investigation queue" value={loadState === "loading" ? "Loading" : loadState === "unavailable" ? "Unknown" : unknowns.length} note="Unresolved AI evidence requiring review" icon={CircleAlert} tone="bg-amber-400/20" />
          <MetricTile label="Open findings" value={loadState === "loading" ? "Loading" : loadState === "unavailable" ? "Unknown" : fallbackSummary.open_findings} note="Findings tied to the available inventory" icon={Activity} tone="bg-rose-400/20" />
        </div>

        <div className="mt-5 grid gap-5 xl:grid-cols-[1.15fr_1.85fr]">
          <div className="space-y-5">
            <section className="rounded-[24px] border border-white/[0.07] bg-[#0d151e]/92">
              <div className="flex flex-col gap-3 border-b border-white/[0.06] p-5 md:flex-row md:items-end md:justify-between">
                <div>
                  <p className="font-mono text-[9px] uppercase tracking-[0.23em] text-cyan-300">Canonical estate</p>
                  <h2 className="mt-1 text-xl font-semibold text-white">Assets and unresolved evidence</h2>
                  <p className="mt-1 text-xs text-slate-500">{visibleAssets.length} canonical · {unknowns.length} unresolved · installation and usage remain separate.</p>
                </div>
                <label className="flex min-w-[230px] items-center gap-2 rounded-xl border border-white/[0.08] bg-black/20 px-3 py-2">
                  <Search className="h-4 w-4 text-slate-500" />
                  <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search estate" className="w-full bg-transparent text-xs text-slate-200 outline-none placeholder:text-slate-600" />
                </label>
              </div>
              <div className="divide-y divide-white/[0.055]">
                {visibleAssets.slice(0, 12).map((asset) => {
                  const Icon = SURFACE_ICONS[asset.asset_type] || Boxes;
                  return (
                    <Link key={asset.asset_id} href={`/discovery/assets/${encodeURIComponent(asset.asset_id)}`} className="group grid gap-3 px-5 py-4 transition hover:bg-cyan-300/[0.035] md:grid-cols-[minmax(0,1.4fr)_0.8fr_0.8fr_0.55fr_auto] md:items-center">
                      <div className="flex min-w-0 items-center gap-3">
                        <div className="rounded-2xl border border-white/[0.07] bg-white/[0.035] p-2.5 text-slate-400 transition group-hover:border-cyan-300/20 group-hover:text-cyan-200"><Icon className="h-4 w-4" /></div>
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-slate-100">{asset.canonical_name}</p>
                          <p className="truncate font-mono text-[9px] uppercase tracking-wider text-slate-600">{formatLabel(asset.asset_type)} · {asset.provider || "provider unknown"}</p>
                        </div>
                      </div>
                      <div>
                        <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Truth</p>
                        <span className={`mt-1 inline-flex rounded-full border px-2 py-0.5 font-mono text-[8px] uppercase ${signalTone(asset.resolution_state)}`}>{asset.resolution_state} · {Math.round(asset.resolution_confidence * 100)}%</span>
                      </div>
                      <div>
                        <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Usage</p>
                        <span className={`mt-1 inline-flex rounded-full border px-2 py-0.5 font-mono text-[8px] uppercase ${signalTone(asset.usage_state)}`}>{formatLabel(asset.usage_state)}</span>
                      </div>
                      <div>
                        <p className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Reach</p>
                        <p className="mt-1 font-mono text-sm text-slate-300">{asset.reachability_count}</p>
                      </div>
                      <div className="flex items-center justify-between gap-3 md:justify-end">
                        {asset.findings_open > 0 && <span className="rounded-full bg-rose-400/10 px-2 py-1 font-mono text-[9px] text-rose-200">{asset.findings_open} finding{asset.findings_open === 1 ? "" : "s"}</span>}
                        <ArrowUpRight className="h-4 w-4 text-slate-600 transition group-hover:text-cyan-300" />
                      </div>
                    </Link>
                  );
                })}
                {!visibleAssets.length && unknowns.length > 0 && (
                  <div>
                    <div className="border-b border-amber-300/10 bg-amber-300/[0.025] px-5 py-3">
                      <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-amber-200">Observed unresolved AI</p>
                      <p className="mt-1 text-xs leading-5 text-slate-500">These signals are real evidence in the tenant, but not yet verified enough to become canonical assets.</p>
                    </div>
                    {unknowns.slice(0, 8).map((item) => <UnknownEvidenceCard key={`${item.subject_kind}-${item.subject_id}`} item={item} />)}
                    {unknowns.length > 8 && <div className="px-5 py-4 text-center"><Link href="/discovery/unknown" className="text-xs font-medium text-amber-200 hover:text-amber-100">Open all {unknowns.length} unresolved AI signals</Link></div>}
                  </div>
                )}
                {!visibleAssets.length && !unknowns.length && (
                  <div className="grid place-items-center px-5 py-16 text-center">
                    <Radar className="h-8 w-8 text-slate-700" />
                    <p className="mt-3 text-sm text-slate-400">No evidence-backed assets match this view.</p>
                    <p className="mt-1 text-xs text-slate-600">Run a bounded scan or clear the truth filter.</p>
                  </div>
                )}
              </div>
              {visibleAssets.length > 12 && <div className="border-t border-white/[0.06] p-4 text-center"><Link href="/discovery/assets" className="text-xs text-cyan-300">Open all {visibleAssets.length} assets</Link></div>}
            </section>

            <section className="grid gap-5 lg:grid-cols-2">
              <div className="rounded-[24px] border border-white/[0.07] bg-[#0d151e]/92 p-5">
                <div className="flex items-center justify-between">
                  <div><p className="font-mono text-[9px] uppercase tracking-[0.23em] text-slate-500">Ecosystem map</p><h2 className="mt-1 text-lg font-semibold text-white">Evidence-native components</h2></div>
                  <CloudCog className="h-5 w-5 text-violet-300" />
                </div>
                <div className="mt-4 space-y-3">
                  {ecosystems.slice(0, 5).map((ecosystem) => (
                    <Link key={ecosystem.ecosystem_id} href="/discovery/ecosystems" className="block rounded-2xl border border-white/[0.06] bg-white/[0.025] p-3 transition hover:border-violet-300/25 hover:bg-violet-300/[0.04]">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0"><p className="truncate text-xs font-medium text-slate-200">{formatLabel(ecosystem.provider)}</p><p className="mt-1 font-mono text-[8px] uppercase tracking-wider text-slate-600">{formatLabel(ecosystem.environment)} · {ecosystem.asset_count} canonical node{ecosystem.asset_count === 1 ? "" : "s"}</p></div>
                        <span className={`shrink-0 rounded-full border px-2 py-1 font-mono text-[8px] uppercase ${ecosystem.resolution_method === "verified_evidence_graph_component" ? "border-emerald-300/20 bg-emerald-300/[0.06] text-emerald-200" : "border-amber-300/20 bg-amber-300/[0.06] text-amber-200"}`}>{ecosystem.resolution_method === "verified_evidence_graph_component" ? `${Math.round(ecosystem.confidence * 100)}% connected` : "isolated"}</span>
                      </div>
                      <div className="mt-3 grid grid-cols-3 gap-2 rounded-xl border border-white/[0.05] bg-black/10 p-2 text-center">
                        <div><p className="font-mono text-sm text-slate-200">{ecosystem.discovery_sources.length || "?"}</p><p className="font-mono text-[7px] uppercase tracking-wider text-slate-600">sources</p></div>
                        <div><p className="font-mono text-sm text-slate-200">{ecosystem.evidence_refs.length || "?"}</p><p className="font-mono text-[7px] uppercase tracking-wider text-slate-600">evidence</p></div>
                        <div><p className="font-mono text-[9px] text-slate-300">{timeAgo(ecosystem.last_seen_at)}</p><p className="font-mono text-[7px] uppercase tracking-wider text-slate-600">last seen</p></div>
                      </div>
                    </Link>
                  ))}
                  {!ecosystems.length && <p className="py-8 text-center text-xs text-slate-500">No ecosystem can be resolved yet.</p>}
                </div>
              </div>

              <div className="rounded-[24px] border border-white/[0.07] bg-[#0d151e]/92 p-5">
                <div className="flex items-center justify-between">
                  <div><p className="font-mono text-[9px] uppercase tracking-[0.23em] text-slate-500">Investigation queue</p><h2 className="mt-1 text-lg font-semibold text-white">Unknown AI</h2></div>
                  <UserRoundSearch className="h-5 w-5 text-amber-300" />
                </div>
                <div className="mt-4 space-y-2">
                  {unknowns.slice(0, 6).map((item) => (
                    <Link key={`${item.subject_kind}-${item.subject_id}`} href="/discovery/unknown" className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.025] px-3 py-2.5 transition hover:border-amber-300/20">
                      <span className="grid h-8 w-8 place-items-center rounded-xl bg-amber-300/[0.07] font-mono text-[9px] text-amber-200">{Math.round(item.confidence * 100)}</span>
                      <span className="min-w-0 flex-1"><span className="block truncate text-xs text-slate-200">{item.label}</span><span className="block truncate font-mono text-[8px] uppercase text-slate-600">{formatLabel(item.probable_type)} · {timeAgo(item.last_seen_at)}</span></span>
                      <ArrowUpRight className="h-3.5 w-3.5 text-slate-600" />
                    </Link>
                  ))}
                  {!unknowns.length && <div className="grid place-items-center py-8 text-center"><ShieldCheck className="h-7 w-7 text-emerald-400/60" /><p className="mt-2 text-xs text-slate-500">No unresolved hypothesis in the current known scope.</p></div>}
                </div>
              </div>
            </section>
          </div>

          <details className="space-y-5" open={false}>
            <summary className="cursor-pointer list-none rounded-xl border border-white/[0.07] bg-white/[0.025] px-4 py-3 text-xs font-medium uppercase tracking-[0.18em] text-slate-400">Technical details</summary>
            <div className="space-y-5">
            <section className="rounded-[24px] border border-white/[0.07] bg-[#0d151e]/92 p-5">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-mono text-[9px] uppercase tracking-[0.24em] text-slate-500">Resolution truth</p>
                  <h2 className="mt-1 text-lg font-semibold text-white">Known ≠ verified</h2>
                </div>
                <Fingerprint className="h-5 w-5 text-cyan-300" />
              </div>
              <ResolutionDonut summary={fallbackSummary} />
              <div className="grid grid-cols-3 gap-2">
                {(["confirmed", "probable", "ambiguous"] as const).map((state) => (
                  <button key={state} onClick={() => setTruthFilter(truthFilter === state ? "all" : state)} className={`rounded-xl border px-2 py-2 text-left transition ${truthFilter === state ? "border-white/25 bg-white/[0.08]" : "border-white/[0.06] bg-white/[0.025] hover:bg-white/[0.05]"}`}>
                    <span className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider text-slate-400">
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: RESOLUTION_COLORS[state] }} /> {state}
                    </span>
                    <span className="mt-1 block font-mono text-lg text-white">{state === "confirmed" ? fallbackSummary.confirmed_assets : state === "probable" ? fallbackSummary.probable_assets : fallbackSummary.ambiguous_assets}</span>
                  </button>
                ))}
              </div>
            </section>

            <section className="rounded-[24px] border border-amber-300/15 bg-amber-300/[0.045] p-5">
              <div className="flex items-start gap-3">
                <div className="rounded-2xl bg-amber-300/10 p-2.5 text-amber-200"><CircleAlert className="h-5 w-5" /></div>
                <div>
                  <p className="font-mono text-[9px] uppercase tracking-[0.23em] text-amber-200">Unknown denominator</p>
                  <p className="mt-2 text-sm leading-6 text-slate-300">{fallbackSummary.denominator_explanation}</p>
                  <Link href="/discovery/unknown" className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-amber-200 hover:text-amber-100">Investigate blind spots <ArrowUpRight className="h-3.5 w-3.5" /></Link>
                </div>
              </div>
            </section>

            <section className="rounded-[24px] border border-white/[0.07] bg-[#0d151e]/92 p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="font-mono text-[9px] uppercase tracking-[0.23em] text-slate-500">Collector pulse</p>
                  <h2 className="mt-1 text-lg font-semibold text-white">Evidence source health</h2>
                </div>
                <Link href="/discovery/scans" className="text-xs text-cyan-300 hover:text-cyan-200">View operations</Link>
              </div>
              <div className="mt-4 space-y-2">
                {collectors.slice(0, 6).map((collector) => (
                  <div key={collector.collector_id} className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.025] px-3 py-2">
                    <span className={`h-2 w-2 rounded-full ${collector.status === "healthy" ? "bg-emerald-400" : collector.status === "warning" ? "bg-amber-400" : "bg-rose-400"}`} />
                    <span className="min-w-0 flex-1 truncate text-xs text-slate-300">{formatLabel(collector.collector_type)}</span>
                    <span className={`rounded-full border px-2 py-0.5 font-mono text-[8px] uppercase ${signalTone(collector.status)}`}>{collector.status}</span>
                  </div>
                ))}
                {!collectors.length && <p className="py-4 text-center text-xs text-slate-500">No registered collector health evidence.</p>}
              </div>
            </section>
          </div>


          </details>
        </div>

        <details className="mt-5 overflow-hidden rounded-[24px] border border-white/[0.07] bg-[#0b1219]/90">
          <summary className="cursor-pointer list-none border-b border-white/[0.06] px-5 py-3 text-xs font-medium uppercase tracking-[0.18em] text-slate-400">Technical evidence summaries</summary>
          <div className="px-5 pb-2">
            <p className="mt-3 text-xs text-slate-500">Recent observations and findings remain linked to their source records.</p>
          </div>
          <EvidenceRiver assets={assets} findings={findings} />
        </details>

        <details className="mt-5" open={false}>
          <summary className="cursor-pointer list-none rounded-xl border border-white/[0.07] bg-white/[0.025] px-4 py-3 text-xs font-medium uppercase tracking-[0.18em] text-slate-400">Coverage and resolution methodology</summary>
          <div className="mt-4">
            <DiscoveryCoverageLens coverage={coverage} />
          </div>
        </details>
      </div>

      <style jsx>{`
        .estate-river-track { animation: estate-river 36s linear infinite; }
        .estate-river:hover .estate-river-track { animation-play-state: paused; }
        @keyframes estate-river { from { transform: translateX(0); } to { transform: translateX(-50%); } }
        @media (prefers-reduced-motion: reduce) { .estate-river-track { animation: none; } }
      `}</style>
    </div>
  );
}
