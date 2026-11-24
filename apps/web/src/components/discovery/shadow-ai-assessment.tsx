"use client";

import { useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { TelemetryImportResult } from "@/lib/types";
import { Button } from "@/components/ui/button";

const SOURCES = [
  ["Endpoint / EDR", "Installed apps and process-associated connections. Export import is available below; Hawk collectors require an enrolled endpoint."],
  ["Browser / network", "Web destinations and supported browser actions. DNS alone establishes a lookup; gateway visibility requires routed traffic."],
  ["SaaS / identity", "AI features, usage and application grants where the connected provider exposes them. A SaaS visit does not establish AI feature use."],
  ["Developer / cloud", "Configured clients, MCP servers and cloud inventory. Configuration is separate from observed execution."],
];
const inputStyle = "mt-1 w-full rounded-lg border border-white/15 bg-slate-950 p-2.5 text-sm text-slate-100 disabled:opacity-50";

export function ShadowAIAssessment() {
  const [format, setFormat] = useState<"defender_csv" | "swg_csv">("defender_csv");
  const [source, setSource] = useState("customer-defender");
  const [start, setStart] = useState("");
  const [end, setEnd] = useState("");
  const [content, setContent] = useState("");
  const [result, setResult] = useState<TelemetryImportResult | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  function clear() { setResult(null); setError(""); }
  async function submit(preview: boolean) {
    setBusy(true); setError("");
    try {
      if (!start || !end || new Date(start) >= new Date(end)) throw new Error("Choose an ordered collection window.");
      const response = await api.importShadowAITelemetry({ format, source_instance: source, content,
        window_start: new Date(start).toISOString(), window_end: new Date(end).toISOString(), preview });
      setResult(response);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Import could not be completed."); setResult(null); }
    finally { setBusy(false); }
  }
  return <section aria-labelledby="shadow-assessment-title" className="mt-5 rounded-2xl border border-cyan-300/20 bg-[#0d151e] p-5">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="text-xs font-medium uppercase tracking-wider text-cyan-200">Shadow AI assessment</p><h2 id="shadow-assessment-title" className="mt-1 text-xl font-semibold text-white">Discover activity beyond the gateway</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">Start with a customer-owned telemetry export. Preview the evidence, then add matching AI destinations to your discovery inventory.</p></div><Link href="/integrations" className="text-sm text-cyan-200 underline underline-offset-4">Connect a live source</Link></div>
    <div className="mt-5 grid gap-3 md:grid-cols-2 xl:grid-cols-4">{SOURCES.map(([title, description]) => <div key={title} className="rounded-xl border border-white/10 p-3"><h3 className="text-sm font-medium text-slate-100">{title}</h3><p className="mt-2 text-xs leading-5 text-slate-400">{description}</p></div>)}</div>
    <div className="mt-6 grid gap-6 lg:grid-cols-2">
      <fieldset disabled={busy} className="min-w-0"><legend className="text-sm font-semibold text-white">1. Choose source and scope</legend>
        <label className="mt-3 block text-xs text-slate-300">Export format<select className={inputStyle} value={format} onChange={(e) => { setFormat(e.target.value as typeof format); clear(); }}><option value="defender_csv">Microsoft Defender — DeviceNetworkEvents CSV</option><option value="swg_csv">Web gateway — normalized CSV</option></select></label>
        <label className="mt-3 block text-xs text-slate-300">Stable source name<input className={inputStyle} maxLength={64} value={source} onChange={(e) => { setSource(e.target.value); clear(); }} /></label>
        <p className="mt-1 text-xs text-slate-500">Reuse this name for repeat exports from the same source. Letters, numbers, dots, underscores and hyphens.</p>
        <div className="mt-3 grid gap-3 sm:grid-cols-2"><label className="text-xs text-slate-300">From (local time)<input type="datetime-local" className={inputStyle} value={start} onChange={(e) => { setStart(e.target.value); clear(); }}/></label><label className="text-xs text-slate-300">Until (exclusive, local time)<input type="datetime-local" className={inputStyle} value={end} onChange={(e) => { setEnd(e.target.value); clear(); }}/></label></div>
      </fieldset>
      <fieldset disabled={busy} className="min-w-0"><legend className="text-sm font-semibold text-white">2. Preview telemetry</legend>
        <label className="mt-3 block text-xs text-slate-300">CSV export · up to 500 rows / 1 MiB<input type="file" accept=".csv,text/csv" className={inputStyle} onChange={async (event) => {
          clear(); setContent(""); const file = event.target.files?.[0]; if (!file) return;
          if (file.size > 1048576) { setError("Export exceeds 1 MiB. Narrow the export window."); return; }
          setBusy(true);
          try { setContent(await file.text()); } catch { setError("The selected file could not be read."); } finally { setBusy(false); }
        }}/></label>
        <p className="mt-3 text-xs leading-5 text-slate-400">Preview sends the file to Hawk for validation but creates no discovery records. Only supported metadata is retained on import; raw CSV, command lines and URL paths or queries are not stored.</p>
        <details className="mt-3 text-xs text-slate-400"><summary className="cursor-pointer text-cyan-200">Required export columns</summary><code className="mt-2 block break-words leading-5">{format === "defender_csv" ? "Timestamp, ReportId, DeviceId, RemoteUrl" : "timestamp, event_id, device_id, destination"}</code><p className="mt-2">Optional: {format === "defender_csv" ? "InitiatingProcessFileName, InitiatingProcessAccountUpn" : "process_name, account_id"}. Use timezone-qualified timestamps. Export only needed columns. Account and device identifiers are stored as tenant-scoped hashes.</p></details>
        <Button className="mt-4" disabled={busy || !content || !start || !end || !source} onClick={() => submit(true)}>{busy ? "Processing…" : "Preview observations"}</Button>
      </fieldset>
    </div>
    {error && <p role="alert" className="mt-4 rounded-lg border border-rose-400/30 bg-rose-400/5 p-3 text-sm text-rose-200">{error}</p>}
    {result && <div className="mt-6 border-t border-white/10 pt-5" aria-live="polite"><h3 className="text-sm font-semibold text-white">3. {result.preview ? "Review and import" : "Review discoveries"}</h3>
      <div className="mt-3 flex flex-wrap gap-4 text-sm text-slate-300"><span>{result.matched} matching rows</span><span>{result.duplicates} duplicates skipped</span><span>{result.unmatched} unclassified destinations</span><span>{result.outside_window} outside window</span>{!result.preview && <span className="text-cyan-200">{result.imported} observations imported</span>}</div>
      <p className="mt-3 text-xs text-amber-200">Fleet coverage: unknown. A connection is not proof of an AI interaction, approval or protection.</p>
      {result.observations.length > 0 && <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[600px] text-left text-xs"><thead className="text-slate-400"><tr>{["AI destination", "Process", "Observed", "Evidence"].map((label) => <th key={label} className="border-b border-white/10 p-2 font-medium">{label}</th>)}</tr></thead><tbody>{result.observations.slice(0, 50).map((row, index) => <tr key={row.signal_id || index} className="border-b border-white/5 text-slate-300"><td className="p-2"><span className="block text-slate-100">{row.tool_name}</span>{row.domain}</td><td className="p-2">{row.process_name}</td><td className="p-2">{new Date(row.observed_at).toLocaleString()}</td><td className="p-2">{row.entity_id ? <Link className="text-cyan-200 underline" href={`/shadow-ai?entity=${encodeURIComponent(row.entity_id)}`}>Inspect contributing evidence</Link> : "Reported network connection"}</td></tr>)}</tbody></table>{result.observations.length > 50 && <p className="mt-2 text-xs text-slate-400">Showing the first 50 of {result.observations.length} observations. All validated observations are included in the import.</p>}</div>}
      <ul className="mt-3 list-disc space-y-1 pl-4 text-xs leading-5 text-slate-400">{result.limitations.map((item) => <li key={item}>{item}</li>)}</ul>
      {result.preview && <Button className="mt-4" disabled={busy || !result.observations.length} onClick={() => submit(false)}>Import {result.observations.length} new observations</Button>}
      {!result.preview && <Link href="/shadow-ai" className="mt-4 inline-block text-sm text-cyan-200 underline">Open discovery inventory</Link>}
    </div>}
  </section>;
}
