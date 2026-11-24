import type { ShadowAIEntityDetail } from "@/lib/types";
import { summarizeDiscoveryEvidence } from "@/lib/discovery-evidence-summary.mjs";

export function DiscoveryEvidenceSummary({ entity }: { entity: ShadowAIEntityDetail }) {
  const summary = summarizeDiscoveryEvidence(entity.signals);
  return <section aria-label="Discovery evidence interpretation" className="rounded-xl border border-cyan-300/20 bg-cyan-300/[0.04] p-4 text-sm">
    <h3 className="font-semibold text-slate-100">What this evidence establishes</h3>
    <dl className="mt-3 grid gap-4 sm:grid-cols-3">
      <div><dt className="text-xs text-slate-400">Observation</dt><dd className="mt-1 text-slate-100">{summary.states.join(" · ")}</dd></div>
      <div><dt className="text-xs text-slate-400">Approval</dt><dd className="mt-1 text-slate-100">{entity.approved_status || "unknown"}</dd></div>
      <div><dt className="text-xs text-slate-400">Protection</dt><dd className="mt-1 text-slate-100">{summary.protection}</dd></div>
    </dl>
    <p className="mt-3 text-xs leading-5 text-slate-400">{summary.count} evidence records loaded. Latest observation: {summary.latest === null ? "unknown" : new Date(summary.latest).toLocaleString()}.{summary.olderThanDay ? " Latest evidence is older than 24 hours; refresh the source before assessing current activity." : ""}</p>
    {summary.imported && <p className="mt-2 text-xs leading-5 text-amber-200">Includes customer-uploaded telemetry. {summary.devices} distinct device references in loaded evidence. Source authenticity and fleet completeness are not independently verified.</p>}
    <p className="mt-2 text-xs leading-5 text-slate-400">Installed software, configured servers and network connections do not establish that an AI prompt was sent. Review the contributing signals below for source, destination and observation time.</p>
  </section>;
}
