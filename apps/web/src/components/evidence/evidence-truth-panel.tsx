import Link from "next/link";
import { Activity, HelpCircle, PlugZap, TestTube2 } from "lucide-react";

type EvidenceFact = {
  label: string;
  value: string | number;
  detail: string;
  tone?: "verified" | "observed" | "estimated" | "unknown" | "blocked" | "demo";
};

type EvidenceTruthPanelProps = {
  title: string;
  description: string;
  whyUnknown: string;
  lastEvidence?: string | null;
  connectHref?: string;
  testHref?: string;
  sourceMode?: "authoritative" | "demo" | "observed" | "estimated" | "unknown";
  facts?: EvidenceFact[];
};

const toneClasses: Record<NonNullable<EvidenceFact["tone"]>, string> = {
  verified: "border-emerald-300/25 bg-emerald-300/[0.08] text-emerald-100",
  observed: "border-cyan-300/25 bg-cyan-300/[0.08] text-cyan-100",
  estimated: "border-amber-300/25 bg-amber-300/[0.08] text-amber-100",
  unknown: "border-slate-400/25 bg-slate-400/[0.08] text-slate-200",
  blocked: "border-rose-300/25 bg-rose-300/[0.08] text-rose-100",
  demo: "border-violet-300/25 bg-violet-300/[0.08] text-violet-100",
};

const sourceModeCopy: Record<NonNullable<EvidenceTruthPanelProps["sourceMode"]>, string> = {
  authoritative: "Authoritative production source",
  demo: "Demo / proof data",
  observed: "Observed evidence",
  estimated: "Estimated from client evidence",
  unknown: "Unknown until a source connects",
};

function readableTime(value?: string | null): string {
  if (!value) return "No evidence received yet";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

export function EvidenceTruthPanel({
  title,
  description,
  whyUnknown,
  lastEvidence,
  connectHref = "/integrations",
  testHref = "/validate",
  sourceMode = "unknown",
  facts = [],
}: EvidenceTruthPanelProps) {
  return (
    <section className="rounded-3xl border border-cyan-300/15 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.12),transparent_38%),linear-gradient(135deg,rgba(15,23,42,0.96),rgba(2,6,23,0.92))] p-5 shadow-[0_22px_70px_rgba(0,0,0,.28)]">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="max-w-4xl">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded-full border border-cyan-300/20 bg-cyan-300/[0.08] px-3 py-1 font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-100">
              Evidence truth
            </span>
            <span className={`rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.16em] ${toneClasses[sourceMode === "authoritative" ? "verified" : sourceMode === "demo" ? "demo" : sourceMode === "estimated" ? "estimated" : sourceMode === "observed" ? "observed" : "unknown"]}`}>
              {sourceModeCopy[sourceMode]}
            </span>
          </div>
          <h2 className="mt-3 text-xl font-semibold tracking-[-0.03em] text-white">{title}</h2>
          <p className="mt-2 text-sm leading-6 text-slate-300">{description}</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link href={connectHref} className="inline-flex items-center rounded-xl border border-cyan-300/20 bg-cyan-300/[0.08] px-3 py-2 text-xs font-medium text-cyan-100 hover:bg-cyan-300/[0.14]">
            <PlugZap className="mr-2 h-4 w-4" />
            Connect source
          </Link>
          <Link href={testHref} className="inline-flex items-center rounded-xl border border-white/10 bg-white/[0.05] px-3 py-2 text-xs font-medium text-white hover:bg-white/[0.09]">
            <TestTube2 className="mr-2 h-4 w-4" />
            Test this control now
          </Link>
        </div>
      </div>

      <div className="mt-5 grid gap-3 lg:grid-cols-3">
        <div className="rounded-2xl border border-white/10 bg-black/15 p-4">
          <p className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">
            <HelpCircle className="h-4 w-4 text-amber-200" />
            Why unknown?
          </p>
          <p className="mt-2 text-sm leading-6 text-slate-300">{whyUnknown}</p>
        </div>
        <div className="rounded-2xl border border-white/10 bg-black/15 p-4">
          <p className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">
            <Activity className="h-4 w-4 text-cyan-200" />
            Last evidence received
          </p>
          <p className="mt-2 text-sm leading-6 text-slate-300">{readableTime(lastEvidence)}</p>
        </div>
        <div className="rounded-2xl border border-white/10 bg-black/15 p-4">
          <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-slate-500">Truth boundary</p>
          <p className="mt-2 text-sm leading-6 text-slate-300">
            Browser-observed, provider-native verified, endpoint-enforced, MCP-routed, and estimated usage are kept separate. Missing evidence never becomes a green control.
          </p>
        </div>
      </div>

      {facts.length ? (
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {facts.map((fact) => (
            <article key={fact.label} className="rounded-2xl border border-white/10 bg-white/[0.025] p-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{fact.label}</p>
                <span className={`rounded-full border px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] ${toneClasses[fact.tone || "unknown"]}`}>
                  {(fact.tone || "unknown").replaceAll("_", " ")}
                </span>
              </div>
              <p className="mt-2 break-words text-lg font-semibold tracking-[-0.03em] text-white">{fact.value}</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">{fact.detail}</p>
            </article>
          ))}
        </div>
      ) : null}
    </section>
  );
}
