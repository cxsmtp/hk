import { Badge } from "@/components/ui/badge";

type TimelineStep = {
  step: number;
  title: string;
  status: "complete" | "partial" | "missing";
  timestamp?: string | null;
  summary: string;
  references: Record<string, unknown>;
};

function statusClass(status: TimelineStep["status"]): string {
  if (status === "complete") return "border-emerald-500/40 bg-emerald-500/15 text-emerald-300";
  if (status === "missing") return "border-red-500/40 bg-red-500/15 text-red-300";
  return "border-amber-500/40 bg-amber-500/15 text-amber-300";
}

function formatReferences(value: Record<string, unknown>): string[] {
  const entries: string[] = [];
  Object.entries(value || {}).forEach(([key, raw]) => {
    if (Array.isArray(raw)) {
      entries.push(`${key}: ${raw.length ? raw.join(", ") : "-"}`);
      return;
    }
    if (raw === null || raw === undefined || raw === "") {
      entries.push(`${key}: -`);
      return;
    }
    entries.push(`${key}: ${String(raw)}`);
  });
  return entries;
}

export function ProofTimeline({
  steps,
  formatDate,
}: {
  steps: TimelineStep[];
  formatDate: (value?: string | null) => string;
}) {
  return (
    <div className="space-y-3">
      {steps.map((step) => (
        <div key={step.step} className="rounded-lg border border-[#1e2433] bg-[#13161f] p-4">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="inline-flex h-6 w-6 items-center justify-center rounded-full bg-brand-500/20 text-xs font-semibold text-brand-300">
                {step.step}
              </span>
              <p className="font-semibold text-slate-100">{step.title}</p>
            </div>
            <Badge className={statusClass(step.status)}>{step.status}</Badge>
          </div>
          <p className="text-sm text-slate-300">{step.summary}</p>
          <p className="mt-1 text-xs text-slate-500">Timestamp: {formatDate(step.timestamp)}</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {formatReferences(step.references).map((line) => (
              <code key={`${step.step}-${line}`} className="rounded bg-[#0e1018] px-2 py-1 text-xs text-slate-400">
                {line}
              </code>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
