import type { RuntimeTimelineEvent } from "@/lib/types";

type Bucket = {
  label: string;
  count: number;
  colorClass: string;
};

function score(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(1, parsed));
}

function bucketsFromEvents(events: RuntimeTimelineEvent[]): Bucket[] {
  const low = events.filter((event) => score(event.risk_score) < 0.34).length;
  const medium = events.filter((event) => score(event.risk_score) >= 0.34 && score(event.risk_score) < 0.67).length;
  const high = events.filter((event) => score(event.risk_score) >= 0.67).length;

  return [
    { label: "Low", count: low, colorClass: "bg-emerald-500" },
    { label: "Medium", count: medium, colorClass: "bg-amber-500" },
    { label: "High", count: high, colorClass: "bg-rose-500" },
  ];
}

export function RiskDistributionChart({ events }: { events: RuntimeTimelineEvent[] }) {
  const buckets = bucketsFromEvents(events);
  const total = buckets.reduce((acc, item) => acc + item.count, 0);

  return (
    <div className="space-y-4">
      <div className="h-4 overflow-hidden rounded-full bg-[#0f1218]">
        <div className="flex h-full w-full">
          {buckets.map((bucket) => {
            const width = total ? Math.max(2, Math.round((bucket.count / total) * 100)) : 0;
            return <div key={bucket.label} className={bucket.colorClass} style={{ width: `${width}%` }} />;
          })}
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        {buckets.map((bucket) => {
          const pct = total ? Math.round((bucket.count / total) * 100) : 0;
          return (
            <div key={bucket.label} className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
              <div className="mb-1 flex items-center gap-2">
                <span className={`inline-block h-2.5 w-2.5 rounded-full ${bucket.colorClass}`} />
                <p className="text-xs uppercase tracking-[0.08em] text-slate-500">{bucket.label}</p>
              </div>
              <p className="text-xl font-semibold text-slate-100">{bucket.count}</p>
              <p className="text-xs text-slate-500">{pct}% of actions</p>
            </div>
          );
        })}
      </div>
    </div>
  );
}
