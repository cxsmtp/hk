import type { ControlCoverageDimension } from "@/lib/types";

const DIMENSIONS = [
  ["discovery", "Discovery", "What Hawk can currently discover"],
  ["identity", "Identity", "Activity attributable to a known identity"],
  ["authorization", "Authorization", "Actions Hawk can authorize before execution"],
  ["evidence", "Evidence", "Actions Hawk can prove after execution"],
  ["deployment", "Deployment", "Observed paths protected by a healthy control surface"],
  ["runtime", "Runtime", "Known runtimes bound to Hawk governance"],
  ["bypass", "Bypass", "Paths with operational bypass detection"],
] as const;

function scoreLabel(value: number | null): string {
  return value === null ? "Unknown" : `${value.toFixed(value % 1 === 0 ? 0 : 1)}%`;
}

function dominantGap(dimension: ControlCoverageDimension | undefined): string {
  const reasons = Object.entries(dimension?.missing_reasons ?? {}).sort(([, left], [, right]) => right - left);
  if (!reasons.length) return "No current missing-reason evidence";
  return reasons[0][0].replaceAll("_", " ");
}

export function DimensionGrid({ dimensions }: { dimensions: Record<string, ControlCoverageDimension> }) {
  return (
    <div className="grid gap-px overflow-hidden rounded-xl border border-[#293247] bg-[#293247] md:grid-cols-2 xl:grid-cols-4">
      {DIMENSIONS.map(([key, label, description], index) => {
        const dimension = dimensions[key];
        const counts = dimension?.counts;
        return (
          <article
            key={key}
            className={`relative bg-[#10141e] p-4 ${index === 0 ? "xl:col-span-2" : ""}`}
          >
            <div className="flex items-start justify-between gap-3">
              <div>
                <div className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">{key}</div>
                <h4 className="mt-1 text-sm font-semibold text-slate-100">{label}</h4>
              </div>
              <div className={dimension?.score === null ? "text-slate-400" : "text-cyan-200"}>
                <span className="font-mono text-lg font-semibold">{scoreLabel(dimension?.score ?? null)}</span>
              </div>
            </div>
            <p className="mt-2 min-h-10 text-xs leading-5 text-slate-400">{description}</p>
            <div className="mt-4 grid grid-cols-3 gap-2 font-mono text-[10px]">
              <span className="text-emerald-300">C {counts?.covered ?? 0}</span>
              <span className="text-rose-300">NC {counts?.not_covered ?? 0}</span>
              <span className="text-amber-200">U {counts?.unknown ?? 0}</span>
            </div>
            <div className="mt-3 truncate border-t border-[#252d40] pt-3 text-[11px] capitalize text-slate-500">
              {dominantGap(dimension)}
            </div>
          </article>
        );
      })}
    </div>
  );
}
