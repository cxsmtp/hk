import type { ControlCoverageImprovement } from "@/lib/types";

function humanize(value: string): string {
  return value.replaceAll("_", " ");
}

export function ImprovementList({ improvements }: { improvements: ControlCoverageImprovement[] }) {
  return (
    <section className="rounded-xl border border-[#293247] bg-[#10141e] p-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <div className="font-mono text-[10px] uppercase tracking-[0.22em] text-amber-300">Deployment leverage</div>
          <h3 className="mt-1 text-lg font-semibold text-slate-100">Where to extend control next</h3>
        </div>
        <span className="text-xs text-slate-500">Ranked by distinct addressable assertions</span>
      </div>

      {improvements.length ? (
        <div className="mt-4 space-y-3">
          {improvements.slice(0, 6).map((item, index) => (
            <article key={`${item.deployment_type}-${index}`} className="border-l-2 border-amber-400/70 bg-[#151a26] p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <h4 className="text-sm font-semibold capitalize text-slate-100">{humanize(item.deployment_type)}</h4>
                    <span className="rounded-sm border border-amber-400/30 bg-amber-400/10 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-amber-200">
                      Conditional
                    </span>
                  </div>
                  <p className="mt-2 text-xs text-slate-400">
                    Could address {item.addressable_assertion_count} assertion{item.addressable_assertion_count === 1 ? "" : "s"} across {item.impacted_path_count} observed path{item.impacted_path_count === 1 ? "" : "s"}.
                  </p>
                </div>
                <div className="font-mono text-2xl text-amber-200">{item.addressable_assertion_count}</div>
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {item.dimensions.map((dimension) => (
                  <span key={dimension} className="rounded-sm bg-[#20283a] px-2 py-1 text-[10px] capitalize text-slate-300">
                    {dimension}
                  </span>
                ))}
              </div>
              {item.prerequisites.length ? (
                <p className="mt-3 border-t border-[#283146] pt-3 text-[11px] leading-5 text-slate-500">
                  Prerequisite: {item.prerequisites[0]}
                </p>
              ) : null}
            </article>
          ))}
        </div>
      ) : (
        <div className="mt-4 border border-dashed border-[#30394d] bg-[#0d1119] p-5 text-sm text-slate-400">
          No evidence-backed deployment improvement can be ranked yet. Hawk will not model uplift without an observed gap and a matching capability profile.
        </div>
      )}
    </section>
  );
}
