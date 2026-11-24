import type { ReactNode } from "react";
import { CircleHelp } from "lucide-react";

import { cn } from "@/lib/utils";

type KpiTone = "default" | "critical" | "warning" | "success" | "info";

export type KpiItem = {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: KpiTone;
  tooltip?: string;
};

const toneClasses: Record<KpiTone, string> = {
  default: "text-slate-100",
  critical: "text-red-400",
  warning: "text-amber-400",
  success: "text-emerald-400",
  info: "text-blue-400",
};

export function KpiStrip({ items }: { items: KpiItem[] }) {
  return (
    <section data-ui="connected-kpi-strip" className="grid overflow-visible rounded-xl border border-white/[0.08] bg-[#0a0f16] divide-y divide-white/[0.07] sm:grid-cols-2 sm:divide-x sm:divide-y-0 lg:grid-cols-3 2xl:grid-cols-5" aria-label="Evidence-backed summary metrics">
      {items.map((item) => (
        <div key={item.label} className="min-w-0 px-4 py-3.5">
          <div className="min-w-0">
            <div className="flex min-w-0 items-center gap-1">
              <p className="min-w-0 break-words text-[10px] font-semibold uppercase tracking-[0.12em] text-slate-600">{item.label}</p>
              {item.tooltip ? (
                <span className="group/tooltip relative inline-flex shrink-0 items-center">
                  <button
                    type="button"
                    aria-label={`${item.label} formula and source`}
                    className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-[#3a4a65] bg-[#0f1218] text-[11px] font-semibold text-slate-300 transition hover:border-brand-400/60 hover:text-brand-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-400/40"
                  >
                    <CircleHelp className="h-3.5 w-3.5" aria-hidden="true" />
                  </button>
                  <span
                    role="tooltip"
                    className="pointer-events-none invisible absolute left-0 top-full z-50 mt-2 w-72 rounded-md border border-[#3a4a65] bg-[#0f1218] px-3 py-2 text-left text-xs normal-case text-slate-200 opacity-0 shadow-2xl transition group-hover/tooltip:visible group-hover/tooltip:opacity-100 group-focus-within/tooltip:visible group-focus-within/tooltip:opacity-100"
                  >
                    {item.tooltip}
                  </span>
                </span>
              ) : null}
            </div>
          </div>
          <div className="mt-2 min-w-0">
            <p className={cn("break-words text-2xl font-semibold tabular-nums", toneClasses[item.tone || "default"])}>{item.value}</p>
            {item.hint ? <p className="mt-1 break-words text-xs text-slate-500">{item.hint}</p> : null}
          </div>
        </div>
      ))}
    </section>
  );
}
