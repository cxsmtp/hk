import { CheckCircle2, CircleHelp, Eye, PlugZap, ShieldAlert } from "lucide-react";

import type { CostUsage, GovernancePresentation } from "@/lib/governed-session-state";
import { cn } from "@/lib/utils";

const PRESENTATION = {
  governed: { icon: CheckCircle2, className: "border-emerald-400/25 bg-emerald-400/10 text-emerald-200", dot: "bg-emerald-300" },
  monitor_only: { icon: Eye, className: "border-sky-400/25 bg-sky-400/10 text-sky-200", dot: "bg-sky-300" },
  partially_governed: { icon: ShieldAlert, className: "border-amber-400/25 bg-amber-400/10 text-amber-200", dot: "bg-amber-300" },
  unknown: { icon: CircleHelp, className: "border-slate-500/25 bg-slate-400/[0.08] text-slate-300", dot: "bg-slate-400" },
  disconnected: { icon: PlugZap, className: "border-rose-400/25 bg-rose-400/10 text-rose-200", dot: "bg-rose-300" },
} as const;

export function GovernanceStatus({ status, compact = false }: { status: GovernancePresentation; compact?: boolean }) {
  const presentation = PRESENTATION[status.state];
  const Icon = presentation.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-2 rounded-full border font-semibold",
        compact ? "px-2.5 py-1 text-[10px]" : "px-3 py-1.5 text-xs",
        presentation.className,
      )}
      title={status.explanation}
    >
      {compact ? <span className={cn("h-1.5 w-1.5 rounded-full", presentation.dot)} /> : <Icon className="h-3.5 w-3.5" />}
      {status.label}
    </span>
  );
}

export function TokenProvenanceBadge({ provenance }: { provenance: "exact" | "estimated" | "unknown" }) {
  const label = provenance === "exact" ? "Provider reported" : provenance === "estimated" ? "Client estimate" : "Unavailable";
  return (
    <span className={cn(
      "rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.1em]",
      provenance === "exact" && "border-emerald-400/20 bg-emerald-400/[0.08] text-emerald-300",
      provenance === "estimated" && "border-amber-400/20 bg-amber-400/[0.08] text-amber-300",
      provenance === "unknown" && "border-slate-500/20 bg-slate-500/[0.08] text-slate-400",
    )}>
      {label}
    </span>
  );
}

export function CostProvenanceBadge({ cost }: { cost: CostUsage }) {
  const labels: Record<CostUsage["source"], string> = {
    provider_billed: "Provider billed",
    provider_reported: "Provider reported",
    customer_rate_card: "Rate-card estimate",
    client_estimate: "Client estimate",
    calculated_estimate: "Calculated estimate",
    mixed: "Mixed sources",
    unknown: "Unavailable",
  };
  return (
    <span className={cn(
      "rounded-full border px-2 py-0.5 text-[9px] font-semibold uppercase tracking-[0.1em]",
      cost.provenance === "exact" && "border-emerald-400/20 bg-emerald-400/[0.08] text-emerald-300",
      cost.provenance === "estimated" && "border-amber-400/20 bg-amber-400/[0.08] text-amber-300",
      cost.provenance === "unknown" && "border-slate-500/20 bg-slate-500/[0.08] text-slate-400",
    )} title={cost.provenance === "unknown" ? "No authoritative spend evidence was reported." : `Spend provenance: ${cost.provenance}`}>
      {labels[cost.source]}
    </span>
  );
}
