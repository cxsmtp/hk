import type { ReactNode } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type Tone = "default" | "critical" | "warning" | "success" | "info";

type ReportItem = {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: Tone;
};

type ModuleReportPanelProps = {
  footprintTitle?: string;
  analyticsTitle?: string;
  footprintItems: ReportItem[];
  analyticsItems: ReportItem[];
};

const toneClasses: Record<Tone, string> = {
  default: "text-slate-100",
  critical: "text-red-400",
  warning: "text-amber-400",
  success: "text-emerald-400",
  info: "text-blue-400",
};

function ReportList({ items }: { items: ReportItem[] }) {
  return (
    <div className="space-y-3">
      {items.map((item) => (
        <div key={item.label} className="rounded-md border border-[#1e2433] bg-[#0f1218] px-3 py-2">
          <div className="flex items-center justify-between gap-3">
            <span className="text-xs uppercase tracking-[0.06em] text-slate-500">{item.label}</span>
            <span className={cn("text-lg font-semibold", toneClasses[item.tone || "default"])}>{item.value}</span>
          </div>
          {item.hint ? <p className="mt-1 text-xs text-slate-500">{item.hint}</p> : null}
        </div>
      ))}
    </div>
  );
}

export function ModuleReportPanel({
  footprintTitle = "AI Footprint",
  analyticsTitle = "Analytics",
  footprintItems,
  analyticsItems,
}: ModuleReportPanelProps) {
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-slate-300">{footprintTitle}</CardTitle>
        </CardHeader>
        <CardContent>
          <ReportList items={footprintItems} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm text-slate-300">{analyticsTitle}</CardTitle>
        </CardHeader>
        <CardContent>
          <ReportList items={analyticsItems} />
        </CardContent>
      </Card>
    </div>
  );
}
