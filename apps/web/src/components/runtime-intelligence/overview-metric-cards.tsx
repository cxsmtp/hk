import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

type MetricTone = "default" | "critical" | "warning" | "success" | "info";

export type RuntimeOverviewMetric = {
  label: string;
  value: string | number;
  hint?: string;
  tone?: MetricTone;
};

const toneClasses: Record<MetricTone, string> = {
  default: "text-slate-100",
  critical: "text-rose-300",
  warning: "text-amber-300",
  success: "text-emerald-300",
  info: "text-blue-300",
};

export function RuntimeOverviewMetricCards({ items }: { items: RuntimeOverviewMetric[] }) {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {items.map((item) => (
        <Card key={item.label}>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs uppercase tracking-[0.1em] text-slate-500">{item.label}</CardTitle>
          </CardHeader>
          <CardContent>
            <p className={cn("text-3xl font-semibold", toneClasses[item.tone || "default"])}>{item.value}</p>
            {item.hint ? <p className="mt-1 text-xs text-slate-500">{item.hint}</p> : null}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
