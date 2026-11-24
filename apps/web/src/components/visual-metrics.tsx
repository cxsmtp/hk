import type { CSSProperties } from "react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type DataPoint = {
  label: string;
  value: number;
};

type Slice = {
  label: string;
  value: number;
  color: string;
};

type RankedItem = {
  label: string;
  value: number;
  hint?: string;
};

function formatCompact(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(1)}K`;
  return `${value}`;
}

function buildSmoothPath(coordinates: Array<{ x: number; y: number }>): string {
  if (!coordinates.length) return "";
  if (coordinates.length === 1) return `M ${coordinates[0].x} ${coordinates[0].y}`;
  let path = `M ${coordinates[0].x} ${coordinates[0].y}`;
  for (let i = 1; i < coordinates.length; i += 1) {
    const prev = coordinates[i - 1];
    const curr = coordinates[i];
    const cx = (prev.x + curr.x) / 2;
    path += ` Q ${cx} ${prev.y}, ${curr.x} ${curr.y}`;
  }
  return path;
}

export function TrendSparkCard({
  title,
  subtitle,
  points,
  tone = "info",
  xAxisLabel = "Time buckets",
  yAxisLabel = "Metric value",
}: {
  title: string;
  subtitle?: string;
  points: DataPoint[];
  tone?: "info" | "success" | "warning" | "critical";
  xAxisLabel?: string;
  yAxisLabel?: string;
}) {
  const values = points.map((item) => item.value);
  const maxValue = Math.max(1, ...values);
  const minValue = Math.min(...values, 0);
  const range = Math.max(1, maxValue - minValue);
  const coordinates = points.map((item, idx) => {
    const x = points.length <= 1 ? 0 : (idx / (points.length - 1)) * 100;
    const y = 100 - ((item.value - minValue) / range) * 100;
    return { x, y };
  });
  const linePath = buildSmoothPath(coordinates);
  const areaPath = coordinates.length
    ? `M ${coordinates[0].x} 100 L ${coordinates[0].x} ${coordinates[0].y} ${coordinates
        .slice(1)
        .map((point) => `L ${point.x} ${point.y}`)
        .join(" ")} L ${coordinates[coordinates.length - 1].x} 100 Z`
    : "";
  const stroke =
    tone === "critical"
      ? "#f87171"
      : tone === "warning"
        ? "#fbbf24"
        : tone === "success"
          ? "#34d399"
          : "#60a5fa";
  const last = points[points.length - 1]?.value ?? 0;
  const sparkId = `spark-fill-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  const firstLabel = points[0]?.label || "start";
  const lastLabel = points[points.length - 1]?.label || "latest";
  const yTicks = [1, 0.75, 0.5, 0.25, 0].map((ratio) => {
    const value = minValue + range * ratio;
    return {
      label: formatCompact(Number(value.toFixed(1))),
      y: 100 - ratio * 100,
    };
  });

  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-slate-300 break-words">{title}</CardTitle>
        {subtitle ? <p className="text-xs text-slate-500 break-words">{subtitle}</p> : null}
      </CardHeader>
      <CardContent className="flex h-full min-h-0 flex-col space-y-3">
        <div className="grid h-36 grid-cols-[3.25rem_minmax(0,1fr)] gap-2 rounded-xl border border-[#2a3348] bg-gradient-to-b from-[#0c1526] via-[#0b111f] to-[#0a0f1b] p-2">
          <div className="flex h-full flex-col justify-between py-1 text-[10px] text-slate-500">
            {yTicks.map((tick, idx) => (
              <span key={`${title}-y-${idx}`} className="leading-none">
                {tick.label}
              </span>
            ))}
          </div>

          {points.length > 1 ? (
            <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="h-full w-full">
              <defs>
                <linearGradient id={sparkId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={stroke} stopOpacity="0.26" />
                  <stop offset="100%" stopColor={stroke} stopOpacity="0.04" />
                </linearGradient>
              </defs>
              {yTicks.map((tick, idx) => (
                <line key={`${title}-grid-${idx}`} x1="0" y1={tick.y} x2="100" y2={tick.y} stroke="#2a3348" strokeWidth="0.5" />
              ))}
              {areaPath ? <path d={areaPath} fill={`url(#${sparkId})`} /> : null}
              {linePath ? (
                <path
                  d={linePath}
                  fill="none"
                  stroke={stroke}
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  vectorEffect="non-scaling-stroke"
                />
              ) : null}
              {coordinates.length ? (
                <circle
                  cx={coordinates[coordinates.length - 1].x}
                  cy={coordinates[coordinates.length - 1].y}
                  r="1.9"
                  fill={stroke}
                  stroke="#0f1218"
                  strokeWidth="1"
                  vectorEffect="non-scaling-stroke"
                />
              ) : null}
            </svg>
          ) : (
            <div className="flex h-full items-center justify-center text-xs text-slate-500">Not enough points</div>
          )}
        </div>

        <div className="grid grid-cols-[3.25rem_minmax(0,1fr)] gap-2 text-[11px] text-slate-400">
          <p className="break-words uppercase tracking-[0.08em]" title={yAxisLabel}>
            Y-axis: {yAxisLabel}
          </p>
          <div className="flex min-w-0 items-center justify-between gap-2">
            <span className="max-w-[34%] truncate" title={firstLabel}>
              {firstLabel}
            </span>
            <span className="text-[10px] uppercase tracking-[0.08em] text-slate-500" title={xAxisLabel}>
              X-axis: {xAxisLabel}
            </span>
            <span className="max-w-[34%] truncate text-right" title={lastLabel}>
              {lastLabel}
            </span>
          </div>
        </div>
        <p className="text-[10px] text-slate-500">
          Scale: {formatCompact(Number(minValue.toFixed(1)))} to {formatCompact(Number(maxValue.toFixed(1)))}
        </p>
        <div className="flex items-end justify-between">
          <p className="text-xs text-slate-500">Latest</p>
          <p className="text-2xl font-semibold text-slate-100">{formatCompact(last)}</p>
        </div>
      </CardContent>
    </Card>
  );
}

export function DistributionDonutCard({
  title,
  subtitle,
  centerLabel,
  centerValue,
  slices,
}: {
  title: string;
  subtitle?: string;
  centerLabel: string;
  centerValue: string;
  slices: Slice[];
}) {
  const total = Math.max(1, slices.reduce((acc, item) => acc + item.value, 0));
  let cursor = 0;
  const gradients = slices.map((slice) => {
    const start = Math.round((cursor / total) * 360);
    cursor += slice.value;
    const end = Math.round((cursor / total) * 360);
    return `${slice.color} ${start}deg ${end}deg`;
  });
  const style = {
    background: `conic-gradient(${gradients.join(", ")})`,
  } satisfies CSSProperties;

  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-slate-300 break-words">{title}</CardTitle>
        {subtitle ? <p className="text-xs text-slate-500 break-words">{subtitle}</p> : null}
      </CardHeader>
      <CardContent className="min-w-0">
        <div className="grid min-w-0 gap-4 xl:grid-cols-[160px_minmax(0,1fr)]">
          <div className="relative mx-auto h-40 w-40">
            <div className="absolute inset-0 rounded-full" style={style} />
            <div className="absolute inset-[18%] flex items-center justify-center rounded-full border border-[#1e2433] bg-[#0f1218] text-center">
              <div>
                <p className="text-[10px] uppercase tracking-[0.08em] text-slate-500">{centerLabel}</p>
                <p className="text-xl font-semibold text-slate-100">{centerValue}</p>
              </div>
            </div>
          </div>
          <div className="min-w-0 space-y-2">
            {slices.map((slice) => {
              const pct = total ? Math.round((slice.value / total) * 100) : 0;
              return (
                <div
                  key={slice.label}
                  className="grid min-w-0 grid-cols-[minmax(0,1fr)_minmax(68px,auto)] items-center gap-3 rounded-md border border-[#1e2433] bg-[#0f1218] px-3 py-2 text-sm"
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span className="inline-flex h-2.5 w-2.5 rounded-full" style={{ backgroundColor: slice.color }} />
                    <span className="text-slate-300 break-words">{slice.label}</span>
                  </div>
                  <span className="text-right text-sm font-semibold text-slate-100 break-words">
                    {slice.value} ({pct}%)
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function RankedBarsCard({
  title,
  subtitle,
  items,
  maxValue,
}: {
  title: string;
  subtitle?: string;
  items: RankedItem[];
  maxValue?: number;
}) {
  const max = Math.max(1, maxValue || Math.max(...items.map((item) => item.value), 1));
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm text-slate-300">{title}</CardTitle>
        {subtitle ? <p className="text-xs text-slate-500">{subtitle}</p> : null}
      </CardHeader>
      <CardContent className="space-y-3">
        {items.length ? (
          items.map((item) => {
            const pct = Math.max(0, Math.min(100, Math.round((item.value / max) * 100)));
            return (
              <div key={item.label} className="space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-slate-300">{item.label}</span>
                  <span className="font-semibold text-slate-100">{item.value}</span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-[#1e2433]">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-blue-500 via-cyan-400 to-emerald-400"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                {item.hint ? <p className="text-xs text-slate-500">{item.hint}</p> : null}
              </div>
            );
          })
        ) : (
          <p className="text-sm text-slate-500">No analytics data available.</p>
        )}
      </CardContent>
    </Card>
  );
}
