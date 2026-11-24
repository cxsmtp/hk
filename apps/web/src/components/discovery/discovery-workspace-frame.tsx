"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowLeft, Radar } from "lucide-react";

export function formatDiscoveryLabel(value: string | null | undefined): string {
  return String(value || "unknown")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function formatDiscoveryTime(value: string | null | undefined): string {
  if (!value) return "Unknown";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown" : date.toLocaleString();
}

export function confidenceLabel(value: number): string {
  return `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

export function discoveryTone(value: string | null | undefined): string {
  const normalized = String(value || "unknown").toLowerCase();
  if (["confirmed", "verified", "active", "healthy", "complete", "managed", "approved"].includes(normalized)) {
    return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
  }
  if (["probable", "occasional", "warning", "stale", "partially_complete", "inferred"].includes(normalized)) {
    return "border-amber-400/30 bg-amber-400/10 text-amber-200";
  }
  if (["ambiguous", "unknown", "degraded", "offline", "failed", "unmanaged", "personal"].includes(normalized)) {
    return "border-rose-400/30 bg-rose-400/10 text-rose-200";
  }
  return "border-slate-400/20 bg-slate-400/10 text-slate-200";
}

export function TruthBadge({ value }: { value: string }) {
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.14em] ${discoveryTone(value)}`}>
      {formatDiscoveryLabel(value)}
    </span>
  );
}

export function DiscoveryWorkspaceFrame({
  eyebrow,
  title,
  description,
  backHref,
  backLabel,
  actions,
  children,
}: {
  eyebrow: string;
  title: string;
  description: string;
  backHref?: string;
  backLabel?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="min-h-full overflow-hidden rounded-[28px] border border-white/[0.06] bg-[#080d13] text-slate-100 shadow-[0_28px_90px_rgba(0,0,0,0.35)]">
      <div className="relative overflow-hidden border-b border-white/[0.06] px-5 py-6 sm:px-7">
        <div className="absolute -right-24 -top-44 h-80 w-80 rounded-full bg-cyan-400/[0.08] blur-[90px]" />
        <div className="absolute -left-24 top-0 h-72 w-72 rounded-full bg-violet-500/[0.06] blur-[95px]" />
        <div className="relative flex flex-col gap-5 lg:flex-row lg:items-end lg:justify-between">
          <div>
            {backHref ? (
              <Link href={backHref} className="mb-4 inline-flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-[0.18em] text-slate-500 transition hover:text-cyan-200">
                <ArrowLeft className="h-3 w-3" /> {backLabel || "Back"}
              </Link>
            ) : null}
            <div className="flex items-center gap-2 font-mono text-[9px] uppercase tracking-[0.24em] text-cyan-300/80">
              <Radar className="h-3.5 w-3.5" /> {eyebrow}
            </div>
            <h1 className="mt-2 max-w-4xl text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">{title}</h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">{description}</p>
          </div>
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      </div>
      <div className="p-4 sm:p-6">{children}</div>
    </div>
  );
}

export function DiscoveryEmpty({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="grid min-h-48 place-items-center rounded-2xl border border-dashed border-white/10 bg-white/[0.015] p-8 text-center">
      <div>
        <Radar className="mx-auto h-7 w-7 text-slate-600" />
        <p className="mt-3 text-sm font-medium text-slate-300">{title}</p>
        <p className="mt-1 max-w-md text-xs leading-5 text-slate-500">{detail}</p>
      </div>
    </div>
  );
}
