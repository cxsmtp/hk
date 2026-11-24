"use client";

import { useState } from "react";
import Link from "next/link";

import { api } from "@/lib/api";
import type { CommandCenterDashboardState } from "@/lib/types";
import { cn } from "@/lib/utils";

type LiveFeedItem = NonNullable<CommandCenterDashboardState["live_activity_feed"]>["items"][number];

function humanizeToken(value: string | null | undefined): string {
  const token = String(value || "").trim();
  if (!token) return "Activity";
  return token
    .replaceAll(".", " ")
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatRelativeTime(value?: string | null): string {
  if (!value) return "just now";
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return "just now";
  const diffMs = Math.max(0, Date.now() - parsed);
  if (diffMs < 10_000) return "just now";
  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function decisionLabel(decision: string): string {
  const normalized = String(decision || "").toLowerCase();
  if (normalized === "block") return "Blocked";
  if (normalized === "warn") return "Warned";
  if (normalized === "allow") return "Allowed";
  if (normalized === "require_approval" || normalized === "hold") return "Review";
  return humanizeToken(normalized);
}

function decisionBadgeClass(decision: string): string {
  const normalized = String(decision || "").toLowerCase();
  if (normalized === "block") return "border-rose-900/70 bg-rose-950/30 text-rose-300";
  if (normalized === "warn") return "border-amber-900/70 bg-amber-950/25 text-amber-300";
  if (normalized === "allow") return "border-emerald-900/70 bg-emerald-950/25 text-emerald-300";
  return "border-sky-900/70 bg-sky-950/25 text-sky-300";
}

function accentDotClass(decision: string): string {
  const normalized = String(decision || "").toLowerCase();
  if (normalized === "block") return "bg-[#ff476f]";
  if (normalized === "warn") return "bg-[#ffc64d]";
  if (normalized === "allow") return "bg-[#1ee6a1]";
  return "bg-[#53a1ff]";
}

function eventHeadline(item: LiveFeedItem): string {
  const actionLabel = humanizeToken(item.action_type);
  const normalizedDecision = String(item.policy_decision || "").toLowerCase();
  if (normalizedDecision === "block") return `${actionLabel} prevented`;
  if (normalizedDecision === "warn") return `${actionLabel} controlled`;
  if (normalizedDecision === "allow") return `${actionLabel} allowed`;
  if (normalizedDecision === "require_approval") return `${actionLabel} held for review`;
  return actionLabel;
}

function eventMeta(item: LiveFeedItem): string {
  return [
    item.agent_id || item.user_email || item.user_id,
    item.application,
    item.tool_name,
    item.ai_surface,
  ]
    .filter(Boolean)
    .map((part) => String(part))
    .join(" • ");
}

function explanationSummary(item: LiveFeedItem): string | null {
  return item.decision_explanation?.decision_summary?.plain_english_reason || null;
}

function explanationFactors(item: LiveFeedItem) {
  return (item.decision_explanation?.decision_factors || []).slice(0, 4);
}

export function OperationsLiveFeed({
  items,
  total,
  drilldown,
  timeWindowLabel,
}: {
  items: LiveFeedItem[];
  total: number;
  drilldown: string;
  timeWindowLabel: string;
}) {
  const [tuningStatus, setTuningStatus] = useState<Record<string, string>>({});

  async function requestTuningAction(item: LiveFeedItem, action: string) {
    const explanationId = item.decision_explanation?.explanation_id;
    if (!explanationId) return;
    const key = `${item.event_id}:${action}`;
    setTuningStatus((current) => ({ ...current, [key]: "Recording" }));
    try {
      await api.recordDecisionTuningAction(explanationId, {
        action,
        runtime_event_id: item.event_id,
        finding_id: item.finding_id || undefined,
      });
      setTuningStatus((current) => ({ ...current, [key]: "Recorded" }));
    } catch (error) {
      setTuningStatus((current) => ({
        ...current,
        [key]: error instanceof Error ? error.message : "Unable to record",
      }));
    }
  }

  function actionTraceHref(item: LiveFeedItem) {
    return item.action_trace_url || item.trace_url || `/runtime-intelligence/context-graph?event_id=${item.event_id}`;
  }

  return (
    <section className="overflow-hidden rounded-[26px] border border-[#1a1f30] bg-[#090c14] shadow-[0_24px_60px_rgba(0,0,0,0.24)]">
      <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-5">
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-slate-500">Command Center</p>
          <h2 className="mt-2 text-[1.55rem] font-semibold tracking-[-0.03em] text-slate-50">AI Activity</h2>
          <p className="mt-1 text-sm text-slate-500">Compact signal stream for recent decisions and traces.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span className="rounded-xl border border-white/8 bg-white/[0.03] px-4 py-2.5 font-medium text-slate-400">
            {total} events
          </span>
          <span className="font-mono text-slate-500">{timeWindowLabel}</span>
        </div>
      </div>

      <div className="border-t border-[#151b28] px-5">
        {items.length ? (
          items.map((item) => (
            <div
              key={item.event_id}
              className="grid gap-3 border-b border-[#141927] py-4 last:border-b-0 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-start"
            >
              <div className="flex min-w-0 items-start gap-4">
                <span className={cn("mt-2 h-3.5 w-3.5 shrink-0 rounded-full", accentDotClass(item.policy_decision))} />
                <div className="min-w-0">
                  <Link
                    href={actionTraceHref(item)}
                    className="block text-base font-medium tracking-[-0.02em] text-slate-100 transition hover:text-white"
                  >
                    {eventHeadline(item)}
                  </Link>
                  <p className="mt-1 truncate font-mono text-[13px] text-slate-500">{eventMeta(item) || "Normalized runtime event"}</p>
                  {item.decision_explanation ? (
                    <details className="group mt-3">
                      <summary className="inline-flex cursor-pointer items-center rounded-lg border border-white/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400 transition hover:border-white/20 hover:text-slate-100">
                        Decision explanation
                      </summary>
                      <div className="mt-3 space-y-3 border-l border-white/10 pl-4">
                        {explanationSummary(item) ? (
                          <p className="text-sm leading-6 text-slate-300">{explanationSummary(item)}</p>
                        ) : null}
                        <div className="grid gap-2 sm:grid-cols-2">
                          {explanationFactors(item).map((factor, index) => (
                            <div key={`${item.event_id}-factor-${index}`} className="rounded-lg border border-white/8 bg-white/[0.025] p-3">
                              <div className="flex items-center justify-between gap-3">
                                <span className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-300">
                                  {humanizeToken(factor.label || factor.factor_type || "Factor")}
                                </span>
                                {factor.effect ? (
                                  <span className="font-mono text-[11px] text-slate-500">{humanizeToken(factor.effect)}</span>
                                ) : null}
                              </div>
                              {factor.explanation ? <p className="mt-2 text-xs leading-5 text-slate-500">{factor.explanation}</p> : null}
                            </div>
                          ))}
                        </div>
                        {item.decision_explanation.decision_summary?.recommended_safe_path ? (
                          <p className="text-xs leading-5 text-slate-500">
                            Safe path: {item.decision_explanation.decision_summary.recommended_safe_path}
                          </p>
                        ) : null}
                        <div className="flex flex-wrap gap-2">
                          {[
                            ["suggest_policy_narrowing", "Suggest narrowing"],
                            ["suggest_policy_exception", "Suggest exception"],
                            ["mark_expected_behavior", "Expected behavior"],
                          ].map(([action, label]) => {
                            const statusKey = `${item.event_id}:${action}`;
                            return (
                              <button
                                key={action}
                                type="button"
                                onClick={() => void requestTuningAction(item, action)}
                                className="rounded-lg border border-white/10 px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-400 transition hover:border-white/20 hover:text-slate-100 disabled:cursor-wait disabled:opacity-60"
                                disabled={tuningStatus[statusKey] === "Recording"}
                              >
                                {tuningStatus[statusKey] || label}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </details>
                  ) : null}
                </div>
              </div>
              <div>
                <span
                  className={cn(
                    "inline-flex items-center rounded-xl border px-3 py-1.5 text-xs font-semibold uppercase tracking-[0.08em]",
                    decisionBadgeClass(item.policy_decision)
                  )}
                >
                  {decisionLabel(item.policy_decision)}
                </span>
              </div>
              <div className="flex items-center gap-4 md:justify-end">
                <span className="font-mono text-xs text-slate-500">{formatRelativeTime(item.timestamp)}</span>
                <Link
                  href={actionTraceHref(item)}
                  className="text-xs uppercase tracking-[0.08em] text-slate-400 transition hover:text-slate-100"
                >
                  Trace
                </Link>
                {item.action_graph_url ? (
                  <Link
                    href={item.action_graph_url}
                    className="text-xs uppercase tracking-[0.08em] text-slate-500 transition hover:text-slate-100"
                  >
                    Graph
                  </Link>
                ) : null}
              </div>
            </div>
          ))
        ) : (
          <div className="py-14 text-center">
            <p className="text-base text-slate-300">No live events in this window.</p>
            <p className="mt-2 text-sm text-slate-500">Refresh or widen the filter window to repopulate the operations feed.</p>
          </div>
        )}
      </div>

      <div className="flex justify-end border-t border-[#151b28] px-5 py-3">
        <Link href={drilldown} className="text-xs font-medium uppercase tracking-[0.08em] text-slate-300 transition hover:text-white">
          Open full activity stream
        </Link>
      </div>
    </section>
  );
}
