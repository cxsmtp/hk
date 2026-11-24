"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { OperationalState } from "@/components/operational-state";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { formatDateTime } from "@/components/runtime-intelligence/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useRuntimeIntelligenceStream } from "@/hooks/use-runtime-intelligence-stream";
import { api } from "@/lib/api";
import { resolvePresentationState } from "@/lib/presentation-state";
import type { AISystem, RuntimeRecommendation, RuntimeStreamEvent } from "@/lib/types";

type RecommendationCard = {
  id: string;
  issue: string;
  recommendation: string;
  affectedSystems: string[];
  suggestedPolicyChange: string;
  priority: string;
  status: string;
  createdAt: string;
  decisionImpact: DecisionImpactSnapshot | null;
};

type DecisionImpactSnapshot = {
  decisionImpactScore: number;
  estimatedRiskReduction: number;
  baseRisk: number;
  confidence: number;
  urgencyMultiplier: number;
  controlEffectiveness: number;
  impactValue: number;
  probabilityScore: number;
  action: string;
  reasoning: string[];
};

function toTitle(value: string): string {
  return String(value || "")
    .trim()
    .replaceAll("_", " ")
    .split(" ")
    .filter(Boolean)
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

function asString(value: unknown): string {
  return String(value || "").trim();
}

function asStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item || "").trim()).filter(Boolean);
}

function asNumber(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return parsed;
}

function formatCurrency(value: number): string {
  if (!Number.isFinite(value)) return "$0";
  const abs = Math.abs(value);
  if (abs >= 1_000_000) return `$${(value / 1_000_000).toFixed(1)}M`;
  if (abs >= 1_000) return `$${(value / 1_000).toFixed(1)}K`;
  return `$${Math.round(value)}`;
}

function formatPercent(value: number): string {
  if (!Number.isFinite(value)) return "0%";
  return `${Math.round(value * 100)}%`;
}

function priorityBadge(priority: string): string {
  const normalized = String(priority || "").toLowerCase();
  if (normalized === "critical" || normalized === "high") return "border-rose-500/40 bg-rose-500/20 text-rose-200";
  if (normalized === "medium") return "border-amber-500/40 bg-amber-500/20 text-amber-200";
  if (normalized === "low") return "border-emerald-500/40 bg-emerald-500/20 text-emerald-200";
  return "border-slate-500/40 bg-slate-500/20 text-slate-200";
}

function statusBadge(status: string): string {
  const normalized = String(status || "").toLowerCase();
  if (["open", "pending", "queued"].includes(normalized)) return "border-amber-500/40 bg-amber-500/20 text-amber-200";
  if (["applied", "approved", "completed"].includes(normalized)) return "border-emerald-500/40 bg-emerald-500/20 text-emerald-200";
  if (["rejected", "dismissed", "blocked"].includes(normalized)) return "border-rose-500/40 bg-rose-500/20 text-rose-200";
  return "border-slate-500/40 bg-slate-500/20 text-slate-200";
}

function deriveRecommendationText(item: RuntimeRecommendation): string {
  const payload = item.payload || {};
  const explicit = asString(payload.recommendation);
  if (explicit) return explicit;

  const recType = String(item.recommendation_type || "").toLowerCase();
  if (recType.includes("tighten") || String(item.reason_code || "").toLowerCase().includes("sensitive")) {
    return "Tighten data handling controls for sensitive AI interactions.";
  }
  if (recType.includes("restrict") || String(item.reason_code || "").toLowerCase().includes("tool")) {
    return "Restrict risky tool usage and enforce explicit allow-lists.";
  }
  if (recType.includes("simulation") || String(item.reason_code || "").toLowerCase().includes("pattern")) {
    return "Increase simulation frequency for this behavior pattern until risk decreases.";
  }
  if (recType.includes("escalate")) return "Escalate risk posture and increase enforcement strictness for impacted paths.";
  if (recType.includes("review")) return "Route this issue to governance review and approval workflow.";
  return `Apply runtime recommendation: ${toTitle(item.recommendation_type || "policy_update")}.`;
}

function derivePolicyChangeText(item: RuntimeRecommendation): string {
  const payload = item.payload || {};
  const explicit = asString(payload.suggested_policy_change || payload.policy_change || payload.guardian_change);
  if (explicit) return explicit;

  const recType = String(item.recommendation_type || "").toLowerCase();
  const reason = String(item.reason_code || "").toLowerCase();
  if (recType.includes("tighten") || reason.includes("data_exfil")) {
    return "Set stricter data movement rules (warn -> block) for external AI destinations.";
  }
  if (recType.includes("restrict") || reason.includes("tool")) {
    return "Move tool scope to least-privilege and deny unapproved tool categories.";
  }
  if (recType.includes("simulation")) {
    return "Raise validation cadence and auto-trigger targeted simulation packs for this behavior.";
  }
  if (recType.includes("escalate")) return "Increase risk tier and require approval on high-risk actions.";
  if (recType.includes("blocked") || recType.includes("move_to_blocked")) return "Set enforcement default to block for this workflow scope.";
  return "Update Guardian policy conditions and decision mode for the affected scope.";
}

function deriveIssueText(item: RuntimeRecommendation): string {
  const payload = item.payload || {};
  const explicit = asString(payload.issue || payload.summary);
  if (explicit) return explicit;
  if (asString(item.reason_code)) return toTitle(item.reason_code);
  return toTitle(item.recommendation_type || "runtime_risk");
}

function extractDecisionImpact(item: RuntimeRecommendation): DecisionImpactSnapshot | null {
  const payload = item.payload || {};
  const nested =
    payload && typeof payload.decision_impact === "object" && payload.decision_impact
      ? (payload.decision_impact as Record<string, unknown>)
      : {};

  const score = asNumber(payload.decision_impact_score ?? nested.decision_impact_score);
  const estimated = asNumber(payload.estimated_risk_reduction ?? nested.estimated_risk_reduction);
  const baseRisk = asNumber(payload.base_risk ?? nested.base_risk);
  const confidence = asNumber((nested as Record<string, unknown>).confidence ?? payload.confidence_score ?? payload.confidence);
  const urgency = asNumber(payload.urgency_multiplier ?? nested.urgency_multiplier);
  const controlEffectiveness = asNumber(payload.control_effectiveness ?? nested.control_effectiveness);
  const impactValue = asNumber(payload.impact_value ?? nested.impact_value);
  const probability = asNumber(payload.probability_score ?? nested.probability_score);
  const action = asString(payload.action ?? nested.action ?? item.recommendation_type);
  const reasoning = asStringList(nested.reasoning ?? payload.reasoning);

  if (score <= 0 && estimated <= 0 && baseRisk <= 0 && impactValue <= 0) return null;
  return {
    decisionImpactScore: score,
    estimatedRiskReduction: estimated,
    baseRisk,
    confidence,
    urgencyMultiplier: urgency,
    controlEffectiveness,
    impactValue,
    probabilityScore: probability,
    action,
    reasoning,
  };
}

export default function RuntimeIntelligenceRecommendationsPage() {
  const [recommendations, setRecommendations] = useState<RuntimeRecommendation[]>([]);
  const [systems, setSystems] = useState<AISystem[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [streamConnected, setStreamConnected] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const [recommendationPayload, systemPayload] = await Promise.all([
        api.runtimeRecommendations({ page_size: 250 }),
        api.listAISystems(),
      ]);
      setRecommendations(recommendationPayload.items || []);
      setSystems(systemPayload.items || []);
      setLoadError(null);
    } catch (error) {
      setRecommendations([]);
      setSystems([]);
      setLoadError(error instanceof Error ? error.message : "Runtime recommendations are unavailable.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
  }, []);

  const onStreamEvent = useCallback((streamEvent: RuntimeStreamEvent) => {
    const payload = streamEvent.payload || {};
    if (streamEvent.event_type !== "runtime.recommendation.created") return;
    const recommendationId = String(payload.recommendation_id || "").trim();
    const eventId = String(payload.event_id || "").trim();
    if (!recommendationId || !eventId) return;
    const incoming: RuntimeRecommendation = {
      recommendation_id: recommendationId,
      event_id: eventId,
      ai_system_id: String(payload.ai_system_id || "").trim() || null,
      recommendation_type: String(payload.recommendation_type || "runtime_recommendation").trim(),
      reason_code: String(payload.reason_code || "runtime_signal").trim(),
      priority: String(payload.priority || "med").trim(),
      payload: {},
      status: String(payload.status || "proposed").trim(),
      created_at: String(payload.created_at || new Date().toISOString()),
      applied_at: null,
    };
    setRecommendations((current) => [incoming, ...current.filter((row) => row.recommendation_id !== incoming.recommendation_id)].slice(0, 300));
  }, []);

  useRuntimeIntelligenceStream({
    channel: "recommendations",
    onEvent: onStreamEvent,
    onReconnect: () => {
      load().catch(() => undefined);
    },
    onConnectionStateChange: setStreamConnected,
  });

  const recommendationState = resolvePresentationState({ loading, hasData: recommendations.length > 0, unavailable: Boolean(loadError) });
  const initialLoading = loading && !recommendations.length;

  const systemsById = useMemo(() => new Map(systems.map((system) => [system.id, system.name])), [systems]);

  const cards = useMemo(() => {
    const rows = [...recommendations].sort(
      (left, right) => new Date(right.created_at).getTime() - new Date(left.created_at).getTime()
    );
    return rows.map((item) => {
      const payload = item.payload || {};
      const payloadSystemIds = asStringList(payload.ai_system_ids);
      const affectedSystemIds = Array.from(
        new Set([...(item.ai_system_id ? [item.ai_system_id] : []), ...payloadSystemIds])
      );
      const affectedSystems = affectedSystemIds.map((id) => systemsById.get(id) || id);

      return {
        id: item.recommendation_id,
        issue: deriveIssueText(item),
        recommendation: deriveRecommendationText(item),
        affectedSystems,
        suggestedPolicyChange: derivePolicyChangeText(item),
        priority: item.priority,
        status: item.status,
        createdAt: item.created_at,
        decisionImpact: extractDecisionImpact(item),
      } satisfies RecommendationCard;
    });
  }, [recommendations, systemsById]);

  const pendingCount = useMemo(
    () => cards.filter((card) => ["open", "pending", "queued"].includes(String(card.status || "").toLowerCase())).length,
    [cards]
  );
  const highPriorityCount = useMemo(
    () => cards.filter((card) => ["high", "critical"].includes(String(card.priority || "").toLowerCase())).length,
    [cards]
  );
  const affectedSystemCount = useMemo(() => {
    const set = new Set<string>();
    cards.forEach((card) => card.affectedSystems.forEach((system) => set.add(system)));
    return set.size;
  }, [cards]);

  const financialSummary = useMemo(() => {
    const impacted = cards.map((card) => card.decisionImpact).filter(Boolean) as DecisionImpactSnapshot[];
    if (!impacted.length) {
      return {
        scoredCount: 0,
        totalReduction: 0,
        avgScore: 0,
        avgConfidence: 0,
        top: null as DecisionImpactSnapshot | null,
      };
    }
    const totalReduction = impacted.reduce((sum, row) => sum + asNumber(row.estimatedRiskReduction), 0);
    const totalScore = impacted.reduce((sum, row) => sum + asNumber(row.decisionImpactScore), 0);
    const totalConfidence = impacted.reduce((sum, row) => sum + asNumber(row.confidence), 0);
    const top = [...impacted].sort((left, right) => right.decisionImpactScore - left.decisionImpactScore)[0] ?? null;
    return {
      scoredCount: impacted.length,
      totalReduction,
      avgScore: totalScore / impacted.length,
      avgConfidence: totalConfidence / impacted.length,
      top,
    };
  }, [cards]);

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="Recommendations"
          description="Actionable runtime insights to strengthen control posture and policy quality."
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button variant="outline" onClick={() => load().catch(() => undefined)}>
                {streamConnected ? "Live Stream On" : "Reconnect Stream"}
              </Button>
              <Button variant="outline" onClick={() => load()}>
                Refresh
              </Button>
            </>
          }
        />

        <OperationalState
          state={recommendationState}
          onRetry={() => void load()}
          description={loadError ? "Runtime recommendations unavailable. No recommendation count is inferred." : undefined}
        />

        <KpiStrip
          items={[
            { label: "Recommendations", value: loading ? "—" : cards.length, tone: "info" },
            { label: "Pending", value: loading ? "—" : pendingCount, tone: pendingCount ? "warning" : "success" },
            { label: "High Priority", value: loading ? "—" : highPriorityCount, tone: highPriorityCount ? "critical" : "success" },
            { label: "Affected Systems", value: loading ? "—" : affectedSystemCount, tone: "info" },
          ]}
        />

        <PageSection
          title="Recommendation Cards"
          description={
            loading
              ? "Loading recommendations..."
              : "Each card includes issue, recommendation, affected systems, and suggested policy change."
          }
        >
          {initialLoading ? (
            <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-10 text-center text-sm text-slate-400">
              Loading runtime recommendation task cards…
            </div>
          ) : cards.length ? (
            <div className="grid gap-4 xl:grid-cols-2">
              {cards.map((card) => (
                <div key={card.id} className="rounded-xl border border-[#2a3348] bg-[#101524] p-4">
                  <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap gap-2">
                      <Badge className={priorityBadge(card.priority)}>{toTitle(card.priority || "unknown")}</Badge>
                      <Badge className={statusBadge(card.status)}>{toTitle(card.status || "unknown")}</Badge>
                    </div>
                    <p className="text-xs text-slate-500">{formatDateTime(card.createdAt)}</p>
                  </div>

                  <div className="space-y-3">
                    <div>
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Issue</p>
                      <p className="mt-1 text-sm font-semibold text-slate-100">{card.issue}</p>
                    </div>

                    <div>
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Recommendation</p>
                      <p className="mt-1 text-sm text-slate-200">{card.recommendation}</p>
                    </div>

                    <div>
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Affected Systems</p>
                      {card.affectedSystems.length ? (
                        <div className="mt-1 flex flex-wrap gap-2">
                          {card.affectedSystems.slice(0, 5).map((system) => (
                            <Badge key={`${card.id}:${system}`}>{system}</Badge>
                          ))}
                        </div>
                      ) : (
                        <p className="mt-1 text-sm text-slate-400">No explicit system scope attached.</p>
                      )}
                    </div>

                    <div>
                      <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Suggested Policy Change</p>
                      <p className="mt-1 text-sm text-slate-200">{card.suggestedPolicyChange}</p>
                    </div>

                    {card.decisionImpact ? (
                      <div className="rounded-md border border-[#2a3348] bg-[#0b1220] p-3">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">CRQ Impact</p>
                        <div className="mt-2 grid gap-2 sm:grid-cols-2">
                          <p className="text-xs text-slate-300">
                            Score:{" "}
                            <span className="font-semibold text-slate-100">
                              {Math.round(asNumber(card.decisionImpact.decisionImpactScore)).toLocaleString()}
                            </span>
                          </p>
                          <p className="text-xs text-slate-300">
                            Reduction:{" "}
                            <span className="font-semibold text-emerald-300">
                              {formatCurrency(asNumber(card.decisionImpact.estimatedRiskReduction))}
                            </span>
                          </p>
                          <p className="text-xs text-slate-300">
                            Base Risk:{" "}
                            <span className="font-semibold text-slate-100">{formatCurrency(asNumber(card.decisionImpact.baseRisk))}</span>
                          </p>
                          <p className="text-xs text-slate-300">
                            Confidence:{" "}
                            <span className="font-semibold text-slate-100">{formatPercent(asNumber(card.decisionImpact.confidence))}</span>
                          </p>
                        </div>
                        {card.decisionImpact.reasoning.length ? (
                          <p className="mt-2 text-xs text-slate-400">
                            {card.decisionImpact.reasoning.slice(0, 2).join(" · ")}
                          </p>
                        ) : null}
                      </div>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-10 text-center text-sm text-slate-400">
              No runtime recommendations available yet.
            </div>
          )}
        </PageSection>

        <details className="rounded-lg border border-[#2a3348] bg-[#0b1220] px-4 py-3">
          <summary className="cursor-pointer text-sm font-semibold text-slate-100">Financial impact explanation (CRQ)</summary>
          <PageSection
            title="Financial Impact Explanation"
            description="Compact CRQ view from runtime recommendation impact scoring."
          >
            {financialSummary.scoredCount > 0 ? (
              <div className="grid gap-4 xl:grid-cols-4">
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Estimated Risk Reduction</p>
                  <p className="mt-2 text-2xl font-semibold text-emerald-300">{formatCurrency(financialSummary.totalReduction)}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Average Impact Score</p>
                  <p className="mt-2 text-2xl font-semibold text-sky-300">{Math.round(financialSummary.avgScore).toLocaleString()}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Average Confidence</p>
                  <p className="mt-2 text-2xl font-semibold text-slate-100">{formatPercent(financialSummary.avgConfidence)}</p>
                </div>
                <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Top Action</p>
                  <p className="mt-2 text-sm font-semibold text-slate-100">
                    {toTitle(financialSummary.top?.action || "not available")}
                  </p>
                  <p className="mt-1 text-xs text-slate-400">
                    Top score {Math.round(asNumber(financialSummary.top?.decisionImpactScore || 0)).toLocaleString()}
                  </p>
                </div>
              </div>
            ) : initialLoading ? (
              <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-center text-sm text-slate-400">
                Loading CRQ impact evidence…
              </div>
            ) : (
              <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-center text-sm text-slate-400">
                No CRQ impact breakdown available yet for the current recommendation set.
              </div>
            )}
          </PageSection>
        </details>
      </div>
    </AppShell>
  );
}
