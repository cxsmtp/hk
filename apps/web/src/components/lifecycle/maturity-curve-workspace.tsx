"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ChevronRight,
  Eye,
  FlaskConical,
  LockKeyhole,
  Play,
  Radar,
  RefreshCw,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { toast } from "sonner";

import { WorkspaceHeader } from "@/components/lifecycle/workspace-header";
import { OperationalState } from "@/components/operational-state";
import { Button } from "@/components/ui/button";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import type {
  MaturityCurveOverview,
  MaturityCurveRecommendation,
  MaturityCurveRollout,
  MaturityCurveScopeDetail,
  MaturityCurveStage,
} from "@/lib/types";
import { cn } from "@/lib/utils";
import type { PresentationState } from "@/lib/presentation-state";

const STAGES: Array<{ stage: MaturityCurveStage; label: string; caption: string }> = [
  { stage: "UNKNOWN", label: "Unknown", caption: "No measured estate" },
  { stage: "CONNECTED", label: "Connected", caption: "Signals attached" },
  { stage: "MONITORING", label: "Monitoring", caption: "Observed activity" },
  { stage: "UNDERSTANDING", label: "Understanding", caption: "Baseline is real" },
  { stage: "POLICY_READY", label: "Policy ready", caption: "Draft is simulated" },
  { stage: "CONTROLLED", label: "Controlled", caption: "Version is active" },
  { stage: "ASSURED", label: "Assured", caption: "Effectiveness is current" },
];

type EvidencePostureCard = {
  label: string;
  value: string;
  Icon: LucideIcon;
};

function stageIndex(stage?: string | null) {
  const found = STAGES.findIndex((item) => item.stage === stage);
  return found >= 0 ? found : 0;
}

function stageTone(stage?: string | null) {
  if (stage === "ASSURED") return "border-emerald-300/30 bg-emerald-300/[0.09] text-emerald-200";
  if (stage === "CONTROLLED" || stage === "POLICY_READY") return "border-cyan-300/30 bg-cyan-300/[0.09] text-cyan-100";
  if (stage === "UNDERSTANDING" || stage === "MONITORING") return "border-orange-300/30 bg-orange-300/[0.09] text-orange-100";
  return "border-white/[0.12] bg-white/[0.04] text-slate-400";
}

function recordNumber(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function decisionCounts(recommendation: MaturityCurveRecommendation): string {
  const draft = recommendation.policy_draft as { scoped_rules?: Array<{ effect?: { decision?: string } }> };
  const decision = draft.scoped_rules?.[0]?.effect?.decision || "review";
  return decision.replaceAll("_", " ");
}

function readableConditions(recommendation: MaturityCurveRecommendation): string[] {
  const draft = recommendation.policy_draft as {
    scoped_rules?: Array<{ condition_tree?: { all?: Array<{ field?: string; operator?: string; value?: unknown }> } }>;
  };
  const conditions = draft.scoped_rules?.[0]?.condition_tree?.all || [];
  return conditions.slice(0, 4).map((condition) => {
    const value = Array.isArray(condition.value) ? condition.value.join(", ") : String(condition.value ?? "unknown");
    return `${String(condition.field || "context").replaceAll("_", " ")} ${condition.operator || "matches"} ${value}`;
  });
}

function latestRollout(detail: MaturityCurveScopeDetail | null, recommendationId: string): MaturityCurveRollout | null {
  return detail?.rollouts.find((item) => item.recommendation_id === recommendationId) || null;
}

export function MaturityCurveWorkspace() {
  const [overview, setOverview] = useState<MaturityCurveOverview | null>(null);
  const [selectedScopeId, setSelectedScopeId] = useState<string>("");
  const [detail, setDetail] = useState<MaturityCurveScopeDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [role, setRole] = useState("viewer");

  // Auditors retain read-only evidence visibility. Lifecycle mutations use the
  // same operator gate as the API, so the UI never advertises an action it
  // cannot perform.
  const canOperate = ["operator", "admin", "owner"].includes(role);
  const canAdminister = ["admin", "owner"].includes(role);

  async function loadScope(scopeId: string) {
    if (!scopeId) {
      setDetail(null);
      return;
    }
    const next = await api.getMaturityCurveScope(scopeId);
    setDetail(next);
  }

  async function load(preferredScopeId?: string) {
    setLoading(true);
    try {
      const nextOverview = await api.maturityCurveOverview();
      setOverview(nextOverview);
      const nextScopeId = preferredScopeId || selectedScopeId || nextOverview.scopes[0]?.id || "";
      setSelectedScopeId(nextScopeId);
      await loadScope(nextScopeId);
      setError(null);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Maturity Curve is unavailable.";
      setError(message.includes("404") || message.includes("Not found")
        ? "Maturity Curve has not been enabled for this tenant. No maturity state is being inferred."
        : message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    setRole(String(getSession()?.userRole || "viewer").toLowerCase());
    void load();
    // Initial tenant-scoped hydration only; refreshes are explicit user actions.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const selectedAssessment = detail?.assessment || overview?.assessments.find((item) => item.scope_id === selectedScopeId) || null;
  const currentStage = selectedAssessment?.stage || "UNKNOWN";
  const currentStageIndex = stageIndex(currentStage);
  const selectedScope = detail?.scope || overview?.scopes.find((item) => item.id === selectedScopeId) || null;
  const baseline = detail?.baseline || null;
  const observedActions = recordNumber(selectedAssessment?.indicators?.observed_actions, baseline?.sample_count || 0);
  const coverageRefs = selectedAssessment?.evidence_refs.filter((item) => item.startsWith("control_coverage:")) || [];
  const patterns = detail?.patterns || [];
  const recommendations = detail?.recommendations || [];
  const latestEffectiveness = detail?.effectiveness[0] || null;
  const executiveReport = overview?.executive?.report || null;
  const maturityState: PresentationState = loading
    ? "loading"
    : error
      ? (overview || detail ? "stale" : "unavailable")
      : overview || detail ? "ready-populated" : "ready-empty";

  const stageHeading = useMemo(
    () => STAGES.find((item) => item.stage === currentStage) || STAGES[0],
    [currentStage],
  );

  async function runAction(key: string, action: () => Promise<void>) {
    setWorking(key);
    try {
      await action();
    } catch (cause) {
      toast.error(cause instanceof Error ? cause.message : "The requested lifecycle action did not complete.");
    } finally {
      setWorking(null);
    }
  }

  function refreshSelected() {
    if (!selectedScope) return;
    void runAction(`refresh:${selectedScope.id}`, async () => {
      await api.refreshMaturityCurveScope(selectedScope.id);
      await load(selectedScope.id);
      toast.success("Evidence window refreshed. Any unknowns remain visible.");
    });
  }

  function createEnterpriseScope() {
    void runAction("create-scope", async () => {
      const scope = await api.createMaturityCurveScope({
        scope_key: "organization:all",
        scope_type: "organization",
        display_name: "Enterprise AI estate",
        filters: {},
      });
      await load(scope.id);
      toast.success("Enterprise scope created. Refresh it to collect the first evidence window.");
    });
  }

  function simulateRecommendation(recommendation: MaturityCurveRecommendation) {
    void runAction(`simulate:${recommendation.id}`, async () => {
      const result = await api.simulateMaturityRecommendation(recommendation.id);
      await load(selectedScopeId);
      toast.success(result.passed ? "Simulation passed against the observed window." : "Simulation retained unresolved evidence.");
    });
  }

  function reviewRecommendation(recommendation: MaturityCurveRecommendation) {
    void runAction(`review:${recommendation.id}`, async () => {
      await api.reviewMaturityRecommendation(
        recommendation.id,
        "REVIEW",
        "Operator started a documented review of the evidence-backed recommendation.",
      );
      await load(selectedScopeId);
      toast.success("Recommendation moved to evidence review. It is still not an active policy.");
    });
  }

  function startRollout(recommendation: MaturityCurveRecommendation) {
    void runAction(`rollout:${recommendation.id}`, async () => {
      await api.startMaturityRollout(recommendation.id);
      await load(selectedScopeId);
      toast.success("Rollout draft created. It cannot enforce until it is reviewed and approved.");
    });
  }

  function transition(rollout: MaturityCurveRollout, target: string, rolloutStage?: string) {
    void runAction(`transition:${rollout.id}:${target}`, async () => {
      await api.transitionMaturityRollout(
        rollout.id,
        target,
        `Maturity Curve ${target.toLowerCase()} transition`,
        rolloutStage,
      );
      await load(selectedScopeId);
      toast.success(`Rollout moved to ${target.toLowerCase()}.`);
    });
  }

  function refreshEffectiveness(rollout: MaturityCurveRollout) {
    void runAction(`effectiveness:${rollout.id}`, async () => {
      const result = await api.refreshMaturityEffectiveness(rollout.id);
      await load(selectedScopeId);
      toast.success(result.status === "CURRENT" ? "Effectiveness evidence is current." : `Effectiveness is ${result.status.toLowerCase()}.`);
    });
  }

  function refreshExecutive() {
    if (!selectedScope) return;
    void runAction(`executive:${selectedScope.id}`, async () => {
      await api.refreshMaturityExecutive(selectedScope.id);
      await load(selectedScope.id);
      toast.success("Executive evidence brief refreshed. Unknowns remain explicit.");
    });
  }

  return (
    <div className="space-y-5">
      <WorkspaceHeader
        eyebrow="Policy intelligence"
        title="Maturity Curve"
        description="Turn observed AI usage into reviewed policy change—without treating a score, a recommendation, or a missing signal as authority."
        actions={(
          <>
            {canOperate && !overview?.scopes.length ? (
              <Button onClick={createEnterpriseScope} disabled={working === "create-scope"}>
                <Sparkles className="mr-2 h-4 w-4" />Create enterprise scope
              </Button>
            ) : null}
            {canOperate && selectedScope ? (
              <Button variant="outline" onClick={refreshSelected} disabled={working === `refresh:${selectedScope.id}`}>
                <RefreshCw className={cn("mr-2 h-4 w-4", working === `refresh:${selectedScope.id}` && "animate-spin")} />Refresh evidence
              </Button>
            ) : null}
            {canOperate && selectedScope ? (
              <Button variant="outline" onClick={refreshExecutive} disabled={working === `executive:${selectedScope.id}`}>
                <Activity className={cn("mr-2 h-4 w-4", working === `executive:${selectedScope.id}` && "animate-pulse")} />Refresh executive brief
              </Button>
            ) : null}
          </>
        )}
      />

      <OperationalState
        state={maturityState}
        onRetry={() => void load(selectedScopeId)}
        description={error ? `${error} Existing evidence remains visible where available.` : undefined}
      />

      {error && !overview && !detail ? (
        <details className="rounded-[22px] border border-white/[0.08] bg-[#0b1017] p-4">
          <summary className="cursor-pointer text-sm font-semibold text-slate-200">How to establish maturity evidence</summary>
          <div className="mt-3 space-y-2 text-sm leading-6 text-slate-400">
            <p>Create an enterprise scope when the tenant is ready to measure its AI estate, then refresh the evidence window after an authoritative activity source is connected.</p>
            <p>Unknown evidence stays unknown until a named source, baseline, simulation, or control reference is available.</p>
          </div>
        </details>
      ) : null}

      {!error || overview || detail ? <>
          <section className="relative overflow-hidden rounded-[26px] border border-white/[0.08] bg-[#0b1017] p-5 sm:p-6" aria-labelledby="maturity-rail-title">
            <div className="pointer-events-none absolute inset-0 opacity-70 [background:radial-gradient(circle_at_12%_0%,rgba(251,146,60,0.15),transparent_30%),radial-gradient(circle_at_86%_100%,rgba(34,211,238,0.1),transparent_34%)]" />
            <div className="relative flex flex-col gap-6 xl:flex-row xl:items-end xl:justify-between">
              <div>
                <p id="maturity-rail-title" className="text-[10px] font-semibold uppercase tracking-[0.2em] text-orange-300/80">Evidence rail</p>
                <div className="mt-2 flex items-center gap-3"><h2 className="text-2xl font-semibold tracking-[-0.035em] text-white">{stageHeading.label}</h2><span className={cn("rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em]", stageTone(currentStage))}>{currentStage.replaceAll("_", " ")}</span></div>
                <p className="mt-2 max-w-xl text-sm leading-6 text-slate-400">{stageHeading.caption}. Hawk advances only when the next named evidence gate is present; there is no blended maturity score.</p>
              </div>
              <div className="grid grid-cols-3 gap-px overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.08] text-center sm:grid-cols-4">
                {[
                  ["Observed", observedActions],
                  ["Sources", selectedAssessment?.source_diversity ?? "Unknown"],
                  ["Coverage refs", coverageRefs.length || "None"],
                  ["Effectiveness", latestEffectiveness?.status || "Unknown"],
                ].map(([label, value]) => <div key={String(label)} className="bg-[#0d131c] px-4 py-3"><p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-600">{label}</p><p className="mt-1 text-lg font-semibold text-slate-100">{String(value)}</p></div>)}
              </div>
            </div>
            <div className="relative mt-8 overflow-x-auto pb-1">
              <div className="min-w-[690px] px-2">
                <div className="relative grid grid-cols-7 gap-1">
                  <div className="absolute left-8 right-8 top-[18px] h-px bg-gradient-to-r from-orange-300/20 via-cyan-300/30 to-white/[0.08]" />
                  {STAGES.map((item, index) => {
                    const active = index <= currentStageIndex;
                    const current = index === currentStageIndex;
                    return <div key={item.stage} className="relative text-center"><span className={cn("mx-auto grid h-9 w-9 place-items-center rounded-full border text-xs font-bold transition", current ? "border-orange-200 bg-orange-300 text-[#15110d] shadow-[0_0_0_5px_rgba(251,146,60,0.08)]" : active ? "border-cyan-300/50 bg-cyan-300/10 text-cyan-100" : "border-white/[0.1] bg-[#0b1017] text-slate-600")}>{active && !current ? <CheckCircle2 className="h-4 w-4" /> : index + 1}</span><p className={cn("mt-3 text-[11px] font-semibold", current ? "text-orange-100" : active ? "text-cyan-100" : "text-slate-600")}>{item.label}</p><p className="mt-1 text-[9px] text-slate-600">{item.caption}</p></div>;
                  })}
                </div>
              </div>
            </div>
          </section>

          <section className="grid gap-4 xl:grid-cols-[0.82fr_1.18fr]">
            <div className="rounded-[24px] border border-white/[0.08] bg-[#0b1017] p-4 sm:p-5">
              <div className="flex items-center justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-slate-500">Scopes</p><h2 className="mt-1 text-lg font-semibold text-white">Where evidence is measured</h2></div><Radar className="h-5 w-5 text-orange-300/70" /></div>
              <div className="mt-4 space-y-2">
                {loading ? <div className="rounded-2xl border border-white/[0.07] p-6 text-center text-sm text-slate-500">Loading tenant-scoped evidence…</div> : null}
                {!loading && !(overview?.scopes.length) ? <div className="rounded-2xl border border-dashed border-white/[0.12] p-6 text-center text-sm leading-6 text-slate-500">No maturity scope exists yet. Create an enterprise scope, then refresh it to establish the first evidence window.</div> : null}
                {overview?.scopes.map((scope) => {
                  const assessment = overview.assessments.find((item) => item.scope_id === scope.id);
                  const active = scope.id === selectedScopeId;
                  return <button key={scope.id} type="button" onClick={() => { setSelectedScopeId(scope.id); void loadScope(scope.id); }} className={cn("w-full rounded-2xl border p-3.5 text-left transition", active ? "border-orange-300/30 bg-orange-300/[0.07]" : "border-white/[0.07] bg-white/[0.018] hover:border-white/[0.15] hover:bg-white/[0.04]")}><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate text-sm font-semibold text-slate-100">{scope.display_name}</p><p className="mt-1 truncate text-[11px] text-slate-500">{scope.scope_type.replaceAll("_", " ")} · {scope.scope_key}</p></div><span className={cn("shrink-0 rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em]", stageTone(assessment?.stage))}>{assessment?.stage || "Unknown"}</span></div><div className="mt-3 flex items-center gap-2 text-[10px] text-slate-600"><Activity className="h-3.5 w-3.5" />{recordNumber(assessment?.indicators?.observed_actions)} observations<ChevronRight className="ml-auto h-3.5 w-3.5" /></div></button>;
                })}
              </div>
            </div>

            <div className="rounded-[24px] border border-white/[0.08] bg-[#0b1017] p-4 sm:p-5">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-slate-500">Evidence posture</p><h2 className="mt-1 text-lg font-semibold text-white">{selectedScope?.display_name || "Select a scope"}</h2><p className="mt-1 text-xs leading-5 text-slate-500">Only source references, derived counts and explicit gaps are retained here. Raw prompt and action content stay in their authoritative systems.</p></div><span className={cn("w-fit rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em]", stageTone(selectedAssessment?.stage))}>{selectedAssessment?.status || "No assessment"}</span></div>
              <div className="mt-5 grid gap-2 sm:grid-cols-3">
                {([
                  { label: "Baseline", value: baseline?.status || "Unknown", Icon: Eye },
                  { label: "Simulation", value: detail?.simulations.some((item) => item.passed) ? "Passed" : "Not passed", Icon: FlaskConical },
                  { label: "Control proof", value: latestEffectiveness?.status || "Unknown", Icon: ShieldAlert },
                ] satisfies EvidencePostureCard[]).map(({ label, value, Icon }) => <div key={label} className="rounded-2xl border border-white/[0.07] bg-black/15 p-3"><Icon className="h-4 w-4 text-orange-300/70" /><p className="mt-3 text-[10px] uppercase tracking-[0.14em] text-slate-600">{label}</p><p className="mt-1 text-sm font-semibold text-slate-200">{value}</p></div>)}
              </div>
              <div className="mt-4 grid gap-3 lg:grid-cols-2">
                <div className="rounded-2xl border border-white/[0.07] bg-white/[0.018] p-3.5"><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Missing gates</p><div className="mt-2 flex flex-wrap gap-1.5">{selectedAssessment?.missing_gates.length ? selectedAssessment.missing_gates.map((gap) => <span key={gap} className="rounded-md bg-amber-300/[0.08] px-2 py-1 text-[10px] text-amber-100">{gap.replaceAll("_", " ")}</span>) : <span className="text-xs text-slate-600">No missing gates reported in this window.</span>}</div></div>
                <div className="rounded-2xl border border-white/[0.07] bg-white/[0.018] p-3.5"><p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Blocking gaps</p><div className="mt-2 flex flex-wrap gap-1.5">{selectedAssessment?.blocking_gaps.length ? selectedAssessment.blocking_gaps.map((gap) => <span key={gap} className="rounded-md bg-rose-300/[0.08] px-2 py-1 text-[10px] text-rose-100">{gap.replaceAll("_", " ")}</span>) : <span className="text-xs text-slate-600">No blocking gap is being hidden.</span>}</div></div>
              </div>
            </div>
          </section>

          <section className="grid gap-4 xl:grid-cols-[1.06fr_0.94fr]">
            <div className="rounded-[24px] border border-white/[0.08] bg-[#0b1017] p-4 sm:p-5">
              <div className="flex items-start justify-between gap-3"><div><p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-cyan-300/75">Observed patterns</p><h2 className="mt-1 text-lg font-semibold text-white">Usage is evidence, never approval</h2><p className="mt-1 text-xs leading-5 text-slate-500">Patterns are privacy-safe summaries of canonical actions. Their labels show observed posture, not a user or application score.</p></div><Eye className="mt-1 h-5 w-5 text-cyan-300/70" /></div>
              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                {!patterns.length ? <div className="col-span-full rounded-2xl border border-dashed border-white/[0.1] p-5 text-center text-xs leading-5 text-slate-500">No stable pattern is available for this evidence window. Hawk will not infer one from absent metadata.</div> : null}
                {patterns.slice(0, 8).map((pattern) => <article key={pattern.id} className="rounded-2xl border border-white/[0.07] bg-white/[0.018] p-3"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><p className="truncate text-sm font-medium text-slate-200">{pattern.value_ref.replaceAll("_", " ")}</p><p className="mt-1 text-[10px] uppercase tracking-[0.13em] text-slate-600">{pattern.dimension.replaceAll("_", " ")} · {pattern.observation_count} observed</p></div><span className={cn("shrink-0 rounded-full border px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.12em]", pattern.risk_state === "HIGH" || pattern.risk_state === "CRITICAL" ? "border-rose-300/25 bg-rose-300/[0.09] text-rose-100" : "border-white/[0.1] bg-white/[0.035] text-slate-400")}>{pattern.risk_state}</span></div><div className="mt-3 flex flex-wrap gap-1.5 text-[9px]"><span className="rounded-md bg-white/[0.045] px-2 py-1 text-slate-500">{pattern.pattern_type}</span><span className={cn("rounded-md px-2 py-1", pattern.approval_state === "UNAPPROVED" ? "bg-amber-300/[0.08] text-amber-100" : "bg-white/[0.045] text-slate-500")}>{pattern.approval_state}</span><span className="rounded-md bg-white/[0.045] px-2 py-1 text-slate-500">{pattern.control_state}</span></div></article>)}
              </div>
            </div>
            <div className="rounded-[24px] border border-white/[0.08] bg-[#0b1017] p-4 sm:p-5">
              <div className="flex items-start justify-between gap-3"><div><p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-emerald-300/75">Executive evidence brief</p><h2 className="mt-1 text-lg font-semibold text-white">What warrants attention</h2></div><ShieldAlert className="mt-1 h-5 w-5 text-emerald-300/70" /></div>
              {!executiveReport ? <div className="mt-4 rounded-2xl border border-dashed border-white/[0.1] p-5 text-xs leading-5 text-slate-500">No executive brief has been materialized. Refresh it when the scope has evidence; Hawk will preserve unknowns instead of inventing a trend.</div> : <><div className="mt-4 grid grid-cols-3 gap-2">{[["Actions", executiveReport.evidence_summary.observed_actions], ["Gaps", executiveReport.top_gaps.length], ["Coverage refs", executiveReport.evidence_summary.control_coverage_reference_count]].map(([label, value]) => <div key={String(label)} className="rounded-xl border border-white/[0.07] bg-black/15 p-3"><p className="text-[9px] uppercase tracking-[0.13em] text-slate-600">{String(label)}</p><p className="mt-1 text-lg font-semibold text-slate-100">{String(value)}</p></div>)}</div><div className="mt-4 space-y-2">{executiveReport.recommended_next_steps.slice(0, 3).map((step) => <div key={step} className="flex gap-2 rounded-xl border border-white/[0.06] bg-white/[0.018] p-2.5 text-xs leading-5 text-slate-400"><ChevronRight className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-300" />{step}</div>)}</div><p className="mt-3 text-[10px] leading-4 text-slate-600">Risk trend: {executiveReport.risk_trend.status.toLowerCase()} — {executiveReport.risk_trend.reason}</p></>}
            </div>
          </section>

          <section className="rounded-[24px] border border-white/[0.08] bg-[#0b1017] p-4 sm:p-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between"><div><p className="text-[10px] font-semibold uppercase tracking-[0.17em] text-orange-300/75">Recommended next action</p><h2 className="mt-1 text-lg font-semibold text-white">Review, simulate, then control</h2><p className="mt-1 text-xs leading-5 text-slate-500">A recommendation is not a policy. It becomes enforceable only after the policy version, simulation and rollout gates all complete.</p></div><div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.14em] text-slate-600"><LockKeyhole className="h-3.5 w-3.5" />Approval-gated</div></div>
            <div className="mt-5 space-y-3">
              {!recommendations.length ? <div className="rounded-2xl border border-dashed border-white/[0.1] p-8 text-center text-sm leading-6 text-slate-500">No recommendation is available. Hawk needs a complete, sufficiently diverse baseline before it will draft one.</div> : null}
              {recommendations.map((recommendation) => {
                const simulation = detail?.simulations.find((item) => item.recommendation_id === recommendation.id);
                const rollout = latestRollout(detail, recommendation.id);
                const conditions = readableConditions(recommendation);
                const nextTarget = rollout?.state === "DRAFT" ? "REVIEW" : rollout?.state === "REVIEW" ? "APPROVED" : rollout?.state === "APPROVED" ? "SHADOW" : rollout?.state === "SHADOW" ? "ENFORCE" : null;
                const elevateStage = rollout?.state === "ENFORCE" && rollout.rollout_stage === "warn" ? "require_approval" : rollout?.state === "ENFORCE" && rollout.rollout_stage === "require_approval" ? "enforce" : null;
                return <article key={recommendation.id} className="relative overflow-hidden rounded-[22px] border border-white/[0.08] bg-white/[0.018] p-4"><div className="absolute inset-y-0 left-0 w-1 bg-gradient-to-b from-orange-300 via-cyan-300 to-emerald-300" /><div className="pl-2"><div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between"><div><div className="flex flex-wrap items-center gap-2"><h3 className="text-base font-semibold text-slate-100">{recommendation.title}</h3><span className="rounded-full border border-orange-300/20 bg-orange-300/[0.08] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.13em] text-orange-100">{recommendation.status}</span><span className="rounded-full border border-cyan-300/20 bg-cyan-300/[0.08] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.13em] text-cyan-100">{decisionCounts(recommendation)}</span><span className="rounded-full border border-white/[0.1] bg-white/[0.035] px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.13em] text-slate-400">{recommendation.review_state}</span></div><p className="mt-2 text-xs text-slate-500">Confidence {Math.round(recommendation.confidence * 100)}% · {recordNumber(recommendation.estimated_impact.matched_historical_actions)} matching observed actions · {recommendation.evidence_refs.length} evidence references</p></div><div className="flex flex-wrap gap-2">{canOperate && recommendation.review_state === "PENDING" ? <Button size="sm" variant="outline" onClick={() => reviewRecommendation(recommendation)} disabled={working === `review:${recommendation.id}`}><Eye className="mr-1.5 h-3.5 w-3.5" />Review evidence</Button> : null}{canOperate && !simulation ? <Button size="sm" variant="outline" onClick={() => simulateRecommendation(recommendation)} disabled={working === `simulate:${recommendation.id}`}><Play className="mr-1.5 h-3.5 w-3.5" />Simulate</Button> : null}{canOperate && simulation?.passed && !rollout ? <Button size="sm" onClick={() => startRollout(recommendation)} disabled={working === `rollout:${recommendation.id}`}><ArrowRight className="mr-1.5 h-3.5 w-3.5" />Start rollout</Button> : null}{rollout && nextTarget && (nextTarget === "REVIEW" ? canOperate : canAdminister) ? <Button size="sm" onClick={() => transition(rollout, nextTarget, nextTarget === "ENFORCE" ? "warn" : undefined)} disabled={working === `transition:${rollout.id}:${nextTarget}`}><ChevronRight className="mr-1.5 h-3.5 w-3.5" />{nextTarget === "ENFORCE" ? "Warn phase" : nextTarget.replaceAll("_", " ")}</Button> : null}{rollout && elevateStage && canAdminister ? <Button size="sm" onClick={() => transition(rollout, "ENFORCE", elevateStage)} disabled={working === `transition:${rollout.id}:ENFORCE`}><ChevronRight className="mr-1.5 h-3.5 w-3.5" />{elevateStage === "require_approval" ? "Require approval" : "Enforce"}</Button> : null}{rollout?.state === "ENFORCE" && canOperate ? <Button size="sm" variant="outline" onClick={() => refreshEffectiveness(rollout)} disabled={working === `effectiveness:${rollout.id}`}><RefreshCw className="mr-1.5 h-3.5 w-3.5" />Verify</Button> : null}</div></div><div className="mt-4 grid gap-3 lg:grid-cols-[1fr_auto]"><div className="rounded-xl border border-white/[0.06] bg-black/15 p-3"><p className="text-[9px] font-semibold uppercase tracking-[0.14em] text-slate-600">Typed policy boundary</p><div className="mt-2 flex flex-wrap gap-1.5">{conditions.map((condition) => <span key={condition} className="rounded-md bg-white/[0.045] px-2 py-1 text-[10px] text-slate-400">{condition}</span>)}</div></div><div className="flex min-w-[180px] items-center gap-2 rounded-xl border border-white/[0.06] bg-black/15 p-3 text-xs text-slate-400"><FlaskConical className={cn("h-4 w-4", simulation?.passed ? "text-emerald-300" : "text-slate-600")} /><span>{simulation ? `${simulation.sample_count} replayed · ${simulation.passed ? "passed" : "not passed"}` : "Simulation required"}</span></div></div>{recommendation.unknowns.length ? <p className="mt-3 text-[11px] leading-5 text-slate-500">Known limits: {recommendation.unknowns.join(" ")}</p> : null}{rollout ? <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500"><span className="rounded-full border border-white/[0.08] px-2 py-1">Rollout: {rollout.state}</span><span>Stage: {rollout.rollout_stage.replaceAll("_", " ")}</span><span>Mode: {rollout.mode}</span>{rollout.policy_version_id ? <span>Version bound</span> : null}</div> : null}</div></article>;
              })}
            </div>
          </section>
      </> : null}
    </div>
  );
}
