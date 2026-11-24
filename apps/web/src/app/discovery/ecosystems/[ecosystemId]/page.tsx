"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Braces,
  CheckCircle2,
  CircleHelp,
  Clock3,
  Fingerprint,
  GitBranch,
  Network,
  Radio,
  RefreshCw,
  ScanSearch,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { DiscoveryWorkspaceFrame, formatDiscoveryLabel, formatDiscoveryTime } from "@/components/discovery/discovery-workspace-frame";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { getSession, SESSION_CHANGE_EVENT } from "@/lib/auth";
import type {
  EcosystemVerificationHistory,
  EcosystemVerificationProjection,
  ERGEcosystemDetail,
  ERGTimeline,
  VerificationOutcome,
} from "@/lib/types";


function text(value: unknown, fallback = "Unknown") {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function number(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function percent(value: number | null) {
  return value === null ? "Unknown" : `${Math.round(value * 100)}%`;
}

function tone(value: number | null) {
  if (value === null) return { ink: "#f59e0b", label: "Unknown" };
  if (value >= 0.9) return { ink: "#2dd4bf", label: "High assurance" };
  if (value >= 0.7) return { ink: "#67e8f9", label: "Probable" };
  return { ink: "#f59e0b", label: "Review required" };
}

function ConfidenceDial({ value, label }: { value: number | null; label: string }) {
  const visual = tone(value);
  const stop = value === null ? 12 : Math.max(2, Math.round(value * 100));
  return (
    <div className="relative grid h-36 w-36 shrink-0 place-items-center rounded-full border border-white/[0.06] bg-[#091119] shadow-[0_28px_90px_rgba(0,0,0,0.38)]">
      <div className="absolute inset-2 rounded-full" style={{ background: `conic-gradient(${visual.ink} ${stop}%, rgba(255,255,255,.055) 0)` }} />
      <div className="absolute inset-[13px] rounded-full border border-white/[0.07] bg-[#0a121b]" />
      <div className="relative text-center">
        <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-slate-600">{label}</p>
        <p className="mt-1 font-mono text-3xl text-white">{percent(value)}</p>
        <p className="mt-1 text-[9px] text-slate-500">{visual.label}</p>
      </div>
    </div>
  );
}

function EvidenceRiver({ timeline }: { timeline: ERGTimeline["items"] }) {
  return (
    <div className="relative overflow-hidden rounded-[26px] border border-white/[0.07] bg-[#0a131c] p-5">
      <div className="pointer-events-none absolute bottom-0 left-12 top-0 w-px bg-gradient-to-b from-transparent via-cyan-300/60 to-transparent" />
      <div className="hawk-river pointer-events-none absolute left-[45px] top-0 h-12 w-3 rounded-full bg-cyan-100 shadow-[0_0_24px_8px_rgba(34,211,238,.45)]" />
      <div className="relative space-y-3">
        {timeline.length ? timeline.slice(0, 12).map((item, index) => (
          <article key={item.event_id} className="group relative grid grid-cols-[28px_1fr] gap-4">
            <span className={`relative z-10 mt-4 h-3 w-3 rounded-full border ${item.changed_resolution ? "border-emerald-200 bg-emerald-300 shadow-[0_0_14px_#34d399]" : "border-cyan-200/70 bg-[#0a131c]"}`} />
            <div className="rounded-2xl border border-white/[0.055] bg-black/15 px-4 py-3 transition duration-300 group-hover:border-cyan-300/20 group-hover:bg-cyan-300/[0.025]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[8px] uppercase tracking-[0.14em] text-cyan-200/75">{formatDiscoveryLabel(item.drift_category)}</span>
                  {item.changed_resolution && <span className="rounded-full border border-emerald-300/15 bg-emerald-300/[0.05] px-2 py-0.5 font-mono text-[7px] uppercase tracking-wider text-emerald-200">Resolution changed</span>}
                </div>
                <time className="font-mono text-[8px] text-slate-600">{formatDiscoveryTime(item.occurred_at)}</time>
              </div>
              <p className="mt-2 text-xs leading-5 text-slate-200">{item.summary}</p>
              <p className="mt-1 truncate font-mono text-[8px] text-slate-600">{item.source_type} · {item.source_reference}</p>
            </div>
            {index < timeline.length - 1 && <span className="pointer-events-none absolute left-[5px] top-8 h-full w-px bg-white/[0.04]" />}
          </article>
        )) : (
          <div className="ml-10 rounded-2xl border border-dashed border-white/10 px-4 py-8 text-center text-xs text-slate-500">No recorded change has been linked to this ecosystem yet.</div>
        )}
      </div>
      <style jsx>{`
        .hawk-river { animation: hawkRiver 5.4s linear infinite; }
        @keyframes hawkRiver { from { transform: translateY(-64px); opacity: 0; } 8% { opacity: 1; } 88% { opacity: 1; } to { transform: translateY(560px); opacity: 0; } }
        @media (prefers-reduced-motion: reduce) { .hawk-river { animation: none; display: none; } }
      `}</style>
    </div>
  );
}

const VERIFICATION_STAGES = [
  { value: "observed", label: "Observed" },
  { value: "candidate", label: "Candidate" },
  { value: "hypothesis", label: "Hypothesis" },
  { value: "verification", label: "Verification" },
  { value: "verified", label: "Verified" },
  { value: "continuously_validated", label: "Continuously validated" },
] as const;

function outcomeStyle(outcome: VerificationOutcome) {
  if (outcome === "verified") return "border-emerald-300/15 bg-emerald-300/[0.045] text-emerald-100";
  if (outcome === "contradicted" || outcome === "failed") return "border-rose-300/15 bg-rose-300/[0.045] text-rose-100";
  if (outcome === "unsupported") return "border-amber-300/15 bg-amber-300/[0.045] text-amber-100";
  return "border-white/[0.07] bg-white/[0.025] text-slate-300";
}

type VerificationProof = {
  key: string;
  requirementId: string;
  evidenceClass: string;
  method: string;
  required: boolean;
  outcome: VerificationOutcome;
};

function ProofList({ title, items }: { title: string; items: VerificationProof[] }) {
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <p className="font-mono text-[8px] uppercase tracking-[0.16em] text-slate-500">{title}</p>
        <span className="font-mono text-[8px] text-slate-600">{items.length}</span>
      </div>
      <div className="mt-2 space-y-2">
        {items.map((item) => (
          <div key={item.key} className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-2.5 ${outcomeStyle(item.outcome)}`}>
            <div className="min-w-0">
              <p className="truncate text-[11px]">{formatDiscoveryLabel(item.requirementId)}</p>
              <p className="mt-1 truncate font-mono text-[7px] uppercase tracking-wider opacity-50">{formatDiscoveryLabel(item.evidenceClass)} · {formatDiscoveryLabel(item.method)}</p>
            </div>
            <span className="shrink-0 font-mono text-[8px] uppercase tracking-wider">{formatDiscoveryLabel(item.outcome)}</span>
          </div>
        ))}
        {!items.length && <div className="rounded-xl border border-dashed border-white/[0.07] px-3 py-4 text-center text-[10px] text-slate-600">No policy requirement is recorded.</div>}
      </div>
    </div>
  );
}

function verificationIdempotencyKey(action: "start" | "retry", ecosystemId: string) {
  const nonce = typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `adv-ui:${action}:${ecosystemId}:${nonce}`;
}

export default function EvidenceResolvedEcosystemPage() {
  const params = useParams<{ ecosystemId: string }>();
  const ecosystemId = decodeURIComponent(params.ecosystemId);
  const [ecosystem, setEcosystem] = useState<ERGEcosystemDetail | null>(null);
  const [timeline, setTimeline] = useState<ERGTimeline["items"]>([]);
  const [verification, setVerification] = useState<EcosystemVerificationProjection | null>(null);
  const [verificationHistory, setVerificationHistory] = useState<EcosystemVerificationHistory | null>(null);
  const [loading, setLoading] = useState(true);
  const [verificationMutation, setVerificationMutation] = useState<"start" | "retry" | null>(null);
  const [canManageVerification, setCanManageVerification] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [detailResult, timelineResult, verificationResult, verificationHistoryResult] = await Promise.allSettled([
        api.getResolvedEcosystem(ecosystemId),
        api.getResolvedEcosystemTimeline(ecosystemId),
        api.getEcosystemVerification(ecosystemId),
        api.getEcosystemVerificationHistory(ecosystemId),
      ]);
      if (detailResult.status !== "fulfilled") throw detailResult.reason;
      setEcosystem(detailResult.value);
      setTimeline(timelineResult.status === "fulfilled" ? timelineResult.value.items || [] : []);
      setVerification(verificationResult.status === "fulfilled" ? verificationResult.value : null);
      setVerificationHistory(verificationHistoryResult.status === "fulfilled" ? verificationHistoryResult.value : null);
    } catch (error) {
      setEcosystem(null);
      setTimeline([]);
      setVerification(null);
      setVerificationHistory(null);
      toast.error(error instanceof Error ? error.message : "Unable to load evidence resolution");
    } finally {
      setLoading(false);
    }
  }, [ecosystemId]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const updateAuthority = () => {
      const role = String(getSession()?.userRole || "viewer").trim().toLowerCase();
      setCanManageVerification(["owner", "admin"].includes(role));
    };
    updateAuthority();
    window.addEventListener(SESSION_CHANGE_EVENT, updateAuthority);
    return () => window.removeEventListener(SESSION_CHANGE_EVENT, updateAuthority);
  }, []);

  const startVerification = useCallback(async () => {
    if (!verification?.erg_evaluation_id) {
      toast.error("Hawk cannot start verification until an exact ERG evaluation is bound.");
      return;
    }
    setVerificationMutation("start");
    try {
      const plan = await api.startEcosystemVerification(ecosystemId, {
        hypothesis_evaluation_id: verification.erg_evaluation_id,
        environment: verificationHistory?.episodes[0]?.environment || "production",
        trigger: "manual_verification",
        idempotency_key: verificationIdempotencyKey("start", ecosystemId),
      });
      toast.success(`Verification started with ${plan.task_count} bounded proof task${plan.task_count === 1 ? "" : "s"}.`);
      await load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to start verification");
    } finally {
      setVerificationMutation(null);
    }
  }, [ecosystemId, load, verification?.erg_evaluation_id, verificationHistory?.episodes]);

  const retryVerification = useCallback(async () => {
    const episodeId = verificationHistory?.episodes[0]?.episode_id;
    if (!episodeId) {
      toast.error("No verification episode is available to retry.");
      return;
    }
    setVerificationMutation("retry");
    try {
      const plan = await api.retryVerificationEpisode(
        episodeId,
        verificationIdempotencyKey("retry", ecosystemId),
      );
      toast.success(`Verification retry created ${plan.task_count} bounded proof task${plan.task_count === 1 ? "" : "s"}.`);
      await load();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Unable to retry verification");
    } finally {
      setVerificationMutation(null);
    }
  }, [ecosystemId, load, verificationHistory?.episodes]);

  const collectors = useMemo(() => ecosystem ? Array.from(new Set(
    ecosystem.relationships.map((relationship) => text(relationship.collector_id, "Unknown collector")),
  )) : [], [ecosystem]);

  const verificationProof = useMemo<VerificationProof[]>(() => {
    const episodeId = verificationHistory?.episodes[0]?.episode_id;
    if (!episodeId || !verificationHistory) return [];
    const latestResults = new Map<string, EcosystemVerificationHistory["results"][number]>();
    for (const result of verificationHistory.results) {
      if (result.episode_id === episodeId && !latestResults.has(result.requirement_record_id)) {
        latestResults.set(result.requirement_record_id, result);
      }
    }
    const proof = new Map<string, VerificationProof>();
    for (const task of verificationHistory.tasks.filter((item) => item.episode_id === episodeId)) {
      const result = latestResults.get(task.requirement_record_id);
      proof.set(task.requirement_record_id, {
        key: task.requirement_record_id,
        requirementId: task.requirement_id,
        evidenceClass: task.evidence_class,
        method: task.method,
        required: task.required,
        outcome: result?.outcome || "unknown",
      });
    }
    for (const result of latestResults.values()) {
      if (!proof.has(result.requirement_record_id)) {
        proof.set(result.requirement_record_id, {
          key: result.requirement_record_id,
          requirementId: result.requirement_id,
          evidenceClass: result.evidence_class,
          method: result.collector_id || result.source_identity,
          required: result.required,
          outcome: result.outcome,
        });
      }
    }
    return Array.from(proof.values()).sort((left, right) => Number(right.required) - Number(left.required) || left.requirementId.localeCompare(right.requirementId));
  }, [verificationHistory]);

  if (loading) {
    return <AppShell><div className="grid min-h-[70vh] place-items-center"><RefreshCw className="h-6 w-6 animate-spin text-cyan-300" /></div></AppShell>;
  }

  if (!ecosystem) {
    return <AppShell><div className="grid min-h-[70vh] place-items-center px-6 text-center"><div><CircleHelp className="mx-auto h-8 w-8 text-amber-300" /><h1 className="mt-4 text-xl text-white">Ecosystem evidence unavailable</h1><p className="mt-2 text-sm text-slate-500">The ecosystem may be outside this tenant or no longer current.</p><Link href="/discovery/ecosystems" className="mt-5 inline-flex text-xs text-cyan-200">Return to ecosystems</Link></div></div></AppShell>;
  }

  const confidence = number(ecosystem.confidence);
  const quality = number(ecosystem.evidence_quality);
  const contributors = ecosystem.why.contributors || [];
  const heroStats: Array<{ label: string; value: number; Icon: LucideIcon }> = [
    { label: "Evidence contributors", value: contributors.length, Icon: Fingerprint },
    { label: "Current relations", value: ecosystem.relationships.length, Icon: GitBranch },
    { label: "Independent collectors", value: collectors.length, Icon: Radio },
    { label: "Contradictions", value: ecosystem.contradictions.length, Icon: AlertTriangle },
  ];

  return (
    <AppShell>
      <DiscoveryWorkspaceFrame
        eyebrow="Evidence Resolution Graph / AI ecosystem"
        title={ecosystem.canonical_name}
        description="A reversible, evidence-backed resolution—not an application-name match. Every confidence input, contradiction and operator change remains inspectable."
        actions={<div className="flex items-center gap-2"><Link href="/discovery/ecosystems"><Button size="sm" variant="outline" className="border-white/10 bg-white/[0.03] text-slate-300"><ArrowLeft className="mr-2 h-3.5 w-3.5" /> Ecosystems</Button></Link><Button size="sm" variant="outline" onClick={load} className="border-white/10 bg-white/[0.03] text-slate-300"><RefreshCw className="mr-2 h-3.5 w-3.5" /> Refresh</Button></div>}
      >
        <section className="relative overflow-hidden rounded-[32px] border border-white/[0.08] bg-[#09121a] px-6 py-7 shadow-[0_35px_100px_rgba(0,0,0,.32)] lg:px-8">
          <div className="pointer-events-none absolute -right-24 -top-24 h-80 w-80 rounded-full bg-cyan-300/[0.075] blur-[90px]" />
          <div className="pointer-events-none absolute bottom-0 left-1/3 h-40 w-80 rounded-full bg-emerald-300/[0.04] blur-[80px]" />
          <div className="relative grid gap-8 lg:grid-cols-[1fr_auto] lg:items-center">
            <div>
              <div className="flex flex-wrap gap-2">
                <span className="rounded-full border border-cyan-300/15 bg-cyan-300/[0.05] px-3 py-1 font-mono text-[8px] uppercase tracking-[0.16em] text-cyan-100">{formatDiscoveryLabel(ecosystem.ecosystem_class)}</span>
                <span className="rounded-full border border-emerald-300/15 bg-emerald-300/[0.05] px-3 py-1 font-mono text-[8px] uppercase tracking-[0.16em] text-emerald-100">{formatDiscoveryLabel(ecosystem.resolution_state)}</span>
                <span className="rounded-full border border-white/[0.08] bg-white/[0.025] px-3 py-1 font-mono text-[8px] uppercase tracking-[0.16em] text-slate-400">v{ecosystem.methodology_version}</span>
              </div>
              <h2 className="mt-6 max-w-3xl text-2xl font-medium leading-tight tracking-[-0.025em] text-white lg:text-4xl">Why Hawk believes this ecosystem exists</h2>
              <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-400">{ecosystem.why.statement}</p>
              <div className="mt-6 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
                {heroStats.map(({ label, value, Icon }) => (
                  <div key={label} className="rounded-2xl border border-white/[0.06] bg-black/15 p-3">
                    <div className="flex items-center gap-2 text-slate-600"><Icon className="h-3.5 w-3.5" /><span className="font-mono text-[8px] uppercase tracking-wider">{label}</span></div>
                    <p className="mt-2 font-mono text-2xl text-slate-100">{value}</p>
                  </div>
                ))}
              </div>
            </div>
            <div className="flex flex-wrap justify-center gap-5 lg:flex-nowrap"><ConfidenceDial value={confidence} label="Confidence" /><ConfidenceDial value={quality} label="Evidence quality" /></div>
          </div>
        </section>

        <section className="relative mt-5 overflow-hidden rounded-[28px] border border-white/[0.075] bg-[#08141b] p-5 lg:p-6">
          <div className="pointer-events-none absolute -left-20 top-0 h-56 w-56 rounded-full bg-cyan-300/[0.055] blur-[80px]" />
          <div className="relative">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <p className="font-mono text-[9px] uppercase tracking-[0.18em] text-cyan-300/70">Autonomous verification</p>
                <h2 className="mt-2 text-lg text-white">Evidence must earn promotion</h2>
                <p className="mt-2 max-w-2xl text-xs leading-5 text-slate-500">Hawk never turns discovery into truth directly. Required proof, freshness and contradiction checks determine the current lifecycle stage.</p>
              </div>
              <div className="flex flex-wrap items-center justify-end gap-2">
                {canManageVerification && (
                  verificationHistory?.episodes[0] ? (
                    <Button size="sm" variant="outline" onClick={retryVerification} disabled={verificationMutation !== null} className="border-cyan-300/15 bg-cyan-300/[0.045] text-cyan-100 hover:bg-cyan-300/[0.08]">
                      <RefreshCw className={`mr-2 h-3.5 w-3.5 ${verificationMutation === "retry" ? "animate-spin" : ""}`} /> Retry verification
                    </Button>
                  ) : (
                    <Button size="sm" variant="outline" onClick={startVerification} disabled={verificationMutation !== null || !verification?.erg_evaluation_id} title={!verification?.erg_evaluation_id ? "No exact ERG evaluation is bound to this ecosystem" : undefined} className="border-cyan-300/15 bg-cyan-300/[0.045] text-cyan-100 hover:bg-cyan-300/[0.08]">
                      <ScanSearch className="mr-2 h-3.5 w-3.5" /> Start verification
                    </Button>
                  )
                )}
                <div className={`rounded-full border px-3 py-1.5 font-mono text-[8px] uppercase tracking-[0.15em] ${verification?.assertion_current ? "border-emerald-300/15 bg-emerald-300/[0.05] text-emerald-100" : "border-amber-300/15 bg-amber-300/[0.05] text-amber-100"}`}>
                  {verification?.assertion_current ? "Current verified assertion" : "Not yet verified"}
                </div>
              </div>
            </div>

            {verification ? <>
              <div className="mt-6 grid grid-cols-2 gap-2 md:grid-cols-3 xl:grid-cols-6">
                {VERIFICATION_STAGES.map((stage, index) => {
                  const activeIndex = VERIFICATION_STAGES.findIndex((item) => item.value === verification.stage);
                  const passed = index < activeIndex;
                  const active = index === activeIndex;
                  return <div key={stage.value} className={`relative rounded-xl border px-3 py-3 ${active ? "border-cyan-300/25 bg-cyan-300/[0.07]" : passed ? "border-emerald-300/10 bg-emerald-300/[0.025]" : "border-white/[0.055] bg-black/10"}`}>
                    <div className={`mb-2 h-1 w-8 rounded-full ${active ? "bg-cyan-300 shadow-[0_0_12px_rgba(34,211,238,.65)]" : passed ? "bg-emerald-300/60" : "bg-white/10"}`} />
                    <p className={`text-[9px] ${active ? "text-cyan-100" : passed ? "text-emerald-100/70" : "text-slate-600"}`}>{stage.label}</p>
                  </div>;
                })}
              </div>

              <div className="mt-5 grid gap-5 xl:grid-cols-[.72fr_1.28fr]">
                <div className="grid grid-cols-[auto_1fr] gap-5 rounded-2xl border border-white/[0.06] bg-black/15 p-4">
                  <ConfidenceDial value={verification.verification_coverage} label="Verification coverage" />
                  <dl className="space-y-3 self-center text-xs">
                    <div className="border-b border-white/[0.05] pb-3"><dt className="text-slate-600">Current stage</dt><dd className="mt-1 text-slate-200">{formatDiscoveryLabel(verification.stage)}</dd></div>
                    <div className="border-b border-white/[0.05] pb-3"><dt className="text-slate-600">Last validation</dt><dd className="mt-1 font-mono text-[9px] text-slate-300">{verification.last_validation_at ? formatDiscoveryTime(verification.last_validation_at) : "Not evaluated"}</dd></div>
                    <div><dt className="text-slate-600">Next validation</dt><dd className="mt-1 font-mono text-[9px] text-slate-300">{verification.next_validation_at ? formatDiscoveryTime(verification.next_validation_at) : "Not scheduled"}</dd></div>
                  </dl>
                </div>
                <div className="grid gap-4 md:grid-cols-2">
                  <ProofList title="Required proof" items={verificationProof.filter((item) => item.required)} />
                  <ProofList title="Optional evidence" items={verificationProof.filter((item) => !item.required)} />
                </div>
              </div>

              <div className="mt-4 rounded-2xl border border-amber-300/10 bg-amber-300/[0.025] p-4">
                <div className="flex items-center gap-2"><AlertTriangle className="h-3.5 w-3.5 text-amber-200" /><p className="font-mono text-[8px] uppercase tracking-[0.16em] text-amber-200/75">Known verification limits</p></div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {verification.limitations.map((item) => <span key={item} className="rounded-full border border-amber-300/10 px-3 py-1 text-[9px] text-amber-100/65">{formatDiscoveryLabel(item)}</span>)}
                  {!verification.limitations.length && <span className="text-[10px] text-emerald-100/65">No current verification limitation is recorded. Future inaccessible evidence remains outside the claim.</span>}
                </div>
              </div>
            </> : <div className="mt-5 rounded-2xl border border-dashed border-amber-300/15 bg-amber-300/[0.025] px-5 py-8 text-center"><CircleHelp className="mx-auto h-5 w-5 text-amber-200/70" /><p className="mt-3 text-xs text-amber-100/70">Verification evidence is unavailable. Hawk does not treat this ecosystem as verified.</p></div>}
          </div>
        </section>

        <div className="mt-5 grid gap-5 xl:grid-cols-[1.12fr_.88fr]">
          <section className="rounded-[26px] border border-white/[0.07] bg-[#0a131c] p-5">
            <div className="flex items-center justify-between gap-3"><div><p className="font-mono text-[9px] uppercase tracking-[0.18em] text-cyan-300/70">Supporting evidence</p><h2 className="mt-2 text-lg text-white">Evidence contributors</h2></div><ScanSearch className="h-5 w-5 text-cyan-200/70" /></div>
            <div className="mt-4 grid gap-3 md:grid-cols-2">
              {contributors.map((item, index) => {
                const contributorConfidence = number(item.confidence);
                return <article key={text(item.graph_node_id, String(index))} className="relative overflow-hidden rounded-2xl border border-white/[0.055] bg-black/15 p-4">
                  <div className="absolute right-0 top-0 h-16 w-16 rounded-full bg-cyan-300/[0.04] blur-2xl" />
                  <div className="relative flex items-start justify-between gap-3"><div><p className="font-mono text-[8px] uppercase tracking-[0.15em] text-slate-600">{formatDiscoveryLabel(text(item.node_class))}</p><p className="mt-2 break-all text-xs leading-5 text-slate-200">{text(item.subject_reference)}</p></div><span className="font-mono text-xs text-cyan-200">{percent(contributorConfidence)}</span></div>
                  <div className="relative mt-3 flex items-center justify-between border-t border-white/[0.05] pt-3 font-mono text-[8px] text-slate-600"><span>{formatDiscoveryLabel(text(item.verification_state))}</span><span>{text(item.evidence_node_id).slice(0, 10)}</span></div>
                </article>;
              })}
            </div>
            {!contributors.length && <div className="mt-4 rounded-2xl border border-amber-300/10 bg-amber-300/[0.03] p-4 text-xs text-amber-100/70">Supporting contributors are Unknown. Hawk will not promote this ecosystem automatically.</div>}
          </section>

          <section className="rounded-[26px] border border-white/[0.07] bg-[#0a131c] p-5">
            <div className="flex items-center justify-between"><div><p className="font-mono text-[9px] uppercase tracking-[0.18em] text-violet-300/70">Reproducible score</p><h2 className="mt-2 text-lg text-white">Confidence methodology</h2></div><Braces className="h-5 w-5 text-violet-200/70" /></div>
            <div className="mt-5 rounded-2xl border border-violet-300/10 bg-violet-300/[0.025] p-4">
              <p className="font-mono text-[9px] leading-5 text-violet-100/70">Versioned evidence ranking considers current validation, source breadth, required anchors, and unresolved conflicts. Confidence is a ranking band, not an empirical probability.</p>
              <div className="mt-4 grid grid-cols-2 gap-2">
                {["Private scoring protected", "Versioned rule", "Freshness aware", "Conflict review"].map((label) => <div key={label} className="flex items-center gap-2 rounded-xl border border-white/[0.05] bg-black/15 px-3 py-2 text-[10px] text-slate-400"><CheckCircle2 className="h-3 w-3 text-emerald-300" />{label}</div>)}
              </div>
            </div>
            <dl className="mt-4 space-y-3 text-xs">
              <div className="flex items-center justify-between border-b border-white/[0.05] pb-3"><dt className="text-slate-500">Method</dt><dd className="font-mono text-[9px] text-slate-300">{ecosystem.methodology_id}</dd></div>
              <div className="flex items-center justify-between border-b border-white/[0.05] pb-3"><dt className="text-slate-500">Last validation</dt><dd className="font-mono text-[9px] text-slate-300">{formatDiscoveryTime(ecosystem.last_validated_at)}</dd></div>
              <div className="flex items-center justify-between"><dt className="text-slate-500">Capability genome</dt><dd className={`font-mono text-[9px] ${ecosystem.capability_genome_id ? "text-emerald-200" : "text-amber-200"}`}>{ecosystem.capability_genome_id ? ecosystem.capability_genome_id.slice(0, 12) : "Unknown"}</dd></div>
            </dl>
          </section>
        </div>

        <div className="mt-5 grid gap-5 xl:grid-cols-[1.12fr_.88fr]">
          <section><div className="mb-3 flex items-center gap-2"><Clock3 className="h-4 w-4 text-cyan-200" /><h2 className="text-sm font-medium text-white">Evidence timeline</h2><span className="font-mono text-[8px] uppercase tracking-wider text-slate-600">Live resolution river</span></div><EvidenceRiver timeline={timeline} /></section>
          <div className="space-y-5">
            <section className={`rounded-[26px] border p-5 ${ecosystem.contradictions.length ? "border-rose-300/15 bg-rose-300/[0.035]" : "border-emerald-300/10 bg-emerald-300/[0.025]"}`}>
              <div className="flex items-center gap-2">{ecosystem.contradictions.length ? <AlertTriangle className="h-4 w-4 text-rose-300" /> : <ShieldCheck className="h-4 w-4 text-emerald-300" />}<h2 className="text-sm font-medium text-white">Outstanding contradictions</h2></div>
              <div className="mt-4 space-y-2">{ecosystem.contradictions.length ? ecosystem.contradictions.map((item, index) => <div key={text(item.edge_id, String(index))} className="rounded-xl border border-rose-300/10 bg-black/10 p-3"><p className="text-xs text-rose-100/80">{formatDiscoveryLabel(text(item.type))}</p><p className="mt-1 font-mono text-[8px] text-rose-200/50">{text(item.state)} · {text(item.edge_id).slice(0, 12)}</p></div>) : <p className="text-xs leading-5 text-emerald-100/70">No current edge contains a confirmed, possible, or unknown contradiction. This is not proof that inaccessible sources agree.</p>}</div>
            </section>
            <section className="rounded-[26px] border border-white/[0.07] bg-[#0a131c] p-5"><div className="flex items-center gap-2"><Sparkles className="h-4 w-4 text-amber-200" /><h2 className="text-sm font-medium text-white">Recommended actions</h2></div><div className="mt-4 space-y-2">{ecosystem.recommended_actions.map((action) => <div key={action} className="flex gap-3 rounded-xl border border-white/[0.055] bg-black/10 p-3 text-xs leading-5 text-slate-300"><ArrowRight className="mt-1 h-3 w-3 shrink-0 text-amber-200" />{action}</div>)}</div></section>
            <section className="rounded-[26px] border border-white/[0.07] bg-[#0a131c] p-5"><div className="flex items-center gap-2"><Radio className="h-4 w-4 text-cyan-200" /><h2 className="text-sm font-medium text-white">Collectors</h2></div><div className="mt-4 flex flex-wrap gap-2">{collectors.map((collector) => <span key={collector} className="rounded-full border border-cyan-300/10 bg-cyan-300/[0.035] px-3 py-1 font-mono text-[8px] text-cyan-100/70">{collector}</span>)}{!collectors.length && <span className="text-xs text-amber-200/70">Unknown</span>}</div></section>
          </div>
        </div>

        <details className="group mt-5 rounded-[26px] border border-white/[0.07] bg-[#09121a]">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-4"><div className="flex items-center gap-3"><Network className="h-4 w-4 text-slate-400" /><div><p className="text-sm text-white">Advanced graph drill-down</p><p className="mt-1 text-[10px] text-slate-600">Exact nodes, edges, rules, confidence bands, freshness, validation and evidence references</p></div></div><GitBranch className="h-4 w-4 text-slate-600 transition group-open:rotate-90" /></summary>
          <div className="border-t border-white/[0.06] p-5">
            <div className="overflow-x-auto"><table className="w-full min-w-[900px] text-left text-[10px]"><thead className="font-mono uppercase tracking-wider text-slate-600"><tr>{["Relationship", "Nodes", "Confidence", "Evidence state", "Freshness", "Rule", "Collector", "Evidence"].map((label) => <th key={label} className="border-b border-white/[0.06] px-3 py-3 font-normal">{label}</th>)}</tr></thead><tbody>{ecosystem.relationships.map((item, index) => <tr key={text(item.edge_id, String(index))} className="border-b border-white/[0.04] text-slate-400"><td className="px-3 py-3 text-slate-200">{formatDiscoveryLabel(text(item.edge_type))}</td><td className="max-w-[220px] px-3 py-3 font-mono text-[8px]">{text(item.from_node_id).slice(0, 8)} → {text(item.to_node_id).slice(0, 8)}</td><td className="px-3 py-3 font-mono">{formatDiscoveryLabel(text(item.confidence_band))} · {percent(number(item.confidence))}</td><td className="px-3 py-3">{formatDiscoveryLabel(text(item.evidence_state))}</td><td className="px-3 py-3">{formatDiscoveryLabel(text(item.freshness))}</td><td className="px-3 py-3 font-mono text-[8px]">{text(item.rule_id)}@{text(item.rule_version)}</td><td className="px-3 py-3 font-mono text-[8px]">{text(item.collector_id)}</td><td className="px-3 py-3 font-mono text-[8px]">{text(item.evidence_node_id).slice(0, 12)}</td></tr>)}</tbody></table></div>
            {!ecosystem.relationships.length && <p className="py-8 text-center text-xs text-slate-600">No current relationship edges are available.</p>}
          </div>
        </details>

        {ecosystem.limitations.length > 0 && <section className="mt-5 rounded-2xl border border-amber-300/10 bg-amber-300/[0.025] p-4"><p className="font-mono text-[8px] uppercase tracking-[0.16em] text-amber-200/70">Known limitations</p><div className="mt-3 flex flex-wrap gap-2">{ecosystem.limitations.map((limitation) => <span key={limitation} className="rounded-full border border-amber-300/10 px-3 py-1 text-[10px] text-amber-100/65">{formatDiscoveryLabel(limitation)}</span>)}</div></section>}
      </DiscoveryWorkspaceFrame>
    </AppShell>
  );
}
