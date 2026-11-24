"use client";

import { useParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, Database, Eye, Fingerprint, History, KeyRound, Network, RefreshCw, Settings2, ShieldAlert, ShieldCheck, UserRoundCog } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { DiscoveryAssetDetail, DiscoveryAssetEvidence, DiscoveryAssetHistory } from "@/lib/types";
import { AssetExposureIntelligence } from "./asset-exposure-intelligence";
import {
  confidenceLabel,
  DiscoveryEmpty,
  DiscoveryWorkspaceFrame,
  formatDiscoveryLabel,
  formatDiscoveryTime,
  TruthBadge,
} from "./discovery-workspace-frame";

function EvidenceRef({ value }: { value: string }) {
  return <span className="break-all font-mono text-[9px] text-cyan-200/70">{value}</span>;
}

function Section({ title, note, icon: Icon, children }: { title: string; note: string; icon: typeof Activity; children: React.ReactNode }) {
  return (
    <section className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4">
      <div className="flex items-start justify-between gap-3 border-b border-white/[0.06] pb-3">
        <div><h2 className="text-sm font-semibold text-white">{title}</h2><p className="mt-1 text-[11px] text-slate-500">{note}</p></div>
        <Icon className="h-4 w-4 text-cyan-300/70" />
      </div>
      <div className="mt-3">{children}</div>
    </section>
  );
}

export function DiscoveryAssetDetailView() {
  const params = useParams<{ id: string }>();
  const assetId = decodeURIComponent(String(params?.id || ""));
  const [detail, setDetail] = useState<DiscoveryAssetDetail | null>(null);
  const [evidence, setEvidence] = useState<DiscoveryAssetEvidence[]>([]);
  const [history, setHistory] = useState<DiscoveryAssetHistory[]>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!assetId) return;
    setLoading(true);
    try {
      const [assetDetail, evidenceList, historyList] = await Promise.all([
        api.getDiscoveryAsset(assetId),
        api.getDiscoveryAssetEvidence(assetId, 50),
        api.getDiscoveryAssetHistory(assetId, 1, 50),
      ]);
      setDetail(assetDetail);
      setEvidence(evidenceList.items);
      setHistory(historyList.items);
    } catch (error) {
      setDetail(null);
      setEvidence([]);
      setHistory([]);
      toast.error(error instanceof Error ? error.message : "Unable to load AI asset intelligence");
    } finally {
      setLoading(false);
    }
  }, [assetId]);

  useEffect(() => { load(); }, [load]);

  const evidenceCount = useMemo(() => {
    if (!detail) return 0;
    return new Set([
      ...detail.usage.map((item) => item.evidence_node_id),
      ...detail.capabilities.map((item) => item.evidence_claim_id),
      ...detail.reachability.map((item) => item.evidence_node_id),
      ...detail.identities.map((item) => item.evidence_node_id),
      ...detail.ownership.map((item) => item.evidence_node_id),
      ...detail.findings.flatMap((item) => item.evidence_node_ids),
      ...evidence.map((item) => item.evidence_hash),
    ]).size;
  }, [detail, evidence]);

  if (loading) {
    return <div className="grid min-h-[70vh] place-items-center rounded-[28px] border border-white/[0.06] bg-[#080d13]"><RefreshCw className="h-5 w-5 animate-spin text-cyan-300" /></div>;
  }
  if (!detail) {
    return (
      <DiscoveryWorkspaceFrame eyebrow="AI Asset Intelligence" title="Asset unavailable" description="The asset was not found in the active tenant or its evidence is no longer accessible." backHref="/discovery/assets" backLabel="Asset inventory">
        <DiscoveryEmpty title="No tenant-safe asset record" detail="Hawk does not expose cross-tenant asset existence." />
      </DiscoveryWorkspaceFrame>
    );
  }

  const asset = detail.asset;
  return (
    <DiscoveryWorkspaceFrame
      eyebrow={`${formatDiscoveryLabel(asset.asset_type)} · Evidence profile`}
      title={asset.canonical_name}
      description={`${formatDiscoveryLabel(asset.provider)} · ${formatDiscoveryLabel(asset.environment)} · first observed ${formatDiscoveryTime(asset.first_seen_at)}`}
      backHref="/discovery/assets"
      backLabel="Asset inventory"
      actions={<Button size="sm" variant="outline" onClick={load} className="border-white/10 bg-white/[0.03] text-slate-200 hover:bg-white/[0.07]"><RefreshCw className="mr-2 h-3.5 w-3.5" /> Refresh evidence</Button>}
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {[
          ["Resolution", confidenceLabel(asset.resolution_confidence), asset.resolution_state],
          ["Usage", formatDiscoveryLabel(asset.usage_state), asset.usage_verification_state],
          ["Capabilities", asset.capabilities_count, "declared/inferred shown below"],
          ["Evidence refs", evidenceCount, "deduplicated references"],
          ["Open findings", asset.findings_open, asset.shadow_type || "No shadow classification"],
        ].map(([label, value, note]) => (
          <div key={String(label)} className="rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4">
            <p className="font-mono text-[9px] uppercase tracking-[0.17em] text-slate-600">{label}</p>
            <p className="mt-2 font-mono text-xl text-white">{value}</p>
            <p className="mt-1 truncate text-[10px] text-slate-500">{formatDiscoveryLabel(String(note))}</p>
          </div>
        ))}
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-2">
        <Section title="Overview" note="Canonical identity and governance state from the existing asset authority." icon={Eye}>
          <div className="grid gap-2 text-[11px] sm:grid-cols-2">{[["Asset type", asset.asset_type], ["Provider", asset.provider], ["Environment", asset.environment], ["Approval", asset.approved_status], ["Lifecycle", asset.lifecycle_status], ["Shadow AI", asset.shadow_ai_status], ["First seen", formatDiscoveryTime(asset.first_seen_at)], ["Last seen", formatDiscoveryTime(asset.last_seen_at)]].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-white/[0.05] bg-white/[0.02] p-2"><p className="font-mono text-[8px] uppercase text-slate-600">{label}</p><p className="mt-1 text-slate-300">{formatDiscoveryLabel(String(value || "unknown"))}</p></div>)}</div>
        </Section>
        <Section title="Configuration" note="Observed product metadata; unknown fields are not inferred." icon={Settings2}>
          <div className="grid gap-2 text-[11px] sm:grid-cols-2">{[["Product", asset.product], ["Framework", asset.framework], ["Version", asset.version], ["Deployment family", asset.deployment_family], ["Technical surface", asset.technical_surface], ["Resolution method", asset.resolution_methodology_id]].map(([label, value]) => <div key={String(label)} className="rounded-lg border border-white/[0.05] bg-white/[0.02] p-2"><p className="font-mono text-[8px] uppercase text-slate-600">{label}</p><p className="mt-1 break-all text-slate-300">{formatDiscoveryLabel(String(value || "unknown"))}</p></div>)}</div>
        </Section>
      </div>

      <div className="mt-4">
        <Section title="Discovery Evidence" note="Bounded observation metadata, provenance, freshness, confidence, and conflicts." icon={Fingerprint}>
          {!evidence.length ? <DiscoveryEmpty title="Discovery evidence unavailable" detail="No tenant-safe observation is attached; absence is not proof that the asset is inactive." /> : <div className="grid gap-2 xl:grid-cols-2">{evidence.map((item) => <div key={`${item.observation_id}-${item.link_sequence}`} className="rounded-xl border border-white/[0.06] bg-white/[0.025] p-3"><div className="flex items-start justify-between gap-2"><div><p className="text-xs text-slate-200">{formatDiscoveryLabel(item.observation_type)}</p><p className="mt-1 text-[9px] text-slate-600">{formatDiscoveryLabel(item.source_surface)} · {formatDiscoveryTime(item.observed_at)}</p></div><TruthBadge value={item.verification_state} /></div><p className="mt-2 text-[10px] text-slate-500">{confidenceLabel(item.confidence)} · {formatDiscoveryLabel(item.freshness)} · signature {formatDiscoveryLabel(item.signature_status)} · {formatDiscoveryLabel(item.evidence_mode)}</p><p className="mt-2"><EvidenceRef value={item.evidence_reference} /></p>{item.contradiction_state !== "none" ? <p className="mt-2 text-[10px] text-amber-200/70">Conflict: {formatDiscoveryLabel(item.contradiction_state)}</p> : null}</div>)}</div>}
        </Section>
      </div>

      <AssetExposureIntelligence assetId={assetId} />

      <div className="mt-5 grid gap-4 xl:grid-cols-2">
        <Section title="Usage" note="Observed usage telemetry remains separate from configuration and access." icon={Activity}>
          {!detail.usage.length ? <DiscoveryEmpty title="Usage unknown" detail="No supported usage telemetry is attached to this asset." /> : <div className="space-y-2">{detail.usage.map((item) => (
            <div key={item.usage_fact_id} className="rounded-xl border border-white/[0.06] bg-white/[0.025] p-3">
              <div className="flex flex-wrap items-center justify-between gap-2"><div className="flex items-center gap-2"><TruthBadge value={item.usage_state} /><span className="text-xs text-slate-300">{formatDiscoveryLabel(item.actor_type)}</span></div><span className="font-mono text-[10px] text-slate-500">{item.event_count} events · {confidenceLabel(item.confidence)}</span></div>
              <div className="mt-2 grid gap-1 text-[10px] text-slate-500 sm:grid-cols-2"><span>Last seen: {formatDiscoveryTime(item.last_observed_at)}</span><span>Source: {formatDiscoveryLabel(item.source_surface)}</span><span>Telemetry complete: {item.telemetry_complete ? "Yes" : "No"}</span><span>Freshness: {formatDiscoveryLabel(item.freshness)}</span></div>
              {item.limitations.length ? <p className="mt-2 text-[10px] leading-4 text-amber-200/70">Limitations: {item.limitations.join(" · ")}</p> : null}
              <p className="mt-2"><EvidenceRef value={item.evidence_node_id} /></p>
            </div>
          ))}</div>}
        </Section>

        <Section title="Capabilities" note="Observed, declared-only, and inferred-only states are explicit." icon={Database}>
          {!detail.capabilities.length ? <DiscoveryEmpty title="Capabilities unknown" detail="No evidence-backed capability assertion is available." /> : <div className="space-y-2">{detail.capabilities.map((item) => (
            <div key={item.capability_id} className="flex flex-col gap-2 rounded-xl border border-white/[0.06] bg-white/[0.025] p-3 sm:flex-row sm:items-start sm:justify-between">
              <div><p className="text-xs font-medium text-slate-200">{formatDiscoveryLabel(item.name)}</p><p className="mt-1 font-mono text-[9px] uppercase text-slate-600">{formatDiscoveryLabel(item.state)} · {formatDiscoveryLabel(item.verification_state)} · {confidenceLabel(item.confidence)}</p><p className="mt-2"><EvidenceRef value={item.evidence_claim_id} /></p></div>
              <div className="flex flex-wrap gap-1">{item.observed_usage && <TruthBadge value="observed" />}{item.declared_only && <TruthBadge value="declared_only" />}{item.inferred_only && <TruthBadge value="inferred_only" />}</div>
            </div>
          ))}</div>}
        </Section>

        <Section title="Reachability" note="Configured, observed, potential, verified and unknown paths are not collapsed." icon={Network}>
          {!detail.reachability.length ? <DiscoveryEmpty title="Reachability unknown" detail="No supported destination relationship can be asserted." /> : <div className="space-y-2">{detail.reachability.map((item) => (
            <div key={item.reachability_id} className="rounded-xl border border-white/[0.06] bg-white/[0.025] p-3">
              <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-xs text-slate-200">{formatDiscoveryLabel(item.target_category)}</span><TruthBadge value={item.state} /></div>
              <p className="mt-2 break-all font-mono text-[9px] text-slate-600">Target {item.target_reference_hash}</p>
              <p className="mt-1 font-mono text-[9px] text-slate-500">{confidenceLabel(item.confidence)} · {formatDiscoveryLabel(item.verification_state)} · observed use {item.observed_usage ? "yes" : "not proven"}</p>
              {item.limitations.length ? <p className="mt-2 text-[10px] text-amber-200/70">Limitations: {item.limitations.join(" · ")}</p> : null}
              <p className="mt-2"><EvidenceRef value={item.evidence_node_id} /></p>
            </div>
          ))}</div>}
        </Section>

        <Section title="Users and identities" note="Access does not imply usage; ownership is shown separately and unknown stays unknown." icon={UserRoundCog}>
          {!detail.identities.length && !detail.ownership.length ? <DiscoveryEmpty title="Attribution incomplete" detail="No tenant-safe identity or owner assertion is available." /> : <div className="space-y-2">
            {detail.identities.map((item) => <div key={item.identity_link_id} className="rounded-xl border border-white/[0.06] bg-white/[0.025] p-3"><div className="flex items-center justify-between gap-2"><span className="flex items-center gap-2 text-xs text-slate-200"><Fingerprint className="h-3.5 w-3.5 text-cyan-300" />{formatDiscoveryLabel(item.identity_type)}</span><TruthBadge value={item.access_state} /></div><p className="mt-2 font-mono text-[9px] text-slate-500">Usage proven: {item.usage_proven ? "Yes" : "No"} · {confidenceLabel(item.confidence)}</p><p className="mt-2"><EvidenceRef value={item.evidence_node_id} /></p></div>)}
            {detail.ownership.map((item) => <div key={item.ownership_assertion_id} className="rounded-xl border border-white/[0.06] bg-white/[0.025] p-3"><div className="flex items-center justify-between gap-2"><span className="flex items-center gap-2 text-xs text-slate-200"><KeyRound className="h-3.5 w-3.5 text-violet-300" />{formatDiscoveryLabel(item.owner_type)}</span><TruthBadge value={item.state} /></div><p className="mt-2 font-mono text-[9px] text-slate-500">{item.owner_reference_hash || "Owner reference unknown"} · {confidenceLabel(item.confidence)}</p><p className="mt-2"><EvidenceRef value={item.evidence_node_id} /></p></div>)}
          </div>}
        </Section>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Section title="Actions" note="Only evidence-backed observed-use capabilities are shown as action classes." icon={Activity}>
          {!detail.capabilities.some((item) => item.observed_usage) ? <DiscoveryEmpty title="Actions unknown" detail="Configured or inferred capability is not represented as an executed action." /> : <div className="space-y-2">{detail.capabilities.filter((item) => item.observed_usage).map((item) => <div key={item.capability_id} className="rounded-lg border border-white/[0.05] bg-white/[0.02] p-2"><div className="flex items-center justify-between gap-2"><span className="text-[11px] text-slate-200">{formatDiscoveryLabel(item.name)}</span><TruthBadge value={item.verification_state} /></div><p className="mt-1"><EvidenceRef value={item.evidence_claim_id} /></p></div>)}</div>}
        </Section>
        <Section title="Control Coverage" note="The existing coverage/exposure authority above remains authoritative; no second score is created." icon={ShieldCheck}>
          {detail.findings.some((item) => item.coverage_impact) ? <div className="space-y-2">{detail.findings.map((item) => <div key={item.finding_id} className="rounded-lg border border-white/[0.05] bg-white/[0.02] p-2"><p className="text-[10px] text-slate-300">{formatDiscoveryLabel(item.finding_type)}</p><p className="mt-1 text-[10px] text-amber-200/70">{item.coverage_impact}</p></div>)}</div> : <DiscoveryEmpty title="Coverage unknown" detail="No asset-specific authoritative coverage path is available. No percentage or gap-free claim is shown." />}
        </Section>
        <Section title="History" note="Append-only resolution and reversal events preserve prior evidence." icon={History}>
          {!history.length ? <DiscoveryEmpty title="No history event" detail="No accepted resolution transition is recorded for this asset." /> : <div className="space-y-2">{history.map((item) => <div key={`${item.history_event_id}-${item.member_ordinal}`} className="rounded-lg border border-white/[0.05] bg-white/[0.02] p-2"><div className="flex items-center justify-between gap-2"><span className="text-[10px] text-slate-200">{formatDiscoveryLabel(item.event_type)}</span><span className="font-mono text-[8px] text-slate-600">{formatDiscoveryTime(item.created_at)}</span></div><p className="mt-1 text-[9px] text-slate-500">{item.reason} · actor {formatDiscoveryLabel(item.actor_role)}</p><p className="mt-1"><EvidenceRef value={item.evidence_claim_id} /></p></div>)}</div>}
        </Section>
      </div>

      <section className="mt-4 rounded-2xl border border-white/[0.07] bg-[#0d151e] p-4">
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-3"><div><h2 className="text-sm font-semibold text-white">Findings & Shadow AI</h2><p className="mt-1 text-[11px] text-slate-500">Every item carries evidence, verification action, and coverage impact.</p></div><ShieldAlert className="h-4 w-4 text-rose-300" /></div>
        {!detail.findings.length && !detail.shadow_classifications.length ? <div className="mt-3"><DiscoveryEmpty title="No evidence-backed finding" detail="This is not proof that risk or shadow activity is absent." /></div> : <div className="mt-3 grid gap-3 lg:grid-cols-2">
          {detail.shadow_classifications.map((item) => <div key={item.classification_id} className="rounded-xl border border-amber-300/10 bg-amber-300/[0.025] p-3"><div className="flex flex-wrap items-center justify-between gap-2"><span className="text-xs font-medium text-slate-200">{formatDiscoveryLabel(item.shadow_type)}</span><TruthBadge value={item.management_class} /></div><p className="mt-2 text-[10px] text-slate-500">{formatDiscoveryLabel(item.verification_state)} · {confidenceLabel(item.confidence)} · {item.methodology_id}</p>{item.limitations.length ? <p className="mt-2 text-[10px] text-amber-200/70">Limitations: {item.limitations.join(" · ")}</p> : null}</div>)}
          {detail.findings.map((item) => <div key={item.finding_id} className="rounded-xl border border-rose-300/10 bg-rose-300/[0.025] p-3"><div className="flex flex-wrap items-center justify-between gap-2"><span className="text-xs font-medium text-slate-200">{formatDiscoveryLabel(item.finding_type)}</span><TruthBadge value={item.severity} /></div><p className="mt-2 text-[10px] leading-4 text-slate-400">{item.remediation}</p><p className="mt-2 text-[10px] text-cyan-200/70">Verify: {item.verification_action}</p><p className="mt-1 text-[10px] text-amber-200/70">Coverage: {item.coverage_impact}</p><div className="mt-2 space-y-1">{item.evidence_node_ids.map((ref) => <div key={ref}><EvidenceRef value={ref} /></div>)}</div></div>)}
        </div>}
      </section>
    </DiscoveryWorkspaceFrame>
  );
}
