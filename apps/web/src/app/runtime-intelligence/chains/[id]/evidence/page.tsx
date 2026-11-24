"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { PageHeader } from "@/components/page-header";
import { PageSection } from "@/components/page-section";
import { RuntimeIntelligenceTabs } from "@/components/runtime-intelligence/module-tabs";
import { formatDateTime } from "@/components/runtime-intelligence/utils";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { RuntimeAgenticChainEvidence } from "@/lib/types";

function compactPayload(payload: Record<string, unknown>): string {
  const serialized = JSON.stringify(payload || {});
  return serialized.length > 240 ? `${serialized.slice(0, 237)}…` : serialized;
}

export default function RuntimeChainEvidencePage() {
  const params = useParams<{ id: string }>();
  const chainId = decodeURIComponent(String(params.id || "")).trim();
  const [evidence, setEvidence] = useState<RuntimeAgenticChainEvidence | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError("");
    api.runtimeAgenticChainEvidence(chainId)
      .then((payload) => {
        if (!cancelled) setEvidence(payload);
      })
      .catch((err) => {
        if (cancelled) return;
        const message = err instanceof Error ? err.message : "Unable to load chain evidence";
        setEvidence(null);
        setError(message);
        toast.error(message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [chainId]);

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="Chain Evidence"
          description="Evidence-backed proof attached to one observed runtime chain. Missing proof remains visibly unavailable."
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button asChild variant="outline">
                <Link href={`/runtime-intelligence/chains/${encodeURIComponent(chainId)}/graph`}>Open Activity Map</Link>
              </Button>
            </>
          }
        />

        {error ? (
          <div className="rounded-lg border border-rose-900/50 bg-rose-950/25 px-4 py-3 text-sm text-rose-200">{error}</div>
        ) : null}

        <KpiStrip
          items={[
            { label: "Chain", value: evidence?.chain_id || chainId || "Unknown", hint: "Requested runtime chain", tone: evidence ? "info" : "default" },
            { label: "Evidence bundles", value: evidence?.evidence_bundle_ids.length ?? 0, hint: loading ? "Loading…" : "Linked proof bundles", tone: evidence?.evidence_bundle_ids.length ? "success" : "warning" },
            { label: "Evidence nodes", value: evidence?.evidence.length ?? 0, hint: "Verifiable chain observations", tone: evidence?.evidence.length ? "success" : "warning" },
          ]}
        />

        <PageSection title="Evidence bundles" description="Canonical evidence bundle identifiers linked to this chain.">
          <div className="flex flex-wrap gap-2">
            {(evidence?.evidence_bundle_ids || []).map((bundleId) => (
              <Badge key={bundleId} className="border-emerald-500/40 bg-emerald-950/25 font-mono text-emerald-200">
                {bundleId}
              </Badge>
            ))}
            {!loading && !evidence?.evidence_bundle_ids.length ? (
              <span className="text-sm text-amber-200">No evidence bundle is available for this chain.</span>
            ) : null}
          </div>
        </PageSection>

        <PageSection title="Evidence nodes" description="Only evidence returned by Hawk is shown; absent values are not inferred.">
          <SimpleTable
            columns={["Type", "Signal", "Label", "Created", "Payload"]}
            rows={(evidence?.evidence || []).map((node) => [
              node.node_type,
              node.signal_type,
              node.label,
              formatDateTime(node.created_at),
              <span key={node.id} className="break-all font-mono text-[11px] text-slate-300">{compactPayload(node.payload)}</span>,
            ])}
            emptyLabel={loading ? "Loading chain evidence…" : "No evidence nodes found"}
            initialVisibleRows={12}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
