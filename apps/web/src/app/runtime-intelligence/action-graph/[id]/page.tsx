"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
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
import type { RuntimeActionGraph } from "@/lib/types";

function nodeTone(nodeType: string) {
  const normalized = nodeType.toLowerCase();
  if (normalized.includes("finding")) return "border-rose-500/40 bg-rose-500/20 text-rose-200";
  if (normalized.includes("policy")) return "border-amber-500/40 bg-amber-500/20 text-amber-200";
  if (normalized.includes("evidence")) return "border-emerald-500/40 bg-emerald-500/20 text-emerald-200";
  if (normalized.includes("authority")) return "border-blue-500/40 bg-blue-500/20 text-blue-200";
  return "border-slate-500/40 bg-slate-500/20 text-slate-200";
}

function shortId(value: unknown): string {
  const text = String(value || "").trim();
  if (text.length <= 24) return text || "-";
  return `${text.slice(0, 11)}...${text.slice(-9)}`;
}

export default function RuntimeActionGraphPage() {
  const params = useParams<{ id: string }>();
  const actionId = decodeURIComponent(String(params.id || ""));
  const [graph, setGraph] = useState<RuntimeActionGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      if (!actionId) return;
      setLoading(true);
      setError(null);
      try {
        const payload = await api.runtimeActionGraph(actionId);
        if (!cancelled) setGraph(payload);
      } catch (err) {
        const message = err instanceof Error ? err.message : "Unable to load action graph";
        if (!cancelled) {
          setGraph(null);
          setError(message);
          toast.error(message);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load().catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [actionId]);

  const nodeTypeCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    (graph?.nodes || []).forEach((node) => {
      counts[node.node_type] = (counts[node.node_type] || 0) + 1;
    });
    return counts;
  }, [graph]);

  const relationshipCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    (graph?.edges || []).forEach((edge) => {
      counts[edge.relationship_type] = (counts[edge.relationship_type] || 0) + 1;
    });
    return counts;
  }, [graph]);

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Runtime Intelligence"
          title="AI Action Graph"
          description="Relationship-backed view of one AI action across authority, policy, evidence, and findings."
          actions={
            <>
              <RuntimeIntelligenceTabs />
              <Button asChild variant="outline">
                <Link href={`/runtime-intelligence/action-trace/${encodeURIComponent(actionId)}`}>Open Trace</Link>
              </Button>
            </>
          }
        />

        {error ? (
          <div className="rounded-lg border border-rose-900/50 bg-rose-950/25 px-4 py-3 text-sm text-rose-200">{error}</div>
        ) : null}

        <KpiStrip
          items={[
            { label: "Action", value: shortId(graph?.action_id || actionId), hint: "Canonical action id", tone: "info" },
            { label: "Runtime Event", value: shortId(graph?.runtime_event_id), hint: "Observed source event", tone: "default" },
            { label: "Nodes", value: graph?.nodes.length ?? 0, hint: loading ? "Loading..." : "Graph entities", tone: "info" },
            { label: "Edges", value: graph?.total_edges ?? 0, hint: "Relationships", tone: (graph?.total_edges || 0) ? "success" : "warning" },
            { label: "AI System", value: shortId(graph?.ai_system_id), hint: "Linked AI asset", tone: graph?.ai_system_id ? "success" : "default" },
          ]}
        />

        <div className="grid gap-4 xl:grid-cols-2">
          <PageSection title="Node Types" description="Entities linked into the action graph.">
            <SimpleTable
              columns={["Type", "Count"]}
              rows={Object.entries(nodeTypeCounts).map(([type, count]) => [
                <Badge key={type} className={nodeTone(type)}>{type}</Badge>,
                count,
              ])}
              emptyLabel="No nodes linked"
            />
          </PageSection>

          <PageSection title="Relationship Types" description="How the action relates to authority, policy, evidence, and findings.">
            <SimpleTable
              columns={["Relationship", "Count"]}
              rows={Object.entries(relationshipCounts).map(([relationship, count]) => [relationship, count])}
              emptyLabel="No relationships linked"
            />
          </PageSection>
        </div>

        <PageSection title="Nodes" description="Graph nodes for this action.">
          <SimpleTable
            columns={["Type", "ID", "Label"]}
            rows={(graph?.nodes || []).map((node) => [
              <Badge key={`${node.node_type}:${node.node_id}`} className={nodeTone(node.node_type)}>{node.node_type}</Badge>,
              node.node_id,
              node.label || "-",
            ])}
            emptyLabel="No nodes linked"
            initialVisibleRows={12}
          />
        </PageSection>

        <PageSection title="Edges" description="Relationship evidence created from runtime normalization.">
          <SimpleTable
            columns={["Relationship", "Source", "Target", "Event", "Created"]}
            rows={(graph?.edges || []).map((edge) => [
              edge.relationship_type,
              `${edge.source_node_type}:${edge.source_node_id}`,
              `${edge.target_node_type}:${edge.target_node_id}`,
              edge.event_id || "-",
              formatDateTime(edge.created_at),
            ])}
            emptyLabel="No edges linked"
            initialVisibleRows={12}
          />
        </PageSection>
      </div>
    </AppShell>
  );
}
