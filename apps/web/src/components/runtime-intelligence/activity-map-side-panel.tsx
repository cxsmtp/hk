"use client";

import Link from "next/link";
import { useState } from "react";

import { DecisionExplanationModal } from "@/components/decision-explanation";
import type {
  ActivityMapEdgeDetail,
  ActivityMapNodeDetail,
} from "@/components/runtime-intelligence/activity-map-graph";
import { decisionBadgeClass, decisionLabel, formatDateTime } from "@/components/runtime-intelligence/utils";
import { Badge } from "@/components/ui/badge";

function scoreLabel(score: number): string {
  if (score >= 0.67) return "High";
  if (score >= 0.34) return "Medium";
  return "Low";
}

export function RuntimeActivityMapSidePanel({
  nodeDetail,
  edgeDetail,
}: {
  nodeDetail: ActivityMapNodeDetail | null;
  edgeDetail: ActivityMapEdgeDetail | null;
}) {
  const [modalEvidenceId, setModalEvidenceId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  function openDecisionExplanation(evidenceId: string) {
    setModalEvidenceId(evidenceId);
    setModalOpen(true);
  }

  if (!nodeDetail && !edgeDetail) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-6 text-sm text-slate-400">
        Select a node or edge in the map to inspect risk, policy context, and action evidence.
      </div>
    );
  }

  if (edgeDetail) {
    return (
      <>
        <div className="space-y-4 rounded-lg border border-[#2a3348] bg-[#101524] p-4">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Edge Detail</p>
            <p className="mt-1 text-lg font-semibold text-slate-100">{edgeDetail.relationType}</p>
          </div>

          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3 text-sm text-slate-300">
            <p className="text-xs text-slate-500">From</p>
            <p>{edgeDetail.fromNodeLabel}</p>
            <p className="mt-2 text-xs text-slate-500">To</p>
            <p>{edgeDetail.toNodeLabel}</p>
          </div>

          <div className="space-y-2 rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
            <p className="text-xs text-slate-500">Decision</p>
            <Badge className={decisionBadgeClass(edgeDetail.decision)}>{decisionLabel(edgeDetail.decision)}</Badge>
            <p className="pt-2 text-xs text-slate-500">Action Details</p>
            <p className="text-sm text-slate-200">{edgeDetail.actionDetails}</p>
          </div>

          <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
            <p className="mb-2 text-xs text-slate-500">Evidence Links</p>
            {edgeDetail.evidenceNodeIds.length ? (
              <div className="space-y-2">
                {edgeDetail.evidenceNodeIds.slice(0, 8).map((evidenceId) => (
                  <div key={evidenceId} className="flex items-center gap-2">
                    <Link
                      href={`/auditor?evidence_id=${encodeURIComponent(evidenceId)}`}
                      className="flex-1 rounded border border-[#2a3348] px-2 py-1 text-xs text-brand-200 hover:border-brand-500/40 hover:bg-brand-500/10"
                    >
                      {`Open evidence ${evidenceId.slice(0, 10)}...`}
                    </Link>
                    <button
                      type="button"
                      className="rounded border border-[#2a3348] px-2 py-1 text-xs text-slate-300 hover:border-brand-500/40 hover:text-brand-200"
                      onClick={() => openDecisionExplanation(evidenceId)}
                    >
                      Explain
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500">No evidence IDs linked to this edge.</p>
            )}
          </div>

          {edgeDetail.linkedEvent ? (
            <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3 text-xs text-slate-400">
              <p>{`Event: ${edgeDetail.linkedEvent.event_id}`}</p>
              <p>{`Source: ${edgeDetail.linkedEvent.source_surface}`}</p>
              <p>{`Time: ${formatDateTime(edgeDetail.linkedEvent.created_at)}`}</p>
            </div>
          ) : null}
        </div>
        <DecisionExplanationModal
          open={modalOpen}
          evidenceId={modalEvidenceId}
          onOpenChange={(open) => {
            setModalOpen(open);
            if (!open) setModalEvidenceId(null);
          }}
        />
      </>
    );
  }

  if (!nodeDetail) return null;

  return (
    <>
      <div className="space-y-4 rounded-lg border border-[#2a3348] bg-[#101524] p-4">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Node Detail</p>
          <p className="mt-1 text-lg font-semibold text-slate-100">{nodeDetail.entityId || nodeDetail.id}</p>
          <p className="text-xs text-slate-400">{`Type: ${nodeDetail.type}`}</p>
        </div>

        <div className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
          <div className="mb-2 flex items-center justify-between text-xs text-slate-400">
            <span>Risk score</span>
            <span>{nodeDetail.riskScore.toFixed(2)}</span>
          </div>
          <div className="h-2 rounded bg-[#1b2231]">
            <div
              className="h-2 rounded bg-brand-500 transition-all"
              style={{ width: `${Math.round(nodeDetail.riskScore * 100)}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-slate-500">{`Risk level: ${scoreLabel(nodeDetail.riskScore)}`}</p>
        </div>

        <div>
          <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Policies Applied</p>
          <div className="flex flex-wrap gap-2">
            {nodeDetail.policiesApplied.length ? (
              nodeDetail.policiesApplied.map((policy) => <Badge key={policy}>{policy}</Badge>)
            ) : (
              <span className="text-xs text-slate-500">No policy metadata attached to this node.</span>
            )}
          </div>
        </div>

        <div>
          <p className="mb-2 text-xs uppercase tracking-[0.2em] text-slate-500">Recent Actions</p>
          <div className="space-y-2">
            {nodeDetail.recentActions.length ? (
              nodeDetail.recentActions.map((event) => (
                <div key={event.event_id} className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-2">
                  <div className="mb-1 flex items-center justify-between gap-2">
                    <Badge className={decisionBadgeClass(event.decision)}>{decisionLabel(event.decision)}</Badge>
                    <span className="text-[11px] text-slate-500">{formatDateTime(event.created_at)}</span>
                  </div>
                  <p className="text-xs text-slate-200">{event.event_type}</p>
                  <p className="text-[11px] text-slate-500">{`source: ${event.source_surface} · risk: ${Number(event.risk_score || 0).toFixed(2)}`}</p>
                </div>
              ))
            ) : (
              <span className="text-xs text-slate-500">No recent actions linked to this node.</span>
            )}
          </div>
        </div>
      </div>
      <DecisionExplanationModal
        open={modalOpen}
        evidenceId={modalEvidenceId}
        onOpenChange={(open) => {
          setModalOpen(open);
          if (!open) setModalEvidenceId(null);
        }}
      />
    </>
  );
}
