"use client";

import Link from "next/link";
import { useState } from "react";

import { DecisionExplanationModal } from "@/components/decision-explanation";
import { decisionBadgeClass, decisionLabel, formatDateTime } from "@/components/runtime-intelligence/utils";
import { Badge } from "@/components/ui/badge";

export type AgentFlowStepEntity = {
  nodeType: string;
  entityId: string;
};

export type AgentFlowStep = {
  id: string;
  eventId: string;
  action: string;
  decision: string;
  decisionTone: "allow" | "warn" | "block" | "unknown";
  timestamp: string | null;
  sourceSurface: string;
  riskScore: number;
  participants: AgentFlowStepEntity[];
  agentIds: string[];
  parentActionId: string | null;
  evidenceNodeIds: string[];
};

function timelineDotClass(tone: AgentFlowStep["decisionTone"]): string {
  if (tone === "allow") return "bg-emerald-400";
  if (tone === "warn") return "bg-amber-400";
  if (tone === "block") return "bg-rose-400";
  return "bg-slate-500";
}

function cardClass(tone: AgentFlowStep["decisionTone"], selected: boolean): string {
  const base = "rounded-lg border bg-[#0f1218] p-3 transition";
  if (tone === "allow") return `${base} ${selected ? "border-emerald-500/60" : "border-emerald-500/30"} hover:border-emerald-500/60`;
  if (tone === "warn") return `${base} ${selected ? "border-amber-500/60" : "border-amber-500/30"} hover:border-amber-500/60`;
  if (tone === "block") return `${base} ${selected ? "border-rose-500/60" : "border-rose-500/30"} hover:border-rose-500/60`;
  return `${base} ${selected ? "border-brand-500/60" : "border-[#2a3348]"} hover:border-brand-500/40`;
}

function participantPath(step: AgentFlowStep): string {
  if (!step.participants.length) return "No participant chain metadata";
  return step.participants.map((part) => `${part.nodeType}:${part.entityId}`).join(" -> ");
}

export function AgentFlowVertical({
  steps,
  selectedStepId,
  onSelectedStepIdChange,
}: {
  steps: AgentFlowStep[];
  selectedStepId: string | null;
  onSelectedStepIdChange: (id: string | null) => void;
}) {
  const [modalEvidenceId, setModalEvidenceId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  function openDecisionExplanation(evidenceId: string) {
    setModalEvidenceId(evidenceId);
    setModalOpen(true);
  }

  if (!steps.length) {
    return (
      <div className="rounded-lg border border-dashed border-[#334155] bg-[#0b1220] px-4 py-10 text-center text-sm text-slate-400">
        No chain steps match the current filters.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-[#2a3348] bg-[#101524] p-3">
      <div className="max-h-[740px] overflow-auto pr-1">
        <div className="space-y-3">
          {steps.map((step, index) => {
            const selected = selectedStepId === step.id;
            return (
              <div key={step.id} className="grid grid-cols-[16px_1fr] gap-2">
                <div className="relative flex justify-center">
                  <span className={`mt-1 h-3 w-3 rounded-full ${timelineDotClass(step.decisionTone)}`} />
                  {index < steps.length - 1 ? (
                    <span className="absolute left-1/2 top-4 h-[calc(100%+8px)] w-px -translate-x-1/2 bg-[#26324a]" />
                  ) : null}
                </div>
                <button
                  type="button"
                  className={cardClass(step.decisionTone, selected)}
                  onClick={() => onSelectedStepIdChange(selected ? null : step.id)}
                >
                  <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                    <p className="text-xs text-slate-400">{formatDateTime(step.timestamp)}</p>
                    <Badge className={decisionBadgeClass(step.decision)}>{decisionLabel(step.decision)}</Badge>
                  </div>

                  <p className="text-sm font-semibold text-slate-100">{step.action}</p>
                  <p className="mt-1 text-xs text-slate-400">{participantPath(step)}</p>

                  <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
                    <span>{`source: ${step.sourceSurface || "unknown"}`}</span>
                    <span>{`risk: ${step.riskScore.toFixed(2)}`}</span>
                    <span>{`event: ${step.eventId}`}</span>
                    {step.parentActionId ? <span>{`parent: ${step.parentActionId}`}</span> : null}
                  </div>

                  {selected ? (
                    <div className="mt-3 rounded-md border border-[#2a3348] bg-[#111a2b] p-2 text-left">
                      <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Evidence</p>
                      {step.evidenceNodeIds.length ? (
                        <div className="mt-2 flex flex-wrap gap-2">
                          {step.evidenceNodeIds.slice(0, 6).map((evidenceId) => (
                            <div key={evidenceId} className="flex items-center gap-2">
                              <Link
                                href={`/auditor?evidence_id=${encodeURIComponent(evidenceId)}`}
                                className="rounded border border-brand-500/40 px-2 py-1 text-xs text-brand-200 hover:bg-brand-500/10"
                              >
                                {`Open ${evidenceId.slice(0, 10)}...`}
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
                        <p className="mt-2 text-xs text-slate-500">No linked evidence nodes on this step.</p>
                      )}
                    </div>
                  ) : null}
                </button>
              </div>
            );
          })}
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
    </div>
  );
}
