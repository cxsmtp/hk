"use client";

import { useEffect, useMemo, useState } from "react";

import { decisionBadgeClass, decisionLabel, formatDateTime } from "@/components/runtime-intelligence/utils";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { AuditEvidenceExplanation } from "@/lib/types";
import { cn } from "@/lib/utils";

function formatFramework(item: AuditEvidenceExplanation["framework_mapping"][number]): string {
  const controls = (item.controls || []).filter(Boolean);
  if (!controls.length) return item.framework;
  return `${item.framework} (${controls.slice(0, 3).join(", ")})`;
}

function DecisionExplanationContent({
  loading,
  error,
  data,
}: {
  loading: boolean;
  error: string;
  data: AuditEvidenceExplanation | null;
}) {
  if (loading) {
    return <p className="text-sm text-slate-400">Loading decision explanation...</p>;
  }
  if (error) {
    return <p className="text-sm text-rose-300">{error}</p>;
  }
  if (!data) {
    return <p className="text-sm text-slate-500">Select an evidence item to explain this decision.</p>;
  }

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-[#2a3348] bg-[#0f1218] p-3">
        <p className="mb-1 text-xs text-slate-500">Decision</p>
        <Badge className={decisionBadgeClass(data.decision)}>{decisionLabel(data.decision)}</Badge>
      </div>

      <div className="rounded-md border border-[#2a3348] bg-[#0f1218] p-3">
        <p className="text-xs text-slate-500">Reason</p>
        <p className="mt-1 text-sm font-semibold text-slate-100">{data.reason || "Policy violation detected"}</p>
      </div>

      <div className="rounded-md border border-[#2a3348] bg-[#0f1218] p-3">
        <p className="text-xs text-slate-500">Violated Policy</p>
        <p className="mt-1 text-sm text-slate-100">
          {data.violated_policy.policy_pack_name || data.violated_policy.policy_pack_id || "Unknown policy pack"}
        </p>
        <p className="text-xs text-slate-400">
          {data.violated_policy.policy_version || data.violated_policy.policy_version_id || "-"}
        </p>
      </div>

      <div className="rounded-md border border-[#2a3348] bg-[#0f1218] p-3">
        <div className="mb-1 flex items-center justify-between text-xs text-slate-500">
          <span>Confidence Score</span>
          <span>{Number(data.confidence_score || 0).toFixed(2)}</span>
        </div>
        <div className="h-2 rounded bg-[#1b2231]">
          <div
            className="h-2 rounded bg-brand-500 transition-all"
            style={{ width: `${Math.round(Number(data.confidence_score || 0) * 100)}%` }}
          />
        </div>
      </div>

      <div className="rounded-md border border-[#2a3348] bg-[#0f1218] p-3">
        <p className="mb-2 text-xs text-slate-500">Framework Mapping (GDPR, ISO, etc.)</p>
        <div className="flex flex-wrap gap-2">
          {data.framework_mapping.length ? (
            data.framework_mapping.map((item) => (
              <Badge key={`${item.framework}:${item.controls.join(",")}`}>{formatFramework(item)}</Badge>
            ))
          ) : (
            <span className="text-xs text-slate-500">No explicit framework mapping available.</span>
          )}
        </div>
      </div>

      <div className="rounded-md border border-[#2a3348] bg-[#0f1218] p-3 text-xs text-slate-400">
        <p>{`Evidence: ${data.evidence_id}`}</p>
        <p>{`Signal: ${data.signal_type}`}</p>
        <p>{`Created: ${formatDateTime(data.created_at)}`}</p>
        <p>{`Correlation: ${data.correlation_id || "-"}`}</p>
      </div>
    </div>
  );
}

function useDecisionExplanationData(open: boolean, evidenceId: string | null) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [data, setData] = useState<AuditEvidenceExplanation | null>(null);

  useEffect(() => {
    if (!open || !evidenceId) {
      setLoading(false);
      setError("");
      setData(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError("");
    api
      .auditEvidence(evidenceId)
      .then((payload) => {
        if (cancelled) return;
        setData(payload);
      })
      .catch((err) => {
        if (cancelled) return;
        setData(null);
        setError(err instanceof Error ? err.message : "Unable to load evidence explainer");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, evidenceId]);

  return { loading, error, data };
}

export function DecisionExplanationSidePanel({
  open,
  evidenceId,
  title = "Decision Explainer",
  className,
  emptyState = "Select an event evidence id to explain decision context.",
  onClear,
}: {
  open: boolean;
  evidenceId: string | null;
  title?: string;
  className?: string;
  emptyState?: string;
  onClear?: () => void;
}) {
  const { loading, error, data } = useDecisionExplanationData(open, evidenceId);
  const hasSelection = open && Boolean(evidenceId);

  return (
    <div className={cn("rounded-lg border border-[#2a3348] bg-[#101524] p-3", className)}>
      <div className="mb-2 flex items-center justify-between">
        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{title}</p>
        {hasSelection && onClear ? (
          <Button variant="outline" size="sm" onClick={onClear}>
            Clear
          </Button>
        ) : null}
      </div>
      {!hasSelection ? (
        <p className="text-sm text-slate-500">{emptyState}</p>
      ) : (
        <DecisionExplanationContent loading={loading} error={error} data={data} />
      )}
    </div>
  );
}

export function DecisionExplanationModal({
  open,
  evidenceId,
  onOpenChange,
  title = "Decision Explanation",
}: {
  open: boolean;
  evidenceId: string | null;
  onOpenChange: (open: boolean) => void;
  title?: string;
}) {
  const { loading, error, data } = useDecisionExplanationData(open, evidenceId);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onOpenChange(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [onOpenChange, open]);

  const subtitle = useMemo(() => {
    if (!evidenceId) return "No evidence selected";
    return `Evidence ${evidenceId.slice(0, 12)}...`;
  }, [evidenceId]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[90]">
      <button
        type="button"
        className="absolute inset-0 bg-black/55"
        aria-label="Close decision explanation modal"
        onClick={() => onOpenChange(false)}
      />
      <div className="absolute left-1/2 top-1/2 w-[min(860px,94vw)] -translate-x-1/2 -translate-y-1/2 rounded-xl border border-[#2a3348] bg-[#101524] p-4 shadow-2xl">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div>
            <p className="text-xs uppercase tracking-[0.2em] text-slate-500">{title}</p>
            <p className="mt-1 text-sm text-slate-400">{subtitle}</p>
          </div>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)}>
            Close
          </Button>
        </div>
        <DecisionExplanationContent loading={loading} error={error} data={data} />
      </div>
    </div>
  );
}

