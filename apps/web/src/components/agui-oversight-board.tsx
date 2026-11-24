"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { PageSection } from "@/components/page-section";
import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { AguiAction, AguiDecision } from "@/lib/types";


type AguiOversightBoardProps = {
  title: string;
  description: string;
  sourceModule: string;
  actionIds: string[];
};

function formatDate(value?: string | null): string {
  if (!value) return "-";
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "-";
  return parsed.toLocaleString();
}

function parseEvidenceIds(value: string): string[] {
  return Array.from(
    new Set(
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function stringifyPayload(value: Record<string, unknown>): string {
  return JSON.stringify(value, null, 2);
}

function customerSourceSummary(value: string): string {
  const normalized = value.toLowerCase();
  if (normalized.includes("runtime source object") && normalized.includes("source_object_id")) {
    return "Runtime record details are unavailable. Add an affected record to continue.";
  }
  return value;
}

function parsePayload(raw: string): Record<string, unknown> {
  const text = raw.trim();
  if (!text) return {};
  const parsed = JSON.parse(text);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Decision payload must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

function diffPreview(payload: Record<string, unknown>): string {
  const current = payload.current_state;
  const proposed = payload.proposed_state;
  if (!current || !proposed || typeof current !== "object" || typeof proposed !== "object") {
    return "Provide a current state and proposed state to render a diff preview.";
  }
  const currentPretty = JSON.stringify(current, null, 2).split("\n");
  const proposedPretty = JSON.stringify(proposed, null, 2).split("\n");
  const lines: string[] = [];
  lines.push("Current state:");
  currentPretty.forEach((line) => lines.push(`- ${line}`));
  lines.push("Proposed state:");
  proposedPretty.forEach((line) => lines.push(`+ ${line}`));
  return lines.join("\n");
}

function preferredActionOrder(actions: AguiAction[], ids: string[]): AguiAction[] {
  const position = new Map(ids.map((id, index) => [id, index]));
  return [...actions].sort((a, b) => {
    const left = position.get(a.action_id);
    const right = position.get(b.action_id);
    if (left !== undefined && right !== undefined) return left - right;
    if (left !== undefined) return -1;
    if (right !== undefined) return 1;
    return a.action_id.localeCompare(b.action_id);
  });
}

export function AguiOversightBoard({ title, description, sourceModule, actionIds }: AguiOversightBoardProps) {
  const [actions, setActions] = useState<AguiAction[]>([]);
  const [decisions, setDecisions] = useState<AguiDecision[]>([]);
  const [selectedActionId, setSelectedActionId] = useState<string>("");
  const [decisionChoice, setDecisionChoice] = useState<string>("");
  const [justification, setJustification] = useState<string>("");
  const [evidenceNodeIdsInput, setEvidenceNodeIdsInput] = useState<string>("");
  const [sourceObjectType, setSourceObjectType] = useState<string>("");
  const [sourceObjectId, setSourceObjectId] = useState<string>("");
  const [decisionPayloadInput, setDecisionPayloadInput] = useState<string>("{}");
  const [evidenceDisplayed, setEvidenceDisplayed] = useState<boolean>(true);
  const [diffPreviewDisplayed, setDiffPreviewDisplayed] = useState<boolean>(true);
  const [loading, setLoading] = useState<boolean>(true);
  const [busy, setBusy] = useState<boolean>(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const selectedAction = useMemo(
    () => actions.find((item) => item.action_id === selectedActionId) || null,
    [actions, selectedActionId]
  );

  const filteredDecisions = useMemo(() => {
    if (!selectedActionId) return decisions;
    return decisions.filter((item) => item.action_id === selectedActionId);
  }, [decisions, selectedActionId]);

  const evidenceLinks = useMemo(() => {
    const out = new Set<string>();
    filteredDecisions.forEach((decision) => {
      decision.evidence_node_ids.forEach((id) => {
        if (id) out.add(id);
      });
    });
    return Array.from(out).slice(0, 20);
  }, [filteredDecisions]);

  useEffect(() => {
    if (!selectedAction) return;
    setDecisionChoice(selectedAction.decision_options[0] || "approve");
    setSourceObjectType(selectedAction.source_object_type || "");
    setEvidenceDisplayed(selectedAction.requires_evidence_display);
    setDiffPreviewDisplayed(selectedAction.requires_diff_preview);
    setJustification("");
    setEvidenceNodeIdsInput("");
    setSourceObjectId("");
    setDecisionPayloadInput(
      stringifyPayload({
        source_object_type: selectedAction.source_object_type,
        source_object_id: "",
      })
    );
  }, [selectedAction]);

  async function load() {
    setLoading(true);
    try {
      const [actionPayload, decisionPayload] = await Promise.all([
        api.listAguiActions({ source_module: sourceModule, page: 1, page_size: 200 }),
        api.listAguiDecisions({ source_module: sourceModule, page: 1, page_size: 200 }),
      ]);
      const ordered = preferredActionOrder(
        (actionPayload.items || []).filter((item) => actionIds.includes(item.action_id)),
        actionIds
      );
      setActions(ordered);
      setDecisions(decisionPayload.items || []);
      setLoadError(null);
      if (!selectedActionId && ordered.length > 0) {
        setSelectedActionId(ordered[0].action_id);
      } else if (selectedActionId && !ordered.some((item) => item.action_id === selectedActionId)) {
        setSelectedActionId(ordered[0]?.action_id || "");
      }
    } catch (err) {
      setActions([]);
      setDecisions([]);
      setLoadError(err instanceof Error ? err.message : "Approval actions are unavailable.");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load().catch(() => undefined);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceModule]);

  async function executeDecision() {
    if (!selectedAction) {
      toast.error("Select an AGUI action first.");
      return;
    }
    if (selectedAction.requires_justification && !justification.trim()) {
      toast.error("Justification is required for this action.");
      return;
    }
    let parsedPayload: Record<string, unknown>;
    try {
      parsedPayload = parsePayload(decisionPayloadInput);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Invalid decision payload JSON");
      return;
    }

    if (sourceObjectType.trim()) parsedPayload.source_object_type = sourceObjectType.trim();
    if (sourceObjectId.trim()) parsedPayload.source_object_id = sourceObjectId.trim();

    setBusy(true);
    try {
      const decided = await api.decideAguiAction(selectedAction.action_id, {
        decision: decisionChoice,
        justification: justification.trim() || undefined,
        evidence_node_ids: parseEvidenceIds(evidenceNodeIdsInput),
        decision_payload: parsedPayload,
        source_module: selectedAction.source_module,
        source_object_type: sourceObjectType.trim() || undefined,
        source_object_id: sourceObjectId.trim() || undefined,
        evidence_displayed: selectedAction.requires_evidence_display ? evidenceDisplayed : true,
        diff_preview_displayed: selectedAction.requires_diff_preview ? diffPreviewDisplayed : true,
      });
      toast.success(`Decision recorded: ${decided.decision_id}`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to execute AGUI decision");
    } finally {
      setBusy(false);
    }
  }

  const currentPayload = useMemo(() => {
    try {
      return parsePayload(decisionPayloadInput);
    } catch {
      return {};
    }
  }, [decisionPayloadInput]);

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-brand-500">Approvals</p>
        <h1 className="text-2xl font-semibold text-slate-100">{title}</h1>
        <p className="mt-1 max-w-3xl text-sm text-slate-400">{description}</p>
      </div>

      {loading ? <p role="status" className="rounded-lg border border-slate-700 p-4 text-sm text-slate-400">Loading approval actions…</p> : null}
      {loadError ? (
        <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-100">
          <span>Approval actions unavailable: {loadError}</span>
          <Button variant="outline" size="sm" onClick={() => void load()}>Retry</Button>
        </div>
      ) : null}

      <PageSection title="Action Queue" description={loading ? "Loading available decisions…" : `${actions.length} actions available. Select one to review its evidence and record a decision.`}>
        <SimpleTable
          columns={["Action", "Required Roles", "Review required", "Proof Timeline", "Select"]}
          rows={actions.map((item) => [
            item.title,
            item.required_role.join(", "),
            <div key={`${item.action_id}-requirements`} className="flex flex-wrap gap-1">
              {item.requires_justification ? <Badge>Justification</Badge> : null}
              {item.requires_evidence_display ? <Badge>Evidence Review</Badge> : null}
              {item.requires_diff_preview ? <Badge>Diff Preview</Badge> : null}
            </div>,
            item.proof_timeline_url ? (
              <Link className="text-brand-700 underline underline-offset-2" href={item.proof_timeline_url}>
                Open Timeline
              </Link>
            ) : (
              "-"
            ),
            <Button
              key={`${item.action_id}-select`}
              size="sm"
              variant={selectedActionId === item.action_id ? "default" : "outline"}
              onClick={() => setSelectedActionId(item.action_id)}
            >
              {selectedActionId === item.action_id ? "Selected" : "Select"}
            </Button>,
          ])}
        />
        {!loading && !loadError && !actions.length ? <p className="mt-3 text-sm text-slate-400">No approval actions are available for this area.</p> : null}
      </PageSection>

      {selectedAction ? (
        <>
          <PageSection title="Review selected action" description="Confirm the affected record and proof before making a decision.">
            <div className="space-y-2 rounded-lg border bg-slate-50 p-4">
              <p className="font-medium">{selectedAction.title}</p>
              <p className="text-xs text-slate-500">Affected record</p>
              <p className="text-sm text-slate-800">{customerSourceSummary(selectedAction.source_summary)}</p>
              <div className="flex flex-wrap gap-2">
                {selectedAction.proof_timeline_url ? (
                  <Link
                    href={selectedAction.proof_timeline_url}
                    className="text-sm text-brand-700 underline underline-offset-2"
                  >
                    Open Proof Timeline
                  </Link>
                ) : null}
              </div>
              <details className="text-xs text-slate-500"><summary className="cursor-pointer">Technical details</summary><div className="space-y-1"><code>{selectedAction.action_id}</code><p>{selectedAction.source_summary}</p></div></details>
            </div>
          </PageSection>

          <PageSection title="Evidence Links" description="Evidence IDs associated with recent AGUI decisions.">
            {evidenceLinks.length ? (
              <div className="flex flex-wrap gap-2">
                {evidenceLinks.map((id) => (
                  <a
                    key={id}
                    href={`/discovery/findings?evidence=${encodeURIComponent(id)}`}
                    className="rounded-md border bg-white px-2 py-1 text-xs text-brand-700 underline underline-offset-2"
                  >
                    {id}
                  </a>
                ))}
              </div>
            ) : (
              <p className="text-sm text-slate-500">No evidence links yet for this action.</p>
            )}
          </PageSection>

          <PageSection title="Record decision" description="Choose a decision and provide the required review details.">
            <div className="grid gap-4 lg:grid-cols-2">
              <label className="space-y-1 text-xs font-medium text-slate-600">
                Decision
                <select
                  className="h-10 w-full rounded-md border bg-white px-3 text-sm"
                  value={decisionChoice}
                  onChange={(event) => setDecisionChoice(event.target.value)}
                >
                  {selectedAction.decision_options.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-1 text-xs font-medium text-slate-600 lg:col-span-2">
                Affected record ID
                <Input
                  value={sourceObjectId}
                  onChange={(event) => setSourceObjectId(event.target.value)}
                  placeholder="finding_id / ai_system_id / control_conflict_id..."
                />
              </label>

              <label className="space-y-1 text-xs font-medium text-slate-600 lg:col-span-2">
                Supporting evidence IDs (comma-separated)
                <Input
                  value={evidenceNodeIdsInput}
                  onChange={(event) => setEvidenceNodeIdsInput(event.target.value)}
                  placeholder="ev_...,ev_..."
                />
              </label>

              <label className="space-y-1 text-xs font-medium text-slate-600 lg:col-span-2">
                Justification {selectedAction.requires_justification ? "(Required)" : "(Optional)"}
                <textarea
                  className="min-h-24 w-full rounded-md border bg-white px-3 py-2 text-sm"
                  value={justification}
                  onChange={(event) => setJustification(event.target.value)}
                />
              </label>

              <details className="lg:col-span-2 rounded-lg border border-slate-200 p-3 text-xs text-slate-600">
                <summary className="cursor-pointer font-medium">Technical decision details</summary>
                <div className="mt-3 space-y-3">
                  <label className="block space-y-1">Record type<Input value={sourceObjectType} onChange={(event) => setSourceObjectType(event.target.value)} /></label>
                  <label className="block space-y-1">Decision payload (JSON object)<textarea className="min-h-40 w-full rounded-md border bg-white px-3 py-2 font-mono text-xs" value={decisionPayloadInput} onChange={(event) => setDecisionPayloadInput(event.target.value)} /></label>
                </div>
              </details>

              {selectedAction.requires_diff_preview ? (
                <div className="space-y-2 rounded-md border bg-slate-950 p-3 text-xs text-slate-200 lg:col-span-2">
                  <div className="flex items-center justify-between">
                    <p className="font-semibold">Diff preview</p>
                    <label className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={diffPreviewDisplayed}
                        onChange={(event) => setDiffPreviewDisplayed(event.target.checked)}
                      />
                      Marked as reviewed
                    </label>
                  </div>
                  <pre className="overflow-auto whitespace-pre-wrap">{diffPreview(currentPayload)}</pre>
                </div>
              ) : null}

              {selectedAction.requires_evidence_display ? (
                <label className="flex items-center gap-2 text-sm lg:col-span-2">
                  <input
                    type="checkbox"
                    checked={evidenceDisplayed}
                    onChange={(event) => setEvidenceDisplayed(event.target.checked)}
                  />
                  Evidence has been reviewed prior to decision
                </label>
              ) : null}
            </div>

            <div className="mt-4 flex justify-end">
              <Button onClick={executeDecision} disabled={busy || loading}>
                {busy ? "Submitting..." : "Record decision"}
              </Button>
            </div>
          </PageSection>

          <PageSection title="Recent Decisions" description="Traceable AGUI decisions for this oversight surface.">
            <SimpleTable
              columns={["Decision ID", "Action", "Decision", "When", "Source Summary", "Evidence", "Proof Timeline"]}
              rows={filteredDecisions.map((item) => [
                <code key={`${item.decision_id}-id`} className="text-xs">
                  {item.decision_id}
                </code>,
                item.action_id,
                <Badge key={`${item.decision_id}-decision`}>{item.decision}</Badge>,
                formatDate(item.decided_at),
                customerSourceSummary(item.source_summary),
                item.evidence_node_ids.length ? item.evidence_node_ids.join(", ") : "-",
                item.proof_timeline_url ? (
                  <Link
                    key={`${item.decision_id}-timeline`}
                    className="text-brand-700 underline underline-offset-2"
                    href={item.proof_timeline_url}
                  >
                    Open Timeline
                  </Link>
                ) : (
                  "-"
                ),
              ])}
            />
          </PageSection>
        </>
      ) : (
        !loading && !loadError ? <p className="text-sm text-slate-400">Select an available action to record a decision.</p> : null
      )}
      <details className="text-xs text-slate-500"><summary className="cursor-pointer">Source details</summary><code>{sourceModule}</code></details>
    </div>
  );
}
