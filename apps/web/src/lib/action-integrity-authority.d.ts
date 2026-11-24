import type { ActionIntegrityDetail, ActionIntegrityEvidence } from "@/lib/types";

export const ACTION_INTEGRITY_TIMELINE_STAGES: string[];

export type ActionIntegrityAuthorityField = ActionIntegrityEvidence & { field: string };
export type ActionIntegrityAuthoritySection = { key: string; label: string; fields: ActionIntegrityAuthorityField[] };
export type ActionIntegrityTimelineStage = Pick<ActionIntegrityDetail["timeline"][number], "timeline_event_id" | "event_type" | "stage_ordinal" | "state" | "value" | "occurred_at" | "evidence_node_ids" | "reason_code">;

export function buildActionIntegrityAuthorityView(detail: ActionIntegrityDetail | null): {
  sections: ActionIntegrityAuthoritySection[];
  timeline: ActionIntegrityTimelineStage[];
};
