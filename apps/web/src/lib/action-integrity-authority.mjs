export const ACTION_INTEGRITY_TIMELINE_STAGES = [
  "REQUEST",
  "ACTOR_RESOLUTION",
  "REPRESENTED_SUBJECT_RESOLUTION",
  "PURPOSE",
  "PROPOSED_ACTION",
  "DOMAIN_SEMANTICS",
  "POLICY",
  "APPROVAL",
  "PERMIT",
  "EXECUTION",
  "TARGET_CONFIRMATION",
  "COMPARISON",
  "OUTCOME",
  "PERSISTENT_EFFECT",
];

const ACTION_INTEGRITY_SECTION_FIELDS = {
  context: ["actor_principal", "executing_identity", "represented_subjects", "business_purpose", "authority", "delegation"],
  action: ["operation", "tool_or_service", "safe_parameters", "resources", "targets", "destinations", "values_or_quantities", "side_effect", "persistence", "reversibility"],
  control: ["requirements", "control_plan", "mandatory_floors", "assurance", "rejected_controls", "blind_spots"],
  authorisation: ["policy", "decision", "approval_request", "approval_binding", "decision_receipt", "execution_permits"],
  execution: ["observed_semantics", "execution_receipts", "evidence_quality", "material_integrity", "execution_state", "drift_fields", "outcome_integrity"],
};

const ACTION_INTEGRITY_ARRAY_FIELDS = new Set([
  "represented_subjects", "resources", "targets", "destinations", "values_or_quantities",
  "requirements", "mandatory_floors", "rejected_controls", "blind_spots",
  "execution_permits", "execution_receipts", "drift_fields",
]);

function unknownEvidence(reasonCode = "evidence_not_persisted") {
  return { state: "UNKNOWN", value: null, evidence_refs: [], occurred_at: null, reason_code: reasonCode };
}

function evidence(value) {
  if (!value || typeof value !== "object") return unknownEvidence();
  return {
    state: value.state === "OBSERVED" ? "OBSERVED" : "UNKNOWN",
    value: value.value ?? null,
    evidence_refs: Array.isArray(value.evidence_refs) ? value.evidence_refs : [],
    occurred_at: typeof value.occurred_at === "string" ? value.occurred_at : null,
    reason_code: value.reason_code ?? (value.state === "OBSERVED" ? null : "evidence_not_persisted"),
  };
}

function fieldEvidence(field, value) {
  const card = evidence(value);
  if (!ACTION_INTEGRITY_ARRAY_FIELDS.has(field)) return card;
  return { ...card, value: Array.isArray(card.value) ? card.value : [] };
}

function section(key, label, source) {
  return {
    key,
    label,
    fields: ACTION_INTEGRITY_SECTION_FIELDS[key].map((field) => ({ field, ...fieldEvidence(field, source?.[field]) })),
  };
}

export function buildActionIntegrityAuthorityView(detail) {
  const source = detail && typeof detail === "object" ? detail : {};
  const timelineByType = new Map();
  for (const stage of Array.isArray(source.timeline) ? source.timeline : []) {
    if (!stage || typeof stage.event_type !== "string") continue;
    const entries = timelineByType.get(stage.event_type) || [];
    entries.push(stage);
    timelineByType.set(stage.event_type, entries);
  }
  return {
    sections: [
      section("context", "Context", source.context),
      section("action", "Action", source.action),
      section("control", "Control", source.control),
      section("authorisation", "Authorisation", source.authorisation),
      section("execution", "Execution", source.execution),
    ],
    timeline: ACTION_INTEGRITY_TIMELINE_STAGES.flatMap((eventType, index) => {
      const stored = timelineByType.get(eventType) || [];
      if (!stored.length) {
        return [{
            timeline_event_id: `missing:${eventType}`,
            event_type: eventType,
            stage_ordinal: index + 1,
            state: "UNKNOWN",
            value: null,
            occurred_at: null,
            reason_code: "timeline_stage_not_persisted",
          }];
      }
      return stored
        .slice()
        .sort((left, right) => {
          const bySequence = Number(left.sequence || 0) - Number(right.sequence || 0);
          if (bySequence) return bySequence;
          const leftTime = typeof left.occurred_at === "string" ? left.occurred_at : "\uffff";
          const rightTime = typeof right.occurred_at === "string" ? right.occurred_at : "\uffff";
          if (leftTime !== rightTime) return leftTime.localeCompare(rightTime);
          return String(left.timeline_event_id || "").localeCompare(String(right.timeline_event_id || ""));
        })
        .map((item) => ({
          ...item,
          stage_ordinal: index + 1,
          state: item.state === "OBSERVED" ? "OBSERVED" : "UNKNOWN",
          reason_code: item.reason_code ?? (item.state === "OBSERVED" ? null : "evidence_not_persisted"),
        }));
    }),
  };
}
