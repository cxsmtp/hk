import assert from "node:assert/strict";
import {
  ACTION_INTEGRITY_TIMELINE_STAGES,
  buildActionIntegrityAuthorityView,
} from "../src/lib/action-integrity-authority.mjs";

const observed = (value) => ({
  state: "OBSERVED", value, evidence_refs: ["event:1"], occurred_at: "2026-08-25T09:00:00Z", reason_code: null,
});
const unknown = (reason = "evidence_not_persisted") => ({
  state: "UNKNOWN", value: null, evidence_refs: [], occurred_at: null, reason_code: reason,
});
const fields = {
  context: ["actor_principal", "executing_identity", "represented_subjects", "business_purpose", "authority", "delegation"],
  action: ["operation", "tool_or_service", "safe_parameters", "resources", "targets", "destinations", "values_or_quantities", "side_effect", "persistence", "reversibility"],
  control: ["requirements", "control_plan", "mandatory_floors", "assurance", "rejected_controls", "blind_spots"],
  authorisation: ["policy", "decision", "approval_request", "approval_binding", "decision_receipt", "execution_permits"],
  execution: ["observed_semantics", "execution_receipts", "evidence_quality", "material_integrity", "execution_state", "drift_fields", "outcome_integrity"],
};
const section = (name) => Object.fromEntries(fields[name].map((field) => [field, unknown()]));

const detail = {
  context: { ...section("context"), actor_principal: observed("user:1") },
  action: { ...section("action"), operation: observed("transfer") },
  control: section("control"),
  authorisation: section("authorisation"),
  execution: section("execution"),
  timeline: [{ timeline_event_id: "event:1", event_type: "REQUEST", stage_ordinal: 1, state: "OBSERVED", value: { request: "received" }, occurred_at: "2026-08-25T09:00:00Z", evidence_node_ids: ["event:1"], reason_code: null }],
};

const view = buildActionIntegrityAuthorityView(detail);

assert.deepEqual(view.sections.map((section) => section.key), ["context", "action", "control", "authorisation", "execution"]);
assert.deepEqual(view.sections.map((section) => section.fields.map((field) => field.field)), Object.values(fields));
assert.equal(view.timeline.length, 14);
assert.equal(view.timeline[0].event_type, "REQUEST");
assert.equal(view.timeline[0].state, "OBSERVED");
assert.equal(view.timeline[1].state, "UNKNOWN");
assert.equal(view.timeline[1].reason_code, "timeline_stage_not_persisted");
assert.equal(ACTION_INTEGRITY_TIMELINE_STAGES.length, 14);
for (const field of [
  "represented_subjects", "resources", "targets", "destinations", "values_or_quantities",
  "requirements", "mandatory_floors", "rejected_controls", "blind_spots",
  "execution_permits", "execution_receipts", "drift_fields",
]) {
  const section = view.sections.find((item) => item.fields.some((card) => card.field === field));
  const card = section.fields.find((item) => item.field === field);
  assert.ok(Array.isArray(card.value), `${field} remains array-shaped even when UNKNOWN`);
}

const repeated = buildActionIntegrityAuthorityView({
  ...detail,
  timeline: [
    { timeline_event_id: "execution-later", event_type: "EXECUTION", state: "OBSERVED", sequence: 2, occurred_at: "2026-08-25T09:01:00Z", evidence_node_ids: ["two"], value: "later", reason_code: null },
    { timeline_event_id: "execution-first", event_type: "EXECUTION", state: "OBSERVED", sequence: 1, occurred_at: "2026-08-25T09:02:00Z", evidence_node_ids: ["one"], value: "first", reason_code: null },
  ],
});
const executionEvents = repeated.timeline.filter((item) => item.event_type === "EXECUTION");
assert.deepEqual(executionEvents.map((item) => item.timeline_event_id), ["execution-first", "execution-later"]);
assert.ok(repeated.timeline.length === 15, "two stored durable execution events are preserved");
