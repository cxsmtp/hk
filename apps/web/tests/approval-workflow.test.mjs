import assert from "node:assert/strict";
import {
  APPROVAL_STATUSES,
  buildApprovalDecisionPayload,
  createDecisionIdempotencyKey,
  approvalStatusFilters,
  mergeApprovalStatusResults,
} from "../src/lib/approval-workflow.mjs";

assert.deepEqual(approvalStatusFilters("all"), APPROVAL_STATUSES);
assert.deepEqual(approvalStatusFilters("pending"), ["pending"]);
assert.deepEqual(approvalStatusFilters(""), APPROVAL_STATUSES);

assert.deepEqual(
  mergeApprovalStatusResults([
    { items: [{ id: "one", status: "pending" }, { id: "two", status: "approved" }] },
    { items: [{ id: "one", status: "pending" }, { id: "three", status: "denied" }] },
  ]).map((approval) => approval.id),
  ["one", "two", "three"],
);

const key = createDecisionIdempotencyKey("approval-123", "b7b746f2-1901-4306-9d13-01e4afb4a4dd");
assert.match(key, /^approval:approval-123:b7b746f2-1901-4306-9d13-01e4afb4a4dd$/);
assert.ok(key.length <= 128);

assert.deepEqual(
  buildApprovalDecisionPayload(
    { id: "legacy", status: "pending" },
    "approve",
    "Legacy approval decision",
    key,
  ),
  { decision: "approve" },
);

assert.deepEqual(
  buildApprovalDecisionPayload(
    {
      id: "v2",
      status: "pending",
      authority_schema_version: "2.0",
      expected_version: 4,
      request_payload: { schema_version: "2.0", expected_version: 99 },
    },
    "deny",
    "Risk owner denied this request",
    key,
  ),
  {
    schema_version: "2.0",
    decision: "deny",
    expected_version: 4,
    idempotency_key: key,
    reason: "Risk owner denied this request",
  },
);

assert.deepEqual(
  buildApprovalDecisionPayload(
    { id: "v2-payload", status: "pending", request_payload: { schema_version: "2.0", expected_version: 7 } },
    "approve",
    "Stored request authorises this action",
    key,
  ),
  {
    schema_version: "2.0",
    decision: "approve",
    expected_version: 7,
    idempotency_key: key,
    reason: "Stored request authorises this action",
  },
);

assert.throws(
  () => buildApprovalDecisionPayload(
    { id: "v2", authority_schema_version: "2.0", expected_version: 4 },
    "approve",
    "   ",
    key,
  ),
  /reason/i,
);

assert.throws(
  () => buildApprovalDecisionPayload(
    { id: "v2", authority_schema_version: "2.0" },
    "approve",
    "Need an approval decision",
    key,
  ),
  /expected version/i,
);
